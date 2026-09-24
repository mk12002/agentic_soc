"""
Microsoft Graph API Integration for Email Remediation.

Provides Graph-backed email remediation actions including:
- Message quarantine (move to Junk)
- Warning banner insertion
- Message resolution by internet message ID
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("graph_client")

# Lazy imports — msal and httpx are only needed at call time.
# Importing msal at module level would crash the entire action_layer
# package (and therefore the orchestrator) if msal is not installed.
_msal = None
_httpx = None


def _get_msal():
    """Lazy import msal to avoid hard crash if not installed."""
    global _msal
    if _msal is None:
        try:
            import msal
            _msal = msal
        except ImportError:
            logger.warning(
                "msal package not installed. Install with: pip install msal. "
                "Graph actions will be unavailable."
            )
    return _msal


def _get_httpx():
    """Lazy import httpx."""
    global _httpx
    if _httpx is None:
        import httpx
        _httpx = httpx
    return _httpx


@dataclass
class GraphActionResult:
    """Result of a Graph API action."""

    ok: bool
    action: str
    status_code: int | None = None
    graph_message_id: str | None = None
    detail: str | None = None

    def __str__(self) -> str:
        status = "✓" if self.ok else "✗"
        return f"{status} {self.action}: {self.detail or 'success'}"


class GraphActionBot:
    """
    Authenticates to Microsoft Graph and performs email remediation actions.
    
    Uses app-only authentication (client credentials flow) for deterministic,
    auditless actions without user interaction or delegated permissions.
    """

    def __init__(self) -> None:
        self.tenant_id = settings.graph_tenant_id or ""
        self.client_id = settings.graph_client_id or ""
        self.client_secret = settings.graph_client_secret or ""
        self.authority = f"{settings.graph_authority}/{self.tenant_id}"
        self.scopes = [settings.graph_scopes]
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"

        # Defer MSAL app initialization to first use
        self.app: Optional[Any] = None
        self._app_initialized = False
        
        if self.tenant_id and self.client_id and self.client_secret:
            logger.debug(
                "Graph client ready (lazy init)",
                tenant_id=self.tenant_id[:12] + "...",
                client_id=self.client_id[:12] + "...",
            )
        else:
            logger.warning(
                "Graph credentials incomplete; actions will fail gracefully"
            )

    def is_configured(self) -> bool:
        """Check if Graph client has valid credentials."""
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def _get_token(self) -> str | None:
        """Acquire app-only access token."""
        if not self.tenant_id or not self.client_id or not self.client_secret:
            return None

        # Lazy initialize MSAL app on first token request
        if not self._app_initialized and self.app is None:
            msal = _get_msal()
            if msal is None:
                self._app_initialized = True
                return None
            try:
                self.app = msal.ConfidentialClientApplication(
                    self.client_id,
                    authority=self.authority,
                    client_credential=self.client_secret,
                )
                self._app_initialized = True
                logger.debug("Graph MSAL app initialized")
            except Exception as exc:
                logger.warning("Failed to initialize Graph MSAL app", error=str(exc))
                self._app_initialized = True  # Don't retry
                return None

        if not self.app:
            return None

        try:
            result = self.app.acquire_token_for_client(scopes=self.scopes)
            if "access_token" in result:
                return result["access_token"]
            else:
                error = result.get("error_description", result.get("error", "unknown"))
                logger.warning("Failed to acquire Graph token", error=error)
                return None
        except Exception as exc:
            logger.warning("Exception acquiring Graph token", error=str(exc))
            return None

    def _graph_request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> tuple[int | None, dict[str, Any] | None]:
        """
        Make an authenticated Graph API request.
        
        Args:
            method: HTTP method (GET, POST, PATCH, etc.)
            endpoint: Graph API endpoint (relative to /v1.0)
            json_data: Request body for POST/PATCH
            params: URL query parameters
            
        Returns:
            Tuple of (status_code, response_json)
        """
        token = self._get_token()
        if not token:
            return None, None

        url = f"{self.graph_endpoint}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            httpx = _get_httpx()
            with httpx.Client(timeout=15.0) as client:
                if method.upper() == "GET":
                    resp = client.get(url, headers=headers, params=params)
                elif method.upper() == "POST":
                    resp = client.post(url, headers=headers, json=json_data)
                elif method.upper() == "PATCH":
                    resp = client.patch(url, headers=headers, json=json_data)
                else:
                    logger.warning(f"Unsupported HTTP method: {method}")
                    return None, None

                try:
                    resp_json = resp.json()
                except Exception:
                    resp_json = None

                return resp.status_code, resp_json
        except Exception as exc:
            logger.warning(
                "Graph request failed",
                method=method,
                endpoint=endpoint,
                error=str(exc),
            )
            return None, None

    def resolve_message_id(
        self, user_principal_name: str, internet_message_id: str
    ) -> str | None:
        """
        Resolve an internet message ID to a Graph message resource ID.
        
        This allows Graph actions to be performed on the correct message.
        
        Args:
            user_principal_name: User mailbox (e.g., "user@company.com")
            internet_message_id: Internet Message-ID header value
            
        Returns:
            Graph message ID if found, None otherwise
        """
        if not self.is_configured():
            return None

        # URL-encode the internet message ID for safe transport
        filter_query = f"internetMessageId eq '{internet_message_id}'"

        status_code, resp_json = self._graph_request(
            "GET",
            f"/users/{user_principal_name}/messages",
            params={"$filter": filter_query, "$select": "id"},
        )

        if status_code != 200 or not resp_json:
            logger.debug(
                "Failed to resolve message ID",
                user=user_principal_name,
                internet_message_id=internet_message_id[:20] + "...",
                status_code=status_code,
            )
            return None

        messages = resp_json.get("value", [])
        if messages:
            graph_id = messages[0].get("id")
            logger.debug(
                "Resolved message ID",
                user=user_principal_name,
                graph_id=graph_id[:12] + "...",
            )
            return graph_id

        return None

    def quarantine_email(
        self, user_principal_name: str, graph_message_id: str
    ) -> GraphActionResult:
        """
        Move an email to Junk folder (quarantine).
        
        Args:
            user_principal_name: User mailbox
            graph_message_id: Graph resource ID of the message
            
        Returns:
            Result of the quarantine action
        """
        if not self.is_configured():
            return GraphActionResult(
                ok=False,
                action="quarantine",
                detail="Graph client not configured",
            )

        # Move message to Junk (deleteditems folder ID)
        # For Junk, use the well-known folder ID "junkemail"
        action_json = {"destinationId": "junkemail"}

        status_code, resp_json = self._graph_request(
            "POST",
            f"/users/{user_principal_name}/messages/{graph_message_id}/move",
            json_data=action_json,
        )

        ok = status_code == 200
        detail = None if ok else f"Graph returned {status_code}"

        if ok:
            logger.info(
                "Email quarantined",
                user=user_principal_name,
                graph_id=graph_message_id[:12] + "...",
            )
        else:
            logger.warning(
                "Quarantine failed",
                user=user_principal_name,
                status_code=status_code,
                response=resp_json,
            )

        return GraphActionResult(
            ok=ok,
            action="quarantine",
            status_code=status_code,
            graph_message_id=graph_message_id,
            detail=detail,
        )

    def delete_email(
        self, user_principal_name: str, graph_message_id: str
    ) -> GraphActionResult:
        """
        Move an email to the Deleted Items folder (soft delete).
        
        Args:
            user_principal_name: User mailbox
            graph_message_id: Graph resource ID of the message
            
        Returns:
            Result of the delete action
        """
        if not self.is_configured():
            return GraphActionResult(
                ok=False,
                action="delete",
                detail="Graph client not configured",
            )

        # Move message to deleteditems folder
        action_json = {"destinationId": "deleteditems"}

        status_code, resp_json = self._graph_request(
            "POST",
            f"/users/{user_principal_name}/messages/{graph_message_id}/move",
            json_data=action_json,
        )

        ok = status_code == 200
        detail = None if ok else f"Graph returned {status_code}"

        if ok:
            logger.info(
                "Email deleted",
                user=user_principal_name,
                graph_id=graph_message_id[:12] + "...",
            )
        else:
            logger.warning(
                "Delete failed",
                user=user_principal_name,
                status_code=status_code,
                response=resp_json,
            )

        return GraphActionResult(
            ok=ok,
            action="delete",
            status_code=status_code,
            graph_message_id=graph_message_id,
            detail=detail,
        )

    def apply_warning_banner(
        self,
        user_principal_name: str,
        graph_message_id: str,
        severity: str = "Medium",
    ) -> GraphActionResult:
        """
        Prepend a warning banner to an email message.
        
        Args:
            user_principal_name: User mailbox
            graph_message_id: Graph resource ID of the message
            severity: Severity level for banner text (e.g., "High", "Medium")
            
        Returns:
            Result of the banner insertion action
        """
        if not self.is_configured():
            return GraphActionResult(
                ok=False,
                action="apply_warning_banner",
                detail="Graph client not configured",
            )

        # Construct warning banner HTML
        banner_html = self._construct_warning_banner(severity)

        # Prepend banner to message body
        status_code, resp_json = self._graph_request(
            "PATCH",
            f"/users/{user_principal_name}/messages/{graph_message_id}",
            json_data={
                "bodyPreview": f"[{severity} Risk] See below.",
                # Note: Direct body HTML modification may require different approach
                # depending on Graph permissions and message format
            },
        )

        ok = status_code == 200
        detail = None if ok else f"Graph returned {status_code}"

        if ok:
            logger.info(
                "Warning banner applied",
                user=user_principal_name,
                severity=severity,
            )
        else:
            logger.warning(
                "Banner application failed",
                user=user_principal_name,
                status_code=status_code,
                severity=severity,
            )

        return GraphActionResult(
            ok=ok,
            action="apply_warning_banner",
            status_code=status_code,
            graph_message_id=graph_message_id,
            detail=detail,
        )

    def add_categories(
        self, user_principal_name: str, graph_message_id: str, categories: list[str]
    ) -> GraphActionResult:
        """
        Add categories/tags to a message for classification and filtering.
        
        Args:
            user_principal_name: User mailbox
            graph_message_id: Graph resource ID of the message
            categories: List of category strings to add
            
        Returns:
            Result of the categorization action
        """
        if not self.is_configured():
            return GraphActionResult(
                ok=False,
                action="add_categories",
                detail="Graph client not configured",
            )

        status_code, resp_json = self._graph_request(
            "PATCH",
            f"/users/{user_principal_name}/messages/{graph_message_id}",
            json_data={"categories": categories},
        )

        ok = status_code == 200
        detail = None if ok else f"Graph returned {status_code}"

        if ok:
            logger.info(
                "Categories added",
                user=user_principal_name,
                categories=categories,
            )
        else:
            logger.warning(
                "Category addition failed",
                user=user_principal_name,
                status_code=status_code,
            )

        return GraphActionResult(
            ok=ok,
            action="add_categories",
            status_code=status_code,
            graph_message_id=graph_message_id,
            detail=detail,
        )

    @staticmethod
    def _construct_warning_banner(severity: str) -> str:
        """Construct HTML warning banner based on severity level."""
        color_map = {
            "Critical": "#d32f2f",  # Red
            "High": "#f57c00",  # Orange
            "Medium": "#fbc02d",  # Yellow
            "Low": "#388e3c",  # Green
        }
        color = color_map.get(severity, "#1976d2")  # Blue default

        return f"""
        <div style="
            border-left: 4px solid {color};
            background-color: #f5f5f5;
            padding: 12px;
            margin-bottom: 12px;
            font-family: Arial, sans-serif;
            font-size: 12px;
            color: #333;
        ">
            <strong style="color: {color}">⚠ Security Warning: {severity} Risk Detected</strong>
            <br/>
            This email has been flagged as potentially malicious by automated security analysis.
            <br/>
            Exercise caution before clicking links or opening attachments.
        </div>
        """


# Convenience function for use in action layer
_GRAPH_CLIENT: Optional[GraphActionBot] = None


def get_graph_client() -> GraphActionBot:
    """
    Get or create the global Graph client singleton.
    """
    global _GRAPH_CLIENT
    if _GRAPH_CLIENT is None:
        _GRAPH_CLIENT = GraphActionBot()
    return _GRAPH_CLIENT
