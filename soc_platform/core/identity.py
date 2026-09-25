"""Cross-source user identity normalisation.

Every tool names users differently: ``ACME\\jane.doe`` (CrowdStrike, Delinea), ``jane.doe`` + domain
(Defender, Canary), ``jane.doe@acme.com`` (Entra, Umbrella, email), ``Jane Doe <jane@acme.com>`` (labels).
``user_ref`` turns any of them into an ``EntityRef`` with the strongest keys available:

* ``upn``   - lower-cased user principal name / primary email (shares a namespace with ``email``)
* ``sam``   - on-prem account name, matched against Entra ``onPremisesSamAccountName`` so that
              ``ACME\\jdoe`` resolves to ``jane.doe@acme.com`` even when the UPN prefix differs
Built-in and machine accounts (SYSTEM, root, www-data, ``HOST$``...) are not people: ``user_ref`` returns
``None`` for them so they never become phantom identities; callers keep the raw name as an attribute.
"""

from __future__ import annotations

import re

from soc_platform.core.schema import EntityRef

BUILTIN_ACCOUNTS = {
    "system", "localsystem", "local service", "localservice", "network service", "networkservice",
    "anonymous logon", "anonymous", "guest", "defaultaccount", "wdagutilityaccount", "iusr", "iwam",
    "root", "daemon", "bin", "sys", "nobody", "www-data", "apache", "nginx", "httpd", "sshd", "postgres",
    "mysql", "redis", "systemd-network", "systemd-resolve", "messagebus", "syslog", "_apt", "dwm-1", "umfd-0",
    "umfd-1", "dwm-2", "-", "n/a", "unknown", "",
}
BUILTIN_DOMAINS = {"nt authority", "nt service", "font driver host", "window manager", "iis apppool", "nt virtual machine"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def split_account(raw: str) -> tuple[str | None, str]:
    """``DOMAIN\\user`` -> (domain, user); ``user@dom`` -> (None, user@dom); ``Name <a@b>`` -> (None, a@b)."""
    s = (raw or "").strip().strip('"')
    m = EMAIL_RE.search(s)
    if m and ("<" in s or " " in s):
        return None, m.group(0)
    if "\\" in s:
        dom, user = s.split("\\", 1)
        return dom.strip() or None, user.strip()
    return None, s


def is_builtin(raw: str) -> bool:
    dom, user = split_account(raw)
    u = user.lower()
    return (u in BUILTIN_ACCOUNTS or u.endswith("$") or (dom or "").lower() in BUILTIN_DOMAINS
            or u.startswith(("dwm-", "umfd-")))


def user_ref(raw: str | None, *, default_domain: str | None = None, role: str = "user") -> EntityRef | None:
    if not raw or is_builtin(str(raw)):
        return None
    dom, user = split_account(str(raw))
    u = user.lower()
    keys: dict[str, str] = {}
    if "@" in u:
        keys["upn"] = u  # never derive a SAM key from a UPN prefix: another person may own that SAM
    attrs: dict[str, str] = {"display_name": user}
    if dom:
        attrs["account_domain"] = dom
    if "@" not in u:
        keys["sam"] = u
        if default_domain:
            # Lookup-only hint: never registered as a key (it may belong to someone else), see resolver.
            attrs["derived_upn"] = f"{u}@{default_domain.lower()}"
    return EntityRef(kind="identity", role=role, keys=keys, attributes=attrs)


def email_aliases(proxy_addresses: list[str] | None, other: list[str] | None = None) -> list[str]:
    """Entra ``proxyAddresses`` (``SMTP:``/``smtp:`` prefixed) + ``otherMails`` -> lower-cased addresses."""
    out = set()
    for p in (proxy_addresses or []):
        if str(p).lower().startswith("smtp:"):
            out.add(str(p)[5:].lower())
    for o in (other or []):
        if "@" in str(o):
            out.add(str(o).lower())
    return sorted(out)
