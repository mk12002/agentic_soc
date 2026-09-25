"""Generate docs/CONNECTORS.md from the connector manifests (the code is the source of truth).

    python scripts/build_connector_docs.py
"""

from __future__ import annotations

from pathlib import Path

from soc_platform.connectors.registry import ConnectorRegistry, discover

OUT = Path(__file__).resolve().parents[1] / "docs" / "CONNECTORS.md"

HEAD = """# Connectors

Generated from the connector manifests by `scripts/build_connector_docs.py` - regenerate after changing a connector.

Every connector runs in one of two modes, set per connector in `config/connectors.yaml`:

* **fake** - replays vendor-shaped fixture responses (`soc_platform/fixtures/<name>.json`) through exactly the same
  parsing, normalisation, lookup and action code as live mode. Used for development, tests and demos.
* **live** - calls the vendor API with the credentials in the config (use `${ENV}` or `<NAME>_FILE` vault mounts,
  never literals).

**Verification status.** Every connector is implemented against the vendor's documented API and verified end to end
on fixtures shaped like the documented responses (`soc_platform/tests/test_connectors.py`). The public feeds (NVD,
EPSS, CISA KEV) are also verified live. The vendor connectors have **not yet been run against the client's tenants**: do
that per connector with the *Test* button (Connectors screen) or `POST /api/v1/connectors/{name}/test`, which
authenticates and reads one page. Items under *To confirm* are licence or permission questions for the client (A01, A03).

**Onboarding a tool (live):**

1. Create a dedicated service principal / API client with the read scopes listed (write scopes only for the
   actions you intend to approve).
2. Put the secrets in the vault and reference them from `config/connectors.yaml`, set `mode: live`.
3. Test the connection, then run one sync (`POST /api/v1/connectors/{name}/sync?stream=...`) and check the
   Integrations screen: records ingested, freshness, reconciliation against the tool's own total.
4. Actions stay at autonomy level L2 (recommend, human approves) until a policy change promotes them.

"""


def main() -> None:
    reg = ConnectorRegistry.all_fake()
    parts = [HEAD, "| Connector | Tool | Category | Streams | Lookups | Actions | Confidence |", "|---|---|---|---|---|---|---|"]
    rows = []
    for name, m in sorted(discover().items()):
        c = reg.get(name)
        acts = sorted({a.action_type for a in (m.actions(c) if m.actions else [])})
        parts.append(f"| `{name}` | {m.tool} | {m.category} | {', '.join(c.streams) or '-'} | "
                     f"{', '.join(getattr(c, 'lookups', ()) or ()) or '-'} | {', '.join(acts) or '-'} | {m.confidence} |")
        cfg = "\n".join(f"  - `{f.name}`{' (secret)' if f.secret else ''}{'' if f.required else ' (optional)'}: {f.description}"
                        for f in m.config) or "  - none"
        rows.append(f"### {m.tool} (`{name}`)\n\n{m.description}\n\n"
                    f"- Vendor: {m.vendor} · focus areas: {', '.join(m.focus_areas)}\n"
                    f"- Read scopes: {', '.join(getattr(c, 'read_scopes', ()) or ()) or 'see vendor docs / to confirm'}\n"
                    f"- Write scopes (only for approved actions): {', '.join(getattr(c, 'write_scopes', ()) or ()) or '-'}\n"
                    f"- To confirm with the client: {m.to_confirm or '-'}\n- Configuration:\n{cfg}\n")
    parts += ["", "## Per-connector setup", ""] + rows
    OUT.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"{len(rows)} connectors -> {OUT}")


if __name__ == "__main__":
    main()
