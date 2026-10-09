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
on fixtures shaped like the documented responses (`soc_platform/tests/test_connectors.py`). Request and response
formats were audited field by field against the vendors' public API references and public reference integrations
(round 14 in `docs/TEST_REPORT.md` lists what that audit corrected). The public feeds (NVD, EPSS, CISA KEV) are also
verified live. Beyond the documented shapes, every connector passes a conformance suite
(`soc_platform/tests/test_connector_conformance.py`, round 16): reading across pages in its vendor's own paging style,
resuming the next sync correctly (a time watermark with an overlap for late logs, or a fresh read - never an expired
continuation token), throttling with `Retry-After`, a refused token renewed once, a missing permission reported at
once, and every field of every record missing, null or of the wrong type (a malformed field is conformed to the
stream's documented shape and reported, never fatal to the record). The demo fixtures are one scripted scenario, far smaller and
tidier than a tenant; `scripts/build_estate_variant.py --messy --scale N` generates large, disorderly estates for
volume tests, and record-and-sanitise (`SOC_RECORD_FIXTURES_DIR`) turns the first live responses into fixtures.
The vendor connectors have **not yet been run against the client's tenants**: do that per connector with
the *Preflight* button (Integrations screen), `python -m soc_platform preflight <name>` or
`POST /api/v1/config/connectors/{name}/preflight`, which checks sign-in, every stream and the permission it needs,
parsing, data freshness and volume, and says how to fix each failure. Items under *To confirm* are licence or
permission questions for the client (A01, A03). Step-by-step onboarding of every tool in the client's environment:
`docs/CLIENT_DEPLOYMENT_GUIDE.md`.

**Onboarding a tool (live):**

1. Create a dedicated service principal / API client with the read scopes listed (write scopes only for the
   actions you intend to approve).
2. Put the secrets in the vault (or environment) under the names *Integrations -> Configure* shows (convention
   `<CONNECTOR>_<SETTING>`); they are never typed into the console.
3. *Configure*: the non-secret settings and the stage **Recording** or **Read-only**; propose. The preflight runs on the
   proposal; a lead approves; it applies within seconds, no restart. (Or `stage: read` in `config/connectors.yaml`.)
4. Check the Integrations screen: records ingested, freshness, reconciliation against the tool's own total.
5. Promote to **Recommend** (actions offered, never above L2), later **Automate** (the autonomy policy decides).

**Adding a tool that has no connector:** `python -m soc_platform connector new <name> --category <cat> --tool "Vendor
Product"` writes a connector that already follows the platform's rules, its fixtures, its paging test and a switched-off
config entry; adapt the endpoints and fields, then `python -m soc_platform connector check <name>`.

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
