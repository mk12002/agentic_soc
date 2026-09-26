#!/usr/bin/env python3
"""Smoke test for the Header Agent using realistic email header scenarios.

Tests the FULL pipeline: raw header dict → feature_extractor → model → agent fusion.
Each test case simulates a real email with headers as they would arrive in production.

Usage:
    cd <repo root>
    python scripts/smoke_test_header_model.py
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.agents.header_agent.agent import analyze
from soc_platform.domains.phishing.engine.agents.header_agent.feature_extractor import extract_features
from soc_platform.domains.phishing.engine.agents.header_agent.model_loader import load_model

# ─────────────────────────────────────────────────────────────────────────────
# Realistic test scenarios
# ─────────────────────────────────────────────────────────────────────────────

TEST_CASES: list[dict[str, Any]] = [
    # ── CLEARLY LEGITIMATE ──
    {
        "name": "Legitimate corporate email (Google, all auth pass)",
        "expected": "safe",
        "data": {
            "headers": {
                "sender": "noreply@google.com",
                "from": "Google Security <noreply@google.com>",
                "reply_to": "noreply@google.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from mail-wr1-f54.google.com (2a00:1450:4864:20::336) by mx.example.com",
                    "from internal-relay.google.com by mail-wr1-f54.google.com",
                    "from smtp.google.com by internal-relay.google.com",
                ],
            },
        },
    },
    {
        "name": "Legitimate newsletter (Substack, all auth pass)",
        "expected": "safe",
        "data": {
            "headers": {
                "sender": "newsletter@substack.com",
                "from": "Tech Weekly <newsletter@substack.com>",
                "reply_to": "newsletter@substack.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from o1.email.substack.com by mx.gmail.com",
                    "from mailer.substack.com by o1.email.substack.com",
                ],
            },
        },
    },
    {
        "name": "Internal company email (short domain, 5 hops, all pass)",
        "expected": "safe",
        "data": {
            "headers": {
                "sender": "hr@acme.com",
                "from": "HR Department <hr@acme.com>",
                "reply_to": "",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "hop1", "hop2", "hop3", "hop4", "hop5",
                ],
            },
        },
    },

    # ── CLEARLY PHISHING ──
    {
        "name": "Classic phishing: all auth fail, lookalike domain",
        "expected": "phishing",
        "data": {
            "headers": {
                "sender": "support@paypa1.com",
                "from": "PayPal Support <support@paypa1.com>",
                "reply_to": "collect@freemail.xyz",
                "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
                "received": [
                    "from unknown-relay.xyz by mx.victim.com",
                ],
            },
        },
    },
    {
        "name": "Phishing: SPF softfail, display name spoofs Microsoft",
        "expected": "phishing",
        "data": {
            "headers": {
                "sender": "alert@m1crosoft-security.xyz",
                "from": "Microsoft Account Team <alert@m1crosoft-security.xyz>",
                "reply_to": "reply@throwaway.tk",
                "authentication_results": "spf=softfail; dkim=fail; dmarc=fail",
                "received": [
                    "from vps-node.hostingxyz.com by mx.target.com",
                    "from relay.hostingxyz.com by vps-node.hostingxyz.com",
                ],
            },
        },
    },
    {
        "name": "Phishing: credential harvester, random long domain",
        "expected": "phishing",
        "data": {
            "headers": {
                "sender": "verify@secure-account-update-login-x7f9k.buzz",
                "from": "Account Security <verify@secure-account-update-login-x7f9k.buzz>",
                "reply_to": "harvester@darknet.ml",
                "authentication_results": "spf=fail; dkim=none; dmarc=fail",
                "received": [
                    "from compromised.server.in by mx.company.com",
                ],
            },
        },
    },

    # ── TRICKY EDGE CASES ──
    {
        "name": "EDGE: Legitimate but SPF softfail (forwarded email)",
        "expected": "safe",
        "data": {
            "headers": {
                "sender": "boss@company.org",
                "from": "Jane Smith <boss@company.org>",
                "reply_to": "boss@company.org",
                "authentication_results": "spf=softfail; dkim=pass; dmarc=pass",
                "received": [
                    "from mx.forwarder.com by mx.dest.com",
                    "from smtp.company.org by mx.forwarder.com",
                    "from internal.company.org by smtp.company.org",
                ],
            },
        },
    },
    {
        "name": "EDGE: Auth passes but reply-to is different domain",
        "expected": "suspicious",
        "data": {
            "headers": {
                "sender": "sales@legit-vendor.com",
                "from": "Sales Team <sales@legit-vendor.com>",
                "reply_to": "invoices@totally-different-company.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from mail.legit-vendor.com by mx.target.com",
                    "from smtp.legit-vendor.com by mail.legit-vendor.com",
                ],
            },
        },
    },
    {
        "name": "EDGE: Lookalike 'amazom.com' but SPF passes (compromised domain)",
        "expected": "phishing",
        "data": {
            "headers": {
                "sender": "orders@amazom.com",
                "from": "Amazon Orders <orders@amazom.com>",
                "reply_to": "orders@amazom.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from smtp.amazom.com by mx.victim.com",
                    "from relay.amazom.com by smtp.amazom.com",
                ],
            },
        },
    },
    {
        "name": "EDGE: No auth results at all (legacy mail server)",
        "expected": "suspicious",
        "data": {
            "headers": {
                "sender": "admin@oldcompany.net",
                "from": "System Admin <admin@oldcompany.net>",
                "reply_to": "",
                "authentication_results": "",
                "received": [
                    "from old-smtp.oldcompany.net by mx.modern.com",
                ],
            },
        },
    },
    {
        "name": "EDGE: Display name says 'Apple' but sender is random domain",
        "expected": "phishing",
        "data": {
            "headers": {
                "sender": "noreply@xk49fj-services.top",
                "from": "Apple ID Support <noreply@xk49fj-services.top>",
                "reply_to": "noreply@xk49fj-services.top",
                "authentication_results": "spf=fail; dkim=fail; dmarc=none",
                "received": [
                    "from vps12.cheaphost.cc by mx.icloud.com",
                ],
            },
        },
    },
    {
        "name": "EDGE: Everything looks perfect except single hop",
        "expected": "suspicious",
        "data": {
            "headers": {
                "sender": "friend@gmail.com",
                "from": "friend@gmail.com",
                "reply_to": "friend@gmail.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from unknown-server by mx.dest.com",
                ],
            },
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def _risk_label(score: float) -> str:
    if score >= 0.6:
        return "PHISHING"
    if score >= 0.3:
        return "SUSPICIOUS"
    return "SAFE"


def main() -> None:
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    report_dir = REPO_ROOT / "analysis_reports" / f"header_smoke_test_{stamp}"
    report_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("  HEADER AGENT SMOKE TEST — Real-World Scenarios")
    print("=" * 80)
    print()

    # Load model once to verify it works
    model_bundle = load_model()
    if model_bundle is None:
        print("⚠️  No trained model found! Tests will run in heuristic-only mode.")
    else:
        kind = model_bundle.get("kind", "unknown") if isinstance(model_bundle, dict) else type(model_bundle).__name__
        print(f"✓ Model loaded: {kind}")
    print()

    results: list[dict[str, Any]] = []
    pass_count = 0
    fail_count = 0
    warn_count = 0

    for idx, tc in enumerate(TEST_CASES, start=1):
        name = tc["name"]
        expected = tc["expected"].lower()
        data = tc["data"]

        print(f"─── Test {idx}/{len(TEST_CASES)}: {name} ───")

        # Log raw input
        headers = data.get("headers", {})
        print(f"  Sender:          {headers.get('sender', 'N/A')}")
        print(f"  From:            {headers.get('from', 'N/A')}")
        print(f"  Reply-To:        {headers.get('reply_to', 'N/A') or '(empty)'}")
        print(f"  Auth:            {headers.get('authentication_results', 'N/A') or '(empty)'}")
        print(f"  Received hops:   {len(headers.get('received', []))}")

        # Extract features (intermediate step log)
        features = extract_features(data)
        vec = features["numeric_vector"].flatten().tolist()
        feature_names = [
            "spf_pass", "dkim_pass", "dmarc_pass", "sender_domain_len",
            "display_name_mismatch", "hop_count", "reply_to_mismatch", "sender_domain_entropy",
        ]
        print(f"  Features:        {dict(zip(feature_names, [round(v, 4) for v in vec]))}")

        # Run full agent analysis
        t0 = time.perf_counter()
        result = analyze(data)
        latency_ms = (time.perf_counter() - t0) * 1000

        risk = result["risk_score"]
        confidence = result["confidence"]
        indicators = result["indicators"]
        predicted_label = _risk_label(risk)

        print(f"  Risk Score:      {risk:.4f}")
        print(f"  Confidence:      {confidence:.4f}")
        print(f"  Predicted:       {predicted_label}")
        print(f"  Expected:        {expected.upper()}")
        print(f"  Indicators:      {indicators}")
        print(f"  Latency:         {latency_ms:.1f} ms")

        # Evaluate
        expected_norm = expected.upper()
        if predicted_label == expected_norm:
            status = "✅ PASS"
            pass_count += 1
        elif expected_norm == "SUSPICIOUS":
            # Suspicious is acceptable as either safe or phishing depending on thresholds
            status = "⚠️  WARN (edge case)"
            warn_count += 1
        else:
            status = "❌ FAIL"
            fail_count += 1

        print(f"  Result:          {status}")
        print()

        results.append({
            "test_id": idx,
            "name": name,
            "expected": expected,
            "predicted": predicted_label.lower(),
            "risk_score": risk,
            "confidence": confidence,
            "indicators": indicators,
            "features": dict(zip(feature_names, [round(v, 4) for v in vec])),
            "latency_ms": round(latency_ms, 1),
            "status": status,
        })

    # ── Summary ──
    print("=" * 80)
    print(f"  RESULTS: {pass_count} PASS / {warn_count} WARN / {fail_count} FAIL  (out of {len(TEST_CASES)})")
    print("=" * 80)
    print()

    if fail_count == 0:
        print("✅ All critical tests passed!")
    else:
        print(f"❌ {fail_count} test(s) failed — review the output above.")

    # ── Save report ──
    report = {
        "timestamp_utc": stamp,
        "model_loaded": model_bundle is not None,
        "total_tests": len(TEST_CASES),
        "passed": pass_count,
        "warned": warn_count,
        "failed": fail_count,
        "results": results,
    }
    report_path = report_dir / "smoke_test_results.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # CSV for easy review
    import csv
    csv_path = report_dir / "smoke_test_detailed.csv"
    with open(csv_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "test_id", "name", "expected", "predicted", "risk_score",
            "confidence", "indicators", "latency_ms", "status",
        ])
        writer.writeheader()
        for r in results:
            row = {k: v for k, v in r.items() if k != "features"}
            row["indicators"] = "; ".join(row["indicators"])
            writer.writerow(row)

    print(f"\nDetailed report:  {report_path}")
    print(f"CSV summary:      {csv_path}")


if __name__ == "__main__":
    main()
