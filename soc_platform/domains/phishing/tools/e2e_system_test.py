from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
#!/usr/bin/env python3
"""Comprehensive E2E system test — ingest 5 diverse emails and collect full analysis."""

import sys
import time
import requests

API = "http://localhost:8000"

# 5 diverse test emails covering different threat categories
SAMPLES = [
    {
        "label": "SPEARPHISHING_CREDS",
        "expected": "malicious/high_risk",
        "path": str(PHISHING_HOME / "samples" / "test_spearphishing_creds.eml"),
        "desc": "Spam phishing with free adult site credential lure",
    },
    {
        "label": "BEC_WIRE_TRANSFER",
        "expected": "malicious/high_risk",
        "path": str(PHISHING_HOME / "samples" / "test_bec_wire_transfer.eml"),
        "desc": "BEC/419 scam — 'Seeking Your Partnership' advance fee fraud",
    },
    {
        "label": "MALSPAM_INVOICE",
        "expected": "malicious/high_risk",
        "path": str(PHISHING_HOME / "samples" / "test_malspam_invoice.eml"),
        "desc": "419 scam from Ivory Coast seeking urgent financial assistance",
    },
    {
        "label": "LEGIT_GITHUB",
        "expected": "safe/likely_safe",
        "path": str(PHISHING_HOME / "samples" / "test_legit_github.eml"),
        "desc": "Legitimate developer mailing list discussion (spambayes project)",
    },
    {
        "label": "ATTACHMENT_MALWARE",
        "expected": "malicious/suspicious",
        "path": str(PHISHING_HOME / "samples" / "00330.c5f7346dec1e6fe6ed324d8e78a2b46e.eml"),
        "desc": "Spam with MIME attachment (multipart mixed)",
    },
]

def ingest(path, label):
    try:
        with open(path, "rb") as f:
            resp = requests.post(f"{API}/ingest-raw-email", files={"file": (f"{label}.eml", f, "message/rfc822")}, timeout=15)
        data = resp.json()
        return data.get("analysis_id"), data.get("status")
    except Exception as e:
        return None, f"ERROR: {e}"

def get_report(analysis_id, retries=6, delay=5):
    for attempt in range(retries):
        try:
            resp = requests.get(f"{API}/reports/{analysis_id}", timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        time.sleep(delay)
    return None

def main():
    print("=" * 80)
    print("  AGENTIC EMAIL SECURITY SYSTEM — COMPREHENSIVE E2E TEST")
    print("=" * 80)
    print()

    # Phase 1: Health check
    print("[1/4] HEALTH CHECK")
    try:
        h = requests.get(f"{API}/health", timeout=5).json()
        print(f"  API:      {h['status']}")
        print(f"  RabbitMQ: {h['rabbitmq']['status']}")
        print(f"  Disk:     {h['disk']['status']} ({h['disk']['free_gb']} GB free, {h['disk']['usage_percent']}% used)")
        print()
    except Exception as e:
        print(f"  FAILED: {e}")
        sys.exit(1)

    # Phase 2: Ingest all samples
    print("[2/4] INGESTING 5 DIVERSE EMAIL SAMPLES")
    ids = {}
    for s in SAMPLES:
        aid, status = ingest(s["path"], s["label"])
        ids[s["label"]] = aid
        icon = "✓" if status == "received" else "✗"
        print(f"  {icon} {s['label']:<25} → {aid or 'FAILED'}  [{status}]")
    print()

    # Phase 3: Wait for processing
    print("[3/4] WAITING FOR AGENT PROCESSING (100s)...")
    time.sleep(100)
    print()

    # Phase 4: Collect and validate results
    print("[4/4] COLLECTING ANALYSIS RESULTS")
    print("=" * 80)
    results = []
    for s in SAMPLES:
        aid = ids.get(s["label"])
        if not aid:
            results.append({"label": s["label"], "status": "INGEST_FAILED"})
            continue

        report = get_report(aid)
        if not report:
            results.append({"label": s["label"], "analysis_id": aid, "status": "REPORT_NOT_READY"})
            continue

        verdict = report.get("verdict", "unknown")
        score = report.get("overall_risk_score", 0.0)
        actions = report.get("recommended_actions", [])
        agents = report.get("agent_results", [])
        storyline = report.get("threat_storyline", [])
        counterfactual = report.get("counterfactual_result", {})
        llm_expl = report.get("llm_explanation", "")
        decision_notes = report.get("decision_notes", [])
        expected_verdicts = s["expected"].split("/")
        is_correct = verdict in expected_verdicts

        print()
        print(f"  {'─' * 76}")
        print(f"  SAMPLE: {s['label']}")
        print(f"  Description: {s['desc']}")
        print(f"  Analysis ID: {aid}")
        print(f"  {'─' * 76}")
        print(f"  Verdict:       {verdict.upper()}")
        print(f"  Risk Score:    {score:.4f}")
        print(f"  Expected:      {s['expected']}")
        print(f"  Correct:       {'✓ YES' if is_correct else '✗ NO'}")
        print(f"  Actions:       {', '.join(actions) if actions else 'none'}")
        print(f"  Agent Count:   {len(agents)}/7")
        print(f"  Storyline:     {len(storyline)} phases")
        print(f"  Counterfactual:{' present' if counterfactual and counterfactual.get('is_counterfactual') else ' none'}")
        if decision_notes:
            print(f"  Notes:         {', '.join(decision_notes)}")
        print()

        # Per-agent breakdown
        print(f"  {'Agent':<25} {'Risk':>6}  {'Conf':>6}  Indicators")
        print(f"  {'─' * 70}")
        for a in agents:
            name = a.get("agent_name", "?")
            risk = float(a.get("risk_score", 0))
            conf = float(a.get("confidence", 0))
            inds = a.get("indicators", [])
            top3 = inds[:3]
            ind_str = "; ".join(str(i)[:50] for i in top3) if top3 else "—"
            print(f"  {name:<25} {risk:>6.2f}  {conf:>6.2f}  {ind_str}")

        if llm_expl:
            preview = llm_expl[:200].replace("\n", " ")
            print(f"\n  LLM Explanation: {preview}...")

        results.append({
            "label": s["label"],
            "analysis_id": aid,
            "verdict": verdict,
            "score": score,
            "expected": s["expected"],
            "correct": is_correct,
            "agent_count": len(agents),
            "actions": actions,
            "storyline_phases": len(storyline),
        })

    # Summary
    print()
    print("=" * 80)
    print("  FINAL SUMMARY")
    print("=" * 80)
    total = len(results)
    correct = sum(1 for r in results if r.get("correct"))
    full_agents = sum(1 for r in results if r.get("agent_count") == 7)
    print(f"  Verdict Accuracy:  {correct}/{total}")
    print(f"  Full Agent Runs:   {full_agents}/{total}")
    print()
    for r in results:
        icon = "✓" if r.get("correct") else "✗"
        agents_icon = "7/7" if r.get("agent_count") == 7 else f"{r.get('agent_count', '?')}/7"
        print(f"  {icon} {r['label']:<25} verdict={r.get('verdict','?'):<12} score={r.get('score',0):.2f}  agents={agents_icon}  actions={r.get('actions', [])}")
    print()
    print("=" * 80)

if __name__ == "__main__":
    main()
