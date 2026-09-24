#!/usr/bin/env python3
import sys, json, requests

aid = sys.argv[1]
try:
    resp = requests.get(f"http://localhost:8000/reports/{aid}", timeout=10)
    if resp.status_code == 404:
        print("Report NOT READY (404)")
        sys.exit(0)
    r = resp.json()
    print(f"Verdict: {r.get('verdict', 'N/A')}")
    print(f"Score: {r.get('overall_risk_score', 'N/A')}")
    print(f"Actions: {r.get('recommended_actions', [])}")
    agents = r.get("agent_results", [])
    print(f"Agents: {len(agents)}")
    print(f"Reason: {r.get('finalization_reason', 'N/A')}")
    for x in agents:
        n = x.get("agent_name", "?")
        rs = float(x.get("risk_score", 0))
        c = float(x.get("confidence", 0))
        inds = x.get("indicators", [])[:3]
        print(f"  {n:<25} risk={rs:.2f} conf={c:.2f} inds={inds}")
except Exception as e:
    print(f"ERROR: {e}")
