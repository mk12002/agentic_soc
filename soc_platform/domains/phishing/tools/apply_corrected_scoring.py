"""
Post-processing script to apply corrected BEC fraud detection logic to audit results.

Reads raw agent scores from existing audits and applies improved decision logic
without needing to rebuild Docker containers.
"""
import json
import sys
from pathlib import Path
from collections import Counter
from typing import Any


def _contains_bec_signals(agent_results: list[dict[str, Any]]) -> bool:
    """Check if email has classic BEC/wire fraud signals."""
    all_indicators = []
    for agent in agent_results:
        all_indicators.extend([str(i).lower() for i in (agent.get("indicators") or [])])
    
    indicators_text = "\n".join(all_indicators)
    
    # Use more lenient keyword matching - if we see any 2+ of these it's likely BEC
    bec_keywords = ["wire", "transfer", "payment", "urgent", "immediate", "asap", 
                    "financial", "bank", "confidential", "urgent"]
    
    keyword_count = sum(1 for kw in bec_keywords if kw in indicators_text.lower())
    return keyword_count >= 2


def _has_multi_agent_fraud_agreement(agent_results: list[dict[str, Any]]) -> bool:
    """If 2+ agents detect elevated risk, it's likely fraud."""
    agent_scores = {item.get("agent_name", ""): float(item.get("risk_score", 0.0)) 
                   for item in agent_results}
    
    elevated_agents = sum(1 for score in agent_scores.values() if score >= 0.3)
    return elevated_agents >= 2


def apply_corrected_logic(report: dict[str, Any]) -> dict[str, Any]:
    """Apply improved decision logic to a report."""
    agent_results = report.get('agent_results', [])
    current_verdict = report.get('verdict', 'unknown')
    current_score = float(report.get('overall_risk_score', 0.0))
    
    # If already malicious, keep it
    if current_verdict == 'malicious':
        return report
    
    # If suspicious AND shows BEC signals -> escalate to high_risk
    if current_verdict == 'suspicious' and current_score >= 0.40:
        if _contains_bec_signals(agent_results) or _has_multi_agent_fraud_agreement(agent_results):
            report['verdict'] = 'high_risk'
            report['overall_risk_score'] = max(current_score, 0.60)
            report['corrected'] = True
            report['correction_reason'] = 'bec_fraud_escalation'
            if 'recommended_actions' not in report:
                report['recommended_actions'] = []
            if 'quarantine' not in report['recommended_actions']:
                report['recommended_actions'].extend(['quarantine', 'soc_alert', 'trigger_garuda'])
    
    return report


def process_audit_results(audit_dir: Path) -> dict[str, Any]:
    """Process audit results and apply corrected logic."""
    results_file = audit_dir / 'batch_audit_results.json'
    
    if not results_file.exists():
        print(f"Error: {results_file} not found")
        return {}
    
    with open(results_file) as f:
        data = json.load(f)
    
    # Apply correction to each result
    corrected_count = 0
    for result in data['results']:
        if result.get('status') == 'ok' and isinstance(result.get('report'), dict):
            old_verdict = result['report'].get('verdict')
            result['report'] = apply_corrected_logic(result['report'])
            if result['report'].get('corrected'):
                corrected_count += 1
            if result['report'].get('verdict') != old_verdict:
                print(f"  Corrected: {result['report'].get('internet_message_id', 'N/A')} "
                      f"{old_verdict} -> {result['report'].get('verdict')}")
    
    # Save corrected results
    output_file = audit_dir / 'batch_audit_results_corrected.json'
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nCorrected {corrected_count} verdicts")
    print(f"Saved to: {output_file}")
    
    # Print verdict distribution
    verdicts = Counter()
    for result in data['results']:
        if result.get('status') == 'ok' and isinstance(result.get('report'), dict):
            v = result['report'].get('verdict', 'unknown')
            verdicts[v] += 1
    
    print("\n=== CORRECTED VERDICT DISTRIBUTION ===")
    for v in ['malicious', 'high_risk', 'suspicious', 'likely_safe', 'safe']:
        print(f"  {v}: {verdicts.get(v, 0)}")
    print(f"  TOTAL: {sum(verdicts.values())}")
    
    return {'verdicts': dict(verdicts), 'corrected': corrected_count, 'output_file': str(output_file)}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python apply_corrected_scoring.py <audit_dir>")
        print("Example: python apply_corrected_scoring.py analysis_reports/batch_eml_audit_20260513_052631")
        sys.exit(1)
    
    audit_dir = Path(sys.argv[1])
    if not audit_dir.exists():
        audit_dir = Path.cwd() / sys.argv[1]
    
    print(f"Processing: {audit_dir}")
    result = process_audit_results(audit_dir)
    
    if result:
        print(f"\nProcessing complete. {result['corrected']} emails corrected.")
