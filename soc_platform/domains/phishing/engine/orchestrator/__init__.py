"""
Orchestrator package for the Agentic Email Security System.

Coordinates agent execution, threat correlation, and scoring.
"""

from soc_platform.domains.phishing.engine.orchestrator.decision_engine import make_decision
from soc_platform.domains.phishing.engine.orchestrator.langgraph_state import OrchestratorState
from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator
from soc_platform.domains.phishing.engine.orchestrator.threat_correlation import correlate_threats
from soc_platform.domains.phishing.engine.orchestrator.scoring_engine import calculate_threat_score

__all__ = [
	"make_decision",
	"correlate_threats",
	"calculate_threat_score",
	"OrchestratorState",
	"LangGraphOrchestrator",
]
