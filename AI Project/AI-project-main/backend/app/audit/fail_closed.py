from typing import Dict, Any, List, Optional
from backend.app.models.core import Decision, FirewallDecision, Finding, Severity, SourceType
from backend.app.config import settings
from datetime import datetime

class FailClosedHandler:
    """
    Ensures that any system failure results in a safe BLOCK decision.
    """
    @staticmethod
    def handle_failure(request_id: str, component: str, exception: Exception) -> FirewallDecision:
        """
        Transforms a system exception into a safe, audited BLOCK decision.
        """
        return FirewallDecision(
            request_id=request_id,
            decision=Decision.BLOCK,
            score=100.0,
            findings=[
                Finding(
                    rule_id="SYS-FAIL-001",
                    category="FIREWALL_INTERNAL_FAILURE",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    evidence=f"Exception in {component}: {str(exception)}",
                    source=SourceType.SYSTEM,
                    location=0
                )
            ],
            transformations=[],
            reason=f"Security Decision Fail-Closed: Internal error in {component}."
        )
