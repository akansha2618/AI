from typing import List, Dict, Any
from backend.app.models.core import Finding, Decision, FirewallDecision, Severity
from backend.app.config import settings
import uuid
from datetime import datetime

class PolicyEngine:
    """
    The final decision-maker of the firewall.
    Maps Findings to an ALLOW/WARN/BLOCK decision using weighted scoring
    and invariant checks.
    """

    def __init__(self):
        # Map categories to their weights and caps as defined in the architecture
        self.category_weights = {
            "INSTRUCTION_OVERRIDE": (settings.WEIGHT_INSTRUCTION_OVERRIDE, settings.CAP_INSTRUCTION_OVERRIDE),
            "ROLE_MANIPULATION": (settings.WEIGHT_ROLE_MANIPULATION, settings.CAP_ROLE_MANIPULATION),
            "SYSTEM_PROMPT_EXTRACTION": (settings.WEIGHT_SYSTEM_PROMPT_EXTRACTION, settings.CAP_SYSTEM_PROMPT_EXTRACTION),
            "OBFUSCATION_ENCODING": (settings.WEIGHT_OBFUSCATION_ENCODING, settings.CAP_OBFUSCATION_ENCODING),
            "PROVENANCE_FORGERY": (float('inf'), float('inf')),
        }

    def evaluate(self, request_id: str, findings: List[Finding], transformations: List[Dict[str, Any]]) -> FirewallDecision:
        """
        Processes findings to reach a final decision.
        """
        # 1. Invariant Checks (Immediate BLOCK)
        for finding in findings:
            if finding.severity == Severity.CRITICAL or finding.category == "PROVENANCE_FORGERY":
                return FirewallDecision(
                    request_id=request_id,
                    decision=Decision.BLOCK,
                    score=100.0,
                    findings=findings,
                    transformations=transformations,
                    reason=f"Invariant violation: {finding.category} with {finding.severity.value} severity."
                )

        # 2. Weighted Score Calculation
        total_score = 0.0
        category_totals = {}

        for finding in findings:
            weight, cap = self.category_weights.get(finding.category, (10, 20))

            # Calculate contribution: weight * confidence
            contribution = weight * finding.confidence

            # Track totals per category for capping
            category_totals[finding.category] = category_totals.get(finding.category, 0.0) + contribution

        # Apply category caps
        for category, total in category_totals.items():
            _, cap = self.category_weights.get(category, (10, 20))
            total_score += min(total, cap)

        final_score = min(100.0, total_score)

        # 3. Decision Mapping
        if final_score >= settings.RISK_THRESHOLD_BLOCK:
            decision = Decision.BLOCK
            reason = f"Risk score {final_score:.1f} exceeds block threshold {settings.RISK_THRESHOLD_BLOCK}."
        elif final_score >= settings.RISK_THRESHOLD_WARN:
            decision = Decision.WARN
            reason = f"Risk score {final_score:.1f} exceeds warn threshold {settings.RISK_THRESHOLD_WARN}."
        else:
            decision = Decision.ALLOW
            reason = "No significant threats detected."

        return FirewallDecision(
            request_id=request_id,
            decision=decision,
            score=final_score,
            findings=findings,
            transformations=transformations,
            reason=reason
        )
