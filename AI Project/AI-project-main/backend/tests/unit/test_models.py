import unittest
from backend.app.models.core import SourceType, Severity, Decision, ContentSpan, Finding, FirewallDecision
from datetime import datetime

class TestPhase1Models(unittest.TestCase):
    def test_content_span_initialization(self):
        span = ContentSpan(source=SourceType.DATA, origin="web", original="hello")
        self.assertEqual(span.source, SourceType.DATA)
        self.assertEqual(span.original, "hello")
        self.assertEqual(span.normalized, "")
        self.assertFalse(span.tainted)

    def test_finding_initialization(self):
        finding = Finding(
            rule_id="R1",
            category="INJECTION",
            severity=Severity.HIGH,
            confidence=0.9,
            evidence="ignore",
            source=SourceType.USER,
            location=0
        )
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, 0.9)

    def test_decision_initialization(self):
        decision = FirewallDecision(
            request_id="123",
            decision=Decision.BLOCK,
            score=85.0,
            findings=[],
            transformations=[],
            reason="Critical Finding"
        )
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertEqual(decision.score, 85.0)

if __name__ == "__main__":
    unittest.main()
