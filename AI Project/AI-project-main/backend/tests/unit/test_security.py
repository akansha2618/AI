import unittest
from backend.app.audit.logger import AuditLogger
from backend.app.audit.fail_closed import FailClosedHandler
from backend.app.models.core import Decision, Severity
import os

class TestPhase7Security(unittest.TestCase):
    def setUp(self):
        self.logger = AuditLogger("test_audit.log")
        self.handler = FailClosedHandler()

    def tearDown(self):
        self.logger.close()
        if os.path.exists("test_audit.log"):
            os.remove("test_audit.log")

    def test_fail_closed_behavior(self):
        # Simulate a crash in the normalization engine
        try:
            raise RuntimeError("Unexpected memory corruption")
        except Exception as e:
            decision = self.handler.handle_failure("req-fail", "NormalizationEngine", e)

        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertEqual(decision.score, 100.0)
        self.assertEqual(decision.findings[0].category, "FIREWALL_INTERNAL_FAILURE")
        self.assertEqual(decision.findings[0].severity, Severity.CRITICAL)

    def test_audit_logging_flow(self):
        from backend.app.models.core import FirewallDecision, SourceType

        # Create a dummy decision
        decision = FirewallDecision(
            request_id="req-audit-123",
            decision=Decision.BLOCK,
            score=85.0,
            findings=[],
            transformations=[{"type": "unicode_nfkc"}],
            reason="Detected attack"
        )

        self.logger.log_decision(decision, {"user_input": "test"})

        with open("test_audit.log", "r") as f:
            content = f.read()
            self.assertIn("req-audit-123", content)
            self.assertIn("BLOCK", content)
            self.assertIn("unicode_nfkc", content)

if __name__ == "__main__":
    unittest.main()
