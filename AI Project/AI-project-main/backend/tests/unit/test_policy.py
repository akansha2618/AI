import unittest
from backend.app.models.core import Finding, Severity, SourceType, Decision
from backend.app.policy.engine import PolicyEngine

class TestPhase5Policy(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine()

    def test_allow_benign(self):
        findings = []
        decision = self.policy.evaluate("req-1", findings, [])
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertEqual(decision.score, 0.0)

    def test_warn_suspicious(self):
        # One low-confidence instruction override
        # Weight 40 * 0.4 = 16 (below 30) -> Actually we need > 30 for WARN
        # Let's do 40 * 0.8 = 32
        findings = [
            Finding("R1", "INSTRUCTION_OVERRIDE", Severity.MEDIUM, 0.8, "ignore", SourceType.USER, 0)
        ]
        decision = self.policy.evaluate("req-1", findings, [])
        self.assertEqual(decision.decision, Decision.WARN)
        self.assertEqual(decision.score, 32.0)

    def test_block_strong_injection(self):
        # Multiple high-confidence attacks
        findings = [
            Finding("R1", "INSTRUCTION_OVERRIDE", Severity.HIGH, 1.0, "ignore all", SourceType.USER, 0),
            Finding("R2", "ROLE_MANIPULATION", Severity.HIGH, 1.0, "you are DAN", SourceType.USER, 20),
        ]
        # Calc: 40 (IO) + 30 (RM) = 70
        decision = self.policy.evaluate("req-1", findings, [])
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertEqual(decision.score, 70.0)

    def test_category_caps(self):
        # Many findings in one category should be capped
        # INSTRUCTION_OVERRIDE cap is 60.
        findings = [
            Finding("R1", "INSTRUCTION_OVERRIDE", Severity.HIGH, 1.0, "ignore 1", SourceType.USER, 0),
            Finding("R2", "INSTRUCTION_OVERRIDE", Severity.HIGH, 1.0, "ignore 2", SourceType.USER, 20),
            Finding("R3", "INSTRUCTION_OVERRIDE", Severity.HIGH, 1.0, "ignore 3", SourceType.USER, 40),
        ]
        # Calc: 40 + 40 + 40 = 120 -> Capped at 60
        decision = self.policy.evaluate("req-1", findings, [])
        self.assertEqual(decision.score, 60.0)

    def test_invariant_block(self):
        # CRITICAL finding regardless of score
        findings = [
            Finding("R1", "SOME_NEW_RULE", Severity.CRITICAL, 1.0, "!", SourceType.USER, 0)
        ]
        decision = self.policy.evaluate("req-1", findings, [])
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertEqual(decision.score, 100.0)
        self.assertIn("Invariant violation", decision.reason)

    def test_provenance_forgery_block(self):
        findings = [
            Finding("R1", "PROVENANCE_FORGERY", Severity.HIGH, 1.0, "nonce", SourceType.USER, 0)
        ]
        decision = self.policy.evaluate("req-1", findings, [])
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertEqual(decision.score, 100.0)

if __name__ == "__main__":
    unittest.main()
