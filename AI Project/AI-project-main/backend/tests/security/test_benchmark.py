import json
import unittest
from backend.app.pipeline.orchestrator import FirewallPipeline
from backend.app.models.core import Decision

class SecurityBenchmark(unittest.TestCase):
    def setUp(self):
        self.pipeline = FirewallPipeline()
        with open("dataset/security_benchmark.json", "r") as f:
            self.dataset = json.load(f)

    def test_run_benchmark(self):
        results = []
        passed = 0
        failed = 0

        print("\n--- Security Benchmark Report ---")
        print(f"{'Test Name':<40} | {'Expected':<10} | {'Actual':<10} | {'Result'}")
        print("-" * 75)

        for entry in self.dataset:
            name = entry["name"]
            request = entry["request"]
            expected = entry["expected_decision"]

            decision_obj = self.pipeline.process_request(request)
            actual = decision_obj.decision.value

            is_pass = (actual == expected)
            if is_pass:
                passed += 1
            else:
                failed += 1

            status = "PASS" if is_pass else "FAIL"
            print(f"{name:<40} | {expected:<10} | {actual:<10} | {status}")

            results.append({
                "name": name,
                "expected": expected,
                "actual": actual,
                "passed": is_pass
            })

        print("-" * 75)
        print(f"TOTAL: {len(self.dataset)} | PASSED: {passed} | FAILED: {failed}")
        print(f"DETECTION RATE: {(passed/len(self.dataset))*100:.2f}%")

        self.assertEqual(failed, 0, f"Benchmark failed {failed} cases.")

if __name__ == "__main__":
    unittest.main()
