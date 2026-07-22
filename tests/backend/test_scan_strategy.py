import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.scan_strategy import build_effective_instruction


class ScanStrategyTests(unittest.TestCase):
    def test_five_minute_strategy_prioritizes_cve_validation_and_immediate_reporting(self) -> None:
        instruction = build_effective_instruction(
            scan_mode="standard",
            timeout_seconds=300,
            user_instruction=None,
        )

        self.assertIn("300 seconds", instruction)
        self.assertIn("240 seconds", instruction)
        self.assertIn("known CVE", instruction)
        self.assertIn("report each confirmed finding immediately", instruction.lower())
        self.assertIn("before pursuing deeper exploit chains", instruction)

    def test_strategy_appends_user_constraint_after_platform_rules(self) -> None:
        instruction = build_effective_instruction(
            scan_mode="standard",
            timeout_seconds=300,
            user_instruction="Do not modify data.",
        )

        self.assertLess(instruction.index("Platform scan priorities"), instruction.index("User constraints"))
        self.assertTrue(instruction.endswith("Do not modify data."))

    def test_unlimited_strategy_does_not_claim_a_deadline(self) -> None:
        instruction = build_effective_instruction(
            scan_mode="standard",
            timeout_seconds=None,
            user_instruction=None,
        )

        self.assertIn("no platform deadline", instruction)
        self.assertNotIn("300 seconds", instruction)

    def test_long_standard_scan_still_requires_autonomous_cve_mapping_and_bounded_follow_up(self) -> None:
        instruction = build_effective_instruction(
            scan_mode="standard",
            timeout_seconds=900,
            user_instruction=None,
        )

        self.assertIn("without waiting for a user-specified CVE", instruction)
        self.assertIn("product, version, and high-value endpoint", instruction)
        self.assertIn("at most three focused follow-up turns", instruction)


if __name__ == "__main__":
    unittest.main()
