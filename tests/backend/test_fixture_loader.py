import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.fixture_loader import load_fixture_report


class FixtureLoaderTests(unittest.TestCase):
    def test_loads_fixture_as_scan_report(self) -> None:
        fixture_path = ROOT / "tests" / "fixtures" / "strix_findings_sample.json"

        report = load_fixture_report(fixture_path)

        self.assertEqual(report.task_id, "fixture-task-001")
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(report.severity_counts()["high"], 1)
        self.assertEqual(report.severity_counts()["medium"], 1)


if __name__ == "__main__":
    unittest.main()
