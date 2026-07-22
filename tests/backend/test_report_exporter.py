import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.domain.models import Finding, ScanReport, ScanTask, TaskStatus
from src.backend.services.report_exporter import build_markdown_export


class ReportExporterTests(unittest.TestCase):
    def test_markdown_distinguishes_confirmed_and_candidate_findings(self) -> None:
        report = ScanReport(
            task_id="task-001",
            findings=[
                Finding("vuln-1", "Confirmed", "high", "summary", "evidence", "fix"),
                Finding(
                    "note-1",
                    "Candidate",
                    "info",
                    "summary",
                    "safe evidence",
                    "verify",
                    verification_status="candidate",
                    source="strix_note",
                ),
            ],
        )
        task = ScanTask(
            task_id="task-001",
            name="Authorized scan",
            target="http://authorized-lab.example",
            status=TaskStatus.PARTIAL,
        )

        content = build_markdown_export(
            task=task,
            report=report,
            summary={"executive_summary": "partial", "technical_analysis": "analysis", "recommendations": "next"},
        )

        self.assertIn("已确认：1", content)
        self.assertIn("待验证：1", content)
        self.assertIn("验证状态：已确认", content)
        self.assertIn("验证状态：待验证", content)


if __name__ == "__main__":
    unittest.main()
