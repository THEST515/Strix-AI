import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.domain.models import Finding, ScanReport, ScanTask, TaskStatus


class ScanTaskTests(unittest.TestCase):
    def test_new_task_defaults_to_draft_status(self) -> None:
        task = ScanTask(
            task_id="task-001",
            name="demo task",
            target="./demo-app",
        )

        self.assertEqual(task.status, TaskStatus.DRAFT)

    def test_task_can_move_to_next_status(self) -> None:
        task = ScanTask(
            task_id="task-001",
            name="demo task",
            target="./demo-app",
        )

        task = task.with_status(TaskStatus.RUNNING)

        self.assertEqual(task.status, TaskStatus.RUNNING)


class ScanReportTests(unittest.TestCase):
    def test_severity_counts_are_aggregated(self) -> None:
        report = ScanReport(
            task_id="task-001",
            findings=[
                Finding(
                    finding_id="f-1",
                    title="Broken Access Control",
                    severity="critical",
                    summary="Access control bypass",
                    evidence="PoC available",
                    remediation="Validate object ownership",
                ),
                Finding(
                    finding_id="f-2",
                    title="Reflected XSS",
                    severity="high",
                    summary="Input reflected unsafely",
                    evidence="Payload executed",
                    remediation="Encode reflected output",
                ),
                Finding(
                    finding_id="f-3",
                    title="Verbose Error Leak",
                    severity="high",
                    summary="Stack trace exposed",
                    evidence="500 response leaks trace",
                    remediation="Harden error handling",
                ),
            ],
        )

        self.assertEqual(
            report.severity_counts(),
            {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        )

    def test_candidate_findings_are_excluded_from_confirmed_counts(self) -> None:
        report = ScanReport(
            task_id="task-002",
            findings=[
                Finding(
                    finding_id="confirmed-1",
                    title="Confirmed issue",
                    severity="high",
                    summary="summary",
                    evidence="evidence",
                    remediation="remediation",
                ),
                Finding(
                    finding_id="note-1",
                    title="Candidate evidence",
                    severity="high",
                    summary="summary",
                    evidence="evidence",
                    remediation="remediation",
                    verification_status="candidate",
                    source="strix_note",
                ),
            ],
        )

        self.assertEqual(report.severity_counts()["high"], 1)
        self.assertEqual(report.confirmed_count(), 1)
        self.assertEqual(report.candidate_count(), 1)


if __name__ == "__main__":
    unittest.main()
