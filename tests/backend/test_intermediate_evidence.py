import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.intermediate_evidence import (
    load_candidate_findings,
    merge_confirmed_and_candidate_findings,
)


class IntermediateEvidenceTests(unittest.TestCase):
    def test_loads_qualifying_finding_note_and_redacts_secrets(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            state_dir = run_dir / ".state"
            state_dir.mkdir()
            (state_dir / "notes.json").write_text(
                json.dumps(
                    {
                        "evidence-1": {
                            "title": "Confirmed product access",
                            "content": (
                                "Version: 5.0.0\n"
                                "Default credentials found: admin:demo-secret\n"
                                "1. **Default credentials found**: root:123456\n"
                                "Session cookie: sid=live-cookie\n"
                                "CSRF Token: csrf-secret"
                            ),
                            "category": "findings",
                            "tags": ["product", "authentication"],
                        },
                        "method-1": {
                            "title": "Next steps",
                            "content": "Need to explore more routes",
                            "category": "methodology",
                            "tags": ["status"],
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            findings = load_candidate_findings(run_dir)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "note-evidence-1")
        self.assertEqual(findings[0]["verification_status"], "candidate")
        self.assertEqual(findings[0]["source"], "strix_note")
        self.assertNotIn("demo-secret", findings[0]["evidence"])
        self.assertNotIn("live-cookie", findings[0]["evidence"])
        self.assertNotIn("csrf-secret", findings[0]["evidence"])
        self.assertNotIn("123456", findings[0]["evidence"])
        self.assertIn("[REDACTED]", findings[0]["evidence"])

    def test_skips_speculative_and_non_finding_notes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            state_dir = run_dir / ".state"
            state_dir.mkdir()
            (state_dir / "notes.json").write_text(
                json.dumps(
                    {
                        "speculative": {
                            "title": "Possible issue",
                            "content": "Maybe vulnerable; need to test this later.",
                            "category": "findings",
                        },
                        "recon": {
                            "title": "Target map",
                            "content": "Version: 1.0",
                            "category": "methodology",
                        },
                    }
                ),
                encoding="utf-8",
            )

            findings = load_candidate_findings(run_dir)

        self.assertEqual(findings, [])

    def test_returns_empty_list_for_incomplete_notes_json(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            state_dir = run_dir / ".state"
            state_dir.mkdir()
            (state_dir / "notes.json").write_text("{", encoding="utf-8")

            findings = load_candidate_findings(run_dir)

        self.assertEqual(findings, [])

    def test_merge_deduplicates_candidate_findings_for_the_same_cve(self) -> None:
        candidates = [
            {
                "finding_id": "note-cve",
                "title": "Possible CVE-2018-2894",
                "severity": "info",
                "evidence": "CVE-2018-2894 matched the observed endpoint.",
            },
            {
                "finding_id": "hypothesis-cve-2018-2894",
                "title": "CVE-2018-2894 候选：WebLogic ws_utc 文件上传",
                "severity": "critical",
                "evidence": "Observed WebLogic ws_utc upload behavior.",
            },
        ]

        merged = merge_confirmed_and_candidate_findings([], candidates)

        self.assertEqual(len(merged), 1)
        self.assertIn("CVE-2018-2894", merged[0]["title"])


if __name__ == "__main__":
    unittest.main()
