import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.cve_hypotheses import build_cve_hypotheses


class CveHypothesisTests(unittest.TestCase):
    def test_web_logic_ws_utc_upload_evidence_produces_cve_2018_2894_candidate(self) -> None:
        candidates = build_cve_hypotheses(
            target="http://authorized-lab.example/ws_utc/config.do",
            vulnerabilities=[
                {
                    "title": "Unauthenticated WebLogic ws_utc settings access",
                    "description": "The keystore configuration endpoint accepts file upload requests without authentication.",
                }
            ],
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["cve_id"], "CVE-2018-2894")
        self.assertEqual(candidates[0]["verification_status"], "candidate")
        self.assertEqual(candidates[0]["source"], "cve_hypothesis")

    def test_phpmyadmin_sql_behavior_produces_cve_2020_5504_candidate(self) -> None:
        candidates = build_cve_hypotheses(
            target="http://authorized-lab.example/pma/",
            vulnerabilities=[
                {
                    "title": "SQL injection in phpMyAdmin search",
                    "description": "The search query is concatenated into SQL.",
                }
            ],
        )

        self.assertEqual([candidate["cve_id"] for candidate in candidates], ["CVE-2020-5504"])

    def test_phpmyadmin_setup_exposure_does_not_guess_sql_injection_cve(self) -> None:
        candidates = build_cve_hypotheses(
            target="http://authorized-lab.example/pma/",
            vulnerabilities=[
                {
                    "title": "Unauthenticated phpMyAdmin Setup Page",
                    "description": "The setup interface is exposed.",
                }
            ],
        )

        self.assertEqual(candidates, [])

    def test_planning_text_alone_does_not_count_as_file_upload_behavior(self) -> None:
        candidates = build_cve_hypotheses(
            target="http://authorized-lab.example/ws_utc/config.do",
            vulnerabilities=[
                {
                    "title": "Unauthenticated WebLogic settings access",
                    "description": "The settings page is public, but the upload attempt failed.",
                }
            ],
        )

        self.assertEqual(candidates, [])

    def test_sanitized_candidate_evidence_can_map_to_cve_before_formal_report(self) -> None:
        candidates = build_cve_hypotheses(
            target="http://authorized-lab.example/ws_utc/config.do",
            vulnerabilities=[],
            candidate_evidence=[
                {
                    "title": "WebLogic ws_utc upload behavior",
                    "evidence": (
                        "Unauthenticated request to the keystore file upload endpoint returned status 200."
                    ),
                }
            ],
        )

        self.assertEqual([candidate["cve_id"] for candidate in candidates], ["CVE-2018-2894"])


if __name__ == "__main__":
    unittest.main()
