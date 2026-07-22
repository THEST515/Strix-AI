import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.runtime_analyzer import analyze_runtime


class RuntimeAnalyzerTests(unittest.TestCase):
    def test_platform_failed_state_overrides_stale_running_run_status(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "stale-running",
                        "status": "running",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example"}],
                    }
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(
                run_dir,
                task_status="failed",
                target="http://authorized-lab.example",
            )

        self.assertEqual(runtime["phase"], "failed")
        self.assertEqual(runtime["run_status"], "running")

    def test_partial_state_reports_candidate_evidence(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / ".state").mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "partial-run",
                        "status": "running",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example"}],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / ".state" / "notes.json").write_text(
                json.dumps(
                    {
                        "evidence": {
                            "title": "Authenticated product access",
                            "content": "Version: 5.0.0 and successfully authenticated",
                            "category": "findings",
                        }
                    }
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(
                run_dir,
                task_status="partial",
                target="http://authorized-lab.example",
            )

        self.assertEqual(runtime["phase"], "partial")
        self.assertEqual(runtime["convergence"]["status"], "candidate_evidence")
        self.assertEqual(runtime["evidence_progress"]["candidate_findings"], 1)
    def test_analyze_runtime_reports_surface_and_convergence_for_running_scan(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "scan-001",
                        "status": "running",
                        "start_time": "2026-07-07T10:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "https://authorized.example/login?redirect=%2Fhome"}],
                        "llm_usage": {
                            "requests": 14,
                            "total_tokens": 20480,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "\n".join(
                    [
                        "2026-07-07 10:00:01 DEBUG - openai.agents: Calling LLM",
                        "2026-07-07 10:00:02 INFO - browser: Opened page https://authorized.example/login?redirect=%2Fhome",
                        "2026-07-07 10:00:04 INFO - browser: Opened page https://authorized.example/api/profile?id=1",
                        "2026-07-07 10:00:06 DEBUG - openai.agents: Invoking tool fill_form",
                        "2026-07-07 10:00:08 DEBUG - openai.agents: Invoking tool wait_for_message",
                    ]
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(run_dir, task_status="running", target="https://authorized.example/login")

        self.assertEqual(runtime["phase"], "running")
        self.assertEqual(runtime["phase_label"], "攻击面分析")
        self.assertEqual(runtime["llm_usage"]["requests"], 14)
        self.assertGreaterEqual(runtime["attack_surface"]["pages"], 2)
        self.assertGreaterEqual(runtime["attack_surface"]["forms"], 1)
        self.assertGreaterEqual(runtime["attack_surface"]["parameters"], 2)
        self.assertGreaterEqual(runtime["attack_surface"]["api_endpoints"], 1)
        self.assertGreaterEqual(runtime["attack_surface"]["auth_points"], 1)
        self.assertEqual(runtime["convergence"]["status"], "surface_found_but_unverified")
        self.assertIsNone(runtime["failure_classification"])
        self.assertIn("收缩", runtime["recommended_next_action"])

    def test_analyze_runtime_classifies_environment_failure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "scan-002",
                        "status": "failed",
                        "start_time": "2026-07-07T11:00:00+00:00",
                        "end_time": "2026-07-07T11:20:00+00:00",
                        "targets_info": [{"original": "https://authorized.example/"}],
                        "llm_usage": {
                            "requests": 784,
                            "total_tokens": 46889902,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "\n".join(
                    [
                        "2026-07-07 11:40:41 INFO - strix.report.state: Added vulnerability report: vuln-0008 - Missing Authentication on Password Change Endpoint /UserManager/xgmm3",
                        "2026-07-07 11:41:20 INFO - strix.tools.reporting.tool: Vulnerability report created: id=vuln-0008 severity=critical",
                        "2026-07-07 12:01:45 ERROR - litellm.llms.custom_httpx.http_handler.MaskedHTTPStatusError: Client error '402 Payment Required' for url 'https://api.deepseek.com/beta/chat/completions'",
                    ]
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(run_dir, task_status="failed", target="https://authorized.example/")

        self.assertEqual(runtime["phase"], "failed")
        self.assertEqual(runtime["phase_label"], "证据整理")
        self.assertEqual(runtime["failure_classification"], "environment_failed")
        self.assertEqual(runtime["evidence_progress"]["validated_findings"], 1)
        self.assertEqual(runtime["convergence"]["status"], "validated_findings")
        self.assertIn("环境", runtime["recommended_next_action"])

    def test_analyze_runtime_classifies_completed_scan_without_findings(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "scan-003",
                        "status": "completed",
                        "start_time": "2026-07-07T12:00:00+00:00",
                        "end_time": "2026-07-07T12:10:00+00:00",
                        "targets_info": [{"original": "https://authorized.example/search?q=test"}],
                        "llm_usage": {
                            "requests": 26,
                            "total_tokens": 32000,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "\n".join(
                    [
                        "2026-07-07 12:00:01 DEBUG - openai.agents: Calling LLM",
                        "2026-07-07 12:00:03 INFO - browser: Opened page https://authorized.example/search?q=test",
                        "2026-07-07 12:00:05 DEBUG - openai.agents: Invoking tool finish_scan",
                        "2026-07-07 12:00:06 INFO - strix.tools.finish.tool: finish_scan: completed scan with 0 vulnerability report(s)",
                    ]
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(run_dir, task_status="completed", target="https://authorized.example/search?q=test")

        self.assertEqual(runtime["phase"], "completed")
        self.assertEqual(runtime["failure_classification"], "completed_without_findings")
        self.assertEqual(runtime["phase_label"], "证据整理")
        self.assertEqual(runtime["convergence"]["status"], "completed_without_findings")
        self.assertIn("结束", runtime["recommended_next_action"])

    def test_analyze_runtime_marks_post_finding_idle_rounds_separately(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "idle-after-finding",
                        "status": "running",
                        "start_time": "2026-07-20T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "https://authorized.example/"}],
                        "llm_usage": {"requests": 8, "total_tokens": 12000},
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "\n".join(
                    [
                        "2026-07-20 00:00:01 INFO - browser: Opened page https://authorized.example/",
                        "2026-07-20 00:00:05 INFO - strix.report.state: Added vulnerability report: vuln-1 - Missing Authentication",
                        "2026-07-20 00:00:06 INFO - strix.tools.reporting.tool: Vulnerability report created: id=vuln-1 severity=high",
                        "2026-07-20 00:00:07 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:08 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:09 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:10 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:11 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:12 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:13 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:14 DEBUG - openai.agents: Calling LLM",
                    ]
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(run_dir, task_status="running", target="https://authorized.example/")

        self.assertEqual(runtime["convergence"]["idle_rounds"], 8)
        self.assertEqual(runtime["convergence"]["status"], "validated_with_idle")
        self.assertIn("空转", runtime["recommended_next_action"])

    def test_function_tool_activity_resets_post_finding_idle_rounds(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "active-after-finding",
                        "status": "running",
                        "start_time": "2026-07-20T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "https://authorized.example/"}],
                        "llm_usage": {"requests": 8, "total_tokens": 12000},
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "\n".join(
                    [
                        "2026-07-20 00:00:05 INFO - strix.report.state: Added vulnerability report: vuln-1 - Missing Authentication",
                        "2026-07-20 00:00:06 INFO - strix.tools.reporting.tool: Vulnerability report created: id=vuln-1 severity=high",
                        "2026-07-20 00:00:07 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:08 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:09 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:10 DEBUG - openai.agents: Processing output item type=function_call class=ResponseFunctionToolCall",
                        "2026-07-20 00:00:11 DEBUG - openai.agents: Calling LLM",
                        "2026-07-20 00:00:12 DEBUG - openai.agents: Calling LLM",
                    ]
                ),
                encoding="utf-8",
            )

            runtime = analyze_runtime(run_dir, task_status="running", target="https://authorized.example/")

        self.assertEqual(runtime["convergence"]["idle_rounds"], 2)
        self.assertEqual(runtime["convergence"]["status"], "validated_findings")
