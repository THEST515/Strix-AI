import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.domain.models import Finding, ScanReport, ScanTask, TaskStatus
from src.backend.api.demo_server import DemoTaskService, create_demo_server


def ready_preflight(target: str) -> dict[str, object]:
    return {"ready": True, "checks": []}


class DemoTaskServiceTests(unittest.TestCase):
    def test_completed_task_reloads_run_to_absorb_new_cached_external_candidate(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "completed-run"
            run_dir.mkdir()
            knowledge_service = object()
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=Path(temp_dir),
                vulnerability_knowledge_service=knowledge_service,
            )
            task = ScanTask(
                task_id="task-001",
                name="completed versioned scan",
                target="http://authorized-lab.example",
                scan_mode="standard",
                status=TaskStatus.COMPLETED,
            )
            confirmed = Finding(
                finding_id="confirmed-1",
                title="已确认漏洞",
                severity="high",
                summary="已确认",
                evidence="正式证据",
                remediation="修复",
            )
            service._tasks = [task]
            service._task_configs_by_task_id[task.task_id] = {
                "result_source": "latest_real_run",
                "target": task.target,
                "scan_timeout_seconds": 600,
            }
            service._reports_by_task_id[task.task_id] = ScanReport(
                task_id=task.task_id,
                findings=[confirmed],
            )
            service._summaries_by_task_id[task.task_id] = {
                "executive_summary": "done",
                "technical_analysis": "done",
                "recommendations": "done",
            }
            service._run_dirs_by_task_id[task.task_id] = run_dir
            refreshed_run = {
                "run": {"status": "completed"},
                "report": {
                    "findings": [
                        {
                            "finding_id": "confirmed-1",
                            "title": "已确认漏洞",
                            "severity": "high",
                            "summary": "已确认",
                            "evidence": "正式证据",
                            "remediation": "修复",
                            "verification_status": "confirmed",
                            "source": "strix_report",
                        },
                        {
                            "finding_id": "external-1",
                            "title": "CVE-2026-0001 候选",
                            "severity": "high",
                            "summary": "待验证",
                            "evidence": "目录匹配",
                            "remediation": "核对版本",
                            "verification_status": "candidate",
                            "source": "external_vulnerability_knowledge",
                        },
                    ]
                },
                "summary": service._summaries_by_task_id[task.task_id],
            }

            with patch(
                "src.backend.api.demo_server.load_latest_real_run_report",
                return_value=refreshed_run,
            ) as loader:
                result = service.get_task_results(task.task_id)

        loader.assert_called_once()
        self.assertEqual(result["report"]["confirmed_count"], 1)
        self.assertEqual(result["report"]["candidate_count"], 1)

    def test_real_run_loader_receives_injected_vulnerability_knowledge_service(self) -> None:
        knowledge_service = object()
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            vulnerability_knowledge_service=knowledge_service,
        )
        real_run = {
            "run": {"run_id": "run-1"},
            "report": {"target": "http://authorized-lab.example", "findings": []},
            "summary": {
                "executive_summary": "done",
                "technical_analysis": "done",
                "recommendations": "done",
            },
        }

        with patch(
            "src.backend.api.demo_server.load_latest_real_run_report",
            return_value=real_run,
        ) as loader:
            service._load_report_bundle(
                task_id="task-001",
                target="http://authorized-lab.example",
                result_source="latest_real_run",
            )

        self.assertIs(loader.call_args.kwargs["knowledge_service"], knowledge_service)

    def test_run_task_does_not_start_real_scan_when_preflight_fails(self) -> None:
        started: list[object] = []
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=lambda task: started.append(task),
            preflight_runner=lambda target: {
                "ready": False,
                "checks": [
                    {
                        "key": "docker",
                        "label": "Docker",
                        "status": "failed",
                        "detail": "Docker daemon 未就绪",
                    }
                ],
            },
        )
        created = service.create_task(
            {
                "name": "blocked real scan",
                "target": "http://localhost:8888",
                "resultSource": "latest_real_run",
            }
        )

        with self.assertRaisesRegex(ValueError, "Docker daemon 未就绪"):
            service.run_task(created["task"]["task_id"])

        self.assertEqual(started, [])

    def test_create_task_loads_fixture_report_and_marks_demo_status(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )

        created = service.create_task(
            {
                "name": "demo task",
                "target": "https://authorized-lab.example",
                "scanMode": "quick",
                "instruction": "authorized demo only",
            }
        )

        self.assertEqual(created["task"]["status"], TaskStatus.DEMO_FIXTURE_LOADED.value)
        self.assertEqual(created["task"]["name"], "demo task")
        self.assertEqual(created["task"]["result_source"], "fixture")
        self.assertEqual(created["report"]["task_id"], created["task"]["task_id"])
        self.assertEqual(created["report"]["target"], "https://authorized-lab.example")
        self.assertEqual(len(created["report"]["findings"]), 2)
        self.assertEqual(created["report"]["findings"][0]["title"], "个人资料接口存在越权访问")

    def test_list_tasks_returns_newest_first(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )

        first = service.create_task({"name": "first", "target": "https://one.example"})
        second = service.create_task({"name": "second", "target": "https://two.example"})

        listing = service.list_tasks()

        self.assertEqual(
            [item["task_id"] for item in listing["tasks"]],
            [second["task"]["task_id"], first["task"]["task_id"]],
        )

    def test_create_task_for_latest_real_run_preserves_requested_target_until_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )

            created = service.create_task(
                {
                    "name": "real run import task",
                    "target": "./placeholder",
                    "resultSource": "latest_real_run",
                }
            )

        self.assertEqual(created["task"]["status"], TaskStatus.CREATED.value)
        self.assertEqual(created["task"]["result_source"], "latest_real_run")
        self.assertEqual(created["task"]["target"], "./placeholder")
        self.assertEqual(created["report"]["task_id"], created["task"]["task_id"])
        self.assertEqual(created["report"]["target"], "./placeholder")
        self.assertEqual(created["report"]["severity_counts"]["medium"], 0)
        self.assertIn("执行摘要", created["summary"]["executive_summary"])
        self.assertIn("等待显式执行", created["summary"]["executive_summary"])

    def test_create_task_keeps_requested_scan_timeout_seconds(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )

        created = service.create_task(
            {
                "name": "timeout-configured task",
                "target": "https://authorized-lab.example",
                "scanTimeoutSeconds": 600,
            }
        )

        self.assertEqual(created["task"]["scan_timeout_seconds"], 600)

    def test_create_real_task_composes_report_first_instruction(self) -> None:
        with TemporaryDirectory() as temp_dir:
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=Path(temp_dir),
            )

            created = service.create_task(
                {
                    "name": "five minute real scan",
                    "target": "http://authorized-lab.example/admin/",
                    "scanMode": "standard",
                    "scanTimeoutSeconds": 300,
                    "resultSource": "latest_real_run",
                    "instruction": "Do not modify data.",
                }
            )

        instruction = created["task"]["instruction"]
        self.assertIn("known CVE", instruction)
        self.assertIn("report each confirmed finding immediately", instruction.lower())
        self.assertTrue(instruction.endswith("Do not modify data."))

    def test_create_task_accepts_unlimited_scan_duration(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )

        created = service.create_task(
            {
                "name": "unlimited timeout task",
                "target": "https://authorized-lab.example",
                "scanTimeoutSeconds": None,
            }
        )

        self.assertIsNone(created["task"]["scan_timeout_seconds"])

    def test_export_task_report_returns_markdown_payload(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )
        created = service.create_task(
            {
                "name": "export demo",
                "target": "https://authorized-lab.example",
            }
        )

        exported = service.get_task_export(created["task"]["task_id"])

        self.assertEqual(exported["task"]["task_id"], created["task"]["task_id"])
        self.assertEqual(exported["format"], "markdown")
        self.assertIn("# 扫描报告", exported["content"])
        self.assertIn("## 任务信息", exported["content"])
        self.assertIn("https://authorized-lab.example", exported["content"])

    def test_export_task_report_returns_docx_payload_bytes(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            template_path=ROOT / "tests" / "fixtures" / "report_template.docx",
        )
        created = service.create_task(
            {
                "name": "export docx demo",
                "target": "https://authorized-lab.example",
            }
        )

        exported = service.get_task_export(created["task"]["task_id"], export_format="docx")

        self.assertEqual(exported["task"]["task_id"], created["task"]["task_id"])
        self.assertEqual(exported["format"], "docx")
        self.assertIsInstance(exported["content"], bytes)
        self.assertTrue(exported["content"].startswith(b"PK"))

    def test_export_all_tasks_can_return_merged_docx_payload(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            template_path=ROOT / "tests" / "fixtures" / "report_template.docx",
        )
        first = service.create_task(
            {
                "name": "站点 A",
                "target": "https://a.example",
            }
        )
        second = service.create_task(
            {
                "name": "站点 B",
                "target": "https://b.example",
            }
        )

        exported = service.get_task_export(second["task"]["task_id"], export_format="docx", export_scope="all")

        self.assertEqual(exported["task"]["task_id"], second["task"]["task_id"])
        self.assertEqual(exported["scope"], "all")
        self.assertEqual(exported["format"], "docx")
        self.assertTrue(exported["content"].startswith(b"PK"))

    def test_create_task_rejects_unsafe_target_scheme(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )

        with self.assertRaisesRegex(ValueError, "目标地址"):
            service.create_task(
                {
                    "name": "unsafe target",
                    "target": "javascript:alert(1)",
                }
            )

    def test_run_task_reloads_fixture_report_for_existing_task(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json"
        )
        created = service.create_task(
            {
                "name": "run demo",
                "target": "https://authorized-lab.example",
                "scanMode": "quick",
            }
        )

        rerun = service.run_task(created["task"]["task_id"])

        self.assertEqual(rerun["task"]["task_id"], created["task"]["task_id"])
        self.assertEqual(rerun["task"]["status"], TaskStatus.DEMO_FIXTURE_LOADED.value)
        self.assertEqual(rerun["task"]["result_source"], "fixture")
        self.assertEqual(rerun["report"]["target"], "https://authorized-lab.example")
        self.assertIn("executive_summary", rerun["summary"])

    def test_run_task_executes_real_strix_scan_for_latest_real_run_tasks(self) -> None:
        observed: dict[str, str] = {}

        def fake_start(task):
            observed["task_id"] = task.task_id
            observed["target"] = task.target
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            run_dir = runs_root / "02_current"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "02_current",
                        "status": "completed",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:02:00+00:00",
                        "end_time": "2026-07-07T00:03:00+00:00",
                        "targets_info": [{"original": observed["target"]}],
                        "scan_results": {
                            "executive_summary": "current run",
                            "technical_analysis": "current analysis",
                            "recommendations": "current recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            return run_dir

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_prev"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_prev",
                        "status": "completed",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": "2026-07-07T00:01:00+00:00",
                        "targets_info": [{"original": "./previous-target"}],
                        "scan_results": {
                            "executive_summary": "previous run",
                            "technical_analysis": "previous analysis",
                            "recommendations": "previous recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=fake_start,
                strix_scan_waiter=fake_wait,
                preflight_runner=ready_preflight,
            )
            created = service.create_task(
                {
                    "name": "real scan task",
                    "target": "./requested-target",
                    "resultSource": "latest_real_run",
                }
            )

            started = service.run_task(created["task"]["task_id"])
            time.sleep(0.1)
            rerun = service.get_task_results(created["task"]["task_id"])

        self.assertEqual(observed["task_id"], created["task"]["task_id"])
        self.assertEqual(observed["target"], "./requested-target")
        self.assertEqual(started["task"]["status"], TaskStatus.RUNNING.value)
        self.assertEqual(rerun["task"]["task_id"], created["task"]["task_id"])
        self.assertEqual(rerun["task"]["result_source"], "latest_real_run")
        self.assertEqual(rerun["task"]["status"], TaskStatus.COMPLETED.value)

    def test_run_task_marks_startup_failure_instead_of_leaving_running_task(self) -> None:
        def failing_start(task):
            raise ValueError("Strix binary failed to start")

        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=failing_start,
            preflight_runner=ready_preflight,
        )
        created = service.create_task(
            {
                "name": "startup failure",
                "target": "http://authorized-lab.example/",
                "resultSource": "latest_real_run",
            }
        )

        result = service.run_task(created["task"]["task_id"])

        self.assertEqual(result["task"]["status"], TaskStatus.FAILED.value)
        self.assertIn("Strix binary failed to start", result["summary"]["executive_summary"])

    def test_running_real_run_results_include_partial_findings_before_completion(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            created = service.create_task(
                {
                    "name": "partial findings task",
                    "target": "http://localhost:8888/",
                    "resultSource": "latest_real_run",
                }
            )
            run_dir = runs_root / "live-run"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "live-run",
                        "status": "running",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://localhost:8888/"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-0008",
                            "title": "Missing Authentication",
                            "severity": "critical",
                            "description": "endpoint accepts password change without auth",
                            "technical_analysis": "POST /UserManager/xgmm3 succeeds anonymously",
                            "remediation_steps": "require authenticated session and server-side identity checks",
                        }
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            service._replace_task(service._get_task(created["task"]["task_id"]).with_status(TaskStatus.RUNNING))

            results = service.get_task_results(created["task"]["task_id"])

        self.assertEqual(results["task"]["status"], TaskStatus.RUNNING.value)
        self.assertEqual(results["report"]["severity_counts"]["critical"], 1)
        self.assertEqual(results["report"]["findings"][0]["finding_id"], "vuln-0008")

    def test_running_real_run_keeps_first_translated_finding_copy_when_finding_ids_are_unchanged(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
        )
        created = service.create_task(
            {
                "name": "stable translation task",
                "target": "http://localhost:8888/",
                "resultSource": "latest_real_run",
            }
        )
        task_id = created["task"]["task_id"]
        service._replace_task(service._get_task(task_id).with_status(TaskStatus.RUNNING))

        first_payload = {
            "run": {
                "run_id": "run-001",
                "status": "running",
                "scan_mode": "quick",
                "target": "http://localhost:8888/",
                "started_at": "2026-07-08T00:00:00+00:00",
                "completed_at": None,
            },
            "report": {
                "task_id": "run-001",
                "target": "http://localhost:8888/",
                "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                "findings": [
                    {
                        "finding_id": "vuln-0001",
                        "title": "首版中文标题",
                        "severity": "critical",
                        "summary": "首版中文摘要",
                        "evidence": "首版中文证据",
                        "remediation": "首版中文建议",
                    }
                ],
            },
            "summary": {
                "executive_summary": "已记录 1 个风险项",
                "technical_analysis": "首版摘要",
                "recommendations": "首版建议",
            },
        }
        second_payload = {
            "run": first_payload["run"],
            "report": {
                "task_id": "run-001",
                "target": "http://localhost:8888/",
                "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                "findings": [
                    {
                        "finding_id": "vuln-0001",
                        "title": "第二版中文标题",
                        "severity": "critical",
                        "summary": "第二版中文摘要",
                        "evidence": "第二版中文证据",
                        "remediation": "第二版中文建议",
                    }
                ],
            },
            "summary": {
                "executive_summary": "已记录 1 个风险项",
                "technical_analysis": "第二版摘要",
                "recommendations": "第二版建议",
            },
        }

        with patch(
            "src.backend.api.demo_server.load_latest_real_run_report",
            side_effect=[first_payload, second_payload],
        ):
            first_results = service.get_task_results(task_id)
            second_results = service.get_task_results(task_id)

        self.assertEqual(first_results["report"]["findings"][0]["title"], "首版中文标题")
        self.assertEqual(second_results["report"]["findings"][0]["title"], "首版中文标题")
        self.assertEqual(second_results["report"]["findings"][0]["summary"], "首版中文摘要")

    def test_running_real_run_upgrades_english_finding_copy_to_chinese(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
        )
        created = service.create_task(
            {
                "name": "translation upgrade task",
                "target": "http://localhost:8888/",
                "resultSource": "latest_real_run",
            }
        )
        task_id = created["task"]["task_id"]
        service._replace_task(service._get_task(task_id).with_status(TaskStatus.RUNNING))
        run = {
            "run_id": "run-001",
            "status": "running",
            "scan_mode": "quick",
            "target": "http://localhost:8888/",
            "started_at": "2026-07-08T00:00:00+00:00",
            "completed_at": None,
        }
        first_payload = {
            "run": run,
            "report": {
                "task_id": "run-001",
                "target": "http://localhost:8888/",
                "findings": [
                    {
                        "finding_id": "vuln-0001",
                        "title": "Weak Database Password",
                        "severity": "critical",
                        "summary": "The administrative account accepts a weak password.",
                        "evidence": "An administrative session was established.",
                        "remediation": "Rotate the password.",
                    }
                ],
            },
            "summary": {
                "executive_summary": "one finding",
                "technical_analysis": "running",
                "recommendations": "fix",
            },
        }
        second_payload = {
            "run": run,
            "report": {
                "task_id": "run-001",
                "target": "http://localhost:8888/",
                "findings": [
                    {
                        "finding_id": "vuln-0001",
                        "title": "数据库管理账户使用弱口令",
                        "severity": "critical",
                        "summary": "管理账户接受弱口令登录。",
                        "evidence": "已建立具有管理权限的会话。",
                        "remediation": "立即轮换口令。",
                    }
                ],
            },
            "summary": {
                "executive_summary": "已记录 1 个风险项",
                "technical_analysis": "扫描进行中",
                "recommendations": "修复弱口令",
            },
        }

        with patch(
            "src.backend.api.demo_server.load_latest_real_run_report",
            side_effect=[first_payload, second_payload],
        ):
            first_results = service.get_task_results(task_id)
            second_results = service.get_task_results(task_id)

        self.assertEqual(first_results["report"]["findings"][0]["title"], "Weak Database Password")
        self.assertEqual(second_results["report"]["findings"][0]["title"], "数据库管理账户使用弱口令")

    def test_background_real_scan_timeout_preserves_partial_findings(self) -> None:
        def fake_start(task):
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            run_dir = runs_root / "partial-timeout"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "partial-timeout",
                        "status": "running",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://localhost:8888/"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-0010",
                            "title": "Stored XSS",
                            "severity": "high",
                            "description": "comment input is stored without sanitization",
                            "technical_analysis": "payload persists and executes on admin review page",
                            "remediation_steps": "encode output and sanitize stored HTML",
                        }
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            raise TimeoutError(f"timed out after {timeout_seconds} seconds")

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=fake_start,
                strix_scan_waiter=fake_wait,
                preflight_runner=ready_preflight,
                real_scan_timeout_seconds=1,
            )
            created = service.create_task(
                {
                    "name": "timeout partial report task",
                    "target": "http://localhost:8888/",
                    "resultSource": "latest_real_run",
                    "scanTimeoutSeconds": 1,
                }
            )

            service.run_task(created["task"]["task_id"])
            refreshed = None
            for _ in range(20):
                refreshed = service.get_task_results(created["task"]["task_id"])
                if refreshed["task"]["status"] == TaskStatus.PARTIAL.value:
                    break
                time.sleep(0.05)

        self.assertEqual(refreshed["task"]["status"], TaskStatus.PARTIAL.value)
        self.assertEqual(refreshed["report"]["severity_counts"]["high"], 1)
        self.assertEqual(refreshed["report"]["findings"][0]["finding_id"], "vuln-0010")
        self.assertIn("已保留", refreshed["summary"]["executive_summary"])

    def test_run_task_uses_task_specific_timeout_seconds(self) -> None:
        observed: dict[str, int | None] = {"timeout_seconds": None}

        def fake_start(task):
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            observed["timeout_seconds"] = timeout_seconds
            return None

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_completed"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_completed",
                        "status": "completed",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": "2026-07-07T00:01:00+00:00",
                        "targets_info": [{"original": "http://localhost:8888/"}],
                        "scan_results": {
                            "executive_summary": "done",
                            "technical_analysis": "done",
                            "recommendations": "done",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=fake_start,
                strix_scan_waiter=fake_wait,
                preflight_runner=ready_preflight,
            )
            created = service.create_task(
                {
                    "name": "specific timeout task",
                    "target": "http://localhost:8888/",
                    "resultSource": "latest_real_run",
                    "scanTimeoutSeconds": 600,
                }
            )

            service.run_task(created["task"]["task_id"])
            time.sleep(0.1)

        self.assertEqual(observed["timeout_seconds"], 600)

    def test_run_task_returns_empty_findings_when_real_run_has_no_vulnerabilities_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_zero"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_zero",
                        "status": "completed",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": "2026-07-07T00:01:00+00:00",
                        "targets_info": [{"original": "./src/frontend"}],
                        "scan_results": {
                            "executive_summary": "no findings",
                            "technical_analysis": "scan completed cleanly",
                            "recommendations": "none",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            os.utime(run_dir, (1, 1))

            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=lambda task: {"task_id": task.task_id},
                strix_scan_waiter=lambda handle, timeout_seconds=None: run_dir,
                preflight_runner=ready_preflight,
            )
            created = service.create_task(
                {
                    "name": "real scan zero findings",
                    "target": "./src/frontend",
                    "resultSource": "latest_real_run",
                }
            )

            service.run_task(created["task"]["task_id"])
            time.sleep(0.1)
            rerun = service.get_task_results(created["task"]["task_id"])

        self.assertEqual(rerun["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertEqual(rerun["task"]["result_source"], "latest_real_run")
        self.assertEqual(rerun["report"]["findings"], [])
        self.assertEqual(rerun["report"]["severity_counts"]["high"], 0)

    def test_run_task_propagates_real_scan_failure_instead_of_reusing_stale_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_previous"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_previous",
                        "status": "completed",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": "2026-07-07T00:01:00+00:00",
                        "targets_info": [{"original": "./old-target"}],
                        "scan_results": {
                            "executive_summary": "old summary",
                            "technical_analysis": "old analysis",
                            "recommendations": "old recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=lambda task: {"task_id": task.task_id},
                strix_scan_waiter=lambda handle, timeout_seconds=None: (_ for _ in ()).throw(
                    ValueError("Strix scan failed: docker")
                ),
                preflight_runner=ready_preflight,
            )
            created = service.create_task(
                {
                    "name": "real scan failure task",
                    "target": "./src/frontend",
                    "resultSource": "latest_real_run",
                }
            )

            started = service.run_task(created["task"]["task_id"])
            time.sleep(0.1)
            failed = service.get_task_results(created["task"]["task_id"])

        self.assertIn(started["task"]["status"], {TaskStatus.RUNNING.value, TaskStatus.FAILED.value})
        self.assertEqual(failed["task"]["status"], TaskStatus.FAILED.value)
        self.assertIn("Strix scan failed", failed["summary"]["executive_summary"])

    def test_get_task_runtime_returns_latest_matching_run_status_and_log_tail(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            created = service.create_task(
                {
                    "name": "runtime task",
                    "target": "http://localhost:8888",
                    "resultSource": "latest_real_run",
                }
            )
            run_dir = runs_root / "byyt-running"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "byyt-running",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://localhost:8888"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "line-1\nline-2\nline-3\n",
                encoding="utf-8",
            )
            service._replace_task(service._get_task(created["task"]["task_id"]).with_status(TaskStatus.RUNNING))

            runtime = service.get_task_runtime(created["task"]["task_id"])

        self.assertEqual(runtime["task"]["task_id"], created["task"]["task_id"])
        self.assertEqual(runtime["runtime"]["phase"], "running")
        self.assertEqual(runtime["runtime"]["run_id"], "byyt-running")
        self.assertEqual(runtime["runtime"]["target"], "http://localhost:8888")
        self.assertEqual(runtime["runtime"]["phase_label"], "侦察识别")
        self.assertEqual(runtime["runtime"]["llm_usage"]["requests"], 0)
        self.assertEqual(runtime["runtime"]["attack_surface"]["pages"], 1)
        self.assertEqual(runtime["runtime"]["convergence"]["status"], "recon_in_progress")
        self.assertIsNone(runtime["runtime"]["failure_classification"])
        self.assertIn("继续侦察", runtime["runtime"]["recommended_next_action"])
        self.assertIn("line-3", runtime["runtime"]["log_tail"])

    def test_get_task_runtime_for_created_task_does_not_reuse_older_matching_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "older-run"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "older-run",
                        "status": "completed",
                        "scan_mode": "standard",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": "2026-07-07T00:01:00+00:00",
                        "targets_info": [{"original": "http://localhost:8888"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            created = service.create_task(
                {
                    "name": "fresh runtime task",
                    "target": "http://localhost:8888",
                    "resultSource": "latest_real_run",
                }
            )

            runtime = service.get_task_runtime(created["task"]["task_id"])

        self.assertEqual(runtime["runtime"]["phase"], "pending")
        self.assertIsNone(runtime["runtime"]["run_id"])

    def test_get_task_runtime_without_run_dir_marks_running_task_as_running(self) -> None:
        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=lambda task: {"task_id": task.task_id},
            strix_scan_waiter=lambda handle, timeout_seconds=None: time.sleep(0.2),
            preflight_runner=ready_preflight,
        )
        created = service.create_task(
            {
                "name": "no run dir yet",
                "target": "http://localhost:8888",
                "resultSource": "latest_real_run",
            }
        )
        service.run_task(created["task"]["task_id"])

        runtime = service.get_task_runtime(created["task"]["task_id"])

        self.assertEqual(runtime["runtime"]["phase"], "running")
        self.assertEqual(runtime["runtime"]["run_status"], TaskStatus.RUNNING.value)

        for _ in range(20):
            results = service.get_task_results(created["task"]["task_id"])
            if results["task"]["status"] == TaskStatus.FAILED.value:
                break
            time.sleep(0.05)

        self.assertEqual(results["task"]["status"], TaskStatus.FAILED.value)
        self.assertIn("执行失败", results["summary"]["executive_summary"])

    def test_run_task_starts_real_scan_in_background_and_returns_running_status_immediately(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def fake_start(task):
            started.set()
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            release.wait(timeout=2)

        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=fake_start,
            strix_scan_waiter=fake_wait,
            preflight_runner=ready_preflight,
        )
        created = service.create_task(
            {
                "name": "background runtime task",
                "target": "http://localhost:8888",
                "resultSource": "latest_real_run",
            }
        )

        started_response = service.run_task(created["task"]["task_id"])

        self.assertTrue(started.wait(timeout=1))
        self.assertEqual(started_response["task"]["status"], TaskStatus.RUNNING.value)
        self.assertIsNotNone(started_response["task"]["started_at"])
        self.assertEqual(started_response["report"]["findings"], [])
        release.set()

    def test_unlimited_real_scan_passes_none_to_background_waiter(self) -> None:
        started = threading.Event()
        release = threading.Event()
        observed: dict[str, object] = {}

        def fake_start(task):
            started.set()
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            observed["timeout_seconds"] = timeout_seconds
            release.wait(timeout=2)

        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=fake_start,
            strix_scan_waiter=fake_wait,
            preflight_runner=ready_preflight,
        )
        created = service.create_task(
            {
                "name": "unlimited runtime task",
                "target": "http://localhost:8888",
                "resultSource": "latest_real_run",
                "scanTimeoutSeconds": None,
            }
        )

        service.run_task(created["task"]["task_id"])

        self.assertTrue(started.wait(timeout=1))
        for _ in range(20):
            if "timeout_seconds" in observed:
                break
            time.sleep(0.05)
        self.assertIn("timeout_seconds", observed)
        self.assertIsNone(observed["timeout_seconds"])
        release.set()

    def test_cancel_task_marks_running_real_scan_as_cancelled(self) -> None:
        started = threading.Event()
        release = threading.Event()
        cancelled: dict[str, object] = {}

        def fake_start(task):
            started.set()
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            release.wait(timeout=2)

        def fake_cancel(handle):
            cancelled["handle"] = handle
            release.set()

        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=fake_start,
            strix_scan_waiter=fake_wait,
            strix_scan_canceller=fake_cancel,
            preflight_runner=ready_preflight,
        )
        created = service.create_task(
            {
                "name": "cancel runtime task",
                "target": "http://localhost:8888",
                "resultSource": "latest_real_run",
            }
        )

        service.run_task(created["task"]["task_id"])
        self.assertTrue(started.wait(timeout=1))

        cancelled_response = service.cancel_task(created["task"]["task_id"])

        self.assertIn("handle", cancelled)
        self.assertEqual(cancelled_response["task"]["status"], TaskStatus.CANCELLED.value)
        self.assertIn("已终止", cancelled_response["summary"]["executive_summary"])

    def test_runtime_guard_stops_post_finding_idle_scan_and_preserves_result(self) -> None:
        cancelled: list[object] = []

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_canceller=lambda handle: cancelled.append(handle),
            )
            created = service.create_task(
                {
                    "name": "idle guard",
                    "target": "http://authorized-lab.example/",
                    "resultSource": "latest_real_run",
                }
            )
            task_id = created["task"]["task_id"]
            service._replace_task(service._get_task(task_id).with_status(TaskStatus.RUNNING))
            service._active_real_runs[task_id] = {"handle": "scan-handle", "worker": None}
            run_dir = runs_root / "idle-run"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "idle-run",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-20T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example/"}],
                        "llm_usage": {"requests": 8, "total_tokens": 1000},
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
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-1",
                            "title": "Missing Authentication",
                            "severity": "high",
                            "description": "The endpoint is public.",
                            "technical_analysis": "The request succeeds without authentication.",
                            "remediation_steps": "Require authentication.",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            runtime = service.get_task_runtime(task_id)
            result = service.get_task_results(task_id)

        self.assertEqual(runtime["runtime"]["convergence"]["status"], "validated_with_idle")
        self.assertEqual(result["task"]["status"], TaskStatus.PARTIAL.value)
        self.assertEqual(result["report"]["confirmed_count"], 1)
        self.assertEqual(cancelled, ["scan-handle"])

    def test_runtime_guard_waits_until_confirmed_finding_artifact_is_loaded(self) -> None:
        cancelled: list[object] = []

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_canceller=lambda handle: cancelled.append(handle),
            )
            created = service.create_task(
                {
                    "name": "guard artifact race",
                    "target": "http://authorized-lab.example/",
                    "resultSource": "latest_real_run",
                }
            )
            task_id = created["task"]["task_id"]
            service._replace_task(service._get_task(task_id).with_status(TaskStatus.RUNNING))
            service._active_real_runs[task_id] = {"handle": "scan-handle", "worker": None}
            run_dir = runs_root / "artifact-race"
            (run_dir / ".state").mkdir(parents=True)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "artifact-race",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-20T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example/"}],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "\n".join(
                    [
                        "2026-07-20 00:00:05 INFO - strix.tools.reporting.tool: Vulnerability report created: id=vuln-race severity=high",
                        *[
                            f"2026-07-20 00:00:{second:02d} DEBUG - openai.agents: Calling LLM"
                            for second in range(6, 16)
                        ],
                    ]
                ),
                encoding="utf-8",
            )
            (run_dir / ".state" / "notes.json").write_text(
                json.dumps(
                    {
                        "candidate": {
                            "title": "Candidate endpoint evidence",
                            "content": "Endpoint request returned status 200 without authentication",
                            "category": "findings",
                        }
                    }
                ),
                encoding="utf-8",
            )

            runtime = service.get_task_runtime(task_id)
            result = service.get_task_results(task_id)

        self.assertEqual(runtime["runtime"]["convergence"]["status"], "validated_with_idle")
        self.assertEqual(result["task"]["status"], TaskStatus.RUNNING.value)
        self.assertEqual(result["report"]["confirmed_count"], 0)
        self.assertEqual(cancelled, [])

    def test_cancel_task_preserves_candidate_evidence_as_partial(self) -> None:
        release = threading.Event()
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)

            def fake_start(task):
                run_dir = runs_root / "candidate-cancel"
                (run_dir / ".state").mkdir(parents=True)
                (run_dir / "run.json").write_text(
                    json.dumps(
                        {
                            "run_id": "candidate-cancel",
                            "status": "running",
                            "scan_mode": "standard",
                            "start_time": "2026-07-19T00:00:00+00:00",
                            "end_time": None,
                            "targets_info": [{"original": task.target}],
                        }
                    ),
                    encoding="utf-8",
                )
                (run_dir / ".state" / "notes.json").write_text(
                    json.dumps({
                        "evidence": {
                            "title": "Authenticated product access",
                            "content": "Version: 5.0.0 and successfully authenticated",
                            "category": "findings",
                        }
                    }),
                    encoding="utf-8",
                )
                return {"task_id": task.task_id}

            def fake_wait(handle, timeout_seconds=None):
                release.wait(timeout=2)
                return None

            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=fake_start,
                strix_scan_waiter=fake_wait,
                strix_scan_canceller=lambda handle: release.set(),
                preflight_runner=ready_preflight,
            )
            created = service.create_task(
                {
                    "name": "cancel with evidence",
                    "target": "http://authorized-lab.example/admin/",
                    "resultSource": "latest_real_run",
                }
            )
            running = service.run_task(created["task"]["task_id"])
            self.assertEqual(running["report"]["candidate_count"], 1)

            cancelled_response = service.cancel_task(created["task"]["task_id"])

        self.assertEqual(cancelled_response["task"]["status"], TaskStatus.PARTIAL.value)
        self.assertEqual(cancelled_response["report"]["candidate_count"], 1)

    def test_background_real_scan_timeout_marks_task_failed(self) -> None:
        def fake_start(task):
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            raise TimeoutError(f"timed out after {timeout_seconds} seconds")

        service = DemoTaskService(
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=fake_start,
            strix_scan_waiter=fake_wait,
            preflight_runner=ready_preflight,
            real_scan_timeout_seconds=1,
        )
        created = service.create_task(
            {
                "name": "timeout runtime task",
                "target": "http://localhost:8888",
                "resultSource": "latest_real_run",
            }
        )

        service.run_task(created["task"]["task_id"])
        refreshed = None
        for _ in range(20):
            refreshed = service.get_task_results(created["task"]["task_id"])
            if refreshed["task"]["status"] == TaskStatus.FAILED.value:
                break
            time.sleep(0.05)

        self.assertEqual(refreshed["task"]["status"], TaskStatus.FAILED.value)
        self.assertIn("超时", refreshed["summary"]["executive_summary"])

    def test_partial_task_promotes_to_completed_when_run_finishes_late(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            created = service.create_task(
                {
                    "name": "late completion",
                    "target": "http://authorized-lab.example/admin/",
                    "resultSource": "latest_real_run",
                }
            )
            task_id = created["task"]["task_id"]
            service._replace_task(service._get_task(task_id).with_status(TaskStatus.PARTIAL))
            run_dir = runs_root / "late-run"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "late-run",
                        "status": "completed",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": "2026-07-19T00:05:16+00:00",
                        "targets_info": [{"original": "http://authorized-lab.example/admin/"}],
                        "scan_results": {
                            "executive_summary": "one confirmed finding",
                            "technical_analysis": "confirmed",
                            "recommendations": "fix",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [{
                        "id": "vuln-late",
                        "title": "Missing Authentication",
                        "severity": "critical",
                        "description": "configuration is public",
                        "technical_analysis": "request succeeds without authentication",
                        "remediation_steps": "require authentication",
                    }]
                ),
                encoding="utf-8",
            )

            result = service.get_task_results(task_id)

        self.assertEqual(result["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertEqual(result["report"]["confirmed_count"], 1)

    def test_task_keeps_its_first_matching_run_when_a_newer_same_target_run_appears(self) -> None:
        def write_run(run_dir, run_id, finding_id, title):
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example/admin/"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": finding_id,
                            "title": title,
                            "severity": "critical",
                            "description": "已确认的漏洞摘要。",
                            "technical_analysis": "已保留可复现证据。",
                            "remediation_steps": "立即修复。",
                        }
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            first = service.create_task(
                {
                    "name": "first scan",
                    "target": "http://authorized-lab.example/admin/",
                    "resultSource": "latest_real_run",
                }
            )
            first_id = first["task"]["task_id"]
            service._replace_task(service._get_task(first_id).with_status(TaskStatus.PARTIAL))
            write_run(runs_root / "01_first", "01_first", "vuln-first", "第一次扫描漏洞")

            first_result = service.get_task_results(first_id)

            second = service.create_task(
                {
                    "name": "second scan",
                    "target": "http://authorized-lab.example/admin/",
                    "resultSource": "latest_real_run",
                }
            )
            second_id = second["task"]["task_id"]
            service._replace_task(service._get_task(second_id).with_status(TaskStatus.PARTIAL))
            write_run(runs_root / "02_second", "02_second", "vuln-second", "第二次扫描漏洞")

            refreshed_first = service.get_task_results(first_id)
            second_result = service.get_task_results(second_id)

        self.assertEqual(first_result["report"]["findings"][0]["finding_id"], "vuln-first")
        self.assertEqual(refreshed_first["report"]["findings"][0]["finding_id"], "vuln-first")
        self.assertEqual(second_result["report"]["findings"][0]["finding_id"], "vuln-second")

    def test_new_task_does_not_bind_same_target_run_that_existed_before_start(self) -> None:
        release = threading.Event()
        cancelled: list[object] = []

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            old_run = runs_root / "old-active-run"
            old_run.mkdir()
            (old_run / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "old-active-run",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example/"}],
                    }
                ),
                encoding="utf-8",
            )

            def fake_wait(handle, timeout_seconds=None):
                release.wait(timeout=2)
                raise ValueError("stopped")

            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
                strix_scan_starter=lambda task: "new-scan-handle",
                strix_scan_waiter=fake_wait,
                strix_scan_canceller=lambda handle: cancelled.append(handle),
                preflight_runner=ready_preflight,
            )
            created = service.create_task(
                {
                    "name": "new same-target scan",
                    "target": "http://authorized-lab.example/",
                    "resultSource": "latest_real_run",
                }
            )
            task_id = created["task"]["task_id"]
            service.run_task(task_id)

            (old_run / "strix.log").write_text(
                "2026-07-20 00:00:10 INFO - old run continued writing\n",
                encoding="utf-8",
            )
            runtime = service.get_task_runtime(task_id)
            result = service.get_task_results(task_id)
            release.set()

        self.assertIsNone(runtime["runtime"]["run_id"])
        self.assertEqual(result["task"]["status"], TaskStatus.RUNNING.value)
        self.assertEqual(result["report"]["findings"], [])
        self.assertEqual(cancelled, [])

    def test_create_task_skips_interrupted_latest_real_run_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            interrupted_dir = runs_root / "02_interrupted"
            interrupted_dir.mkdir()
            (interrupted_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "02_interrupted",
                        "status": "interrupted",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:00:00+00:00",
                        "end_time": "2026-07-07T00:01:00+00:00",
                        "targets_info": [{"original": "./broken-target"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            completed_dir = runs_root / "01_completed"
            completed_dir.mkdir()
            (completed_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_completed",
                        "status": "completed",
                        "scan_mode": "quick",
                        "start_time": "2026-07-07T00:02:00+00:00",
                        "end_time": "2026-07-07T00:03:00+00:00",
                        "targets_info": [{"original": "./usable-target"}],
                        "scan_results": {
                            "executive_summary": "usable summary",
                            "technical_analysis": "usable analysis",
                            "recommendations": "usable recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            service = DemoTaskService(
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            created = service.create_task(
                {
                    "name": "skip interrupted latest run",
                    "target": "./requested-target",
                    "resultSource": "latest_real_run",
                }
            )

        self.assertEqual(created["task"]["status"], TaskStatus.CREATED.value)
        self.assertEqual(created["task"]["result_source"], "latest_real_run")
        self.assertEqual(created["task"]["target"], "./requested-target")
        self.assertEqual(created["report"]["target"], "./requested-target")
        self.assertIn("等待显式执行", created["summary"]["executive_summary"])


class DemoServerApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_demo_server(
            host="127.0.0.1",
            port=0,
            frontend_dir=ROOT / "src" / "frontend",
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_static_root_serves_frontend_index(self) -> None:
        with urlopen(f"{self.base_url}/") as response:
            html = response.read().decode("utf-8")

        self.assertIn("Strix AI 辅助安全分析平台", html)

    def test_get_preflight_over_http(self) -> None:
        server = create_demo_server(
            host="127.0.0.1",
            port=0,
            frontend_dir=ROOT / "src" / "frontend",
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            preflight_runner=lambda target: {"ready": True, "checks": []},
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            with urlopen(f"{base_url}/api/preflight?target=http%3A%2F%2Flocalhost%3A8888") as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(payload["ready"])
        self.assertEqual(payload["checks"], [])

    def test_get_vulnerability_knowledge_status_over_http_without_secrets(self) -> None:
        class KnowledgeStatusStub:
            def status(self):
                return {
                    "enabled": True,
                    "sources": ["nvd_cve_2.0", "cisa_kev", "first_epss"],
                    "cache_entries": 2,
                    "ttl_seconds": 86400,
                    "refreshing": 0,
                }

        server = create_demo_server(
            host="127.0.0.1",
            port=0,
            frontend_dir=ROOT / "src" / "frontend",
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            vulnerability_knowledge_service=KnowledgeStatusStub(),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            with urlopen(f"{base_url}/api/vulnerability-knowledge/status") as response:
                raw_payload = response.read().decode("utf-8")
                payload = json.loads(raw_payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["cache_entries"], 2)
        self.assertNotIn("api_key", raw_payload.lower())
        self.assertNotIn("cache_dir", raw_payload.lower())

    def test_static_module_assets_use_javascript_mime_type(self) -> None:
        with urlopen(f"{self.base_url}/rendering.mjs") as response:
            rendering_content_type = response.headers.get_content_type()

        with urlopen(f"{self.base_url}/taskData.mjs") as response:
            task_data_content_type = response.headers.get_content_type()

        self.assertEqual(rendering_content_type, "text/javascript")
        self.assertEqual(task_data_content_type, "text/javascript")

    def test_create_and_read_task_results_over_http(self) -> None:
        payload = json.dumps(
            {
                "name": "HTTP demo task",
                "target": "https://authorized-lab.example",
                "scanMode": "standard",
                "instruction": "authorized only",
            }
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/tasks",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(request) as response:
            created = json.loads(response.read().decode("utf-8"))

        task_id = created["task"]["task_id"]

        with urlopen(f"{self.base_url}/api/tasks") as response:
            listing = json.loads(response.read().decode("utf-8"))

        with urlopen(f"{self.base_url}/api/tasks/{task_id}/results") as response:
            results = json.loads(response.read().decode("utf-8"))

        self.assertEqual(listing["tasks"][0]["task_id"], task_id)
        self.assertEqual(results["task"]["task_id"], task_id)
        self.assertEqual(results["report"]["task_id"], task_id)
        self.assertEqual(results["report"]["target"], "https://authorized-lab.example")
        self.assertEqual(results["task"]["result_source"], "fixture")

    def test_missing_task_results_return_404(self) -> None:
        with self.assertRaises(HTTPError) as context:
            urlopen(f"{self.base_url}/api/tasks/task-999/results")

        self.assertEqual(context.exception.code, 404)

    def test_create_latest_real_run_task_over_http(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            server = create_demo_server(
                host="127.0.0.1",
                port=0,
                frontend_dir=ROOT / "src" / "frontend",
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"

            try:
                payload = json.dumps(
                    {
                        "name": "latest real run",
                        "target": "./placeholder",
                        "resultSource": "latest_real_run",
                    }
                ).encode("utf-8")
                request = Request(
                    f"{base_url}/api/tasks",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                with urlopen(request) as response:
                    created = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertEqual(created["task"]["status"], TaskStatus.CREATED.value)
        self.assertEqual(created["task"]["result_source"], "latest_real_run")
        self.assertEqual(created["task"]["target"], "./placeholder")
        self.assertEqual(created["report"]["target"], "./placeholder")
        self.assertEqual(created["report"]["severity_counts"]["medium"], 0)
        self.assertIn("executive_summary", created["summary"])
        self.assertNotIn("Executive Summary", created["summary"]["executive_summary"])

    def test_get_task_runtime_over_http(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            server = create_demo_server(
                host="127.0.0.1",
                port=0,
                frontend_dir=ROOT / "src" / "frontend",
                fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
                strix_runs_root=runs_root,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"

            try:
                payload = json.dumps(
                    {
                        "name": "runtime http task",
                        "target": "http://localhost:8888",
                        "resultSource": "latest_real_run",
                    }
                ).encode("utf-8")
                request = Request(
                    f"{base_url}/api/tasks",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                with urlopen(request) as response:
                    created = json.loads(response.read().decode("utf-8"))

                task_id = created["task"]["task_id"]
                run_dir = runs_root / "local-running"
                run_dir.mkdir()
                (run_dir / "run.json").write_text(
                    json.dumps(
                        {
                            "run_id": "local-running",
                            "status": "running",
                            "scan_mode": "standard",
                            "start_time": "2026-07-07T00:00:00+00:00",
                            "end_time": None,
                            "targets_info": [{"original": "http://localhost:8888"}],
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                (run_dir / "strix.log").write_text("progress-a\nprogress-b\n", encoding="utf-8")
                server.RequestHandlerClass.keywords["task_service"]._replace_task(
                    server.RequestHandlerClass.keywords["task_service"]
                    ._get_task(task_id)
                    .with_status(TaskStatus.RUNNING)
                )

                with urlopen(f"{base_url}/api/tasks/{task_id}/runtime") as response:
                    runtime = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertEqual(runtime["task"]["task_id"], task_id)
        self.assertEqual(runtime["runtime"]["phase"], "running")
        self.assertIn("progress-b", runtime["runtime"]["log_tail"])

    def test_cancel_task_over_http(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def fake_start(task):
            started.set()
            return {"task_id": task.task_id}

        def fake_wait(handle, timeout_seconds=None):
            release.wait(timeout=2)

        def fake_cancel(handle):
            release.set()

        server = create_demo_server(
            host="127.0.0.1",
            port=0,
            frontend_dir=ROOT / "src" / "frontend",
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            strix_scan_starter=fake_start,
            strix_scan_waiter=fake_wait,
            strix_scan_canceller=fake_cancel,
            preflight_runner=ready_preflight,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            payload = json.dumps(
                {
                    "name": "runtime http task",
                    "target": "http://localhost:8888",
                    "resultSource": "latest_real_run",
                }
            ).encode("utf-8")
            create_request = Request(
                f"{base_url}/api/tasks",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urlopen(create_request) as response:
                created = json.loads(response.read().decode("utf-8"))

            task_id = created["task"]["task_id"]
            run_request = Request(
                f"{base_url}/api/tasks/{task_id}/run",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(run_request) as response:
                started_payload = json.loads(response.read().decode("utf-8"))

            self.assertTrue(started.wait(timeout=1))

            cancel_request = Request(
                f"{base_url}/api/tasks/{task_id}/cancel",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(cancel_request) as response:
                cancelled_payload = json.loads(response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(started_payload["task"]["status"], TaskStatus.RUNNING.value)
        self.assertEqual(cancelled_payload["task"]["status"], TaskStatus.CANCELLED.value)

    def test_export_task_report_over_http(self) -> None:
        payload = json.dumps(
            {
                "name": "HTTP export task",
                "target": "https://authorized-lab.example",
            }
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/tasks",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(request) as response:
            created = json.loads(response.read().decode("utf-8"))

        task_id = created["task"]["task_id"]

        with urlopen(f"{self.base_url}/api/tasks/{task_id}/export") as response:
            exported = json.loads(response.read().decode("utf-8"))

        self.assertEqual(exported["task"]["task_id"], task_id)
        self.assertEqual(exported["format"], "markdown")
        self.assertIn("# 扫描报告", exported["content"])

    def test_export_task_docx_over_http(self) -> None:
        server = create_demo_server(
            host="127.0.0.1",
            port=0,
            frontend_dir=ROOT / "src" / "frontend",
            fixture_path=ROOT / "tests" / "fixtures" / "strix_findings_sample.json",
            strix_runs_root=ROOT / "strix_runs",
            template_path=ROOT / "tests" / "fixtures" / "report_template.docx",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        try:
            payload = json.dumps(
                {
                    "name": "HTTP docx export task",
                    "target": "https://authorized-lab.example",
                }
            ).encode("utf-8")
            request = Request(
                f"{base_url}/api/tasks",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urlopen(request) as response:
                created = json.loads(response.read().decode("utf-8"))

            task_id = created["task"]["task_id"]

            with urlopen(f"{base_url}/api/tasks/{task_id}/export?format=docx") as response:
                content = response.read()
                content_type = response.headers.get_content_type()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(content_type, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.assertTrue(content.startswith(b"PK"))

    def test_run_task_over_http(self) -> None:
        payload = json.dumps(
            {
                "name": "HTTP run task",
                "target": "https://authorized-lab.example",
            }
        ).encode("utf-8")
        create_request = Request(
            f"{self.base_url}/api/tasks",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(create_request) as response:
            created = json.loads(response.read().decode("utf-8"))

        run_request = Request(
            f"{self.base_url}/api/tasks/{created['task']['task_id']}/run",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(run_request) as response:
            rerun = json.loads(response.read().decode("utf-8"))

        self.assertEqual(rerun["task"]["task_id"], created["task"]["task_id"])
        self.assertEqual(rerun["task"]["status"], TaskStatus.DEMO_FIXTURE_LOADED.value)
        self.assertEqual(rerun["task"]["result_source"], "fixture")
        self.assertIn("report", rerun)
        self.assertIn("summary", rerun)

    def test_rejects_unsafe_target_scheme_over_http(self) -> None:
        payload = json.dumps(
            {
                "name": "unsafe target",
                "target": "file:///tmp/demo",
            }
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/tasks",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with self.assertRaises(HTTPError) as context:
            urlopen(request)

        self.assertEqual(context.exception.code, 400)
        self.assertIn("目标地址", context.exception.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
