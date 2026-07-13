from __future__ import annotations

import json
import threading
from dataclasses import asdict, replace
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from src.backend.domain.models import ScanReport, ScanTask, TaskStatus
from src.backend.services.ai_summary import build_fixture_summary
from src.backend.services.docx_exporter import build_docx_export_bytes
from src.backend.services.fixture_loader import load_fixture_report
from src.backend.services.preflight import run_preflight
from src.backend.services.real_run_loader import load_latest_real_run_report
from src.backend.services.report_exporter import build_export_payload
from src.backend.services.runtime_analyzer import analyze_runtime
from src.backend.services.strix_runner import cancel_strix_scan, start_strix_scan, wait_for_strix_scan


class DemoTaskService:
    def __init__(
        self,
        fixture_path: str | Path,
        strix_runs_root: str | Path | None = None,
        template_path: str | Path | None = None,
        strix_scan_starter=None,
        strix_scan_waiter=None,
        strix_scan_canceller=None,
        preflight_runner=None,
        real_scan_timeout_seconds: int = 300,
    ) -> None:
        self.fixture_path = Path(fixture_path)
        self.strix_runs_root = Path(strix_runs_root) if strix_runs_root else None
        self.template_path = Path(template_path) if template_path else None
        self._tasks: list[ScanTask] = []
        self._task_configs_by_task_id: dict[str, dict[str, Any]] = {}
        self._reports_by_task_id: dict[str, ScanReport] = {}
        self._summaries_by_task_id: dict[str, dict[str, str]] = {}
        self._strix_scan_starter = strix_scan_starter or self._start_real_scan
        self._strix_scan_waiter = strix_scan_waiter or self._wait_for_real_scan
        self._strix_scan_canceller = strix_scan_canceller or self._cancel_real_scan
        self._preflight_runner = preflight_runner or (
            lambda target: run_preflight(target, target_is_allowed=self._is_allowed_target)
        )
        self._real_scan_timeout_seconds = real_scan_timeout_seconds
        self._active_real_runs: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create_task(self, payload: dict[str, Any]) -> dict[str, Any]:
        task_id = f"task-{len(self._tasks) + 1:03d}"
        name = str(payload.get("name", "")).strip()
        target = str(payload.get("target", "")).strip()
        scan_mode = str(payload.get("scanMode", "quick")).strip() or "quick"
        instruction = str(payload.get("instruction", "")).strip() or None
        result_source = str(payload.get("resultSource", "fixture")).strip() or "fixture"
        scan_timeout_seconds = int(payload.get("scanTimeoutSeconds", self._real_scan_timeout_seconds))

        if not name:
            raise ValueError("name is required")
        if not target:
            raise ValueError("target is required")
        if not self._is_allowed_target(target):
            raise ValueError("目标地址必须使用 http(s) 协议，或使用相对演示路径")
        if scan_timeout_seconds <= 0:
            raise ValueError("扫描时长必须大于 0 秒")

        if result_source == "latest_real_run":
            report_bundle = self._build_pending_real_run_bundle(task_id=task_id, target=target)
        else:
            report_bundle = self._load_report_bundle(task_id=task_id, target=target, result_source=result_source)

        task = ScanTask(
            task_id=task_id,
            name=name,
            target=report_bundle["target"],
            scan_mode=scan_mode,
            instruction=instruction,
            status=report_bundle["status"],
        )

        self._tasks.append(task)
        self._task_configs_by_task_id[task_id] = {
            "result_source": result_source,
            "target": target,
            "scan_timeout_seconds": scan_timeout_seconds,
        }
        self._reports_by_task_id[task_id] = report_bundle["report"]
        self._summaries_by_task_id[task_id] = report_bundle["summary"]

        return self.get_task_results(task_id)

    def _build_pending_real_run_bundle(self, *, task_id: str, target: str) -> dict[str, Any]:
        return {
            "target": target,
            "report": ScanReport(task_id=task_id, findings=[]),
            "summary": {
                "executive_summary": "执行摘要：已创建真实 Strix 扫描任务，等待显式执行。",
                "technical_analysis": "当前尚未载入真实扫描结果。",
                "recommendations": "请点击“启动真实 Strix 扫描”以执行本次目标扫描。",
            },
            "status": TaskStatus.CREATED,
        }

    def list_tasks(self) -> dict[str, Any]:
        return {
            "tasks": [self._serialize_task(task) for task in reversed(self._tasks)],
        }

    def get_task_results(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._get_task(task_id)
            self._refresh_live_real_run_artifacts(task)
            report = self._reports_by_task_id[task_id]
            return {
                "task": self._serialize_task(task),
                "report": self._serialize_report(report, task),
                "summary": self._summaries_by_task_id[task_id],
            }

    def get_task_summary(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        return {
            "task": self._serialize_task(task),
            "summary": self._summaries_by_task_id[task_id],
        }

    def get_task_runtime(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        config = self._task_configs_by_task_id[task_id]
        runtime = self._build_runtime_payload(task=task, target=config["target"], result_source=config["result_source"])
        return {
            "task": self._serialize_task(task),
            "runtime": runtime,
        }

    def get_preflight(self, target: str) -> dict[str, object]:
        return self._preflight_runner(target)

    def get_task_export(
        self,
        task_id: str,
        *,
        export_format: str = "markdown",
        export_scope: str = "current",
    ) -> dict[str, Any]:
        task = self._get_task(task_id)
        report = self._reports_by_task_id[task_id]
        if export_format == "docx":
            if self.template_path is None:
                raise ValueError("DOCX 模板不可用")

            task_exports = self._collect_task_exports(task_id, export_scope)
            return {
                "task": self._serialize_task(task),
                "scope": export_scope,
                "format": "docx",
                "content": build_docx_export_bytes(
                    template_path=self.template_path,
                    task_exports=task_exports,
                ),
            }

        return build_export_payload(
            task=task,
            report=report,
            summary=self._summaries_by_task_id[task_id],
            serialized_task=self._serialize_task(task),
        )

    def run_task(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        config = self._task_configs_by_task_id[task_id]
        if config["result_source"] == "latest_real_run":
            if self.strix_runs_root is None:
                raise ValueError("real run source is unavailable")
            self._require_real_scan_preflight(config["target"])
            with self._lock:
                if task_id in self._active_real_runs:
                    raise ValueError("real scan is already running")
            running_task = replace(task, target=config["target"], status=TaskStatus.RUNNING)
            self._replace_task(running_task)
            self._reports_by_task_id[task_id] = ScanReport(task_id=task_id, findings=[])
            self._summaries_by_task_id[task_id] = self._build_running_summary()
            self._start_real_scan_in_background(running_task, config["scan_timeout_seconds"])
            return self.get_task_results(task_id)

        report_bundle = self._load_report_bundle(
            task_id=task_id,
            target=config["target"],
            result_source=config["result_source"],
        )
        refreshed_task = replace(
            task,
            target=report_bundle["target"],
            status=report_bundle["status"],
        )

        for index, existing_task in enumerate(self._tasks):
            if existing_task.task_id == task_id:
                self._tasks[index] = refreshed_task
                break

        self._reports_by_task_id[task_id] = report_bundle["report"]
        self._summaries_by_task_id[task_id] = report_bundle["summary"]

        return self.get_task_results(task_id)

    def _require_real_scan_preflight(self, target: str) -> None:
        result = self.get_preflight(target)
        if result.get("ready"):
            return

        failed_details = [
            str(check.get("detail", "运行前检查未通过"))
            for check in result.get("checks", [])
            if check.get("status") == "failed"
        ]
        details = "；".join(failed_details) or "运行环境未就绪"
        raise ValueError(f"真实扫描运行前检查未通过：{details}")

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        with self._lock:
            active_run = self._active_real_runs.get(task_id)
        if active_run is None:
            raise ValueError("real scan is not running")

        self._strix_scan_canceller(active_run["handle"])
        cancelled_task = replace(task, status=TaskStatus.CANCELLED)
        self._replace_task(cancelled_task)
        self._reports_by_task_id[task_id] = ScanReport(task_id=task_id, findings=[])
        self._summaries_by_task_id[task_id] = self._build_cancelled_summary()
        with self._lock:
            self._active_real_runs.pop(task_id, None)
        return self.get_task_results(task_id)

    def _start_real_scan(self, task: ScanTask):
        if self.strix_runs_root is None:
            raise ValueError("real run source is unavailable")
        return start_strix_scan(task, strix_runs_root=self.strix_runs_root)

    def _wait_for_real_scan(self, handle, timeout_seconds: int | None = None) -> Path:
        return wait_for_strix_scan(handle, timeout_seconds=timeout_seconds)

    def _cancel_real_scan(self, handle) -> None:
        cancel_strix_scan(handle)

    def _start_real_scan_in_background(self, task: ScanTask, timeout_seconds: int) -> None:
        if self.strix_runs_root is not None:
            self.strix_runs_root.mkdir(parents=True, exist_ok=True)
        handle = self._strix_scan_starter(task)
        worker = threading.Thread(
            target=self._finalize_real_scan_in_background,
            args=(task.task_id, task, handle, timeout_seconds),
            daemon=True,
        )
        with self._lock:
            self._active_real_runs[task.task_id] = {"handle": handle, "worker": worker}
        worker.start()

    def _finalize_real_scan_in_background(self, task_id: str, task: ScanTask, handle, timeout_seconds: int) -> None:
        try:
            self._strix_scan_waiter(handle, timeout_seconds=timeout_seconds)
            report_bundle = self._load_report_bundle(
                task_id=task_id,
                target=task.target,
                result_source="latest_real_run",
            )
            completed_task = replace(task, status=report_bundle["status"])
            self._replace_task(completed_task)
            self._reports_by_task_id[task_id] = report_bundle["report"]
            self._summaries_by_task_id[task_id] = report_bundle["summary"]
        except TimeoutError:
            with self._lock:
                if not self._restore_partial_real_run_bundle(task_id=task_id, target=task.target, failed_status="timeout"):
                    self._reports_by_task_id[task_id] = ScanReport(task_id=task_id, findings=[])
                    self._summaries_by_task_id[task_id] = self._build_timeout_summary(timeout_seconds)
                self._replace_task(replace(task, status=TaskStatus.FAILED))
        except (ValueError, FileNotFoundError) as error:
            if self._get_task(task_id).status == TaskStatus.CANCELLED:
                return
            with self._lock:
                if not self._restore_partial_real_run_bundle(task_id=task_id, target=task.target, failed_status="failed"):
                    self._reports_by_task_id[task_id] = ScanReport(task_id=task_id, findings=[])
                    self._summaries_by_task_id[task_id] = self._build_failed_summary(str(error))
                self._replace_task(replace(task, status=TaskStatus.FAILED))
        finally:
            with self._lock:
                self._active_real_runs.pop(task_id, None)

    def _collect_task_exports(self, task_id: str, export_scope: str) -> list[dict[str, object]]:
        if export_scope == "all":
            selected_tasks = list(self._tasks)
        else:
            selected_tasks = [self._get_task(task_id)]

        return [
            {
                "task": task,
                "report": self._reports_by_task_id[task.task_id],
                "summary": self._summaries_by_task_id[task.task_id],
            }
            for task in selected_tasks
        ]

    def _get_task(self, task_id: str) -> ScanTask:
        for task in self._tasks:
            if task.task_id == task_id:
                return task
        raise KeyError(task_id)

    def _serialize_task(self, task: ScanTask) -> dict[str, Any]:
        payload = asdict(task)
        payload["status"] = task.status.value
        payload["created_at"] = task.created_at.isoformat()
        config = self._task_configs_by_task_id.get(task.task_id, {})
        payload["result_source"] = config.get("result_source", "fixture")
        payload["scan_timeout_seconds"] = config.get("scan_timeout_seconds", self._real_scan_timeout_seconds)
        return payload

    def _serialize_report(self, report: ScanReport, task: ScanTask) -> dict[str, Any]:
        return {
            "task_id": report.task_id,
            "target": task.target,
            "severity_counts": report.severity_counts(),
            "findings": [asdict(finding) for finding in report.findings],
        }

    def _build_runtime_payload(self, *, task: ScanTask, target: str, result_source: str) -> dict[str, Any]:
        if result_source != "latest_real_run" or self.strix_runs_root is None:
            return analyze_runtime(None, task_status="unavailable", target=target)

        if task.status == TaskStatus.CREATED:
            return analyze_runtime(None, task_status=task.status.value, target=target)

        if task.status == TaskStatus.CANCELLED:
            runtime = analyze_runtime(None, task_status=task.status.value, target=target)
            runtime["log_tail"] = "本次真实扫描已被用户终止。"
            return runtime

        latest_run = self._find_latest_run_for_target(target, created_after=task.created_at.timestamp())
        if latest_run is None:
            return analyze_runtime(
                None,
                task_status="running" if task.status == TaskStatus.RUNNING else task.status.value,
                target=target,
            )

        return analyze_runtime(latest_run, task_status=task.status.value, target=target)

    def _find_latest_run_for_target(self, target: str, created_after: float | None = None) -> Path | None:
        if self.strix_runs_root is None or not self.strix_runs_root.exists():
            return None

        candidates: list[Path] = []
        for run_dir in self.strix_runs_root.iterdir():
            if not run_dir.is_dir() or run_dir.name.startswith("."):
                continue

            run_path = run_dir / "run.json"
            if not run_path.exists():
                continue

            try:
                run_payload = json.loads(run_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            targets_info = run_payload.get("targets_info") or []
            original_target = targets_info[0].get("original") if targets_info else None
            if original_target == target:
                if created_after is not None and run_dir.stat().st_mtime < created_after:
                    continue
                candidates.append(run_dir)

        if not candidates:
            return None

        return sorted(candidates, key=lambda path: path.stat().st_mtime, reverse=True)[0]

    @staticmethod
    def _read_log_tail(log_path: Path, max_lines: int = 40) -> str:
        if not log_path.exists():
            return ""

        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(lines[-max_lines:])

    @staticmethod
    def _is_allowed_target(target: str) -> bool:
        parsed = urlparse(target)
        if parsed.scheme in {"http", "https"}:
            return True
        if parsed.scheme:
            return False

        return target.startswith(("./", "../")) or "://" not in target

    @staticmethod
    def _build_finding(payload: dict[str, Any]):
        from src.backend.domain.models import Finding

        return Finding(
            finding_id=payload["finding_id"],
            title=payload["title"],
            severity=payload["severity"],
            summary=payload["summary"],
            evidence=payload["evidence"],
            remediation=payload["remediation"],
        )

    def _load_report_bundle(self, *, task_id: str, target: str, result_source: str) -> dict[str, Any]:
        if result_source == "latest_real_run":
            if self.strix_runs_root is None:
                raise ValueError("real run source is unavailable")
            real_run = load_latest_real_run_report(self.strix_runs_root, target=target)
            return {
                "target": real_run["report"]["target"],
                "report": ScanReport(
                    task_id=task_id,
                    findings=[
                        self._build_finding(finding_payload) for finding_payload in real_run["report"]["findings"]
                    ],
                ),
                "summary": real_run["summary"],
                "status": TaskStatus.COMPLETED,
            }

        fixture_report = load_fixture_report(self.fixture_path)
        report = ScanReport(task_id=task_id, findings=fixture_report.findings)
        return {
            "target": target,
            "report": report,
            "summary": build_fixture_summary(report),
            "status": TaskStatus.DEMO_FIXTURE_LOADED,
        }

    def _refresh_live_real_run_artifacts(self, task: ScanTask) -> None:
        config = self._task_configs_by_task_id.get(task.task_id, {})
        if config.get("result_source") != "latest_real_run" or self.strix_runs_root is None:
            return
        if task.status not in {TaskStatus.RUNNING, TaskStatus.FAILED, TaskStatus.COMPLETED}:
            return

        existing_report = self._reports_by_task_id.get(task.task_id)
        if (
            task.status in {TaskStatus.FAILED, TaskStatus.COMPLETED}
            and existing_report is not None
            and existing_report.findings
        ):
            return

        try:
            partial_run = load_latest_real_run_report(
                self.strix_runs_root,
                target=config["target"],
                created_after=task.created_at.timestamp(),
                allow_statuses={"running", "completed", "failed", "interrupted", "cancelled"},
                require_scan_results=False,
            )
        except FileNotFoundError:
            return

        refreshed_report = ScanReport(
            task_id=task.task_id,
            findings=[
                self._build_finding(finding_payload) for finding_payload in partial_run["report"]["findings"]
            ],
        )
        if (
            existing_report is not None
            and existing_report.findings
            and self._finding_ids(existing_report.findings) == self._finding_ids(refreshed_report.findings)
        ):
            return

        self._reports_by_task_id[task.task_id] = refreshed_report
        if task.status == TaskStatus.RUNNING and self._reports_by_task_id[task.task_id].findings:
            self._summaries_by_task_id[task.task_id] = partial_run["summary"]

    def _restore_partial_real_run_bundle(self, *, task_id: str, target: str, failed_status: str) -> bool:
        if self.strix_runs_root is None:
            return False
        task = self._get_task(task_id)
        try:
            partial_run = load_latest_real_run_report(
                self.strix_runs_root,
                target=target,
                created_after=task.created_at.timestamp(),
                allow_statuses={"running", "completed", "failed", "interrupted", "cancelled"},
                require_scan_results=False,
            )
        except FileNotFoundError:
            return False

        findings = [
            self._build_finding(finding_payload) for finding_payload in partial_run["report"]["findings"]
        ]
        if not findings:
            return False

        self._reports_by_task_id[task_id] = ScanReport(task_id=task_id, findings=findings)
        self._summaries_by_task_id[task_id] = self._build_partial_failure_summary(
            finding_count=len(findings),
            failed_status=failed_status,
        )
        return True

    def _replace_task(self, next_task: ScanTask) -> None:
        for index, existing_task in enumerate(self._tasks):
            if existing_task.task_id == next_task.task_id:
                self._tasks[index] = next_task
                return

    @staticmethod
    def _finding_ids(findings) -> tuple[str, ...]:
        return tuple(finding.finding_id for finding in findings)

    @staticmethod
    def _build_running_summary() -> dict[str, str]:
        return {
            "executive_summary": "执行摘要：真实 Strix 扫描已启动，正在后台持续执行。",
            "technical_analysis": "当前请求已不再阻塞等待完整扫描结束，可通过执行轨迹查看实时日志与阶段变化。",
            "recommendations": "如发现日志长时间无变化，可点击“终止任务”停止本次扫描，再调整扫描模式或目标后重试。",
        }

    @staticmethod
    def _build_cancelled_summary() -> dict[str, str]:
        return {
            "executive_summary": "执行摘要：本次真实扫描已终止。",
            "technical_analysis": "平台已向 Strix 进程发送终止指令，并停止继续等待本次后台扫描。",
            "recommendations": "如需继续测试，请重新创建或重新启动任务；建议优先使用 quick 或 standard 模式缩短黑盒扫描时长。",
        }

    @staticmethod
    def _build_timeout_summary(timeout_seconds: int) -> dict[str, str]:
        return {
            "executive_summary": f"执行摘要：本次真实扫描超时，已在 {timeout_seconds} 秒后自动停止。",
            "technical_analysis": "Strix 在限制时间内未结束，平台已将任务标记为失败，避免界面长期停留在执行中。",
            "recommendations": "建议缩小目标范围、改用 quick 模式，或检查目标站点是否存在导致黑盒流程反复探索的复杂交互。",
        }

    @staticmethod
    def _build_failed_summary(message: str) -> dict[str, str]:
        return {
            "executive_summary": f"执行摘要：本次真实扫描执行失败：{message}",
            "technical_analysis": "本次后台扫描未能完成，平台已清空本次任务的风险列表，避免误将旧结果视为当前输出。",
            "recommendations": "请结合执行轨迹中的最后日志排查原因；若是黑盒流程过长，可先缩小范围或直接终止并重新发起。",
        }

    @staticmethod
    def _build_partial_failure_summary(*, finding_count: int, failed_status: str) -> dict[str, str]:
        reason = "超时" if failed_status == "timeout" else "失败"
        return {
            "executive_summary": f"执行摘要：本次真实扫描{reason}，但已保留 {finding_count} 个已发现漏洞进入当前报告。",
            "technical_analysis": "Strix 未完整收敛到最终总结，但运行目录中已落盘的漏洞证据已被平台即时吸收并保留下来。",
            "recommendations": "可直接查看并导出当前部分报告；如需更完整结论，建议延长扫描时长或缩小目标范围后重试。",
        }


class DemoApiRequestHandler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
    }

    def __init__(
        self,
        *args: Any,
        task_service: DemoTaskService,
        directory: str | Path,
        **kwargs: Any,
    ) -> None:
        self.task_service = task_service
        super().__init__(*args, directory=str(directory), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/api/tasks":
            self._send_json(HTTPStatus.OK, self.task_service.list_tasks())
            return

        if parsed.path == "/api/preflight":
            target = query.get("target", [""])[0]
            self._send_json(HTTPStatus.OK, self.task_service.get_preflight(target))
            return

        if parsed.path.startswith("/api/tasks/"):
            task_id, action = self._parse_task_route(parsed.path)
            if task_id is not None:
                try:
                    if action == "summary":
                        payload = self.task_service.get_task_summary(task_id)
                    elif action == "runtime":
                        payload = self.task_service.get_task_runtime(task_id)
                    elif action == "export":
                        export_format = query.get("format", ["markdown"])[0]
                        export_scope = query.get("scope", ["current"])[0]
                        payload = self.task_service.get_task_export(
                            task_id,
                            export_format=export_format,
                            export_scope=export_scope,
                        )
                    else:
                        payload = self.task_service.get_task_results(task_id)
                except KeyError:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "任务不存在"})
                    return
                except ValueError as error:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                    return

                if action == "export" and isinstance(payload, dict) and payload.get("format") == "docx":
                    self._send_docx(payload["content"], f"{task_id}.docx")
                    return

                if action in (None, "results", "summary", "runtime", "export"):
                    self._send_json(HTTPStatus.OK, payload)
                    return

        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/tasks":
            try:
                payload = self._read_json_body()
                created = self.task_service.create_task(payload)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "请求体不是有效的 JSON"})
                return
            except ValueError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return

            self._send_json(HTTPStatus.CREATED, created)
            return

        if parsed.path.startswith("/api/tasks/"):
            task_id, action = self._parse_task_route(parsed.path)
            if task_id is not None and action in {"run", "cancel"}:
                try:
                    self._read_json_body()
                    rerun = (
                        self.task_service.run_task(task_id)
                        if action == "run"
                        else self.task_service.cancel_task(task_id)
                    )
                except json.JSONDecodeError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "请求体不是有效的 JSON"})
                    return
                except KeyError:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "任务不存在"})
                    return
                except ValueError as error:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                    return

                self._send_json(HTTPStatus.OK, rerun)
                return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "接口不存在"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(body or "{}")

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_docx(self, content: bytes, file_name: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        self.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    @staticmethod
    def _parse_task_route(path: str) -> tuple[str | None, str | None]:
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "tasks":
            return None, None
        task_id = parts[2]
        action = parts[3] if len(parts) > 3 else None
        return task_id, action


def create_demo_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    frontend_dir: str | Path,
    fixture_path: str | Path,
    strix_runs_root: str | Path | None = None,
    template_path: str | Path | None = None,
    strix_scan_starter=None,
    strix_scan_waiter=None,
    strix_scan_canceller=None,
    preflight_runner=None,
    real_scan_timeout_seconds: int = 300,
) -> ThreadingHTTPServer:
    task_service = DemoTaskService(
        fixture_path=fixture_path,
        strix_runs_root=strix_runs_root,
        template_path=template_path,
        strix_scan_starter=strix_scan_starter,
        strix_scan_waiter=strix_scan_waiter,
        strix_scan_canceller=strix_scan_canceller,
        preflight_runner=preflight_runner,
        real_scan_timeout_seconds=real_scan_timeout_seconds,
    )
    handler = partial(
        DemoApiRequestHandler,
        task_service=task_service,
        directory=frontend_dir,
    )
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    project_root = Path(__file__).resolve().parents[3]
    server = create_demo_server(
        frontend_dir=project_root / "src" / "frontend",
        fixture_path=project_root / "tests" / "fixtures" / "strix_findings_sample.json",
        strix_runs_root=project_root / "strix_runs",
        template_path=project_root / "assets" / "report_template.docx",
    )
    try:
        print("演示服务已启动：http://127.0.0.1:8000")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
