from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from src.backend.services.intermediate_evidence import load_candidate_findings


_TIMESTAMP_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_URL_PATTERN = re.compile(r"https?://[^\s\"']+")
_VULNERABILITY_ID_PATTERNS = (
    re.compile(r"Added vulnerability report:\s+([^\s]+)"),
    re.compile(r"Vulnerability report created:\s+id=([^\s]+)"),
)
_MEANINGFUL_EVENT_PATTERN = re.compile(
    r"Opened page|Invoking tool|Processing output item type=function_call|Added vulnerability report|"
    r"Vulnerability report created|finish_scan|create_note|candidate evidence",
    re.IGNORECASE,
)
POST_FINDING_IDLE_ROUND_LIMIT = 8
_ENVIRONMENT_FAILURE_PATTERN = re.compile(
    r"Payment Required|MaskedHTTPStatusError|missing Strix configuration|Tool agent-browser open not found|"
    r"filesystem permission error|PermissionError|Docker|connection refused|api key|quota|rate limit",
    re.IGNORECASE,
)


def analyze_runtime(run_dir: Path | None, *, task_status: str, target: str) -> dict[str, Any]:
    run_payload = _load_run_payload(run_dir)
    log_text = _read_log_text(run_dir / "strix.log") if run_dir else ""
    log_lines = log_text.splitlines()
    lifecycle_phase = _resolve_lifecycle_phase(task_status=task_status, run_status=str(run_payload.get("status", "")))
    resolved_target = _extract_target(run_payload, fallback=target)
    llm_usage = _extract_llm_usage(run_payload)
    attack_surface = _extract_attack_surface(log_text, resolved_target)
    evidence_progress = _extract_evidence_progress(log_text, run_dir)
    failure_classification = _classify_failure(
        lifecycle_phase=lifecycle_phase,
        log_text=log_text,
        llm_usage=llm_usage,
        attack_surface=attack_surface,
        evidence_progress=evidence_progress,
    )
    convergence = _build_convergence(
        lifecycle_phase=lifecycle_phase,
        log_lines=log_lines,
        llm_usage=llm_usage,
        attack_surface=attack_surface,
        evidence_progress=evidence_progress,
        failure_classification=failure_classification,
    )

    return {
        "phase": lifecycle_phase,
        "phase_label": _build_phase_label(
            lifecycle_phase=lifecycle_phase,
            llm_usage=llm_usage,
            attack_surface=attack_surface,
            evidence_progress=evidence_progress,
        ),
        "run_id": run_payload.get("run_id", run_dir.name if run_dir else None),
        "run_status": run_payload.get("status") or task_status or None,
        "target": resolved_target,
        "started_at": run_payload.get("start_time"),
        "completed_at": run_payload.get("end_time"),
        "log_tail": _build_log_tail(log_lines),
        "llm_usage": llm_usage,
        "attack_surface": attack_surface,
        "evidence_progress": evidence_progress,
        "convergence": convergence,
        "failure_classification": failure_classification,
        "recommended_next_action": _recommend_next_action(
            lifecycle_phase=lifecycle_phase,
            failure_classification=failure_classification,
            attack_surface=attack_surface,
            evidence_progress=evidence_progress,
            convergence_status=convergence["status"],
        ),
    }


def _load_run_payload(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {}

    run_path = run_dir / "run.json"
    if not run_path.exists():
        return {}

    try:
        return json.loads(run_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _read_log_text(log_path: Path) -> str:
    if not log_path.exists():
        return ""

    return log_path.read_text(encoding="utf-8", errors="ignore")


def _resolve_lifecycle_phase(*, task_status: str, run_status: str) -> str:
    normalized_task = (task_status or "").strip().lower()
    if normalized_task in {"completed", "partial", "failed", "cancelled"}:
        return normalized_task
    normalized = (run_status or task_status or "").strip().lower()
    if normalized in {"completed", "partial", "failed", "cancelled", "running"}:
        return normalized
    if normalized in {"created", "queued", "pending"}:
        return "pending"
    if normalized in {"demo_fixture_loaded", "draft"}:
        return "unavailable"
    if normalized:
        return "failed"
    return "unavailable"


def _extract_target(run_payload: dict[str, Any], *, fallback: str) -> str:
    targets_info = run_payload.get("targets_info") or []
    if not targets_info:
        return fallback

    return str(targets_info[0].get("original") or fallback)


def _extract_llm_usage(run_payload: dict[str, Any]) -> dict[str, int]:
    llm_usage = run_payload.get("llm_usage") or {}
    requests = int(llm_usage.get("requests") or 0)
    total_tokens = int(llm_usage.get("total_tokens") or 0)
    return {
        "requests": requests,
        "total_tokens": total_tokens,
    }


def _extract_attack_surface(log_text: str, target: str) -> dict[str, int]:
    discovered_urls = {target} if target.startswith(("http://", "https://")) else set()
    discovered_urls.update(_URL_PATTERN.findall(log_text))

    parameters: set[str] = set()
    api_endpoints: set[str] = set()
    auth_points = 0
    for url in discovered_urls:
        split = urlsplit(url)
        parameters.update(key for key, _ in parse_qsl(split.query, keep_blank_values=True))
        if "/api/" in split.path.lower():
            api_endpoints.add(split.path)
        if re.search(r"login|signin|password|auth", split.path, re.IGNORECASE):
            auth_points += 1

    lowered_log = log_text.lower()
    forms = len(re.findall(r"fill_form|submit_form|\bform\b", lowered_log))
    auth_points += len(re.findall(r"login|signin|password|unauthoriz|auth\b", lowered_log))
    upload_points = len(re.findall(r"upload|multipart|file input", lowered_log))

    return {
        "pages": len(discovered_urls),
        "forms": forms,
        "parameters": len(parameters),
        "api_endpoints": len(api_endpoints),
        "auth_points": auth_points,
        "upload_points": upload_points,
    }


def _extract_evidence_progress(log_text: str, run_dir: Path | None) -> dict[str, int]:
    vulnerability_ids: set[str] = set()
    for pattern in _VULNERABILITY_ID_PATTERNS:
        vulnerability_ids.update(pattern.findall(log_text))

    suspicions = len(re.findall(r"create_note|potential|candidate vulnerability", log_text, re.IGNORECASE))
    suspicions = max(suspicions, len(vulnerability_ids))
    return {
        "suspicions": suspicions,
        "validated_findings": len(vulnerability_ids),
        "reports_created": len(vulnerability_ids),
        "candidate_findings": len(load_candidate_findings(run_dir)) if run_dir else 0,
    }


def _classify_failure(
    *,
    lifecycle_phase: str,
    log_text: str,
    llm_usage: dict[str, int],
    attack_surface: dict[str, int],
    evidence_progress: dict[str, int],
) -> str | None:
    if lifecycle_phase == "cancelled":
        return "cancelled"

    if lifecycle_phase == "partial":
        return "evidence_in_progress"

    if lifecycle_phase == "completed":
        if evidence_progress["validated_findings"] > 0:
            return "validated_findings"
        return "completed_without_findings"

    if lifecycle_phase != "failed":
        return None

    if _ENVIRONMENT_FAILURE_PATTERN.search(log_text):
        return "environment_failed"
    if re.search(r"timed out|timeout", log_text, re.IGNORECASE):
        return "timeout_unconverged"
    if evidence_progress["validated_findings"] > 0:
        return "evidence_in_progress"
    if _has_meaningful_surface(attack_surface):
        return "surface_found_but_unverified"
    if llm_usage["requests"] > 0:
        return "no_surface_found"
    return "environment_failed"


def _build_convergence(
    *,
    lifecycle_phase: str,
    log_lines: list[str],
    llm_usage: dict[str, int],
    attack_surface: dict[str, int],
    evidence_progress: dict[str, int],
    failure_classification: str | None,
) -> dict[str, Any]:
    last_meaningful_index = -1
    last_meaningful_event_at = None
    for index, line in enumerate(log_lines):
        if not _MEANINGFUL_EVENT_PATTERN.search(line):
            continue
        last_meaningful_index = index
        last_meaningful_event_at = _extract_timestamp(line)

    idle_rounds = 0
    if last_meaningful_index >= 0:
        for line in log_lines[last_meaningful_index + 1 :]:
            if "Calling LLM" in line:
                idle_rounds += 1

    status = _derive_convergence_status(
        lifecycle_phase=lifecycle_phase,
        llm_usage=llm_usage,
        attack_surface=attack_surface,
        evidence_progress=evidence_progress,
        failure_classification=failure_classification,
        idle_rounds=idle_rounds,
    )

    return {
        "score": _build_convergence_score(
            llm_usage=llm_usage,
            attack_surface=attack_surface,
            evidence_progress=evidence_progress,
            failure_classification=failure_classification,
        ),
        "status": status,
        "last_meaningful_event_at": last_meaningful_event_at,
        "idle_rounds": idle_rounds,
    }


def _derive_convergence_status(
    *,
    lifecycle_phase: str,
    llm_usage: dict[str, int],
    attack_surface: dict[str, int],
    evidence_progress: dict[str, int],
    failure_classification: str | None,
    idle_rounds: int,
) -> str:
    if evidence_progress["validated_findings"] > 0 and idle_rounds >= POST_FINDING_IDLE_ROUND_LIMIT:
        return "validated_with_idle"
    if evidence_progress["validated_findings"] > 0:
        return "validated_findings"
    if evidence_progress.get("candidate_findings", 0) > 0:
        return "candidate_evidence"
    if failure_classification == "completed_without_findings":
        return "completed_without_findings"
    if failure_classification == "no_surface_found":
        return "no_surface_found"
    if _has_meaningful_surface(attack_surface):
        return "surface_found_but_unverified"
    if llm_usage["requests"] > 0 or lifecycle_phase == "running":
        return "recon_in_progress"
    return "not_started"


def _build_convergence_score(
    *,
    llm_usage: dict[str, int],
    attack_surface: dict[str, int],
    evidence_progress: dict[str, int],
    failure_classification: str | None,
) -> float:
    if evidence_progress["validated_findings"] > 0:
        return 0.9
    if failure_classification == "completed_without_findings":
        return 0.62

    score = 0.0
    if llm_usage["requests"] > 0:
        score += 0.2
    score += min(_surface_signal_total(attack_surface), 5) * 0.08
    score += min(llm_usage["requests"], 50) / 50 * 0.2
    return round(min(score, 0.85), 2)


def _build_phase_label(
    *,
    lifecycle_phase: str,
    llm_usage: dict[str, int],
    attack_surface: dict[str, int],
    evidence_progress: dict[str, int],
) -> str:
    if lifecycle_phase == "pending":
        return "等待启动"
    if lifecycle_phase == "cancelled":
        return "已终止"
    if lifecycle_phase == "partial":
        return "部分证据已保留"
    if lifecycle_phase == "unavailable":
        return "运行信息不可用"
    if evidence_progress["validated_findings"] > 0 or lifecycle_phase == "completed":
        return "证据整理"
    if _has_meaningful_surface(attack_surface):
        return "攻击面分析"
    if llm_usage["requests"] > 0 or lifecycle_phase == "running":
        return "侦察识别"
    return "预检查"


def _recommend_next_action(
    *,
    lifecycle_phase: str,
    failure_classification: str | None,
    attack_surface: dict[str, int],
    evidence_progress: dict[str, int],
    convergence_status: str,
) -> str:
    if failure_classification == "environment_failed":
        return "先修复运行环境或模型额度问题，再重新执行真实扫描。"
    if failure_classification in {"timeout_unconverged", "surface_found_but_unverified", "evidence_in_progress"}:
        return "建议收缩到表单与查询参数验证，优先复现单个高置信问题。"
    if failure_classification == "no_surface_found":
        return "建议继续侦察入口，优先确认登录口、查询参数和 API 路径。"
    if failure_classification == "validated_findings":
        return "建议导出报告并复核漏洞证据，必要时补做单点复现。"
    if convergence_status == "validated_with_idle":
        return "已形成漏洞证据且后续出现空转，建议停止无效子代理并收口当前扫描。"
    if failure_classification == "completed_without_findings":
        return "当前可结束本次扫描；如需继续，建议缩小到高价值输入点发起下一轮验证。"
    if lifecycle_phase == "pending":
        return "请先启动真实扫描，再观察阶段、攻击面与收敛变化。"
    if lifecycle_phase == "running" and _has_meaningful_surface(attack_surface):
        return "建议继续当前扫描；若长时间无新增证据，可收缩到表单与查询参数验证。"
    if lifecycle_phase == "running":
        return "建议继续侦察目标，优先确认页面、接口和认证入口。"
    if evidence_progress["validated_findings"] > 0:
        return "建议优先整理现有证据并导出报告。"
    return "建议继续侦察目标，优先确认页面、接口和认证入口。"


def _build_log_tail(log_lines: list[str], max_lines: int = 40) -> str:
    if not log_lines:
        return ""

    return "\n".join(log_lines[-max_lines:])


def _extract_timestamp(line: str) -> str | None:
    match = _TIMESTAMP_PREFIX.match(line)
    if not match:
        return None
    return match.group(1)


def _surface_signal_total(attack_surface: dict[str, int]) -> int:
    return sum(attack_surface.values())


def _has_meaningful_surface(attack_surface: dict[str, int]) -> bool:
    if attack_surface["forms"] > 0:
        return True
    if attack_surface["parameters"] > 0:
        return True
    if attack_surface["api_endpoints"] > 0:
        return True
    if attack_surface["auth_points"] > 0:
        return True
    if attack_surface["upload_points"] > 0:
        return True
    return attack_surface["pages"] > 1
