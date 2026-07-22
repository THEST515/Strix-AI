from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from src.backend.services.intermediate_evidence import (
    load_candidate_findings,
    merge_confirmed_and_candidate_findings,
)
from src.backend.services.cve_hypotheses import build_cve_hypotheses
from src.backend.services.llm_finding_translator import translate_findings_with_strix_llm
from src.backend.services.summary_localizer import (
    localize_finding_fields,
    localize_summary_fields,
)
from src.backend.services.vulnerability_knowledge import extract_product_fingerprints

TRANSLATED_FINDINGS_CACHE_NAME = "finding_translations.zh-CN.json"


def load_latest_real_run_report(
    strix_runs_root: str | Path,
    *,
    run_dir: str | Path | None = None,
    target: str | None = None,
    created_after: float | None = None,
    allow_statuses: Iterable[str] = ("completed",),
    require_scan_results: bool = True,
    knowledge_service=None,
) -> dict:
    runs_root = Path(strix_runs_root)
    allowed_statuses = {status for status in allow_statuses}
    run_directories = (
        [Path(run_dir)]
        if run_dir is not None
        else sorted(
            [path for path in runs_root.iterdir() if path.is_dir() and not path.name.startswith(".")],
            key=lambda path: path.name,
            reverse=True,
        )
    )

    if not run_directories:
        raise FileNotFoundError("no strix run directories found")

    for latest_run in run_directories:
        if run_dir is None and created_after is not None and latest_run.stat().st_mtime < created_after:
            continue

        run_path = latest_run / "run.json"
        if not run_path.exists():
            continue

        run_payload = json.loads(run_path.read_text(encoding="utf-8"))
        if run_payload.get("status") not in allowed_statuses:
            continue

        current_target = run_payload["targets_info"][0]["original"]
        if target is not None and current_target != target:
            continue

        scan_results = run_payload.get("scan_results")
        if require_scan_results and not isinstance(scan_results, dict):
            continue

        vulnerabilities_path = latest_run / "vulnerabilities.json"
        vulnerabilities = (
            json.loads(vulnerabilities_path.read_text(encoding="utf-8"))
            if vulnerabilities_path.exists()
            else []
        )
        confirmed_findings = _load_or_translate_findings(latest_run, vulnerabilities)
        note_candidate_findings = load_candidate_findings(latest_run)
        external_candidate_findings: list[dict[str, str]] = []
        if knowledge_service is not None:
            fingerprints = extract_product_fingerprints(
                target=current_target,
                vulnerabilities=vulnerabilities,
                candidate_evidence=note_candidate_findings,
            )
            for fingerprint in fingerprints:
                try:
                    external_candidate_findings.extend(
                        knowledge_service.cached_candidates(fingerprint)
                    )
                except (OSError, TimeoutError, ValueError, json.JSONDecodeError):
                    continue
        candidate_findings = [
            *note_candidate_findings,
            *build_cve_hypotheses(
                target=current_target,
                vulnerabilities=vulnerabilities,
                candidate_evidence=note_candidate_findings,
            ),
            *external_candidate_findings,
        ]
        findings = merge_confirmed_and_candidate_findings(confirmed_findings, candidate_findings)
        confirmed_count = sum(finding["verification_status"] == "confirmed" for finding in findings)
        candidate_count = sum(finding["verification_status"] == "candidate" for finding in findings)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            if finding["verification_status"] != "confirmed":
                continue
            severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1

        if isinstance(scan_results, dict):
            summary = localize_summary_fields(
                {
                    "executive_summary": scan_results["executive_summary"],
                    "technical_analysis": scan_results["technical_analysis"],
                    "recommendations": scan_results["recommendations"],
                }
            )
        else:
            summary = _build_partial_summary(
                run_payload.get("status", "unknown"),
                confirmed_count,
                candidate_count,
            )

        return {
            "run": {
                "run_id": run_payload["run_id"],
                "status": run_payload["status"],
                "scan_mode": run_payload["scan_mode"],
                "target": current_target,
                "started_at": run_payload["start_time"],
                "completed_at": run_payload["end_time"],
            },
            "report": {
                "task_id": run_payload["run_id"],
                "target": current_target,
                "severity_counts": severity_counts,
                "confirmed_count": confirmed_count,
                "candidate_count": candidate_count,
                "findings": findings,
            },
            "summary": summary,
        }

    raise FileNotFoundError("no completed strix run directories with scan results found")


def _build_partial_summary(status: str, confirmed_count: int, candidate_count: int) -> dict[str, str]:
    if confirmed_count or candidate_count:
        return {
            "executive_summary": (
                f"已记录 {confirmed_count} 个已确认漏洞和 {candidate_count} 个候选风险，"
                "当前扫描仍未完整收敛。"
            ),
            "technical_analysis": "Strix 已写出部分正式或候选证据，但本次运行尚未形成完整最终总结。",
            "recommendations": "优先复核候选证据；任务失败或超时时，平台仍会保留已落盘结果。",
        }

    if status == "running":
        return {
            "executive_summary": "当前正在持续侦察和验证，尚未记录到已落盘漏洞。",
            "technical_analysis": "扫描仍在进行中，平台会在 Strix 写出漏洞文件后立刻吸收到当前任务。",
            "recommendations": "若长时间未出现漏洞或高价值输入点，建议缩小目标范围后重新执行。",
        }

    return {
        "executive_summary": "本次运行未完整结束，且尚未产出可保留的漏洞证据。",
        "technical_analysis": "Strix 没有形成最终总结，也没有在当前运行目录写出可导入的漏洞文件。",
        "recommendations": "建议调整时长或缩小范围后再次执行。",
    }


def _load_or_translate_findings(run_dir: Path, vulnerabilities: list[dict]) -> list[dict[str, str]]:
    base_findings = _build_localized_findings(vulnerabilities)
    source_hash = _hash_vulnerabilities(vulnerabilities)
    cached_findings = _load_cached_findings(run_dir, source_hash)
    if cached_findings is not None:
        return cached_findings

    translated_findings = translate_findings_with_strix_llm(base_findings)
    translated_findings = [_with_confirmed_metadata(finding) for finding in translated_findings]
    if _has_complete_chinese_translation(translated_findings):
        _write_cached_findings(run_dir, source_hash, translated_findings)
    return translated_findings


def _build_localized_findings(vulnerabilities: list[dict]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for item in vulnerabilities:
        localized_fields = localize_finding_fields(
            {
                "title": item["title"],
                "summary": item["description"],
                "evidence": item["technical_analysis"],
                "remediation": item["remediation_steps"],
            }
        )
        findings.append(
            {
                "finding_id": item["id"],
                "title": localized_fields["title"],
                "severity": item["severity"],
                "summary": localized_fields["summary"],
                "evidence": localized_fields["evidence"],
                "remediation": localized_fields["remediation"],
                "verification_status": "confirmed",
                "source": "strix_report",
            }
        )
    return findings


def _hash_vulnerabilities(vulnerabilities: list[dict]) -> str:
    serialized = json.dumps(vulnerabilities, ensure_ascii=False, sort_keys=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _load_cached_findings(run_dir: Path, source_hash: str) -> list[dict[str, str]] | None:
    cache_path = run_dir / TRANSLATED_FINDINGS_CACHE_NAME
    if not cache_path.exists():
        return None

    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if payload.get("source_hash") != source_hash:
        return None

    findings = payload.get("findings")
    if not isinstance(findings, list):
        return None

    normalized_findings: list[dict[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            return None
        normalized_findings.append(
            {
                "finding_id": str(finding.get("finding_id", "")),
                "title": str(finding.get("title", "")),
                "severity": str(finding.get("severity", "")),
                "summary": str(finding.get("summary", "")),
                "evidence": str(finding.get("evidence", "")),
                "remediation": str(finding.get("remediation", "")),
                "verification_status": str(finding.get("verification_status", "confirmed")),
                "source": str(finding.get("source", "strix_report")),
            }
        )

    if not _has_complete_chinese_translation(normalized_findings):
        return None
    return normalized_findings


def _write_cached_findings(run_dir: Path, source_hash: str, findings: list[dict[str, str]]) -> None:
    cache_path = run_dir / TRANSLATED_FINDINGS_CACHE_NAME
    payload = {
        "source_hash": source_hash,
        "findings": findings,
    }
    try:
        cache_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return


def _with_confirmed_metadata(finding: dict[str, str]) -> dict[str, str]:
    return {
        **finding,
        "verification_status": "confirmed",
        "source": "strix_report",
    }


def _has_complete_chinese_translation(findings: list[dict[str, str]]) -> bool:
    required_fields = ("title", "summary", "remediation")
    return bool(findings) and all(
        not finding.get(field) or _contains_cjk(str(finding[field]))
        for finding in findings
        for field in required_fields
    )


def _contains_cjk(value: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in value)
