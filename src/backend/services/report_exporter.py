from __future__ import annotations

from typing import Any

from src.backend.domain.models import ScanReport, ScanTask
from src.backend.services.summary_localizer import STATUS_TRANSLATIONS


def build_markdown_export(
    *,
    task: ScanTask,
    report: ScanReport,
    summary: dict[str, str],
) -> str:
    status_label = STATUS_TRANSLATIONS.get(task.status.value, task.status.value)
    scan_mode_label = STATUS_TRANSLATIONS.get(task.scan_mode, task.scan_mode)
    severity_label_map = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "提示",
    }

    lines = [
        "# 扫描报告",
        "",
        "## 任务信息",
        f"- 任务编号：{task.task_id}",
        f"- 任务名称：{task.name}",
        f"- 目标地址：{task.target}",
        f"- 扫描模式：{scan_mode_label}",
        f"- 当前状态：{status_label}",
        "",
        "## 摘要",
        summary.get("executive_summary", ""),
        "",
        "### 技术分析",
        summary.get("technical_analysis", ""),
        "",
        "### 修复建议",
        summary.get("recommendations", ""),
        "",
        "## 风险级别统计",
    ]

    severity_counts = report.severity_counts()
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity_label_map.get(severity, severity)}：{severity_counts.get(severity, 0)}")

    lines.extend(["", "## 风险详情"])

    if not report.findings:
        lines.append("- 未发现风险项。")
        return "\n".join(lines)

    for finding in report.findings:
        lines.extend(
            [
                "",
                f"### {finding.title}",
                f"- 编号：{finding.finding_id}",
                f"- 级别：{severity_label_map.get(finding.severity, finding.severity)}",
                f"- 摘要：{finding.summary}",
                f"- 证据：{finding.evidence}",
                f"- 修复建议：{finding.remediation}",
            ]
        )

    return "\n".join(lines)


def build_export_payload(
    *,
    task: ScanTask,
    report: ScanReport,
    summary: dict[str, str],
    serialized_task: dict[str, Any],
) -> dict[str, Any]:
    return {
        "task": serialized_task,
        "format": "markdown",
        "content": build_markdown_export(task=task, report=report, summary=summary),
    }
