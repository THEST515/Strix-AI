from __future__ import annotations

from src.backend.domain.models import ScanReport


def build_fixture_summary(report: ScanReport) -> dict[str, str]:
    counts = report.severity_counts()
    top_finding = report.findings[0].title if report.findings else "暂无风险"
    return {
        "executive_summary": f"当前夹具结果共包含 {len(report.findings)} 条风险，最高优先级问题为 {top_finding}。",
        "technical_analysis": f"夹具结果中高风险 {counts['high']} 条，中风险 {counts['medium']} 条，可用于演示前端风险分布和详情视图。",
        "recommendations": "当前为本地夹具模式，后续可切换到真实 Strix 结果并接入更完整的 AI 总结。",
    }
