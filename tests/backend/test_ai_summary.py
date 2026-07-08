import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.domain.models import Finding, ScanReport
from src.backend.services.ai_summary import build_fixture_summary


class AiSummaryTests(unittest.TestCase):
    def test_build_fixture_summary_uses_report_findings_and_counts(self) -> None:
        report = ScanReport(
            task_id="task-001",
            findings=[
                Finding(
                    finding_id="finding-001",
                    title="个人资料接口存在越权访问",
                    severity="high",
                    summary="资料查询接口缺少有效归属校验，可跨账号读取用户信息。",
                    evidence="替换用户编号后，接口返回了其他用户的数据。",
                    remediation="增加服务端归属校验。",
                ),
                Finding(
                    finding_id="finding-002",
                    title="错误信息泄露内部细节",
                    severity="medium",
                    summary="堆栈信息被直接返回给前端。",
                    evidence="500 响应包含 traceback。",
                    remediation="关闭调试输出。",
                ),
            ],
        )

        summary = build_fixture_summary(report)

        self.assertIn("2 条风险", summary["executive_summary"])
        self.assertIn("个人资料接口存在越权访问", summary["executive_summary"])
        self.assertIn("高风险 1 条", summary["technical_analysis"])
        self.assertIn("中风险 1 条", summary["technical_analysis"])
        self.assertIn("真实 Strix 结果", summary["recommendations"])


if __name__ == "__main__":
    unittest.main()
