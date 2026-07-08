import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.summary_localizer import (
    localize_finding_fields,
    localize_summary_fields,
)


class SummaryLocalizerTests(unittest.TestCase):
    def test_localizes_common_strix_english_summary_phrases_to_chinese(self) -> None:
        localized = localize_summary_fields(
            {
                "executive_summary": "## Executive Summary\n\nOverall Risk Level: Low\n\nNo actively exploitable security vulnerabilities were identified.",
                "technical_analysis": "## Technical Analysis\n\nDemo/Fixture mode (default) - uses hardcoded sample data from `fixtureData.js`.",
                "recommendations": "## Recommendations\n\nAdd a Content Security Policy meta tag.\n\nNo findings.",
            }
        )

        self.assertIn("执行摘要", localized["executive_summary"])
        self.assertIn("总体风险等级：低", localized["executive_summary"])
        self.assertIn("未发现可直接利用的安全漏洞", localized["executive_summary"])
        self.assertIn("技术分析", localized["technical_analysis"])
        self.assertIn("演示样例模式（默认）", localized["technical_analysis"])
        self.assertIn("修复建议", localized["recommendations"])
        self.assertIn("添加内容安全策略", localized["recommendations"])
        self.assertIn("未发现风险项", localized["recommendations"])

    def test_localizes_real_run_finding_fields_to_chinese(self) -> None:
        localized = localize_finding_fields(
            {
                "title": "Missing Authentication",
                "summary": "endpoint accepts password change without auth",
                "evidence": "POST /UserManager/xgmm3 succeeds anonymously",
                "remediation": "require authenticated session and server-side identity checks",
            }
        )

        self.assertEqual(localized["title"], "缺少身份认证")
        self.assertNotEqual(localized["summary"], "endpoint accepts password change without auth")
        self.assertNotIn("without auth", localized["summary"])
        self.assertNotIn("succeeds anonymously", localized["evidence"])
        self.assertNotIn("require authenticated session", localized["remediation"])


if __name__ == "__main__":
    unittest.main()
