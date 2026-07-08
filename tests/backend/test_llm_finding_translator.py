import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.llm_finding_translator import translate_findings_with_strix_llm


class LlmFindingTranslatorTests(unittest.TestCase):
    def test_returns_original_findings_when_llm_config_is_missing(self) -> None:
        findings = [
            {
                "title": "SSRF Filter Bypass",
                "summary": "English summary",
                "evidence": "English evidence",
                "remediation": "English remediation",
            }
        ]

        translated = translate_findings_with_strix_llm(findings, environment={})

        self.assertEqual(translated, findings)

    def test_uses_strix_llm_config_to_translate_findings(self) -> None:
        findings = [
            {
                "title": "SSRF Filter Bypass in ssrf2.php via Multiple Techniques",
                "summary": "The ssrf2.php application implements a server-side request forgery endpoint.",
                "evidence": "The ssrf2.php application accepts a URL via POST parameter \"url\".",
                "remediation": "Implement proper IP validation after DNS resolution.",
            }
        ]
        environment = {
            "STRIX_LLM": "deepseek/deepseek-v4-flash",
            "DEEPSEEK_API_KEY": "test-key",
        }
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            payload = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                [
                                    {
                                        "title": "ssrf2.php 中的 SSRF 过滤绕过（多种技巧）",
                                        "summary": "ssrf2.php 存在服务端请求伪造端点。",
                                        "evidence": "应用通过 POST 参数 url 接收地址并在服务端发起请求。",
                                        "remediation": "在 DNS 解析后对最终 IP 做严格校验。",
                                    }
                                ],
                                ensure_ascii=False,
                            )
                        }
                    }
                ]
            }
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        translated = translate_findings_with_strix_llm(
            findings,
            environment=environment,
            urlopen=fake_urlopen,
        )

        self.assertEqual(captured["url"], "https://api.deepseek.com/chat/completions")
        self.assertEqual(captured["authorization"], "Bearer test-key")
        self.assertEqual(captured["body"]["model"], "deepseek-v4-flash")
        self.assertEqual(translated[0]["title"], "ssrf2.php 中的 SSRF 过滤绕过（多种技巧）")
        self.assertIn("服务端请求伪造", translated[0]["summary"])


if __name__ == "__main__":
    unittest.main()
