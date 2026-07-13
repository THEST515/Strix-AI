import json
import shutil
import sys
import unittest
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.services.real_run_loader import load_latest_real_run_report


class RealRunLoaderTests(unittest.TestCase):
    def test_loads_latest_real_run_report_from_strix_runs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            shutil.copytree(ROOT / "tests" / "fixtures" / "real_run_sample", runs_root / "01_62fb")

            result = load_latest_real_run_report(runs_root)

        self.assertEqual(result["run"]["run_id"], "01_62fb")
        self.assertEqual(result["run"]["status"], "completed")
        self.assertEqual(result["report"]["task_id"], "01_62fb")
        self.assertEqual(result["report"]["severity_counts"]["medium"], 1)
        self.assertEqual(result["report"]["findings"][0]["finding_id"], "vuln-0001")
        self.assertIn("执行摘要", result["summary"]["executive_summary"])
        self.assertIn("总体风险等级：中", result["summary"]["executive_summary"])

    def test_loads_completed_run_without_vulnerabilities_file_as_empty_findings(self) -> None:
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

            result = load_latest_real_run_report(runs_root)

        self.assertEqual(result["run"]["run_id"], "01_zero")
        self.assertEqual(result["report"]["severity_counts"]["medium"], 0)
        self.assertEqual(result["report"]["findings"], [])
        self.assertEqual(result["summary"]["executive_summary"], "no findings")

    def test_skips_latest_interrupted_run_without_scan_results(self) -> None:
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

            result = load_latest_real_run_report(runs_root)

        self.assertEqual(result["run"]["run_id"], "01_completed")
        self.assertEqual(result["report"]["findings"], [])
        self.assertEqual(result["summary"]["executive_summary"], "usable summary")

    def test_can_load_partial_findings_from_running_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_running"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_running",
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

            result = load_latest_real_run_report(
                runs_root,
                target="http://localhost:8888/",
                allow_statuses={"running", "completed", "failed"},
                require_scan_results=False,
            )

        self.assertEqual(result["run"]["run_id"], "01_running")
        self.assertEqual(result["run"]["status"], "running")
        self.assertEqual(result["report"]["severity_counts"]["critical"], 1)
        self.assertEqual(result["report"]["findings"][0]["finding_id"], "vuln-0008")
        self.assertEqual(result["report"]["findings"][0]["title"], "缺少身份认证")
        self.assertNotEqual(
            result["report"]["findings"][0]["summary"],
            "endpoint accepts password change without auth",
        )
        self.assertNotIn("without auth", result["report"]["findings"][0]["summary"])
        self.assertNotIn("succeeds anonymously", result["report"]["findings"][0]["evidence"])
        self.assertNotIn("require authenticated session", result["report"]["findings"][0]["remediation"])
        self.assertIn("已记录", result["summary"]["executive_summary"])

    def test_prefers_llm_translated_findings_when_available(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_completed"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_completed",
                        "status": "completed",
                        "scan_mode": "deep",
                        "start_time": "2026-07-08T00:00:00+00:00",
                        "end_time": "2026-07-08T00:03:00+00:00",
                        "targets_info": [{"original": "http://host.docker.internal/4.7/ssrf2.php"}],
                        "scan_results": {
                            "executive_summary": "english summary",
                            "technical_analysis": "english analysis",
                            "recommendations": "english recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-0001",
                            "title": "SSRF Filter Bypass in ssrf2.php via Multiple Techniques",
                            "severity": "critical",
                            "description": "The ssrf2.php application implements a server-side request forgery endpoint.",
                            "technical_analysis": "The ssrf2.php application accepts a URL via POST parameter url.",
                            "remediation_steps": "Implement proper IP validation after DNS resolution.",
                        }
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                return_value=[
                    {
                        "finding_id": "vuln-0001",
                        "title": "ssrf2.php 中的 SSRF 过滤绕过（多种技巧）",
                        "severity": "critical",
                        "summary": "ssrf2.php 存在服务端请求伪造端点。",
                        "evidence": "应用通过 POST 参数 url 接收地址并在服务端发起请求。",
                        "remediation": "在 DNS 解析后对最终 IP 做严格校验。",
                    }
                ],
            ):
                result = load_latest_real_run_report(
                    runs_root,
                    target="http://host.docker.internal/4.7/ssrf2.php",
                )

        self.assertEqual(result["report"]["findings"][0]["title"], "ssrf2.php 中的 SSRF 过滤绕过（多种技巧）")
        self.assertIn("服务端请求伪造", result["report"]["findings"][0]["summary"])


    def test_persists_translated_findings_cache_and_reuses_it_without_retranslation(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_completed"
            run_dir.mkdir()
            vulnerabilities = [
                {
                    "id": "vuln-0001",
                    "title": "SQL Injection in search endpoint",
                    "severity": "high",
                    "description": "The search parameter is concatenated into a SQL statement.",
                    "technical_analysis": "A single quote in q changes the backend query behavior.",
                    "remediation_steps": "Use parameterized queries and strict server-side validation.",
                }
            ]
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_completed",
                        "status": "completed",
                        "scan_mode": "deep",
                        "start_time": "2026-07-08T00:00:00+00:00",
                        "end_time": "2026-07-08T00:03:00+00:00",
                        "targets_info": [{"original": "http://localhost/search"}],
                        "scan_results": {
                            "executive_summary": "english summary",
                            "technical_analysis": "english analysis",
                            "recommendations": "english recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(vulnerabilities, ensure_ascii=False),
                encoding="utf-8",
            )

            translated = [
                {
                    "finding_id": "vuln-0001",
                    "title": "search 接口存在 SQL 注入",
                    "severity": "high",
                    "summary": "search 参数被直接拼接进 SQL 语句。",
                    "evidence": "q 参数中的单引号会改变后端查询行为。",
                    "remediation": "使用参数化查询并补充严格的服务端校验。",
                }
            ]
            expected_source_hash = sha256(
                json.dumps(vulnerabilities, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                return_value=translated,
            ) as translator:
                first = load_latest_real_run_report(runs_root, target="http://localhost/search")

            translator.assert_called_once()
            cache_path = run_dir / "finding_translations.zh-CN.json"
            self.assertTrue(cache_path.exists())
            cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
            self.assertEqual(cache_payload["source_hash"], expected_source_hash)
            self.assertEqual(cache_payload["findings"][0]["title"], "search 接口存在 SQL 注入")
            self.assertEqual(first["report"]["findings"][0]["title"], "search 接口存在 SQL 注入")

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                side_effect=AssertionError("translator should not be called when cache exists"),
            ):
                second = load_latest_real_run_report(runs_root, target="http://localhost/search")

        self.assertEqual(second["report"]["findings"][0]["title"], "search 接口存在 SQL 注入")

    def test_localizes_high_frequency_web_vulnerability_terms_without_llm(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_completed"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_completed",
                        "status": "completed",
                        "scan_mode": "deep",
                        "start_time": "2026-07-08T00:00:00+00:00",
                        "end_time": "2026-07-08T00:03:00+00:00",
                        "targets_info": [{"original": "http://localhost/app"}],
                        "scan_results": {
                            "executive_summary": "english summary",
                            "technical_analysis": "english analysis",
                            "recommendations": "english recommendations",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-0009",
                            "title": "Cross-Site Request Forgery in profile update endpoint",
                            "severity": "medium",
                            "description": "The endpoint is vulnerable to XML External Entity and Open Redirect chaining.",
                            "technical_analysis": "Server-Side Template Injection can be combined with Local File Inclusion.",
                            "remediation_steps": "Enable CSRF validation, disable XXE resolution, and block open redirect sinks.",
                        }
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                side_effect=lambda findings: findings,
            ):
                result = load_latest_real_run_report(runs_root, target="http://localhost/app")

        finding = result["report"]["findings"][0]
        self.assertNotIn("Cross-Site Request Forgery", finding["title"])
        self.assertIn("跨站请求伪造", finding["title"])
        self.assertIn("XML 外部实体", finding["summary"])
        self.assertIn("开放重定向", finding["summary"])
        self.assertIn("服务端模板注入", finding["evidence"])
        self.assertIn("本地文件包含", finding["evidence"])
        self.assertIn("CSRF", finding["remediation"])


if __name__ == "__main__":
    unittest.main()
