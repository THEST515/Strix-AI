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
from src.backend.services.vulnerability_knowledge import ProductFingerprint


class _KnowledgeStub:
    def __init__(self) -> None:
        self.calls: list[ProductFingerprint] = []

    def cached_candidates(self, fingerprint: ProductFingerprint) -> list[dict[str, str]]:
        self.calls.append(fingerprint)
        return [
            {
                "finding_id": "external-cve-2026-0001",
                "cve_id": "CVE-2026-0001",
                "title": "CVE-2026-0001 候选：weblogic 12.2.1.3",
                "severity": "high",
                "summary": "外部漏洞目录显示该版本可能受影响，需继续验证。",
                "evidence": "NVD CPE 与明确识别的产品版本匹配，尚未证明目标可被利用。",
                "remediation": "核对厂商公告并升级到修复版本。",
                "verification_status": "candidate",
                "source": "external_vulnerability_knowledge",
            }
        ]


class RealRunLoaderTests(unittest.TestCase):
    def test_merges_cached_external_candidates_for_explicit_product_version(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "versioned-weblogic"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "versioned-weblogic",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-20T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [
                            {"original": "http://authorized-lab.example/console/login/LoginForm.jsp"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-version",
                            "title": "Oracle WebLogic Server console version disclosure",
                            "severity": "info",
                            "description": "The response identifies WebLogic Server version 12.2.1.3.",
                            "technical_analysis": "Version: 12.2.1.3",
                            "remediation_steps": "Remove version disclosure.",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            knowledge = _KnowledgeStub()

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                side_effect=lambda findings: findings,
            ):
                result = load_latest_real_run_report(
                    runs_root,
                    allow_statuses={"running"},
                    require_scan_results=False,
                    knowledge_service=knowledge,
                )

        self.assertEqual(len(knowledge.calls), 1)
        self.assertEqual(knowledge.calls[0].version, "12.2.1.3")
        self.assertEqual(result["report"]["confirmed_count"], 1)
        self.assertEqual(result["report"]["candidate_count"], 1)
        self.assertEqual(
            result["report"]["findings"][1]["source"],
            "external_vulnerability_knowledge",
        )
    def test_loads_sanitized_candidate_findings_from_running_run_notes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "candidate-run"
            (run_dir / ".state").mkdir(parents=True)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "candidate-run",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example/admin/"}],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / ".state" / "notes.json").write_text(
                json.dumps(
                    {
                        "evidence": {
                            "title": "Product version and authenticated access",
                            "content": "Version: 5.0.0\nDefault credentials found: admin:secret-value",
                            "category": "findings",
                        },
                        "method": {
                            "title": "Next action",
                            "content": "Need to continue exploring",
                            "category": "methodology",
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = load_latest_real_run_report(
                runs_root,
                target="http://authorized-lab.example/admin/",
                allow_statuses={"running"},
                require_scan_results=False,
            )

        self.assertEqual(result["report"]["confirmed_count"], 0)
        self.assertEqual(result["report"]["candidate_count"], 1)
        self.assertEqual(result["report"]["findings"][0]["verification_status"], "candidate")
        self.assertNotIn("secret-value", result["report"]["findings"][0]["evidence"])
        self.assertIn("候选", result["summary"]["executive_summary"])

    def test_autonomously_adds_web_logic_cve_candidate_without_user_cve_instruction(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "weblogic-run"
            run_dir.mkdir()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "weblogic-run",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-20T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://authorized-lab.example/ws_utc/config.do"}],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "strix.log").write_text(
                "WebLogic ws_utc keystore file upload is reachable without authentication.\n",
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "vuln-0001",
                            "title": "Unauthenticated WebLogic settings access",
                            "severity": "critical",
                            "description": "The keystore settings endpoint allows file upload without authentication.",
                            "technical_analysis": "The ws_utc settings API responds without authentication.",
                            "remediation_steps": "Restrict access to ws_utc and enable authentication.",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                side_effect=lambda findings: findings,
            ):
                result = load_latest_real_run_report(
                    runs_root,
                    target="http://authorized-lab.example/ws_utc/config.do",
                    allow_statuses={"running"},
                    require_scan_results=False,
                )

        self.assertEqual(result["report"]["confirmed_count"], 1)
        self.assertEqual(result["report"]["candidate_count"], 1)
        self.assertIn("CVE-2018-2894", result["report"]["findings"][1]["title"])
        self.assertEqual(result["report"]["findings"][1]["verification_status"], "candidate")

    def test_confirmed_cve_finding_replaces_matching_candidate_note(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "confirmed-run"
            (run_dir / ".state").mkdir(parents=True)
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "confirmed-run",
                        "status": "completed",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": "2026-07-19T00:04:00+00:00",
                        "targets_info": [{"original": "http://authorized-lab.example/admin/"}],
                        "scan_results": {
                            "executive_summary": "confirmed",
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
                        "id": "vuln-1",
                        "title": "CVE-2020-5504 SQL Injection",
                        "severity": "high",
                        "description": "confirmed SQL injection",
                        "technical_analysis": "reproducible request",
                        "remediation_steps": "upgrade",
                    }]
                ),
                encoding="utf-8",
            )
            (run_dir / ".state" / "notes.json").write_text(
                json.dumps({
                    "cve-note": {
                        "title": "Possible CVE-2020-5504",
                        "content": "CVE-2020-5504 matched product Version: 5.0.0",
                        "category": "findings",
                    }
                }),
                encoding="utf-8",
            )

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                side_effect=lambda findings: findings,
            ):
                result = load_latest_real_run_report(runs_root)

        self.assertEqual(result["report"]["confirmed_count"], 1)
        self.assertEqual(result["report"]["candidate_count"], 0)
        self.assertEqual(len(result["report"]["findings"]), 1)
        self.assertEqual(result["report"]["findings"][0]["verification_status"], "confirmed")

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

    def test_does_not_cache_untranslated_llm_fallback(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_running"
            run_dir.mkdir()
            vulnerabilities = [
                {
                    "id": "vuln-0001",
                    "title": "Weak Database Password",
                    "severity": "critical",
                    "description": "The administrative account accepts a weak password.",
                    "technical_analysis": "An authenticated administrative session was established.",
                    "remediation_steps": "Set a unique high-entropy password and rotate credentials.",
                }
            ]
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_running",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://localhost/admin"}],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(vulnerabilities),
                encoding="utf-8",
            )

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                side_effect=lambda findings: findings,
            ):
                result = load_latest_real_run_report(
                    runs_root,
                    target="http://localhost/admin",
                    allow_statuses={"running"},
                    require_scan_results=False,
                )

            self.assertEqual(result["report"]["findings"][0]["title"], "Weak Database Password")
            self.assertFalse((run_dir / "finding_translations.zh-CN.json").exists())

    def test_retries_when_cached_finding_is_not_translated(self) -> None:
        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_dir = runs_root / "01_running"
            run_dir.mkdir()
            vulnerabilities = [
                {
                    "id": "vuln-0001",
                    "title": "Weak Database Password",
                    "severity": "critical",
                    "description": "The administrative account accepts a weak password.",
                    "technical_analysis": "An authenticated administrative session was established.",
                    "remediation_steps": "Set a unique high-entropy password and rotate credentials.",
                }
            ]
            source_hash = sha256(
                json.dumps(vulnerabilities, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": "01_running",
                        "status": "running",
                        "scan_mode": "standard",
                        "start_time": "2026-07-19T00:00:00+00:00",
                        "end_time": None,
                        "targets_info": [{"original": "http://localhost/admin"}],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerabilities.json").write_text(
                json.dumps(vulnerabilities),
                encoding="utf-8",
            )
            (run_dir / "finding_translations.zh-CN.json").write_text(
                json.dumps(
                    {
                        "source_hash": source_hash,
                        "findings": [
                            {
                                "finding_id": "vuln-0001",
                                "title": "Weak Database Password",
                                "severity": "critical",
                                "summary": "The administrative account accepts a weak password.",
                                "evidence": "An authenticated administrative session was established.",
                                "remediation": "Set a unique high-entropy password and rotate credentials.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            translated = [
                {
                    "finding_id": "vuln-0001",
                    "title": "数据库管理账户使用弱口令",
                    "severity": "critical",
                    "summary": "管理账户接受弱口令登录。",
                    "evidence": "已建立具有管理权限的认证会话。",
                    "remediation": "设置唯一的高强度口令并轮换凭据。",
                }
            ]

            with patch(
                "src.backend.services.real_run_loader.translate_findings_with_strix_llm",
                return_value=translated,
            ) as translator:
                result = load_latest_real_run_report(
                    runs_root,
                    target="http://localhost/admin",
                    allow_statuses={"running"},
                    require_scan_results=False,
                )

            translator.assert_called_once()
            self.assertEqual(result["report"]["findings"][0]["title"], "数据库管理账户使用弱口令")

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
