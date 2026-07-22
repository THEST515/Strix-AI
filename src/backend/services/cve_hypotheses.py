from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True, slots=True)
class CveSignature:
    cve_id: str
    product_groups: tuple[tuple[str, ...], ...]
    behavior_groups: tuple[tuple[str, ...], ...]
    title: str
    summary: str
    evidence: str
    remediation: str
    severity: str = "high"

    def matches(self, text: str) -> bool:
        normalized = _normalize(text)
        return all(
            any(_normalize(token) in normalized for token in alternatives)
            for alternatives in (*self.product_groups, *self.behavior_groups)
        )


BUILTIN_CVE_SIGNATURES: tuple[CveSignature, ...] = (
    CveSignature(
        cve_id="CVE-2018-2894",
        product_groups=(("weblogic",), ("ws_utc", "web services test client")),
        behavior_groups=(
            ("keystore", "keystore settings"),
            ("upload", "file upload"),
            ("unauthenticated", "without authentication", "without auth", "no authentication"),
        ),
        title="CVE-2018-2894 候选：WebLogic ws_utc 文件上传",
        summary=(
            "已观察到 WebLogic Web Services Test Client 的未认证 keystore/文件上传相关行为，"
            "与 CVE-2018-2894 的攻击面特征匹配。"
        ),
        evidence=(
            "黑盒证据显示 ws_utc 设置接口可在未认证状态下访问，并出现 keystore 或文件上传相关行为；"
            "仍需确认受影响版本和可复现文件上传结果。"
        ),
        remediation="核对 WebLogic 版本并升级到厂商修复版本，关闭或限制 ws_utc 访问并启用认证。",
        severity="critical",
    ),
    CveSignature(
        cve_id="CVE-2020-5504",
        product_groups=(("phpmyadmin", "php my admin"),),
        behavior_groups=(
            ("sql injection", "sql query", "sql statement"),
            ("search", "query parameter", "quote character", "changes query behavior"),
        ),
        title="CVE-2020-5504 候选：phpMyAdmin SQL 注入",
        summary="已观察到 phpMyAdmin 查询入口存在 SQL 行为异常，与 CVE-2020-5504 特征匹配。",
        evidence="黑盒请求改变了查询行为；仍需确认受影响版本、前置条件和可重复响应差异。",
        remediation="核对 phpMyAdmin 版本并升级到修复版本，限制管理入口访问并使用参数化查询。",
        severity="high",
    ),
)


def build_cve_hypotheses(
    *,
    target: str,
    vulnerabilities: Iterable[dict],
    candidate_evidence: Iterable[dict] = (),
    signatures: Iterable[CveSignature] = BUILTIN_CVE_SIGNATURES,
) -> list[dict[str, str]]:
    vulnerability_text = "\n".join(
        " ".join(str(item.get(field, "")) for field in ("title", "description", "technical_analysis", "remediation_steps"))
        for item in vulnerabilities
    )
    candidate_text = "\n".join(
        " ".join(str(item.get(field, "")) for field in ("title", "summary", "evidence"))
        for item in candidate_evidence
    )
    # Only structured findings and already-filtered candidate notes qualify;
    # raw model planning logs are intentionally excluded.
    observed_text = f"{target}\n{vulnerability_text}\n{candidate_text}"
    existing_text = _normalize(vulnerability_text)
    candidates: list[dict[str, str]] = []

    for signature in signatures:
        if signature.matches(observed_text) and _normalize(signature.cve_id) not in existing_text:
            candidates.append(
                {
                    "finding_id": f"hypothesis-{signature.cve_id.lower()}",
                    "cve_id": signature.cve_id,
                    "title": signature.title,
                    "severity": signature.severity,
                    "summary": signature.summary,
                    "evidence": signature.evidence,
                    "remediation": signature.remediation,
                    "verification_status": "candidate",
                    "source": "cve_hypothesis",
                }
            )

    return candidates


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", str(value).lower()).strip()
