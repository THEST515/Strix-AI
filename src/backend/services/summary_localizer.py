from __future__ import annotations

import re


STATUS_TRANSLATIONS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
    "completed": "已完成",
    "partial": "部分结果",
    "running": "执行中",
    "created": "已创建",
    "demo_fixture_loaded": "演示结果",
    "quick": "快速",
    "standard": "标准",
    "deep": "深度",
}

PHRASE_REPLACEMENTS: list[tuple[str, str]] = [
    ("# Executive Summary", "# 执行摘要"),
    ("## Executive Summary", "## 执行摘要"),
    ("# Methodology", "# 评估方法"),
    ("## Methodology", "## 评估方法"),
    ("# Technical Analysis", "# 技术分析"),
    ("## Technical Analysis", "## 技术分析"),
    ("# Recommendations", "# 修复建议"),
    ("## Recommendations", "## 修复建议"),
    ("### Codebase Architecture", "### 代码结构"),
    ("### Security Control Review", "### 安全控制审查"),
    ("### Tool Results Summary", "### 工具结果汇总"),
    ("### Conclusion", "### 结论"),
    ("### Immediate (Low Effort, Medium Impact)", "### 立即可做（低成本，中等收益）"),
    ("### Short-term (Medium Effort, Low Impact)", "### 短期优化（中等成本，较低风险）"),
    ("### Not Required", "### 暂不需要"),
    ("Overall Risk Level:", "总体风险等级："),
    ("**Overall Risk Level: Low**", "**总体风险等级：低**"),
    ("**Overall Risk Level: Medium**", "**总体风险等级：中**"),
    ("**Overall Risk Level: High**", "**总体风险等级：高**"),
    ("**Overall Risk Level: Critical**", "**总体风险等级：严重**"),
    ("No actively exploitable security vulnerabilities were identified.", "未发现可直接利用的安全漏洞。"),
    ("No findings.", "未发现风险项。"),
    ("Demo/Fixture mode (default)", "演示样例模式（默认）"),
    ("Live API mode", "实时接口模式"),
    ("Hardening Recommendations", "加固建议"),
    ("Key strengths observed:", "主要优点："),
    ("The application is free from actively exploitable security vulnerabilities.", "当前应用未发现可直接利用的安全漏洞。"),
    ("The primary recommendations are hardening improvements rather than vulnerability fixes.", "当前建议以加固优化为主，而不是漏洞修复。"),
    ("Add a Content Security Policy meta tag", "添加内容安全策略（CSP）元标签"),
    ("Add client-side input validation for the target URL field", "为目标地址输入框增加前端校验"),
    ("The codebase demonstrates a strong security baseline:", "当前代码基线较稳健："),
    ("Same-origin API interaction only", "仅进行同源 API 调用"),
    ("Zero dependency footprint", "无额外第三方依赖"),
    ("No secrets, hardcoded credentials, or dependency vulnerabilities were found in the codebase.", "代码库中未发现密钥泄露、硬编码凭据或依赖漏洞。"),
    ("This assessment followed a white-box (source-available) security testing methodology:", "本次评估采用白盒（可读源码）安全测试方法："),
    (
        "A white-box security assessment was performed on the Strix AI Security Analysis Platform, a university course project prototype.",
        "本次以白盒方式审查了 Strix AI 安全分析平台课程原型。",
    ),
    (
        "One vulnerability was identified and remediated: a DOM-based Cross-Site Scripting (XSS) vulnerability (CWE-79, CVSS 5.4) in the frontend application.",
        "曾识别并修复 1 项漏洞：前端中的 DOM 型跨站脚本漏洞（XSS，CWE-79，CVSS 5.4）。",
    ),
    (
        "The vulnerability allowed injection of arbitrary HTML and JavaScript through unsanitized user input being rendered via innerHTML.",
        "该漏洞允许未经过滤的用户输入通过 innerHTML 注入任意 HTML 与 JavaScript。",
    ),
    ("The fix has been applied and verified.", "相关修复已完成并通过验证。"),
    ("1. **Full source-code review**", "1. **完整源码审查**"),
    ("2. **Automated Static Analysis (SAST)**", "2. **自动化静态分析（SAST）**"),
    ("3. **Secret Scanning**", "3. **敏感信息扫描**"),
    ("4. **Dependency & Misconfiguration Scanning**", "4. **依赖与错误配置扫描**"),
    ("5. **DOM/Browser API Audit**", "5. **DOM / 浏览器 API 审查**"),
]

FINDING_REPLACEMENTS: list[tuple[str, str]] = [
    ("Missing Authentication", "缺少身份认证"),
    ("Missing Authorization", "缺少权限校验"),
    ("Broken Access Control", "访问控制失效"),
    ("Insecure Direct Object Reference", "不安全的直接对象引用"),
    ("SQL Injection", "SQL 注入"),
    ("Cross-Site Scripting", "跨站脚本"),
    ("Cross-Site Request Forgery", "跨站请求伪造"),
    ("Server-Side Request Forgery", "服务端请求伪造"),
    ("Remote Code Execution", "远程代码执行"),
    ("Path Traversal", "路径遍历"),
    ("Command Injection", "命令注入"),
    ("Authentication Bypass", "身份认证绕过"),
    ("Privilege Escalation", "权限提升"),
    ("XML External Entity", "XML 外部实体"),
    ("XXE", "XXE"),
    ("Server-Side Template Injection", "服务端模板注入"),
    ("SSTI", "SSTI"),
    ("Open Redirect", "开放重定向"),
    ("Local File Inclusion", "本地文件包含"),
    ("LFI", "LFI"),
    ("Remote File Inclusion", "远程文件包含"),
    ("RFI", "RFI"),
    ("Insecure Deserialization", "不安全的反序列化"),
    ("Sensitive Information Exposure", "敏感信息泄露"),
    ("Default Credentials", "默认凭据"),
    ("Weak Password Policy", "弱密码策略"),
    ("Security Misconfiguration", "安全配置不当"),
    ("Clickjacking", "点击劫持"),
    ("Arbitrary File Upload", "任意文件上传"),
    ("endpoint accepts password change without auth", "接口在无认证情况下接受密码修改请求"),
    ("POST /UserManager/xgmm3 succeeds anonymously", "匿名访问时，POST /UserManager/xgmm3 仍可成功执行"),
    ("require authenticated session and server-side identity checks", "要求已认证会话，并在服务端执行身份归属校验"),
    ("succeeds anonymously", "可在匿名访问下成功执行"),
    ("without auth", "无需认证"),
    ("without authorization", "无需授权"),
    ("Enable CSRF validation", "启用 CSRF 校验"),
    ("disable XXE resolution", "禁用 XXE 解析"),
    ("block open redirect sinks", "阻断开放重定向路径"),
]


def localize_text(text: str) -> str:
    localized = text or ""
    for source, target in PHRASE_REPLACEMENTS:
        localized = localized.replace(source, target)

    localized = re.sub(r"\bLow\b", "低", localized)
    localized = re.sub(r"\bMedium\b", "中", localized)
    localized = re.sub(r"\bHigh\b", "高", localized)
    localized = re.sub(r"\bCritical\b", "严重", localized)
    localized = re.sub(r"\bInfo\b", "提示", localized)
    localized = re.sub(r"总体风险等级：\s+", "总体风险等级：", localized)
    return localized


def localize_finding_text(text: str) -> str:
    localized = text or ""
    for source, target in FINDING_REPLACEMENTS:
        localized = localized.replace(source, target)
    return localized


def localize_finding_fields(finding: dict[str, str]) -> dict[str, str]:
    return {
        "title": localize_finding_text(finding.get("title", "")),
        "summary": localize_finding_text(finding.get("summary", "")),
        "evidence": localize_finding_text(finding.get("evidence", "")),
        "remediation": localize_finding_text(finding.get("remediation", "")),
    }


def ensure_heading(text: str, heading: str) -> str:
    stripped = text.strip()
    if not stripped:
        return f"## {heading}"
    if stripped.startswith("#"):
        return stripped
    if "\n" not in stripped and len(stripped) < 80:
        return stripped
    return f"## {heading}\n\n{stripped}"


def localize_summary_fields(summary: dict[str, str]) -> dict[str, str]:
    return {
        "executive_summary": ensure_heading(
            localize_text(summary.get("executive_summary", "")),
            "执行摘要",
        ),
        "technical_analysis": ensure_heading(
            localize_text(summary.get("technical_analysis", "")),
            "技术分析",
        ),
        "recommendations": ensure_heading(
            localize_text(summary.get("recommendations", "")),
            "修复建议",
        ),
    }
