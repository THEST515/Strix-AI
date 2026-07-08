from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from typing import Any
from urllib.request import Request, urlopen as default_urlopen


def translate_findings_with_strix_llm(
    findings: list[dict[str, str]],
    *,
    environment: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] = default_urlopen,
) -> list[dict[str, str]]:
    if not findings:
        return findings

    env = dict(os.environ if environment is None else environment)
    config = _resolve_llm_translation_config(env)
    if config is None:
        return findings

    translatable = [
        {
            "title": item.get("title", ""),
            "summary": item.get("summary", ""),
            "evidence": item.get("evidence", ""),
            "remediation": item.get("remediation", ""),
        }
        for item in findings
    ]
    if not any(_contains_english_text_block(item) for item in translatable):
        return findings

    prompt = (
        "你是安全漏洞报告翻译助手。请把输入 JSON 数组中每一项的 title、summary、evidence、remediation "
        "翻译成专业、自然、面向中文课程演示的简体中文。保持技术含义准确，不要省略漏洞名称、端点、参数、"
        "协议、函数名、文件名、IP、路径、PoC 关键信息。输出必须是 JSON 数组，不要添加 markdown 代码块，不要解释。"
    )
    body = {
        "model": config["model"],
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(translatable, ensure_ascii=False)},
        ],
    }
    request = Request(
        config["url"],
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['api_key']}",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        translated_blocks = json.loads(_strip_code_fence(content))
    except Exception:
        return findings

    if not isinstance(translated_blocks, list) or len(translated_blocks) != len(findings):
        return findings

    merged: list[dict[str, str]] = []
    for original, translated in zip(findings, translated_blocks):
        if not isinstance(translated, dict):
            return findings
        merged.append(
            {
                **original,
                "title": str(translated.get("title", original.get("title", ""))),
                "summary": str(translated.get("summary", original.get("summary", ""))),
                "evidence": str(translated.get("evidence", original.get("evidence", ""))),
                "remediation": str(translated.get("remediation", original.get("remediation", ""))),
            }
        )

    return merged


def _resolve_llm_translation_config(environment: Mapping[str, str]) -> dict[str, str] | None:
    model = environment.get("STRIX_LLM", "").strip()
    if not model:
        return None

    api_key = environment.get("LLM_API_KEY") or environment.get("DEEPSEEK_API_KEY")
    if not api_key:
        return None

    if model.startswith("deepseek/"):
        return {
            "model": model.split("/", 1)[1],
            "api_key": api_key,
            "url": "https://api.deepseek.com/chat/completions",
        }

    return None


def _strip_code_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    return stripped


def _contains_english_text_block(item: dict[str, str]) -> bool:
    text = " ".join(item.values())
    ascii_letters = sum(1 for char in text if char.isascii() and char.isalpha())
    cjk_chars = sum(1 for char in text if "\u4e00" <= char <= "\u9fff")
    return ascii_letters > cjk_chars
