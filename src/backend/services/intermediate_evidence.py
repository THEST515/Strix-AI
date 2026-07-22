from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_CONCRETE_EVIDENCE_PATTERN = re.compile(
    r"\bversion\s*:|default credentials found|logged in|successful(?:ly)? authenticated|"
    r"superuser privileges|grant all privileges|accessible\s+at|\bload_file works|"
    r"\bCVE-\d{4}-\d+|(?:request|endpoint).*(?:succeeds|returned|status\s*2\d\d)",
    re.IGNORECASE,
)
_LINE_SECRET_PATTERN = re.compile(
    r"(?im)^(\s*(?:default credentials found|session cookie|cookie|csrf(?: token)?|"
    r"token|api[_ -]?key|password|passwd|pwd)\s*:\s*).+$"
)
_MARKDOWN_SECRET_PATTERN = re.compile(
    r"(?im)^([^\n]{0,120}(?:default credentials found|session cookie|cookie|csrf(?: token)?|"
    r"token|api[_ -]?key|password|passwd|pwd)\*{0,2}\s*:\s*).+$"
)
_INLINE_SECRET_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|api[_ -]?key|cookie|session(?: id)?)\s*[=:]\s*)"
    r"[^\s,;]+"
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def load_candidate_findings(run_dir: Path) -> list[dict[str, str]]:
    notes_path = run_dir / ".state" / "notes.json"
    try:
        payload = json.loads(notes_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(payload, dict):
        return []

    findings: list[dict[str, str]] = []
    for note_id, note in payload.items():
        finding = _candidate_from_note(str(note_id), note)
        if finding is not None:
            findings.append(finding)
    return findings


def merge_confirmed_and_candidate_findings(
    confirmed: list[dict[str, str]],
    candidates: list[dict[str, str]],
) -> list[dict[str, str]]:
    confirmed_cves = {
        cve.upper()
        for finding in confirmed
        for cve in _CVE_PATTERN.findall(f"{finding.get('title', '')} {finding.get('evidence', '')}")
    }
    confirmed_titles = {_normalize_title(finding.get("title", "")) for finding in confirmed}
    retained_candidates: list[dict[str, str]] = []
    retained_candidate_cves: set[str] = set()
    retained_candidate_titles: set[str] = set()
    for candidate in candidates:
        candidate_text = f"{candidate.get('title', '')} {candidate.get('evidence', '')}"
        candidate_cves = {cve.upper() for cve in _CVE_PATTERN.findall(candidate_text)}
        candidate_title = _normalize_title(candidate.get("title", ""))
        same_title = any(
            candidate_title and (candidate_title in title or title in candidate_title)
            for title in confirmed_titles
            if title
        )
        if candidate_cves.intersection(confirmed_cves) or same_title:
            continue
        if candidate_cves.intersection(retained_candidate_cves) or candidate_title in retained_candidate_titles:
            continue
        retained_candidates.append(candidate)
        retained_candidate_cves.update(candidate_cves)
        if candidate_title:
            retained_candidate_titles.add(candidate_title)
    return [*confirmed, *retained_candidates]


def _candidate_from_note(note_id: str, note: Any) -> dict[str, str] | None:
    if not isinstance(note, dict) or note.get("category") != "findings":
        return None

    title = str(note.get("title", "")).strip()
    content = str(note.get("content", "")).strip()
    if not title or not content or not _CONCRETE_EVIDENCE_PATTERN.search(content):
        return None

    try:
        safe_title = _redact_sensitive(title)
        safe_content = _redact_sensitive(content)
    except (TypeError, re.error):
        return None

    return {
        "finding_id": f"note-{note_id}",
        "title": safe_title,
        "severity": "info",
        "summary": f"Strix 已记录待进一步复现的候选证据：{safe_title}",
        "evidence": safe_content,
        "remediation": "复核原始请求与响应，完成最小可复现验证后再按正式漏洞处置。",
        "verification_status": "candidate",
        "source": "strix_note",
    }


def _redact_sensitive(value: str) -> str:
    redacted = _MARKDOWN_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}[REDACTED]", value)
    redacted = _LINE_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)
    redacted = _INLINE_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)
    return _BEARER_PATTERN.sub("Bearer [REDACTED]", redacted)


def _normalize_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())
