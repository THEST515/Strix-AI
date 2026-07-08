from __future__ import annotations

import json
from pathlib import Path

from src.backend.domain.models import Finding, ScanReport


def load_fixture_report(path: str | Path) -> ScanReport:
    fixture_path = Path(path)
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))

    findings = [
        Finding(
            finding_id=item["finding_id"],
            title=item["title"],
            severity=item["severity"],
            summary=item["summary"],
            evidence=item["evidence"],
            remediation=item["remediation"],
        )
        for item in payload["findings"]
    ]

    return ScanReport(task_id=payload["task_id"], findings=findings)
