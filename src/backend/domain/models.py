from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum


class TaskStatus(StrEnum):
    DRAFT = "draft"
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    PARSING = "parsing"
    SUMMARIZING = "summarizing"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DEMO_FIXTURE_LOADED = "demo_fixture_loaded"


@dataclass(slots=True, frozen=True)
class ScanTask:
    task_id: str
    name: str
    target: str
    scan_mode: str = "quick"
    instruction: str | None = None
    instruction_file: str | None = None
    status: TaskStatus = TaskStatus.DRAFT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None

    def with_status(self, status: TaskStatus) -> "ScanTask":
        return replace(self, status=status)


@dataclass(slots=True, frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    summary: str
    evidence: str
    remediation: str
    verification_status: str = "confirmed"
    source: str = "strix_report"


@dataclass(slots=True, frozen=True)
class ScanReport:
    task_id: str
    findings: list[Finding]

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.verification_status != "confirmed":
                continue
            if finding.severity not in counts:
                counts[finding.severity] = 0
            counts[finding.severity] += 1
        return counts

    def confirmed_count(self) -> int:
        return sum(finding.verification_status == "confirmed" for finding in self.findings)

    def candidate_count(self) -> int:
        return sum(finding.verification_status == "candidate" for finding in self.findings)
