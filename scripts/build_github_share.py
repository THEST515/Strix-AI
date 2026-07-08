from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT / "dist" / "github-share" / "strix-ai-security-demo-platform"

DIRECTORIES_TO_COPY = [
    "assets",
    "docs",
    "scripts",
    "src",
    "tests",
]

FILES_TO_COPY = [
    "README.md",
]

FILES_TO_EXCLUDE = {
    "findings.md",
    "task_plan.md",
    "progress.md",
    "next_session_context.md",
    "context_checkpoint.md",
    "project_context_snapshot.md",
    "retrospective.md",
    "session_handoff.md",
    "tmp-redesign-preview.png",
}

DIRECTORIES_TO_EXCLUDE = {
    ".acceptance",
    ".acceptance-ui",
    ".docx_render_probe",
    ".run",
    ".superpowers",
    "dist",
    "strix_runs",
    "__pycache__",
}


def _ignore(_directory: str, names: list[str]) -> set[str]:
    ignored = set()
    for name in names:
        if name in DIRECTORIES_TO_EXCLUDE or name in FILES_TO_EXCLUDE:
            ignored.add(name)
        if name.endswith(".pyc"):
            ignored.add(name)
    return ignored


def build_share_copy() -> Path:
    if OUTPUT_ROOT.exists():
        shutil.rmtree(OUTPUT_ROOT)

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    for file_name in FILES_TO_COPY:
        shutil.copy2(ROOT / file_name, OUTPUT_ROOT / file_name)

    for directory_name in DIRECTORIES_TO_COPY:
        shutil.copytree(
            ROOT / directory_name,
            OUTPUT_ROOT / directory_name,
            ignore=_ignore,
        )

    (OUTPUT_ROOT / ".gitignore").write_text(
        "\n".join(
            [
                "__pycache__/",
                "*.pyc",
                ".DS_Store",
                "dist/",
                "strix_runs/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    return OUTPUT_ROOT


if __name__ == "__main__":
    output = build_share_copy()
    print(output)
