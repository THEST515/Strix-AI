from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from collections.abc import Mapping
from pathlib import Path

from src.backend.domain.models import ScanTask


@dataclass(slots=True)
class StartedStrixScan:
    process: subprocess.Popen
    runs_root: Path
    previous_run_directories: set[str]


def build_strix_command(task: ScanTask, *, strix_binary: str = "strix") -> list[str]:
    command = [strix_binary, "-n", "--target", task.target, "--scan-mode", task.scan_mode]

    if task.instruction:
        command.extend(["--instruction", task.instruction])

    if task.instruction_file:
        command.extend(["--instruction-file", task.instruction_file])

    return command


def missing_strix_configuration(environment: Mapping[str, str]) -> list[str]:
    missing: list[str] = []

    if not environment.get("STRIX_LLM"):
        missing.append("STRIX_LLM")

    model = environment.get("STRIX_LLM", "")
    has_generic_key = bool(environment.get("LLM_API_KEY"))
    has_deepseek_key = bool(environment.get("DEEPSEEK_API_KEY"))

    if model.startswith("deepseek/"):
        if not (has_generic_key or has_deepseek_key):
            missing.append("DEEPSEEK_API_KEY or LLM_API_KEY")
    elif not has_generic_key:
        missing.append("LLM_API_KEY")

    return missing


def _latest_strix_log_message(
    runs_root: Path,
    previous_run_directories: set[str],
) -> str | None:
    current_run_directories = [
        path for path in runs_root.iterdir() if path.is_dir() and not path.name.startswith(".")
    ]
    candidate_directories = [
        path for path in current_run_directories if path.name not in previous_run_directories
    ] or current_run_directories

    if not candidate_directories:
        return None

    latest_run = sorted(candidate_directories, key=lambda path: path.name, reverse=True)[0]
    log_path = latest_run / "strix.log"
    if not log_path.exists():
        return None

    return log_path.read_text(encoding="utf-8", errors="ignore")


def _classify_failed_scan_detail(
    *,
    return_code: int,
    completed,
    runs_root: Path,
    previous_run_directories: set[str],
) -> str:
    detail = getattr(completed, "stderr", "") or getattr(completed, "stdout", "") or ""
    latest_log = _latest_strix_log_message(runs_root, previous_run_directories) or ""

    if "Tool agent-browser open not found in agent strix" in latest_log:
        return (
            "browser tool mismatch: Strix black-box browser tool is unavailable in the current runtime "
            "(Tool agent-browser open not found in agent strix)"
        )

    if "PermissionError" in latest_log and "run.json" in latest_log:
        return "filesystem permission error while Strix was writing run artifacts"

    return detail or f"exit code {return_code}"


def execute_strix_scan(
    task: ScanTask,
    *,
    environment: Mapping[str, str] | None = None,
    strix_runs_root: str | Path,
    strix_binary: str = "strix",
    run_command=subprocess.run,
) -> Path:
    env = dict(os.environ if environment is None else environment)
    missing = missing_strix_configuration(env)
    if missing:
        raise ValueError(f"missing Strix configuration: {', '.join(missing)}")

    runs_root = Path(strix_runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)
    previous_run_directories = {
        path.name for path in runs_root.iterdir() if path.is_dir() and not path.name.startswith(".")
    }
    command = build_strix_command(task, strix_binary=strix_binary)
    completed = run_command(
        command,
        check=False,
        cwd=str(runs_root.parent),
        env=env,
    )
    return _finalize_completed_scan(
        completed=completed,
        runs_root=runs_root,
        previous_run_directories=previous_run_directories,
    )


def start_strix_scan(
    task: ScanTask,
    *,
    environment: Mapping[str, str] | None = None,
    strix_runs_root: str | Path,
    strix_binary: str = "strix",
    popen_factory=subprocess.Popen,
    run_command=None,
):
    env = dict(os.environ if environment is None else environment)
    missing = missing_strix_configuration(env)
    if missing:
        raise ValueError(f"missing Strix configuration: {', '.join(missing)}")

    runs_root = Path(strix_runs_root)
    runs_root.mkdir(parents=True, exist_ok=True)
    previous_run_directories = {
        path.name for path in runs_root.iterdir() if path.is_dir() and not path.name.startswith(".")
    }

    command = build_strix_command(task, strix_binary=strix_binary)
    if popen_factory is None and run_command is not None:
        return run_command(
            command,
            check=False,
            cwd=str(runs_root.parent),
            env=env,
        )

    process = popen_factory(
        command,
        cwd=str(runs_root.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return StartedStrixScan(
        process=process,
        runs_root=runs_root,
        previous_run_directories=previous_run_directories,
    )


def wait_for_strix_scan(started: StartedStrixScan, *, timeout_seconds: int | None = None) -> Path:
    try:
        stdout, stderr = started.process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        cancel_strix_scan(started)
        raise TimeoutError(f"timed out after {timeout_seconds} seconds") from error

    completed = type(
        "Completed",
        (),
        {
            "returncode": started.process.returncode,
            "stdout": stdout,
            "stderr": stderr,
        },
    )()
    return _finalize_completed_scan(
        completed=completed,
        runs_root=started.runs_root,
        previous_run_directories=started.previous_run_directories,
    )


def cancel_strix_scan(started: StartedStrixScan) -> None:
    if started.process.poll() is not None:
        return

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(started.process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        started.process.terminate()

    try:
        started.process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        started.process.kill()
        started.process.wait(timeout=5)


def _finalize_completed_scan(*, completed, runs_root: Path, previous_run_directories: set[str]) -> Path:
    return_code = getattr(completed, "returncode", 0)
    if return_code != 0:
        detail = _classify_failed_scan_detail(
            return_code=return_code,
            completed=completed,
            runs_root=runs_root,
            previous_run_directories=previous_run_directories,
        )
        raise ValueError(f"Strix scan failed: {detail}")

    current_run_directories = [
        path for path in runs_root.iterdir() if path.is_dir() and not path.name.startswith(".")
    ]
    new_run_directories = [
        path for path in current_run_directories if path.name not in previous_run_directories
    ]

    if new_run_directories:
        return sorted(new_run_directories, key=lambda path: path.name, reverse=True)[0]

    if current_run_directories:
        return sorted(current_run_directories, key=lambda path: path.name, reverse=True)[0]

    raise FileNotFoundError("no strix run directories found after scan execution")
