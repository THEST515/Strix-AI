from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from typing import Any

from src.backend.services.strix_runner import missing_strix_configuration


Check = dict[str, str]


def run_preflight(
    target: str,
    *,
    environment: Mapping[str, str] | None = None,
    command_exists: Callable[[str], str | None] = shutil.which,
    docker_info_runner: Callable[..., Any] = subprocess.run,
    target_is_allowed: Callable[[str], bool] | None = None,
) -> dict[str, object]:
    """Return only user-safe prerequisites required by the current scan runner."""
    environment_values = dict(os.environ if environment is None else environment)
    checks = [
        _build_target_check(target, target_is_allowed),
        _build_docker_check(command_exists, docker_info_runner),
        _build_strix_check(command_exists),
        _build_llm_check(environment_values),
    ]
    return {
        "ready": all(check["status"] == "passed" for check in checks),
        "checks": checks,
    }


def _build_target_check(target: str, target_is_allowed: Callable[[str], bool] | None) -> Check:
    is_allowed = target_is_allowed(target) if target_is_allowed is not None else bool(target.strip())
    if is_allowed:
        return _passed_check("target", "目标地址", "目标格式有效")
    return _failed_check("target", "目标地址", "目标地址格式无效")


def _build_docker_check(
    command_exists: Callable[[str], str | None], docker_info_runner: Callable[..., Any]
) -> Check:
    if not command_exists("docker"):
        return _failed_check("docker", "Docker", "未检测到 Docker CLI")

    try:
        completed = docker_info_runner(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _failed_check("docker", "Docker", "Docker daemon 未就绪")

    if getattr(completed, "returncode", 1) == 0:
        return _passed_check("docker", "Docker", "Docker daemon 已就绪")
    return _failed_check("docker", "Docker", "Docker daemon 未就绪")


def _build_strix_check(command_exists: Callable[[str], str | None]) -> Check:
    if command_exists("strix"):
        return _passed_check("strix", "Strix CLI", "已检测到 Strix CLI")
    return _failed_check("strix", "Strix CLI", "未检测到 Strix CLI")


def _build_llm_check(environment: Mapping[str, str]) -> Check:
    if not missing_strix_configuration(environment):
        return _passed_check("llm", "LLM 配置", "已检测到模型与 API 配置")
    return _failed_check("llm", "LLM 配置", "LLM 模型或 API 配置未就绪")


def _passed_check(key: str, label: str, detail: str) -> Check:
    return {"key": key, "label": label, "status": "passed", "detail": detail}


def _failed_check(key: str, label: str, detail: str) -> Check:
    return {"key": key, "label": label, "status": "failed", "detail": detail}
