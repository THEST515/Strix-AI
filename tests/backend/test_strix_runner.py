import unittest
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.backend.domain.models import ScanTask
from src.backend.services.strix_runner import (
    build_strix_command,
    execute_strix_scan,
    missing_strix_configuration,
)


class StrixRunnerTests(unittest.TestCase):
    def test_builds_headless_command_for_local_target(self) -> None:
        task = ScanTask(
            task_id="task-001",
            name="demo task",
            target="./demo-app",
            scan_mode="quick",
        )

        command = build_strix_command(task)

        self.assertEqual(
            command,
            ["strix", "-n", "--target", "./demo-app", "--scan-mode", "quick"],
        )

    def test_includes_instruction_file_when_provided(self) -> None:
        task = ScanTask(
            task_id="task-002",
            name="api task",
            target="https://lab.example",
            instruction_file="./instruction.md",
        )

        command = build_strix_command(task)

        self.assertIn("--instruction-file", command)
        self.assertIn("./instruction.md", command)

    def test_reports_missing_generic_llm_api_key_when_no_deepseek_key_exists(self) -> None:
        missing = missing_strix_configuration({"STRIX_LLM": "openai/gpt-5.4"})

        self.assertEqual(missing, ["LLM_API_KEY"])

    def test_accepts_deepseek_api_key_for_deepseek_provider(self) -> None:
        missing = missing_strix_configuration(
            {
                "STRIX_LLM": "deepseek/deepseek-v4-flash",
                "DEEPSEEK_API_KEY": "demo-key",
            }
        )

        self.assertEqual(missing, [])

    def test_execute_strix_scan_rejects_missing_configuration(self) -> None:
        task = ScanTask(
            task_id="task-003",
            name="real scan",
            target="https://authorized-lab.example",
        )

        with TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "missing Strix configuration"):
                execute_strix_scan(
                    task,
                    environment={},
                    strix_runs_root=Path(temp_dir),
                )

    def test_execute_strix_scan_runs_command_and_returns_latest_run_directory(self) -> None:
        task = ScanTask(
            task_id="task-004",
            name="real scan",
            target="https://authorized-lab.example",
            scan_mode="deep",
        )
        observed: dict[str, object] = {}

        def fake_run(command, **kwargs):
            observed["command"] = command
            observed["cwd"] = kwargs.get("cwd")
            observed["env"] = kwargs.get("env")
            runs_root = Path(kwargs["cwd"]) / "strix_runs"
            run_dir = runs_root / "99_test_run"
            run_dir.mkdir(parents=True, exist_ok=True)
            return type("Completed", (), {"returncode": 0})()

        with TemporaryDirectory() as temp_dir:
            run_dir = execute_strix_scan(
                task,
                environment={
                    "STRIX_LLM": "deepseek/deepseek-v4-flash",
                    "DEEPSEEK_API_KEY": "demo-key",
                },
                strix_runs_root=Path(temp_dir) / "strix_runs",
                run_command=fake_run,
            )

        self.assertEqual(
            observed["command"],
            ["strix", "-n", "--target", "https://authorized-lab.example", "--scan-mode", "deep"],
        )
        self.assertEqual(run_dir.name, "99_test_run")

    def test_execute_strix_scan_raises_when_command_fails_even_if_old_run_exists(self) -> None:
        task = ScanTask(
            task_id="task-005",
            name="real scan",
            target="./src/frontend",
        )

        def fake_run(command, **kwargs):
            runs_root = Path(kwargs["cwd"]) / "strix_runs"
            (runs_root / "01_previous").mkdir(parents=True, exist_ok=True)
            return type("Completed", (), {"returncode": 1, "stderr": "docker not available"})()

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir) / "strix_runs"
            (runs_root / "00_existing").mkdir(parents=True, exist_ok=True)

            with self.assertRaisesRegex(ValueError, "Strix scan failed"):
                execute_strix_scan(
                    task,
                    environment={
                        "STRIX_LLM": "deepseek/deepseek-v4-flash",
                        "DEEPSEEK_API_KEY": "demo-key",
                    },
                    strix_runs_root=runs_root,
                    run_command=fake_run,
                )

    def test_execute_strix_scan_surfaces_browser_tool_mismatch_from_failed_run_log(self) -> None:
        task = ScanTask(
            task_id="task-006",
            name="blackbox scan",
            target="http://localhost:8888",
        )

        def fake_run(command, **kwargs):
            runs_root = Path(kwargs["cwd"]) / "strix_runs"
            run_dir = runs_root / "99_failed_run"
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "strix.log").write_text(
                "agents.exceptions.ModelBehaviorError: Tool agent-browser open not found in agent strix",
                encoding="utf-8",
            )
            return type("Completed", (), {"returncode": 1, "stderr": ""})()

        with TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir) / "strix_runs"

            with self.assertRaisesRegex(ValueError, "browser tool mismatch"):
                execute_strix_scan(
                    task,
                    environment={
                        "STRIX_LLM": "deepseek/deepseek-v4-flash",
                        "DEEPSEEK_API_KEY": "demo-key",
                    },
                    strix_runs_root=runs_root,
                    run_command=fake_run,
                )


if __name__ == "__main__":
    unittest.main()
