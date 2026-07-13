import json
import sys
import unittest
from pathlib import Path
from subprocess import CompletedProcess


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.backend.services.preflight import run_preflight


class PreflightTests(unittest.TestCase):
    def test_reports_ready_when_target_and_dependencies_pass(self) -> None:
        result = run_preflight(
            "http://localhost:8888",
            environment={"STRIX_LLM": "deepseek/model", "DEEPSEEK_API_KEY": "demo-secret"},
            command_exists=lambda command: command in {"docker", "strix"},
            docker_info_runner=lambda *args, **kwargs: CompletedProcess(args, 0),
            target_is_allowed=lambda target: target.startswith("http"),
        )

        self.assertTrue(result["ready"])
        self.assertEqual([check["status"] for check in result["checks"]], ["passed"] * 4)

    def test_reports_failed_docker_without_exposing_environment_values(self) -> None:
        result = run_preflight(
            "http://localhost:8888",
            environment={"STRIX_LLM": "deepseek/model", "DEEPSEEK_API_KEY": "actual-secret"},
            command_exists=lambda command: command == "strix",
            docker_info_runner=lambda *args, **kwargs: CompletedProcess(args, 1),
            target_is_allowed=lambda target: True,
        )

        self.assertFalse(result["ready"])
        self.assertNotIn("actual-secret", json.dumps(result, ensure_ascii=False))
        self.assertEqual(result["checks"][1]["key"], "docker")
        self.assertEqual(result["checks"][1]["status"], "failed")

    def test_reports_missing_llm_configuration(self) -> None:
        result = run_preflight(
            "http://localhost:8888",
            environment={"STRIX_LLM": "deepseek/model"},
            command_exists=lambda command: command in {"docker", "strix"},
            docker_info_runner=lambda *args, **kwargs: CompletedProcess(args, 0),
            target_is_allowed=lambda target: True,
        )

        self.assertFalse(result["ready"])
        self.assertEqual(result["checks"][-1]["key"], "llm")
        self.assertEqual(result["checks"][-1]["status"], "failed")
        self.assertIn("LLM", result["checks"][-1]["detail"])


if __name__ == "__main__":
    unittest.main()
