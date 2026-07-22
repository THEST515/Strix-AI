from __future__ import annotations

import re
import subprocess
import unittest

from scripts.build_github_share import ROOT, build_share_copy


class BuildGithubShareTests(unittest.TestCase):
    def test_share_build_can_run_twice_when_assets_are_read_only(self) -> None:
        first_output = build_share_copy()
        second_output = build_share_copy()

        self.assertEqual(first_output, second_output)
        self.assertTrue((second_output / "assets" / "report_template.docx").is_file())

    def test_share_build_excludes_private_and_presentation_artifacts(self) -> None:
        output = build_share_copy()
        forbidden_directories = {
            "acceptance",
            "demo",
            "handover",
            "ppt-master-projects",
            "presentation",
            "presentation-visual-references",
            "reports",
            "strix_runs",
            "superpowers",
            "team-division",
            "tmp",
        }
        forbidden_markers = (
            "MMK" + "20041021",
            "82." + "156.",
        )
        secret_patterns = (
            r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}",
            r"Bearer\s+[A-Za-z0-9._~+/=-]{12,}",
        )

        for path in output.rglob("*"):
            self.assertTrue(forbidden_directories.isdisjoint(path.parts), path)
            if path.is_file() and path.suffix.lower() in {".html", ".js", ".json", ".md", ".mjs", ".py", ".txt"}:
                content = path.read_text(encoding="utf-8")
                for marker in forbidden_markers:
                    self.assertNotIn(marker, content, f"{marker!r} leaked through {path}")
                for pattern in secret_patterns:
                    self.assertIsNone(re.search(pattern, content), f"secret leaked through {path}")

    def test_repository_does_not_track_private_or_presentation_artifacts(self) -> None:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            check=True,
            capture_output=True,
            text=True,
        )
        forbidden_parts = {
            "demo",
            "handover",
            "ppt-master-projects",
            "presentation",
            "presentation-visual-references",
            "strix_runs",
            "superpowers",
            "tmp",
        }

        for relative_path in result.stdout.splitlines():
            path_parts = set(relative_path.replace("\\", "/").split("/"))
            self.assertTrue(forbidden_parts.isdisjoint(path_parts), relative_path)
            self.assertFalse(relative_path.endswith((".inspect.ndjson", ".pptx")), relative_path)


if __name__ == "__main__":
    unittest.main()
