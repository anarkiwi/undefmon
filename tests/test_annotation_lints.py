"""Drive the 10-check annotation lint suite via `make lint`."""

import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"


class TestAnnotationLints(unittest.TestCase):
    def setUp(self):
        if shutil.which("make") is None:
            self.skipTest("make not installed")
        if not STATIC_BIN.is_file():
            self.skipTest(f"{STATIC_BIN} missing — run `make fetch-static` first")

    def test_make_lint_passes(self):
        result = subprocess.run(
            ["make", "lint"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(
                "make lint failed:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )


if __name__ == "__main__":
    unittest.main()
