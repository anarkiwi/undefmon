"""Round-trip: defmon.s assembled by 64tass must match defmon-static.bin."""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFMON_S = REPO_ROOT / "defmon.s"
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
BUILD_DIR = REPO_ROOT / "build"
REASSEMBLED = BUILD_DIR / "defmon-reassembled.bin"


class TestRoundtrip(unittest.TestCase):
    def setUp(self):
        if shutil.which("64tass") is None:
            self.skipTest("64tass not installed")
        if not STATIC_BIN.is_file():
            self.skipTest(f"{STATIC_BIN} missing — run `python -m tools.fetch_static`")
        if not DEFMON_S.is_file():
            self.skipTest(f"{DEFMON_S} missing — run `make`")
        BUILD_DIR.mkdir(exist_ok=True)

    def test_assembles_to_static_image(self):
        result = subprocess.run(
            [
                "64tass",
                "-i",
                "-b",
                "--nostart",
                "-o",
                str(REASSEMBLED),
                str(DEFMON_S),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(
                "64tass failed:\n" f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        self.assertTrue(REASSEMBLED.is_file())

        check = subprocess.run(
            [
                sys.executable,
                "-m",
                "tools.roundtrip_check",
                "--static",
                str(STATIC_BIN),
                "--reassembled",
                str(REASSEMBLED),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if check.returncode != 0:
            self.fail(
                "Round-trip diff failed:\n"
                f"stdout:\n{check.stdout}\nstderr:\n{check.stderr}"
            )


if __name__ == "__main__":
    unittest.main()
