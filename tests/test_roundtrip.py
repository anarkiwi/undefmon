"""Round-trip: defmon.asm assembled by Kick Assembler must match
defmon-static.bin."""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFMON_ASM = REPO_ROOT / "defmon.asm"
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
BUILD_DIR = REPO_ROOT / "build"
REASSEMBLED = BUILD_DIR / "defmon-reassembled.prg"

KICKASS_JAR = Path(os.environ.get("KICKASS_JAR", "/usr/local/kickass/KickAss.jar"))
JAVA = os.environ.get("JAVA", "java")


class TestRoundtrip(unittest.TestCase):
    def setUp(self):
        if shutil.which(JAVA) is None:
            self.skipTest(f"java ({JAVA}) not installed")
        if not KICKASS_JAR.is_file():
            self.skipTest(
                f"{KICKASS_JAR} missing — set KICKASS_JAR to your KickAss.jar"
            )
        if not STATIC_BIN.is_file():
            self.skipTest(f"{STATIC_BIN} missing — run `python -m tools.fetch_static`")
        if not DEFMON_ASM.is_file():
            self.skipTest(f"{DEFMON_ASM} missing — run `make`")
        BUILD_DIR.mkdir(exist_ok=True)

    def test_assembles_to_static_image(self):
        result = subprocess.run(
            [
                JAVA,
                "-jar",
                str(KICKASS_JAR),
                str(DEFMON_ASM),
                "-o",
                str(REASSEMBLED),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(
                "Kick Assembler failed:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
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
