"""End-to-end: regenerate defmon.s and verify it matches the committed copy."""

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED_DEFMON_S = REPO_ROOT / "defmon.s"
BUILD_DIR = REPO_ROOT / "build"
CMP_FACTS = BUILD_DIR / "cmp_facts.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class TestEmitRoundtrip(unittest.TestCase):
    def test_committed_defmon_s_exists(self):
        self.assertTrue(
            COMMITTED_DEFMON_S.is_file(),
            f"{COMMITTED_DEFMON_S} must be committed as the reference",
        )

    def test_cmp_facts_builds(self):
        BUILD_DIR.mkdir(exist_ok=True)
        result = _run("tools.re.cmp_facts", "--out", str(CMP_FACTS))
        if result.returncode != 0:
            self.fail(
                "tools.re.cmp_facts failed:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        self.assertTrue(CMP_FACTS.is_file())
        self.assertGreater(CMP_FACTS.stat().st_size, 1000)

    def test_emit_matches_committed_defmon_s(self):
        BUILD_DIR.mkdir(exist_ok=True)
        if not CMP_FACTS.is_file():
            result = _run("tools.re.cmp_facts", "--out", str(CMP_FACTS))
            self.assertEqual(result.returncode, 0, f"cmp_facts failed: {result.stderr}")

        out_path = BUILD_DIR / "defmon.regen.s"
        result = _run("tools.re.emit_defmon_source", "--out", str(out_path))
        if result.returncode != 0:
            self.fail(
                "tools.re.emit_defmon_source failed:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        self.assertTrue(out_path.is_file())

        committed = _sha256(COMMITTED_DEFMON_S)
        regenerated = _sha256(out_path)
        self.assertEqual(
            committed,
            regenerated,
            "Regenerated defmon.s does not match the committed copy. "
            "Re-run `make` and commit the result if the change is intended.",
        )


if __name__ == "__main__":
    unittest.main()
