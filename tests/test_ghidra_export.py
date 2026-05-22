"""Verify the Ghidra export reproduces committed artefacts/ghidra/*.json."""

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED_DIR = REPO_ROOT / "artefacts" / "ghidra"
FRESH_DIR = REPO_ROOT / "build" / "ghidra-fresh"
JSON_FILES = (
    "symbols.json",
    "segments.json",
    "smc_dispatch.json",
    "smc_branch.json",
    "smc_opcode.json",
)


def _normalise(path: Path) -> str:
    return json.dumps(json.loads(path.read_text()), sort_keys=True)


class TestGhidraExport(unittest.TestCase):
    def setUp(self):
        if not any((FRESH_DIR / name).is_file() for name in JSON_FILES):
            self.skipTest(f"{FRESH_DIR} not populated — run `make ghidra-export` first")

    def test_all_five_jsons_present(self):
        missing = [name for name in JSON_FILES if not (FRESH_DIR / name).is_file()]
        if missing:
            self.fail(
                "Dockerfile.ghidra did not produce expected outputs: "
                + ", ".join(missing)
            )

    def test_jsons_match_committed(self):
        diffs = []
        for name in JSON_FILES:
            committed = COMMITTED_DIR / name
            fresh = FRESH_DIR / name
            if not fresh.is_file():
                continue
            if not committed.is_file():
                diffs.append(f"{name}: committed copy missing")
                continue
            if _normalise(committed) != _normalise(fresh):
                diffs.append(f"{name}: diff-as-JSON mismatch")
        if diffs:
            self.fail(
                "Ghidra re-export diverges from committed artefacts:\n  "
                + "\n  ".join(diffs)
            )


if __name__ == "__main__":
    unittest.main()
