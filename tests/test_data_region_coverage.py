"""Smoke tests for the data_region_coverage gate and --profile report."""

import unittest
from pathlib import Path

from tools.re import data_region_coverage as D

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
ENTRYPOINTS = REPO_ROOT / "trace" / "entrypoints.json"
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"


class TestDataRegionCoverage(unittest.TestCase):
    def setUp(self):
        if not STATIC_BIN.is_file():
            self.skipTest(f"{STATIC_BIN} not present — run `make fetch-static`")

    def test_gate_passes(self):
        """Every data sub-span starts at an annotated address (exit 0)."""
        self.assertEqual(D.check(STATIC_BIN, ENTRYPOINTS, ANNOTATIONS), 0)

    def test_profile_runs(self):
        """The --profile report runs and returns 0."""
        self.assertEqual(D.profile(STATIC_BIN, ENTRYPOINTS, ANNOTATIONS), 0)


if __name__ == "__main__":
    unittest.main()
