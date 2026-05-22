"""Smoke tests for tools.probe — registry + CLI surface only."""

import subprocess
import sys
import unittest
from pathlib import Path

from tools import probe

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestRegistry(unittest.TestCase):
    def test_disasm_evidence_registered(self):
        self.assertIn("disasm_evidence", probe.PROBES)

    def test_probes_are_callable(self):
        for name, fn in probe.PROBES.items():
            self.assertTrue(callable(fn), f"probe {name!r} is not callable")

    def test_double_register_raises(self):
        with self.assertRaises(ValueError):

            @probe.probe("disasm_evidence")
            def _dup(ctx):
                pass


class TestCLI(unittest.TestCase):
    def test_help_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "tools.probe", "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("list", result.stdout)
        self.assertIn("run", result.stdout)

    def test_list_includes_disasm_evidence(self):
        result = subprocess.run(
            [sys.executable, "-m", "tools.probe", "list"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("disasm_evidence", result.stdout.split())

    def test_unknown_probe_exits_nonzero(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "tools.probe",
                "run",
                "no_such_probe",
                "--skip-fetch",
                "--d64",
                str(REPO_ROOT / "artefacts" / "defmon-withtunes.d64"),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
