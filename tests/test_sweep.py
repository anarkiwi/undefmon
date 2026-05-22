"""Smoke tests for tools.sweep — aggregator + arg parsing only."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tools import sweep

REPO_ROOT = Path(__file__).resolve().parent.parent


def _action_coverage(pcs, page_hits=None):
    return SimpleNamespace(
        executed_pcs=frozenset(pcs),
        page_hits=dict(page_hits or {}),
    )


class TestAggregateSweep(unittest.TestCase):
    def test_empty(self):
        obj = sweep.aggregate_sweep([], tune_count=0)
        self.assertEqual(obj["schema_version"], 1)
        self.assertEqual(obj["tune_count"], 0)
        self.assertEqual(obj["action_count"], 0)
        self.assertEqual(obj["distinct_pcs"], 0)
        self.assertEqual(obj["pages_touched"], 0)
        self.assertEqual(obj["pcs"], [])

    def test_pc_dedup_and_occurrence_count(self):
        acs = [
            _action_coverage([0x0800, 0x0801, 0x0802]),
            _action_coverage([0x0801, 0x1000]),
        ]
        obj = sweep.aggregate_sweep(acs, tune_count=1)
        self.assertEqual(obj["action_count"], 2)
        self.assertEqual(obj["distinct_pcs"], 4)
        self.assertEqual({0x08, 0x10}, set(int(p, 16) for p in obj["pages"]))
        by_pc = {int(e["pc"], 16): e for e in obj["pcs"]}
        self.assertEqual(by_pc[0x0800]["occurrences"], 1)
        self.assertEqual(by_pc[0x0801]["occurrences"], 2)
        self.assertEqual(by_pc[0x0802]["occurrences"], 1)
        self.assertEqual(by_pc[0x1000]["occurrences"], 1)

    def test_pcs_sorted_ascending(self):
        acs = [_action_coverage([0x5000, 0x0900, 0x2000])]
        obj = sweep.aggregate_sweep(acs, tune_count=1)
        pcs = [int(e["pc"], 16) for e in obj["pcs"]]
        self.assertEqual(pcs, sorted(pcs))

    def test_pc_and_page_fields_are_lowercase_hex(self):
        obj = sweep.aggregate_sweep([_action_coverage([0xABCD])], tune_count=1)
        self.assertEqual(obj["pcs"][0]["pc"], "0xabcd")
        self.assertEqual(obj["pcs"][0]["page"], "0xab")
        self.assertEqual(obj["pages"], ["0xab"])

    def test_pages_from_page_hits_too(self):
        acs = [_action_coverage([0x0800], page_hits={0x70: 5, 0x71: 1})]
        obj = sweep.aggregate_sweep(acs, tune_count=1)
        self.assertEqual(
            set(int(p, 16) for p in obj["pages"]),
            {0x08, 0x70, 0x71},
        )


class TestCLI(unittest.TestCase):
    def test_help_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "tools.sweep", "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--tune", result.stdout)
        self.assertIn("--skip-fetch", result.stdout)

    def test_missing_d64_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.sweep",
                    "--skip-fetch",
                    "--d64",
                    str(Path(td) / "nope.d64"),
                    "--out",
                    str(out),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(out.exists())


class TestAggregateSchemaMatchesEmitterExpectations(unittest.TestCase):
    def test_schema_keys_align_with_committed_entrypoints_json(self):
        committed = REPO_ROOT / "trace" / "entrypoints.json"
        if not committed.is_file():
            self.skipTest(f"{committed} missing")
        committed_obj = json.loads(committed.read_text())
        produced = sweep.aggregate_sweep(
            [_action_coverage([0x0800, 0x0801])], tune_count=1
        )
        committed_keys = set(committed_obj.keys())
        produced_keys = set(produced.keys())
        missing = committed_keys - produced_keys
        if missing:
            self.fail(
                f"aggregate_sweep is missing top-level keys present in the "
                f"committed entrypoints.json: {sorted(missing)}"
            )
        pc_entry = produced["pcs"][0]
        committed_pc = committed_obj["pcs"][0]
        self.assertEqual(set(pc_entry.keys()), set(committed_pc.keys()))


if __name__ == "__main__":
    unittest.main()
