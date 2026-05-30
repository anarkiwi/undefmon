"""Unit + smoke tests for tools.re.unreachable_triage bucketing."""

import json
import unittest
from pathlib import Path

from tools.re import unreachable_triage as U

REPO_ROOT = Path(__file__).resolve().parent.parent
CALLGRAPH = REPO_ROOT / "build" / "callgraph.json"


def _synthetic_cg():
    """Callgraph with one unreachable node per bucket: $D400 io-band,
    $3000 data-xref-only, $4000 reachable-referrer (source $2000 is
    reachable), $5000 transitively-unreachable via $6000, and $6000
    isolated (the root feeding $5000)."""
    return {
        "code_start_count": 7,
        "reachable_count": 2,
        "code_in": {
            "$2000": {"sources": ["$1000"]},
            "$4000": {"sources": ["$2000 some_label"]},
            "$5000": {"sources": ["$6000"]},
        },
        "fall_through_in": {"$1000": {"source": "$0FFE"}},
        "apparent_in_from_data": {"$3000": {"sources": ["$7FFF"]}},
        "unreachable_code_starts": ["$D400", "$3000", "$4000", "$5000", "$6000"],
    }


class TestBucketing(unittest.TestCase):
    def test_each_bucket_assigned(self):
        res = U.classify(_synthetic_cg(), ann={}, smc=set())
        b = res["bucket"]
        self.assertEqual(b[0xD400], "smc_io_band")
        self.assertEqual(b[0x3000], "data_xref_only")
        self.assertEqual(b[0x4000], "reachable_referrer")
        self.assertEqual(b[0x5000], "transitively_unreachable")
        self.assertEqual(b[0x6000], "isolated")

    def test_root_reclaims_subtree(self):
        """$6000 is a root feeding $5000, so its subtree is 2; $5000 has
        an unreachable in-edge so it is not itself a root."""
        res = U.classify(_synthetic_cg(), ann={}, smc=set())
        rank = dict((r, size) for size, r in res["root_rank"])
        self.assertEqual(rank[0x6000], 2)
        self.assertNotIn(0x5000, rank)

    def test_smc_dispatch_target_wins_over_reachable_referrer(self):
        """SMC membership classifies a node as smc_io_band even when a
        reachable instruction references it."""
        cg = _synthetic_cg()
        cg["unreachable_code_starts"].append("$8575")
        cg["code_in"]["$8575"] = {"sources": ["$1000"]}
        res = U.classify(cg, ann={}, smc={0x8575})
        self.assertEqual(res["bucket"][0x8575], "smc_io_band")

    def test_label_suffixed_addresses_parse(self):
        self.assertEqual(U._parse("$14EB groove_song_position"), 0x14EB)
        self.assertEqual(U._parse("$0826"), 0x0826)


class TestRealCallgraphSmoke(unittest.TestCase):
    def setUp(self):
        if not CALLGRAPH.is_file():
            self.skipTest(f"{CALLGRAPH} not present — run `make callgraph` first")

    def test_buckets_partition_unreachable_set(self):
        """Every unreachable start lands in exactly one known bucket."""
        cg = json.loads(CALLGRAPH.read_text())
        res = U.classify(cg, ann={}, smc=set())
        self.assertEqual(len(res["bucket"]), len(res["unreachable"]))
        self.assertTrue(all(v in U.BUCKETS for v in res["bucket"].values()))


if __name__ == "__main__":
    unittest.main()
