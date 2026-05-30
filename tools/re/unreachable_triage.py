"""Triage the unreachable code-starts recorded in ``build/callgraph.json``.

``callgraph.py`` walks code edges from the seed set and marks every
code-start it cannot reach as ``unreachable``. That list is large (≈3.2k
of 11.5k starts) and lumps together several very different situations:

  - ``smc_io_band``    — host sits in the RAM-under-I/O / register-aliased
                         band (``$D000-$DFFF``) or is a catalogued
                         ``smc_dispatch`` target. Reached at runtime via a
                         self-modified JSR/JMP or by executing RAM under a
                         banked-out I/O range, neither of which the static
                         code-edge walk follows. *Expected* unreachable.
  - ``data_xref_only`` — no code-edge in, but a byte inside a data span
                         decodes to an operand that points here
                         (``apparent_in_from_data``). The canonical
                         "only inbound reference is a data byte" ghost —
                         almost always a mis-seeded code-start inside data.
  - ``reachable_referrer`` — a *reachable* instruction references this
                         address, yet the walk never flowed in. Means the
                         inbound edge is an operand/computed-jump/jump-table
                         the walker doesn't follow — a genuine candidate for
                         a new code-start seed or an SMC/jump-table hint.
  - ``transitively_unreachable`` — has code-edge sources, but every one of
                         them is itself unreachable. Root cause is upstream;
                         fixing a root reclaims the whole chain.
  - ``isolated``       — no inbound edge of any kind. Dead code, or a
                         code-start the seed set simply never names.

The tool prints per-bucket counts + samples, then a "roots" section: the
unreachable nodes with no unreachable in-edge, ranked by how many other
unreachable starts they dominate (forward-reach over code edges). Seeding
or explaining a root reclaims its whole subtree, so the roots are the
highest-leverage triage targets.

Read-only. Consumes the committed ``build/callgraph.json`` plus
``annotations.toml`` (for region/function context) and the committed
``artefacts/ghidra/smc_dispatch.json`` (for SMC targets). Exits 0 always —
this is a report, not a gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

from tools.re.emit_defmon_source import HW_LABELS, load_annotations

REPO_ROOT = Path(__file__).resolve().parents[2]
CALLGRAPH = REPO_ROOT / "build" / "callgraph.json"
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"
SMC_DISPATCH = REPO_ROOT / "artefacts" / "ghidra" / "smc_dispatch.json"

# RAM-under-I/O / register-aliased band. Code that lives here executes only
# while the matching I/O range is banked out, and the bytes double as
# hardware-register write targets — so the static code-edge walk can't reach
# it the normal way. $D000-$DFFF covers VIC/SID/CIA + the RAM-under-I/O
# encoder/decoder defMON runs there.
IO_BAND = range(0xD000, 0xE000)

BUCKETS = (
    "smc_io_band",
    "data_xref_only",
    "reachable_referrer",
    "transitively_unreachable",
    "isolated",
)


def _hex(pc: int) -> str:
    return f"${pc:04X}"


def _parse(addr: str) -> int:
    # Some callgraph fields carry a trailing label, e.g.
    # "$14EB groove_song_position" or "$0826 post_load_init_decoder".
    return int(addr.split()[0].lstrip("$"), 16)


def _smc_targets(path: Path) -> set[int]:
    """Catalogued SMC-dispatch host PCs (the JSR/JMP whose target is
    patched) — their fall-through successors are commonly unreachable."""
    if not path.is_file():
        return set()
    raw = json.loads(path.read_text())
    return {_parse(k) for k in raw}


def _enclosing_region(pc: int, region_starts: list[int], ann: dict[int, dict]) -> str:
    """Name of the [region]/[function] whose start is the greatest address
    <= pc, or '' if none precedes it."""
    import bisect  # noqa: PLC0415

    i = bisect.bisect_right(region_starts, pc) - 1
    if i < 0:
        return ""
    start = region_starts[i]
    return ann.get(start, {}).get("name", "") or _hex(start)


def classify(cg: dict, ann: dict[int, dict], smc: set[int]) -> dict:
    code_in = cg["code_in"]
    data_in = cg["apparent_in_from_data"]
    unreachable = {_parse(a) for a in cg["unreachable_code_starts"]}
    all_starts_reachable = set()  # reachable = every code-start not unreachable
    # `code_in`/`fall_through_in` keys are code-starts; the reachable set is
    # their union minus the unreachable list.
    for key in (*code_in, *cg["fall_through_in"]):
        all_starts_reachable.add(_parse(key))
    all_starts_reachable -= unreachable

    def sources(pc: int) -> list[int]:
        entry = code_in.get(_hex(pc))
        if not entry:
            return []
        return [_parse(s) for s in entry.get("sources", [])]

    bucket: dict[int, str] = {}
    for pc in unreachable:
        srcs = sources(pc)
        if pc in IO_BAND or pc in smc:
            bucket[pc] = "smc_io_band"
        elif not srcs and _hex(pc) in data_in:
            bucket[pc] = "data_xref_only"
        elif any(s in all_starts_reachable for s in srcs):
            bucket[pc] = "reachable_referrer"
        elif srcs:
            bucket[pc] = "transitively_unreachable"
        else:
            bucket[pc] = "isolated"

    # Forward code edges restricted to the unreachable subgraph, for roots.
    fwd: dict[int, list[int]] = {pc: [] for pc in unreachable}
    indeg_from_unreachable: dict[int, int] = {pc: 0 for pc in unreachable}
    for pc in unreachable:
        for s in sources(pc):
            if s in unreachable:
                fwd[s].append(pc)
                indeg_from_unreachable[pc] += 1

    def subtree_size(root: int) -> int:
        seen = {root}
        dq = deque([root])
        while dq:
            for nxt in fwd[dq.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    dq.append(nxt)
        return len(seen)

    roots = [pc for pc in unreachable if indeg_from_unreachable[pc] == 0]
    root_rank = sorted(((subtree_size(r), r) for r in roots), reverse=True)

    region_starts = sorted(ann)
    return {
        "unreachable": unreachable,
        "bucket": bucket,
        "sources": sources,
        "root_rank": root_rank,
        "region_starts": region_starts,
    }


def report(cg: dict, ann: dict[int, dict], smc: set[int], sample: int = 12) -> int:
    res = classify(cg, ann, smc)
    bucket = res["bucket"]
    total = len(res["unreachable"])
    counts = {b: 0 for b in BUCKETS}
    for b in bucket.values():
        counts[b] += 1

    print(
        f"unreachable code-starts: {total} "
        f"(of {cg['code_start_count']}, reachable {cg['reachable_count']})"
    )
    print()
    for b in BUCKETS:
        n = counts[b]
        pct = 100 * n / total if total else 0
        print(f"  {b:26s} {n:5d}  ({pct:4.1f}%)")
    print()

    by_bucket: dict[str, list[int]] = {b: [] for b in BUCKETS}
    for pc, b in bucket.items():
        by_bucket[b].append(pc)

    for b in ("reachable_referrer", "isolated", "data_xref_only"):
        pcs = sorted(by_bucket[b])
        if not pcs:
            continue
        print(f"── {b} (showing {min(sample, len(pcs))} of {len(pcs)}) ──")
        for pc in pcs[:sample]:
            reg = _enclosing_region(pc, res["region_starts"], ann)
            srcs = res["sources"](pc)
            src_txt = ", ".join(_hex(s) for s in srcs[:4]) or "(no code-edge in)"
            print(f"  {_hex(pc)}  in {reg or '?':28s} <- {src_txt}")
        print()

    # Which regions harbour the most unreachable starts? A region with many
    # is almost certainly data the decoder is mis-seeding as code — the
    # highest-value place to tighten a data declaration.
    from collections import Counter  # noqa: PLC0415

    region_hits: Counter[str] = Counter()
    for pc in bucket:
        reg = _enclosing_region(pc, res["region_starts"], ann)
        region_hits[reg or "?"] += 1
    print(f"── regions harbouring the most unreachable starts " f"(top {sample}) ──")
    for reg, n in region_hits.most_common(sample):
        print(f"  {n:5d}  {reg}")
    print()

    print("── roots (no unreachable in-edge), ranked by subtree reclaimed ──")
    print("   seeding/explaining a root reclaims its whole forward chain.")
    shown = [r for r in res["root_rank"] if r[0] > 1][:sample]
    for size, r in shown:
        reg = _enclosing_region(r, res["region_starts"], ann)
        print(f"  {_hex(r)}  reclaims {size:4d} starts   in {reg or '?'}")
    if not shown:
        print("  (no multi-node unreachable chains)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--callgraph",
        default=str(CALLGRAPH),
        help="path to build/callgraph.json (run `make callgraph`)",
    )
    ap.add_argument("--annotations", default=str(ANNOTATIONS))
    ap.add_argument("--smc-dispatch", default=str(SMC_DISPATCH))
    ap.add_argument(
        "--sample", type=int, default=12, help="rows to show per bucket / root list"
    )
    args = ap.parse_args(argv)

    cg_path = Path(args.callgraph)
    if not cg_path.is_file():
        print(f"{cg_path} not found — run `make callgraph` first.", file=sys.stderr)
        return 2
    cg = json.loads(cg_path.read_text())
    ann = load_annotations(Path(args.annotations))
    smc = _smc_targets(Path(args.smc_dispatch))
    return report(cg, ann, smc, sample=args.sample)


if __name__ == "__main__":
    sys.exit(main())
