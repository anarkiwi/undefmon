"""Hard-error cross-check: hand-written ``callers`` strings vs. graph.

For every annotation with a ``callers = "..."`` string that begins with
a numeric count (``"8 sites: ..."`` / ``"3 callers, ..."`` /
``"5 JSR callers"`` etc.), compare that count to the graph's
``code_in[addr]`` length.

Mismatches exit 1, listing the offenders. Entries that genuinely can't
be derived statically (SMC-patched JMP sources, jump-table indirects,
computed JMPs) opt out by setting ``derived_override = "<reason>"`` —
the gate then skips that entry but lists the override addresses as an
informational footer so the catalog stays auditable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tools.re.emit_defmon_source import (
    EQUATE_LABELS,
    HW_LABELS,
    SEED_LANDMARKS,
    extract_annotation_labels,
    load_annotations,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"
CALLGRAPH = REPO_ROOT / "build" / "callgraph.json"

# Patterns that introduce a leading caller count. Each captures one
# integer at group(1).
_COUNT_PATTERNS = [
    re.compile(r"^\s*(\d+)\s+sites?\b", re.IGNORECASE),
    re.compile(r"^\s*(\d+)\s+callers?\b", re.IGNORECASE),
    re.compile(r"^\s*(\d+)\s+JSR\s+callers?\b", re.IGNORECASE),
    re.compile(r"^\s*(\d+)\s+JMP\s+callers?\b", re.IGNORECASE),
    re.compile(r"^\s*(\d+)\s+JSR/JMP\s+callers?\b", re.IGNORECASE),
    re.compile(r"^\s*Reached\s+from\s+(\d+)\s+\w+", re.IGNORECASE),
]


def parse_count(callers: str) -> int | None:
    """Extract the leading caller count from a hand-written string."""
    for pat in _COUNT_PATTERNS:
        m = pat.search(callers)
        if m:
            return int(m.group(1))
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--annotations", type=Path, default=ANNOTATIONS)
    ap.add_argument("--callgraph", type=Path, default=CALLGRAPH)
    ap.add_argument("--max-show", type=int, default=40)
    args = ap.parse_args(argv)

    if not args.callgraph.is_file():
        print(f"callgraph_check: {args.callgraph} not found; "
              f"run `make callgraph` first.", file=sys.stderr)
        return 0  # soft-skip — don't block verify if artefact missing

    graph = json.loads(args.callgraph.read_text())
    code_in_index: dict[int, int] = {}
    for addr_text, info in graph.get("code_in", {}).items():
        addr = int(addr_text.lstrip("$"), 16)
        code_in_index[addr] = len(info.get("sources", []))
    fall_through_index: dict[int, str] = {}
    for addr_text, info in graph.get("fall_through_in", {}).items():
        addr = int(addr_text.lstrip("$"), 16)
        fall_through_index[addr] = info.get("source", "")

    annotations = load_annotations(args.annotations)
    labels: dict[int, str] = dict(SEED_LANDMARKS)
    labels.update(EQUATE_LABELS)
    for addr, name in HW_LABELS.items():
        labels.setdefault(addr, name)
    for addr, name in extract_annotation_labels(annotations).items():
        labels.setdefault(addr, name)

    mismatches: list[tuple[int, str, int, int, str]] = []
    overrides: list[tuple[int, str, str]] = []
    checked = 0
    for addr, body in sorted(annotations.items()):
        callers = body.get("callers", "")
        if not isinstance(callers, str) or not callers:
            continue
        claimed = parse_count(callers)
        if claimed is None:
            continue
        checked += 1
        actual = code_in_index.get(addr, 0)
        override = body.get("derived_override")
        if isinstance(override, str) and override.strip():
            name = labels.get(addr, "")
            overrides.append((addr, name, override))
            continue
        # Allow exact match only — `callers` strings that lead with a
        # number are explicit and shouldn't be ±1 off.
        if claimed != actual:
            name = labels.get(addr, "")
            note = ""
            ft = fall_through_index.get(addr)
            if ft and actual == 0:
                note = f"(fall-through from {ft} — prose probably stale)"
            elif ft:
                note = f"(also fall-through from {ft})"
            mismatches.append((addr, name, claimed, actual, note))

    n_ann = len(annotations)
    n_with_callers = sum(1 for b in annotations.values()
                         if isinstance(b.get("callers"), str)
                         and b.get("callers"))
    print(f"callgraph_check: {checked}/{n_with_callers} `callers` strings "
          f"have a parseable leading count "
          f"(of {n_ann} annotations); {len(overrides)} carry "
          f"`derived_override`.")

    if not mismatches:
        print("callgraph_check: OK — all checked counts agree with graph "
              "(or carry `derived_override`).")
        if overrides:
            print(f"\n  derived_override entries ({len(overrides)}):")
            for addr, name, reason in overrides:
                tag = name or "—"
                snippet = reason if len(reason) <= 110 else reason[:107] + "..."
                print(f"     ${addr:04X}  {tag:<32}  {snippet}")
        return 0

    print(f"\ncallgraph_check: FAIL — {len(mismatches)} hand-written "
          f"`callers` counts disagree with build/callgraph.json:")
    for addr, name, claimed, actual, note in mismatches[:args.max_show]:
        tag = name or "—"
        delta = actual - claimed
        sign = "+" if delta > 0 else ""
        line = (f"     ${addr:04X}  {tag:<32}  hand={claimed:>3}  "
                f"graph={actual:>3}  ({sign}{delta})")
        if note:
            line += f"  {note}"
        print(line)
    if len(mismatches) > args.max_show:
        print(f"     ... +{len(mismatches) - args.max_show} more")
    print()
    print("Each mismatch needs one of:")
    print("  (a) delete the hand-written `callers` so the graph-derived "
          "value emits (works when the graph is right and the prose stale).")
    print("  (b) set `derived_override = \"<reason>\"` on the entry "
          "(works when the graph genuinely can't model the inbound — "
          "SMC-patched JMP source, jump-table indirect, computed JMP).")
    print("  (c) fix the graph (4b.2 jump_table / 4b.3 smc_patches hints).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
