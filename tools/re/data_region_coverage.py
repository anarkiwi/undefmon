"""Data-region completeness check (Phase 3a-pass-1 acceptance, data side).

Runs the same classify + expand pipeline as `emit_defmon_source.py`,
then verifies that every data byte in $0800-$E786 falls inside the
implicit extent of some [function] or [region] entry in
`tools/re/annotations.toml`.

The complementary code-side gate ("every JSR/JMP-abs target in
defmon.s resolves to a [function] or [region]") landed in pass-8
(commit 8bcd672). Pass-9 adds the data-side gate so the "every byte
documented" goal is enforced by CI, not just AGENTS narrative.

Coverage model
==============

A data SUB-span is defined as a contiguous run of data bytes that:
  - starts at the first data byte after a code byte (or after the
    image's load address), OR at an annotation boundary inside a
    larger contiguous data run, AND
  - continues until either the next code byte or the next
    annotation boundary inside the data run, whichever is sooner.

Each data sub-span must have a [region] (or [function]) entry at
its first byte. If it doesn't, the bytes are "uncovered" — there's
no annotation that names what those bytes are.

This is stricter than "every byte has SOME preceding annotation"
because it forces an explicit annotation at every transition
(code -> data, data-A -> data-B), not just somewhere upstream.

Exit codes
==========
  0 - every data sub-span starts at an annotated address.
  1 - at least one sub-span is uncovered. Stdout lists the offenders.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.re.emit_defmon_source import (
    LOAD_ADDR,
    END_ADDR_EXCL,
    SEED_LANDMARKS,
    classify,
    expand_code_starts,
    load_annotations,
    load_code_starts,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
ENTRYPOINTS = REPO_ROOT / "trace" / "entrypoints.json"
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"


def compute_data_sub_spans(
    code_bytes: set[int],
    annotated_addrs: set[int],
    start: int,
    end_excl: int,
) -> list[tuple[int, int]]:
    """Return [(span_start, span_end_inclusive), ...] for contiguous
    runs of non-code bytes in [start, end_excl), splitting at every
    annotated address that falls inside a run.

    Each returned sub-span starts at either:
      - the first data byte after a code byte (or after `start`), OR
      - an annotated address inside an ongoing data run.
    """
    spans: list[tuple[int, int]] = []
    cur_start: int | None = None
    for pc in range(start, end_excl):
        if pc in code_bytes:
            if cur_start is not None:
                spans.append((cur_start, pc - 1))
                cur_start = None
            continue
        # pc is a data byte
        if cur_start is None:
            cur_start = pc
        else:
            # split at annotation boundaries inside an ongoing run
            if pc in annotated_addrs:
                spans.append((cur_start, pc - 1))
                cur_start = pc
    if cur_start is not None:
        spans.append((cur_start, end_excl - 1))
    return spans


def profile(
    bin_path: Path,
    entrypoints_path: Path,
    annotations_path: Path,
    start: int = LOAD_ADDR,
    end_excl: int = END_ADDR_EXCL,
) -> int:
    """Break the image into instruction bytes, zero-fill data (init RAM /
    buffers — not RE gaps), documented non-zero data, and the genuinely
    undocumented non-zero residue. The headline "uncategorised" share is
    dominated by zero-filled buffers (pattern RAM, sidTAB, tail padding)
    that are named at their boundaries; this separates those from bytes
    that actually lack an explanation."""
    mem = bin_path.read_bytes()
    seeds = load_code_starts(entrypoints_path)
    seeds.update(SEED_LANDMARKS.keys())
    expanded = expand_code_starts(mem, seeds, start, end_excl)
    instr_at, consumed = classify(mem, expanded, start, end_excl)
    code_bytes = set(instr_at.keys()) | consumed
    ann = load_annotations(annotations_path)
    annotated = {a for a in ann if start <= a < end_excl}
    spans = compute_data_sub_spans(code_bytes, annotated, start, end_excl)

    total = end_excl - start
    data_b = sum(e - s + 1 for s, e in spans)
    zero = sum(mem[s : e + 1].count(0) for s, e in spans)
    nonzero = data_b - zero
    documented = sum(
        (e - s + 1) - mem[s : e + 1].count(0)
        for s, e in spans
        if ann.get(s, {}).get("notes")
    )
    residue = [
        (s, e, (e - s + 1) - mem[s : e + 1].count(0))
        for s, e in spans
        if not ann.get(s, {}).get("notes") and (e - s + 1) - mem[s : e + 1].count(0) > 0
    ]
    residue.sort(key=lambda x: -x[2])
    residue_b = sum(x[2] for x in residue)

    def pct(n: int) -> str:
        return f"{100 * n / total:4.1f}%"

    print(f"image:                 {total:6d} B")
    print(f"  instruction bytes:   {len(code_bytes):6d} B  {pct(len(code_bytes))}")
    print(f"  data bytes:          {data_b:6d} B  {pct(data_b)}")
    print(
        f"    zero-fill:         {zero:6d} B  {pct(zero)}  "
        f"buffers / init RAM (named at boundaries; not RE gaps)"
    )
    print(f"    non-zero data:     {nonzero:6d} B  {pct(nonzero)}")
    print(f"      with notes:      {documented:6d} B  {pct(documented)}")
    print(
        f"      role-only:       {residue_b:6d} B  {pct(residue_b)}  "
        f"non-zero, no notes — the real worklist"
    )
    print()
    print(f"undocumented non-zero residue: {len(residue)} spans, {residue_b} B:")
    for s, e, nz in residue[:20]:
        nm = ann.get(s, {}).get("name", "")
        print(f"  ${s:04X}-${e:04X}  nz={nz:4d}/{e - s + 1:<5d}  {nm}")
    if len(residue) > 20:
        print(f"  ... +{len(residue) - 20} more")
    return 0


def check(
    bin_path: Path,
    entrypoints_path: Path,
    annotations_path: Path,
    start: int = LOAD_ADDR,
    end_excl: int = END_ADDR_EXCL,
) -> int:
    mem = bin_path.read_bytes()

    seeds = load_code_starts(entrypoints_path)
    seeds.update(SEED_LANDMARKS.keys())
    expanded = expand_code_starts(mem, seeds, start, end_excl)
    instr_at, consumed = classify(mem, expanded, start, end_excl)

    code_bytes = set(instr_at.keys()) | consumed

    annotations = load_annotations(annotations_path)
    annotated_addrs = {a for a in annotations if start <= a < end_excl}

    data_spans = compute_data_sub_spans(code_bytes, annotated_addrs, start, end_excl)

    uncovered: list[tuple[int, int]] = []
    for span_start, span_end in data_spans:
        if span_start not in annotated_addrs:
            uncovered.append((span_start, span_end))

    total_data_bytes = sum(e - s + 1 for s, e in data_spans)
    uncov_bytes = sum(e - s + 1 for s, e in uncovered)

    print(f"data sub-spans:    {len(data_spans)}")
    print(f"data bytes:        {total_data_bytes}")
    print(f"covered sub-spans: {len(data_spans) - len(uncovered)}")
    print(f"uncovered sub-spans: {len(uncovered)}")
    print(f"uncovered bytes:   {uncov_bytes}")

    if uncovered:
        print()
        print("UNCOVERED data sub-spans (no [region]/[function] at first byte):")
        for s, e in uncovered[:80]:
            n = e - s + 1
            preview = mem[s : min(s + 16, e + 1)].hex(" ")
            print(f"  ${s:04X}-${e:04X}  ({n:5d} B)  {preview}")
        if len(uncovered) > 80:
            print(f"  ... +{len(uncovered) - 80} more")
        return 1

    print()
    print(
        f"PASS: every data sub-span in ${start:04X}-${end_excl - 1:04X} "
        f"starts at a [region]/[function] address."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=str(STATIC_BIN))
    ap.add_argument("--entrypoints", default=str(ENTRYPOINTS))
    ap.add_argument("--annotations", default=str(ANNOTATIONS))
    ap.add_argument("--start", type=lambda x: int(x, 0), default=LOAD_ADDR)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=END_ADDR_EXCL)
    ap.add_argument(
        "--profile",
        action="store_true",
        help="print the instruction / zero-fill / documented / "
        "undocumented-residue breakdown instead of the gate",
    )
    args = ap.parse_args(argv)
    fn = profile if args.profile else check
    return fn(
        Path(args.bin),
        Path(args.entrypoints),
        Path(args.annotations),
        args.start,
        args.end,
    )


if __name__ == "__main__":
    sys.exit(main())
