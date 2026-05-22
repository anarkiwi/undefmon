"""Static call graph for the defMON image.

The graph distinguishes two kinds of inbound edges to any address:

  - ``code_in``  — source PC is a confirmed code-start (an address the
                   emitter classified as the start of an instruction).
                   These are real callers / readers / writers.

  - ``apparent_in_from_data``
                 — source PC is a byte inside a data span that *happens*
                   to decode as an opcode whose operand resolves to the
                   target. These are the "xref ghosts" that previously
                   leaked into prose as "the single reference at X is
                   screen-RAM data ... Dead path." The graph computes
                   them once so the prose layer doesn't have to.

A node with ``code_in == [] and apparent_in_from_data != []`` is
unreachable through code edges but xref-visible — i.e. the canonical
"Unreachable: only inbound reference is a data byte inside <name>."
case. Step 3 will use that predicate to derive the comment block at
emit time so the hand-written prose can go.

Reachability seeds default to every address with a ``[function]`` entry
in ``annotations.toml`` plus the hardware vectors at ``$FFFA`` / ``$FFFE``
and the soft-IRQ/NMI vector writers at ``$0314`` / ``$0318``. A code-start
is ``reachable`` iff a path of code edges from any seed reaches it.

This module deliberately does NOT touch SMC patch sites, computed JMPs,
or jump tables beyond what flows out of the standard expansion in
``emit_defmon_source.expand_code_starts``. Step 4 will fold those in via
structured ``smc_patches`` / ``jump_table`` annotation hints.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from tools.re.dasm6502 import OPS
from tools.re.emit_defmon_source import (
    EQUATE_LABELS,
    END_ADDR_EXCL,
    HW_LABELS,
    LOAD_ADDR,
    SEED_LANDMARKS,
    classify,
    expand_code_starts,
    extract_annotation_labels,
    load_annotations,
    load_code_starts,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINTS = REPO_ROOT / "trace" / "entrypoints.json"
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"

_ADDR_MODES_RESOLVING_TO_TARGET = {"abs", "abx", "aby", "ind", "rel"}


def _operand_target(mem: bytes, pc: int, mode: str, n: int) -> int | None:
    """Resolve the 16-bit target of an instruction's operand, if any.

    Returns None for addressing modes that don't encode a 16-bit target
    (imm, zp, zpx, zpy, izx, izy, imp, acc).
    """
    if mode in ("abs", "abx", "aby", "ind"):
        if n != 3:
            return None
        return mem[pc + 1] | (mem[pc + 2] << 8)
    if mode == "rel":
        if n != 2:
            return None
        off = mem[pc + 1]
        if off >= 0x80:
            off -= 256
        return (pc + 2 + off) & 0xFFFF
    return None


# Opcodes that transfer control (and thus drive reachability).
_CONTROL_OPS = {
    0x20,  # JSR
    0x4C,  # JMP abs
    0x6C,  # JMP ind  (target unknown statically)
    # Branches:
    0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0,
}
_FALLS_THROUGH = lambda op: op not in {0x60, 0x40, 0x4C, 0x6C, 0x00}


@dataclass
class CallGraph:
    """Static graph keyed by 16-bit address."""

    code_starts: set[int]
    consumed: set[int]
    # target -> [src_pc, ...]
    code_in: dict[int, list[int]] = field(default_factory=dict)
    apparent_in_from_data: dict[int, list[int]] = field(default_factory=dict)
    # target -> predecessor PC (fall-through is unique per target — there is
    # at most one instruction immediately before any given code-start).
    fall_through_in: dict[int, int] = field(default_factory=dict)
    # source -> [target, ...]
    code_out: dict[int, list[int]] = field(default_factory=dict)
    # reachability
    seeds: set[int] = field(default_factory=set)
    reachable: set[int] = field(default_factory=set)

    def in_data(self, pc: int) -> bool:
        return pc not in self.code_starts and pc not in self.consumed

    def to_json_obj(self, labels: dict[int, str] | None = None) -> dict:
        labels = labels or {}

        def fmt_addr(addr: int) -> str:
            name = labels.get(addr)
            return f"${addr:04X}" + (f" {name}" if name else "")

        def fmt_edges(d: dict[int, list[int]]) -> dict:
            return {
                f"${addr:04X}": {
                    "label": labels.get(addr),
                    "sources": [fmt_addr(pc) for pc in sorted(set(srcs))],
                }
                for addr, srcs in sorted(d.items())
                if srcs
            }

        fall_through = {
            f"${addr:04X}": {
                "label": labels.get(addr),
                "source": fmt_addr(src),
            }
            for addr, src in sorted(self.fall_through_in.items())
        }
        return {
            "load_address": LOAD_ADDR,
            "end_address_excl": END_ADDR_EXCL,
            "code_start_count": len(self.code_starts),
            "code_in": fmt_edges(self.code_in),
            "apparent_in_from_data": fmt_edges(self.apparent_in_from_data),
            "fall_through_in": fall_through,
            "reachable_count": len(self.reachable),
            "unreachable_code_starts": sorted(
                fmt_addr(pc) for pc in (self.code_starts - self.reachable)
            ),
        }


def build(
    mem: bytes,
    code_starts: set[int],
    consumed: set[int],
    start: int = LOAD_ADDR,
    end_excl: int = END_ADDR_EXCL,
    seeds: set[int] | None = None,
) -> CallGraph:
    """Build the static call graph.

    ``code_starts`` is the set of accepted instruction PCs (from
    ``classify()``). ``consumed`` is the set of operand bytes occupied
    by those instructions. Everything else in [start, end_excl) is
    considered a data byte.
    """
    graph = CallGraph(code_starts=set(code_starts), consumed=set(consumed))
    code_addrs = graph.code_starts | graph.consumed

    # Pass 1: real edges from accepted code-starts.
    for pc in graph.code_starts:
        if pc < start or pc >= end_excl:
            continue
        op = mem[pc]
        info = OPS.get(op)
        if info is None:
            continue
        _, mode, n = info
        if pc + n > end_excl:
            continue
        if mode not in _ADDR_MODES_RESOLVING_TO_TARGET:
            continue
        tgt = _operand_target(mem, pc, mode, n)
        if tgt is None or not (start <= tgt < end_excl):
            continue
        graph.code_in.setdefault(tgt, []).append(pc)
        graph.code_out.setdefault(pc, []).append(tgt)

    # Pass 1b: fall-through edges. For every accepted code-start whose
    # opcode falls through (i.e. not RTS/RTI/JMP/BRK) and whose pc+n is
    # also an accepted code-start, record the predecessor. The map is
    # 1:1 because there is at most one instruction directly preceding
    # any given code-start.
    for pc in graph.code_starts:
        if pc < start or pc >= end_excl:
            continue
        op = mem[pc]
        info = OPS.get(op)
        if info is None:
            continue
        _, _, n = info
        nxt = pc + n
        if nxt >= end_excl:
            continue
        if not _FALLS_THROUGH(op):
            continue
        if nxt in graph.code_starts:
            graph.fall_through_in[nxt] = pc

    # Pass 2: apparent edges from bytes that aren't code.
    for pc in range(start, end_excl):
        if pc in code_addrs:
            continue
        op = mem[pc]
        info = OPS.get(op)
        if info is None:
            continue
        _, mode, n = info
        if pc + n > end_excl:
            continue
        if mode not in _ADDR_MODES_RESOLVING_TO_TARGET:
            continue
        tgt = _operand_target(mem, pc, mode, n)
        if tgt is None or not (start <= tgt < end_excl):
            continue
        graph.apparent_in_from_data.setdefault(tgt, []).append(pc)

    # Pass 3: reachability from seeds along control-flow edges.
    if seeds is None:
        seeds = set()
    graph.seeds = {s for s in seeds if start <= s < end_excl}
    graph.reachable = _walk_reachable(mem, graph.code_starts, graph.seeds,
                                      start, end_excl)
    return graph


def _walk_reachable(mem: bytes, code_starts: set[int], seeds: set[int],
                    start: int, end_excl: int) -> set[int]:
    """Forward closure along JSR/JMP-abs/branch/fall-through edges."""
    reachable: set[int] = set()
    frontier = list(seeds & code_starts)
    while frontier:
        pc = frontier.pop()
        if pc in reachable:
            continue
        reachable.add(pc)
        op = mem[pc]
        info = OPS.get(op)
        if info is None:
            continue
        _, mode, n = info
        if pc + n > end_excl:
            continue
        # fall-through
        if _FALLS_THROUGH(op) and (pc + n) in code_starts:
            frontier.append(pc + n)
        # control transfer
        if op in _CONTROL_OPS:
            tgt = _operand_target(mem, pc, mode, n)
            if tgt is not None and start <= tgt < end_excl and tgt in code_starts:
                frontier.append(tgt)
    return reachable


def default_seeds(annotations: dict[int, dict]) -> set[int]:
    """Seed addresses for reachability analysis.

    Uses (a) every address with a ``[function]`` entry in
    ``annotations.toml`` (proxy for "named entry point") and
    (b) the standard hardware/IRQ vector reads at $FFFA/$FFFE.

    ``[function]`` is a reasonable proxy because the hand-curated
    function catalog represents the things humans have identified as
    entry points worth naming. Anything truly orphaned won't be in
    there and won't be a seed.
    """
    seeds: set[int] = set()
    for addr in annotations:
        seeds.add(addr)
    seeds |= {0xFFFA, 0xFFFE}
    return seeds


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", type=Path, default=STATIC_BIN)
    ap.add_argument("--entrypoints", type=Path, default=ENTRYPOINTS)
    ap.add_argument("--annotations", type=Path, default=ANNOTATIONS)
    ap.add_argument("--out", type=Path,
                    default=REPO_ROOT / "build" / "callgraph.json")
    args = ap.parse_args(argv)

    mem = args.bin.read_bytes()
    if len(mem) != 0x10000:
        raise SystemExit(f"expected 64K image, got {len(mem)} bytes")

    raw_seeds = load_code_starts(args.entrypoints)
    raw_seeds.update(SEED_LANDMARKS.keys())
    expanded = expand_code_starts(mem, raw_seeds, LOAD_ADDR, END_ADDR_EXCL)
    instr_at, consumed = classify(mem, expanded, LOAD_ADDR, END_ADDR_EXCL)
    code_starts = set(instr_at.keys())

    annotations = load_annotations(args.annotations)
    labels: dict[int, str] = dict(SEED_LANDMARKS)
    labels.update(EQUATE_LABELS)
    for addr, name in HW_LABELS.items():
        labels.setdefault(addr, name)
    for addr, name in extract_annotation_labels(annotations).items():
        labels.setdefault(addr, name)
    rs_seeds = default_seeds(annotations)

    graph = build(mem, code_starts, consumed, seeds=rs_seeds)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(graph.to_json_obj(labels), indent=2))

    n_code_in = sum(len(v) for v in graph.code_in.values())
    n_app_in = sum(len(v) for v in graph.apparent_in_from_data.values())
    n_dead_app = sum(
        1 for tgt in graph.code_starts
        if not graph.code_in.get(tgt) and graph.apparent_in_from_data.get(tgt)
    )
    n_unreachable = len(graph.code_starts - graph.reachable)
    n_fall_through = len(graph.fall_through_in)
    n_recoverable = sum(
        1 for tgt in graph.fall_through_in
        if not graph.code_in.get(tgt)
    )
    print(f"callgraph: wrote {args.out}")
    print(f"  code-starts         = {len(graph.code_starts)}")
    print(f"  real code edges     = {n_code_in}")
    print(f"  apparent edges      = {n_app_in}  (from data bytes)")
    print(f"  fall-through edges  = {n_fall_through}  "
          f"({n_recoverable} otherwise have no code_in)")
    print(f"  code-starts with ONLY apparent inbounds = {n_dead_app}")
    print(f"  unreachable from {len(graph.seeds)} seeds = {n_unreachable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
