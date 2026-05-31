"""Per-function register-effect analysis (clobbers + inputs).

For every ``[function]`` entry, computes two interface fields over A/X/Y:
  - ``registers_clobbered`` — registers the function destroys (written on
    some path before it returns), transitive over its callees.
  - ``inputs`` — registers it reads before defining (live-in): what the
    caller must set up, also transitive over its callees.

Both compose across JSR/tail-call edges via a fixed-point. A register is
clobbered if any path writes it; an input if any path reads it before a
definite write. Computed/self-modified/out-of-image calls are treated
conservatively (clobber A/X/Y; read A/X/Y) so neither field UNDER-reports.

Method
======
Walk each function's intra-procedural CFG over the classified
instruction stream:
  - union the registers each instruction writes (the WRITES table);
  - follow fall-through + conditional-branch + intra-function JMP-abs
    edges;
  - stop at RTS / RTI / BRK / indirect JMP;
  - a JSR records its target as a callee and continues at the
    fall-through; a JMP-abs (or fall-through) that lands on ANOTHER
    function's entry is a tail-continuation — recorded as a callee and
    not walked into.
Then take the fixed-point: ``clobbers[F] = direct[F] ∪ ⋃ clobbers[callee]``.

This is a sound over-approximation for the common cases: if any path
writes a register it is reported clobbered (callers must assume so).
Limits: an indirect/self-modified JMP whose target isn't statically
known ends the walk (its callee effects aren't followed) and a callee
that isn't itself a named ``[function]`` contributes only what the walk
reaches inline — both can only UNDER-report, never falsely add, so the
output is a safe lower bound for those edges. Output mirrors
``callgraph.json`` / ``cmp_facts.json``: a build artifact the emitter
renders, lint can cross-check, and `--report` prints for humans.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.re.emit_defmon_source import (
    END_ADDR_EXCL,
    LOAD_ADDR,
    SEED_LANDMARKS,
    classify,
    expand_code_starts,
    load_annotations,
    load_code_starts,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
ENTRYPOINTS = REPO_ROOT / "trace" / "entrypoints.json"
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"

# Which of A / X / Y each mnemonic writes. acc-mode shifts (ASL A etc.)
# write A and are handled separately. Stores (STA/STX/STY/SAX), compares
# (CMP/CPX/CPY/BIT) and memory inc/dec write memory or flags only, so they
# are absent here.
_WRITES: dict[str, frozenset[str]] = {
    "LDA": frozenset("A"),
    "TXA": frozenset("A"),
    "TYA": frozenset("A"),
    "PLA": frozenset("A"),
    "AND": frozenset("A"),
    "ORA": frozenset("A"),
    "EOR": frozenset("A"),
    "ADC": frozenset("A"),
    "SBC": frozenset("A"),
    "ALR": frozenset("A"),
    "ARR": frozenset("A"),
    "ANC": frozenset("A"),
    "LDX": frozenset("X"),
    "TAX": frozenset("X"),
    "TSX": frozenset("X"),
    "INX": frozenset("X"),
    "DEX": frozenset("X"),
    "AXS": frozenset("X"),
    "LDY": frozenset("Y"),
    "TAY": frozenset("Y"),
    "INY": frozenset("Y"),
    "DEY": frozenset("Y"),
    "LAX": frozenset("AX"),
}
_SHIFTS = {"ASL", "LSR", "ROL", "ROR"}

_RETURNS = {0x60, 0x40, 0x00}  # RTS, RTI, BRK
_JSR = 0x20
_JMP_ABS = 0x4C
_JMP_IND = 0x6C
_BRANCHES = {0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0}


def _writes(mnem: str, mode: str) -> frozenset[str]:
    if mode == "acc" and mnem in _SHIFTS:
        return frozenset("A")
    return _WRITES.get(mnem, frozenset())


# Which of A / X / Y each mnemonic READS (before any write it also does).
# Index registers used by the addressing mode are added separately.
_READS: dict[str, frozenset[str]] = {
    "STA": frozenset("A"),
    "STX": frozenset("X"),
    "STY": frozenset("Y"),
    "SAX": frozenset("AX"),
    "CMP": frozenset("A"),
    "CPX": frozenset("X"),
    "CPY": frozenset("Y"),
    "AND": frozenset("A"),
    "ORA": frozenset("A"),
    "EOR": frozenset("A"),
    "ADC": frozenset("A"),
    "SBC": frozenset("A"),
    "BIT": frozenset("A"),
    "ANC": frozenset("A"),
    "ALR": frozenset("A"),
    "ARR": frozenset("A"),
    "AXS": frozenset("AX"),
    "TAX": frozenset("A"),
    "TAY": frozenset("A"),
    "TXA": frozenset("X"),
    "TXS": frozenset("X"),
    "TYA": frozenset("Y"),
    "INX": frozenset("X"),
    "DEX": frozenset("X"),
    "INY": frozenset("Y"),
    "DEY": frozenset("Y"),
    "PHA": frozenset("A"),
}
# Addressing modes whose effective-address computation reads an index reg.
_MODE_INDEX = {"abx": "X", "zpx": "X", "izx": "X", "aby": "Y", "zpy": "Y", "izy": "Y"}


def _reads(mnem: str, mode: str) -> frozenset[str]:
    base = set(_READS.get(mnem, ()))
    if mode == "acc" and mnem in _SHIFTS:
        base.add("A")
    idx = _MODE_INDEX.get(mode)
    if idx is not None:
        base.add(idx)
    return frozenset(base)


_ALL = frozenset("AXY")


def _walk_subroutine(
    entry: int,
    mem: bytes,
    instr_at: dict,
    entries: frozenset[int],
    start: int,
    end_excl: int,
):
    """Build one subroutine's intra-procedural CFG.

    Returns (nodes, callees, uncertain) where nodes[pc] = {reads, writes,
    calls, succs}: ``calls`` is the set of subroutine entries invoked at
    pc (a JSR target, or a tail JMP/fall-through into another entry) whose
    inputs/clobbers compose at fixpoint; ``succs`` are the intra-procedural
    continuation PCs. ``uncertain`` is set for a computed/self-modified/
    out-of-image transfer whose effect can't be followed."""
    nodes: dict[int, dict] = {}
    callees: set[int] = set()
    uncertain = False
    seen: set[int] = set()
    frontier = [entry]

    def reachable(pc: int) -> bool:
        return start <= pc < end_excl and pc in instr_at

    while frontier:
        pc = frontier.pop()
        if pc in seen:
            continue
        seen.add(pc)
        info = instr_at.get(pc)
        if info is None:
            continue
        mnem, mode, n = info
        reads = set(_reads(mnem, mode))
        writes = set(_writes(mnem, mode))
        calls: set[int] = set()
        succs: list[int] = []
        op = mem[pc]

        def go(dst: int) -> None:
            # A continuation that lands on another subroutine's entry is a
            # tail-call (compose its effects); a reachable address is an
            # intra edge; anything else (data) is simply not followed —
            # matching the clobbers walk, which only flags `uncertain`
            # for computed JSR / unresolved JMP.
            if dst != entry and dst in entries:
                calls.add(dst)
            elif reachable(dst):
                succs.append(dst)
                frontier.append(dst)

        if op in _RETURNS:
            pass
        elif op == _JMP_IND:
            uncertain = True
            reads |= _ALL  # tail to an unknown target — may read anything
        elif op == _JSR and n == 3:
            tgt = mem[pc + 1] | (mem[pc + 2] << 8)
            if reachable(tgt):
                calls.add(tgt)
                callees.add(tgt)
            else:
                uncertain = True
                reads |= _ALL  # computed callee — may read anything
            go(pc + 3)
        elif op == _JMP_ABS and n == 3:
            tgt = mem[pc + 1] | (mem[pc + 2] << 8)
            if tgt in entries or reachable(tgt):
                go(tgt)
            else:
                uncertain = True
        elif op in _BRANCHES and n == 2:
            off = mem[pc + 1]
            go((pc + 2 + (off - 256 if off >= 0x80 else off)) & 0xFFFF)
            go(pc + 2)
        else:
            go(pc + n)

        callees |= calls
        nodes[pc] = {"reads": reads, "writes": writes, "calls": calls, "succs": succs}
    return nodes, callees, uncertain


def _live_in(entry: int, nodes: dict, clob: dict, inputs: dict, unc: dict) -> set[str]:
    """Registers this subroutine reads before defining (live-in / inputs),
    composing callee inputs/clobbers. Forward 'definite-written' must-
    analysis: in[pc] = ∩ out[pred]; a read of R not in in[pc] is an input;
    out[pc] = in[pc] ∪ writes(pc) ∪ clobbers(callees). Over-approximates
    (never under-reports an input) — joins shrink the must-set."""
    preds: dict[int, list[int]] = {pc: [] for pc in nodes}
    for pc, nd in nodes.items():
        for s in nd["succs"]:
            if s in preds:
                preds[s].append(pc)

    def node_reads(nd: dict) -> set[str]:
        r = set(nd["reads"])
        for c in nd["calls"]:
            r |= inputs.get(c, set())  # callee's unmet inputs propagate
        return r

    def node_writes(nd: dict) -> set[str]:
        w = set(nd["writes"])
        for c in nd["calls"]:
            w |= _ALL if unc.get(c) else clob.get(c, set())
        return w

    # Fixed-point on the must-set (start optimistic = all-written, except
    # the entry which has nothing written before it).
    out: dict[int, set[str]] = {pc: set(_ALL) for pc in nodes}
    changed = True
    while changed:
        changed = False
        for pc, nd in nodes.items():
            in_set = set() if pc == entry else set(_ALL)
            for p in preds[pc]:
                in_set &= out[p]
            if not preds[pc] and pc != entry:
                in_set = set()  # unreachable-from-entry node: assume nothing
            new_out = in_set | node_writes(nd)
            if new_out != out[pc]:
                out[pc] = new_out
                changed = True

    inp: set[str] = set()
    for pc, nd in nodes.items():
        in_set = set() if pc == entry else set(_ALL)
        for p in preds[pc]:
            in_set &= out[p]
        if not preds[pc] and pc != entry:
            in_set = set()
        inp |= node_reads(nd) - in_set
    return inp


def _jsr_targets(mem: bytes, instr_at: dict) -> set[int]:
    out: set[int] = set()
    for pc, (_m, _mode, n) in instr_at.items():
        if mem[pc] == _JSR and n == 3:
            out.add(mem[pc + 1] | (mem[pc + 2] << 8))
    return out


def analyze(
    mem: bytes,
    instr_at: dict,
    fn_entries: frozenset[int],
    start: int = LOAD_ADDR,
    end_excl: int = END_ADDR_EXCL,
) -> dict:
    # Analyse every subroutine entry (named functions + all JSR targets) so
    # the transitive closure is complete, not just the [function]-annotated
    # subset.
    entries = frozenset(
        e
        for e in (fn_entries | _jsr_targets(mem, instr_at))
        if start <= e < end_excl and e in instr_at
    )
    nodes_of: dict[int, dict] = {}
    direct: dict[int, set[str]] = {}
    callees: dict[int, set[int]] = {}
    uncertain: dict[int, bool] = {}
    for e in entries:
        nodes_of[e], callees[e], uncertain[e] = _walk_subroutine(
            e, mem, instr_at, entries, start, end_excl
        )
        direct[e] = (
            set().union(*(nd["writes"] for nd in nodes_of[e].values()))
            if nodes_of[e]
            else set()
        )

    # Clobbers + uncertainty flow up from callees (transitive fixed-point).
    clob = {e: set(d) for e, d in direct.items()}
    unc = dict(uncertain)
    changed = True
    while changed:
        changed = False
        for e in entries:
            cb, uc = len(clob[e]), unc[e]
            for c in callees.get(e, ()):
                if c in clob:
                    clob[e] |= clob[c]
                    unc[e] = unc[e] or unc[c]
                else:
                    unc[e] = True  # callee we couldn't analyse
            if len(clob[e]) != cb or unc[e] != uc:
                changed = True

    # Inputs (live-in) need the now-final clobbers + their own fixed-point:
    # a function's inputs grow as its callees' inputs are discovered.
    inputs = {e: set() for e in entries}
    changed = True
    while changed:
        changed = False
        for e in entries:
            new = _live_in(e, nodes_of[e], clob, inputs, unc)
            if new != inputs[e]:
                inputs[e] = new
                changed = True

    out: dict = {}
    for f in sorted(fn_entries):
        if f not in clob:
            continue
        regs = _ALL if unc[f] else clob[f]
        out[f"${f:04X}"] = {
            "clobbers": "".join(sorted(regs)),
            "inputs": "".join(sorted(inputs[f])),
            "direct": "".join(sorted(direct[f])),
            "uncertain": unc[f],
            "callees": sorted(f"${c:04X}" for c in callees.get(f, ())),
        }
    return out


def _function_entries(ann_path: Path) -> frozenset[int]:
    import tomllib  # noqa: PLC0415

    raw = tomllib.loads(ann_path.read_text())
    out: set[int] = set()
    for key in raw.get("function", {}):
        try:
            out.add(int(str(key).lstrip("$"), 16))
        except ValueError:
            pass
    return frozenset(out)


def _load(bin_path: Path, entry_path: Path, ann_path: Path):
    mem = bin_path.read_bytes()
    seeds = load_code_starts(entry_path)
    seeds.update(SEED_LANDMARKS.keys())
    expanded = expand_code_starts(mem, seeds, LOAD_ADDR, END_ADDR_EXCL)
    instr_at, _ = classify(mem, expanded, LOAD_ADDR, END_ADDR_EXCL)
    ann = load_annotations(ann_path)
    fn_entries = _function_entries(ann_path)
    return mem, instr_at, fn_entries, ann


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", default=str(STATIC_BIN))
    ap.add_argument("--entrypoints", default=str(ENTRYPOINTS))
    ap.add_argument("--annotations", default=str(ANNOTATIONS))
    ap.add_argument("--out", default=str(REPO_ROOT / "build" / "reg_effects.json"))
    ap.add_argument(
        "--report",
        action="store_true",
        help="print a summary instead of writing the artifact",
    )
    args = ap.parse_args(argv)

    mem, instr_at, fn_entries, ann = _load(
        Path(args.bin), Path(args.entrypoints), Path(args.annotations)
    )
    facts = analyze(mem, instr_at, fn_entries)

    if args.report:
        from collections import Counter  # noqa: PLC0415

        print(f"functions analysed: {len(facts)}")
        for field in ("clobbers", "inputs"):
            dist = Counter(v[field] or "(none)" for v in facts.values())
            print(f"  {field} distribution:")
            for combo, n in sorted(dist.items(), key=lambda x: (-x[1], x[0])):
                print(f"    {combo:6s} {n}")
        # Cross-check only registers_clobbered (a clean A/X/Y reg-list).
        # The hand `inputs` field is free prose ("A = palette index"), not
        # a reg-set, so a char-extraction comparison there is meaningless.
        mism = []
        n_hand = 0
        for k, v in facts.items():
            hand = ann.get(int(k.lstrip("$"), 16), {}).get("registers_clobbered")
            if isinstance(hand, str) and hand:
                n_hand += 1
                hand_set = "".join(sorted(c for c in hand.upper() if c in "AXY"))
                if hand_set and hand_set != v["clobbers"]:
                    mism.append(
                        (
                            k,
                            ann.get(int(k.lstrip("$"), 16), {}).get("name", ""),
                            hand_set,
                            v["clobbers"],
                        )
                    )
        print(
            f"\nhand-annotated registers_clobbered checked: {n_hand}; "
            f"mismatches vs derived: {len(mism)}"
        )
        for k, nm, h, d in mism[:20]:
            print(f"  {k} {nm}: hand={h or '∅'} derived={d or '∅'}")
        return 0

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(facts, indent=2) + "\n")
    print(f"reg_effects: wrote {out} ({len(facts)} functions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
