"""Per-function register-clobber analysis.

For every ``[function]`` entry, computes which of A / X / Y the function
destroys — the ``registers_clobbered`` interface field. A register is
clobbered if some path from the entry writes it before the function
returns, INCLUDING via the functions it calls (transitive closure over
JSR targets and tail-JMPs).

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


_ALL = frozenset("AXY")


def _walk_subroutine(
    entry: int,
    mem: bytes,
    instr_at: dict,
    entries: frozenset[int],
    start: int,
    end_excl: int,
) -> tuple[set[str], set[int], bool]:
    """Direct register writes + callee entries for one subroutine, plus an
    ``uncertain`` flag set when control leaves through an edge whose effect
    we can't follow statically (computed/self-modified JSR or JMP to a
    target that isn't a classified instruction). Uncertain subroutines are
    forced to clobber A/X/Y so the result never UNDER-reports."""
    direct: set[str] = set()
    callees: set[int] = set()
    seen: set[int] = set()
    uncertain = False
    frontier = [entry]

    def reachable(pc: int) -> bool:
        return start <= pc < end_excl and pc in instr_at

    def successor(pc: int) -> None:
        if pc != entry and pc in entries:
            callees.add(pc)  # tail-continuation into another subroutine
        elif reachable(pc):
            frontier.append(pc)

    while frontier:
        pc = frontier.pop()
        if pc in seen:
            continue
        seen.add(pc)
        info = instr_at.get(pc)
        if info is None:
            continue
        mnem, mode, n = info
        direct |= _writes(mnem, mode)
        op = mem[pc]
        if op in _RETURNS:
            continue
        if op == _JMP_IND:
            uncertain = True  # indirect jump — target unknown
            continue
        if op == _JSR and n == 3:
            tgt = mem[pc + 1] | (mem[pc + 2] << 8)
            if reachable(tgt):
                callees.add(tgt)
            else:
                uncertain = True  # computed / out-of-image / self-mod call
            successor(pc + 3)
        elif op == _JMP_ABS and n == 3:
            tgt = mem[pc + 1] | (mem[pc + 2] << 8)
            if tgt in entries:
                callees.add(tgt)
            elif reachable(tgt):
                frontier.append(tgt)
            else:
                uncertain = True
        elif op in _BRANCHES and n == 2:
            off = mem[pc + 1]
            successor((pc + 2 + (off - 256 if off >= 0x80 else off)) & 0xFFFF)
            successor(pc + 2)
        else:
            successor(pc + n)
    return direct, callees, uncertain


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
    direct: dict[int, set[str]] = {}
    callees: dict[int, set[int]] = {}
    uncertain: dict[int, bool] = {}
    for e in entries:
        direct[e], callees[e], uncertain[e] = _walk_subroutine(
            e, mem, instr_at, entries, start, end_excl
        )

    # Fixed-point: clobbers and uncertainty both flow up from callees.
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

    out: dict = {}
    for f in sorted(fn_entries):
        if f not in clob:
            continue
        regs = _ALL if unc[f] else clob[f]
        out[f"${f:04X}"] = {
            "clobbers": "".join(sorted(regs)),
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

        dist = Counter(v["clobbers"] or "(none)" for v in facts.values())
        print(f"functions analysed: {len(facts)}")
        for combo, n in sorted(dist.items(), key=lambda x: (-x[1], x[0])):
            print(f"  clobbers {combo:6s} {n}")
        # cross-check vs hand annotations
        mism = []
        for k, v in facts.items():
            a = ann.get(int(k.lstrip("$"), 16), {})
            hand = a.get("registers_clobbered")
            if isinstance(hand, str) and hand:
                hand_set = "".join(sorted(c for c in hand.upper() if c in "AXY"))
                if hand_set and hand_set != v["clobbers"]:
                    mism.append((k, a.get("name", ""), hand_set, v["clobbers"]))
        print(
            f"\nhand-annotated registers_clobbered checked: "
            f"{sum(1 for v in ann.values() if isinstance(v, dict) and v.get('registers_clobbered'))}"
        )
        if mism:
            print(f"mismatches vs derived ({len(mism)}):")
            for k, nm, h, d in mism[:30]:
                print(f"  {k} {nm}: hand={h or '∅'} derived={d or '∅'}")
        else:
            print("no hand/derived mismatches.")
        return 0

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(facts, indent=2) + "\n")
    print(f"reg_effects: wrote {out} ({len(facts)} functions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
