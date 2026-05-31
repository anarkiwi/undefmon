"""Per-function register-effect analysis (clobbers + inputs + outputs).

For every ``[function]`` entry, computes three interface fields over A/X/Y:
  - ``registers_clobbered`` — registers the function destroys (written on
    some path before it returns), transitive over its callees.
  - ``inputs`` — registers it reads before defining (live-in): what the
    caller must set up, also transitive over its callees.
  - ``outputs`` — registers it returns a meaningful value in: those it
    DEFINITELY writes before every exit (must-define) AND that some caller
    reads after the call before redefining (interprocedural liveness). The
    intersection excludes scratch left in a register and inputs passed
    through unchanged, so it does not falsely claim a return value; a
    function with no caller (handler/entrypoint) has no outputs.

All three compose across JSR/tail-call edges via fixed-points. A register
is clobbered if any path writes it; an input if any path reads it before a
definite write. Calls to the standard C64 KERNAL jump-table vectors are
modelled from their documented register effects (the ``_KERNAL`` table), so
a function whose only opaque call is a KERNAL routine is analysed precisely.
Remaining computed/self-modified/out-of-image calls are treated
conservatively (clobber A/X/Y; read A/X/Y) so neither clobbers nor inputs
UNDER-reports; outputs is the conservative-against-false-claim direction
and is only rendered for soundly-analysed (certain) functions.

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

# Documented A/X/Y register effects of the standard C64 KERNAL jump-table
# vectors, as (reads, writes). `reads` = the registers the routine consumes
# as inputs (so they are live-in at the call); `writes` = the registers it
# changes ("registers affected" per the Commodore 64 Programmer's Reference
# Guide) — the sound clobber set. A direct `JSR $FFxx` runs with the KERNAL
# ROM banked in (defMON only banks it out behind the jsr_with_ram_helper
# trampoline, never around these straight calls), so the standard contract
# holds. Modelling these lets a function whose only opaque call was a KERNAL
# vector be analysed precisely instead of falling back to the conservative
# A/X/Y; the effect cascades to its callers.
_KERNAL: dict[int, tuple[frozenset[str], frozenset[str]]] = {
    0xFF9F: (frozenset(), frozenset("AXY")),  # SCNKEY  scan keyboard
    0xFFB7: (frozenset(), frozenset("A")),  # READST  read I/O status
    0xFFBA: (frozenset("AXY"), frozenset()),  # SETLFS  set file/dev/secondary
    0xFFBD: (frozenset("AXY"), frozenset()),  # SETNAM  set filename
    0xFFC0: (frozenset(), frozenset("AXY")),  # OPEN
    0xFFC3: (frozenset("A"), frozenset("AXY")),  # CLOSE   A = logical file no.
    0xFFC6: (frozenset("X"), frozenset("AX")),  # CHKIN   X = logical file no.
    0xFFC9: (frozenset("X"), frozenset("AX")),  # CHKOUT  X = logical file no.
    0xFFCC: (frozenset(), frozenset("AX")),  # CLRCHN  restore default I/O
    0xFFCF: (frozenset(), frozenset("AX")),  # CHRIN   -> A = byte
    0xFFD2: (frozenset("A"), frozenset("A")),  # CHROUT  A = byte to output
    0xFFD5: (frozenset("AXY"), frozenset("AXY")),  # LOAD    A=verify X/Y=addr
    0xFFD8: (frozenset("AXY"), frozenset("AXY")),  # SAVE    A=zp ptr X/Y=end
    0xFFDB: (frozenset("AXY"), frozenset()),  # SETTIM  set jiffy clock
    0xFFDE: (frozenset(), frozenset("AXY")),  # RDTIM   -> A/X/Y = jiffies
    0xFFE1: (frozenset(), frozenset("AX")),  # STOP    test STOP key
    0xFFE4: (frozenset(), frozenset("AXY")),  # GETIN   -> A = byte
    0xFFE7: (frozenset(), frozenset("AX")),  # CLALL   close all channels
    0xFFF0: (frozenset("XY"), frozenset("AXY")),  # PLOT    C=0 set / C=1 read cursor
}

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
    smc: dict[int, frozenset[int]] | None = None,
):
    """Build one subroutine's intra-procedural CFG.

    Returns (nodes, callees, uncertain) where nodes[pc] = {reads, writes,
    calls, succs}: ``calls`` is the set of subroutine entries invoked at
    pc (a JSR target, or a tail JMP/fall-through into another entry) whose
    inputs/clobbers compose at fixpoint; ``succs`` are the intra-procedural
    continuation PCs. ``uncertain`` is set for a computed/self-modified/
    out-of-image transfer whose effect can't be followed.

    ``smc`` maps a self-modified dispatch site (a JSR/JMP whose operand the
    program patches at runtime) to its enumerated set of target entries
    (from the ``smc_dispatch`` annotations). At such a site the static
    operand is a placeholder, so the walk composes the union of the listed
    targets instead of giving up — turning a known multi-way dispatch into
    a precise multi-callee edge."""
    smc = smc or {}
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
            if pc in smc:
                for t in smc[pc]:  # self-modified dispatch: all known targets
                    calls.add(t)
                    callees.add(t)
            elif reachable(tgt):
                calls.add(tgt)
                callees.add(tgt)
            elif tgt in _KERNAL:
                kr, kw = _KERNAL[tgt]
                reads |= kr  # KERNAL routine's documented effects, inline
                writes |= kw
            else:
                uncertain = True
                reads |= _ALL  # computed callee — may read anything
            go(pc + 3)
        elif op == _JMP_ABS and n == 3:
            tgt = mem[pc + 1] | (mem[pc + 2] << 8)
            if pc in smc:
                for t in smc[pc]:  # self-modified tail dispatch
                    calls.add(t)
                    callees.add(t)
            elif tgt in entries or reachable(tgt):
                go(tgt)
            elif tgt in _KERNAL:
                kr, kw = _KERNAL[tgt]  # tail-call into KERNAL, then returns
                reads |= kr
                writes |= kw
            else:
                uncertain = True
        elif op in _BRANCHES and n == 2:
            off = mem[pc + 1]
            go((pc + 2 + (off - 256 if off >= 0x80 else off)) & 0xFFFF)
            go(pc + 2)
        else:
            go(pc + n)

        callees |= calls
        nodes[pc] = {
            "reads": reads,
            "writes": writes,
            "calls": calls,
            "succs": succs,
            "op": op,
        }
    return nodes, callees, uncertain


def _preds(nodes: dict) -> dict[int, list[int]]:
    preds: dict[int, list[int]] = {pc: [] for pc in nodes}
    for pc, nd in nodes.items():
        for s in nd["succs"]:
            if s in preds:
                preds[s].append(pc)
    return preds


def _node_writes(nd: dict, clob: dict, unc: dict) -> set[str]:
    w = set(nd["writes"])
    for c in nd["calls"]:
        w |= _ALL if unc.get(c) else clob.get(c, set())
    return w


def _definite_written(
    entry: int, nodes: dict, preds: dict, clob: dict, unc: dict
) -> dict[int, set[str]]:
    """Forward 'definite-written' must-analysis. Returns out[pc] = the set
    of A/X/Y written on EVERY path from entry through pc. Starts optimistic
    (all-written) and shrinks at joins (in[pc] = ∩ out[pred]); the entry —
    and any node unreachable from it — starts with nothing written."""
    out: dict[int, set[str]] = {pc: set(_ALL) for pc in nodes}
    changed = True
    while changed:
        changed = False
        for pc, nd in nodes.items():
            in_set = set() if pc == entry else set(_ALL)
            for p in preds[pc]:
                in_set &= out[p]
            if not preds[pc] and pc != entry:
                in_set = set()
            new_out = in_set | _node_writes(nd, clob, unc)
            if new_out != out[pc]:
                out[pc] = new_out
                changed = True
    return out


def _in_set(pc: int, entry: int, preds: dict, out: dict) -> set[str]:
    """The definite-written set on entry to ``pc`` (before its own writes)."""
    if pc == entry or not preds[pc]:
        return set()
    acc = set(_ALL)
    for p in preds[pc]:
        acc &= out[p]
    return acc


def _live_in(entry: int, nodes: dict, clob: dict, inputs: dict, unc: dict) -> set[str]:
    """Registers this subroutine reads before defining (live-in / inputs),
    composing callee inputs/clobbers. A read of R at pc that is not in the
    definite-written set on entry to pc is an input; callee unmet inputs
    propagate. Over-approximates (never under-reports an input)."""
    preds = _preds(nodes)
    out = _definite_written(entry, nodes, preds, clob, unc)

    def node_reads(nd: dict) -> set[str]:
        r = set(nd["reads"])
        for c in nd["calls"]:
            r |= inputs.get(c, set())  # callee's unmet inputs propagate
        return r

    inp: set[str] = set()
    for pc, nd in nodes.items():
        inp |= node_reads(nd) - _in_set(pc, entry, preds, out)
    return inp


def _exit_nodes(nodes: dict) -> list[int]:
    """PCs at which the subroutine returns to its caller: an RTS/RTI/BRK, a
    tail-call (JMP/fall-through into another entry — calls set, no intra
    successor), or an indirect/computed tail JMP."""
    out = []
    for pc, nd in nodes.items():
        op = nd["op"]
        if op in _RETURNS or op == _JMP_IND or (nd["calls"] and not nd["succs"]):
            out.append(pc)
    return out


def _defined_at_exit(
    entry: int, nodes: dict, clob: dict, unc: dict, mustdef: dict
) -> set[str]:
    """Registers this subroutine DEFINITELY writes before every return —
    a must-analysis intersected over all exit points. A tail-call exit also
    inherits whatever the tail callee must-defines (``mustdef``). Used to
    distinguish a genuine return value from a register the caller passed
    through unchanged. No normal exit (pure loop) -> nothing claimed."""
    preds = _preds(nodes)
    out = _definite_written(entry, nodes, preds, clob, unc)
    exits = _exit_nodes(nodes)
    if not exits:
        return set()
    acc = set(_ALL)
    for pc in exits:
        nd = nodes[pc]
        defined = out[pc]  # includes pc's own writes / call clobbers
        if nd["op"] == _JMP_ABS and nd["calls"] and not nd["succs"]:
            for c in nd["calls"]:
                defined = defined | mustdef.get(c, set())
        acc &= defined
    return acc


def _liveness(
    entry: int, nodes: dict, inputs: dict, clob: dict, unc: dict, demand_f: set[str]
) -> dict[int, set[str]]:
    """Backward liveness within one subroutine, given ``demand_f`` (the
    registers this subroutine's own callers want back). Returns, per call
    site, the set of registers live immediately after that site — i.e. what
    its callee is demanded to produce. A JSR site uses the callee's inputs
    and is killed by the callee's clobbers; an exit node's live-out is
    ``demand_f`` (the value flows on up to this subroutine's caller)."""
    live_in: dict[int, set[str]] = {pc: set() for pc in nodes}
    live_out: dict[int, set[str]] = {pc: set() for pc in nodes}

    def use_def(nd: dict) -> tuple[set[str], set[str]]:
        use = set(nd["reads"])
        dfn = set(nd["writes"])
        for c in nd["calls"]:
            use |= inputs.get(c, set())
            dfn |= _ALL if unc.get(c) else clob.get(c, set())
        return use, dfn

    is_exit = set(_exit_nodes(nodes))
    changed = True
    while changed:
        changed = False
        for pc, nd in nodes.items():
            if pc in is_exit:
                lo = set(demand_f)
            else:
                lo = set()
                for s in nd["succs"]:
                    lo |= live_in[s]
            use, dfn = use_def(nd)
            li = use | (lo - dfn)
            if lo != live_out[pc] or li != live_in[pc]:
                live_out[pc], live_in[pc] = lo, li
                changed = True

    # What each callee is demanded to produce from this subroutine.
    contrib: dict[int, set[str]] = {}
    for pc, nd in nodes.items():
        if not nd["calls"]:
            continue
        if nd["op"] == _JSR:
            after = set()  # live immediately after the call = live-in of succs
            for s in nd["succs"]:
                after |= live_in[s]
        else:  # tail-call: the callee returns straight to this caller's caller
            after = set(demand_f)
        for c in nd["calls"]:
            contrib.setdefault(c, set()).update(after)
    return contrib


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
    smc: dict[int, frozenset[int]] | None = None,
) -> dict:
    # Self-modified dispatch sites resolve to their enumerated targets; keep
    # only classified ones (so they compose as real callees).
    smc = {
        site: frozenset(t for t in tgts if start <= t < end_excl and t in instr_at)
        for site, tgts in (smc or {}).items()
    }
    smc = {site: tgts for site, tgts in smc.items() if tgts}
    smc_targets = frozenset().union(*smc.values()) if smc else frozenset()
    # Analyse every subroutine entry (named functions + all JSR targets, plus
    # the targets of self-modified dispatch sites) so the transitive closure
    # is complete, not just the [function]-annotated subset.
    entries = frozenset(
        e
        for e in (fn_entries | _jsr_targets(mem, instr_at) | smc_targets)
        if start <= e < end_excl and e in instr_at
    )
    nodes_of: dict[int, dict] = {}
    direct: dict[int, set[str]] = {}
    callees: dict[int, set[int]] = {}
    uncertain: dict[int, bool] = {}
    for e in entries:
        nodes_of[e], callees[e], uncertain[e] = _walk_subroutine(
            e, mem, instr_at, entries, start, end_excl, smc
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

    # Must-define-at-exit: registers a function always freshly writes before
    # returning. Fixed-point because a tail-call exit inherits its callee's
    # must-defines.
    mustdef = {e: set(_ALL) for e in entries}
    changed = True
    while changed:
        changed = False
        for e in entries:
            new = _defined_at_exit(e, nodes_of[e], clob, unc, mustdef)
            if new != mustdef[e]:
                mustdef[e] = new
                changed = True

    # Demand (interprocedural backward liveness): the registers some caller
    # reads after a call to F, before redefining them. Grows monotonically:
    # as a function's own demand rises, so does what it asks of its callees.
    demand = {e: set() for e in entries}
    changed = True
    while changed:
        changed = False
        acc = {e: set() for e in entries}
        for e in entries:
            for c, regs in _liveness(
                e, nodes_of[e], inputs, clob, unc, demand[e]
            ).items():
                if c in acc:
                    acc[c] |= regs
        for e in entries:
            if acc[e] != demand[e]:
                demand[e] = acc[e]
                changed = True

    # A return register is one the function definitely produces (mustdef) AND
    # a caller actually consumes (demand): excludes scratch left in a register
    # and inputs passed through unchanged.
    outputs = {e: (mustdef[e] & demand[e]) for e in entries}

    out: dict = {}
    for f in sorted(fn_entries):
        if f not in clob:
            continue
        regs = _ALL if unc[f] else clob[f]
        out[f"${f:04X}"] = {
            "clobbers": "".join(sorted(regs)),
            "inputs": "".join(sorted(inputs[f])),
            "outputs": "".join(sorted(outputs[f])),
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


def _smc_dispatch_targets(ann_path: Path) -> dict[int, frozenset[int]]:
    """Map each ``[smc_dispatch]`` site address to its enumerated target
    entries. Sites with no recorded targets (e.g. the jsr_with_ram_helper
    trampoline, whose target the caller passes in at runtime) are omitted —
    they stay opaque and the function remains conservatively uncertain."""
    import tomllib  # noqa: PLC0415

    raw = tomllib.loads(ann_path.read_text())
    out: dict[int, frozenset[int]] = {}
    for site, body in raw.get("smc_dispatch", {}).items():
        tgts = body.get("targets") or []
        addrs = frozenset(int(t["addr"].lstrip("$"), 16) for t in tgts if "addr" in t)
        if addrs:
            out[int(str(site).lstrip("$"), 16)] = addrs
    return out


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
    smc = _smc_dispatch_targets(Path(args.annotations))
    facts = analyze(mem, instr_at, fn_entries, smc=smc)

    if args.report:
        from collections import Counter  # noqa: PLC0415

        print(f"functions analysed: {len(facts)}")
        for field in ("clobbers", "inputs", "outputs"):
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
