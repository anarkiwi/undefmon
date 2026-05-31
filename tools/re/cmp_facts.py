"""Comparison-site fact extractor for defMON.

For every conditional branch in the static image, traces backwards
through the CFG to find:

  * which register the branch's flag-setter consumes (A / X / Y);
  * what variable was last loaded into that register, possibly with
    a chain of mask transforms (currently only AND #imm);
  * the comparison's RHS (immediate value, or RHS-variable for
    `cmp var` forms);
  * the containing function annotation (so the emitter can synthesise
    `<block>_skip_N` labels instead of bare `L_XXXX`).

Independent of the existing emit-time PC-window walker — uses the
static call graph (every conditional/unconditional branch + every
fall-through edge) so the walk crosses branch arrivals and joins
multiple intra-procedural predecessors.

Output: build/cmp_facts.json. Keyed by branch PC (hex string).

Usage:
    python3 -m tools.re.cmp_facts \\
        --bin artefacts/defmon-static.bin \\
        --entrypoints trace/entrypoints.json \\
        --annotations tools/re/annotations.toml \\
        --out build/cmp_facts.json
"""

from __future__ import annotations

import argparse
import bisect
import json
from pathlib import Path

from tools.re.callgraph import build as build_callgraph, default_seeds
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
DEFAULT_OUT = REPO_ROOT / "build" / "cmp_facts.json"


# ── Mnemonic categories ─────────────────────────────────────────────

_BRANCHES = frozenset({"BPL", "BMI", "BVC", "BVS", "BCC", "BCS", "BNE", "BEQ"})

# Which flag each branch consumes.
_BRANCH_FLAG = {
    "BEQ": "Z",
    "BNE": "Z",
    "BMI": "N",
    "BPL": "N",
    "BCS": "C",
    "BCC": "C",
    "BVS": "V",
    "BVC": "V",
}

# Instructions that set each flag. The undocumented opcodes defMON uses
# set the same N/Z(/C) flags as their documented analogues: LAX loads
# A/X (N/Z); ANC/ALR/ARR compute A (N/Z + C); AXS computes X (N/Z/C).
_FLAG_SETTERS_ZN = frozenset(
    {
        "LDA",
        "LDX",
        "LDY",
        "AND",
        "ORA",
        "EOR",
        "ADC",
        "SBC",
        "INC",
        "DEC",
        "INX",
        "INY",
        "DEX",
        "DEY",
        "ASL",
        "LSR",
        "ROL",
        "ROR",
        "TAX",
        "TAY",
        "TXA",
        "TYA",
        "TSX",
        "CMP",
        "CPX",
        "CPY",
        "BIT",
        "PLA",
        "LAX",
        "ANC",
        "ALR",
        "ARR",
        "AXS",
    }
)
_FLAG_SETTERS = {
    "Z": _FLAG_SETTERS_ZN,
    "N": _FLAG_SETTERS_ZN,
    "C": frozenset(
        {
            "CMP",
            "CPX",
            "CPY",
            "ADC",
            "SBC",
            "ASL",
            "LSR",
            "ROL",
            "ROR",
            "SEC",
            "CLC",
            "PLP",
            "RTI",
            "ANC",
            "ALR",
            "ARR",
            "AXS",
        }
    ),
    "V": frozenset({"ADC", "SBC", "BIT", "CLV", "PLP", "RTI"}),
}

# Flag-neutral instructions — skippable when hunting backwards for the
# instruction that actually set the flag the branch consumes.
_FLAG_NEUTRAL = frozenset(
    {
        "STA",
        "STX",
        "STY",
        "NOP",
        "PHA",
        "PHP",
        "TXS",
        "SED",
        "CLD",
        "CLI",
        "SEI",
        # branches don't write flags
        "BEQ",
        "BNE",
        "BMI",
        "BPL",
        "BCS",
        "BCC",
        "BVS",
        "BVC",
    }
)


# Per-register classification used during the source walk. A "writer"
# kills the register's source; a "neutral" op walks past; a "transform"
# is recorded and carried in the transform chain.
_A_WRITERS_PLAIN = frozenset({"LDA", "TXA", "TYA", "PLA", "LAX"})
_A_TRANSFORMS = frozenset({"AND", "ORA", "EOR", "ADC", "SBC", "ANC", "ALR", "ARR"})

_X_WRITERS = frozenset({"LDX", "TAX", "TSX", "INX", "DEX", "LAX", "AXS"})
_Y_WRITERS = frozenset({"LDY", "TAY", "INY", "DEY"})

# Per-register neutrals. Anything not in writers/transforms/neutrals
# is "unmodeled" — treated as a kill (conservative).
_A_NEUTRAL = frozenset(
    {
        "LDX",
        "LDY",
        "STA",
        "STX",
        "STY",
        "INC",
        "DEC",
        "INX",
        "INY",
        "DEX",
        "DEY",
        "TAX",
        "TAY",
        "CMP",
        "CPX",
        "CPY",
        "BIT",
        "NOP",
        "PHA",
        "PHP",
        "PLP",
        "TXS",
        "SED",
        "CLD",
        "CLI",
        "SEI",
        "SEC",
        "CLC",
        "CLV",
        "AXS",  # writes X only — neutral for A
        "JMP",
        "BEQ",
        "BNE",
        "BMI",
        "BPL",
        "BCS",
        "BCC",
        "BVS",
        "BVC",
    }
)
_X_NEUTRAL = frozenset(
    {
        "LDA",
        "LDY",
        "STA",
        "STX",
        "STY",
        "INC",
        "DEC",
        "INY",
        "DEY",
        "TYA",
        "TAY",
        "TXA",
        "AND",
        "ORA",
        "EOR",
        "ADC",
        "SBC",
        "ANC",
        "ALR",
        "ARR",  # write A only — neutral for X
        "PLA",  # pulls into A only — neutral for X
        "CMP",
        "CPX",
        "CPY",
        "BIT",
        "NOP",
        "PHA",
        "PHP",
        "PLP",
        "TXS",
        "SED",
        "CLD",
        "CLI",
        "SEI",
        "SEC",
        "CLC",
        "CLV",
        "ASL",
        "LSR",
        "ROL",
        "ROR",
        "JMP",
        "BEQ",
        "BNE",
        "BMI",
        "BPL",
        "BCS",
        "BCC",
        "BVS",
        "BVC",
    }
)
_Y_NEUTRAL = frozenset(
    {
        "LDA",
        "LDX",
        "STA",
        "STX",
        "STY",
        "INC",
        "DEC",
        "INX",
        "DEX",
        "TXA",
        "TAX",
        "TSX",
        "TYA",
        "AND",
        "ORA",
        "EOR",
        "ADC",
        "SBC",
        "ANC",
        "ALR",
        "ARR",
        "AXS",  # write A or X only — neutral for Y
        "CMP",
        "CPX",
        "CPY",
        "BIT",
        "NOP",
        "PHA",
        "PHP",
        "PLP",
        "TXS",
        "SED",
        "CLD",
        "CLI",
        "SEI",
        "SEC",
        "CLC",
        "CLV",
        "ASL",
        "LSR",
        "ROL",
        "ROR",
        "LAX",  # writes A+X, reads Y — neutral for Y
        "PLA",  # pulls into A only — neutral for Y
        "JMP",
        "BEQ",
        "BNE",
        "BMI",
        "BPL",
        "BCS",
        "BCC",
        "BVS",
        "BVC",
    }
)

_LOADER_OF = {"A": "LDA", "X": "LDX", "Y": "LDY"}
_LOADER_MODES = {
    "A": frozenset({"abs", "zp", "abx", "aby", "zpx", "zpy"}),
    "X": frozenset({"abs", "zp", "aby", "zpy"}),
    "Y": frozenset({"abs", "zp", "abx", "zpx"}),
}
# Modes that load via a zp pointer + register index. The source isn't
# a static memory address; we record it as ("var_indirect", ptr_zp_addr,
# index_reg). Both LDA and LAX use izy for `lda/lax (zp),Y`.
_INDIRECT_LOADER_MODES = {
    "A": frozenset({"izy"}),
    "X": frozenset(),  # LDX doesn't have izy
    "Y": frozenset(),
}
_INDEXED = {"abx": "X", "aby": "Y", "zpx": "X", "zpy": "Y"}

# Walk budget per branch — guards against pathological CFGs (wide
# multi-path joins). The branch+transform state-space can explode
# when many predecessors converge or transforms stack up; 2048 covers
# every dispatch + handler chain in defMON.
_MAX_WALK_STEPS = 2048


# ── CFG helpers ─────────────────────────────────────────────────────


def _operand_addr(mem: bytes, pc: int, mode: str, n: int) -> int | None:
    """Resolve the 16-bit memory address an instruction reads/writes,
    or None if the mode doesn't address memory directly."""
    if mode in ("abs", "abx", "aby"):
        if n != 3:
            return None
        return mem[pc + 1] | (mem[pc + 2] << 8)
    if mode in ("zp", "zpx", "zpy", "izy"):
        return mem[pc + 1]
    return None


def _preds_of(pc: int, graph, instr_at: dict[int, tuple[str, str, int]]) -> list[int]:
    """Intra-procedural predecessors of ``pc``: its fall-through
    predecessor (if any) plus any branch / JMP source landing on it.
    JSR sources are deliberately excluded — they cross function
    boundaries and the callee's register state isn't a continuation
    of the caller's."""
    preds: list[int] = []
    ft = graph.fall_through_in.get(pc)
    if ft is not None:
        preds.append(ft)
    for src in graph.code_in.get(pc, []):
        info = instr_at.get(src)
        if info is None:
            continue
        mnem = info[0]
        if mnem in _BRANCHES or mnem == "JMP":
            preds.append(src)
    return preds


def _find_flag_setter(
    branch_pc: int,
    branch_mnem: str,
    graph,
    instr_at: dict[int, tuple[str, str, int]],
    max_skip: int = 40,
) -> int | None:
    """Walk back via fall-through edges to the instruction that set the
    flag the branch consumes. Skips any instruction that does NOT set
    that specific flag (the per-flag setter table is complete, so an op
    absent from it leaves the flag untouched and is transparent) — e.g.
    an ``LDA`` between a ``CMP`` and a ``BCC`` doesn't touch carry. A
    ``JSR`` is returned as the setter: nothing after it touched the flag,
    so the value tested is the flag as the callee left it. Returns None at
    a control-flow barrier (``JMP``/``RTS``/``RTI``/``BRK``), when the
    chain leaves fall-through territory (a multi-inbound site), or after
    ``max_skip`` transparent instructions."""
    flag = _BRANCH_FLAG.get(branch_mnem)
    if flag is None:
        return None
    setters = _FLAG_SETTERS[flag]
    pc = graph.fall_through_in.get(branch_pc)
    skipped = 0
    while pc is not None:
        info = instr_at.get(pc)
        if info is None:
            return None
        mnem = info[0]
        if mnem in setters or mnem == "JSR":
            return pc
        if mnem in ("JMP", "RTS", "RTI", "BRK"):
            return None
        skipped += 1
        if skipped > max_skip:
            return None
        pc = graph.fall_through_in.get(pc)
    return None


def _reg_for_setter(mnem: str, mode: str) -> tuple[str, str | None] | None:
    """Return ``(walk_reg, post_op)`` for setters whose flag-input is a
    register, or None for setters whose flag-input is their explicit
    operand (handled by ``_lhs_from_operand_setter``).

    ``walk_reg``: the register whose backward source we should resolve.
    ``post_op``: a tag describing how the setter itself transformed
    that register's value before setting the flags. For example,
    ``INX`` sets flags on ``X + 1`` so the tested value is the source
    incremented; the renderer can choose whether to surface that.

    Cases:
      * ``CMP/AND/ORA/EOR/ADC/SBC`` → A, no post-op (CMP doesn't write A;
        the arithmetic/bitwise ones do, but the flag is read AFTER the
        op so the tested value IS A-post, and the walker is asked for
        A's source PRE-op — by walking back from the setter's
        predecessors, we see A-pre, not A-post, exactly what we want).
      * ``CPX/CPY`` → X / Y respectively.
      * ``INX/DEX/INY/DEY`` → tracked register with ``INC``/``DEC``
        post-op.
      * ``TAX/TAY`` write X/Y from A — flag tested is the destination
        but the SOURCE is A, so we walk A. Post-op: ``None``
        (the transfer is identity).
      * ``TXA/TYA`` write A from X/Y — walk X/Y.
      * acc-mode ``ASL/LSR/ROL/ROR`` rewrite A; walk A pre-shift; the
        post-op carries the shift kind so the renderer knows whether
        a BCC/BCS reads bit 0 (LSR) or bit 7 (ASL).
      * ``PLA`` — A came from the stack, unwalkable. Caller should
        record unknown directly.
    """
    if mnem in ("CMP", "AND", "ORA", "EOR", "ADC", "SBC"):
        return ("A", None)
    if mnem == "CPX":
        return ("X", None)
    if mnem == "CPY":
        return ("Y", None)
    if mnem == "INX":
        return ("X", "INC")
    if mnem == "DEX":
        return ("X", "DEC")
    if mnem == "INY":
        return ("Y", "INC")
    if mnem == "DEY":
        return ("Y", "DEC")
    if mnem == "TAX":
        return ("A", None)
    if mnem == "TAY":
        return ("A", None)
    if mnem == "TXA":
        return ("X", None)
    if mnem == "TYA":
        return ("Y", None)
    if mode == "acc" and mnem in ("ASL", "LSR", "ROL", "ROR"):
        return ("A", mnem)
    return None


# ── Source-walk core ────────────────────────────────────────────────


def _is_acc_mode_writer(mnem: str, mode: str, reg: str) -> bool:
    """ASL/LSR/ROL/ROR with mode=acc rewrite A. Memory-mode forms don't."""
    return reg == "A" and mode == "acc" and mnem in ("ASL", "LSR", "ROL", "ROR")


def _is_writer(mnem: str, mode: str, reg: str) -> bool:
    """Does this op overwrite ``reg``? Transforms count as writers for
    the purpose of the kill check (the caller handles transforms
    specially before this check)."""
    if _is_acc_mode_writer(mnem, mode, reg):
        return True
    if reg == "A":
        return mnem in _A_WRITERS_PLAIN or mnem in _A_TRANSFORMS
    if reg == "X":
        return mnem in _X_WRITERS
    if reg == "Y":
        return mnem in _Y_WRITERS
    return False


def _is_neutral(mnem: str, mode: str, reg: str) -> bool:
    """Does this op leave ``reg`` unchanged? acc-mode shifts are NOT
    neutral for A."""
    if _is_acc_mode_writer(mnem, mode, reg):
        return False
    if reg == "A":
        return mnem in _A_NEUTRAL
    if reg == "X":
        return mnem in _X_NEUTRAL
    if reg == "Y":
        return mnem in _Y_NEUTRAL
    return False


# ── Source representation ──────────────────────────────────────────
# Each source the walker finds is a tagged tuple:
#   ("var",    addr_int, index_str_or_None, transform_tuple)
#   ("imm",    value_int,                  transform_tuple)
#   ("caller", reg_at_exit,                transform_tuple)
#
# ``transform_tuple`` is a tuple of items, oldest at the START
# (entry of the chain, closest to the load) and newest at the END
# (closest to the setter). Items have shape:
#   ("AND",  imm)
#   ("ORA",  imm)   — not currently produced, reserved
#   ("EOR",  imm)   — reserved
#   ("INX",) / ("DEX",) / ("INY",) / ("DEY",)
#   ("TXA",) / ("TYA",) / ("TAX",) / ("TAY",)
#   ("ASL",) / ("LSR",) / ("ROL",) / ("ROR",)


def _resolve_lhs(
    setter_pc: int,
    reg: str,
    mem: bytes,
    instr_at: dict[int, tuple[str, str, int]],
    graph,
    depth: int = 0,
) -> dict:
    """Find what fed ``reg`` at ``setter_pc``.

    Walks backwards over intra-procedural CFG edges. State carried per
    frontier entry: ``(pc, transform_chain, current_register)``. The
    current register switches when the walker passes through a
    transfer instruction (going backwards): if we're looking for A's
    source and we encounter a ``TXA``, we know A came from X — so we
    switch to tracking X and keep walking.

    Stops at:
      * A loader for the current register (LDA/LDX/LDY abs/zp/indexed
        or imm). Records the source; doesn't walk further on this path.
      * A function-entry boundary (no fall-through predecessor, no
        branch source). Records ``("caller", reg, transform)`` so the
        emitter knows A came in from outside this function.
      * A kill (unmodeled writer to the tracked register). Aborts the
        whole resolution with ``unknown``.
    """
    sources: set[tuple] = set()
    # visited keyed by (pc, cur_reg) only — NOT by transform. A second
    # visit to the same (pc, cur) via a back-edge would otherwise
    # accumulate a longer transform chain indefinitely (e.g. a
    # countdown loop adds a DEX per iteration), exploding the walk.
    # The single-transform-chain assumption in `_format_resolved`
    # collapses distinct chains arriving at the same source key into
    # `transform=None` anyway, so dropping transform from the visited
    # key only changes behaviour for true loops.
    visited: set[tuple[int, str]] = set()
    # frontier: (pc, transform, cur_reg)
    frontier: list[tuple[int, tuple, str]] = []
    initial_preds = _preds_of(setter_pc, graph, instr_at)
    if not initial_preds:
        return {"kind": "from_caller", "reg": reg, "transform": None}
    for p in initial_preds:
        frontier.append((p, (), reg))
    steps = 0

    while frontier:
        if steps >= _MAX_WALK_STEPS:
            return {"kind": "unknown", "reason": "walk_limit"}
        steps += 1
        pc, transform, cur = frontier.pop()
        state = (pc, cur)
        if state in visited:
            continue
        visited.add(state)
        info = instr_at.get(pc)
        if info is None:
            return {"kind": "unknown", "reason": "non_code_predecessor"}
        mnem, mode, n = info

        # Loader for the currently-tracked register?
        # LAX loads BOTH A and X from memory; counts as a loader for
        # either when we're tracking that register.
        is_loader = (mnem == _LOADER_OF[cur]) or (mnem == "LAX" and cur in ("A", "X"))
        if is_loader:
            if mode == "imm":
                sources.add(("imm", mem[pc + 1], transform))
                continue
            if mode in _LOADER_MODES[cur]:
                addr = _operand_addr(mem, pc, mode, n)
                if addr is None:
                    return {"kind": "unknown", "reason": "bad_loader_mode"}
                index = _INDEXED.get(mode)
                sources.add(("var", addr, index, transform))
                continue
            if mode in _INDIRECT_LOADER_MODES[cur] or (mnem == "LAX" and mode == "izy"):
                # lda/lax (zp),Y — source is the zp pointer + Y index.
                # The pointer's contents change at runtime, so we can't
                # name a single var, but the pointer's label is itself
                # informative ("(zp_sidtab_row_lo),Y" is meaningful).
                ptr_addr = mem[pc + 1]
                sources.add(("var_indirect", ptr_addr, "Y", transform))
                continue
            return {"kind": "unknown", "reason": f"{mnem.lower()}_mode_{mode}"}

        # ── Register-switching transfers ─────────────────────────
        # Walking BACKWARDS, a transfer that wrote our tracked
        # register tells us where that register's value came from.
        if cur == "A" and mnem == "TXA":
            new_t = transform + (("TXA",),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, "X"))
            continue
        if cur == "A" and mnem == "TYA":
            new_t = transform + (("TYA",),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, "Y"))
            continue
        if cur == "X" and mnem == "TAX":
            new_t = transform + (("TAX",),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, "A"))
            continue
        if cur == "Y" and mnem == "TAY":
            new_t = transform + (("TAY",),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, "A"))
            continue

        # ── In-place transforms ──────────────────────────────────
        # AND #imm on A
        if cur == "A" and mnem == "AND" and mode == "imm":
            new_t = transform + (("AND", mem[pc + 1]),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, "A"))
            continue
        # INX/DEX on X, INY/DEY on Y
        if (cur == "X" and mnem in ("INX", "DEX")) or (
            cur == "Y" and mnem in ("INY", "DEY")
        ):
            new_t = transform + ((mnem,),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, cur))
            continue
        # acc-mode shifts on A
        if cur == "A" and mode == "acc" and mnem in ("ASL", "LSR", "ROL", "ROR"):
            new_t = transform + ((mnem,),)
            for p in _preds_of(pc, graph, instr_at):
                frontier.append((p, new_t, "A"))
            continue

        # ── Kill / neutral / unmodeled ───────────────────────────
        if _is_writer(mnem, mode, cur):
            # An ALU op computed `cur` in-function from a value we can't
            # name. The register itself is still the honest lhs: the
            # branch condition surfaces the comparison (e.g. `A < #imm?`)
            # even though the operand isn't a variable.
            if mnem in ("ADC", "SBC", "ORA", "EOR", "AND", "ANC", "ALR", "ARR", "AXS"):
                return {"kind": "computed_reg", "reg": cur, "via": mnem}
            # PLA pulled `cur` (=A) off the stack — trace it to the
            # matching PHA's pushed value via stack-depth balancing.
            if mnem == "PLA" and cur == "A":
                return _resolve_pla_source(pc, mem, instr_at, graph, depth + 1)
            return {"kind": "unknown", "reason": f"clobber_{mnem.lower()}"}

        if _is_neutral(mnem, mode, cur):
            new_preds = _preds_of(pc, graph, instr_at)
            if not new_preds:
                # Walked off the front of this function. Register's
                # value came from the caller on this path.
                sources.add(("caller", cur, transform))
                continue
            for p in new_preds:
                if p == pc:
                    continue  # self-loop guard
                frontier.append((p, transform, cur))
            continue

        # Reaching a JSR while walking back `cur` means nothing wrote the
        # register between the call and the setter, so the tested value is
        # `cur` as the callee left it — name it `<callee>->reg`. Honest
        # regardless of the callee's return convention (it's the register
        # state right after the call). Targets without a label render as
        # bare hex and are dropped by the condition de-bouncer.
        if mnem == "JSR" and n == 3:
            tgt = mem[pc + 1] | (mem[pc + 2] << 8)
            return {"kind": "jsr_return", "target": tgt, "reg": cur}

        return {"kind": "unknown", "reason": f"unmodeled_{mnem.lower()}"}

    if not sources:
        return {"kind": "unknown", "reason": "no_source"}

    # Deduplicate. All sources must agree on (kind, address-or-value,
    # index) to count as a single resolved source; transforms are
    # union-ed (single-distinct only).
    keys = {_source_key(s) for s in sources}
    if len(keys) > 1:
        return {
            "kind": "multi_source",
            "count": len(sources),
            "sources": [_format_source(s) for s in sorted(sources)],
        }
    transforms = {s[-1] for s in sources}
    transform_out = next(iter(transforms)) if len(transforms) == 1 else None
    return _format_resolved(next(iter(sources)), transform_out)


_MAX_PLA_DEPTH = 4


def _resolve_pla_source(
    pla_pc: int,
    mem: bytes,
    instr_at: dict[int, tuple[str, str, int]],
    graph,
    depth: int = 0,
) -> dict:
    """Resolve the value a ``PLA`` pulls by matching it to the ``PHA``
    that pushed it. Walks back over CFG edges tracking ``pending`` — the
    number of pulls still needing a matching push (a PLA/PLP seen going
    back adds one, a PHA/PHP removes one). When a PHA balances the stack
    (``pending`` hits 0) it pushed our value, so resolve A's source there.

    Conservative: a balancing PHP means the pull took a status byte (not a
    register) — unknown; TSX/TXS move the stack pointer directly —
    unknown; walking off the function front before balancing means the
    value came from the caller's stack — unknown. JSR/RTS are stack-
    neutral within a function (the callee balances its own frame). If
    multiple paths resolve to different sources, the result is unknown."""
    if depth > _MAX_PLA_DEPTH:
        return {"kind": "unknown", "reason": "pla_depth"}
    preds = _preds_of(pla_pc, graph, instr_at)
    if not preds:
        return {"kind": "unknown", "reason": "pla_from_caller"}
    visited: set[tuple[int, int]] = set()
    frontier: list[tuple[int, int]] = [(p, 1) for p in preds]
    results: list[dict] = []
    steps = 0
    while frontier:
        if steps >= _MAX_WALK_STEPS:
            return {"kind": "unknown", "reason": "pla_walk_limit"}
        steps += 1
        pc, pending = frontier.pop()
        if (pc, pending) in visited:
            continue
        visited.add((pc, pending))
        info = instr_at.get(pc)
        if info is None:
            return {"kind": "unknown", "reason": "pla_non_code"}
        mnem = info[0]
        if mnem in ("PLA", "PLP"):
            pending += 1
        elif mnem == "PHA":
            pending -= 1
            if pending == 0:
                results.append(_resolve_lhs(pc, "A", mem, instr_at, graph, depth + 1))
                continue
        elif mnem == "PHP":
            pending -= 1
            if pending == 0:
                return {"kind": "unknown", "reason": "pla_pulls_status"}
        elif mnem in ("TXS", "TSX"):
            return {"kind": "unknown", "reason": "pla_sp_moved"}
        nxt = _preds_of(pc, graph, instr_at)
        if not nxt:
            return {"kind": "unknown", "reason": "pla_from_caller"}
        for p in nxt:
            frontier.append((p, pending))
    if not results:
        return {"kind": "unknown", "reason": "pla_no_push"}
    keys = {_source_key_of_lhs(r) for r in results}
    if len(keys) > 1:
        return {"kind": "unknown", "reason": "pla_ambiguous"}
    return results[0]


def _source_key_of_lhs(lhs: dict) -> tuple:
    """Identity key for an already-formatted lhs dict, to test whether
    two PLA-source resolutions agree."""
    k = lhs.get("kind")
    if k == "var":
        return ("var", lhs.get("var_addr"), lhs.get("index"))
    if k == "imm":
        return ("imm", lhs.get("value"))
    if k == "var_indirect":
        return ("var_indirect", lhs.get("ptr_addr"), lhs.get("index"))
    if k == "computed_reg":
        return ("computed_reg", lhs.get("reg"), lhs.get("via"))
    if k == "from_caller":
        return ("from_caller", lhs.get("reg"))
    if k == "jsr_return":
        return ("jsr_return", lhs.get("target"), lhs.get("reg"))
    return ("unknown", lhs.get("reason"))


def _source_key(src: tuple) -> tuple:
    """Identity key for de-duplicating sources — drops the transform
    chain, since identical-key sources with different transforms still
    represent the same underlying variable."""
    tag = src[0]
    if tag == "var":
        return ("var", src[1], src[2])  # addr, index
    if tag == "var_indirect":
        return ("var_indirect", src[1], src[2])  # ptr_addr, index_reg
    if tag == "imm":
        return ("imm", src[1])
    if tag == "caller":
        return ("caller", src[1])
    return src


def _format_resolved(src: tuple, transform: tuple | None) -> dict:
    """Render a single canonical source for emission. The `transform`
    is the unanimous transform chain across whatever multiplicity of
    source records produced this key."""
    tag = src[0]
    if tag == "var":
        out: dict = {"kind": "var", "var_addr": src[1]}  # int; pretty-printed later
        if src[2] is not None:
            out["index"] = src[2]
        if transform:
            out["transform"] = _format_transform(transform)
        return out
    if tag == "var_indirect":
        out = {"kind": "var_indirect", "ptr_addr": src[1], "index": src[2]}
        if transform:
            out["transform"] = _format_transform(transform)
        return out
    if tag == "imm":
        out = {"kind": "imm", "value": src[1]}  # int; pretty-printed later
        if transform:
            out["transform"] = _format_transform(transform)
        return out
    if tag == "caller":
        out = {"kind": "from_caller", "reg": src[1]}
        if transform:
            out["transform"] = _format_transform(transform)
        return out
    return {"kind": "unknown", "reason": f"bad_source_tag_{tag}"}


def _format_transform(t: tuple) -> list[dict]:
    out = []
    for item in t:
        op = item[0]
        if len(item) >= 2:
            out.append({"op": op, "imm": f"${item[1]:02X}"})
        else:
            out.append({"op": op})
    return out


def _format_source(src: tuple) -> dict:
    """Render one source for the `multi_source` listing — keeps its
    own transform chain."""
    tag = src[0]
    if tag == "var":
        out: dict = {"kind": "var", "var_addr": f"${src[1]:04X}"}
        if src[2] is not None:
            out["index"] = src[2]
        if src[3]:
            out["transform"] = _format_transform(src[3])
        return out
    if tag == "var_indirect":
        out = {"kind": "var_indirect", "ptr_addr": f"${src[1]:02X}", "index": src[2]}
        if src[3]:
            out["transform"] = _format_transform(src[3])
        return out
    if tag == "imm":
        out = {"kind": "imm", "value": f"${src[1]:02X}"}
        if src[2]:
            out["transform"] = _format_transform(src[2])
        return out
    if tag == "caller":
        out = {"kind": "from_caller", "reg": src[1]}
        if src[2]:
            out["transform"] = _format_transform(src[2])
        return out
    return {"kind": "unknown"}


# ── Containing-block lookup ─────────────────────────────────────────


def _build_block_index(
    annotations: dict[int, dict], instr_at: dict[int, tuple[str, str, int]]
) -> tuple[list[int], dict[int, str]]:
    """Return ``(sorted_pcs, name_by_pc)`` over annotation entries that
    land on a known code-start AND carry a ``name``. Those are the
    de-facto function-entry blocks. Region-only entries (state vars)
    are filtered out — they aren't code blocks.

    The emitter will use ``bisect_right - 1`` to find the nearest
    preceding block for any PC."""
    name_by_pc: dict[int, str] = {}
    for addr, body in annotations.items():
        if addr not in instr_at:
            continue
        name = body.get("name")
        if isinstance(name, str) and name:
            name_by_pc[addr] = name
    return sorted(name_by_pc.keys()), name_by_pc


def _block_of(
    pc: int, sorted_pcs: list[int], name_by_pc: dict[int, str]
) -> dict | None:
    idx = bisect.bisect_right(sorted_pcs, pc) - 1
    if idx < 0:
        return None
    block_pc = sorted_pcs[idx]
    return {"pc": f"${block_pc:04X}", "name": name_by_pc[block_pc]}


# ── Top-level driver ────────────────────────────────────────────────


def collect_facts(
    mem: bytes,
    instr_at: dict[int, tuple[str, str, int]],
    graph,
    annotations: dict[int, dict],
) -> dict:
    """Return the cmp_facts table for every conditional branch in
    ``instr_at``. Each entry has the shape documented in the module
    docstring; ``stats`` summarises resolution outcomes."""
    sorted_pcs, name_by_pc = _build_block_index(annotations, instr_at)

    facts: dict[str, dict] = {}
    stats = {
        "branches": 0,
        "no_flag_setter": 0,
        "operand_based": 0,  # LDA/LDX/LDY/BIT/INC/DEC as setter — no walk needed
        "resolved_var": 0,
        "resolved_var_indirect": 0,
        "resolved_imm": 0,
        "transformed": 0,
        "from_caller": 0,
        "computed_reg": 0,  # ALU-computed register (ADC/SBC/ORA/EOR/AND)
        "jsr_return": 0,  # register as a callee left it (`<fn>->reg`)
        "multi_source": 0,
        "unknown": 0,
    }

    for pc in sorted(instr_at.keys()):
        mnem, mode, n = instr_at[pc]
        if mnem not in _BRANCHES:
            continue
        stats["branches"] += 1

        # Resolve taken-target via the relative offset.
        if mode == "rel" and n == 2:
            off = mem[pc + 1]
            if off >= 0x80:
                off -= 256
            taken = (pc + 2 + off) & 0xFFFF
        else:
            taken = None
        fall_through = pc + 2  # all conditional branches are 2 bytes

        setter_pc = _find_flag_setter(pc, mnem, graph, instr_at)
        if setter_pc is None:
            stats["no_flag_setter"] += 1
            facts[f"${pc:04X}"] = {
                "branch": mnem,
                "taken_target": f"${taken:04X}" if taken is not None else None,
                "fall_through": f"${fall_through:04X}",
                "flag_setter": None,
                "lhs": {"kind": "unknown", "reason": "no_flag_setter"},
                "rhs": None,
                "containing_block": _block_of(pc, sorted_pcs, name_by_pc),
            }
            continue

        s_mnem, s_mode, s_n = instr_at[setter_pc]
        s_p1 = mem[setter_pc + 1] if s_n >= 2 else 0

        flag_setter_rec: dict = {
            "pc": f"${setter_pc:04X}",
            "mnem": s_mnem,
            "mode": s_mode,
        }
        if s_mode == "imm":
            flag_setter_rec["imm"] = f"${s_p1:02X}"
        elif s_mode in ("abs", "zp", "abx", "aby", "zpx", "zpy"):
            saddr = _operand_addr(mem, setter_pc, s_mode, s_n)
            if saddr is not None:
                flag_setter_rec["addr"] = f"${saddr:04X}"

        # Undocumented ALU setters compute the tested register from A/X +
        # an immediate (ANC/ALR/ARR -> A, AXS -> X); the result, not the
        # operand, is what the branch tests, so surface it as a computed
        # register (like ADC/AND reached in a walk).
        if s_mnem in ("ANC", "ALR", "ARR", "AXS"):
            reg = "X" if s_mnem == "AXS" else "A"
            facts[f"${pc:04X}"] = {
                "branch": mnem,
                "taken_target": f"${taken:04X}" if taken is not None else None,
                "fall_through": f"${fall_through:04X}",
                "flag_setter": flag_setter_rec,
                "lhs": {"kind": "computed_reg", "reg": reg, "via": s_mnem},
                "rhs": None,
                "containing_block": _block_of(pc, sorted_pcs, name_by_pc),
            }
            stats["computed_reg"] += 1
            continue

        # JSR as the setter: nothing after the call touched the flag, so
        # the branch tests the flag as the callee left it on return.
        if s_mnem == "JSR" and s_n == 3:
            tgt = mem[setter_pc + 1] | (mem[setter_pc + 2] << 8)
            flag = _BRANCH_FLAG[mnem]
            facts[f"${pc:04X}"] = {
                "branch": mnem,
                "taken_target": f"${taken:04X}" if taken is not None else None,
                "fall_through": f"${fall_through:04X}",
                "flag_setter": flag_setter_rec,
                "lhs": {"kind": "jsr_flag", "target": f"${tgt:04X}", "flag": flag},
                "rhs": None,
                "containing_block": _block_of(pc, sorted_pcs, name_by_pc),
            }
            stats["jsr_flag"] = stats.get("jsr_flag", 0) + 1
            continue

        # PLA as the direct setter: the branch tests the byte pulled off
        # the stack (vs zero / bit 7). Trace it to its matching PHA.
        if s_mnem == "PLA":
            lhs = _resolve_pla_source(setter_pc, mem, instr_at, graph)
            rhs = {"kind": "zero"}
            if lhs["kind"] in ("var", "imm", "var_indirect"):
                stats["operand_based"] += 1
            else:
                stats["unknown"] += 1
            facts[f"${pc:04X}"] = {
                "branch": mnem,
                "taken_target": f"${taken:04X}" if taken is not None else None,
                "fall_through": f"${fall_through:04X}",
                "flag_setter": flag_setter_rec,
                "lhs": lhs,
                "rhs": rhs,
                "containing_block": _block_of(pc, sorted_pcs, name_by_pc),
            }
            continue

        reg_info = _reg_for_setter(s_mnem, s_mode)

        # Operand-based setters: the value being tested IS the setter's
        # operand. No backward walk needed.
        if reg_info is None:
            lhs = _lhs_from_operand_setter(setter_pc, s_mnem, s_mode, s_n, mem)
            rhs = _rhs_zero_or_none(s_mnem)
            if lhs["kind"] in ("var", "imm"):
                stats["operand_based"] += 1
            elif lhs["kind"] == "var_indirect":
                stats["resolved_var_indirect"] += 1
            else:
                stats["unknown"] += 1
            facts[f"${pc:04X}"] = {
                "branch": mnem,
                "taken_target": f"${taken:04X}" if taken is not None else None,
                "fall_through": f"${fall_through:04X}",
                "flag_setter": flag_setter_rec,
                "lhs": lhs,
                "rhs": rhs,
                "containing_block": _block_of(pc, sorted_pcs, name_by_pc),
            }
            continue

        reg, post_op = reg_info

        # Register-consuming setter — walk back to its load.
        lhs = _resolve_lhs(setter_pc, reg, mem, instr_at, graph)
        rhs = _rhs_from_register_setter(s_mnem, s_mode, s_n, setter_pc, mem)

        # If the setter itself transforms the tested value (e.g. INX, or
        # acc-mode ASL), record the post-op on the lhs so the renderer
        # can surface it as (X + 1), shifted-A bit 7, etc.
        if post_op is not None and lhs["kind"] in (
            "var",
            "imm",
            "from_caller",
            "computed_reg",
            "jsr_return",
        ):
            lhs = dict(lhs)
            lhs["post_op"] = post_op

        # Stat bookkeeping.
        if lhs["kind"] == "var":
            if lhs.get("transform"):
                stats["transformed"] += 1
            else:
                stats["resolved_var"] += 1
        elif lhs["kind"] == "var_indirect":
            stats["resolved_var_indirect"] += 1
        elif lhs["kind"] == "imm":
            stats["resolved_imm"] += 1
        elif lhs["kind"] == "from_caller":
            stats["from_caller"] += 1
        elif lhs["kind"] == "computed_reg":
            stats["computed_reg"] += 1
        elif lhs["kind"] == "jsr_return":
            stats["jsr_return"] += 1
        elif lhs["kind"] == "multi_source":
            stats["multi_source"] += 1
        else:
            stats["unknown"] += 1

        # Pretty-print integer fields.
        if lhs["kind"] == "var" and isinstance(lhs.get("var_addr"), int):
            lhs = dict(lhs)
            lhs["var_addr"] = f"${lhs['var_addr']:04X}"
        if lhs["kind"] == "var_indirect" and isinstance(lhs.get("ptr_addr"), int):
            lhs = dict(lhs)
            lhs["ptr_addr"] = f"${lhs['ptr_addr']:02X}"
        if lhs["kind"] == "imm" and isinstance(lhs.get("value"), int):
            lhs = dict(lhs)
            lhs["value"] = f"${lhs['value']:02X}"
        if lhs["kind"] == "jsr_return" and isinstance(lhs.get("target"), int):
            lhs = dict(lhs)
            lhs["target"] = f"${lhs['target']:04X}"

        facts[f"${pc:04X}"] = {
            "branch": mnem,
            "taken_target": f"${taken:04X}" if taken is not None else None,
            "fall_through": f"${fall_through:04X}",
            "flag_setter": flag_setter_rec,
            "consumed_register": reg,
            "lhs": lhs,
            "rhs": rhs,
            "containing_block": _block_of(pc, sorted_pcs, name_by_pc),
        }

    return {"stats": stats, "facts": facts}


def _lhs_from_operand_setter(
    setter_pc: int, mnem: str, mode: str, n: int, mem: bytes
) -> dict:
    """LHS for setters whose operand IS the tested value: standalone
    LDA/LDX/LDY (the loaded value is the test), BIT, INC/DEC mem.
    """
    if mode == "imm":
        return {"kind": "imm", "value": f"${mem[setter_pc + 1]:02X}"}
    if mode in ("abs", "zp", "abx", "aby", "zpx", "zpy"):
        addr = _operand_addr(mem, setter_pc, mode, n)
        if addr is None:
            return {"kind": "unknown", "reason": "bad_setter_mode"}
        out: dict = {"kind": "var", "var_addr": f"${addr:04X}"}
        idx = _INDEXED.get(mode)
        if idx is not None:
            out["index"] = idx
        if mnem in ("INC", "DEC"):
            out["post_op"] = mnem  # the test is on var AFTER inc/dec
        return out
    if mode == "izy":
        # `LDA/LAX (zp),Y` flag-setter: the tested value is the byte at
        # the indirect pointer, same shape _resolve_lhs records when izy
        # appears in a walk-back. The operand byte is the zp pointer.
        ptr = mem[setter_pc + 1]
        return {"kind": "var_indirect", "ptr_addr": f"${ptr:02X}", "index": "Y"}
    if mnem == "PLA":
        # A pulled from the stack — genuinely unwalkable, not an
        # addressing-mode gap. Name the reason honestly.
        return {"kind": "unknown", "reason": "pla_from_stack"}
    return {"kind": "unknown", "reason": f"setter_mode_{mode}"}


def _rhs_zero_or_none(mnem: str) -> dict | None:
    """For LDA/LDX/LDY/BIT/INC/DEC operand-based setters: branch flags
    compare against zero (BEQ/BNE) or test bit 7 (BMI/BPL). The RHS is
    implicit-zero (or bit-7 for sign tests); we emit ``{"kind": "zero"}``
    and the renderer decides based on the branch."""
    if mnem in ("LDA", "LDX", "LDY", "INC", "DEC", "BIT", "LAX"):
        return {"kind": "zero"}
    return None


def _rhs_from_register_setter(
    mnem: str, mode: str, n: int, setter_pc: int, mem: bytes
) -> dict | None:
    """RHS for CMP/CPX/CPY/AND/ORA/EOR/ADC/SBC followed by branch. The
    setter's operand IS the RHS for CMP/CPX/CPY; for arithmetic / bitwise
    setters the branch tests the transformed value against zero (or
    bit 7), so RHS is implicit zero."""
    if mnem in ("CMP", "CPX", "CPY"):
        if mode == "imm":
            return {"kind": "imm", "value": f"${mem[setter_pc + 1]:02X}"}
        if mode in ("abs", "zp", "abx", "aby", "zpx", "zpy"):
            addr = _operand_addr(mem, setter_pc, mode, n)
            if addr is None:
                return None
            out: dict = {"kind": "var", "var_addr": f"${addr:04X}"}
            idx = _INDEXED.get(mode)
            if idx is not None:
                out["index"] = idx
            return out
        return None
    # AND/ORA/EOR/ADC/SBC fall through to branch — implicit zero test.
    return {"kind": "zero"}


# ── CLI ─────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--bin", type=Path, default=STATIC_BIN)
    ap.add_argument("--entrypoints", type=Path, default=ENTRYPOINTS)
    ap.add_argument("--annotations", type=Path, default=ANNOTATIONS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
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
    rs_seeds = default_seeds(annotations)
    graph = build_callgraph(mem, code_starts, consumed, seeds=rs_seeds)

    result = collect_facts(mem, instr_at, graph, annotations)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2))

    stats = result["stats"]
    print(f"cmp_facts: wrote {args.out}")
    for key in (
        "branches",
        "no_flag_setter",
        "operand_based",
        "resolved_var",
        "resolved_var_indirect",
        "resolved_imm",
        "transformed",
        "from_caller",
        "computed_reg",
        "jsr_return",
        "multi_source",
        "unknown",
    ):
        print(f"  {key:<22} = {stats[key]}")
    resolved = (
        stats["operand_based"]
        + stats["resolved_var"]
        + stats["resolved_var_indirect"]
        + stats["resolved_imm"]
        + stats["transformed"]
    )
    if stats["branches"]:
        pct = 100.0 * resolved / stats["branches"]
        print(f"  resolved (any kind)    = {resolved}  ({pct:.1f}%)")
        # from_caller + computed_reg are register-level lhs: not a named
        # variable, but the branch condition still surfaces the
        # comparison (`A < #imm?`) so they are genuine information.
        with_reg = (
            resolved
            + stats["from_caller"]
            + stats["computed_reg"]
            + stats["jsr_return"]
        )
        pct2 = 100.0 * with_reg / stats["branches"]
        print(f"  + register-level lhs   = {with_reg}  ({pct2:.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
