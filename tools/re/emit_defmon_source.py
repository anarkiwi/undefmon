"""Emit a 64tass-assemblable .s file for the defMON static image.

Pass-1 strategy:
  - Code-start oracle = PCs from `trace/entrypoints.json` (every PC the CPU
    actually executed across the 9-tune × 14-phase sweep).
  - From each code start, decode one instruction; mark its operand bytes
    as consumed.
  - Emit disassembled instruction lines in 64tass syntax (`@b`/`@w`
    forcing to keep the assembler from picking a different addressing
    mode than the original bytes).
  - For any byte not an instruction start and not consumed as an operand,
    emit `.byte`.
  - All addressing-mode forcing is eager; the round-trip check
    (`tools/re/roundtrip_check.py`) is the authoritative pass/fail.

Pass-2 will layer Ghidra labels + data-segment hints on top without
changing emitted bytes.

Usage:
    python3 -m tools.re.emit_defmon_source \\
        --bin artefacts/defmon-static.bin \\
        --entrypoints trace/entrypoints.json \\
        --out tools/re/defmon.s
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import tomllib
from collections.abc import Callable
from pathlib import Path

from tools.re.dasm6502 import (
    OPS,
    ROUND_TRIP_UNSAFE_OPCODES,
    emit_64tass_instruction,
)


# ── Branch condition rendering ──────────────────────────────────────────
# Whether a given instruction is a conditional branch — used both at
# emit time (to decide whether to look for a cmp_facts entry) and
# inside the rendering helpers below.

_BRANCH_FLAG = {
    "beq": "Z", "bne": "Z",
    "bmi": "N", "bpl": "N",
    "bcs": "C", "bcc": "C",
    "bvs": "V", "bvc": "V",
}



# ── Fact-driven condition rendering ────────────────────────────────────
# `render_condition_from_fact` consumes a record from `build/cmp_facts.json`
# (produced by `tools/re/cmp_facts.py`) and returns a human-readable
# condition string. The fact already encodes the CFG-walked source
# (variable / indirect-pointer / immediate / caller-supplied) plus any
# transform chain, so this function is a pure formatter — no walker.
#
# Returning None tells the caller "skip the comment entirely" (lhs was
# unknown or multi_source).

_CMP_PREDICATE = {
    "BEQ": "{lhs} was {rhs}?",
    "BNE": "{lhs} was not {rhs}?",
    "BCC": "{lhs} was below {rhs}?",
    "BCS": "{lhs} was {rhs} or above?",
    "BMI": "{lhs} − {rhs} had bit 7 set?",
    "BPL": "{lhs} − {rhs} had bit 7 clear?",
}

# Past-tense readable prose. The 6502 BMI/BPL test bit 7 of the result
# of the most recent flag-setting op, which on an 8-bit value IS the
# sign bit — "had bit 7 set?" reads more directly than "was negative?"
# (the value might be a bitmask, not a number). EOL comments are the
# only place these phrases appear; branch operands themselves render
# as the canonical target label (or `<region> + $offset` fallback) so
# the reader sees WHERE control goes in the operand and WHY in the
# comment.
_ZERO_PREDICATE = {
    "BEQ": "{expr} was zero?",
    "BNE": "{expr} was non-zero?",
    "BMI": "{expr} had bit 7 set?",
    "BPL": "{expr} had bit 7 clear?",
    # acc-mode shift then BCC/BCS — carry holds the shifted-out bit.
    "BCS": "{expr} shifted-out bit was 1?",
    "BCC": "{expr} shifted-out bit was 0?",
}

_BIT_PREDICATE = {
    "BEQ": "A & {expr} was zero?",
    "BNE": "A & {expr} was non-zero?",
    "BMI": "{expr} had bit 7 set?",
    "BPL": "{expr} had bit 7 clear?",
    "BVS": "{expr} had bit 6 set?",
    "BVC": "{expr} had bit 6 clear?",
}

_SETTER_INFIX = {"AND": "&", "ORA": "|", "EOR": "^", "ADC": "+", "SBC": "−"}

_TRANSFORM_WRAPPERS = {
    "AND": lambda e, t: f"({e} & {t['imm']})",
    "ORA": lambda e, t: f"({e} | {t['imm']})",
    "EOR": lambda e, t: f"({e} ^ {t['imm']})",
    "INX": lambda e, _t: f"({e} + 1)",
    "INY": lambda e, _t: f"({e} + 1)",
    "DEX": lambda e, _t: f"({e} − 1)",
    "DEY": lambda e, _t: f"({e} − 1)",
    "ASL": lambda e, _t: f"({e} << 1)",
    "LSR": lambda e, _t: f"({e} >> 1)",
    "ROL": lambda e, _t: f"rol({e})",
    "ROR": lambda e, _t: f"ror({e})",
    # Register-transfer transforms are identity for the value being
    # tracked — going backwards through TXA tells us A came from X,
    # but the VALUE wasn't changed. No visible wrapping.
    "TXA": lambda e, _t: e,
    "TYA": lambda e, _t: e,
    "TAX": lambda e, _t: e,
    "TAY": lambda e, _t: e,
}

_POST_OP_WRAPPERS = {
    "INC": lambda e: f"({e} + 1)",
    "DEC": lambda e: f"({e} − 1)",
    "ASL": lambda e: f"({e} << 1)",
    "LSR": lambda e: f"({e} >> 1)",
    "ROL": lambda e: f"rol({e})",
    "ROR": lambda e: f"ror({e})",
}


def _parse_hex_addr(text: str) -> int | None:
    try:
        return int(text.lstrip("$"), 16)
    except (ValueError, AttributeError):
        return None


# Inverse pairs of transform ops. When two of these appear adjacent in
# the transform chain, both cancel and can be dropped — the CFG walker
# emits them when an inner-loop body decrements then increments (or
# vice versa) the index register used to read a byte, but for the
# purposes of the value tested by the branch the round-trip is a no-op.
# Reported by the 2026-05-17 awful-label survey: 43 of 113 long labels
# are `_minus_1_plus_1` instances of this exact pattern.
_INVERSE_OP_PAIRS = frozenset({
    ("DEX", "INX"), ("INX", "DEX"),
    ("DEY", "INY"), ("INY", "DEY"),
})


def _fold_transform_chain(transform: list[dict]) -> list[dict]:
    """Cancel adjacent inverse-pair ops in a transform list. Iterates
    until no more cancellations apply. Operates on a copy; input is
    untouched."""
    out = list(transform)
    while True:
        for i in range(len(out) - 1):
            pair = (out[i].get("op", ""), out[i + 1].get("op", ""))
            if pair in _INVERSE_OP_PAIRS:
                del out[i:i + 2]
                break
        else:
            return out


def _name_for_address(addr: int,
                      labels: dict[int, str],
                      block_pcs_sorted: list[int] | None,
                      block_name_by_pc: dict[int, str] | None,
                      ) -> str:
    """Render an address for inclusion in a condition string.

    Preference order:
      1. Direct label (``labels[addr]``) — the symbolic name.
      2. ``<block_name>_$<offset_hex>`` when ``addr`` falls inside a
         known function block. Tells the reader WHERE the SMC slot
         lives instead of leaving a meaningless ``$XXXX``.
      3. Raw ``$XXXX`` — last-resort fallback.
    """
    if addr in labels:
        return labels[addr]
    if block_pcs_sorted and block_name_by_pc:
        block_pc = _nearest_block_pc(addr, block_pcs_sorted)
        if block_pc is not None and block_pc in block_name_by_pc:
            offset = addr - block_pc
            return f"{block_name_by_pc[block_pc]}_${offset:X}"
    return f"${addr:04X}"


def _render_lhs_expr(lhs: dict,
                     labels: dict[int, str],
                     block_pcs_sorted: list[int] | None = None,
                     block_name_by_pc: dict[int, str] | None = None,
                     apply_transforms: bool = True,
                     ) -> str | None:
    """Render the lhs side of a fact-derived condition.

    Returns the expression (with any transform chain + setter post-op
    already wrapped around the source), or None for unknown / unrenderable
    lhs kinds.

    Set ``apply_transforms=False`` to get JUST the source rendering
    (variable name + optional index), without the +1/-1/shift wrappers.
    Used by idiom-template renderers that want to describe the whole
    transform chain semantically rather than one op at a time.
    """
    kind = lhs.get("kind")
    if kind == "var":
        addr = _parse_hex_addr(lhs.get("var_addr", ""))
        if addr is None:
            return None
        expr = _name_for_address(addr, labels, block_pcs_sorted,
                                 block_name_by_pc)
        if lhs.get("index"):
            expr = f"{expr},{lhs['index']}"
    elif kind == "var_indirect":
        addr = _parse_hex_addr(lhs.get("ptr_addr", ""))
        if addr is None:
            return None
        ptr_name = _name_for_address(addr, labels, block_pcs_sorted,
                                     block_name_by_pc)
        expr = f"({ptr_name}),{lhs.get('index', 'Y')}"
    elif kind == "imm":
        # Constant lhs — usually SMC patch slots (`lda #$FF` before
        # the operand byte gets overwritten). The static value isn't
        # informative as a condition; render but the caller's label
        # de-bouncer will likely reject this via `_COND_BARE_HEX_RE`.
        expr = lhs.get("value", "?")
    elif kind == "from_caller":
        # Register parameter from caller. Bare register letter is the
        # honest rendering — we don't know what the caller loaded.
        expr = lhs.get("reg", "?")
    elif kind == "computed_reg":
        # Register holds a value computed in-function by an ALU op
        # (ADC/SBC/ORA/EOR/AND) we can't name. The register letter is
        # the honest lhs — the condition still surfaces the comparison
        # (e.g. `A < #$XX?`) even though the operand isn't a variable.
        expr = lhs.get("reg", "?")
    elif kind == "jsr_return":
        # Register as the callee left it: render `<callee>->reg`. If the
        # target has no label it resolves to bare hex and the condition
        # de-bouncer drops it, so unnamed callees stay uncommented.
        addr = _parse_hex_addr(lhs.get("target", ""))
        if addr is None:
            return None
        fn = _name_for_address(addr, labels, block_pcs_sorted, block_name_by_pc)
        expr = f"{fn}->{lhs.get('reg', 'A')}"
    else:
        return None

    if not apply_transforms:
        return expr

    for t in _fold_transform_chain(lhs.get("transform") or []):
        wrap = _TRANSFORM_WRAPPERS.get(t.get("op", ""))
        if wrap is None:
            return None  # unrecognised transform — bail safely
        expr = wrap(expr, t)

    post = lhs.get("post_op")
    if post is not None:
        wrap_post = _POST_OP_WRAPPERS.get(post)
        if wrap_post is not None:
            expr = wrap_post(expr)
    return expr


_STEP_UP_OPS = frozenset({"INX", "INY", "INC"})
_STEP_DOWN_OPS = frozenset({"DEX", "DEY", "DEC"})

# All 2-byte imm-mode 6502 mnemonics. The emit loop uses this to gate
# the "SMC operand" EOL comment: any imm whose operand byte at pc+1
# has an exact label gets `← <slot_name>` appended (the operand is
# patched at runtime by an SMC writer elsewhere in the image, so the
# static `#$XX` value is only the initial state).
_IMM_2BYTE_OPS = frozenset({
    "lda", "ldx", "ldy",
    "cmp", "cpx", "cpy",
    "adc", "sbc",
    "and", "ora", "eor",
})


def _detect_step_idiom(lhs: dict, branch: str, rhs: dict
                       ) -> tuple[int, str, str] | None:
    """Recognise the `(INX/INY/INC)×N + BPL/BMI on lhs-zero` pattern
    (and its symmetric DEX/DEY/DEC sibling) as a single compound idiom.

    Returns ``(step_count, direction_word, predicate_word)`` when the
    pattern matches:
      * ``direction_word`` is ``"step"`` for incremental, ``"back"``
        for decremental.
      * ``predicate_word`` is ``"pos"`` (BPL) or ``"neg"`` (BMI).
    Returns ``None`` when the chain has any non-increment op, mixes
    directions, or the branch/rhs don't match the idiom shape.

    The chain is folded before counting so that ``[INX, DEX, INX]``
    collapses to ``[INX]`` (1 step up) rather than failing the
    uniformity guard.
    """
    if branch not in ("BPL", "BMI"):
        return None
    if rhs.get("kind") != "zero":
        return None
    transforms = _fold_transform_chain(lhs.get("transform") or [])
    ops: list[str] = [t.get("op", "") for t in transforms]
    post = lhs.get("post_op")
    if post:
        ops.append(post)
    if not ops:
        return None
    if all(o in _STEP_UP_OPS for o in ops):
        return (len(ops),
                "stepped",
                "had bit 7 clear?" if branch == "BPL" else "had bit 7 set?")
    if all(o in _STEP_DOWN_OPS for o in ops):
        return (len(ops),
                "walked back",
                "had bit 7 clear?" if branch == "BPL" else "had bit 7 set?")
    return None


_STEP_IDIOM_SEMANTICS: dict[tuple[str, str], str] = {
    ("BPL", "pos"): 'BPL "pos" (high bit clear, ≈ "value < $80")',
    ("BMI", "neg"): 'BMI "neg" (high bit set, ≈ "value ≥ $80")',
}


def _emit_step_idiom_comment(
    fact: dict,
    labels: dict[int, str],
    block_pcs_sorted: list[int] | None,
    block_name_by_pc: dict[int, str] | None,
    step_info: tuple[int, str, str],
) -> str:
    """Multi-line pre-instruction comment that lays out the step-idiom
    structure vertically — source, advance count + ops, branch test —
    so the reader sees the compound shape side-by-side rather than
    parsing the slug. See the architecture-overview "BRANCH-CONDITION
    CONVENTIONS" section for the full template explanation.
    """
    count, direction, _predicate = step_info
    lhs = fact.get("lhs") or {}
    branch = fact.get("branch", "")
    rhs = fact.get("rhs") or {}
    source = _render_lhs_expr(lhs, labels, block_pcs_sorted,
                              block_name_by_pc,
                              apply_transforms=False) or "?"
    # Cite the raw $XXXX only when the rendered source isn't already
    # one (i.e. when we used the block_name+offset path or a label) —
    # avoids redundant "(= $891A)" after `${891A}` already showed.
    addr = _parse_hex_addr(lhs.get("var_addr") or lhs.get("ptr_addr", "")) \
        if lhs.get("kind") in ("var", "var_indirect") else None
    addr_suffix = ""
    if addr is not None and f"${addr:04X}" not in source:
        addr_suffix = f"  (= ${addr:04X})"
    ops_text = "INX/INY/INC" if direction == "step" else "DEX/DEY/DEC"
    direction_verb = "advanced" if direction == "step" else "decremented"
    setter = fact.get("flag_setter") or {}
    last_step_pc = _parse_hex_addr(setter.get("pc") or "")
    last_step_text = (f"; final step @ ${last_step_pc:04X}"
                      if last_step_pc is not None else "")
    predicate_key = (branch, _predicate)
    semantic = _STEP_IDIOM_SEMANTICS.get(
        predicate_key, f'{branch} "{_predicate}"')
    rhs_note = ""
    if rhs.get("kind") != "zero":
        rhs_note = f" (rhs={rhs.get('kind')})"
    return (
        f";   step-idiom: source = {source}{addr_suffix}\n"
        f";               {direction_verb} {count}× via {ops_text}"
        f"     {last_step_text}\n"
        f";               test     = {semantic}{rhs_note}\n"
    )


def _render_rhs_text(rhs: dict, lhs: dict,
                     value_names_per_var: dict[int, dict[int, str]],
                     labels: dict[int, str],
                     block_pcs_sorted: list[int] | None = None,
                     block_name_by_pc: dict[int, str] | None = None,
                     ) -> str | None:
    """Render the rhs of a fact-derived condition. Looks up the
    immediate against the lhs variable's `value_names` so a literal
    `$01` becomes `UI_MODE_SEQED` when comparing `ui_mode`."""
    kind = rhs.get("kind")
    if kind == "imm":
        value = _parse_hex_addr(rhs.get("value", ""))
        if (value is not None and lhs.get("kind") == "var"
                and not lhs.get("transform")):
            lhs_addr = _parse_hex_addr(lhs.get("var_addr", ""))
            if lhs_addr is not None:
                names = value_names_per_var.get(lhs_addr, {})
                if value in names:
                    return names[value]
        return rhs.get("value", "?")
    if kind == "var":
        addr = _parse_hex_addr(rhs.get("var_addr", ""))
        if addr is None:
            return rhs.get("var_addr", "?")
        expr = _name_for_address(addr, labels, block_pcs_sorted,
                                 block_name_by_pc)
        if rhs.get("index"):
            expr = f"{expr},{rhs['index']}"
        return expr
    return None


# Setter-centric semantic templates. For arithmetic/bitwise flag-setters
# whose operand is a named variable, the BRANCH is best described as
# something happening to THAT operand, not as a math expression rooted
# at the (often constant or accumulator-derived) lhs. Otherwise the
# walker emits chains like `((($01 + 1) + 1) + 1) + v0_freq_lookup_smc`
# where the only thing the reader needs to recognise is the trailing
# `v0_freq_lookup_smc`. The templates below collapse that to the
# semantic event the carry/zero bit actually witnesses.
_SEMANTIC_BY_SETTER: dict[tuple[str, str], str] = {
    ("ADC", "BCC"): "{var} no carry",
    ("ADC", "BCS"): "{var} carry",
    ("SBC", "BCC"): "{var} borrow",
    ("SBC", "BCS"): "{var} no borrow",
    ("AND", "BEQ"): "A & {var} == 0",
    ("AND", "BNE"): "A & {var} ≠ 0",
    ("EOR", "BEQ"): "A == {var}",
    ("EOR", "BNE"): "A ≠ {var}",
}


def _render_setter_centric_condition(
    branch: str,
    setter: dict,
    labels: dict[int, str],
) -> str | None:
    """When the flag-setter is one of the templates in
    `_SEMANTIC_BY_SETTER` AND its operand resolves to a named address,
    render the test using the operand as the semantic anchor. Returns
    None for unsupported (setter.mnem, branch) pairs or for setters
    whose operand is unnamed — the caller then falls back to the
    lhs-rooted rendering."""
    mnem = setter.get("mnem")
    if not isinstance(mnem, str):
        return None
    template = _SEMANTIC_BY_SETTER.get((mnem, branch))
    if template is None:
        return None
    addr_text = setter.get("addr")
    if not isinstance(addr_text, str):
        return None
    addr = _parse_hex_addr(addr_text)
    if addr is None:
        return None
    var = labels.get(addr)
    if var is None:
        return None
    return template.format(var=var)


def _render_setter_operand(setter: dict,
                           labels: dict[int, str],
                           imm_subs: dict[int, str] | None = None) -> str | None:
    """For register-consuming arithmetic/bitwise setters
    (AND/ORA/EOR/ADC/SBC), render the setter's own operand so the
    condition can read `(lhs OP setter_operand) <pred>`.

    ``imm_subs`` (optional) maps setter PCs whose IMM operand has been
    given a symbolic name (via `[imm."$XXXX"]` or value_names CFG
    inference) to that name. When present, the condition reads with
    the symbolic name instead of the raw hex byte."""
    if "imm" in setter:
        pc_text = setter.get("pc")
        if isinstance(pc_text, str) and imm_subs:
            pc = _parse_hex_addr(pc_text)
            if pc is not None and pc in imm_subs:
                return imm_subs[pc]
        return setter["imm"]
    addr_text = setter.get("addr")
    if addr_text is None:
        return None
    addr = _parse_hex_addr(addr_text)
    if addr is None:
        return addr_text
    return labels.get(addr, addr_text)


def render_condition_from_fact(
    fact: dict | None,
    labels: dict[int, str],
    value_names_per_var: dict[int, dict[int, str]] | None = None,
    imm_subs: dict[int, str] | None = None,
    block_pcs_sorted: list[int] | None = None,
    block_name_by_pc: dict[int, str] | None = None,
    reg_inputs_per_fn: dict[int, dict[str, int]] | None = None,
) -> str | None:
    """Pure formatter: take a cmp_facts record + label/value-name
    tables, return the condition string for the branch.

    Returns None when no informative rendering is possible (unknown
    lhs, multi_source, unrecognised transform op). Callers should
    skip emitting a postfix comment in that case.

    When ``block_pcs_sorted`` + ``block_name_by_pc`` are supplied,
    var/var_indirect addresses without a direct label fall back to
    ``<containing_block_name>_$<offset>`` rather than raw ``$XXXX``.
    Tells the reader WHERE in the program the SMC slot lives.
    """
    if not fact:
        return None
    branch_raw = fact.get("branch")
    if not isinstance(branch_raw, str):
        return None
    branch: str = branch_raw
    lhs = fact.get("lhs") or {}
    rhs = fact.get("rhs") or {}
    setter = fact.get("flag_setter") or {}
    value_names_per_var = value_names_per_var or {}

    if lhs.get("kind") in ("unknown", "multi_source", None):
        return None

    # SMC-immediate pivot: when lhs reduces to a literal constant
    # (e.g. `lda #$00`), the test is not really against the constant
    # — it's against the LDA's operand byte, which in defMON is
    # almost always self-modified at runtime (the busy-wait barrier
    # at editor_frame_barrier is the canonical example). Rewrite lhs
    # to a synthetic var pointing at the operand-byte address so the
    # predicate reads as "<region + $offset> was zero?" instead of
    # the meaningless "$00 was zero?".
    if (lhs.get("kind") == "imm"
            and setter.get("mnem") in ("LDA", "LDX", "LDY")
            and setter.get("imm") is not None):
        setter_pc = _parse_hex_addr(setter.get("pc", ""))
        if setter_pc is not None:
            lhs = {"kind": "var", "var_addr": f"${setter_pc + 1:04X}"}

    # from_caller pivot: when lhs is a bare register that came from
    # the JSR caller (cmp_facts couldn't trace it across the call),
    # and the containing function block declares register_inputs
    # binding that register to an enum-var, rewrite lhs to point at
    # that var. Lets `cpy #KEY_LEFTARROW` followed by `bne` render as
    # `kbd_decoded_key was not KEY_LEFTARROW?` instead of
    # `Y was not $1F?` — the rhs gets value_names substitution and
    # the lhs reads as the source variable rather than the register.
    if (lhs.get("kind") == "from_caller"
            and reg_inputs_per_fn is not None):
        reg_key = (lhs.get("reg") or "").lower()
        block = fact.get("containing_block") or {}
        block_pc = _parse_hex_addr(block.get("pc", ""))
        if block_pc is not None and reg_key in ("a", "x", "y"):
            seeds = reg_inputs_per_fn.get(block_pc, {})
            var_addr = seeds.get(reg_key)
            if var_addr is not None:
                lhs = {"kind": "var", "var_addr": f"${var_addr:04X}"}

    # Step-idiom: collapse a uniform +1 or -1 chain + BPL/BMI on
    # lhs-zero into a single semantic phrase. Fires only when the chain
    # is exclusively INX/INY/INC (up) or exclusively DEX/DEY/DEC (down)
    # — heterogeneous chains keep the literal +1/-1 transcription.
    step_info = _detect_step_idiom(lhs, branch, rhs)
    if step_info is not None:
        count, direction, predicate = step_info
        source_expr = _render_lhs_expr(
            lhs, labels, block_pcs_sorted, block_name_by_pc,
            apply_transforms=False)
        if source_expr is not None:
            return f"{source_expr} {direction} {count} and {predicate}"

    expr = _render_lhs_expr(lhs, labels, block_pcs_sorted, block_name_by_pc)
    if expr is None:
        return None

    # Register-consuming arithmetic / bitwise setter: the tested value
    # is (lhs OP setter_operand). Wrap before the predicate selection.
    s_mnem_raw = setter.get("mnem")
    s_mnem: str | None = s_mnem_raw if isinstance(s_mnem_raw, str) else None
    if s_mnem is not None and s_mnem in _SETTER_INFIX:
        s_op = _render_setter_operand(setter, labels, imm_subs)
        if s_op is not None:
            expr = f"({expr} {_SETTER_INFIX[s_mnem]} {s_op})"

    # BIT mem followed by branch: distinct predicate set (bit 6/7 of
    # the operand, or A & operand for Z).
    if s_mnem == "BIT":
        template = _BIT_PREDICATE.get(branch)
        if template is None:
            return None
        return template.format(expr=expr)

    # CMP/CPX/CPY → compare against rhs
    if rhs.get("kind") in ("imm", "var") and s_mnem in ("CMP", "CPX", "CPY"):
        rhs_text = _render_rhs_text(rhs, lhs, value_names_per_var, labels,
                                     block_pcs_sorted, block_name_by_pc)
        if rhs_text is None:
            return None
        template = _CMP_PREDICATE.get(branch)
        if template is None:
            return None
        return template.format(lhs=expr, rhs=rhs_text)

    # Setter-centric semantic rename: for arithmetic/bitwise flag-setters
    # whose operand is a named variable, describe the test in terms of
    # that variable (the carry/zero bit's actual semantic anchor)
    # instead of unspooling the lhs transform chain. Falls through to
    # the lhs-rooted zero-predicate path when no template matches or
    # the operand isn't named.
    semantic = _render_setter_centric_condition(branch, setter, labels)
    if semantic is not None:
        return semantic

    # Otherwise zero / bit 7 test on the (possibly transformed) lhs.
    # When the lhs is an untransformed enum-bound variable and the enum
    # names $00 (e.g. STEREO_OFF, PLAYBACK_OFF), substitute the named
    # constant into the BEQ/BNE templates so the comment reads
    # `stereo_enable was STEREO_OFF?` instead of `stereo_enable was zero?`.
    # The bit-7 (BMI/BPL) and shifted-out (BCS/BCC) variants stay as-is
    # — those test single bits, not value equality.
    if branch in ("BEQ", "BNE") and lhs.get("kind") == "var":
        lhs_addr = _parse_hex_addr(lhs.get("var_addr", ""))
        if lhs_addr is not None:
            zero_name = (value_names_per_var.get(lhs_addr, {}) or {}).get(0)
            if zero_name is not None and not lhs.get("transform") \
                    and not lhs.get("post_op"):
                phrase = (f"{expr} was {zero_name}?" if branch == "BEQ"
                          else f"{expr} was not {zero_name}?")
                return phrase
    template = _ZERO_PREDICATE.get(branch)
    if template is None:
        return None
    return template.format(expr=expr)


def _build_block_pc_index(
    annotations: dict[int, dict],
    instr_at: dict[int, tuple[str, str, int]],
) -> tuple[list[int], dict[int, str]]:
    """Sorted list of [function]-annotated code-start PCs + their names.
    Used to attribute any instruction PC to its enclosing block (via
    ``_nearest_block_pc``). Filters region-only entries — those are
    data addresses, not code blocks."""
    name_by_pc: dict[int, str] = {}
    for addr, body in annotations.items():
        if addr not in instr_at:
            continue
        name = body.get("name")
        if isinstance(name, str) and name:
            name_by_pc[addr] = name
    return sorted(name_by_pc.keys()), name_by_pc


def _nearest_block_pc(pc: int, sorted_block_pcs: list[int]) -> int | None:
    """Return the nearest block-entry PC ≤ ``pc``, or None when there
    is no preceding block (i.e. ``pc`` is before any [function])."""
    idx = bisect.bisect_right(sorted_block_pcs, pc) - 1
    if idx < 0:
        return None
    return sorted_block_pcs[idx]


_SWITCH_MIN_CASES = 3


def detect_switch_dispatchers(
    cmp_facts: dict[int, dict],
    labels: dict[int, str],
    value_names_per_var: dict[int, dict[int, str]] | None = None,
) -> dict[int, dict]:
    """Find CMP/branch cascades that act as switch statements.

    A switch is N≥3 consecutive cmp_facts entries (in PC order) where:
      * all branches are the SAME flavour (all BEQ or all BNE)
      * all share the same lhs (var_addr, no transform chain)
      * all have rhs.kind == "imm" with DISTINCT values

    Returns {first_cmp_pc: {var_name, var_addr, branch, cases:[…]}}.
    The first_cmp_pc is the setter PC of the first branch in the group
    (the `CMP #x1` instruction) — that's where the emitter renders the
    switch-block comment.

    Mixed BEQ/BNE cascades are skipped (rare and harder to model). Pure
    BNE cascades fall-through on match (the BEQ flavour is the opposite).
    """
    value_names_per_var = value_names_per_var or {}
    facts_in_order = sorted(cmp_facts.items())
    out: dict[int, dict] = {}
    n = len(facts_in_order)
    i = 0
    while i < n:
        # Start a candidate group at i.
        pc_i, f_i = facts_in_order[i]
        lhs_i = f_i.get("lhs") or {}
        rhs_i = f_i.get("rhs") or {}
        branch_i = f_i.get("branch", "")
        if (branch_i not in ("BEQ", "BNE")
                or lhs_i.get("kind") != "var"
                or lhs_i.get("transform")
                or rhs_i.get("kind") != "imm"):
            i += 1
            continue
        var_addr = _parse_hex_addr(lhs_i.get("var_addr", ""))
        if var_addr is None:
            i += 1
            continue
        # Greedily extend.
        cases: list[dict] = []
        seen_values: set[int] = set()
        j = i
        while j < n:
            pc_j, f_j = facts_in_order[j]
            lhs_j = f_j.get("lhs") or {}
            rhs_j = f_j.get("rhs") or {}
            br_j = f_j.get("branch", "")
            if (br_j != branch_i
                    or lhs_j.get("kind") != "var"
                    or lhs_j.get("transform")
                    or _parse_hex_addr(lhs_j.get("var_addr", "")) != var_addr
                    or rhs_j.get("kind") != "imm"):
                break
            val = _parse_hex_addr(rhs_j.get("value", ""))
            if val is None or val in seen_values:
                break
            taken = _parse_hex_addr(f_j.get("taken_target", ""))
            fall = _parse_hex_addr(f_j.get("fall_through", ""))
            # Case dispatch semantics differ by cascade flavour:
            #   BEQ cascade: case match TAKES the branch → handler is `taken`.
            #   BNE cascade: case match FALLS THROUGH    → handler is `fall`.
            handler_pc = taken if branch_i == "BEQ" else fall
            cases.append({
                "value": val,
                "branch_pc": pc_j,
                "handler_pc": handler_pc,
                "handler_label": labels.get(handler_pc) if handler_pc is not None else None,
            })
            seen_values.add(val)
            j += 1
        if len(cases) >= _SWITCH_MIN_CASES:
            first_setter = f_i.get("flag_setter", {}).get("pc")
            first_setter_pc = _parse_hex_addr(first_setter or "")
            var_name = labels.get(var_addr, f"${var_addr:04X}")
            value_names = value_names_per_var.get(var_addr, {})
            for c in cases:
                c["value_name"] = value_names.get(c["value"])
            # `default` arm: for BNE cascade, the path when no case matches
            # is the last branch's taken target. For BEQ, it's the last
            # branch's fall-through.
            last_pc, last_f = facts_in_order[j - 1]
            default_pc = _parse_hex_addr(
                last_f.get("taken_target", "")
                if branch_i == "BNE"
                else last_f.get("fall_through", ""))
            default_label = (labels.get(default_pc)
                             if default_pc is not None else None)
            anchor_pc = first_setter_pc if first_setter_pc is not None else pc_i
            out[anchor_pc] = {
                "var_addr": var_addr,
                "var_name": var_name,
                "branch": branch_i,
                "cases": cases,
                "default_pc": default_pc,
                "default_label": default_label,
            }
            i = j
        else:
            i += 1
    return out


# ── Enum-list rendering ─────────────────────────────────────────────────
# Several annotation fields are *de-facto* enums written as prose:
#   values = "$01 = seqED, $02 = seqLIST, $04 = sidTAB, $20 = secondary_disk_mode"
# `_parse_enum_list` recognises this shape (with an optional `prefix:`
# header) and `_render_enum_lines` formats it as a column-aligned table
# so the reader can scan keys at a glance instead of parsing the prose.
# The parser is conservative — it returns None for descriptive prose
# that *mentions* hex values (e.g. "Per-tune. Example: $F9 (...); $98
# (...)"), so non-enum fields render verbatim.

_ENUM_ENTRY_RE = re.compile(r"^\$([0-9A-Fa-f]{1,4})\s*=\s*(.+)$")

# Sentence boundary inside an entry name (period + space + capital) —
# strong signal the "name" has run over into the next prose sentence.
_SENTENCE_BOUNDARY_RE = re.compile(r"\.\s+[A-Z]")


def _unbalanced_parens(s: str) -> bool:
    """Return True if s has unmatched ``(`` or ``)`` brackets."""
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return True
    return depth != 0


def _parse_enum_list(text: str) -> tuple[str, list[tuple[str, str]]] | None:
    """Try to parse text as ``[prefix:] $HH = name1, $HH = name2, …``.

    Returns ``(prefix_or_empty, [(key, name), …])`` when the whole text
    is structurally an enum list with ≥2 entries; otherwise None.

    Rejects cases where the apparent enum runs out of a parenthetical
    group (e.g. ``Sets filter (high nibble: $10 = LP, $20 = BP, $40 =
    HP, $80 = 3-off) + volume``) — the prefix has unbalanced ``(`` or
    the trailing entry's "name" has unbalanced ``)`` and prose tail.
    """
    if not text:
        return None
    body = text.strip().rstrip(".")
    if not body:
        return None
    prefix = ""
    if not re.match(r"^\$[0-9A-Fa-f]{1,4}\s*=", body):
        m = re.match(r"^([^:$]+?):\s+(\$[0-9A-Fa-f]{1,4}\s*=.+)$", body)
        if not m:
            return None
        prefix = m.group(1).strip()
        body = m.group(2)
    if _unbalanced_parens(prefix):
        return None
    parts = re.split(r"\s*[,;]\s+(?=\$[0-9A-Fa-f]{1,4}\s*=)", body)
    if len(parts) < 2:
        return None
    entries: list[tuple[str, str]] = []
    for part in parts:
        m = _ENUM_ENTRY_RE.match(part.strip())
        if not m:
            return None
        key = f"${m.group(1).upper()}"
        name = m.group(2).strip().rstrip(".")
        if _unbalanced_parens(name):
            return None
        if _SENTENCE_BOUNDARY_RE.search(name):
            return None
        entries.append((key, name))
    return prefix, entries


def _render_enum_lines(prefix: str,
                       entries: list[tuple[str, str]]) -> list[str]:
    """Return the body lines of an enum table (no ``;`` comment prefix).

    Includes a leading ``prefix:`` line when the parser extracted one;
    otherwise the table stands alone. Keys are right-padded to a common
    width so the ``=`` columns align.
    """
    width = max(len(k) for k, _ in entries)
    out: list[str] = []
    if prefix:
        out.append(f"{prefix}:")
    for key, name in entries:
        out.append(f"  {key:<{width}} = {name}")
    return out


_VALID_VALUES_KIND = frozenset({"exhaustive", "flagset", "open"})


def _normalise_values_dict(values_dict: dict) -> list[tuple[str, str]] | None:
    """Coerce a TOML-loaded values dict into ``[(key, name), …]`` sorted
    by numeric key. Returns None if any key isn't ``$HH``-shaped."""
    out: list[tuple[int, str, str]] = []
    for k, v in values_dict.items():
        if not (isinstance(k, str) and isinstance(v, str)):
            return None
        if not re.fullmatch(r"\$[0-9A-Fa-f]{1,4}", k):
            return None
        out.append((int(k.lstrip("$"), 16), f"${k.lstrip('$').upper()}", v))
    out.sort()
    return [(key, name) for _, key, name in out]


def _format_notes_with_enums(notes: str) -> list[str]:
    """Walk a notes blob paragraph-by-paragraph; tabulate single-line
    paragraphs that match the enum-list shape, emit the rest verbatim.

    Returns lines (without comment prefix) and uses ``""`` to mark
    blank-line separators between paragraphs.
    """
    lines_in = notes.rstrip("\n").split("\n")
    paragraphs: list[list[str]] = []
    cur: list[str] = []
    for line in lines_in:
        if line.strip():
            cur.append(line)
        else:
            if cur:
                paragraphs.append(cur)
                cur = []
            paragraphs.append([])
    if cur:
        paragraphs.append(cur)

    out: list[str] = []
    for i, para in enumerate(paragraphs):
        if not para:
            if out and out[-1] != "":
                out.append("")
            continue
        if len(para) == 1:
            parsed = _parse_enum_list(para[0])
            if parsed is not None:
                pfx, entries = parsed
                out.extend(_render_enum_lines(pfx, entries))
                continue
        out.extend(para)
    return out


# Fields in each annotation that are loaded by the TOML parser but
# DELIBERATELY never emitted to defmon.s. The defmon.s output is meant
# to read as a maintained piece of code; anything related to the
# reverse-engineering process (probe evidence, prior versions of an
# annotation, classification snapshots, mining provenance) belongs in
# these never-emitted fields rather than in `notes`.
NEVER_EMIT_FIELDS = frozenset({"evidence", "internal_notes",
                               "inline_comments"})


LOAD_ADDR = 0x0800
END_ADDR_EXCL = 0xE787  # last body byte is $E786

# Hand-curated seed code-starts from AGENTS.md's RE notes. These are
# guaranteed-to-execute entry points whose cpuhistory PCs the player-IRQ
# ring-buffer churn typically drops between drains. Each is verified
# present in the static disassembly maps (Editor input / Other-mode
# dispatch tables sections).
SEED_LANDMARKS = {
    # NMI SID#2-silence self-mod counter block ($0AD9-$0AEC): `lda #imm;
    # beq tail; DEC $0ADA (self-patches that imm); jsr $C51F; ...; rti`.
    # Statically unreachable (entered via the post-NMI branch fan-out),
    # so seed it explicitly to decode as code instead of a .byte run.
    0x0AD9: "nmi_sid2_silence_count",
    # Player API (per docs:callingtheplayer)
    0x1000: "player_init",
    0x1003: "player_play",
    0x1006: "player_sound_update",
    # Main editor loop
    0x092C: "main_loop",
    0x0939: "mode_dispatch",
    0x0E47: "kbd_scan",
    0x0F32: "modifier_extract",
    # Field-writer dispatcher
    0x844C: "field_writer_dispatcher",
    # Per-mode handlers
    0xAE78: "seqED_handler",
    0xAE85: "seqED_dispatch",
    0xE550: "seqLIST_handler",
    0xBBB5: "sidTAB_handler",
    # NOTE: `$C491` is NOT the visible disk menu (that's `$75DB` below).
    # It's a secondary mode-$20 dispatcher reachable only by CTRL+/ from
    # sidTAB ($BD5D writer site). The harness has no path through it.
    0xC491: "secondary_disk_mode_handler",
    # seqED writer arms (from $AE78 cascade)
    0xAEB3: "seqED_note_arm",
    0xAECA: "seqED_clear_advance_arm",
    0xAED8: "seqED_clear_arm",
    0xAF1C: "seqED_sidcall_arm",
    0xAFC3: "seqED_cursor_step",
    0xAFCE: "seqED_cursor_wrap",
    0xB06E: "seqED_ctrl_prefix",
    0xB075: "seqED_super_set",
    0xB134: "seqED_cbm_shift_arm",
    0xB177: "seqED_ctrl_cbm",
    0xB187: "seqED_speed_arm",
    0xB27D: "seqED_voice_selector_check",
    # seqED writer endpoints
    0xB396: "writer_sidcall",
    0xB3DF: "writer_note",
    0xB3F6: "writer_clear_note",
    0xB3FF: "writer_speed",
    # seqLIST writer endpoints + helpers
    0xE13E: "seqLIST_helper",
    0xE149: "writer_seqlist_advance",
    0xE211: "writer_seqlist_digit",
    0xE233: "writer_seqlist_clear",
    0xE23C: "writer_seqlist_supercmd",
    0xE41E: "writer_seqlist_row_clone",
    0xE444: "writer_seqlist_row_insert",
    0xE52C: "writer_seqlist_dec",
    0xE53E: "writer_seqlist_inc",
    # sidTAB writer endpoints + staging
    0xBDA4: "sidTAB_staging",
    0xBDF3: "sidTAB_helper",
    0xBE15: "sidTAB_shifted_helper",
    0xC15F: "writer_sidtab_digit",
    0xC146: "writer_sidtab_toggle",
    0xC199: "writer_sidtab_clear_advance",
    0xC1AB: "writer_sidtab_inc",
    0xC1CE: "writer_sidtab_dec",
    0xC211: "writer_sidtab_supercmd",
    0xC352: "writer_sidtab_cbm_shift_a",
    0xC36A: "writer_sidtab_inst_row",
    0xC406: "writer_sidtab_cbm_shift_b",
    # Secondary-disk-mode writer (reached only via $C491)
    0xC4FA: "writer_disk_filename",
    # Global pre-dispatch (called from main loop *before* $0939 mode
    # dispatch). Catches voice-mute toggles, F-keys, and the LSHIFT+X
    # disk-menu chord (at $8244 → $7423 → $75DB nested input loop).
    0x80C4: "global_pre_dispatch",
    0x8234: "global_shift_modifier_arm",
    0x8244: "shift_x_disk_menu_chord",   # LSHIFT+X handler entry
    # Visible disk menu — the nested UI loop the harness drives.
    # $7423 is the save-UI / menu entry helper called from $8244.
    # $75DB is the input loop proper: paints the menu, scans keys at
    # $7618, dispatches at $7629+ (bare SPACE refresh, COMMA/PERIOD
    # drive nav, S save, LEFTARROW exit). Runs nested under the main
    # loop and suspends $0939 dispatch for the menu's lifetime — so
    # `$7167` stays at $01 (seqED) while the menu is up.
    0x7423: "save_ui_entry",
    0x75DB: "disk_menu_input_loop",
    0x7618: "disk_menu_kbd_scan",
    0x7629: "disk_menu_prev_drive_arm",  # bare COMMA → DEC $BA (also dispatch entry)
    0x763A: "disk_menu_next_drive_arm",  # bare PERIOD → INC $BA
    0x7643: "disk_menu_refresh_arm",     # bare SPACE → JMP $75DB
    0x76B6: "disk_menu_exit_arm",        # bare LEFTARROW
    0x76E4: "disk_menu_save_arm",        # bare 'S'
    # Secondary disk mode entry (CTRL+/ in sidTAB → mode = $20)
    0xBD5D: "sidTAB_ctrl_slash_arm",
    0xBD6A: "mode_disk_set",             # sole LDA #$20; STA $7167
    # Post-LOAD decoder (RAM-under-I/O at $D6xx/$D7xx; banked-in by
    # $0A78 setting $01=#$35). Static-disasm coverage missed these
    # without seeds — trace_runner never drives a real LOAD.
    # Verified via harness/probe_decoder_catch.py 2026-05-12.
    0xD6B8: "decoder_emit_byte_inc",     # STA ($FD),Y + INC $FD + count
    0xD6C9: "decoder_block_helper",      # 2× JSR $D74C wrappers
    0xD709: "decoder_loop_entry",        # LDX #$00 / loop top (probe-confirmed)
    0xD712: "decoder_fill_jump",         # JMP $D732 (fall-into fill-loop)
    0xD732: "decoder_emit_byte_dec",     # downward-fill writer
    0xD74C: "decoder_src_decr",          # decrement source pointer ($02/$03) by 1
    # Save-encoder chain (per AGENTS Step 4). Not in entrypoints.json
    # because the trace_runner moved the save earlier in the sweep
    # (gotcha #9 fix) — these get executed only when a real defMON SAVE
    # runs. SEEDed here so the emitter disassembles them; annotations
    # in tools/re/annotations.toml describe each routine.
    0xCE81: "save_prep_orchestrator",    # JSR $CF2A / $CF6A / $CFEF
    0xCEB2: "decoder_load_setup",        # patches $D60D/$D60E from $AE/$AF-3
    0xCF2A: "save_prep_markers",         # fill empty song-position slots with $11
    0xCFEF: "save_prep_zero_pat_base",   # zero $1A00..$1AFF
    0xCF6A: "save_prep_arranger_scan",   # arranger pat-num search
    # Code reachable only via indirect JSR / self-mod (no direct
    # JSR/JMP-abs caller). The dynamic sweep doesn't exercise these
    # paths so they're missing from trace/entrypoints.json; SEEDed
    # here so the emitter disassembles them as instructions instead
    # of `.byte` data.
    0xB21A: "seqED_auto_advance_via_b2c3",       # variant of $B20D, writer=$B2C3
    0xB3C8: "writer_seqED_speed_or_value",       # CBM/CTRL writer-arm dispatch
    0xB5A1: "writer_seqED_pat_base_resolve",     # pat_base resolver
    0xB5B0: "writer_seqED_kbd_xy_preload",       # kbd_modifiers → X/Y stride preload
    0xB5C0: "writer_seqED_jmp_to_paint",         # 1-byte JMP $B5EB trampoline
    0xB5C3: "writer_seqED_pattern_to_screen",    # copy ($02),Y pattern row to screen
    0xB5EB: "writer_seqED_screen_to_pattern",    # inverse: copy ($02),Y → ($FD),Y
    0xB607: "writer_seqED_pattern_copy_v3",      # adjacent variant
    0xB623: "writer_seqED_jmp_screen_to_pat",    # 3-byte JMP $B5EB trampoline
    0xB626: "writer_seqED_flag_byte_merge",      # merge flag-byte high/low nibbles
    0xB660: "writer_seqED_pat_base_high",        # alt pat_base resolver
    0xC2D8: "sidTAB_C2D8_dispatch_body",         # $C2D7 is the self-mod operand byte
    0xCC9D: "sid2_pitch_pw_clamp_commit",        # SID#2 PS sweep clamp + commit
    0xCE16: "sid2_sidtab_ctrl_accumulator",      # SID#2 sidtab CTRL accumulator
    0xCEFE: "sid2_jp_marker_walker",             # SID#2 JP-marker mirror walker
    0xD02C: "load_decoder_setup_chain",          # JSR D0CC/D1E4/D3DF/D51E/D365
    0xD28C: "load_decoder_continuation_d28c",    # past the $D289 infinite loop
    0xD30F: "load_decoder_pat_base_walk",        # walk $1A00/$1A80 → ($FD/$FE)

    # ── Super-cmd parser ($8641 state machine, pinned 2026-05-16 sub-F RE).
    # Prefix phase: CTRL+letter sets $71C0 (super_cmd_flags) to a bitmask.
    # Digit phase: $868B reads $71C0 and dispatches to lo/hi-nibble arms.
    # Names use SCREEN-CODE letter (the actual decoded key per $0F90 LUT),
    # not the wiki's user-facing letter (which is shifted by one in some
    # places). See annotations.toml [function.$8641] for the full table.
    0x8604: "hex_digit_validate",                # decoded-key → 0..F nibble
    0x861D: "super_flag_or",                     # ORA $71C1 (super-cmd extra mask)
    0x8624: "super_arg_buffer_init",             # paint typed-arg prompt
    0x85D5: "super_init_full",                   # full super-cmd state reset
    0x85F8: "super_set_active",                  # mark super-cmd mode active
    0x85FE: "super_enter_status",                # 'enter super mode' init
    0x8641: "super_cmd_dispatch",                # parser entry (called from main_loop)
    0x86BE: "super_cmd_s_lo_nibble",             # $71C0==$01: S 1st digit
    0x86DB: "super_cmd_s_hi_nibble",             # $71C0==$02: S 2nd digit
    0x86F5: "super_cmd_terminate",               # shared exit (lo committed/abort)
    0x86FB: "super_cmd_w_lo_nibble",             # $71C0==$04: W 1st digit
    0x8717: "super_cmd_r_lo_nibble",             # $71C0==$10: R 1st digit
    0x8734: "super_cmd_wr_hi_nibble",            # $71C0==$20: shared W/R 2nd digit
    0x8751: "super_cmd_q_lo_nibble",             # $71C0==$40: Q 1st digit
    0x876E: "super_cmd_q_hi_nibble",             # $71C0==$80: Q 2nd digit
    0x878B: "super_cmd_z_arm",                   # $71C0==$08: Z (single-digit)

    # ── $82xx CBM+F-key dispatch arms (pinned 2026-05-16 sub-F deep-RE).
    # Reached from $80C4 global_pre_dispatch → $8234 modifier cascade.
    # CMP arms below all JMP to per-action handlers in $0Dxx.
    0x8282: "cbm_only_modifier_arm",             # CPX #$20 entry
    0x82A9: "cbm_shift_modifier_arm",            # CPX #$30 entry
    0x82D0: "ctrl_only_modifier_arm",            # CPX #$04 entry
    0x828C: "speedadj_cbm_f1_bumpup",            # JMP $0D3C with A=$01
    0x8295: "speedadj_cbm_f3_bumpup_inv",        # JMP $0D3C with A=$80
    0x829C: "speedadj_cbm_f5_subframe_up",       # JMP $0DD6
    0x82A3: "speedadj_cbm_f7_shiftleft",         # JMP $0D5F
    0x82B3: "speedadj_cbmshift_f1_bumpdown",     # JMP $0D4B with A=$01
    0x82BC: "speedadj_cbmshift_f3_bumpdown_inv", # JMP $0D4B with A=$80
    0x82C3: "speedadj_cbmshift_f5_subframe_dn",  # JMP $0DE3
    0x82CA: "speedadj_cbmshift_f7_shiftright",   # JMP $0D69

    # ── Speed-adjust sub-arms ($0Dxx). All share the $0DAC write-back tail
    # (Timer-A → CIA1 $DD04/$DD05). Dispatched by the $82xx parser arms above.
    0x0D3C: "speedadj_bump_up",                  # ADC Timer-A
    0x0D4B: "speedadj_bump_down",                # SBC Timer-A
    0x0D5F: "speedadj_shift_left",               # ROL Timer-A (×2)
    0x0D69: "speedadj_shift_right",              # LSR Timer-A (÷2 with $0800 floor)
    0x0D79: "speedadj_preset_loader",            # LSHIFT+F1/F3/F5/F7 presets
    0x0DAC: "speedadj_writeback_tail",           # Timer-A → DD04/DD05 + status repaint
    0x0DD6: "speedadj_subframe_up",              # CBM+F5: $715C += 1 (clamp 8)
    0x0DE3: "speedadj_subframe_down",            # CBM+SHIFT+F5: $715C -= 1 (clamp 1)
    0x0DED: "speedadj_status_repaint",           # shared tail of $0DD6/$0DE3

    # ── IEC encoder/save band ($7F0x, pinned 2026-05-16 Step B RE).
    # Custom bit-bang IEC primitives — NOT KERNAL.
    0x7F02: "iec_tx_byte",                       # send 1 byte with ATN handshake
    0x7F4E: "iec_clk_pulse",                     # pulse CLK line (sync from player)
    0x7F6F: "vic_display_on",                    # $D011 bit 4 SET (24-row display)
    0x7F78: "vic_display_off",                   # $D011 bit 4 CLEAR (blank)
    0x7F81: "iec_bus_quiesce",                   # 256-iter bit-bang IEC reset

    # ── Status-line print family ($83xx). Used by super-cmd arms +
    # disk-menu paint + Timer-A status display.
    0x838C: "statusline_clear",                  # clear status line buffer
    0x83B6: "statusline_print_char",             # A = char to print
    0x83D5: "statusline_print_hex_byte",         # X = byte → two hex digits
    0x83E2: "statusline_print_zstring",          # X/Y = pointer to zstring
    0x83F9: "statusline_scroll_left",            # scroll status line left

    # ── Kbd-scan code-start label (LUT — non-executable, but the
    # bytes at $0F90 onward aren't BRK opcodes so safe to seed).
    0x0F90: "kbd_scancode_lut",                  # 64-byte scancode→screen-code
}

# Equate-only labels — emitted as `name = $XXXX` equates but NOT added
# to the code-start seed set. Used for state vars whose byte values
# happen to be $00 (BRK opcode) and would otherwise be classified as
# code-starts by expand_code_starts, breaking the data-coverage gate.
# The emitter merges these into the `labels` dict for operand-resolution
# (so `LDA $71C2` emits as `lda super_arg_slot_r`) without affecting
# instruction classification.
# Standard C64 hardware register + KERNAL entry-point labels (outside
# the defMON image at $0800-$E786, so emitted only as equates). UPPER_CASE
# to distinguish from defMON's internal lower_snake_case labels. Names
# follow the conventional C64 reference (Mapping the C64, CC65 headers).
HW_LABELS = {
    # ── VIC-II ($D000-$D02E) ────────────────────────────────────────────
    # Sprite X/Y pairs $D000-$D00F (8 sprites, 2 bytes each).
    0xD000: "VIC_SP0_X",  0xD001: "VIC_SP0_Y",
    0xD002: "VIC_SP1_X",  0xD003: "VIC_SP1_Y",
    0xD004: "VIC_SP2_X",  0xD005: "VIC_SP2_Y",
    0xD006: "VIC_SP3_X",  0xD007: "VIC_SP3_Y",
    0xD008: "VIC_SP4_X",  0xD009: "VIC_SP4_Y",
    0xD00A: "VIC_SP5_X",  0xD00B: "VIC_SP5_Y",
    0xD00C: "VIC_SP6_X",  0xD00D: "VIC_SP6_Y",
    0xD00E: "VIC_SP7_X",  0xD00F: "VIC_SP7_Y",
    0xD010: "VIC_SPRITES_X_MSB",       # sprite-X bit 8 (bitmask, 1/sprite)
    0xD011: "VIC_CR1",                 # control reg 1 (RST8/ECM/BMM/DEN/RSEL/YSCROLL)
    0xD012: "VIC_RASTER",              # raster line lo (R/W: r=current, w=compare)
    0xD013: "VIC_LP_X",                # light-pen X
    0xD014: "VIC_LP_Y",                # light-pen Y
    0xD015: "VIC_SPRITE_ENABLE",
    0xD016: "VIC_CR2",                 # control reg 2 (RES/MCM/CSEL/XSCROLL)
    0xD017: "VIC_SPRITE_Y_EXPAND",
    0xD018: "VIC_MEM_PTR",             # video matrix + char-base pointers
    0xD019: "VIC_IRQ_STATUS",          # latched IRQ source bits
    0xD01A: "VIC_IRQ_MASK",            # IRQ enable
    0xD01B: "VIC_SPRITE_BG_PRIO",      # sprite-to-bg priority
    0xD01C: "VIC_SPRITE_MC",           # sprite multicolor enable
    0xD01D: "VIC_SPRITE_X_EXPAND",
    0xD01E: "VIC_SPRITE_SS_COLL",      # sprite-sprite collision (read-clears)
    0xD01F: "VIC_SPRITE_SB_COLL",      # sprite-background collision
    0xD020: "VIC_BORDER",
    0xD021: "VIC_BG0",                 # bg color 0
    0xD022: "VIC_BG1",
    0xD023: "VIC_BG2",
    0xD024: "VIC_BG3",
    0xD025: "VIC_SPRITE_MC0",          # shared sprite multicolor 0
    0xD026: "VIC_SPRITE_MC1",
    0xD027: "VIC_SP0_COL",  0xD028: "VIC_SP1_COL",
    0xD029: "VIC_SP2_COL",  0xD02A: "VIC_SP3_COL",
    0xD02B: "VIC_SP4_COL",  0xD02C: "VIC_SP5_COL",
    0xD02D: "VIC_SP6_COL",  0xD02E: "VIC_SP7_COL",

    # ── SID#1 ($D400-$D41C) ─────────────────────────────────────────────
    0xD400: "SID_V1_FREQ_LO", 0xD401: "SID_V1_FREQ_HI",
    0xD402: "SID_V1_PW_LO",   0xD403: "SID_V1_PW_HI",
    0xD404: "SID_V1_CTRL",    0xD405: "SID_V1_AD",  0xD406: "SID_V1_SR",
    0xD407: "SID_V2_FREQ_LO", 0xD408: "SID_V2_FREQ_HI",
    0xD409: "SID_V2_PW_LO",   0xD40A: "SID_V2_PW_HI",
    0xD40B: "SID_V2_CTRL",    0xD40C: "SID_V2_AD",  0xD40D: "SID_V2_SR",
    0xD40E: "SID_V3_FREQ_LO", 0xD40F: "SID_V3_FREQ_HI",
    0xD410: "SID_V3_PW_LO",   0xD411: "SID_V3_PW_HI",
    0xD412: "SID_V3_CTRL",    0xD413: "SID_V3_AD",  0xD414: "SID_V3_SR",
    0xD415: "SID_FC_LO",      0xD416: "SID_FC_HI",
    0xD417: "SID_FILTER_RES",          # resonance hi-nibble + routing lo-nibble
    0xD418: "SID_VOL_FILTER",          # volume lo-nibble + filter-mode hi-nibble
    0xD419: "SID_POT_X",  0xD41A: "SID_POT_Y",
    0xD41B: "SID_OSC3",                # voice-3 oscillator readback
    0xD41C: "SID_ENV3",                # voice-3 envelope readback

    # ── SID#2 ($D500 default mapping; the SMC operand bytes hold $D5
    # by default but get rewritten by `sid2_register_write_body` arms
    # ($C8xx) based on `sid2_base_hi` ($7165). The labels document the
    # register layout — same as SID#1, mirrored 256 bytes up). ────────
    0xD500: "SID2_V1_FREQ_LO", 0xD501: "SID2_V1_FREQ_HI",
    0xD502: "SID2_V1_PW_LO",   0xD503: "SID2_V1_PW_HI",
    0xD504: "SID2_V1_CTRL",    0xD505: "SID2_V1_AD",  0xD506: "SID2_V1_SR",
    0xD507: "SID2_V2_FREQ_LO", 0xD508: "SID2_V2_FREQ_HI",
    0xD509: "SID2_V2_PW_LO",   0xD50A: "SID2_V2_PW_HI",
    0xD50B: "SID2_V2_CTRL",    0xD50C: "SID2_V2_AD",  0xD50D: "SID2_V2_SR",
    0xD50E: "SID2_V3_FREQ_LO", 0xD50F: "SID2_V3_FREQ_HI",
    0xD510: "SID2_V3_PW_LO",   0xD511: "SID2_V3_PW_HI",
    0xD512: "SID2_V3_CTRL",    0xD513: "SID2_V3_AD",  0xD514: "SID2_V3_SR",
    0xD515: "SID2_FC_LO",      0xD516: "SID2_FC_HI",
    0xD517: "SID2_FILTER_RES",
    0xD518: "SID2_VOL_FILTER",

    # ── CIA#1 ($DC00-$DC0F) — keyboard, joystick port 1, timers ────────
    0xDC00: "CIA1_PRA",                # port A (keyboard cols out / joy2)
    0xDC01: "CIA1_PRB",                # port B (keyboard rows in / joy1)
    0xDC02: "CIA1_DDRA",
    0xDC03: "CIA1_DDRB",
    0xDC04: "CIA1_TA_LO", 0xDC05: "CIA1_TA_HI",
    0xDC06: "CIA1_TB_LO", 0xDC07: "CIA1_TB_HI",
    0xDC08: "CIA1_TOD_TS",             # tenths-of-second BCD
    0xDC09: "CIA1_TOD_SEC", 0xDC0A: "CIA1_TOD_MIN", 0xDC0B: "CIA1_TOD_HR",
    0xDC0C: "CIA1_SDR",                # serial data
    0xDC0D: "CIA1_ICR",                # IRQ control (latched on read)
    0xDC0E: "CIA1_CRA",  0xDC0F: "CIA1_CRB",

    # ── CIA#2 ($DD00-$DD0F) — VIC bank, serial bus, NMI timer ──────────
    0xDD00: "CIA2_PRA",                # port A: VIC bank (bits 0-1) + serial
    0xDD01: "CIA2_PRB",
    0xDD02: "CIA2_DDRA",
    0xDD03: "CIA2_DDRB",
    0xDD04: "CIA2_TA_LO", 0xDD05: "CIA2_TA_HI",  # defMON NMI rate timer
    0xDD06: "CIA2_TB_LO", 0xDD07: "CIA2_TB_HI",
    0xDD08: "CIA2_TOD_TS",
    0xDD09: "CIA2_TOD_SEC", 0xDD0A: "CIA2_TOD_MIN", 0xDD0B: "CIA2_TOD_HR",
    0xDD0C: "CIA2_SDR",
    0xDD0D: "CIA2_ICR",                # NMI control (latched on read)
    0xDD0E: "CIA2_CRA",  0xDD0F: "CIA2_CRB",

    # ── KERNAL jumptable ($FF81-$FFF3) ─────────────────────────────────
    # Each entry is JMP to the actual KERNAL routine. Stable across all
    # C64 KERNAL revisions.
    0xFF81: "KERNAL_CINT",             # init editor / VIC / screen
    0xFF84: "KERNAL_IOINIT",           # init I/O devices
    0xFF87: "KERNAL_RAMTAS",           # init RAM, allocate tape buffer
    0xFF8A: "KERNAL_RESTOR",           # restore default I/O vectors
    0xFF8D: "KERNAL_VECTOR",           # read/set vector table
    0xFF90: "KERNAL_SETMSG",           # kernal message control
    0xFF93: "KERNAL_LSTNSA",           # send secondary after listen
    0xFF96: "KERNAL_TALKSA",           # send secondary after talk
    0xFF99: "KERNAL_MEMTOP",           # read/set top of memory
    0xFF9C: "KERNAL_MEMBOT",           # read/set bottom
    0xFF9F: "KERNAL_SCNKEY",           # scan keyboard
    0xFFA2: "KERNAL_SETTMO",           # IEEE timeout
    0xFFA5: "KERNAL_IECIN",            # serial: input byte (ACPTR)
    0xFFA8: "KERNAL_IECOUT",           # serial: output byte (CIOUT)
    0xFFAB: "KERNAL_UNTLK",
    0xFFAE: "KERNAL_UNLSN",
    0xFFB1: "KERNAL_LISTEN",
    0xFFB4: "KERNAL_TALK",
    0xFFB7: "KERNAL_READST",           # read I/O status word
    0xFFBA: "KERNAL_SETLFS",           # set logical file / device / sa
    0xFFBD: "KERNAL_SETNAM",
    0xFFC0: "KERNAL_OPEN",
    0xFFC3: "KERNAL_CLOSE",
    0xFFC6: "KERNAL_CHKIN",
    0xFFC9: "KERNAL_CHKOUT",
    0xFFCC: "KERNAL_CLRCHN",
    0xFFCF: "KERNAL_CHRIN",
    0xFFD2: "KERNAL_CHROUT",
    0xFFD5: "KERNAL_LOAD",
    0xFFD8: "KERNAL_SAVE",
    0xFFDB: "KERNAL_SETTIM",
    0xFFDE: "KERNAL_RDTIM",
    0xFFE1: "KERNAL_STOP",             # test STOP key
    0xFFE4: "KERNAL_GETIN",
    0xFFE7: "KERNAL_CLALL",
    0xFFEA: "KERNAL_UDTIM",            # update jiffy clock
    0xFFED: "KERNAL_SCREEN",
    0xFFF0: "KERNAL_PLOT",
    0xFFF3: "KERNAL_IOBASE",

    # ── Hardware vector table ($FFFA-$FFFF) ────────────────────────────
    0xFFFA: "VEC_NMI_LO",   0xFFFB: "VEC_NMI_HI",
    0xFFFC: "VEC_RESET_LO", 0xFFFD: "VEC_RESET_HI",
    0xFFFE: "VEC_IRQ_LO",   0xFFFF: "VEC_IRQ_HI",

    # ── Indirect vectors in low RAM ($0314-$0333) ──────────────────────
    # Patched by KERNAL init + by defMON ($0A3F quiesce). The IRQ/NMI
    # vectors are the most commonly retargeted.
    0x0314: "VEC_CINV_LO",  0x0315: "VEC_CINV_HI",   # IRQ vector
    0x0316: "VEC_CBINV_LO", 0x0317: "VEC_CBINV_HI",  # BRK vector
    0x0318: "VEC_NMINV_LO", 0x0319: "VEC_NMINV_HI",  # NMI vector

    # ── Color RAM ($D800-$DBFF, 1000 visible + 24 pad bytes) ───────────
    0xD800: "COLOR_RAM",

    # ── 6510 CPU on-chip I/O port ──────────────────────────────────────
    0x0000: "CPU_DDR",                 # data-direction register
    0x0001: "CPU_PORT",                # bank-select + tape control

    # ── KERNAL ZP — LOAD end pointer (top-of-program after LOAD) ────────
    0x00AE: "KERNAL_LOAD_END_LO",
    0x00AF: "KERNAL_LOAD_END_HI",

    # ── KERNAL keyboard buffer (10-byte FIFO at $0277-$0280); $04F0 is
    # an adjacent scratch area defMON reuses during save (non-interactive).
    0x04F0: "KERNAL_KEYBUF_SCRATCH",

    # ── KERNAL ZP — cursor text colour (foreground colour for next CHROUT).
    0x0286: "TEXT_COLOR",

    # ── Screen RAM page boundaries (defMON uses 4-page layout for the
    # 25×40 grid: $0400+$0500+$0600+$0700, 1024 bytes total). The
    # SCREEN_RAM anchor at $0400 is also an HW_ANCHOR_REGION so the
    # resolver renders intra-screen-RAM addresses as `SCREEN_RAM + $XYZ`.
    0x0400: "SCREEN_RAM",
    0x0500: "SCREEN_RAM_P2",
    0x0600: "SCREEN_RAM_P3",
    0x0700: "SCREEN_RAM_P4",
    0x07FF: "SCREEN_RAM_END",
    # Specific named cells referenced by multiple summaries.
    0x0401: "SCREEN_RAM_ROW0_COL1",
    0x0419: "SCREEN_RAM_ROW0_COL25",
    0x0426: "SCREEN_RAM_ROW0_COL38",
    0x0427: "SCREEN_RAM_ROW0_COL39",
    0x0450: "SCREEN_RAM_ROW2_COL16",
    0x045B: "SCREEN_RAM_ROW2_COL27",
    0x0748: "SCREEN_RAM_SIDTAB_GLYPH",  # row 13 col 8 (sidTAB/disk paint slot)
}


# Contiguous hardware/system RAM regions used as anchors when an
# ABS-operand target lands inside the region but doesn't match any exact
# label. The resolver renders such addresses as `name + $offset` so
# `sta $D823` becomes `sta COLOR_RAM + $23` (the colour cell at row 0
# col 35) and `sta $0429` becomes `sta SCREEN_RAM + $29`. Anchor spans
# take priority over annotation-derived `name_spans` because the I/O
# overlay at $D800+ never matches a static-image annotation, and
# screen RAM at $0400-$07FF sits below the annotated $0800-$E786 image.
HW_ANCHOR_REGIONS: list[tuple[int, int, str]] = [
    (0x0400, 0x0800, "SCREEN_RAM"),    # default 25x40 video matrix (4 pages)
    (0xD800, 0xDC00, "COLOR_RAM"),     # 1000 visible cells + 24-byte pad
]


EQUATE_LABELS = {
    # Kbd-scan state vars ($0E43-$0E46). $00/$02 byte values would
    # otherwise be classified as BRK code-starts.
    0x0E43: "kbd_modifiers_prev",                # prev-frame modifier mask
    0x0E45: "kbd_decoded_key_prev",              # prev-frame decoded key
    0x0E46: "kbd_debounce_counter",              # decremented per frame

    # Super-cmd slot vars ($71Cx) — typed-arg accumulators per prefix.
    # Each lo-nibble arm writes its slot; the hi-nibble arm ASL-shifts
    # the prior digit into the high nibble then ORs with the new digit.
    0x71C2: "super_arg_slot_r",                  # R lo: $8717 STA $71C2
    0x71C3: "super_arg_slot_q",                  # Q lo: $8751 STA $71C3 + Q hi shifts
    0x71C4: "super_arg_slot_swr_hi",             # shared S/W/R hi target (shifted)
    0x71C5: "super_arg_slot_w",                  # W lo: $86FB STA $71C5
    0x71C6: "super_arg_slot_z",                  # Z (single-digit): $878B STA $71C6
    0x7166: "super_cmd_staged",                  # currently-staged super-cmd opcode

    # Save-UI state byte (referenced by $7423 prologue + $7448 cleanup).
    0x9EC5: "save_ui_saved_state",

    # ── Player runtime state — per-voice records ($1019/$104A/$107B).
    # These slots are also the immediate-operand bytes of instructions in
    # player_play_body, hence not code-starts. Indexed by X = $00 / $31 /
    # $62 (V0 / V1 / V2 stride).
    0x1019: "voice_record_v0",            # V0 working-record base
    0x101B: "slide_mode_v0",               # neg=down, pos=up, 0=hold
    0x101E: "ps_depth_v0",                 # pulse-sweep / vibrato depth
    0x101F: "pitch_base_v0",               # per-voice pitch detune
    0x1023: "pw_lo_patch_v0",              # PW LO immediate of `ldx #$XX`
    0x1025: "pw_hi_patch_v0",              # PW HI immediate of `lda #$XX`
    0x104A: "voice_record_v1",
    0x107B: "voice_record_v2",

    # ── Row timers (immediate operand of `ldy #$XX` self-mod cell).
    0x114A: "v0_row_timer",
    0x11D2: "v1_row_timer",
    0x125A: "v2_row_timer",

    # ── Sub-frame sentinel opcode at the row-advance gate.
    0x10D8: "subframe_sentinel_opcode",

    # ── Filter-cutoff slide accumulator + threshold (16-bit).
    0x10B6: "filter_cutoff_acc_lo",        # paired with $10BE acc-hi (already labeled)

    # ── Playback gate flag.
    0x0AF7: "playback_state",              # 0 = paused, !=0 = playing

    # ── Sub-frame phase counter (player ratchet).
    0x7172: "sub_frame_phase",

    # ── Super-command arg state.
    0x71C7: "super_arg_count",             # how many hex digits left to consume
    0x71C8: "super_arg",                   # resolved super-cmd argument

    # ── Sidcall step counters + row-index slots (V0/V1/V2 × sc1/sc2).
    0x12E0: "v0_sc1_counter",
    0x1311: "v1_sc1_counter",
    0x1342: "v2_sc1_counter",
    0x1373: "v0_sc2_counter",
    0x13A4: "v1_sc2_counter",
    0x13D5: "v2_sc2_counter",
    0x12EF: "v0_sc1_row_idx",
    0x1320: "v1_sc1_row_idx",
    0x1351: "v2_sc1_row_idx",
    0x1382: "v0_sc2_row_idx",
    0x13B3: "v1_sc2_row_idx",
    0x13E4: "v2_sc2_row_idx",

    # ── Groove timer ($1B00 V0-arranger JUMP-COMMAND mechanism).
    0x14EB: "groove_song_position",        # Y at time of jump
    0x14ED: "groove_repeat_counter",       # V2's per-row count

    # ── Per-voice current note (indexed $137F,X).
    0x137F: "current_note_v0",

    # ── Hex-digit screen-code LUTs (256-byte each).
    0x7B00: "hex_digit_lo_lut",            # cycles 30..39 01..06 indexed by lo nibble
    0x7C00: "hex_digit_hi_lut",            # 16 copies, indexed by hi nibble (X>>4)

    # ── Pitch-LUT band sub-tables ($1578-$163F).
    0x14F8: "slide_dec_lut_lo",            # 576-byte backing region
    0x1578: "pitch_lut_band",              # paired-LUT band start
    0x1583: "interval_lut_lo_a",           # adjacent-semitone interval lo, table A
    0x1584: "interval_lut_lo_b",           # adjacent-semitone interval lo, table B
    0x1594: "slide_dec_lut_hi",
    0x159C: "note_pitch_lut_lo",
    0x1614: "slide_inc_lut_hi",
    0x161F: "interval_lut_hi_a",
    0x1620: "interval_lut_hi_b",
    0x1638: "note_pitch_lut_hi",

    # ── High-frequency unlabeled variable slots (≥4 refs in defmon.s).
    # Editor / runtime state.
    0x08AB: "editor_busy_wait_counter",    # self-mod immediate at editor_frame_barrier+1
    0x08DA: "editor_other_delta",          # per-frame delta accumulator, parallel to editor_row_delta/_col_delta
    0x0912: "editor_aux_counter",          # editor super-cmd page-commit aux counter
    0x716A: "cursor_redraw_flag",          # set to $04 by cursor_redraw_request to request a paint
    0x716B: "border_color_state_a",        # written by border_set_a
    0x716C: "border_color_state_b",        # written by border_set_b
    0x716E: "ui_state_716e",               # editor-paint state byte
    0x71BB: "kbd_voice_mute_mirror",       # 2nd kbd voice-mute slot (mirror of $7180?)
    0x71CF: "super_cmd_state_71cf",        # super-cmd internal state

    # Save / disk / cursor state.
    0x7296: "seqlist_cursor_aux1",
    0x7298: "seqlist_cursor_aux2",
    0x7299: "seqlist_cursor_aux3",
    0x797F: "save_name_buf_marker",        # '.' marker check in filename buffer
    0x7978: "save_name_buf_byte0",
    0x7979: "save_name_buf_byte1",
    0x798F: "save_name_buf_len",           # filename buffer length (non-zero check)

    # sidTAB staging buffer slots (referenced by all writer arms).
    0xBDA1: "sidtab_staging_field1",
    0xBDA2: "sidtab_staging_field2",
    0xBDA3: "sidtab_staging_field3",
    0xBDD5: "sidtab_staging_dispatch_smc",

    # SID#2 mirror state.
    0xC81A: "sid2_v0_voice_record_slot_a",
    0xC81E: "sid2_v0_voice_record_slot_b",
    0xC8EB: "sid2_frame_state_slot",
    0xCB7F: "sid2_cascade_inner_counter",  # SID#2 mirror of cascade gate counter

    # LOAD-decoder / save-encoder state.
    0xCE7E: "song_end_pointer_hi",         # hi byte paired with song_end_pointer lo
    0xD11C: "decoder_main_state_d11c",
    0xD309: "pat_num_occupancy_table_d309",
    0xD512: "decoder_state_d512",
    0xD51D: "decoder_xy_smc_d51d",         # paired with decoder_xy_smc_pair
    0xD77E: "selfmod_emitter_target_lo",   # operand lo of self_modifying_byte_emitter's STA
    0xD77F: "selfmod_emitter_target_hi",

    # Player / V0 row-read state.
    0x120E: "player_state_120e",
    0x1296: "v0_player_state_1296",

    # Per-voice slide accumulator commit slots (X-indexed: V0=$00,
    # V1=$31, V2=$62; sta $102D,X / $102F,X by pitch-slide oscillator).
    0x102D: "slide_acc_commit_lo",
    0x102F: "slide_acc_commit_hi",

    # Filter-cutoff slide ADC-imm operand slots (patched at runtime by
    # sidtab_row_apply's filter-slide handler).
    0x10B9: "filter_cutoff_slide_step_lo_smc",
    0x10C0: "filter_cutoff_slide_step_hi_smc",

    # Save / disk: overwrite state byte.
    0x792B: "save_overwrite_state",

    # Super-cmd state cluster ($71B9-$71BD).
    0x71B9: "super_cmd_state_71b9",
    0x71BA: "super_cmd_state_71ba",
    0x71BC: "super_cmd_state_71bc",
    0x71BD: "super_cmd_state_71bd",

    # SID#2 stereo-sync byte at $0B18.
    0x0B18: "sid2_stereo_sync_byte",

    # Chip-view step body local cursor save slots.
    0xC05F: "chipview_cursor_x_save",
    0xC060: "chipview_cursor_y_save",

    # Decoder running byte-count operand bytes (16-bit at $D60D/$D60E).
    0xD60D: "decoder_byte_count_lo_smc",
    0xD60E: "decoder_byte_count_hi_smc",

    # Pat-num occupancy table low byte (paired with pat_num_occupancy_table_d309).
    0xD308: "pat_num_occupancy_d308",

    # seqED writer state at $B696.
    0xB696: "seqED_writer_state_b696",

    # SID#2 voice records — V0 step state + per-voice slots.
    0xC81B: "sid2_v0_voice_record_slot_c",   # paired with sid2_v0_voice_record_slot_a/_b
    0xC823: "sid2_v0_step_accumulator",      # cascade step-accumulator slot
    0xC8CE: "sid2_v1_voice_record_slot_a",
    0xC8D9: "sid2_v1_voice_record_slot_b",
    0xC986: "sid2_filter_slot_c986",
    0xCA0E: "sid2_filter_slot_ca0e",
    0xCA96: "sid2_filter_slot_ca96",
    0xCAE0: "sid2_filter_slot_cae0",
    0xCB73: "sid2_cascade_inner_gate_counter",   # self-mod counter at sid2_cascade_inner_gate

    # SID#2 base alias + ZP-style pat-num table.
    0xD504: "sid2_alias_d504",
    0xD50B: "sid2_alias_d50b",

    # Kbd matrix row 1 (in matrix mirror).
    0x0E3A: "kbd_matrix_row1",

    # Player V0 state continuations.
    0x120F: "v0_player_state_120f",
    0x1297: "v0_player_state_1297",

    # Save filename buffer additional slots.
    0x7977: "save_name_buf_pre",
    0x797A: "save_name_buf_byte2",
    0x797B: "save_name_buf_byte3",

    # Super-cmd state additional slots.
    0x71C9: "super_cmd_state_71c9",
    0x71D0: "super_cmd_state_71d0",

    # Super-cmd writer self-mod.
    0x858A: "super_cmd_writer_step_byte_smc",

    # SID#2 frame state companions.
    0xC8B6: "sid2_frame_state_c8b6",
    0xC8BE: "sid2_frame_state_c8be",
    0xC987: "sid2_filter_slot_c987",
    0xCA0F: "sid2_filter_slot_ca0f",
    0xCA97: "sid2_filter_slot_ca97",
    0xCAEF: "sid2_cascade_step_counter",   # ($CAEF self-mod counter)

    # seqED paint band tail.
    0xAACE: "seqED_paint_end_byte_a",
    0xAACF: "seqED_paint_end_byte_b",

    # Color RAM offset in disk-menu paint.
    0xDAF8: "color_ram_disk_menu_offset",

    # sidTAB staging buffer additional slot.
    0xBDE4: "sidtab_staging_field4",

    # SID#2 cascade slot counters (mirror series for V0/V1/V2 × sc1/sc2).
    0xCB11: "sid2_v0_sc1_counter",
    0xCB42: "sid2_v1_sc1_counter",
    # ($CB73 already labelled as sid2_cascade_inner_gate_counter above)

    # SID#2 mirror sidcall step counters (siblings of v0/v1/v2_sc1/sc2_counter
    # at $12E0/$1311/$1342/$1373/$13A4/$13D5 in SID#1).
    0xC8CA: "sid2_cascade_pre_counter",
    0xC94A: "sid2_v1_sc1_step_counter",
    0xC9D2: "sid2_v2_sc1_step_counter",
    0xCA5A: "sid2_v0_sc2_step_counter",
    0xCAED: "sid2_v2_sc2_step_counter",
    0xCCED: "sid2_player_init_stride_counter",

    # Decoder save chain state operand bytes ($D64B / $D65C).
    0xD64B: "decoder_save_state_d64b",
    0xD65C: "decoder_save_state_d65c",

    # save_prep state continuation.
    0xCFCC: "save_prep_state_cfcc",
    0xCFD1: "save_prep_state_cfd1",

    # Save-chain band 5 byte cluster ($CE7A-$CE80, around song_end_pointer).
    0xCE70: "save_chain_state_ce70",
    0xCE7A: "save_chain_state_ce7a",
    0xCE7B: "save_chain_state_ce7b",
    0xCE7F: "save_chain_state_ce7f",
    0xCE80: "save_chain_state_ce80",
    0xCBA4: "sid2_v0_sc2_counter",
    0xCBD5: "sid2_v1_sc2_counter",
    0xCB82: "sid2_v2_sc2_counter",

    # SID#2 V0 voice-record additional slots ($C825/$C82D/$C82F).
    0xC825: "sid2_v0_voice_record_pw_slot",
    0xC82D: "sid2_v0_voice_record_slide_lo",
    0xC82F: "sid2_v0_voice_record_slide_hi",

    # Decoder pointer init operand bytes ($D60D/$D60E/$D60F/$D610).
    0xD60F: "decoder_dest_init_lo_smc",
    0xD610: "decoder_dest_init_hi_smc",

    # save_prep / decoder save chain state.
    0xCFCB: "save_prep_state_cfcb",

    # Pat-num occupancy table continuation slots.
    0xD30A: "pat_num_occupancy_d30a",
    0xD30B: "pat_num_occupancy_d30b",

    # song_end_pointer cluster (lo/hi already labelled; mid byte here).
    0xCE7C: "song_end_pointer_pre",

    # Cursor state cluster — 728D companion to seqED_cursor_band ($7280-$729F).
    0x728D: "cursor_state_728d",

    # ── ZP slots heavily used by editor + decoder ──────────────────────
    # ZP_PTR1: ($02),Y → screen-row address for editor paint code.
    # Set by screen_row_addr_resolver.
    0x0002: "zp_ptr1_lo",
    0x0003: "zp_ptr1_hi",
    # sidtab_row pointer: ($FB),Y read by sidtab_row_apply for per-row
    # bitmap walk. Set by the row-fetch landings.
    0x00FB: "zp_sidtab_row_lo",
    0x00FC: "zp_sidtab_row_hi",
    # Decoder destination pointer ($FD/$FE): set by decoder_pointer_init,
    # walked by decoder_emit_byte_inc / decoder_emit_byte_dec / etc.
    0x00FD: "zp_decoder_dest_lo",
    0x00FE: "zp_decoder_dest_hi",
    # Paint nibble-shift scratch ($FF): each seqED paint page does
    # `sta $FF / asl $FF / asl $FF` to extract high/low nibbles from an
    # arranger byte before writing them to screen as hex digits.
    0x00FF: "zp_paint_scratch",
    # Miscellaneous ZP scratch slots (touched by various editor paths).
    0x0096: "zp_scratch_96",
    0x009E: "zp_scratch_9e",
    0x009F: "zp_scratch_9f",

    # V0 SID-write patch slots ($1037/$1039/$103B/$103D — operand bytes
    # of LDX/LDY/LDA/EOR immediates inside the V0 SID-write band; zeroed
    # by player_init_body, patched per-frame by sidtab_row_apply).
    0x1037: "v0_sid_patch_a",
    0x1039: "v0_sid_patch_b",
    0x103B: "v0_sid_patch_c",
    0x103D: "v0_sid_patch_d",

    # SID#2 V0 SID-write patch slots (mirror of v0_sid_patch_a..d).
    0xC837: "sid2_v0_sid_patch_a",
    0xC839: "sid2_v0_sid_patch_b",
    0xC83B: "sid2_v0_sid_patch_c",
    0xC83D: "sid2_v0_sid_patch_d",

    # Cursor cluster aux + voice-selector LUT extension.
    0x728A: "cursor_state_728a",
    0x71E4: "voice_selector_lut_modifier_class",  # per-modifier value class lookup

    # Arranger byte 1 entries (second byte of arranger arrays).
    0x1B01: "arranger_v0_sid1_byte1",
    0x6E01: "arranger_v3_sid2_byte1",

    # SMC opcode slots inside filter-cutoff slide accumulator
    # (`adc #$00` opcode byte at $10B8 / $10BF gets patched per-call to
    # swap between A+= and A-= mode).
    0x10B8: "filter_cutoff_slide_adc_opcode_smc",
    0x10BF: "filter_cutoff_slide_adc_opcode_smc2",

    # NMI playback gate self-mod slot (paired with playback_state).
    0x0AFB: "nmi_playback_gate_smc",

    # SID#2 master volume register slot.
    0xD518: "sid2_master_volume",

    # Save UI: error/state byte after R/W abort.
    0x7723: "save_overwrite_state_byte",

    # SID#2 cascade self-mod target ($CB20 = SID#2 mirror of cascade
    # silence-latch counter; written by both STA and STY paths).
    0xCB20: "sid2_cascade_silence_latch_counter",

    # SID#2 mirror cascade slots — siblings of sid2_cascade_*_counter.
    0xCB51: "sid2_cascade_v1_silence_counter",
    0xCBB3: "sid2_cascade_v0_sc2_silence_counter",
    0xCBE4: "sid2_cascade_v1_sc2_silence_counter",
    0xCCEC: "sid2_player_init_stride",

    # save_prep area state.
    0xCFD0: "save_prep_state_cfd0",
    0xD50E: "sid2_alias_d50e",
    0xD50F: "sid2_alias_d50f",

    # secondary disk mode internal slot.
    0xC246: "secondary_disk_state_c246",

    # status-line print scratch ($83B7).
    0x83B7: "statusline_print_state_83b7",

    # State-page extras ($716F, $7288, $7297, $71BF, $71D4).
    0x716F: "editor_state_716f",
    0x71BF: "super_cmd_current_step",         # written by super_cmd_write_iter
    0x71D4: "super_cmd_writer_arm_state",     # written by writer_seqED_speed_or_value
    0x7288: "seqlist_state_7288",
    0x7297: "cursor_state_7297",

    # Save-side state ($CE7C-$CE7F cluster, paired with song_end_pointer).
    0xCE75: "save_chain_counter",          # SAVE/LOAD chain counter (5 refs)
    0xCE78: "save_chain_state_lo",
    0xCE79: "save_chain_state_hi",

    # Voice bit-masks at the V0/V1/V2 voice records ($1020 = $01 for V0,
    # $1051 = $02 for V1, $1082 = $04 for V2; complement at +1).
    0x1020: "v0_voice_bit_mask",        # $01 = V0 SID-bit
    0x1021: "v0_voice_bit_complement",  # $FE = ~V0
    0x1051: "v1_voice_bit_mask",        # $02
    0x1052: "v1_voice_bit_complement",  # $FD
    0x1082: "v2_voice_bit_mask",        # $04
    0x1083: "v2_voice_bit_complement",  # $FB

    # sidtab base byte 1 (sidtab_row_lo / _hi byte 1 — these are the FF
    # marker bytes inside the per-row JP table band).
    0x1801: "sidtab_row_lo_byte1",
    0x1901: "sidtab_row_hi_byte1",
    0x1E01: "dl_per_step_counters_byte1",

    # Cursor cluster + LUTs in $72xx that index by X via the sidtab
    # dispatcher (LDA $72D8,X / $7300,X / $7328,X / $7350,X / $7378,X /
    # $73A0,X / $73C8,X — 7 parallel tables at stride $28).
    0x72D8: "sidtab_dispatch_lut0",
    0x7300: "sidtab_dispatch_lut1",
    0x7328: "sidtab_dispatch_lut2",
    0x7350: "sidtab_dispatch_lut3",
    0x7378: "sidtab_dispatch_lut4",
    0x73A0: "sidtab_dispatch_lut5",
    0x73C8: "sidtab_dispatch_lut6",

    # Color RAM per-row paint anchors (COLOR_RAM + row*$28; LDA/STA $XXXX,X
    # targets in the unrolled seqED paint pages). Rows 1..23; row 0 = COLOR_RAM
    # and row 24 = COLOR_RAM_ROW24 below (incomplete in some pages).
    0xD828: "color_ram_row01",  0xD850: "color_ram_row02",
    0xD878: "color_ram_row03",  0xD8A0: "color_ram_row04",
    0xD8C8: "color_ram_row05",  0xD8F0: "color_ram_row06",
    0xD918: "color_ram_row07",  0xD940: "color_ram_row08",
    0xD968: "color_ram_row09",  0xD990: "color_ram_row10",
    0xD9B8: "color_ram_row11",  0xD9E0: "color_ram_row12",
    0xDA08: "color_ram_row13",  0xDA30: "color_ram_row14",
    0xDA58: "color_ram_row15",  0xDA80: "color_ram_row16",
    0xDAA8: "color_ram_row17",  0xDAD0: "color_ram_row18",
    # ($DAF8 already labelled as color_ram_disk_menu_offset = row19)
    0xDB20: "color_ram_row20",  0xDB48: "color_ram_row21",
    0xDB70: "color_ram_row22",  0xDB98: "color_ram_row23",
    0xDBC0: "color_ram_row24",

    # Screen RAM per-row paint anchors (SCREEN_RAM + row*$28; mirrors
    # of color_ram_rowNN at $D8xx). Row 0 = SCREEN_RAM ($0400).
    0x0428: "screen_ram_row01",  # ($0450 already labelled SCREEN_RAM_ROW2_COL16)
    0x0478: "screen_ram_row03",  0x04A0: "screen_ram_row04",
    0x04C8: "screen_ram_row05",  # ($04F0 = KERNAL_KEYBUF_SCRATCH — row6 alias skipped)
    0x0518: "screen_ram_row07",  0x0540: "screen_ram_row08",
    0x0568: "screen_ram_row09",  0x0590: "screen_ram_row10",
    0x05B8: "screen_ram_row11",  0x05E0: "screen_ram_row12",
    0x0608: "screen_ram_row13",  0x0630: "screen_ram_row14",
    0x0658: "screen_ram_row15",  0x0680: "screen_ram_row16",
    0x06A8: "screen_ram_row17",  0x06D0: "screen_ram_row18",
    0x06F8: "screen_ram_row19",  0x0720: "screen_ram_row20",
    # ($0748 already labelled as SCREEN_RAM_SIDTAB_GLYPH = row21)
    0x0770: "screen_ram_row22",  0x0798: "screen_ram_row23",
    0x07C0: "screen_ram_row24",

    # Paint-page template anchor (indexed via Y).
    0xAD82: "seqED_status_template_base",  # the LDA $AD82,Y target

    # ── Misc operand-byte / data-byte slots.
    0x12DE: "row_advance_band_end",        # tail SAX operand of V2 row-advance band
    0xD6D9: "decoder_term_lo_smc",         # SBC-imm operand (= src_floor lo)
    0xD6E0: "decoder_term_hi_smc",         # SBC-imm operand (= src_floor hi)

    # ── Auto-advance loop slots (count + repeat).
    0xB20B: "auto_advance_count",
    0xB20C: "auto_advance_repeat",

    # ── Editor frame counters (per-frame delta accumulators).
    0x08F5: "editor_row_delta",
    0x08FC: "editor_col_delta",

    # ── Per-mode super-cmd state save table ($0C7D-$0C8C, 16 bytes).
    0x0C7D: "super_cmd_save_table",
    0x0C8C: "super_cmd_save_table_end",

    # ── Screen RAM (top-left of the 25×40 grid).
    0x0400: "screen_ram",
    0x0413: "screen_ram_row0_col19",       # disk menu "blocks" column anchor

    # ── seqLIST cursor-step self-mod slots.
    0xE1A8: "seqlist_step_row_smc",
    0xE1A9: "seqlist_step_col_smc",
    0xE1AA: "seqlist_step_dx_smc",
    0xE1AB: "seqlist_step_dy_smc",

    # ── Row-advance branch landing pads (BMI target inside row_advance_band_vX).
    0x114B: "v0_row_advance_bmi",

    # ── SID#2 mirror state vars (parallel to SID#1 working records).
    0xC8AA: "sid2_silence_latch_acc",

    # ── Default SID#2 base address (stereo mode).
    0xD500: "sid2_base_default",

    # ── Status-line buffer ($71A3-$71B0 visible + scratch through $71B6).
    0x71A3: "statusline_buffer",
    0x71B0: "statusline_buffer_end",
    0x71B6: "statusline_scratch",

    # ── sidTAB cursor descriptor LUT (chip-view editable-cell map).
    0xBDB3: "sidtab_cell_descriptor_lut",

    # ── Per-voice slide-mode + freq-lookup operand slots inside the
    # row-read body (`row_read_body_v0`).
    0x101A: "v0_slide_acc",                # slide accumulator hi (within voice_record_v0)
    0x1186: "v0_freq_lookup_smc",          # self-mod operand of LDA in row_read_body_v0

    # ── SID#2 voice record (mirror of voice_record_v0 at $1019).
    0xC819: "sid2_voice_record_v0",

    # ── V1 sidcall1 refetch target landing (mid-cascade).
    0x131F: "v1_sc1_refetch",

    # ── Speed-adjust documentary block header (NOT a code-start; mid-instruction).
    0x0D24: "speedadj_block_header",

    # ── Auto-advance writer self-mod slots ($B252/$B253) — patched by
    # the seqED_auto_advance / seqED_auto_advance_octave dispatchers
    # to redirect JSR at $B251 to note_arm_auto_writer or $B380.
    0xB252: "auto_advance_writer_smc_lo",
    0xB253: "auto_advance_writer_smc_hi",

    # ── Cursor-walk self-mod slots inside seqED_cursor_walk_dispatcher.
    0xB347: "cursor_walk_x_offset_smc",
    0xB348: "cursor_walk_y_delta_smc",

    # ── Super-cmd writer step counter SMC operand.
    0x84F4: "super_cmd_writer_step_smc",

    # ── Directory-paint self-mod operand high bytes (paired with the
    # function-labelled low bytes at $75C8 / $75CF).
    0x75C9: "dir_paint_blocks_col_smc_hi",
    0x75D0: "dir_paint_name_col_smc_hi",

    # ── Kbd matrix mirror (8 bytes at $0E39-$0E40).
    0x0E39: "kbd_matrix_mirror",
    0x0E40: "kbd_matrix_mirror_end",

    # ── Voice-selector LUT band ($71D5/$71D8/$71DB/$71DE/$71E1, stride 3).
    0x71D5: "voice_selector_lut_v0",
    0x71D8: "voice_selector_lut_v1",
    0x71DB: "voice_selector_lut_v2",
    0x71DE: "voice_selector_lut_v3",
    0x71E1: "voice_selector_lut_v4",

    # ── Status-line / UI mode mirrors.
    0x7170: "ui_mode_mirror",
    0x71B7: "statusline_color_mirror",
    0x71BE: "super_cmd_status_mirror",

    # ── seqED per-mode slot offsets (filled by super_cmd_state_load).
    0x0C80: "super_cmd_save_slot_b",
    0x0C83: "super_cmd_save_slot_c",
    0x0C86: "super_cmd_save_slot_d",
    0x0C89: "super_cmd_save_slot_e",

    # ── Player-tick + row-read landmarks (immediate operands of
    # self-modifying instructions inside row_advance_band / row_read_body).
    0x1149: "v0_row_ldy_smc",
    0x1187: "v0_freq_lookup_smc_hi",
    0x11B4: "v0_row_dur_sax_smc",
    0x104C: "v1_voice_record_pad",
    0x149C: "ps_sweep_add_path_smc",

}

# Opcodes that don't fall through to PC + n.
_FLOW_TERMINATORS = {
    0x60,  # RTS
    0x40,  # RTI
    0x4C,  # JMP abs
    0x6C,  # JMP ind
    0x00,  # BRK
}
# Opcodes where the operand encodes a statically-resolvable target.
_TAKES_ABS_TARGET = {0x20, 0x4C}  # JSR, JMP abs
_BRANCH_OPCODES = {0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0}


def load_code_starts(entrypoints_path: Path) -> set[int]:
    data = json.loads(entrypoints_path.read_text())
    pcs = set()
    for entry in data.get("pcs", []):
        pc_field = entry["pc"] if isinstance(entry, dict) else entry
        pcs.add(int(pc_field, 16))
    return pcs


def expand_code_starts(mem: bytes, seeds: set[int],
                       start: int, end_excl: int) -> set[int]:
    """Fixed-point expand seed code PCs via linear fallthrough + abs targets.

    For every accepted code PC, add:
      - PC + n if the instruction doesn't terminate flow,
      - the abs/rel branch target for JSR / JMP abs / Bxx instructions.

    Indirect JMP ($6C) and self-modifying JSR (`$844C` etc.) are not
    followed — their targets only show up via direct execution.
    """
    code = set(pc for pc in seeds if start <= pc < end_excl)
    pending = set(code)
    while pending:
        nxt: set[int] = set()
        for pc in pending:
            if pc < start or pc >= end_excl:
                continue
            op = mem[pc]
            info = OPS.get(op)
            if info is None:
                continue
            n = info[2]
            if pc + n > end_excl:
                continue
            # fallthrough
            if op not in _FLOW_TERMINATORS:
                nxt.add(pc + n)
            # abs target
            if op in _TAKES_ABS_TARGET and n == 3:
                tgt = mem[pc + 1] | (mem[pc + 2] << 8)
                if start <= tgt < end_excl:
                    nxt.add(tgt)
            # branch target
            if op in _BRANCH_OPCODES and n == 2:
                off = mem[pc + 1]
                if off >= 0x80:
                    off -= 256
                tgt = (pc + 2 + off) & 0xFFFF
                if start <= tgt < end_excl:
                    nxt.add(tgt)
        nxt -= code
        code.update(nxt)
        pending = nxt
    return code


def classify(mem: bytes, code_starts: set[int],
             start: int, end_excl: int) -> tuple[dict[int, tuple[str, str, int]], set[int]]:
    """Walk the image and decide which addresses are instruction starts.

    Returns (instr_at, consumed) where:
      - instr_at[pc] = (mnemonic, mode, n_bytes) for accepted instruction starts
      - consumed = set of addresses occupied by operand bytes of accepted
        instructions (callers must not emit data for these).

    A code-start candidate is rejected when:
      - opcode byte isn't in the NMOS table (BRK and undocumented opcodes
        are valid in OPS but defMON code rarely starts on them — we keep
        them as instructions unless they conflict),
      - the instruction would run past `end_excl`,
      - an earlier accepted instruction's operand range already claims one
        of this instruction's bytes.
    """
    instr_at: dict[int, tuple[str, str, int]] = {}
    consumed: set[int] = set()
    for pc in sorted(code_starts):
        if pc < start or pc >= end_excl:
            continue
        op = mem[pc]
        info = OPS.get(op)
        if info is None:
            continue
        n = info[2]
        if pc + n > end_excl:
            continue
        operand_bytes = range(pc + 1, pc + n)
        if pc in consumed or any(b in consumed for b in operand_bytes):
            # this PC overlaps a previously-accepted operand: don't classify
            # it as an instruction start (the previous decode wins, and the
            # round-trip will reveal if that's wrong).
            continue
        if pc + 1 < end_excl and (pc + 1) in instr_at:
            # next byte was already accepted as an instruction; skip to
            # avoid consuming it.
            continue
        instr_at[pc] = info
        consumed.update(operand_bytes)
    return instr_at, consumed


# ── ASCII diagram renderer (shared infra) ────────────────────────────
# Single renderer used by:
#   - struct overlays (VoiceRecord, PatternStep, SidtabRow) — emits a
#     byte-cell grid above each struct definition so the reader sees the
#     field layout instead of scanning a list of offsets.
#   - memory map — vertical address-band grid keyed off the same shape.
#   - bit-packed fields (PatternStep.flag, SidtabRow.low_bitmap) — a
#     mini bit-cell grid below the parent byte cell.
# Inspired by the RFC packet-header convention
# (draft-mcquistin-augmented-ascii-diagrams), adapted from bit-wide to
# byte-wide cells since defMON's field widths are mostly whole bytes.
# All functions return list[str] of pre-formatted lines WITHOUT the
# leading `; ` comment marker — callers add it.


def _abbrev(name: str, width: int) -> str:
    """Fit ``name`` into ``width`` chars. Truncate with no marker (the
    diagram cell is narrow and trailing dots steal a char from every
    label that doesn't actually need them)."""
    return name[:width]


def _render_bit_layout(bit_layout: list[dict]) -> list[str]:
    """Render a bit-cell grid for a single byte's bit_layout.

    Each entry in ``bit_layout`` is either ``{"bit": N, "name": "..."}``
    (single bit) or ``{"bits": "hi..lo", "name": "..."}`` (bit range).
    Cells share a width auto-sized to fit the longest name plus a
    margin so labels never truncate. Bit 7 is leftmost (MSB-first),
    matching the C64 bit-numbering convention.

    Output: 4 lines — bit-number header, top border, name row, bottom
    border. Optional ``meaning`` fields on entries are surfaced below
    as a short legend by the caller, not here.
    """
    spans: list[tuple[int, int, str]] = []
    for ent in bit_layout:
        if "bit" in ent:
            b = int(ent["bit"])
            spans.append((b, b, ent.get("name", "")))
        elif "bits" in ent:
            hi_s, lo_s = ent["bits"].split("..")
            spans.append((int(hi_s), int(lo_s), ent.get("name", "")))
    covered = {b for hi, lo, _ in spans for b in range(lo, hi + 1)}
    for b in range(8):
        if b not in covered:
            spans.append((b, b, ""))
    spans.sort(key=lambda s: -s[0])

    per_bit = max((len(n) for _h, _l, n in spans), default=2) + 2
    per_bit = max(per_bit, 4)   # always at least "+-N-+"

    bit_row = "  "
    border = "  "
    name_row = "  "
    for hi, lo, name in spans:
        n_bits = hi - lo + 1
        cell_w = per_bit * n_bits + (n_bits - 1)   # share inner borders
        bit_nums = " ".join(str(b) for b in range(hi, lo - 1, -1))
        bit_row += " " + bit_nums.center(cell_w - 1)
        border += "+" + "-" * (cell_w - 1)
        name_row += "|" + name.center(cell_w - 1)
    return [
        bit_row,
        border + "+",
        name_row + "|",
        border + "+",
    ]


def _render_bit_layout_legend(bit_layout: list[dict]) -> list[str]:
    """Optional one-line-per-meaning legend under a bit_layout diagram.

    Returns [] when no entry carries a ``meaning`` field, so the
    diagram stays compact when the names speak for themselves.
    """
    out: list[str] = []
    for ent in bit_layout:
        meaning = ent.get("meaning")
        if not meaning:
            continue
        key = ent.get("name", "")
        out.append(f"    {key} = {meaning}")
    return out


def _render_struct_diagram(struct_def: dict,
                           instances: list[tuple[str, int]] | None = None,
                           cell_w: int = 8,
                           cols: int = 8) -> list[str]:
    """Render an RFC-style byte-cell grid for a fixed-size struct.

    ``struct_def`` shape (matches segments.json / VIRTUAL_STRUCT_SEGMENTS):
        {"name": "...", "size": <bytes>,
         "fields": [{"offset": N, "name": "...", "size": M,
                     "bit_layout": [...]?}, ...]}

    Produces a ``cols``-cell-wide grid with byte offsets labelled at the
    start of each row. Unnamed bytes show as blank cells so SMC/padding
    gaps are visually obvious. Fields with ``bit_layout`` metadata get
    a per-field bit-grid sub-diagram appended after the byte grid.
    """
    name = struct_def.get("name", "?")
    size = struct_def.get("size", 0)
    fields = struct_def.get("fields", [])
    field_by_off: dict[int, dict] = {f["offset"]: f for f in fields if "offset" in f}

    inner = cell_w - 1   # printable chars inside each cell (excludes the `|`)
    addr_col = " ${:02X}   "
    addr_pad = " " * len(addr_col.format(0))
    border = addr_pad + "+" + ("-" * inner + "+") * cols
    col_hdr = addr_pad + " " + "".join(f"+{i}".ljust(cell_w)[:cell_w]
                                       for i in range(cols))

    lines: list[str] = []
    lines.append(f"{name}  (size = ${size:02X} bytes = {size} B)")
    if instances:
        joined = ", ".join(f"{n} @ ${a:04X}" for n, a in instances)
        lines.append(f"  instances: {joined}")
    lines.append("")
    lines.append(col_hdr)

    n_rows = (size + cols - 1) // cols
    pending_empty = 0
    last_named_row = -1

    def _flush_empty(upto_row: int) -> None:
        """Render the deferred empty rows as either a single "..." line
        (run of 2+ rows) or as the original empty row (run of 1)."""
        nonlocal pending_empty
        if pending_empty >= 2:
            first = (upto_row - pending_empty) * cols
            last = min(upto_row * cols, size) - 1
            lines.append(addr_pad + f"  ...   (no named fields, "
                                    f"+${first:02X}..+${last:02X})")
        elif pending_empty == 1:
            empty_row = addr_col.format((upto_row - 1) * cols) + (
                "|" + " " * inner) * cols + "|"
            lines.append(border)
            lines.append(empty_row)
        pending_empty = 0

    for row in range(n_rows):
        row_start = row * cols
        cells = addr_col.format(row_start)
        row_has_field = False
        for col in range(cols):
            off = row_start + col
            if off >= size:
                cells += "|" + " " * inner
                continue
            fld = field_by_off.get(off)
            if fld is None:
                cells += "|" + " " * inner
                continue
            row_has_field = True
            label = _abbrev(fld.get("name", ""), inner)
            cells += "|" + label.center(inner)
        cells += "|"
        if not row_has_field:
            pending_empty += 1
            continue
        _flush_empty(row)
        lines.append(border)
        lines.append(cells)
        last_named_row = row
    # Tail: if the trailing rows were empty, collapse them too.
    if pending_empty:
        _flush_empty(n_rows)
    if last_named_row >= 0:
        lines.append(border)

    for f in fields:
        bl = f.get("bit_layout")
        if not bl:
            continue
        lines.append("")
        lines.append(f"  {name}.{f.get('name')}  "
                     f"(bit layout, byte +${f.get('offset', 0):02X})")
        lines.extend(_render_bit_layout(bl))
        legend = _render_bit_layout_legend(bl)
        if legend:
            lines.extend(legend)

    return lines


def _fmt_map_size(n: int) -> str:
    """Format a byte count for the memory-map size column (7 chars wide).
    Module-level so the map regression tests can assert displayed sizes
    against re-derived band lengths without duplicating the rule."""
    if n >= 1024 and n % 1024 == 0:
        return f"{n // 1024:5d} K"
    if n >= 1024:
        return f"{n / 1024:5.1f} K"
    return f"{n:5d} B"


def _render_memory_map_grid(rows: list[tuple[int, int, str, str]],
                            total_end: int = 0x10000) -> list[str]:
    """Render the address-band map as a vertical ASCII grid.

    ``rows`` = sorted list of ``(start, end_excl, label, kind)``.
    ``kind`` ∈ {"code", "data", "sys", "hw"} selects a fill glyph so
    the visual texture matches the band's character (code vs data vs
    system vs hardware overlay).

    Layout: a fixed-width grid where the left column is the start
    address, the middle column is a kind-glyph bar, and the right
    column is "label  size". Gaps between consecutive rows render as
    an explicit `— unused —` band so dead space is never invisible.
    """
    KIND_GLYPH = {"code": "█", "data": "▒", "hw": "░", "sys": "·",
                  "unused": " "}

    lines: list[str] = []
    bar_w = 8
    range_start = rows[0][0] if rows else 0
    lines.append(f"   addr   bar       size     band")
    lines.append(f"   -----  {'-' * bar_w}  -------  {'-' * 48}")
    last_end = range_start
    for start, end, label, kind in rows:
        if start > last_end:
            gap = start - last_end
            lines.append(
                f"   ${last_end:04X}  {' ' * bar_w}  {_fmt_map_size(gap)}  — unused —")
        size = end - start
        glyph = KIND_GLYPH.get(kind, " ")
        bar = glyph * bar_w
        lines.append(
            f"   ${start:04X}  {bar}  {_fmt_map_size(size)}  {label}")
        last_end = end
    if last_end < total_end:
        gap = total_end - last_end
        lines.append(
            f"   ${last_end:04X}  {' ' * bar_w}  {_fmt_map_size(gap)}  — unused —")
    lines.append("")
    lines.append("   Legend:  " + "  ".join(
        f"{KIND_GLYPH[k]} {desc}" for k, desc in [
            ("code", "code"), ("data", "data segment"),
            ("hw", "HW overlay"), ("sys", "system / KERNAL"),
        ]))
    return lines


# ── Hardware-register flag/value decoders ────────────────────────────
# Maps a hardware-register address to a function that turns the byte
# value being written into a short human-readable hint. Used by the emit
# loop to append a `; <decode>` tail to STA/STX/STY instructions whose
# target is a known register AND whose immediate value is known from an
# immediately-preceding LDA/LDX/LDY #imm. Hints are deliberately terse
# — the goal is to surface the operational intent (`enable IRQ on
# raster`, `BASIC off, KERNAL+I/O in`) without restating the full
# register's bit layout, which lives in the C64 reference docs.

def _decode_cpu_port(v: int) -> str:
    parts = []
    parts.append("BASIC " + ("in" if v & 0x01 else "out"))
    parts.append("KERNAL " + ("in" if v & 0x02 else "out"))
    parts.append("I/O " if v & 0x04 else "char ROM")
    if v & 0x20:
        parts.append("cas motor off")
    return ", ".join(parts)

def _decode_vic_cr1(v: int) -> str:
    parts = []
    if v & 0x80:
        parts.append("RST8")
    parts.append("ECM" if v & 0x40 else "ECM off")
    parts.append("BMM" if v & 0x20 else "text")
    parts.append("DEN" if v & 0x10 else "blank")
    parts.append("25 rows" if v & 0x08 else "24 rows")
    yscroll = v & 0x07
    parts.append(f"yscroll={yscroll}")
    return ", ".join(parts)

def _decode_vic_cr2(v: int) -> str:
    parts = []
    if v & 0x20:
        parts.append("RES")
    parts.append("MCM" if v & 0x10 else "MCM off")
    parts.append("40 cols" if v & 0x08 else "38 cols")
    parts.append(f"xscroll={v & 0x07}")
    return ", ".join(parts)

def _decode_vic_mem_ptr(v: int) -> str:
    matrix_base = ((v >> 4) & 0x0F) * 0x0400
    char_base = ((v >> 1) & 0x07) * 0x0800
    return f"matrix=${matrix_base:04X}, char=${char_base:04X}"

def _decode_vic_irq_mask(v: int) -> str:
    parts = []
    if v & 0x01: parts.append("raster")
    if v & 0x02: parts.append("sprite-bg coll")
    if v & 0x04: parts.append("sprite-sprite coll")
    if v & 0x08: parts.append("light pen")
    return "enable " + ("/".join(parts) if parts else "none")

def _decode_vic_sprite_enable(v: int) -> str:
    on = [str(i) for i in range(8) if v & (1 << i)]
    return f"sprites on: {'/'.join(on) if on else 'none'}"

def _decode_sid_ctrl(v: int) -> str:
    waves = []
    if v & 0x10: waves.append("TRI")
    if v & 0x20: waves.append("SAW")
    if v & 0x40: waves.append("PUL")
    if v & 0x80: waves.append("NOI")
    parts = ["+".join(waves) or "wave off"]
    if v & 0x01: parts.append("GATE")
    if v & 0x02: parts.append("SYNC")
    if v & 0x04: parts.append("RING")
    if v & 0x08: parts.append("TEST")
    return " ".join(parts)

def _decode_sid_vol_filter(v: int) -> str:
    parts = [f"vol={v & 0x0F}"]
    if v & 0x10: parts.append("LP")
    if v & 0x20: parts.append("BP")
    if v & 0x40: parts.append("HP")
    if v & 0x80: parts.append("V3 mute")
    return ", ".join(parts)

def _decode_cia_icr(v: int) -> str:
    action = "enable" if v & 0x80 else "disable"
    sources = []
    if v & 0x01: sources.append("TA")
    if v & 0x02: sources.append("TB")
    if v & 0x04: sources.append("TOD")
    if v & 0x08: sources.append("SP")
    if v & 0x10: sources.append("FLAG")
    return f"{action} " + ("/".join(sources) if sources else "(no sources)")

def _decode_cia_cra(v: int) -> str:
    parts = []
    parts.append("start TA" if v & 0x01 else "stop TA")
    if v & 0x02: parts.append("PB6 out")
    parts.append("one-shot" if v & 0x08 else "continuous")
    if v & 0x10: parts.append("force load")
    parts.append("count CNT" if v & 0x20 else "count φ2")
    if v & 0x40: parts.append("SP out")
    parts.append("TOD 50Hz" if v & 0x80 else "TOD 60Hz")
    return ", ".join(parts)

def _decode_cia_crb(v: int) -> str:
    parts = []
    parts.append("start TB" if v & 0x01 else "stop TB")
    if v & 0x02: parts.append("PB7 out")
    parts.append("one-shot" if v & 0x08 else "continuous")
    if v & 0x10: parts.append("force load")
    src = (v >> 5) & 0x03
    parts.append(["count φ2", "count CNT", "count TA underflow",
                  "count TA underflow & CNT"][src])
    if v & 0x80: parts.append("TOD-alarm-set mode")
    return ", ".join(parts)

HW_IMM_DECODERS: dict[int, Callable[[int], str]] = {
    0x0001: _decode_cpu_port,
    0xD011: _decode_vic_cr1,
    0xD015: _decode_vic_sprite_enable,
    0xD016: _decode_vic_cr2,
    0xD018: _decode_vic_mem_ptr,
    0xD019: _decode_vic_irq_mask,    # write-1-to-clear; same bit layout
    0xD01A: _decode_vic_irq_mask,
    0xD404: _decode_sid_ctrl, 0xD40B: _decode_sid_ctrl, 0xD412: _decode_sid_ctrl,
    0xD504: _decode_sid_ctrl, 0xD50B: _decode_sid_ctrl, 0xD512: _decode_sid_ctrl,
    0xD418: _decode_sid_vol_filter,
    0xD518: _decode_sid_vol_filter,
    0xDC0D: _decode_cia_icr, 0xDD0D: _decode_cia_icr,
    0xDC0E: _decode_cia_cra, 0xDD0E: _decode_cia_cra,
    0xDC0F: _decode_cia_crb, 0xDD0F: _decode_cia_crb,
}


def _emit_memory_map(fh,
                     mem: bytes,
                     base: int,
                     end_excl: int,
                     segments: list[dict],
                     hw_anchors: list[tuple[int, int, str]],
                     annotations: dict[int, dict],
                     labels: dict[int, str]) -> None:
    """Emit an auto-generated ASCII memory map of $0000-$FFFF.

    The map is data-driven, not hand-maintained: every band is sourced
    from one of (a) HW_ANCHOR_REGIONS — the system memory layout below
    $0800 and the I/O overlay at $D000-$DFFF; (b) Ghidra data segments
    — the typed song-data tables (pat_base, pattern_bank, sidtab_data,
    arrangers, etc.); (c) gaps between data segments inside the static
    image — labelled with the first [function]/[region] annotation in
    that gap. Sizes are computed from start/end_excl. The result is
    structural, not pretty — when a new segment is added or an
    annotation gets a new name the map updates on the next emit.
    """
    # ── system memory below + above the static image ────────────────────
    # The system layout is invariant across all C64 software; only the
    # SCREEN_RAM entry is sourced from hw_anchors (so renaming the
    # anchor in HW_ANCHOR_REGIONS flows here automatically).
    screen_ram_name = next(
        (n for s, _e, n in hw_anchors if s == 0x0400), "SCREEN_RAM")
    BELOW_IMAGE = [
        (0x0000, 0x0002, "CPU on-chip I/O (CPU_DDR, CPU_PORT)"),
        (0x0002, 0x0100, "zero page (system + defMON state vars)"),
        (0x0100, 0x0200, "6502 stack (page 1)"),
        (0x0200, 0x0400, "KERNAL workspace (TEXT_COLOR at $0286, ...)"),
        (0x0400, 0x0800, f"{screen_ram_name} (default video matrix, 4 pages)"),
    ]
    ABOVE_IMAGE = [
        (0xFF81, 0xFFFA, "KERNAL jumptable (KERNAL_CINT ... KERNAL_IOBASE)"),
        (0xFFFA, 0x10000, "hardware vectors (VEC_NMI/RESET/IRQ)"),
    ]

    # ── bands inside the static image ───────────────────────────────────
    # Strategy: every Ghidra data segment is a fixed boundary. Gaps
    # between consecutive segments (still inside [base, end_excl)) get
    # labelled "code" with the first [function]/[region] annotation in
    # that range as a hint. hw_anchors are NOT used here — they describe
    # runtime hardware overlays, not in-image bands (and ram_under_io
    # in particular overlaps COLOR_RAM numerically).
    image_segs = sorted(
        (s["start"], s["end_excl"], s.get("name", ""))
        for s in segments
        if s["end_excl"] > base and s["start"] < end_excl)
    sorted_ann = sorted(a for a in annotations if base <= a < end_excl)

    def _first_annotation_name(lo: int, hi: int) -> str:
        for addr in sorted_ann:
            if lo <= addr < hi and addr in labels:
                return labels[addr]
        return ""

    def _emptiness(lo: int, hi: int) -> str:
        """Tag a data band with its zero-fill share when it is mostly
        empty. Large defMON data segments are initialised working RAM
        (pattern_bank, sidtab_data, tail buffers) that ship zeroed or
        with a trivial default — the byte count overstates how much is
        actual content. Surfaced so the map matches the
        `data_region_coverage --profile` breakdown."""
        # mem is the full 64K image indexed by absolute address (classify
        # does mem[pc]), so slice with absolute lo/hi — not lo-base.
        span = mem[lo:hi]
        if not span:
            return ""
        zero_pct = 100 * span.count(0) // len(span)
        return f" (~{zero_pct}% zero)" if zero_pct >= 50 else ""

    image_bands: list[tuple[int, int, str, str]] = []
    cursor = base
    for start, end_excl_b, name in image_segs:
        b_start = max(start, base)
        b_end = min(end_excl_b, end_excl)
        if b_start > cursor:
            hint = _first_annotation_name(cursor, b_start)
            image_bands.append((cursor, b_start,
                                f"code (first: {hint})" if hint else "code",
                                "code"))
        image_bands.append((b_start, b_end, name + _emptiness(b_start, b_end),
                            "data"))
        cursor = max(cursor, b_end)
    if cursor < end_excl:
        hint = _first_annotation_name(cursor, end_excl)
        image_bands.append((cursor, end_excl,
                            f"code (first: {hint})" if hint else "code",
                            "code"))

    # ── I/O overlay rows shown alongside the static-image band ──────────
    # Below $D800 the static image holds RAM (ram_under_io covers the
    # LOAD/SAVE codec). $D800-$DFFF can never be reached from
    # static-image code at runtime — the C64 banks the I/O overlay in
    # for those addresses, exposing colour RAM + CIA + expansion port.
    IO_OVERLAY = [
        (0xD000, 0xD400, "VIC-II ($D000 sprites/raster/IRQ/colours)"),
        (0xD400, 0xD800, "SID (#1 at $D400, #2 at $D500 in stereo mode)"),
        (0xD800, 0xDC00, "COLOR_RAM (1000 visible nibbles + pad)"),
        (0xDC00, 0xDD00, "CIA1 (keyboard / joystick / Timer A → IRQ)"),
        (0xDD00, 0xDE00, "CIA2 (VIC bank / serial / Timer A → NMI)"),
        (0xDE00, 0xE000, "expansion port"),
    ]

    rows: list[tuple[int, int, str, str]] = []
    rows.extend((s, e, n, "sys") for s, e, n in BELOW_IMAGE)
    rows.extend(image_bands)
    rows.extend((s, e, n, "sys") for s, e, n in ABOVE_IMAGE)
    # Pull the high_mem_scratch_ff00 name from annotations so renaming
    # the annotation flows through to the map without editing this file.
    ff00_name = labels.get(0xFF00, "high_mem_scratch_ff00")
    rows.append((0xFF00, 0xFF01, f"{ff00_name} (LOAD dead-store)", "sys"))
    rows.sort()

    fh.write("; ──────────────────────────────────────────────────────────────────────\n")
    fh.write("; MEMORY MAP — auto-generated from segments + HW anchors + annotations\n")
    fh.write("; ──────────────────────────────────────────────────────────────────────\n")
    fh.write(";\n")
    for line in _render_memory_map_grid(rows):
        fh.write(f"; {line}\n" if line else ";\n")
    fh.write(";\n")
    fh.write(";   I/O overlay at $D000-$DFFF (visible when CHAREN/HIRAM bank "
             "the chips in):\n")
    io_rows: list[tuple[int, int, str, str]] = [
        (s, e, n, "hw") for s, e, n in IO_OVERLAY]
    for line in _render_memory_map_grid(io_rows, total_end=0xE000):
        fh.write(f"; {line}\n" if line else ";\n")
    fh.write(";\n")
    fh.write("; ──────────────────────────────────────────────────────────────────────\n")


def _emit_architecture_overview(fh) -> None:
    """Emit a comment-block "theory of operation" header into `defmon.s`.

    Ties together the major structural sections of the binary so a reader
    can navigate the body top-to-bottom without consulting an external
    reference. Pure prose; no code-facts here that aren't already in the
    relevant `[function]` / `[region]` annotations downstream.
    """
    block = """\
; ──────────────────────────────────────────────────────────────────────
; ARCHITECTURE OVERVIEW — theory of operation
; ──────────────────────────────────────────────────────────────────────
;
; defMON is a Commodore 64 music tracker. The static image at $0800-$E786
; is organised into six structural bands; each band is named and
; cross-referenced below. The bands are not page-aligned — they overlap
; freely and each section's exact start is documented at its [function]
; / [region] entry. The map is structural intent, not literal RAM page
; boundaries.
;
;   $0800-$0FFF  boot + main loop + NMI player driver ($0AED)
;   $1000-$17FF  player IRQ body — sub-frame ($1006), main-tick ($1003),
;                pitch / PS oscillator ($1405), per-voice cascade arms,
;                sidTAB writer ($16B0), pitch LUT ($1583/$161F)
;   $1800-$71FF  song RAM — pitch LUT ($1800-$19FF, regenerated at LOAD),
;                arrangers $1B/$1C/$1D (V0/V1/V2), pattern bank ($1F00+),
;                sidTAB body ($5F00), SID#2 arrangers $6E/$6F/$70 (V3-V5),
;                ui-state cluster ($7167+ mode/cursor/super-cmd flags)
;   $7400-$87FF  disk menu paint+input ($7423/$75DB), KERNAL save setup
;                ($789C), player-band helpers + status-line painters
;                ($83B6/$83D5/$83E2), super-command parser ($8244/$8368/
;                $844C), self-modifying field-writer dispatch ($85xx)
;   $8800-$AAFF  unrolled paint pages — 35 near-identical templates that
;                draw the seqED/seqLIST/sidTAB UI cells
;   $AE00-$DFFF  editor handler bands — seqED ($AE78), seqLIST ($E550),
;                sidTAB ($BBB5), secondary-disk ($C491); per-field writer
;                endpoints ($B3xx); SID#2 player mirror ($C800-$CFFF);
;                LOAD decoder ($D6C9) + save encoder ($D2xx-$D5xx); both
;                live in RAM-under-I/O at $D000-$DFFF
;   $E000-$E786  seqLIST writer band, post-LOAD reconstruction tail
;
; ── BOOT CHAIN ────────────────────────────────────────────────────────
;
; The disk-resident defMON ships as `defmon-packed.prg` (exomizer
; SYS-stub PRG). It self-decompresses to the static image and JMPs
; into the boot cold-start at $0826. Boot quiesces VIC + CIA at $0A3F,
; paints the 'defMON' splash via $0889 post_load_startup, installs the
; CIA-1 Timer-A IRQ vector → $0AED at $0A78, then falls into the
; main editor loop at $08AA. From there everything is event-driven:
; either a CIA IRQ fires the player, or the keyboard scanner ($0E47)
; produces a decoded key that the main loop's mode dispatcher ($0939)
; routes to the active mode handler.
;
; ── MAIN LOOP & MODE DISPATCH ─────────────────────────────────────────
;
; $08AA main_loop is a busy-wait barrier: read $0E44 kbd_decoded_key,
; BEQ stay-idle, else fall into the $0939 mode_dispatch byte. The
; dispatch byte is a self-modifying LDA-imm whose immediate operand is
; $7167 ui_mode (NOT a CMP — the LDA loads the mode, then a small
; cascade of CMP+BEQ arms picks one of four handlers:
;
;   $7167 = $01 → seqED handler           $AE78
;   $7167 = $02 → seqLIST handler         $E550
;   $7167 = $04 → sidTAB handler          $BBB5
;   $7167 = $20 → secondary_disk_mode     $C491
;
; The visible disk-menu ($75DB) is NOT mode $20 — it is a nested
; synchronous input loop invoked from $8244 by SHIFT+X, which suspends
; the main loop's dispatch for the menu's lifetime and leaves $7167
; at its prior value (typically $01 seqED) throughout. Mode $20 is a
; separate state reachable only from sidTAB via CTRL+/ ($BD5D).
;
; ── PLAYER IRQ ────────────────────────────────────────────────────────
;
; defMON installs a CIA-1 Timer-A IRQ at 23546 cycles (≈42 Hz), NOT
; the 50 Hz PAL VBL. The IRQ vector points at $0AED.
;
; $0AED is gated by a self-modifying byte at $0AF7 that doubles as the
; immediate operand of the LDA at $0AF6: stop_playback writes $00 there
; (BEQ short-circuits to exit), play_from_* writes non-zero (the body
; runs). The body splits into two cadences:
;
;   per-NMI    — every IRQ; runs $1006 sub_frame_player_update which
;                ticks the sidTAB cascade ($16B0 fan-out), runs the
;                pitch / PS oscillator ($1405), and emits SID writes
;                derived from the per-voice patch slots at $1023-$1087.
;
;   per-frame  — every N-th IRQ (N = $715C sub_frame_count, set per
;                tune to 1/2/4/8); runs $1003 player_play which walks
;                the arranger ($10EB row → $1B/$1C/$1D entry), reads
;                the pattern bank's 4-byte step record (flag, slot_a,
;                slot_b, note), and arms the per-voice cascade. GATE_N
;                (flag bit 4) must be set for a step to actually
;                produce sound — ungated steps are zeroed by the
;                player.
;
; The arranger has a JUMP-COMMAND escape: when an arranger entry's
; V0 column is $FF, that row is a jump marker; the V1[Y] column holds
; the JUMP TARGET song-position and the V2[Y] column holds the REPEAT
; COUNT (0 = infinite loop). The groove timer at $14EC/$14ED arms
; this on first visit and decrements per repeat.
;
; ── PATTERN DATA FLOW ─────────────────────────────────────────────────
;
;   song_position ($10EB)
;       │
;       ▼
;   arranger_v{0,1,2}_sid1[Y]   ($1B00 / $1C00 / $1D00, +$100 stride)
;       │       → pat_num (or $FF jump marker)
;       ▼
;   pat_base_{lo,hi}[pat_num]   ($1A00 / $1A80, per-pattern address LUT)
;       │       → 16-bit absolute address of this pattern's 128 B
;       ▼
;   pattern_bank ($1F00+)       — 32 steps × 4 bytes per voice
;       │       step record = (flag, slot_a, slot_b, note)
;       │       flag bit 4 = GATE_N — must be set or the note is muted
;       ▼
;   sidTAB cascade row ($5F00+) — column-encoded via JP ($1900,Y == 0
;       │       redirects to $1800,Y target) + DL ($1E00,Y step count)
;       ▼
;   $16B0 sidtab_row_apply      — per-column writers: CTRL, PW (12-bit
;       │       via $1023/$1025), AD, SR, TR, AF (portamento), PS
;       │       (pulse sweep), RE, FV, CP, ACID (filter cutoff slide)
;       ▼
;   per-voice patch slots in $1023-$1087 (V0/V1/V2 stride $31)
;       │
;       ▼
;   $D400-$D418 SID#1 registers (and $D420+/etc. for SID#2 when stereo)
;
; ── EDITOR BANDS ──────────────────────────────────────────────────────
;
; Each mode handler is a CMP+BNE cascade keyed on (modifier, decoded_key)
; pairs from $0E41/$0E44. Bare keys hit cascade arms in the handler's
; own band ($AE78-$B0xx for seqED, $E550-$E6xx for seqLIST, $BBB5-$BDA4
; for sidTAB); modifier-held chords route through a shared super-command
; parser ($8244 → $8368 arg prompt → $844C self-modifying field-writer
; dispatch). The field-writer dispatch lands at per-field endpoints in
; $B3xx (writer_note $B3DF, writer_clear_note $B3F6, writer_speed $B3FF,
; writer_sidcall $B396) for seqED and $E2xx for seqLIST.
;
; Pattern data ($1F00+) is the editor's direct write target. The
; cursor cluster at $71B8-$71D2 carries voice_selector ($71CD = voice
; × 9), step_cursor ($71D2), and writer_loop_count ($71CA) which the
; super-command parser uses for range-fill writes.
;
; ── DISK MENU + LOAD/SAVE ─────────────────────────────────────────────
;
; SHIFT+X ($AE80 / $80E0 / $E5xx — same dispatch from any mode) fires
; $8244 shift_x_disk_menu_chord, which JSRs $7423 disk_menu_entry. The
; entry helper paints the directory listing ($7400-$77FF), then enters
; a nested input loop at $75DB (NOT the main loop's $0939 dispatch).
; Keys read inside $75DB drive cursor walk ($760B), LOAD ($76C9 by
; cursor / $77xx by name), SAVE ($76E4), and exit ($76B6 LEFTARROW).
;
; LOAD decode lives at $D6C9 in RAM-under-I/O. It is a backward-RLE
; codec that walks the PRG body from end to start and writes to RAM
; via STA ($FD),Y. Termination is self-modified: $D6D9/$D6E0 SBC
; operands are patched to point at the song-floor ($1800 by default)
; before $CEE1 JSR $D6C9. Two post-LOAD passes then reconstruct
; runtime state from on-disk markers: $CF42 walks $1900,X for
; sidtab-row JP markers and rewrites them into pointers; $D004 mirrors
; the same pass for an adjacent table.
;
; SAVE encode lives at $D2xx-$D5xx (mirror of the LOAD decoder's
; layout). The JP-chain transitive walker at $D4F6 follows $1800/$1900
; reference chains via a $04F0,X visited bitmap so JP-target rows
; serialise correctly. write_defmon (the Python codec at
; tools/songfmt/encode_load_format.py) is the reference inverse.
;
; ── STEREO / SID#2 MIRROR ─────────────────────────────────────────────
;
; When $715D stereo_enable = $01, the player IRQ at $0AED conditionally
; fires SID#2 versions of the per-frame and sub-frame paths:
;
;   $1003 (SID#1 main_tick)  → also JSR $C803 (SID#2 main_tick)
;   $1006 (SID#1 sub_frame)  → also JSR $C806 (SID#2 sub_frame)
;
; The SID#2 mirror at $C800-$CFFF is a near-1:1 copy of $1000-$17FF
; with its arrangers at $6E00/$6F00/$7000 (V3/V4/V5) and pattern
; data shared with SID#1 (both chips read the same $1F00 pattern bank).
; SID#2 register fan-out targets the base address in $7164/$7165
; (cycles $D420/$D500/$DE00/$DF00 etc. via CTRL+SHIFT+UP).
;
; ── KEY INVARIANTS (LOAD-BEARING) ─────────────────────────────────────
;
;   - $0AF7 IS BOTH the LDA-imm operand AND the play-state flag inside
;     $0AED. Patching it is how stop/start actually works.
;   - $10D8 IS BOTH an opcode byte AND a sentinel: per-NMI patch + restore.
;   - $1019 / $104A / $107B per-voice records are INTERLEAVED with
;     SID-write code at $1022+; do not reorder instructions inside this
;     band, the operand byte offsets are load-bearing.
;   - $1800-$19FF carries TWO unrelated payloads at different lifecycle
;     phases: the on-disk JP-marker tables (between KERNAL LOAD and
;     $D6C9 decode), and the runtime pitch LUT (after $D6C9 regenerates
;     it). They share the same address range.
;   - The visible disk menu suspends $0939 mode_dispatch but does NOT
;     change $7167 ui_mode. Use screen-diff (not current_mode()) to
;     detect the menu being visible.
;   - The super-command parser at $8244 expects CTRL held ACROSS the
;     prefix letter AND the typed-digit suffix. Releasing CTRL between
;     prefix and digit re-routes the digit through the mode handler.
;
; ── BRANCH-CONDITION CONVENTIONS ──────────────────────────────────────
;
; Conditional branches render with two halves: the operand is the
; canonical target label (or the `<region> + $offset` fallback when
; the target lands mid-region) and the EOL comment is past-tense
; readable prose describing what condition brought control here. The
; prose is auto-derived from cmp_facts — a CFG-walked dataflow
; summary of each branch's lhs/rhs and the most recent flag-setting
; op. Example shapes:
;
;     bne  main_loop_close    ; ui_mode was not UI_MODE_SEQED?
;     beq  l_2                ; kbd_decoded_key was $6F?
;     bpl  l_1                ; $05 walked back 1 and had bit 7 clear?
;
; The "walked back N" / "stepped N" form collapses a uniform chain of
; INX/INY/INC (stepped) or DEX/DEY/DEC (walked back) atoms before a
; BPL/BMI on lhs-zero. Heterogeneous chains keep the literal
; `((src + 1) − 1) + 1 …` transcription.
;
; When the source variable has no symbolic name but falls inside a
; [function]-annotated block, the slug renders as
; `<block_name>_$<offset_hex>` instead of raw `$XXXX`, telling the
; reader WHERE in the program the SMC slot lives.
;
; Per-instance pre-comments above each step-idiom branch lay these
; pieces out vertically so the reader can see the source / step count
; / branch test side-by-side without parsing the slug.
;
; ──────────────────────────────────────────────────────────────────────
"""
    fh.write(block)


# Virtual struct segments — describe layouts where the bytes live
# INSIDE disassembled instructions (operand bytes of self-modifying
# loads in the player IRQ). Ghidra can't `createData` over them
# without clashing with the code, so they're not in `ghidra_import.py`
# DATA_SEGMENTS. The operand resolver still gets to render addresses
# in these ranges via `<seg> + <element_idx>*<E>_size + <E>_<field>`
# expressions, and the STRUCT EQUATES block names the field offsets.
#
# Voice record map (per-voice $31-byte stride; V0/V1/V2 at $1019/$104A/
# $107B). Offsets named here are the patched immediate-operand bytes
# that double as runtime register state — see `[region.$1019]` in
# annotations.toml + the field labels (pw_lo_patch_v0 at $1023,
# ps_depth_v0 at $101E, etc.) which always win over the struct
# expression at their exact addresses.
_VOICE_RECORD_STRUCT: dict = {
    "element": {
        "name": "VoiceRecord",
        "size": 0x31,
        "fields": [
            {"name": "slide_acc_lo", "offset": 0x01, "size": 1,
             "comment": "slide accumulator low byte (v0_slide_acc)"},
            {"name": "slide_mode", "offset": 0x02, "size": 1,
             "comment": "slide mode: neg=down, pos=up, 0=hold"},
            {"name": "ps_depth", "offset": 0x05, "size": 1,
             "comment": "pulse-sweep / vibrato depth; "
                        "signed (bit7=direction)"},
            {"name": "pitch_base", "offset": 0x06, "size": 1,
             "comment": "per-voice detune ($00/$01/$02 for V0/V1/V2)"},
            {"name": "voice_bit_mask", "offset": 0x07, "size": 1,
             "comment": "voice select mask: $01/$02/$04 for V0/V1/V2"},
            {"name": "voice_bit_complement", "offset": 0x08, "size": 1,
             "comment": "complement of voice_bit_mask: $FE/$FD/$FB"},
            {"name": "pw_lo", "offset": 0x0A, "size": 1,
             "comment": "PW lo immediate operand "
                        "(also slide-acc transient lo)"},
            {"name": "pw_hi", "offset": 0x0C, "size": 1,
             "comment": "PW hi immediate operand "
                        "(also slide-acc transient hi)"},
            {"name": "freq_lo", "offset": 0x0E, "size": 1,
             "comment": "FREQ lo immediate operand patched by pitch oscillator"},
            {"name": "freq_hi", "offset": 0x0F, "size": 1,
             "comment": "FREQ hi immediate operand"},
        ],
    },
}

VIRTUAL_STRUCT_SEGMENTS: list[dict] = [
    {
        "start": 0x1019,
        "end_excl": 0x1019 + 3 * 0x31,
        "name": "voice_record_v0",
        "comment": "Per-voice working record table (V0/V1/V2 strided $31).",
        "struct": _VOICE_RECORD_STRUCT,
        "instances": [
            ("voice_record_v0", 0x1019),
            ("voice_record_v1", 0x104A),
            ("voice_record_v2", 0x107B),
        ],
    },
    {
        "start": 0xC819,
        "end_excl": 0xC819 + 3 * 0x31,
        "name": "sid2_voice_record_v0",
        "comment": "SID#2 mirror of voice_record_v0 (same $31-byte layout; "
                   "writes go to $D500+ via the SMC patch sites instead of "
                   "$D400+).",
        "struct": _VOICE_RECORD_STRUCT,
        "instances": [
            ("sid2_voice_record_v0", 0xC819),
            ("sid2_voice_record_v1", 0xC84A),
            ("sid2_voice_record_v2", 0xC87B),
        ],
    },
]


def emit_source(mem: bytes, base: int, end_excl: int,
                instr_at: dict[int, tuple[str, str, int]],
                consumed: set[int], fh,
                labels: dict[int, str] | None = None,
                segments: list[dict] | None = None,
                annotations: dict[int, dict] | None = None,
                graph=None,
                with_bytes: bool = False,
                text_segments: dict[int, dict] | None = None,
                byte_runs: dict[int, list[dict]] | None = None,
                imm_subs: dict[int, str] | None = None,
                value_names_per_var: dict[int, dict[int, str]] | None = None,
                branch_operand_override: dict[int, str] | None = None,
                cmp_facts: dict[int, dict] | None = None,
                branch_condition_overrides: dict[int, str] | None = None,
                named_constants: dict[str, int] | None = None,
                smc_dispatch: dict[int, dict] | None = None,
                smc_branch: dict[int, dict] | None = None,
                smc_opcode: dict[int, dict] | None = None,
                switch_dispatchers: dict[int, dict] | None = None,
                register_inputs: dict[int, dict[str, int]] | None = None,
                ) -> tuple[int, int]:
    """Emit the .s body. Returns (instr_count, data_byte_count).

    ``labels`` is an {addr: name} dict used both for line prefixes at
    code-start positions and for operand resolution inside
    ``emit_64tass_instruction``.

    ``segments`` is an optional list of Ghidra data-segment dicts
    (see ``load_ghidra_segments``). When the emitter crosses a
    segment boundary we emit a header comment ("; ─── segment name ───")
    so the resulting source has clear chapter markers between the
    untyped code/data regions and the named tables (sidTAB, arrangers,
    pat_base, pattern bank, etc.)."""
    labels = dict(labels) if labels else {}
    segments = segments or []
    annotations = annotations or {}
    text_segments = text_segments or {}
    byte_runs = byte_runs or {}
    imm_subs = imm_subs or {}
    value_names_per_var = value_names_per_var or {}
    branch_operand_override = branch_operand_override or {}
    cmp_facts = cmp_facts or {}
    branch_condition_overrides = branch_condition_overrides or {}
    named_constants = named_constants or {}
    smc_dispatch = smc_dispatch or {}
    smc_branch = smc_branch or {}
    smc_opcode = smc_opcode or {}
    switch_dispatchers = switch_dispatchers or {}
    register_inputs = register_inputs or {}

    # SMC-target audit: every address that's the operand of an
    # STA/STX/STY-abs anywhere in the disassembled image. The imm-mode
    # comment emitter uses this to classify each immediate's operand
    # byte (at pc+1) as:
    #   * in_targets + labelled   → `← <slot_name>` (catalogued SMC)
    #   * in_targets + no label   → `← (SMC operand, no name)` (flagged)
    #   * not in_targets          → real constant, no comment
    # We restrict to abs-mode (no abx/aby) because indexed stores walk
    # tables, not single SMC slots — abx/aby targets would over-flag.
    smc_write_targets: set[int] = set()
    _STA_FAMILY_ABS = {"STA", "STX", "STY"}
    for _pc, (_m, _mode, _n) in instr_at.items():
        if _m in _STA_FAMILY_ABS and _mode == "abs":
            smc_write_targets.add(mem[_pc + 1] | (mem[_pc + 2] << 8))

    def _emit_switch_header(pc: int) -> str:
        """Render a Ghidra-style switch comment block above the first
        CMP of a detected dispatcher cascade. Each case shows the value
        (symbolic via value_names when available) and the handler PC —
        the address execution reaches when that case matches, regardless
        of cascade flavour (fall-through for BNE, taken for BEQ)."""
        entry = switch_dispatchers.get(pc)
        if not entry:
            return ""
        var_name = entry["var_name"]
        cases = entry["cases"]
        lines = [f"; ─── switch ({var_name}) — {len(cases)} cases ───\n"]
        for c in cases:
            val_s = (c.get("value_name") or f"${c['value']:02X}")
            tgt = (c.get("handler_label")
                   or (f"${c['handler_pc']:04X}" if c.get("handler_pc") is not None
                       else "?"))
            lines.append(f";     case {val_s:<22} → {tgt}\n")
        default_label = entry.get("default_label")
        default_pc = entry.get("default_pc")
        if default_label or default_pc is not None:
            default_text = (default_label
                            or f"${default_pc:04X}")
            lines.append(f";     default                   → {default_text}\n")
        return "".join(lines)

    def _emit_smc_opcode_header(pc: int) -> str:
        """Render a comment above an SMC-patched opcode-flip site.

        The OPCODE byte of the host instruction is rewritten at runtime
        — the reader sees one mnemonic in the listing but the CPU may
        execute a different instruction. Header shows current mnemonic
        + any candidate mnemonics traced from the writer's source
        value. "Inconclusive" entries mean the writer is register-
        sourced or the trace window was too short; flagged for human
        review."""
        entry = smc_opcode.get(pc)
        if not entry:
            return ""
        sources = entry.get("patch_sources") or []
        cur = entry.get("current_mnem") or "?"
        candidates = entry.get("candidate_opcodes") or []
        inconclusive = entry.get("inconclusive", False)
        ps_text = ", ".join(f"${p:04X}" for p in sources) or "(unknown)"
        lines = [f"; ──── SMC-patched OPCODE — instruction TYPE changes at runtime ────\n",
                 f";   Patched at: {ps_text}\n"]
        if candidates:
            cand_text = " / ".join(candidates)
            lines.append(f";   {cur} can flip to: {cand_text}\n")
        elif inconclusive:
            lines.append(f";   {cur} writer-source inconclusive "
                         f"(register-sourced or chained — curate me)\n")
        # Structured flip targets (e.g. the JMP landing of a STX->JMP
        # voice-skip) — rendered from the annotation so the address stays
        # out of the free-text description.
        targets = entry.get("targets") or []
        if targets:
            lines.append(";   When patched, jumps to:\n")
            for t in targets:
                ctx = f"  [{t['context']}]" if t.get("context") else ""
                lines.append(f";     ${t['addr']:04X}  {t.get('name', ''):<28}{ctx}\n")
        desc = (entry.get("description") or "").strip()
        if desc:
            for line in desc.split("\n"):
                lines.append(f";   {line}\n")
        return "".join(lines)

    def _emit_smc_branch_header(pc: int) -> str:
        """Render a short comment line above a SMC-patched branch.

        Branch SMC sites have a 1-byte offset operand patched by another
        site (at load or at runtime), so the static target shown in the
        listing is the UNPATCHED default. We cannot enumerate possible
        targets (a byte covers ±128 PCs), so the comment just warns +
        lists patch sources + carries the optional curator description.
        """
        entry = smc_branch.get(pc)
        if not entry:
            return ""
        sources = entry.get("patch_sources") or []
        ps_text = ", ".join(f"${p:04X}" for p in sources) or "(unknown)"
        lines = [f"; ──── SMC-patched branch — static target is the unpatched default ────\n",
                 f";   Patched at: {ps_text}\n"]
        desc = (entry.get("description") or "").strip()
        if desc:
            for line in desc.split("\n"):
                lines.append(f";   {line}\n")
        return "".join(lines)

    def _emit_smc_dispatch_header(pc: int) -> str:
        """Render a comment block above a SMC-patched JSR or JMP site.

        Curated sites (with `targets`) get the full target list. Sites
        marked only by auto-discovery get a "targets uncatalogued"
        marker — patch sources still surface so the reader can trace
        the dispatch manually.
        """
        entry = smc_dispatch.get(pc)
        if not entry:
            return ""
        targets = entry.get("targets") or []
        patch_sources = entry.get("patch_sources") or []
        desc = (entry.get("description") or "").strip()
        ps_text = ", ".join(f"${p:04X}" for p in patch_sources) or "(unknown)"
        host_mnem, _, _ = instr_at.get(pc, ("?", "", 0))
        host_label = host_mnem.upper() if host_mnem else "dispatch"
        if targets:
            header = (f"; ──── SMC-patched {host_label} "
                      f"({len(targets)} catalogued targets) ────\n")
        else:
            header = (f"; ──── SMC-patched {host_label} "
                      "(targets uncatalogued) ────\n")
        lines = [header,
                 f";   Patched at: {ps_text}\n"]
        if desc:
            # Word-wrap roughly to 76 cols for readability.
            words = desc.split()
            line: list[str] = []
            width = 0
            for w in words:
                if width + len(w) + 1 > 70 and line:
                    lines.append(";   " + " ".join(line) + "\n")
                    line = [w]
                    width = len(w)
                else:
                    line.append(w)
                    width += len(w) + 1
            if line:
                lines.append(";   " + " ".join(line) + "\n")
        if targets:
            lines.append(";   Targets:\n")
            for t in targets:
                addr = t.get("addr")
                name = t.get("name") or ""
                ctx = t.get("context") or ""
                ctx_text = f"  [{ctx}]" if ctx else ""
                if isinstance(addr, int):
                    lines.append(f";     ${addr:04X}  {name:<32}{ctx_text}\n")
        return "".join(lines)

    # Struct-typed segments (subset of `segments` that carry a Ghidra-
    # exported struct layout) plus VIRTUAL_STRUCT_SEGMENTS (struct
    # layouts that overlay code regions and so aren't Ghidra-applied).
    # Threaded into emit_64tass_instruction so ABS/ABX/ABY/IND operands
    # that fall inside such a segment but have no explicit label render
    # as `<seg> + <expr>` instead of bare hex. Hand-curated labels in
    # `labels` always take precedence. Virtual segments are kept out of
    # the data-segment header pass (they don't represent contiguous
    # data) — they only feed the resolver + STRUCT EQUATES block.
    struct_segments = [s for s in segments if "struct" in s]
    struct_segments.extend(VIRTUAL_STRUCT_SEGMENTS)

    # Tile of (start, end_excl, name) triples derived from the annotation
    # catalogue. Last-resort fallback in `emit_64tass_instruction` for
    # ABS operands whose target lands inside an annotated span but not on
    # the exact start byte — renders `name + $offset` so SMC-operand-byte
    # writes (`sta $11A2`) surface as `sta v0_gate_n_branch + $01`.
    # Restricted to addresses that came from `annotations` (i.e. authored
    # [function]/[region] entries) so synthetic + hardware-register
    # labels in `labels` (VIC_BORDER etc.) don't create spurious spans
    # like `VIC_BORDER + $03` for adjacent I/O addresses. Spans
    # straddling the I/O boundary at $D800 are clipped there so
    # colour-RAM/CIA addresses never inherit a static-image name (e.g.
    # the LOAD's `psid_export_template` at $D7F8..$D8FC stops at $D800;
    # runtime `sta $D801,X` to colour RAM never resolves to
    # `psid_export_template + $09`).
    annotated_addrs = sorted(a for a in annotations
                             if base <= a < end_excl and a in labels)
    name_spans: list[tuple[int, int, str]] = []
    for i, addr in enumerate(annotated_addrs):
        nxt = annotated_addrs[i + 1] if i + 1 < len(annotated_addrs) else end_excl
        if addr < 0xD800 < nxt:
            nxt = 0xD800
        name_spans.append((addr, nxt, labels[addr]))

    # Validate every text segment against the binary up front so a typo
    # in annotations.toml fails fast (with a clear error pointing at the
    # mismatched address) instead of silently emitting wrong bytes.
    for ts_addr, ts in text_segments.items():
        encoded = _encode_text(ts["string"], ts["encoding"]) * ts.get("reps", 1)
        actual = mem[ts_addr:ts_addr + len(encoded)]
        if actual != encoded:
            raise SystemExit(
                f"text_segments[${ts_addr:04X}]: declared string "
                f"{ts['string']!r} (×{ts.get('reps', 1)}) encodes to "
                f"{encoded.hex()} but image has {actual.hex()} — "
                f"fix the annotation")

    for br_addr, runs in byte_runs.items():
        encoded = _byte_runs_encoded(runs)
        actual = mem[br_addr:br_addr + len(encoded)]
        if actual != encoded:
            raise SystemExit(
                f"byte_runs[${br_addr:04X}]: declared runs encode to "
                f"{encoded.hex()} but image has {actual.hex()} — "
                f"fix the annotation")

    fh.write("; defMON static image — annotated 64tass source.\n")
    fh.write(";\n")
    fh.write(f"; Layout: ${base:04X}-${end_excl - 1:04X} "
             f"({end_excl - base} bytes), byte-identical to the\n"
             "; uncompressed PRG body.\n")
    fh.write(";\n")
    _emit_architecture_overview(fh)
    fh.write("\n")
    _emit_memory_map(fh, mem, base, end_excl, segments, HW_ANCHOR_REGIONS,
                     annotations, labels)
    fh.write("\n")

    def _enclosing_label(pc: int) -> str:
        """Return the name of the labelled region that contains pc.

        Walks back from pc through `labels` to find the nearest label
        at or before this address. Used to annotate xref-ghost sources
        with the data span they live in (e.g. `$7583 in
        disk_confirm_prompt_template`).
        """
        cur = pc
        while cur >= base:
            if cur in labels:
                return labels[cur]
            cur -= 1
        return ""

    def _format_apparent_sources(srcs: list[int], limit: int = 4) -> str:
        out = []
        for pc in sorted(set(srcs))[:limit]:
            container = _enclosing_label(pc)
            if container:
                out.append(f"${pc:04X} in {container}")
            else:
                out.append(f"${pc:04X}")
        extra = len(set(srcs)) - limit
        if extra > 0:
            out.append(f"... +{extra} more")
        return ", ".join(out)

    def _graph_dead_lines(addr: int) -> list[str]:
        """Reachability lines for an address with no code edges.

        Returns lines (each without leading `;   ` — caller adds it)
        when the graph confirms code_in is empty. Returns [] when
        either the graph is absent, the address has live code edges,
        or the address is outside the image.

        When code_in is empty but the address has a fall-through
        predecessor, the block surfaces that — the function is live
        but reached only by falling off the previous instruction, not
        by JSR / JMP / branch. Without this channel the block reads as
        "code edges: none / apparent: none" and the reader concludes
        the address is orphaned.
        """
        if graph is None:
            return []
        if not (base <= addr < end_excl):
            return []
        code_in = graph.code_in.get(addr, [])
        if code_in:
            return []
        apparent = graph.apparent_in_from_data.get(addr, [])
        ft_src = graph.fall_through_in.get(addr)
        if ft_src is not None:
            delta = addr - ft_src
            ft_label = labels.get(ft_src, "")
            if ft_label:
                ft_text = f"${ft_src:04X} {ft_label}"
            else:
                enclosing = _enclosing_label(ft_src)
                ft_text = (f"${ft_src:04X} in {enclosing}" if enclosing
                           else f"${ft_src:04X}")
            lines = [f"code edges:          fall-through from {ft_text} "
                     f"({delta} bytes earlier)"]
            if apparent:
                lines.append(f"apparent (from data): "
                             f"{_format_apparent_sources(apparent)}")
            return lines
        # No code edges, no fall-through predecessor. Only emit a
        # reachability block when the data-byte channel actually has
        # sources; otherwise "code edges: none / apparent: none" is
        # pure boilerplate and the address simply has no callers.
        if not apparent:
            return []
        return ["code edges:          none",
                f"apparent (from data): "
                f"{_format_apparent_sources(apparent)}"]

    def _derived_callers_line(addr: int, ann: dict | None) -> str:
        """Graph-derived `callers:` rendering.

        Returns "" when (a) the graph is absent, (b) the annotation
        has a hand-written `callers` string (the hand value takes
        precedence — callgraph-check surfaces mismatches), or (c)
        the graph has no code-edge inbounds (the existing dead-path
        block already says so).

        Format:
            12 code sites: $08AA main_loop, $0E47 kbd_scan, ... +8 more
        """
        if graph is None:
            return ""
        if ann and isinstance(ann.get("callers"), str) and ann["callers"]:
            return ""
        if not (base <= addr < end_excl):
            return ""
        srcs = sorted(set(graph.code_in.get(addr, [])))
        if not srcs:
            return ""
        cap = 8
        parts = []
        for pc in srcs[:cap]:
            name = labels.get(pc, "")
            parts.append(f"${pc:04X}" + (f" {name}" if name else ""))
        extra = len(srcs) - cap
        if extra > 0:
            parts.append(f"+{extra} more")
        return f"{len(srcs)} code sites: " + ", ".join(parts)

    def _constraints_lines(ann: dict | None) -> list[str]:
        """Lines for the `constraints` block (do_not_reorder / load-
        bearing offsets / because). Returns [] when no constraints set.

        The block reads as a short table — sub-key, value, optional
        explanation — so the reader sees the invariant before they get
        to free-form notes.
        """
        if not ann:
            return []
        c = ann.get("constraints")
        if not isinstance(c, dict):
            return []
        out: list[str] = []
        if c.get("do_not_reorder") is True:
            out.append("do_not_reorder       true")
        lbo = c.get("load_bearing_offsets") or []
        if lbo:
            out.append(f"load_bearing_offsets {', '.join(lbo)}")
        because = c.get("because", "")
        if because:
            out.append(f"because              {because}")
        return out

    # Pass-2: emit equates for every label whose address is NOT a
    # code-start. Code-starts emit a `label:` prefix on their
    # instruction line, so they don't need a separate equate. Data-
    # segment labels (pat_base_lo @ $1A00), ZP state vars (kbd_modifiers
    # @ $0E41, cbm_drive_num @ $00BA), and out-of-range references
    # (e.g. $D000 VIC-II SFRs if Ghidra has them) all need an equate
    # so 64tass can resolve operand references like `sta sid_chip_view`.
    #
    # Addresses claimed by .virtual/.dstruct emission (struct instances)
    # are filtered out — declaring them as both an equate and a .dstruct
    # label is a duplicate-symbol error.
    virtual_instance_addrs: set[int] = set()
    for seg in struct_segments:
        for _name, inst_addr in seg.get("instances", []):
            virtual_instance_addrs.add(inst_addr)
    equate_labels = [(addr, name) for addr, name in labels.items()
                     if addr not in instr_at
                     and addr not in virtual_instance_addrs]
    equate_labels.sort()
    # Set of names whose addresses are code-starts. Used to strip
    # forward-reference sentences from EQUATE notes — when a variable's
    # notes describe what some named function does to it, the reader
    # encounters the prose before the function has been introduced.
    # The same prose lives (or belongs) at the function's block header.
    code_start_names = {labels[a] for a in instr_at if a in labels}
    code_ref_re = re.compile(
        r"\b(?:" + "|".join(re.escape(n) for n in sorted(code_start_names, key=len, reverse=True)) + r")\b"
    ) if code_start_names else None

    def _strip_forward_refs(text: str) -> str:
        """Drop sentences/lines that mention a code-start label.

        EQUATE notes that say "X writes #$35 to this variable" are
        valuable, but the reader hits them before any code has been
        introduced. The same fact lives at X's function block (or
        ought to). Strip those sentences here; keep ones that describe
        the variable's storage shape, defaults, or layout.

        Paragraph-by-paragraph, sentence-by-sentence:
          - Lines that look like bulleted Sequence: blocks are dropped
            wholesale when ANY bullet references a code-start.
          - Otherwise split on `. ` and drop only the sentences that
            reference a code-start name; rejoin the survivors.
        """
        if not text or code_ref_re is None:
            return text
        out_paragraphs: list[str] = []
        for para in text.split("\n\n"):
            stripped = para.rstrip()
            # Bullet-block detection: paragraph contains "  - " bullets.
            if re.search(r"^\s*-\s", stripped, re.MULTILINE):
                if code_ref_re.search(stripped):
                    continue  # drop the whole bulleted block
                out_paragraphs.append(stripped)
                continue
            # Sentence-by-sentence prose. Only split on `.` followed by
            # whitespace + capital letter, so "e.g.", "i.e.", and abbrev
            # patterns don't cleave a sentence mid-word.
            sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", stripped)
            kept = [s for s in sentences if not code_ref_re.search(s)]
            if kept:
                out_paragraphs.append(" ".join(kept))
        return "\n\n".join(out_paragraphs).strip()

    # Region bands for the equates dump. Each entry is (start_addr,
    # heading); the equate at address A is placed under the last band
    # whose start_addr <= A. Bands track the architecture overview's
    # structural map so equates aren't a flat 686-line wall.
    _EQUATE_BANDS = [
        (0x0000, "ZERO PAGE ($0000-$00FF)"),
        (0x0100, "STACK + KERNAL VECTORS ($0100-$03FF)"),
        (0x0400, "SCREEN RAM ($0400-$07FF)"),
        (0x0800, "BOOT + MAIN LOOP + NMI PLAYER ($0800-$0FFF)"),
        (0x1000, "PLAYER IRQ — SUB-FRAME + MAIN-TICK + PITCH LUT ($1000-$17FF)"),
        (0x1800, "SONG RAM — ARRANGERS, PATTERN BANK, sidTAB ($1800-$71FF)"),
        (0x7100, "UI STATE CLUSTER ($7100-$73FF)"),
        (0x7400, "DISK MENU + SAVE PATH + STATUS PAINTERS ($7400-$87FF)"),
        (0x8800, "UNROLLED PAINT PAGES ($8800-$AAFF)"),
        (0xAB00, "EDITOR HANDLERS — seqED / seqLIST / sidTAB ($AB00-$CFFF)"),
        (0xD000, "C64 SFRs (VIC / SID / CIA) + RAM-UNDER-IO LOAD/SAVE CODEC ($D000-$DFFF)"),
        (0xE000, "seqLIST WRITER BAND + POST-LOAD TAIL ($E000-$E786)"),
        (0xFF00, "KERNAL JUMPTABLE ($FF00-$FFFF)"),
    ]

    def _band_for(addr: int) -> int:
        """Return the index of the last band whose start <= addr."""
        idx = 0
        for i, (start, _heading) in enumerate(_EQUATE_BANDS):
            if start <= addr:
                idx = i
            else:
                break
        return idx

    instance_segments = [s for s in struct_segments if s.get("instances")]
    flat_segments = [s for s in struct_segments if not s.get("instances")]

    # ── Native 64tass struct definitions + .virtual / .dstruct instance
    # overlays. Used for segments whose member bytes are SMC operand
    # bytes interleaved with code (no real .byte emission possible) —
    # .virtual discards compilation so PC advances + dotted field labels
    # resolve, but no bytes are emitted. Operand resolver renders as
    # `<instance>.<field>` (see render_struct_offset).
    if instance_segments:
        bar = "; " + "─" * 70 + "\n"
        fh.write(bar)
        fh.write("; VIRTUAL STRUCT INSTANCES — typed overlays for SMC-operand bands.\n")
        fh.write(";   .struct definition + per-instance .virtual / .dstruct blocks.\n")
        fh.write(";   .virtual discards compilation so the bytes at these addresses\n")
        fh.write(";   are NOT emitted here — the player-IRQ instruction stream below\n")
        fh.write(";   produces them as the operand bytes of self-modifying loads/stores.\n")
        fh.write(";   The dotted field labels (e.g. `voice_record_v0.freq_lo`) resolve\n")
        fh.write(";   at assemble time, replacing the prior\n")
        fh.write(";   `<seg> + N*Element_size + Element_<field>` flat-equate form.\n")
        fh.write(bar)
        emitted_struct_defs: set[str] = set()
        for seg in instance_segments:
            struct = seg.get("struct") or {}
            element = struct.get("element") or {}
            ename = element.get("name")
            esize = element.get("size")
            if not (ename and esize):
                continue
            if ename not in emitted_struct_defs:
                # Gather all instances of this struct across segments
                # so the diagram lists every overlay site in one place.
                all_instances: list[tuple[str, int]] = []
                for s2 in instance_segments:
                    if (s2.get("struct") or {}).get("element", {}).get(
                            "name") == ename:
                        all_instances.extend(s2.get("instances", []))
                fh.write("\n")
                # Auto-pick cell width and column count. Wider cells fit
                # longer field names without truncation; lower column
                # counts keep the diagram terminal-friendly for small
                # structs. Truncation is acceptable since the per-field
                # equate block below carries the full name unabbreviated.
                max_field_w = max(
                    (len(f.get("name", "")) for f in element.get("fields", [])),
                    default=4)
                cell_w = min(14, max(8, max_field_w + 2))
                cols = 8 if esize > 16 else min(esize, 8)
                for line in _render_struct_diagram(element, all_instances,
                                                   cell_w=cell_w, cols=cols):
                    fh.write(f"; {line}\n" if line else ";\n")
                fh.write("\n")
                fh.write(f"{ename} .struct\n")
                fields = sorted(element.get("fields", []),
                                key=lambda f: f.get("offset", 0))
                cur = 0
                for f in fields:
                    fname = f.get("name")
                    foff = f.get("offset")
                    fsize = f.get("size", 1)
                    if fname is None or foff is None:
                        continue
                    if foff > cur:
                        gap = foff - cur
                        if gap == 1:
                            fh.write(f"            .byte ?\n")
                        else:
                            fh.write(f"            .fill {gap}\n")
                    comment = f.get("comment", "")
                    suffix = f"    ; +${foff:02X}"
                    if comment:
                        suffix += f"  {comment}"
                    fh.write(f"{fname:<20} .byte ?{suffix}\n")
                    cur = foff + fsize
                if cur < esize:
                    fh.write(f"            .fill {esize - cur}"
                             f"    ; +${cur:02X}..${esize - 1:02X}"
                             f" (unnamed tail)\n")
                fh.write(f"            .endstruct\n")
                fh.write(f".cerror size({ename}) != ${esize:02X},"
                         f' "{ename} size drift"\n')
                emitted_struct_defs.add(ename)
            fh.write(f"\n;   {seg['name']}: {seg.get('comment', '')}\n")
            for inst_name, inst_addr in seg["instances"]:
                fh.write(f"            .virtual ${inst_addr:04X}\n")
                fh.write(f"{inst_name:<24} .dstruct {ename}\n")
                fh.write(f"            .endvirtual\n")
        fh.write("\n")

    if flat_segments:
        bar = "; " + "─" * 70 + "\n"
        fh.write(bar)
        fh.write("; STRUCT EQUATES — element/container sizes + field offsets for\n")
        fh.write(";   typed data segments (see Ghidra segments.json). Used by the\n")
        fh.write(";   operand resolver to render addresses inside these segments as\n")
        fh.write(";   `<segment> + <container_idx>*<C>_size + <element_idx>*<E>_size\n")
        fh.write(";   + <E>_<field>` expressions; the equates below close those.\n")
        fh.write(bar)
        emitted_struct_names: set[str] = set()
        for seg in flat_segments:
            struct = seg.get("struct") or {}
            container = struct.get("container") or None
            element = struct.get("element") or {}
            ename = element.get("name")
            esize = element.get("size")
            if not (ename and esize):
                continue
            if container:
                cname = container.get("name")
                csize = container.get("size")
                ccount = container.get("element_count", "?")
                fh.write(f"\n; {seg['name']}: {cname}[{ccount}]"
                         f"  ({cname}_size = {csize}, "
                         f"{ename}_size = {esize})\n")
                if cname and csize is not None and cname not in emitted_struct_names:
                    fh.write(f"{cname + '_size':<40} = ${csize:04X}\n")
                    emitted_struct_names.add(cname)
            else:
                fh.write(f"\n; {seg['name']}: {ename}[]"
                         f"  ({ename}_size = {esize}; no fixed container — "
                         f"single-level array)\n")
            if ename not in emitted_struct_names:
                # Pre-equate diagram so the reader sees the layout
                # visually before the per-field `_size = $NN` lines.
                cell_w = max(8, max(
                    (len(f.get("name", "")) for f in element.get("fields", [])),
                    default=4) + 2)
                cols = 8 if esize > 16 else min(esize, 8)
                fh.write("\n")
                for line in _render_struct_diagram(element, cell_w=cell_w,
                                                   cols=cols):
                    fh.write(f"; {line}\n" if line else ";\n")
                fh.write("\n")
                fh.write(f"{ename + '_size':<40} = ${esize:04X}\n")
                for f in element.get("fields", []):
                    fname = f.get("name")
                    foff = f.get("offset")
                    if fname is None or foff is None:
                        continue
                    key = f"{ename}_{fname}"
                    comment = f.get("comment", "")
                    suffix = "" if not comment else f"    ; {comment}"
                    fh.write(f"{key:<40} = ${foff:04X}{suffix}\n")
                emitted_struct_names.add(ename)
            else:
                fh.write(f";   (struct equates above — see {ename} block)\n")
        fh.write("\n")

    if named_constants:
        bar = "; " + "─" * 70 + "\n"
        fh.write(bar)
        fh.write("; NAMED CONSTANTS — IMM operand values given symbolic names\n")
        fh.write(";   via `[imm.\"$XXXX\"]` entries in annotations.toml. The\n")
        fh.write(";   instruction at the cited PC renders `#<NAME>` instead\n")
        fh.write(";   of the bare hex; the equates below close those refs.\n")
        fh.write(bar)
        for name in sorted(named_constants):
            fh.write(f"{name:<40} = ${named_constants[name]:04X}\n")
        fh.write("\n")

    if equate_labels:
        bar = "; " + "─" * 70 + "\n"
        fh.write(bar)
        fh.write("; EQUATES — non-code labels (state vars, data segments, etc.).\n")
        fh.write(";   Labels at code-start addresses are emitted inline below.\n")
        fh.write(bar)
        current_band = -1
        # Dedup enum-constant equates across regions: when two state
        # variables share a value_names enum (e.g. ui_mode at $7167 and
        # ui_mode_range_bound at $7169 both name $01=UI_MODE_SEQED), we
        # emit each constant exactly once. 64tass rejects duplicate
        # definitions even when the right-hand value is identical.
        emitted_enum_constants: set[str] = set()
        for addr, name in equate_labels:
            band = _band_for(addr)
            if band != current_band:
                heading = _EQUATE_BANDS[band][1]
                fh.write(f"\n; ── {heading} {'─' * max(1, 67 - len(heading))}\n")
                current_band = band
            ann = annotations.get(addr)
            summary = ann.get("summary", "") if ann else ""
            if summary:
                fh.write(f"{name:<24} = ${addr:04X}    ; {summary}\n")
            else:
                fh.write(f"{name:<24} = ${addr:04X}\n")
            # Per-value named constants for enum vars (referenced by
            # `lda/cmp #NAME` in code below; the substitution map maps
            # those instruction PCs to the matching name).
            vn = value_names_per_var.get(addr)
            if vn:
                for v in sorted(vn.keys()):
                    if vn[v] in emitted_enum_constants:
                        continue
                    fh.write(f"{vn[v]:<24} = ${v:02X}\n")
                    emitted_enum_constants.add(vn[v])
            if ann:
                for key in ("values", "notes"):
                    if key in NEVER_EMIT_FIELDS:
                        continue
                    val = ann.get(key, "")
                    if not val:
                        continue
                    if key == "values" and isinstance(val, dict):
                        entries = _normalise_values_dict(val)
                        if entries:
                            kind = ann.get("values_kind", "exhaustive")
                            head = "" if kind == "exhaustive" else f" ({kind})"
                            fh.write(f";   {key}:{head}\n")
                            for line in _render_enum_lines("", entries):
                                fh.write(f";   {line}\n")
                            continue
                    if not isinstance(val, str):
                        continue
                    val = _strip_forward_refs(val)
                    if not val:
                        continue
                    parsed_enum = _parse_enum_list(val)
                    if parsed_enum is not None:
                        pfx, entries = parsed_enum
                        head = f" {pfx}:" if pfx else ""
                        fh.write(f";   {key}:{head}\n")
                        for line in _render_enum_lines("", entries):
                            fh.write(f";   {line}\n")
                        continue
                    if key == "notes":
                        rendered = _format_notes_with_enums(val)
                    else:
                        rendered = val.rstrip("\n").split("\n")
                    if len(rendered) == 1:
                        fh.write(f";   {key}: {rendered[0]}\n")
                    else:
                        fh.write(f";   {key}:\n")
                        for line in rendered:
                            fh.write(f";     {line}\n" if line else ";\n")
            # Graph-derived reachability block for non-code-start
            # equates that have an annotation. Same predicate as the
            # function-block emit: only when code_in is empty.
            reach_lines = _graph_dead_lines(addr)
            if reach_lines:
                for line in reach_lines:
                    fh.write(f";   {line}\n")
            cons_lines = _constraints_lines(ann)
            if cons_lines:
                fh.write(";   constraints:\n")
                for line in cons_lines:
                    fh.write(f";     {line}\n")
        fh.write("\n")

    fh.write(f"        * = ${base:04X}\n")
    fh.write("\n")

    instr_count = 0
    data_count = 0
    pc = base
    BYTES_PER_LINE = 16
    pending_data: list[int] = []
    pending_start = base
    # 64tass's `.enc` is sticky — track the currently-active encoding
    # so we only emit a switch directive when it actually changes.
    current_enc: str = "none"
    # Sliding window of recently emitted instruction PCs, used to find
    # each branch's flag-setter. Cleared whenever we cross a branch
    # target (the inbound flag state is unknown from another arrival
    # path) and whenever data interrupts the code stream.
    recent_instr_pcs: list[int] = []
    WINDOW_DEPTH = 8

    # Last `LDA/LDX/LDY #imm` value per register, used to decode the byte
    # being written to a hardware register on the next STA/STX/STY. Set
    # by the LD?-imm emit path, consumed (and cleared) by the
    # corresponding ST? emit path, and invalidated whenever any other
    # instruction emits (so we never decode against a stale immediate
    # from many instructions back).
    prev_imm: dict[str, int | None] = {"a": None, "x": None, "y": None}

    # {start_addr: segment_dict} for O(1) entry-point lookup.
    seg_starts = {s["start"]: s for s in segments
                  if base <= s["start"] < end_excl}
    # End-points where we emit the closing rule.
    seg_ends = {s["end_excl"]: s for s in segments
                if base < s["end_excl"] <= end_excl}

    # PCs reached by a real branch / call / jump (per the static call
    # graph). Used to gate the synthetic `_XXXX:` line prefix — when an
    # instruction is neither named nor a control-flow target, no label
    # is needed and the prefix is dropped. ~75% of instruction lines
    # land in this no-label bucket; removing the prefix lets the eye
    # track named entries and branch landings instead of scanning a
    # column of synthetic anchors.
    branch_targets: set[int] = set()
    if graph is not None:
        branch_targets = set(graph.code_in.keys())

    # Synthetic labels for branch targets without a hand-curated name.
    # Preferred form is ``<block>_<N>`` where ``<block>`` is the nearest
    # preceding [function] annotation — readers see the local block
    # name + a sequence index instead of a hex address that conveys
    # nothing. Falls back to ``L_XXXX`` for code outside any annotated
    # block (e.g. inline code in a data span).
    #
    # The semantic naming (`on_<cond>`) lives in a separate alias-equate
    # mechanism — the branch operand reads with the semantic name but
    # the landing keeps the short block-relative anchor, so the reader
    # isn't forced to mentally parse a long condition name where the
    # local code is about a different variable than the inbound branch
    # tested.
    #
    # 64tass treats bare ``_XXXX`` as a label local to the previous
    # global label, so cross-scope branches would fail to resolve;
    # block-relative names are global-form by construction.
    block_pcs_sorted, block_name_by_pc = _build_block_pc_index(
        annotations, instr_at)
    block_counters: dict[int, int] = {}
    for tgt in sorted(branch_targets):
        if not (base <= tgt < end_excl and tgt in instr_at and tgt not in labels):
            continue
        block_pc = _nearest_block_pc(tgt, block_pcs_sorted)
        if block_pc is not None and tgt != block_pc:
            block_counters[block_pc] = block_counters.get(block_pc, 0) + 1
            labels[tgt] = (f"{block_name_by_pc[block_pc]}"
                           f"_{block_counters[block_pc]}")
        else:
            labels[tgt] = f"L_{tgt:04X}"

    # ─── Function-scoped .block wrapping (Phase A) ───────────────────
    # Each [function]-annotated code-start gets a `funcname .block` /
    # `.bend` envelope. The block name doubles as the entry label (zero
    # bytes added). Cross-block label references are rewritten to
    # `<funcname>.<label>` dot-notation by `_rebuild_effective_labels`
    # whenever current_block_entry changes. Function-entry labels are
    # globally accessible as the .block name, so they stay bare.
    function_blocks: dict[int, tuple[int, str]] = {}
    _fn_entries: list[int] = sorted(
        pc for pc in block_name_by_pc
        if base <= pc < end_excl and pc in instr_at)
    for _i, _entry_pc in enumerate(_fn_entries):
        _nxt = _fn_entries[_i + 1] if _i + 1 < len(_fn_entries) else end_excl
        _block_name = labels.get(_entry_pc, block_name_by_pc[_entry_pc])
        function_blocks[_entry_pc] = (_nxt, _block_name)
    function_entries_set: set[int] = set(function_blocks)

    # label_block[addr] = entry_pc of the function block containing
    # ``addr``, or None when addr is outside any block OR is itself the
    # entry of a block (entries are globally visible as the block name).
    # Only CODE addresses (in instr_at) can be attributed to a block —
    # EQUATE labels for state vars / hardware regs happen to fall inside
    # a function's PC range numerically but live outside any .block in
    # source, so their references must stay bare.
    label_block: dict[int, int | None] = {}
    for _addr in labels:
        if _addr in function_entries_set:
            label_block[_addr] = None
            continue
        if _addr not in instr_at:
            label_block[_addr] = None
            continue
        _idx = bisect.bisect_right(_fn_entries, _addr) - 1
        if _idx < 0:
            label_block[_addr] = None
            continue
        _entry = _fn_entries[_idx]
        _end_pc = function_blocks[_entry][0]
        label_block[_addr] = _entry if _addr < _end_pc else None

    # Phase B: in-block name = label with its enclosing function-block's
    # name prefix stripped when redundant. Inside `kbd_scan .block`, the
    # label `kbd_scan_inner_continue` becomes `inner_continue`; the
    # synthetic anchor `kbd_scan_9` becomes `l_9` (the `l_` keeps it a
    # valid 64tass identifier — bare leading-underscore + digit forms
    # like `_9` are LOCAL labels scoped to the most recent non-`_`
    # label, which breaks once any HW-alias label appears mid-block).
    # From outside, both are referenced as `kbd_scan.inner_continue` /
    # `kbd_scan.l_9`. Function-entry labels (which ARE the block name)
    # keep their full name.
    inblock_name: dict[int, str] = {}
    for _addr, _name in labels.items():
        _tb = label_block.get(_addr)
        if _tb is None:
            continue
        _prefix = function_blocks[_tb][1]
        if (_name.startswith(_prefix + "_")
                and len(_name) > len(_prefix) + 1):
            _suffix = _name[len(_prefix) + 1:]
            inblock_name[_addr] = ("l_" + _suffix
                                   if _suffix[0].isdigit() else _suffix)

    current_block_entry: int | None = None
    effective_labels: dict[int, str] = dict(labels)

    def _rebuild_effective_labels() -> None:
        nonlocal effective_labels
        new: dict[int, str] = {}
        for addr, name in labels.items():
            tb = label_block.get(addr)
            # `local` is the in-block name — the stripped form when the
            # label had a redundant `funcname_` prefix, else the full
            # name (HW-register aliases, hand-curated labels without the
            # prefix, etc.). Either way the label IS defined inside the
            # .block source line at this PC, so cross-block refs use
            # `funcname.local`.
            local = inblock_name.get(addr, name)
            if tb is None:
                new[addr] = name
            elif tb == current_block_entry:
                new[addr] = local
            else:
                new[addr] = f"{function_blocks[tb][1]}.{local}"
        effective_labels = new

    _rebuild_effective_labels()

    def emit_segment_header(seg: dict) -> None:
        bar = "; " + "─" * 70 + "\n"
        fh.write("\n")
        fh.write(bar)
        size = seg["end_excl"] - seg["start"]
        fh.write(f"; SEGMENT  {seg['name']}  "
                 f"(${seg['start']:04X}-${seg['end_excl'] - 1:04X}, "
                 f"{size} bytes, element_size={seg['element_size']})\n")
        if seg.get("comment"):
            for line in seg["comment"].split("\n"):
                fh.write(f";   {line}\n")
        fh.write(bar)

    def emit_segment_footer(seg: dict) -> None:
        fh.write(f"; ─── end segment {seg['name']} ───\n")
        fh.write("\n")

    # Structured field order for the emitted header. The summary leads;
    # then the structured "ABI" fields appear in a fixed order; then
    # free-form notes. Fields in NEVER_EMIT_FIELDS (`evidence`,
    # `internal_notes`) belong to the RE archive in annotations.toml and
    # are skipped here.
    _STRUCTURED_FIELDS = (
        ("callers",             "callers"),
        ("inputs",              "inputs"),
        ("outputs",             "outputs"),
        ("registers_clobbered", "registers clobbered"),
        ("variables_changed",   "variables changed"),
        ("values",              "values"),
    )
    _FIELD_LABEL_WIDTH = max(len(label) for _, label in _STRUCTURED_FIELDS)

    def _parse_sequence_block(notes: str) -> list[str]:
        """Pull `Sequence:` bullets out of a notes blob.

        Recognises the canonical bullet form `  - <text>` lines that
        follow a `Sequence:` label. Returns the bullet texts (without
        the leading dash/whitespace, with trailing period preserved).
        Sub-bullets (4+ space indent) are folded into their parent.
        """
        lines = notes.split("\n")
        bullets: list[str] = []
        in_seq = False
        for line in lines:
            stripped = line.strip()
            if not in_seq:
                if stripped.lower().rstrip(":") == "sequence":
                    in_seq = True
                continue
            # Inside the sequence block.
            if not stripped:
                break  # blank line ends the block
            m = re.match(r"^(\s*)-\s+(.*)$", line)
            if m:
                indent = len(m.group(1))
                text = m.group(2).rstrip()
                if indent <= 2:
                    bullets.append(text)
                else:
                    # Sub-bullet — append to last parent.
                    if bullets:
                        bullets[-1] += " " + text
            else:
                # Continuation line for the last bullet.
                if bullets and stripped:
                    bullets[-1] += " " + stripped
                else:
                    break
        return bullets

    def _walk_linear_block(start_pc: int, max_instrs: int = 32) -> list[int]:
        """Return consecutive instruction PCs from start_pc up to (and
        including) the first RTS/RTI/JMP/BRK, capped at max_instrs.
        """
        pcs: list[int] = []
        pc = start_pc
        while pc in instr_at and len(pcs) < max_instrs:
            pcs.append(pc)
            _, _, n = instr_at[pc]
            op = mem[pc]
            if op in (0x60, 0x40, 0x4C, 0x6C, 0x00):  # RTS RTI JMP BRK
                break
            pc += n
            if pc >= end_excl:
                break
        return pcs

    # (regex, mnemonic set). Each rule matches the *first clause* of a
    # bullet. Compound bullets ("clear-carry / A += step_cursor / →skip")
    # anchor on the FIRST verb encountered.
    _BULLET_VERB_RULES: list[tuple[re.Pattern[str], set[str]]] = [
        # flag ops
        (re.compile(r"^\s*clear[- ]carry\b", re.I), {"clc"}),
        (re.compile(r"^\s*set[- ]carry\b", re.I), {"sec"}),
        (re.compile(r"^\s*clear[- ]decimal\b", re.I), {"cld"}),
        (re.compile(r"^\s*set[- ]decimal\b", re.I), {"sed"}),
        (re.compile(r"^\s*IRQ[- ]off\b", re.I), {"sei"}),
        (re.compile(r"^\s*IRQ[- ]on\b", re.I), {"cli"}),
        (re.compile(r"^\s*clear[- ]?overflow\b", re.I), {"clv"}),
        # control flow
        (re.compile(r"^\s*return\b", re.I), {"rts", "rti"}),
        (re.compile(r"^\s*call\b", re.I), {"jsr"}),
        (re.compile(r"^\s*jump\b", re.I), {"jmp"}),
        (re.compile(r"^\s*tail[- ]?call\b", re.I), {"jmp"}),
        # stack
        (re.compile(r"^\s*push flags?\b", re.I), {"php"}),
        (re.compile(r"^\s*pop flags?\b", re.I), {"plp"}),
        (re.compile(r"^\s*push A\b"), {"pha"}),
        (re.compile(r"^\s*pop A\b"), {"pla"}),
        # register transfers (A ← Y, etc.) — narrow rules first so they
        # win over the general "A ← X" → LDA fallthrough.
        (re.compile(r"^\s*A\s*[:=←]+\s*Y\b"), {"tya"}),
        (re.compile(r"^\s*A\s*[:=←]+\s*X\b"), {"txa"}),
        (re.compile(r"^\s*Y\s*[:=←]+\s*A\b"), {"tay"}),
        (re.compile(r"^\s*X\s*[:=←]+\s*A\b"), {"tax"}),
        (re.compile(r"^\s*S\s*[:=←]+\s*X\b"), {"txs"}),
        (re.compile(r"^\s*X\s*[:=←]+\s*S\b"), {"tsx"}),
        # immediate / memory loads via ←  (A ← $XX, X ← label, etc.).
        # These cover bullets like "A ← $00", "Y ← $17", "X ← $FF".
        (re.compile(r"^\s*A\s*[:=←]+\s*[\$#]"), {"lda"}),
        (re.compile(r"^\s*X\s*[:=←]+\s*[\$#]"), {"ldx"}),
        (re.compile(r"^\s*Y\s*[:=←]+\s*[\$#]"), {"ldy"}),
        # Memory writes via ← (label as target).
        (re.compile(r"^\s*[a-z_][a-z0-9_]*\s*[:=←]+\s*A\b"), {"sta"}),
        (re.compile(r"^\s*[a-z_][a-z0-9_]*\s*[:=←]+\s*X\b"), {"stx"}),
        (re.compile(r"^\s*[a-z_][a-z0-9_]*\s*[:=←]+\s*Y\b"), {"sty"}),
        # Stores written as "A → label", "X → label", "Y → label"
        # (register source → memory target).
        (re.compile(r"^\s*A\s*→\s*[a-z_]"), {"sta"}),
        (re.compile(r"^\s*X\s*→\s*[a-z_]"), {"stx"}),
        (re.compile(r"^\s*Y\s*→\s*[a-z_]"), {"sty"}),
        # increment / decrement (register forms — operand forms fall
        # through to the label-match path)
        (re.compile(r"^\s*increment\s+Y\b", re.I), {"iny"}),
        (re.compile(r"^\s*increment\s+X\b", re.I), {"inx"}),
        (re.compile(r"^\s*decrement\s+Y\b", re.I), {"dey"}),
        (re.compile(r"^\s*decrement\s+X\b", re.I), {"dex"}),
        (re.compile(r"^\s*increment\b", re.I), {"inc", "iny", "inx"}),
        (re.compile(r"^\s*decrement\b", re.I), {"dec", "dey", "dex"}),
        # comparison
        (re.compile(r"^\s*compare\s+Y\b", re.I), {"cpy"}),
        (re.compile(r"^\s*compare\s+X\b", re.I), {"cpx"}),
        (re.compile(r"^\s*compare\b", re.I), {"cmp", "cpx", "cpy"}),
        # loads/stores (operand may also satisfy label-match)
        (re.compile(r"^\s*read\b", re.I), {"lda", "ldx", "ldy"}),
        (re.compile(r"^\s*load\b", re.I), {"lda", "ldx", "ldy"}),
        (re.compile(r"^\s*write\b", re.I), {"sta", "stx", "sty"}),
        (re.compile(r"^\s*store\b", re.I), {"sta", "stx", "sty"}),
        # arithmetic on A
        (re.compile(r"^\s*A\s*\+=", re.I), {"adc"}),
        (re.compile(r"^\s*A\s*-=", re.I), {"sbc"}),
        (re.compile(r"^\s*A\s+AND\b", re.I), {"and"}),
        (re.compile(r"^\s*A\s+OR\b", re.I), {"ora"}),
        (re.compile(r"^\s*A\s+EOR\b", re.I), {"eor"}),
        # shifts
        (re.compile(r"^\s*shift[- ]?left\b", re.I), {"asl"}),
        (re.compile(r"^\s*shift[- ]?right\b", re.I), {"lsr"}),
        (re.compile(r"^\s*rotate[- ]?left\b", re.I), {"rol"}),
        (re.compile(r"^\s*rotate[- ]?right\b", re.I), {"ror"}),
        # bit test
        (re.compile(r"^\s*bit[- ]?test\b", re.I), {"bit"}),
        # explicit branch arrow at start → any branch mnemonic
        (re.compile(r"^\s*→"),
            {"bcc", "bcs", "beq", "bne", "bmi", "bpl", "bvc", "bvs"}),
        # bare explicit mnemonic at start ("asl A", "bpl —", "rts")
        (re.compile(r"^\s*(lda|ldx|ldy|sta|stx|sty|adc|sbc|and|ora|eor|"
                    r"cmp|cpx|cpy|inc|dec|inx|iny|dex|dey|asl|lsr|rol|ror|"
                    r"bit|tax|tay|txa|tya|tsx|txs|pha|pla|php|plp|"
                    r"clc|sec|cld|sed|cli|sei|clv|nop|brk|"
                    r"bcc|bcs|beq|bne|bmi|bpl|bvc|bvs|jmp|jsr|rts|rti)\b",
                    re.I),
            {"_explicit_"}),
    ]

    _EXPLICIT_MNEM_RE = re.compile(
        r"^\s*(lda|ldx|ldy|sta|stx|sty|adc|sbc|and|ora|eor|"
        r"cmp|cpx|cpy|inc|dec|inx|iny|dex|dey|asl|lsr|rol|ror|"
        r"bit|tax|tay|txa|tya|tsx|txs|pha|pla|php|plp|"
        r"clc|sec|cld|sed|cli|sei|clv|nop|brk|"
        r"bcc|bcs|beq|bne|bmi|bpl|bvc|bvs|jmp|jsr|rts|rti)\b",
        re.I,
    )

    # Compound bullets join multiple actions with " / " or " — ". The
    # arrow "→" is a destination marker for the action immediately to
    # its LEFT (e.g. "→skip when no-carry" describes a branch, where
    # the entire bullet is the action). So we split on / and — but NOT
    # on →.
    _CLAUSE_SPLIT = re.compile(r"\s*(?:/|—)\s*")

    def _bullet_first_clause(bullet: str) -> str:
        """Return the first non-empty clause of a compound bullet."""
        parts = _CLAUSE_SPLIT.split(bullet, maxsplit=2)
        for p in parts:
            if p.strip():
                return p
        return bullet

    def _bullet_first_label_token(bullet: str) -> str | None:
        """Return the first known label name appearing in the bullet."""
        # Iterate over labels by descending length so longer names match
        # first ("page_offset" wins over its prefix substring inside a
        # larger compound, etc.).
        for cand in sorted(labels.values(), key=len, reverse=True):
            if len(cand) < 4:
                continue  # too short to discriminate (Y, X, A noise)
            if re.search(rf"\b{re.escape(cand)}\b", bullet):
                return cand
        return None

    def _operand_text(pc: int) -> str:
        _, mode, n = instr_at[pc]
        p1 = mem[pc + 1] if n >= 2 else 0
        p2 = mem[pc + 2] if n >= 3 else 0
        return emit_64tass_instruction(mode, p1, p2, pc, labels=labels,
                                       struct_segments=struct_segments,
                                       name_spans=name_spans,
                                       anchor_spans=HW_ANCHOR_REGIONS)

    def _bullet_matches_instr(bullet: str, pc: int) -> bool:
        """True if the bullet plausibly anchors at this instruction.

        Anchors on the *first clause* of compound bullets only — a bullet
        like "clear-carry / A += step_cursor / →skip" anchors at the CLC
        instruction; subsequent clauses are documentation, not anchors.
        """
        if pc not in instr_at:
            return False
        mnem, _, _ = instr_at[pc]
        mn = mnem.lower()
        first = _bullet_first_clause(bullet)
        # Try verb rules first (matched against the first clause only).
        for pat, mnems in _BULLET_VERB_RULES:
            m = pat.search(first)
            if not m:
                continue
            if "_explicit_" in mnems:
                # Explicit mnemonic literally appears in the bullet —
                # match only the exact mnemonic.
                em = _EXPLICIT_MNEM_RE.search(first)
                if em and em.group(1).lower() == mn:
                    return True
                continue
            if mn in mnems:
                return True
        # Try labelled operand token (full bullet — labels may appear
        # anywhere). This is the fall-through for "read page_offset"
        # style bullets where "read" matches lda/ldx/ldy AND the label
        # appears in the operand.
        tok = _bullet_first_label_token(first) or _bullet_first_label_token(bullet)
        if tok:
            op_text = _operand_text(pc)
            if re.search(rf"\b{re.escape(tok)}\b", op_text):
                return True
        return False

    def _align_bullets(bullets: list[str], pcs: list[int]) -> list[tuple[int, str]] | None:
        """Map each bullet to its anchor PC in `pcs`. Returns
        [(pc, bullet_text), ...] in order, or None on failed alignment.

        Constraints:
          - First bullet must anchor at pcs[0] (function entry).
          - Each subsequent bullet's anchor PC is strictly after the
            previous one.
          - All bullets must be placed; otherwise alignment fails and
            the caller falls back to the header form.
        """
        if not bullets or not pcs:
            return None
        anchors: list[tuple[int, str]] = []
        cursor = 0  # index into pcs
        for i, bullet in enumerate(bullets):
            # First bullet must anchor at pcs[0]. Verify by matching.
            if i == 0:
                if not _bullet_matches_instr(bullet, pcs[0]):
                    return None
                anchors.append((pcs[0], bullet))
                cursor = 1
                continue
            # Search forward in pcs for the next matching instruction.
            found = None
            for j in range(cursor, len(pcs)):
                if _bullet_matches_instr(bullet, pcs[j]):
                    found = j
                    break
            if found is None:
                return None
            anchors.append((pcs[found], bullet))
            cursor = found + 1
        return anchors

    def _compute_sequence_inlining() -> tuple[dict[int, str], set[int]]:
        """Build {pc: bullet_text} for every function whose Sequence:
        block aligns cleanly. Returns (inline_comments, inlined_addrs).
        """
        inline: dict[int, str] = {}
        inlined: set[int] = set()
        for addr, ann in annotations.items():
            if addr not in instr_at:
                continue
            notes = ann.get("notes", "")
            if not notes or "Sequence:" not in notes:
                continue
            bullets = _parse_sequence_block(notes)
            if len(bullets) < 2:
                continue
            pcs = _walk_linear_block(addr)
            if len(pcs) < len(bullets):
                continue
            result = _align_bullets(bullets, pcs)
            if result is None:
                continue
            for pc, comment in result:
                inline[pc] = comment
            inlined.add(addr)
        return inline, inlined

    seq_inline_comments, seq_inlined_addrs = _compute_sequence_inlining()

    # Catalog-supplied `inline_comments = { "$XXXX" = "text", ... }`.
    # These take precedence over Sequence:-derived comments at the same
    # PC. Use this slot to attach per-instruction semantics (magic
    # constants, sentinel meanings) that don't fit in any structured
    # field — see `inline_comments` schema in check_schema.py.
    catalog_inline_comments: dict[int, str] = {}
    for _ann in annotations.values():
        _ic = _ann.get("inline_comments")
        if not isinstance(_ic, dict):
            continue
        for _pc_str, _text in _ic.items():
            if not isinstance(_pc_str, str) or not _pc_str.startswith("$"):
                continue
            try:
                _pc = int(_pc_str[1:], 16)
            except ValueError:
                continue
            if isinstance(_text, str) and _text.strip():
                catalog_inline_comments[_pc] = _text
    # Catalog values override sequence-derived ones at the same PC.
    for _pc, _text in catalog_inline_comments.items():
        seq_inline_comments[_pc] = _text

    def _strip_sequence_block(notes: str) -> str:
        """Drop the `Sequence:` block from a notes string."""
        if not notes or "Sequence:" not in notes:
            return notes
        lines = notes.split("\n")
        out: list[str] = []
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            if stripped.lower().rstrip(":") == "sequence":
                # Skip the header + its bullet block.
                i += 1
                while i < len(lines):
                    s = lines[i].strip()
                    if not s:
                        break
                    if re.match(r"^\s*-\s+", lines[i]):
                        i += 1
                        continue
                    # Indented continuation of a bullet.
                    if lines[i].startswith("  ") and out and not s.endswith(":"):
                        i += 1
                        continue
                    break
                continue
            out.append(lines[i])
            i += 1
        # Collapse runs of empty lines into a single blank.
        cleaned: list[str] = []
        prev_blank = False
        for line in out:
            if not line.strip():
                if not prev_blank:
                    cleaned.append("")
                prev_blank = True
            else:
                cleaned.append(line)
                prev_blank = False
        return "\n".join(cleaned).strip()

    def emit_function_annotation(addr: int) -> None:
        """Emit a structured block-comment header for an annotated
        code-start. Adds no bytes to the assembled output — comments
        only. Format:

            ;──────────────────────────────────────────────────────────
            ; $XXXX  label_name
            ;──────────────────────────────────────────────────────────
            ; <summary sentence>
            ;
            ;   callers:             ...
            ;   inputs:              ...
            ;   outputs:             ...
            ;   registers clobbered: ...
            ;   variables changed:   ...
            ;   values:              ...
            ;   notes:
            ;     ...

        Field order is fixed; absent fields are omitted entirely.
        """
        ann = annotations.get(addr)
        if not ann:
            return
        role = ann.get("role", "")
        structured = [(label, ann.get(key, ""))
                      for key, label in _STRUCTURED_FIELDS]
        notes = ann.get("notes", "")
        if addr in seq_inlined_addrs:
            notes = _strip_sequence_block(notes)
        if not (role or any(v for _, v in structured) or notes):
            return
        # Inert-helper gate: when the only content is derivable
        # structured/xref noise (no role, no notes, no constraints) and
        # the body is a tiny stub (≤3 instructions to RTS/JMP/RTI),
        # skip the header entirely — a five-line block-comment for a
        # two-instruction landing pad reads as filler.
        has_hand_prose = bool(role or notes
                              or _constraints_lines(ann))
        if not has_hand_prose:
            body = _walk_linear_block(addr, max_instrs=4)
            if len(body) <= 3:
                return

        bar = "; " + "─" * 70 + "\n"
        fh.write("\n")
        fh.write(bar)
        head = f"; ${addr:04X}"
        lbl = labels.get(addr)
        if lbl:
            head += f"  {lbl}"
        fh.write(head + "\n")
        fh.write(bar)
        if role:
            fh.write(f"; {role}\n")
        # Structured fields, column-aligned. The `callers` slot has a
        # special case: when no hand-written value, the graph fills it
        # in derived form. This makes callers ubiquitous (every live
        # code-start gets one) without forcing 600+ hand entries.
        derived_callers = _derived_callers_line(addr, ann)
        any_struct = any(v for _, v in structured) or bool(derived_callers)
        if any_struct:
            fh.write(";\n")
            for label, val in structured:
                if not val:
                    if label == "callers" and derived_callers:
                        pad = " " * (_FIELD_LABEL_WIDTH - len(label))
                        fh.write(f";   {label}:{pad} {derived_callers}\n")
                    continue
                pad = " " * (_FIELD_LABEL_WIDTH - len(label))
                if label == "values" and isinstance(val, dict):
                    entries = _normalise_values_dict(val)
                    if entries:
                        kind = ann.get("values_kind", "exhaustive")
                        head = "" if kind == "exhaustive" else f" ({kind})"
                        fh.write(f";   {label}:{head}\n")
                        for line in _render_enum_lines("", entries):
                            fh.write(f";   {line}\n")
                        continue
                if isinstance(val, str):
                    parsed_enum = _parse_enum_list(val)
                else:
                    parsed_enum = None
                if parsed_enum is not None:
                    pfx, entries = parsed_enum
                    head = f" {pfx}:" if pfx else ""
                    fh.write(f";   {label}:{pad}{head}\n")
                    for line in _render_enum_lines("", entries):
                        fh.write(f";   {line}\n")
                else:
                    fh.write(f";   {label}:{pad} {val}\n")
        # Graph-derived reachability block — only emitted when code_in
        # is empty (dead via data byte / true orphan). The graph is
        # authoritative; this replaces the hand-written
        # "Unreachable: …" notes that step-1/2 chased with regex.
        reach_lines = _graph_dead_lines(addr)
        if reach_lines:
            fh.write(";\n")
            for line in reach_lines:
                fh.write(f";   {line}\n")
        cons_lines = _constraints_lines(ann)
        if cons_lines:
            fh.write(";\n")
            fh.write(";   constraints:\n")
            for line in cons_lines:
                fh.write(f";     {line}\n")
        override = ann.get("derived_override") if ann else None
        if isinstance(override, str) and override.strip():
            fh.write(";\n")
            pad = " " * (_FIELD_LABEL_WIDTH - len("derived_override"))
            fh.write(f";   derived_override:{pad} {override}\n")
        if notes:
            fh.write(";\n")
            for line in _format_notes_with_enums(notes):
                fh.write(f";   {line}\n" if line else ";\n")

    def flush_data():
        nonlocal pending_data, pending_start
        if not pending_data:
            return

        def _emit_chunk(addr: int, chunk: bytes) -> None:
            bytes_text = ", ".join(f"${b:02X}" for b in chunk)
            fh.write(f"        .byte {bytes_text}    ; ${addr:04X}\n")

        def _fill_literal(chunk: bytes) -> str:
            """Return a 64tass fill literal for ``chunk``. 64tass reads
            the byte width from the hex-digit count of the literal:
            ``$XX`` is a 1-byte fill, ``$XXYY`` a 2-byte LE pattern,
            ``$XXYYZZWW`` a 4-byte LE pattern, and so on. So pick the
            narrowest periodic sub-pattern the chunk supports."""
            for period in (1, 2, 4, 8):
                if all(chunk[i] == chunk[i % period]
                       for i in range(len(chunk))):
                    sub = chunk[:period]
                    v = 0
                    for j, b in enumerate(sub):
                        v |= b << (j * 8)
                    return f"${v:0{period * 2}X}"
            v = 0
            for j, b in enumerate(chunk):
                v |= b << (j * 8)
            return f"${v:0{len(chunk) * 2}X}"

        def _emit_byte_segment(seg_addr: int, sub: bytes) -> None:
            """Emit ``sub`` as 16-byte .byte chunks, applying the
            multi-byte-periodic chunk collapse for ≥6 identical aligned
            full rows (zero pads with $0000-style periodic fills, etc.)."""
            chunks: list[tuple[int, bytes]] = []
            for off in range(0, len(sub), BYTES_PER_LINE):
                chunks.append((seg_addr + off,
                               bytes(sub[off:off + BYTES_PER_LINE])))
            i = 0
            while i < len(chunks):
                addr, chunk = chunks[i]
                if len(chunk) == BYTES_PER_LINE:
                    run_end = i + 1
                    while (run_end < len(chunks)
                           and chunks[run_end][1] == chunk
                           and len(chunks[run_end][1]) == BYTES_PER_LINE):
                        run_end += 1
                    run_len = run_end - i
                    if run_len >= 6:
                        _emit_chunk(addr, chunk)
                        middle = run_len - 2
                        last_addr, last_chunk = chunks[run_end - 1]
                        elided_lo = addr + BYTES_PER_LINE
                        elided_hi = last_addr - BYTES_PER_LINE
                        literal = _fill_literal(chunk)
                        fh.write(
                            f"        .fill {middle * BYTES_PER_LINE}, "
                            f"{literal}    "
                            f"; ${elided_lo:04X}-${elided_hi:04X} "
                            f"({middle} identical rows)\n")
                        _emit_chunk(last_addr, last_chunk)
                        i = run_end
                        continue
                _emit_chunk(addr, chunk)
                i += 1

        # Pass 1: split pending_data into segments separated by
        # single-byte runs of ≥FILL_BYTE_THRESHOLD identical bytes.
        # Catches NOP pads / zero fills / space pads that aren't 16-
        # byte-row-aligned (so the multi-byte chunk collapse below
        # would miss them — that pass only sees full identical rows).
        FILL_BYTE_THRESHOLD = 16
        n = len(pending_data)
        segments: list[tuple[str, int, int, int]] = []
        i = 0
        while i < n:
            j = i
            while j < n and pending_data[j] == pending_data[i]:
                j += 1
            if j - i >= FILL_BYTE_THRESHOLD:
                segments.append(("fill", i, j - i, pending_data[i]))
                i = j
                continue
            # Walk past short runs until the next eligible fill start.
            byte_end = j
            while byte_end < n:
                k = byte_end
                while k < n and pending_data[k] == pending_data[byte_end]:
                    k += 1
                if k - byte_end >= FILL_BYTE_THRESHOLD:
                    break
                byte_end = k
            segments.append(("bytes", i, byte_end - i, 0))
            i = byte_end

        # Pass 2: emit each segment. "fill" → single `.fill N, $XX`
        # with start-end range comment. "bytes" → fall through to the
        # chunk emit (with multi-byte periodic collapse for $00 pads,
        # $8000 templates, etc.).
        for kind, off, length, byte_val in segments:
            seg_addr = pending_start + off
            if kind == "fill":
                end_addr = seg_addr + length - 1
                fh.write(f"        .fill {length}, ${byte_val:02X}    "
                         f"; ${seg_addr:04X}-${end_addr:04X}\n")
            else:
                _emit_byte_segment(seg_addr, bytes(pending_data[off:off + length]))

        pending_data = []

    while pc < end_excl:
        # Segment header (printed once, just before the first byte of
        # the segment) and footer (printed just after the last byte).
        if pc in seg_starts:
            flush_data()
            emit_segment_header(seg_starts[pc])
        if pc in text_segments:
            flush_data()
            ts = text_segments[pc]
            encoded = _encode_text(ts["string"], ts["encoding"])
            reps = ts.get("reps", 1)
            if current_enc != ts["encoding"]:
                fh.write(f'        .enc "{ts["encoding"]}"\n')
                current_enc = ts["encoding"]
            esc = (ts["string"]
                   .replace("\\", "\\\\")
                   .replace('"', '\\"'))
            if reps == 1:
                fh.write(f'        .text "{esc}"    ; ${pc:04X}\n')
            else:
                fh.write(f'        ; ${pc:04X}\n')
                fh.write(f'        .rept {reps}\n')
                fh.write(f'        .text "{esc}"\n')
                fh.write(f'        .endrept\n')
            pc += len(encoded) * reps
            pending_start = pc
            if pc in seg_ends:
                emit_segment_footer(seg_ends[pc])
            continue
        if pc in byte_runs:
            flush_data()
            runs = byte_runs[pc]
            fh.write(f'        ; ${pc:04X}\n')
            for r in runs:
                if r["kind"] == "fill":
                    fh.write(f'        .fill {r["count"]}, ${r["byte"]:02X}\n')
                else:
                    bytes_text = ", ".join(f"${b:02X}" for b in r["bytes"])
                    if r["reps"] == 1:
                        fh.write(f'        .byte {bytes_text}\n')
                    else:
                        fh.write(f'        .rept {r["reps"]}\n')
                        fh.write(f'        .byte {bytes_text}\n')
                        fh.write(f'        .endrept\n')
            pc += _byte_runs_encoded_length(runs)
            pending_start = pc
            if pc in seg_ends:
                emit_segment_footer(seg_ends[pc])
            continue
        if pc in instr_at:
            flush_data()
            # Function-block lifecycle: close the open .block first so
            # the next function's header/.block emits at top level.
            if (current_block_entry is not None
                    and pc >= function_blocks[current_block_entry][0]):
                fh.write(".bend\n")
                current_block_entry = None
                _rebuild_effective_labels()
            # Annotation block-comment goes ABOVE the label line so
            # readers see the function header before the entry instruction.
            if pc in annotations:
                emit_function_annotation(pc)
            # Open this function's .block envelope (Phase A wrapping).
            # The block name doubles as the entry label, so the per-
            # instruction label prefix is suppressed below.
            if pc in function_entries_set:
                _block_name = function_blocks[pc][1]
                fh.write(f"{_block_name} .block\n")
                current_block_entry = pc
                _rebuild_effective_labels()
            if pc in seq_inline_comments:
                fh.write(f";     {seq_inline_comments[pc]}\n")
            # When this PC is a branch target the inbound flag state is
            # unknown — drop the predecessor window so the next branch
            # doesn't reach into instructions from an unrelated arrival
            # path.
            if pc in branch_targets:
                recent_instr_pcs = []
                prev_imm = {"a": None, "x": None, "y": None}
            mnem, mode, n = instr_at[pc]
            mnem_lower = mnem.lower()
            p1 = mem[pc + 1] if n >= 2 else 0
            p2 = mem[pc + 2] if n >= 3 else 0
            # Switch dispatcher: when this PC is the first CMP of a
            # detected cascade, emit the case table above it so readers
            # see the dispatch shape before scrolling the individual
            # branches.
            if pc in switch_dispatchers:
                sw = _emit_switch_header(pc)
                if sw:
                    fh.write(sw)
            # SMC-opcode header: when this PC's opcode byte itself is
            # patched at runtime, the instruction TYPE may change. Emit
            # first so the reader sees the most-radical SMC warning
            # before any dispatch/branch headers.
            if pc in smc_opcode:
                header = _emit_smc_opcode_header(pc)
                if header:
                    fh.write(header)
            # SMC-dispatch header: when this PC is a known SMC-patched
            # JSR or JMP, emit a case-list comment block above the
            # instruction so the reader sees the dispatch table before
            # the opaque `jsr/jmp <placeholder>` line.
            if mnem_lower in ("jsr", "jmp") and pc in smc_dispatch:
                header = _emit_smc_dispatch_header(pc)
                if header:
                    fh.write(header)
            # SMC-branch header: when this PC is a known SMC-patched
            # conditional branch, warn that the static target is the
            # unpatched default — actual landing chosen at runtime.
            if mnem_lower in _BRANCH_FLAG and pc in smc_branch:
                header = _emit_smc_branch_header(pc)
                if header:
                    fh.write(header)
            # Step-idiom pre-comment: when the cmp_facts entry for this
            # branch matches the (INX/INY/INC × N + BPL/BMI on lhs-zero)
            # compound pattern, lay out the structure vertically so the
            # reader sees source / step count / branch test at a glance
            # rather than having to parse the slug.
            if mnem_lower in _BRANCH_FLAG and pc in cmp_facts:
                fact = cmp_facts[pc]
                lhs_for_idiom = fact.get("lhs") or {}
                step_info = _detect_step_idiom(
                    lhs_for_idiom,
                    fact.get("branch", ""),
                    fact.get("rhs") or {})
                # Only emit the visual-structure block when the source
                # is a real variable. For `imm`/`from_caller` sources
                # the slug is already short (`$05 back 1 pos`) and the
                # multi-line comment adds noise without insight.
                if step_info is not None and lhs_for_idiom.get("kind") in (
                        "var", "var_indirect"):
                    fh.write(_emit_step_idiom_comment(
                        fact, labels, block_pcs_sorted,
                        block_name_by_pc, step_info))
            operand = emit_64tass_instruction(mode, p1, p2, pc, labels=effective_labels,
                                              imm_subs=imm_subs,
                                              branch_operand_override=branch_operand_override,
                                              struct_segments=struct_segments,
                                              name_spans=name_spans,
                                              anchor_spans=HW_ANCHOR_REGIONS)
            if pc in function_entries_set:
                # The `funcname .block` directive above already declares
                # the entry label — emitting `funcname:` again here would
                # be a redundant double-definition.
                lbl_prefix = ""
            else:
                # Inside the current .block use the in-block name
                # (stripped form when the label had the funcname_ prefix,
                # else the full name); outside any block, use the stored
                # bare label.
                if (current_block_entry is not None
                        and label_block.get(pc) == current_block_entry):
                    lbl_name = inblock_name.get(pc, labels.get(pc))
                else:
                    lbl_name = labels.get(pc)
                lbl_prefix = f"{lbl_name}:" if lbl_name else ""
            # Duplicate-encoding undocumented opcodes ($2B ANC, $EB SBC)
            # can't round-trip through the mnemonic (64tass canonicalises
            # to $0B/$E9), so render them as `.byte` for byte-exactness
            # with the decoded instruction in the tail comment. They are
            # still classified as instructions, so the fall-through this
            # produces keeps the downstream run reachable.
            unsafe_instr_note = None
            if mem[pc] in ROUND_TRIP_UNSAFE_OPCODES:
                byte_list = ", ".join(f"${mem[pc + i]:02X}" for i in range(n))
                line = f"{lbl_prefix:<26} .byte {byte_list}"
                unsafe_instr_note = (f"; {mnem_lower} {operand.strip()} "
                                     f"(undocumented opcode ${mem[pc]:02X})")
            else:
                line = f"{lbl_prefix:<26} {mnem_lower:<4} {operand:<28}"

            # Branch-condition comment is now driven by the cmp_facts
            # table (precomputed CFG dataflow, see tools/re/cmp_facts.py).
            # When the fact is missing (cmp_facts.json not built) or
            # the lhs is unknown / multi_source, we emit no postfix
            # comment — silence is better than a misleading guess.
            cond_text = None
            if pc in branch_condition_overrides:
                cond_text = branch_condition_overrides[pc]
            elif mnem_lower in _BRANCH_FLAG and pc in cmp_facts:
                cond_text = render_condition_from_fact(
                    cmp_facts[pc], labels, value_names_per_var, imm_subs,
                    block_pcs_sorted=block_pcs_sorted,
                    block_name_by_pc=block_name_by_pc,
                    reg_inputs_per_fn=register_inputs)

            # Hardware-register decode: when this is a STA/STX/STY into
            # a register listed in HW_IMM_DECODERS and the immediately
            # prior instruction was a matching LD?-imm, append a short
            # hint decoding the bits being written (e.g. "BASIC off,
            # KERNAL+I/O in" for CPU_PORT). The strict "immediately
            # prior" rule avoids false positives from any intervening
            # instruction that would have invalidated the register's
            # contents — see prev_imm bookkeeping below.
            hw_text = None
            if (mnem_lower in ("sta", "stx", "sty")
                    and mode in ("abs", "abx", "aby")):
                tgt = p1 | (p2 << 8)
                reg = mnem_lower[-1]   # 'a', 'x', or 'y'
                imm = prev_imm.get(reg)
                if tgt in HW_IMM_DECODERS and imm is not None:
                    reg_name = labels.get(tgt, f"${tgt:04X}")
                    hw_text = (f"{reg_name} := {HW_IMM_DECODERS[tgt](imm)}")
            # SMC-immediate comment: classify the operand byte at pc+1
            # for any imm-mode 2-byte instruction (LDA/LDX/LDY/CMP/CPX/
            # CPY/ADC/SBC/AND/ORA/EOR). Three outcomes:
            #   labelled SMC slot     → `← <slot_name>`
            #   written-to but unnamed → `← (SMC operand, no name)`
            #   never written          → no comment (true constant)
            # The classifier comes from smc_write_targets — every
            # operand of an STA/STX/STY-abs in the image. Static `#$XX`
            # text stays unchanged so the round-trip preserves bytes.
            smc_imm_text = None
            if mode == "imm" and mnem_lower in _IMM_2BYTE_OPS:
                operand_byte_addr = pc + 1
                if operand_byte_addr in labels:
                    smc_imm_text = f"← {labels[operand_byte_addr]}"
                elif operand_byte_addr in smc_write_targets:
                    smc_imm_text = (f"← (SMC operand at "
                                    f"${operand_byte_addr:04X}, no name)")

            tail_parts: list[str] = []
            if unsafe_instr_note:
                tail_parts.append(unsafe_instr_note)
            if cond_text:
                tail_parts.append(cond_text)
            if hw_text:
                tail_parts.append(f"; {hw_text}")
            if smc_imm_text:
                tail_parts.append(f"; {smc_imm_text}")
            tail = ("  " + "  ".join(tail_parts)) if tail_parts else ""

            # Update prev_imm bookkeeping. LD?-imm seeds the matching
            # register's slot; every other instruction invalidates all
            # three (safer than tracking arithmetic / transfers).
            if mode == "imm" and mnem_lower in ("lda", "ldx", "ldy"):
                seeded = mnem_lower[-1]
                prev_imm = {"a": None, "x": None, "y": None,
                            seeded: p1}
            else:
                prev_imm = {"a": None, "x": None, "y": None}

            if with_bytes:
                bytes_hex = " ".join(f"{mem[pc + i]:02X}" for i in range(n))
                fh.write(f"{line}; ${pc:04X}  {bytes_hex}{tail}\n")
            else:
                fh.write(f"{line.rstrip()}    ; ${pc:04X}{tail}\n")
            recent_instr_pcs.append(pc)
            if len(recent_instr_pcs) > WINDOW_DEPTH:
                recent_instr_pcs.pop(0)
            pc += n
            if pc in seg_ends:
                emit_segment_footer(seg_ends[pc])
            pending_start = pc
            instr_count += 1
            continue
        if pc in consumed:
            # operand byte of an accepted instruction — already emitted as
            # part of that instruction's mnemonic+operand. shouldn't reach
            # here, but flush + advance just in case.
            flush_data()
            pc += 1
            pending_start = pc
            continue
        # data byte — also breaks the predecessor window since the next
        # instruction is reached from elsewhere, not by fall-through.
        if not pending_data:
            pending_start = pc
            recent_instr_pcs = []
            prev_imm = {"a": None, "x": None, "y": None}
        pending_data.append(mem[pc])
        data_count += 1
        pc += 1
        if pc in seg_ends:
            flush_data()
            emit_segment_footer(seg_ends[pc])
            pending_start = pc

    flush_data()
    # Close the final function block if still open at end of code.
    if current_block_entry is not None:
        fh.write(".bend\n")
        current_block_entry = None
    return instr_count, data_count


# ── Screen-code / PETSCII text encoding ────────────────────────────────
# Names match 64tass's built-in `.enc` modes: ``none`` is pass-through
# (PETSCII / ASCII for our uppercase strings) and ``screen`` maps ASCII
# uppercase letters to C64 screen codes.

def _encode_text(s: str, encoding: str) -> bytes:
    """Encode ``s`` per the 64tass encoding name. Returns bytes; raises
    ``ValueError`` for characters the encoding can't represent."""
    if encoding == "none":
        return s.encode("ascii")
    if encoding == "screen":
        out = bytearray()
        for c in s:
            n = ord(c)
            if 0x41 <= n <= 0x5A:        # 'A'-'Z' → $01-$1A
                out.append(n - 0x40)
            elif n == 0x40:              # '@' → $00
                out.append(0x00)
            elif n == 0x5B:              # '[' → $1B
                out.append(0x1B)
            elif n == 0x5D:              # ']' → $1D
                out.append(0x1D)
            elif 0x20 <= n <= 0x3F:      # ' '-'?' → same as ASCII
                out.append(n)
            else:
                raise ValueError(
                    f"screen encoding cannot represent {c!r} (U+{n:04X})")
        return bytes(out)
    raise ValueError(f"unknown encoding: {encoding!r}")


def load_text_segments(annotations_path: Path) -> dict[int, dict]:
    """Load address → text-segment dict from the ``[text]`` table.

    Schema::

        [text."$7D7F"]
        encoding = "screen"
        string   = "READ MORE? Y/N"
        reps     = 16   # optional, default 1 — emit as .rept block

    The caller validates that the encoded bytes match the static image
    at the declared address before emitting. Returns ``{}`` if the file
    is missing or the section absent.
    """
    if not annotations_path.is_file():
        return {}
    raw = tomllib.loads(annotations_path.read_text())
    out: dict[int, dict] = {}
    for addr_text, spec in raw.get("text", {}).items():
        if not (isinstance(addr_text, str) and addr_text.startswith("$")):
            continue
        try:
            addr = int(addr_text.lstrip("$"), 16)
        except ValueError:
            continue
        if not isinstance(spec, dict):
            continue
        encoding = spec.get("encoding", "none")
        string = spec.get("string", "")
        reps = int(spec.get("reps", 1))
        if not isinstance(string, str) or not string:
            continue
        if reps < 1:
            continue
        out[addr] = {"encoding": encoding, "string": string, "reps": reps}
    return out


def _parse_byte_literal(s: str | int) -> int:
    """Accept ``$XX`` / ``"$XX"`` / int and return a 0..255 value."""
    if isinstance(s, int):
        v = s
    elif isinstance(s, str):
        v = int(s.lstrip("$"), 16)
    else:
        raise ValueError(f"byte literal must be str or int: {s!r}")
    if not (0 <= v <= 0xFF):
        raise ValueError(f"byte literal out of range: {v}")
    return v


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_value_names(annotations: dict[int, dict]) -> dict[int, dict[int, str]]:
    """Return {var_addr: {imm_value: symbolic_name}} from per-var
    ``value_names`` sub-tables. Used to (a) emit named-constant equates
    next to each enum var and (b) substitute literal immediates with
    their symbolic name at emit time for `lda/cmp/sta` patterns whose
    immediate is provably bound to an enum-bound variable.

    Schema::

        [region."$7167".values]
        "$01" = "seqED"
        ...

        [region."$7167".value_names]
        "$01" = "UI_MODE_SEQED"
        ...
    """
    out: dict[int, dict[int, str]] = {}
    for addr, body in annotations.items():
        vn = body.get("value_names")
        if not isinstance(vn, dict):
            continue
        mapped: dict[int, str] = {}
        for vt, name in vn.items():
            if not (isinstance(vt, str) and vt.startswith("$")):
                continue
            try:
                v = int(vt.lstrip("$"), 16)
            except ValueError:
                continue
            if not (isinstance(name, str) and _IDENT_RE.match(name)):
                raise SystemExit(
                    f"value_names[${addr:04X}][{vt}]: {name!r} is not a "
                    f"valid 64tass identifier")
            if not (0 <= v <= 0xFF):
                continue
            mapped[v] = name
        if mapped:
            out[addr] = mapped
    return out


def load_register_inputs(annotations: dict[int, dict],
                         ) -> dict[int, dict[str, int]]:
    """Load per-function ``register_inputs`` declarations.

    Schema (in annotations.toml, under any ``[function."$XXXX"]`` block):

        register_inputs = { x = "kbd_modifiers", y = "kbd_decoded_key" }

    Returns ``{entry_pc: {"a"|"x"|"y": var_addr_int}}``. The var name is
    resolved by reverse-lookup against the annotation catalogue (every
    region with a ``name`` field is a candidate). Unresolved names raise
    SystemExit — typos in this field would silently break the imm-subst
    walker without it.

    Used by ``build_imm_substitutions`` to seed register provenance at
    each declared function entry, propagating enum bindings across the
    JSR/JMP boundaries the straight-line walker can't follow.
    """
    name_to_addr: dict[str, int] = {}
    for addr, body in annotations.items():
        name = body.get("name")
        if isinstance(name, str) and name:
            name_to_addr.setdefault(name, addr)
    out: dict[int, dict[str, int]] = {}
    for addr, body in annotations.items():
        seeds = body.get("register_inputs")
        if not isinstance(seeds, dict) or not seeds:
            continue
        resolved: dict[str, int] = {}
        for reg_key, var_name in seeds.items():
            reg = reg_key.lower()
            if reg not in ("a", "x", "y"):
                raise SystemExit(
                    f"[function.${addr:04X}].register_inputs: register "
                    f"{reg_key!r} must be one of a/x/y")
            if not isinstance(var_name, str) or var_name not in name_to_addr:
                raise SystemExit(
                    f"[function.${addr:04X}].register_inputs.{reg_key}: "
                    f"{var_name!r} not a known annotation `name`")
            resolved[reg] = name_to_addr[var_name]
        out[addr] = resolved
    return out


def build_imm_substitutions(mem: bytes, instr_at: dict,
                             value_names: dict[int, dict[int, str]],
                             register_inputs: dict[int, dict[str, int]] | None = None,
                             cmp_facts: dict[int, dict] | None = None,
                             ) -> dict[int, str]:
    """Walk instructions in PC order, track A/X/Y provenance, and
    return {pc_of_imm_instr: symbolic_name} for every immediate whose
    value is provably bound to an enum-bound variable's value_names.

    Patterns recognised:

      * ``lda/ldx/ldy #imm`` followed by ``sta/stx/sty enum_var`` —
        the imm at the LD-IMM PC gets the enum's symbolic name.
      * ``lda/ldx/ldy enum_var`` followed by ``cmp/cpx/cpy #imm`` —
        the imm at the CMP PC gets the symbolic name.

    ``register_inputs`` — optional ``{entry_pc: {reg: var_addr, ...}}``
    map sourced from `[function."$XXXX"].register_inputs` entries in
    annotations.toml. Seeds the walker's A/X/Y provenance whenever it
    reaches a function entry that declares register inputs. Lets
    cpy/cmp inside a dispatcher arm pick up the enum even when the
    LDY happens in the caller across a JSR boundary — e.g.
    `ldy kbd_decoded_key / jsr sidtab_cascade` reaches the arm with
    Y still bound to kbd_decoded_key, but the walker can't see that
    without the explicit hint.

    ``cmp_facts`` — optional ``{branch_pc: fact}`` from
    `tools/re/cmp_facts.py`. After the linear walker pass, a second
    pass consults cmp_facts for any ``cmp/cpx/cpy #imm`` site whose
    flag-setter PC the walker missed: cmp_facts' own data-flow
    analysis covers cascade-arm cases where the walker's PC-order
    state was clobbered by an unrelated LDY/LDX immediate in a prior
    arm's writer-dispatch tail (e.g. the seqLIST_handler arms after
    $E5xx where each arm sets up LDX/LDY for field_writer_dispatcher
    then jmp's away — the next arm's CPY is at a branch-target PC
    the walker can't reach with the correct register provenance).

    Branches, jumps, and any reg-mutating instruction (and/ora/eor,
    inx/iny, transfers, …) clear the corresponding register state, so
    only short straight-line windows match. The walker is intentionally
    conservative: false positives would rewrite a literal that isn't
    actually a member of the enum.
    """
    if not value_names:
        return {}
    register_inputs = register_inputs or {}
    pcs_sorted = sorted(instr_at.keys())
    # Register state: None | ("imm", value, imm_pc) | ("var", var_addr)
    A = X = Y = None
    subs: dict[int, str] = {}

    # Only function-end / call-site control transfers reset register
    # state in the PC-order linear walk. Conditional branches and bare
    # JMPs let the next instruction (in PC order) keep the provenance
    # we already have — JMPs because at runtime they preserve all
    # registers, conditional branches because the fall-through path
    # by definition keeps the predecessor's state. JSR / RTS / RTI
    # are the boundary cases: a called routine may clobber anything,
    # and a return restores the pre-JSR state (which the walker
    # doesn't track across the call). Cross-block JMPs that DO need
    # a register-state hint at the target should declare
    # `register_inputs` at the target function so the seed restores it.
    BRANCH_OPS = {"jsr", "rts", "rti"}

    def _operand_addr(mode: str, p1: int, p2: int) -> int | None:
        if mode == "abs":
            return p1 | (p2 << 8)
        if mode == "zp":
            return p1
        return None

    for pc in pcs_sorted:
        # Function-entry seed: if this PC is the start of a function
        # whose annotation declared register_inputs, override whatever
        # the walker's PC-order state has and bind A/X/Y to the
        # declared enum-var addresses.
        seeds = register_inputs.get(pc)
        if seeds:
            for reg_letter, var_addr in seeds.items():
                if var_addr not in value_names:
                    continue
                provenance = ("var", var_addr)
                if reg_letter == "a":
                    A = provenance
                elif reg_letter == "x":
                    X = provenance
                elif reg_letter == "y":
                    Y = provenance

        mnem, mode, n = instr_at[pc]
        op = mnem.lower()
        p1 = mem[pc + 1] if n >= 2 else 0
        p2 = mem[pc + 2] if n >= 3 else 0

        if mode == "imm":
            if op == "lda":
                A = ("imm", p1, pc)
                continue
            if op == "ldx":
                X = ("imm", p1, pc)
                continue
            if op == "ldy":
                Y = ("imm", p1, pc)
                continue
            if op in ("cmp", "cpx", "cpy"):
                reg = {"cmp": A, "cpx": X, "cpy": Y}[op]
                if reg is not None and reg[0] == "var":
                    var_addr = reg[1]
                    if var_addr in value_names and p1 in value_names[var_addr]:
                        subs[pc] = value_names[var_addr][p1]
                continue
            # AND/ORA/EOR/etc with imm clobbers A but doesn't bind it
            if op in ("and", "ora", "eor", "adc", "sbc"):
                A = None
                continue
            continue

        addr = _operand_addr(mode, p1, p2) if mode in ("abs", "zp") else None
        if mode in ("abs", "zp") and addr is not None:
            if op == "sta" and A is not None and A[0] == "imm":
                if addr in value_names and A[1] in value_names[addr]:
                    subs[A[2]] = value_names[addr][A[1]]
            elif op == "stx" and X is not None and X[0] == "imm":
                if addr in value_names and X[1] in value_names[addr]:
                    subs[X[2]] = value_names[addr][X[1]]
            elif op == "sty" and Y is not None and Y[0] == "imm":
                if addr in value_names and Y[1] in value_names[addr]:
                    subs[Y[2]] = value_names[addr][Y[1]]
            elif op == "lda":
                A = ("var", addr) if addr in value_names else None
            elif op == "ldx":
                X = ("var", addr) if addr in value_names else None
            elif op == "ldy":
                Y = ("var", addr) if addr in value_names else None
            elif op in ("and", "ora", "eor", "adc", "sbc"):
                A = None
            elif op in ("inc", "dec"):
                pass  # memory-only; registers untouched
            continue

        # Implied / transfer / branch / etc. — conservative state
        # clearing for anything that touches the registers. Transfers
        # only clobber the destination; the source is preserved.
        if op == "tax":
            X = None  # A → X (A preserved)
        elif op == "txa":
            A = None  # X → A (X preserved)
        elif op in ("inx", "dex"):
            X = None
        elif op == "tay":
            Y = None  # A → Y (A preserved)
        elif op == "tya":
            A = None  # Y → A (Y preserved)
        elif op in ("iny", "dey"):
            Y = None
        elif op in ("pla", "tsx"):
            A = None if op == "pla" else A
            X = None if op == "tsx" else X
        elif op in ("rol", "ror", "asl", "lsr") and mode == "acc":
            A = None
        elif op in BRANCH_OPS:
            # Conservative: clear all on any control transfer. (A more
            # precise walker would re-converge at branch targets, but
            # the false-negative cost is fine — we just won't rewrite
            # across branches.)
            A = X = Y = None

    # Supplement pass: consult cmp_facts for any cmp/cpx/cpy #imm the
    # linear walker missed. cmp_facts has proper data-flow resolution
    # (lhs.kind="var" with var_addr, plus from_caller resolution via
    # the containing block's register_inputs), so it covers cascade
    # arms where a prior arm's LDY/LDX immediate killed the walker's
    # bound-var provenance before the next arm's CPY at a branch
    # target PC.
    if cmp_facts:
        for _branch_pc, fact in cmp_facts.items():
            setter = fact.get("flag_setter") or {}
            if setter.get("mode") != "imm":
                continue
            setter_pc_text = setter.get("pc") or ""
            try:
                setter_pc = int(setter_pc_text.lstrip("$"), 16)
            except (AttributeError, ValueError):
                continue
            if setter_pc in subs:
                continue  # walker already substituted
            rhs = fact.get("rhs") or {}
            if rhs.get("kind") != "imm":
                continue
            rhs_text = rhs.get("value") or ""
            try:
                rhs_val = int(rhs_text.lstrip("$"), 16)
            except (AttributeError, ValueError):
                continue
            # Resolve lhs to an enum-bound variable: direct var, or
            # from_caller via the containing function's register_inputs.
            lhs = fact.get("lhs") or {}
            var_addr: int | None = None
            if lhs.get("kind") == "var":
                try:
                    var_addr = int(
                        (lhs.get("var_addr") or "").lstrip("$"), 16)
                except (AttributeError, ValueError):
                    var_addr = None
            elif lhs.get("kind") == "from_caller":
                reg_key = (lhs.get("reg") or "").lower()
                block_pc_text = (
                    (fact.get("containing_block") or {}).get("pc") or "")
                try:
                    block_pc = int(block_pc_text.lstrip("$"), 16)
                except (AttributeError, ValueError):
                    block_pc = None
                if block_pc is not None and reg_key in ("a", "x", "y"):
                    seeds = register_inputs.get(block_pc) or {}
                    var_addr = seeds.get(reg_key)
            if var_addr is None:
                continue
            names = value_names.get(var_addr)
            if not names or rhs_val not in names:
                continue
            subs[setter_pc] = names[rhs_val]

    return subs


def load_byte_runs(annotations_path: Path) -> dict[int, list[dict]]:
    """Load address → list-of-runs from the ``[byte_runs]`` table.

    Each run is one of:

      ``{ count = N, byte = "$XX" }``        → ``.fill N, $XX``
      ``{ bytes = ["$XX", ...], reps = M }`` → ``.rept M / .byte / .endrept``
        (``reps`` defaults to 1; emits a bare ``.byte`` line then.)

    Schema::

        [byte_runs."$7C00"]
        runs = [
          { count = 16, byte = "$30" },
          { count = 16, byte = "$31" },
          ...
        ]
    """
    if not annotations_path.is_file():
        return {}
    raw = tomllib.loads(annotations_path.read_text())
    out: dict[int, list[dict]] = {}
    for addr_text, spec in raw.get("byte_runs", {}).items():
        if not (isinstance(addr_text, str) and addr_text.startswith("$")):
            continue
        try:
            addr = int(addr_text.lstrip("$"), 16)
        except ValueError:
            continue
        if not isinstance(spec, dict):
            continue
        runs_in = spec.get("runs", [])
        if not isinstance(runs_in, list) or not runs_in:
            continue
        runs_out: list[dict] = []
        for r in runs_in:
            if not isinstance(r, dict):
                continue
            if "count" in r and "byte" in r:
                runs_out.append({
                    "kind": "fill",
                    "count": int(r["count"]),
                    "byte": _parse_byte_literal(r["byte"]),
                })
            elif "bytes" in r:
                bs = [_parse_byte_literal(b) for b in r["bytes"]]
                runs_out.append({
                    "kind": "bytes",
                    "bytes": bs,
                    "reps": int(r.get("reps", 1)),
                })
        if runs_out:
            out[addr] = runs_out
    return out


def _byte_runs_encoded_length(runs: list[dict]) -> int:
    n = 0
    for r in runs:
        if r["kind"] == "fill":
            n += r["count"]
        else:
            n += len(r["bytes"]) * r["reps"]
    return n


def _byte_runs_encoded(runs: list[dict]) -> bytes:
    out = bytearray()
    for r in runs:
        if r["kind"] == "fill":
            out.extend([r["byte"]] * r["count"])
        else:
            out.extend(bytes(r["bytes"]) * r["reps"])
    return bytes(out)


def load_ghidra_labels(symbols_path: Path) -> dict[int, str]:
    """Load USER_DEFINED labels from a Ghidra symbols.json export.

    Returns {addr: name}. Includes data-segment names (e.g.
    pat_base_lo @ $1A00) and state-var names (e.g. cbm_drive_num @
    $00BA) so operand resolution in emit_64tass_instruction renders
    them by name everywhere they're referenced.

    Skips DEFAULT (Ghidra-auto DAT_xxxx / FUN_xxxx) and IMPORTED
    entries; we only want the labels the importer or the analyst has
    actually committed to."""
    data = json.loads(symbols_path.read_text())
    out: dict[int, str] = {}
    for sym in data.get("symbols", []):
        if sym.get("source") != "USER_DEFINED":
            continue
        addr_text = sym["addr"]
        if addr_text.startswith("$"):
            addr_text = addr_text[1:]
        try:
            addr = int(addr_text, 16)
        except ValueError:
            continue
        # If a symbol has multiple aliases (Ghidra exports
        # "DAT_009e+1" entries for offsets inside a labelled run),
        # prefer the primary entry — but also fall through so the
        # first USER_DEFINED at an address wins.
        if addr not in out:
            out[addr] = sym["name"]
    return out


def load_annotations(annotations_path: Path) -> dict[int, dict]:
    """Load address → annotation-dict from a TOML file.

    Schema (see tools/re/annotations.toml for the canonical reference):
        [function."$XXXX"]   # for code-start addresses
        [region."$XXXX"]     # for non-code addresses (state vars, tables)

    Returned dict is keyed by integer address. The emitter does not
    distinguish [function] vs [region] for output — it dispatches on
    whether the address is a code-start at emit time. This keeps the
    TOML schema authorable (a reviewer can write [region] for a
    state byte without thinking about whether the emitter will treat
    it as code).

    Returns {} if the file does not exist (annotations are optional).
    """
    if not annotations_path.is_file():
        return {}
    raw = tomllib.loads(annotations_path.read_text())
    out: dict[int, dict] = {}
    for section_name in ("function", "region"):
        section = raw.get(section_name, {})
        for addr_text, body in section.items():
            if isinstance(addr_text, str) and addr_text.startswith("$"):
                addr_text = addr_text[1:]
            try:
                addr = int(addr_text, 16)
            except (ValueError, TypeError):
                continue
            if not isinstance(body, dict):
                continue
            out[addr] = dict(body)  # copy; downstream may mutate
    return out


def load_imm_overrides(annotations_path: Path) -> dict[int, str]:
    """Load per-PC IMM operand symbolic-name overrides from
    `[imm."$XXXX"]` sections. Returns {pc: symbolic_name}.

    Schema::

        [imm."$11C8"]
        name = "DECODER_THRESHOLD"   # symbolic name; valid 64tass ident

    The emitter looks up the static byte at `pc + 1` (the imm operand
    of the instruction starting at `pc`) and emits a NAMED CONSTANTS
    equate ``DECODER_THRESHOLD = $XX``, then substitutes the instruction's
    `#$XX` operand with `#DECODER_THRESHOLD`. Multiple PCs may share a
    name iff their IMM bytes match (the resolver enforces this).
    """
    if not annotations_path.is_file():
        return {}
    raw = tomllib.loads(annotations_path.read_text())
    section = raw.get("imm", {})
    out: dict[int, str] = {}
    for addr_text, body in section.items():
        if isinstance(addr_text, str) and addr_text.startswith("$"):
            addr_text = addr_text[1:]
        try:
            addr = int(addr_text, 16)
        except (ValueError, TypeError):
            continue
        if not isinstance(body, dict):
            continue
        name = body.get("name")
        if not (isinstance(name, str) and name):
            continue
        if not _IDENT_RE.match(name):
            raise SystemExit(
                f"imm[${addr:04X}].name: {name!r} is not a valid "
                f"64tass identifier")
        out[addr] = name
    return out


def resolve_imm_overrides(
    imm_overrides: dict[int, str],
    mem: bytes,
    instr_at: dict[int, tuple],
) -> tuple[dict[int, str], dict[str, int]]:
    """For each (pc, name) override, look up the IMM byte at pc+1 (the
    operand of the imm-mode instruction at pc). Returns:

    * ``imm_subs_additions`` — ``{pc: name}`` for the operand renderer.
    * ``named_constants`` — ``{name: value}`` for the equates section.

    Raises ``SystemExit`` when a name is bound to inconsistent values
    across PCs, when the PC isn't an imm-mode instruction, or when the
    PC has no entry in ``instr_at``.
    """
    if not imm_overrides:
        return {}, {}
    additions: dict[int, str] = {}
    constants: dict[str, int] = {}
    for pc, name in sorted(imm_overrides.items()):
        info = instr_at.get(pc)
        if info is None:
            raise SystemExit(
                f"imm[${pc:04X}]: no instruction starts here")
        _mnem, mode, n = info
        if mode != "imm" or n < 2:
            raise SystemExit(
                f"imm[${pc:04X}]: instruction is not imm-mode "
                f"(mode={mode!r}, n={n})")
        value = mem[pc + 1]
        prior = constants.get(name)
        if prior is not None and prior != value:
            raise SystemExit(
                f"imm[${pc:04X}]: name {name!r} already bound to "
                f"${prior:02X} elsewhere; cannot rebind to ${value:02X}")
        constants[name] = value
        additions[pc] = name
    return additions, constants


def load_branch_overrides(annotations_path: Path) -> dict[int, str]:
    """Load per-PC branch-comment overrides from `[branch."$XXXX"]`.

    Schema::

        [branch."$11C5"]
        condition = "decoder dest_lo step did not wrap"  # EOL comment

    A manual ``condition`` string overrides the auto-derived comment
    that ``render_condition_from_fact`` would produce for the branch
    at that PC. Used when cmp_facts can't reach an informative
    rendering or when the author wants a domain-specific phrasing.

    The legacy ``alias`` field that used to generate ``on_<slug>``
    target labels has been removed — branch operands now resolve
    through the standard ``lbl()`` chain (named label or
    ``<region> + $offset`` fallback). Any leftover ``alias = ...``
    line in the TOML is ignored silently; the schema doc above is the
    canonical reference.

    Returns ``{branch_pc: condition_string}``.
    """
    if not annotations_path.is_file():
        return {}
    raw = tomllib.loads(annotations_path.read_text())
    section = raw.get("branch", {})
    conditions: dict[int, str] = {}
    for addr_text, body in section.items():
        if isinstance(addr_text, str) and addr_text.startswith("$"):
            addr_text = addr_text[1:]
        try:
            addr = int(addr_text, 16)
        except (ValueError, TypeError):
            continue
        if not isinstance(body, dict):
            continue
        condition = body.get("condition")
        if isinstance(condition, str) and condition:
            conditions[addr] = condition
    return conditions


def extract_annotation_labels(annotations: dict[int, dict]) -> dict[int, str]:
    """Return {addr: name} from explicit ``name`` fields in the catalog.

    Refuted entries (loaded by load_refuted_addresses) are never
    label-eligible — they live in a separate `[refuted]` section and
    don't pass through load_annotations at all.
    """
    out: dict[int, str] = {}
    for addr, body in annotations.items():
        name = body.get("name", "")
        if isinstance(name, str) and name:
            out[addr] = name
    return out


def load_refuted_addresses(annotations_path: Path) -> set[int]:
    """Addresses with a `[refuted."$XXXX"]` entry. Excluded from labels."""
    if not annotations_path.is_file():
        return set()
    raw = tomllib.loads(annotations_path.read_text())
    out: set[int] = set()
    for addr_text in raw.get("refuted", {}):
        if isinstance(addr_text, str) and addr_text.startswith("$"):
            try:
                out.add(int(addr_text[1:], 16))
            except ValueError:
                continue
    return out


def load_cmp_facts(facts_path: Path) -> dict[int, dict]:
    """Load comparison-site facts (from `tools/re/cmp_facts.py`) keyed
    by integer branch PC.

    Each fact tells the emitter what a conditional branch is actually
    comparing — variable + transform chain on the lhs, immediate or
    variable on the rhs, plus the containing function block. Used to
    derive both the per-branch condition comment and the `on_<cond>`
    alias equates without re-running the PC-window walker at emit time.

    Returns {} if the file doesn't exist (cmp_facts is optional;
    without it the emitter falls back to bare disassembly labels).
    """
    if not facts_path.is_file():
        return {}
    data = json.loads(facts_path.read_text())
    out: dict[int, dict] = {}
    for k, v in data.get("facts", {}).items():
        if not (isinstance(k, str) and k.startswith("$")):
            continue
        try:
            pc = int(k.lstrip("$"), 16)
        except ValueError:
            continue
        out[pc] = v
    return out


def load_smc_opcode_catalogue(path: Path) -> dict[int, dict]:
    """Load SMC-opcode-flip catalogue (`smc_opcode.json`).

    Returns {host_pc: {description, patch_sources, current_mnem,
    candidate_opcodes, inconclusive}}. Curated `candidate_opcodes` wins
    over auto-discovered ones; if both are empty the entry is rendered
    with an "inconclusive" marker.

    Discovered (un-annotated) hosts that ARE hardware registers
    (`HW_LABELS`) are dropped: a store to a VIC/SID register address is
    an I/O write, but those addresses also alias RAM-under-I/O code, so
    Ghidra records the I/O store as a write-ref to a code byte and
    `_discover_smc_opcode_sites` reports a bogus opcode-flip whose
    "candidate" is the traced register *data* value (e.g. $00 -> BRK).
    The genuine SMC at those addresses is the per-voice operand/dispatch
    patch, catalogued separately as `smc_dispatch`. An explicit
    `[smc_opcode."$Dxxx"]` annotation overrides this and renders."""
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text())
    out: dict[int, dict] = {}
    for key, body in raw.items():
        if not isinstance(body, dict):
            continue
        try:
            pc = int(key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        if pc in HW_LABELS and not body.get("annotated"):
            continue
        sources = set(body.get("patch_sources_annotated") or [])
        sources.update(body.get("patch_sources_discovered") or [])
        # Curated candidates take precedence; fall back to discovered.
        candidates = list(body.get("candidate_opcodes_annotated") or [])
        if not candidates:
            candidates = list(body.get("candidate_opcodes_discovered") or [])
        targets: list[dict] = []
        for t in body.get("targets") or []:
            addr = t.get("addr")
            if isinstance(addr, str):
                try:
                    addr = int(addr.lstrip("$"), 16)
                except ValueError:
                    continue
            if isinstance(addr, int):
                targets.append({"addr": addr, "name": t.get("name", ""),
                                "context": t.get("context", "")})
        out[pc] = {
            "description": body.get("description", ""),
            "patch_sources": sorted(sources),
            "current_mnem": body.get("current_mnem", ""),
            "candidate_opcodes": candidates,
            "targets": targets,
            "inconclusive": bool(body.get("inconclusive")),
        }
    return out


def load_smc_branch_catalogue(path: Path) -> dict[int, dict]:
    """Load SMC-branch catalogue (`smc_branch.json`).

    Returns {branch_pc: {description, patch_sources}}. The emitter
    renders a short comment above each branch noting that its offset
    byte is patched at runtime.

    As in `load_smc_opcode_catalogue`, discovered (un-annotated) hosts
    that are hardware registers (`HW_LABELS`) are dropped — the "branch
    offset patch" is really a VIC/SID register store aliasing the
    RAM-under-I/O code byte. An explicit annotation overrides.
    """
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text())
    out: dict[int, dict] = {}
    for key, body in raw.items():
        if not isinstance(body, dict):
            continue
        try:
            pc = int(key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        if pc in HW_LABELS and not body.get("annotated"):
            continue
        sources = set(body.get("patch_sources_annotated") or [])
        sources.update(body.get("patch_sources_discovered") or [])
        out[pc] = {
            "description": body.get("description", ""),
            "patch_sources": sorted(sources),
        }
    return out


def load_smc_dispatch_catalogue(path: Path) -> dict[int, dict]:
    """Load SMC-JSR catalogue produced by ghidra_import (`smc_dispatch.json`).

    Returns {jsr_pc: {description, patch_sources (merged annotated +
    discovered), targets, annotated, discovered}}. The emitter renders
    a comment block above each JSR PC in this dict.
    """
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text())
    out: dict[int, dict] = {}
    for key, body in raw.items():
        if not isinstance(body, dict):
            continue
        try:
            pc = int(key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        sources = set(body.get("patch_sources_annotated") or [])
        sources.update(body.get("patch_sources_discovered") or [])
        out[pc] = {
            "description": body.get("description", ""),
            "patch_sources": sorted(sources),
            "targets": body.get("targets") or [],
            "annotated": bool(body.get("annotated")),
            "discovered": bool(body.get("discovered")),
        }
    return out


def load_ghidra_segments(segments_path: Path) -> list[dict]:
    """Load data segments from segments.json. Returned dicts have
    integer ``start``/``end_excl`` plus the upstream ``name``,
    ``element_size`` and ``comment`` fields. The optional ``struct``
    field (added by `ghidra_import.py` for segments with a typed
    layout — see PATTERN_STEP_FIELDS) is preserved as-is so the
    emitter's operand resolver can render struct-field expressions
    for intra-segment addresses. Sorted by start."""
    data = json.loads(segments_path.read_text())
    out: list[dict] = []
    for seg in data.get("segments", []):
        start_text = seg["start"].lstrip("$")
        end_text = seg["end_excl"].lstrip("$")
        row = {
            "start": int(start_text, 16),
            "end_excl": int(end_text, 16),
            "name": seg.get("name", ""),
            "element_size": seg.get("element_size", 1),
            "comment": seg.get("comment", ""),
        }
        if "struct" in seg:
            row["struct"] = seg["struct"]
        out.append(row)
    out.sort(key=lambda s: s["start"])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="artefacts/defmon-static.bin",
                    help="flat 64K static image")
    ap.add_argument("--entrypoints", default="trace/entrypoints.json",
                    help="JSON with executed PCs (code-start oracle)")
    ap.add_argument("--out", default="defmon.s",
                    help="output 64tass source")
    ap.add_argument("--start", type=lambda s: int(s, 0), default=LOAD_ADDR)
    ap.add_argument("--end", type=lambda s: int(s, 0), default=END_ADDR_EXCL,
                    help="end address (exclusive)")
    ap.add_argument("--bytes-only", action="store_true",
                    help="emit pure .byte for everything (no disassembly); "
                         "useful for re-validating the toolchain only")
    ap.add_argument("--with-bytes", action="store_true",
                    help="suffix every instruction line with its raw "
                         "machine-code bytes (e.g. `; $0828  8D F7 0A`). "
                         "Default off — the bytes column doubles line "
                         "width and is rarely consulted; the `; $XXXX` "
                         "address column always appears.")
    ap.add_argument("--ghidra", default="artefacts/ghidra",
                    help="directory holding Ghidra symbols.json + "
                         "segments.json (pass-2 inputs); pass an "
                         "empty string to disable")
    ap.add_argument("--annotations", default="tools/re/annotations.toml",
                    help="TOML file with [function.$XXXX] / [region.$XXXX] "
                         "blocks (centralised RE knowledge); pass an empty "
                         "string to disable")
    args = ap.parse_args()

    mem = Path(args.bin).read_bytes()
    if len(mem) < args.end:
        raise SystemExit(f"input too short: {len(mem)} < {args.end}")

    if args.bytes_only:
        code_starts: set[int] = set()
        expanded = code_starts
    else:
        code_starts = load_code_starts(Path(args.entrypoints))
        code_starts.update(SEED_LANDMARKS.keys())
        expanded = expand_code_starts(mem, code_starts, args.start, args.end)

    instr_at, consumed = classify(mem, expanded, args.start, args.end)

    # Pass-2 inputs: merge Ghidra-exported labels and segments.
    ghidra_label_count = 0
    segments: list[dict] = []
    labels = dict(SEED_LANDMARKS) if not args.bytes_only else {}
    # EQUATE_LABELS are non-code-start state vars (typically $00/BRK
    # bytes) — emitted as equates but not added to the code-start seed
    # set. See definition above.
    if not args.bytes_only:
        labels.update(EQUATE_LABELS)
        # Standard C64 hardware register + KERNAL labels (outside the
        # defMON image). Lower precedence than internal labels — only
        # fill addresses no SEED_LANDMARKS / EQUATE_LABELS already names.
        for addr, name in HW_LABELS.items():
            labels.setdefault(addr, name)
    if args.ghidra and not args.bytes_only:
        ghidra_dir = Path(args.ghidra)
        sym_path = ghidra_dir / "symbols.json"
        seg_path = ghidra_dir / "segments.json"
        if sym_path.is_file():
            extra = load_ghidra_labels(sym_path)
            # Ghidra USER_DEFINED labels are the source of truth; they
            # came from ghidra_import.py which seeded them from
            # SEED_LANDMARKS + STATE_LABELS. Override entries from the
            # in-file dict.
            labels.update(extra)
            ghidra_label_count = len(extra)
        if seg_path.is_file():
            segments = load_ghidra_segments(seg_path)
    # SMC-JSR catalogue: emitted by ghidra_import.py from annotations
    # plus auto-discovery (see `_export_smc_dispatch` in that file).
    smc_dispatch_map: dict[int, dict] = {}
    smc_branch_map: dict[int, dict] = {}
    smc_opcode_map: dict[int, dict] = {}
    if args.ghidra:
        smc_path = Path(args.ghidra) / "smc_dispatch.json"
        smc_dispatch_map = load_smc_dispatch_catalogue(smc_path)
        smcb_path = Path(args.ghidra) / "smc_branch.json"
        smc_branch_map = load_smc_branch_catalogue(smcb_path)
        smco_path = Path(args.ghidra) / "smc_opcode.json"
        smc_opcode_map = load_smc_opcode_catalogue(smco_path)

    annotations: dict[int, dict] = {}
    text_segments_map: dict[int, dict] = {}
    byte_runs_map: dict[int, list[dict]] = {}
    value_names_per_var: dict[int, dict[int, str]] = {}
    branch_condition_overrides: dict[int, str] = {}
    if args.annotations and not args.bytes_only:
        annotations = load_annotations(Path(args.annotations))
        text_segments_map = load_text_segments(Path(args.annotations))
        byte_runs_map = load_byte_runs(Path(args.annotations))
        value_names_per_var = load_value_names(annotations)
        branch_condition_overrides = load_branch_overrides(
            Path(args.annotations))
        # Auto-derive {addr: name} from annotation summaries that lead
        # with the `name — description` convention. Lower precedence
        # than SEED_LANDMARKS / EQUATE_LABELS / Ghidra (already in
        # `labels`); only fill addresses that don't have a label yet.
        for addr, name in extract_annotation_labels(annotations).items():
            labels.setdefault(addr, name)

    # Static call graph — the emitter consults it to derive the
    # "code edges / apparent (from data)" block for addresses with no
    # real code-edge inbound. Replaces the hand-written "Unreachable: …"
    # prose that step-1/2 chased with regex.
    graph = None
    if not args.bytes_only:
        from tools.re.callgraph import build as _build_callgraph
        graph = _build_callgraph(mem, set(instr_at.keys()), consumed,
                                 args.start, args.end)

    # Comparison-site facts (CFG-walked lhs/rhs per conditional branch).
    # Drives both the per-branch condition comment and the `on_<cond>`
    # alias equates. Optional: emit_source falls back to bare disassembly
    # when this file is missing.
    cmp_facts_path = Path(__file__).resolve().parents[2] / "build" / "cmp_facts.json"
    cmp_facts = load_cmp_facts(cmp_facts_path)

    # Per-PC IMM operand overrides (manual `[imm."$XXXX"]` entries).
    # Loaded here so the resolver can be passed into emit_source.
    imm_overrides_map: dict[int, str] = {}
    named_constants: dict[str, int] = {}
    if args.annotations and not args.bytes_only:
        imm_overrides_map = load_imm_overrides(Path(args.annotations))
        if imm_overrides_map:
            additions, named_constants = resolve_imm_overrides(
                imm_overrides_map, mem, instr_at)
            # Manual overrides win — apply AFTER build_imm_substitutions.
            imm_overrides_map = additions

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        register_inputs_map = load_register_inputs(annotations)
        imm_subs_map = build_imm_substitutions(mem, instr_at,
                                                value_names_per_var,
                                                register_inputs_map,
                                                cmp_facts=cmp_facts)
        imm_subs_map.update(imm_overrides_map)
        # Branch operands take their semantic name from alias equates
        # (`on_<cond> = $XXXX`). The landing keeps its block-relative
        # anchor (assigned inside emit_source) — see the comment near
        # `_build_block_pc_index` for rationale.
        if graph is not None and cmp_facts:
            _branch_targets = set(graph.code_in.keys())
            # Use the same label set that emit_source will see, so the
            # alias-dedup logic stays consistent.
            _labels_view = dict(labels)
            block_pcs_sorted, block_name_by_pc = _build_block_pc_index(
                annotations, instr_at)
            block_counters: dict[int, int] = {}
            for tgt in sorted(_branch_targets):
                if tgt in instr_at and tgt not in _labels_view:
                    block_pc = _nearest_block_pc(tgt, block_pcs_sorted)
                    if block_pc is not None and tgt != block_pc:
                        block_counters[block_pc] = block_counters.get(block_pc, 0) + 1
                        _labels_view[tgt] = (f"{block_name_by_pc[block_pc]}"
                                             f"_{block_counters[block_pc]}")
                    else:
                        _labels_view[tgt] = f"L_{tgt:04X}"
        # Branch operands resolve through the standard lbl() chain
        # (exact label → struct-segment → anchor → name_spans →
        # `region + $offset` fallback → bare hex). The predicate that
        # brought control to a given branch lives in the EOL comment,
        # not in the operand — see `render_condition_from_fact`.
        # Detect switch dispatchers (CMP/branch cascades on the same
        # variable). Pure documentation — adds a Ghidra-style case
        # table comment above the first CMP of each detected group.
        switch_dispatchers = detect_switch_dispatchers(
            cmp_facts, labels, value_names_per_var) if cmp_facts else {}
        ic, dc = emit_source(mem, args.start, args.end, instr_at, consumed, fh,
                             labels=labels, segments=segments,
                             annotations=annotations, graph=graph,
                             with_bytes=args.with_bytes,
                             text_segments=text_segments_map,
                             byte_runs=byte_runs_map,
                             imm_subs=imm_subs_map,
                             value_names_per_var=value_names_per_var,
                             cmp_facts=cmp_facts,
                             branch_condition_overrides=branch_condition_overrides,
                             named_constants=named_constants,
                             smc_dispatch=smc_dispatch_map,
                             smc_branch=smc_branch_map,
                             smc_opcode=smc_opcode_map,
                             switch_dispatchers=switch_dispatchers,
                             register_inputs=register_inputs_map)

    total = args.end - args.start
    print(f"wrote {out_path}  ({total} bytes  ${args.start:04X}-${args.end - 1:04X})")
    print(f"  instructions = {ic}  ({ic / max(1, total) * 100:.1f}% of starts)")
    print(f"  data bytes   = {dc}  ({dc / max(1, total) * 100:.1f}%)")
    print(f"  seed code-starts (entrypoints.json) = {len(code_starts)}")
    print(f"  expanded code-starts (+fallthrough +abs targets) = {len(expanded)}")
    rejected = len(expanded) - ic
    if rejected:
        print(f"  rejected code-starts (overlap/oob/unknown opcode) = {rejected}")
    if ghidra_label_count or segments:
        print(f"  ghidra labels merged = {ghidra_label_count}")
        print(f"  ghidra data segments = {len(segments)} "
              f"(annotated as block headers)")
    if annotations:
        n_func = sum(1 for addr in annotations if addr in instr_at)
        n_region = len(annotations) - n_func
        print(f"  annotations merged   = {len(annotations)} "
              f"({n_func} function, {n_region} region)")


if __name__ == "__main__":
    main()
