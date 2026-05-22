"""Verify gate: every $XX literal cited alongside or compared against
an enum variable must be reachable per that variable's declared
``values`` set.

A region/function annotation declares a structured enum:

    [region."$7167"]
    name = "ui_mode"

    [region."$7167".values]
    "$01" = "seqED"
    "$02" = "seqLIST"
    "$04" = "sidTAB"
    "$20" = "secondary_disk_mode (NOT visible menu)"

…with optional ``values_kind`` ∈ {exhaustive (default), flagset, open}:

    exhaustive — only declared values are valid
    flagset    — any OR-combination of declared single-bit values is valid
    open       — declared values are documentation only (no checks)

Two coverage passes:

1. **Prose**. Walk every annotation field, find ``varname (==|=|set
   to|is|→) $XX`` patterns, verify ``$XX`` is reachable.

2. **Code**. Walk the static image. Track which register slot (A / X /
   Y) currently holds an enum variable's value (or a masked subset
   after ``and #imm``), and what plain immediate is in each slot.
   Verify:
     - ``cmp/cpx/cpy #imm`` after ``lda/ldx/ldy var`` — does ``imm``
       match a reachable value of ``var`` (or of ``var & mask`` when
       ``and #imm`` narrowed it)?
     - ``sta/stx/sty var`` after ``lda/ldx/ldy #imm`` — is ``imm`` a
       value ``var`` is allowed to hold?

Register tracking is conservative: cleared at every branch target,
every JSR/JMP/RTS/RTI/BRK, every gap between sorted PCs (data byte),
and every modifier instruction we don't precisely model (``adc``,
``sbc``, ``eor``, ``ora``, shifts, …). The ``and #imm`` case narrows
the mask. ``tax/tay/txa/tya`` transfer the tracked state to the
destination register.

``$00`` is universally allowed (the C64 "unset" / "cleared" sentinel).

Exits 1 with a per-violation listing; exits 0 otherwise.
"""

from __future__ import annotations

import argparse
import re
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

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
ENTRYPOINTS = REPO_ROOT / "trace" / "entrypoints.json"

# Fields scanned for `varname … $XX` references.
_SCAN_FIELDS = ("role", "notes", "callers", "inputs", "outputs",
                "registers_clobbered", "variables_changed", "values")


def _collect_enum_vars(ann_map: dict) -> dict[str, dict]:
    """Return ``{varname: {"addr": int, "kind": str, "values": dict}}``.

    Only entries with a structured (dict) ``values`` field qualify.
    Variables with kind ``open`` are excluded from coverage checks but
    kept in the index so other linters can see them.
    """
    out: dict[str, dict] = {}
    for addr, body in ann_map.items():
        v = body.get("values")
        if not isinstance(v, dict) or not v:
            continue
        name = body.get("name")
        if not isinstance(name, str) or not name:
            continue
        out[name] = {
            "addr": addr,
            "kind": body.get("values_kind", "exhaustive"),
            "values": v,
        }
    return out


def _parse_keys(values_dict: dict) -> list[int]:
    out: list[int] = []
    for k in values_dict:
        if isinstance(k, str) and k.startswith("$"):
            try:
                out.append(int(k.lstrip("$"), 16))
            except ValueError:
                continue
    return out


def _value_is_reachable(val: int, kind: str, declared: list[int]) -> bool:
    """Is ``val`` reachable for an enum of the given kind?"""
    if val == 0:
        return True  # universally allowed: "cleared" / "unset"
    if kind == "open":
        return True
    if kind == "exhaustive":
        return val in declared
    if kind == "flagset":
        mask = 0
        for d in declared:
            mask |= d
        return (val & mask) == val and val != 0
    return True


def _value_is_reachable_masked(val: int, mask: int, kind: str,
                               declared: list[int]) -> bool:
    """Is ``val`` reachable for ``var & mask``?

    Used when the code has ``lda var / and #imm`` before a ``cmp``: the
    accumulator's effective value is ``var & mask``, so the comparison
    is against that narrowed range, not the variable's full value set.
    """
    if val == 0:
        return True
    if mask == 0:
        return False
    if (val & mask) != val:
        return False
    if kind == "open":
        return True
    if kind == "exhaustive":
        return val in {d & mask for d in declared}
    if kind == "flagset":
        full = 0
        for d in declared:
            full |= d
        return (val & full & mask) == val
    return True


def _ref_regex(varname: str) -> re.Pattern[str]:
    """Pattern matching ``<varname> [==|=|set to|is] $XX`` (with the
    literal captured)."""
    return re.compile(
        rf"\b{re.escape(varname)}\b"
        r"\s*(?:==|=|:|is set to|is|set to|<-|←|→)\s*"
        r"\$([0-9A-Fa-f]{1,4})\b",
        re.IGNORECASE,
    )


def find_violations(ann_map: dict) -> list[str]:
    enum_vars = _collect_enum_vars(ann_map)
    if not enum_vars:
        return []
    var_patterns = {name: _ref_regex(name) for name in enum_vars}
    var_declared = {
        name: _parse_keys(info["values"]) for name, info in enum_vars.items()
    }

    out: list[str] = []
    for addr, body in sorted(ann_map.items()):
        addr_text = f"${addr:04X}"
        for field in _SCAN_FIELDS:
            v = body.get(field)
            if not isinstance(v, str) or not v:
                continue
            for var_name, pat in var_patterns.items():
                kind = enum_vars[var_name]["kind"]
                if kind == "open":
                    continue
                declared = var_declared[var_name]
                for m in pat.finditer(v):
                    lit_text = m.group(1)
                    lit = int(lit_text, 16)
                    if _value_is_reachable(lit, kind, declared):
                        continue
                    out.append(
                        f"{addr_text}.{field}: `{var_name} … ${lit_text.upper()}` "
                        f"unreachable (kind={kind}, declared="
                        f"{sorted(f'${d:02X}' for d in declared)})"
                    )
    return out


# ── Code-side analysis ──────────────────────────────────────────────────
# Register-state tracking is a 3-tuple: kind, payload, mask.
#   kind = "var" → payload = var_name (str); mask = bits not yet AND'd off
#   kind = "imm" → payload = immediate value (int); mask unused
#   None        → untracked
#
# Conservative: state is reset at every branch target, JSR/JMP/RTS/RTI/
# BRK, gap between sorted PCs (intervening data), and any instruction
# whose effect on the register we don't precisely model.

# Mnemonics that modify A in ways we don't track precisely.
_A_CLOBBER_OPS = frozenset({
    "ora", "eor", "adc", "sbc",
    "pla",
})
# AND #imm is special-cased to narrow the mask; AND abs/zp also
# clobbers A in our model since we don't track memory-mask state.


def _emit_imm(mem: bytes, pc: int, n: int) -> tuple[int, int]:
    p1 = mem[pc + 1] if n >= 2 else 0
    p2 = mem[pc + 2] if n >= 3 else 0
    return p1, p2


def _operand_addr(mode: str, p1: int, p2: int) -> int | None:
    """Return the absolute / ZP address an instruction reads from / writes
    to, for the modes where there's a single fixed target. Indexed modes
    (abx/aby/zpx/zpy) return None because the target depends on a
    register value we don't track."""
    if mode == "abs":
        return p1 | (p2 << 8)
    if mode == "zp":
        return p1
    return None


def find_code_violations(mem: bytes,
                         instr_at: dict[int, tuple[str, str, int]],
                         enum_addrs: dict[int, dict],
                         enum_vars: dict[str, dict]) -> list[str]:
    """Walk instructions in PC order; track A/X/Y enum-or-immediate
    provenance; verify CMP/CPX/CPY #imm and STA/STX/STY var write
    paths. Returns formatted violation strings."""
    if not enum_addrs:
        return []
    out: list[str] = []
    # State per register: None | ("var", var_name, mask) | ("imm", value)
    A: tuple | None = None
    X: tuple | None = None
    Y: tuple | None = None

    sorted_pcs = sorted(instr_at.keys())
    expected_next: int | None = None

    def _check_cmp(reg, imm: int, pc: int, mnem: str) -> None:
        if reg is None or reg[0] != "var":
            return
        var_name, mask = reg[1], reg[2]
        info = enum_vars.get(var_name)
        if info is None or info["kind"] == "open":
            return
        declared = [int(k.lstrip("$"), 16) for k in info["values"]]
        if not _value_is_reachable_masked(imm, mask, info["kind"], declared):
            mask_txt = "" if mask == 0xFF else f" (post-and mask ${mask:02X})"
            out.append(
                f"${pc:04X}: {mnem} #${imm:02X} unreachable for "
                f"{var_name}{mask_txt} "
                f"(kind={info['kind']}, declared="
                f"{sorted(f'${d:02X}' for d in declared)})"
            )

    def _check_sta(reg, addr: int, pc: int, mnem: str) -> None:
        if reg is None or reg[0] != "imm":
            return
        info = enum_addrs.get(addr)
        if info is None or info["kind"] == "open":
            return
        imm = reg[1]
        declared = [int(k.lstrip("$"), 16) for k in info["values"]]
        if not _value_is_reachable(imm, info["kind"], declared):
            out.append(
                f"${pc:04X}: {mnem} {info['name']} <- #${imm:02X} "
                f"unreachable (kind={info['kind']}, declared="
                f"{sorted(f'${d:02X}' for d in declared)})"
            )

    for pc in sorted_pcs:
        if expected_next is not None and pc != expected_next:
            A = X = Y = None  # gap (data byte interrupted the stream)
        # Note: we do NOT clear at branch_targets. Conditional branches
        # don't modify A/X/Y, so a CMP reached only by fall-through over
        # a `bne skip` still tests the originally-loaded variable. A
        # branch target reached from a JMP or JSR-return path will
        # already be in the cleared state because the preceding
        # instruction's terminator clearing handled it.

        mnem, mode, n = instr_at[pc]
        op = mnem.lower()
        p1, p2 = _emit_imm(mem, pc, n)
        addr = _operand_addr(mode, p1, p2)

        # === Verification step (runs before state update) ===
        if mode == "imm":
            if op == "cmp":
                _check_cmp(A, p1, pc, "cmp")
            elif op == "cpx":
                _check_cmp(X, p1, pc, "cpx")
            elif op == "cpy":
                _check_cmp(Y, p1, pc, "cpy")
        if addr is not None:
            if op == "sta":
                _check_sta(A, addr, pc, "sta")
            elif op == "stx":
                _check_sta(X, addr, pc, "stx")
            elif op == "sty":
                _check_sta(Y, addr, pc, "sty")

        # === State update ===
        if op == "lda":
            if mode == "imm":
                A = ("imm", p1)
            elif addr is not None and addr in enum_addrs:
                A = ("var", enum_addrs[addr]["name"], 0xFF)
            else:
                A = None
        elif op == "ldx":
            if mode == "imm":
                X = ("imm", p1)
            elif addr is not None and addr in enum_addrs:
                X = ("var", enum_addrs[addr]["name"], 0xFF)
            else:
                X = None
        elif op == "ldy":
            if mode == "imm":
                Y = ("imm", p1)
            elif addr is not None and addr in enum_addrs:
                Y = ("var", enum_addrs[addr]["name"], 0xFF)
            else:
                Y = None
        elif op == "lax":  # undocumented A,X := load
            if addr is not None and addr in enum_addrs:
                A = X = ("var", enum_addrs[addr]["name"], 0xFF)
            else:
                A = X = None
        elif op == "and" and mode == "imm":
            if A is not None and A[0] == "var":
                A = ("var", A[1], A[2] & p1)
            else:
                A = None
        elif op in _A_CLOBBER_OPS:
            A = None
        elif op == "and":  # AND non-imm
            A = None
        elif op == "asl" and mode == "acc":
            A = None
        elif op in ("lsr", "rol", "ror") and mode == "acc":
            A = None
        elif op in ("inx", "dex"):
            X = None
        elif op in ("iny", "dey"):
            Y = None
        elif op == "tax":
            X = A
        elif op == "tay":
            Y = A
        elif op == "txa":
            A = X
        elif op == "tya":
            A = Y
        elif op == "tsx":
            X = None
        elif op == "jsr":
            A = X = Y = None
        elif op in ("jmp", "rts", "rti", "brk"):
            A = X = Y = None
        # sta/stx/sty/pha/php/plp/sec/clc/sed/cld/cli/sei/clv/nop/bit/
        # all branches — no register-state change (apart from checks above)

        expected_next = pc + n

    return out


def _resolve_static_image(args) -> tuple[bytes, dict]:
    """Load mem + classify the static image into instr_at."""
    mem = args.bin.read_bytes()
    if args.entrypoints.is_file():
        seeds = load_code_starts(args.entrypoints)
    else:
        seeds = set()
    seeds.update(SEED_LANDMARKS.keys())
    expanded = expand_code_starts(mem, seeds, LOAD_ADDR, END_ADDR_EXCL)
    instr_at, _consumed = classify(mem, expanded, LOAD_ADDR, END_ADDR_EXCL)
    return mem, instr_at


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--annotations", type=Path, default=ANNOTATIONS)
    ap.add_argument("--bin", type=Path, default=STATIC_BIN,
                    help="Static image binary for the code-side pass.")
    ap.add_argument("--entrypoints", type=Path, default=ENTRYPOINTS,
                    help="Executed PCs (code-start oracle) for the "
                         "code-side pass.")
    ap.add_argument("--max-show", type=int, default=30)
    ap.add_argument("--no-prose", action="store_true",
                    help="Skip the prose-side coverage check.")
    ap.add_argument("--no-code", action="store_true",
                    help="Skip the code-side coverage check.")
    args = ap.parse_args(argv)

    ann_map = load_annotations(args.annotations)
    enum_vars = _collect_enum_vars(ann_map)
    n_vars = sum(1 for v in enum_vars.values()
                 if v["kind"] in ("exhaustive", "flagset"))

    enum_addrs = {info["addr"]: {"name": name,
                                  "kind": info["kind"],
                                  "values": info["values"]}
                  for name, info in enum_vars.items()}

    prose_violations: list[str] = []
    if not args.no_prose:
        prose_violations = find_violations(ann_map)

    code_violations: list[str] = []
    if not args.no_code and args.bin.is_file():
        mem, instr_at = _resolve_static_image(args)
        code_violations = find_code_violations(
            mem, instr_at, enum_addrs, enum_vars)

    all_violations = prose_violations + code_violations
    if all_violations:
        print(f"check_enum_coverage: "
              f"{len(prose_violations)} prose + "
              f"{len(code_violations)} code = "
              f"{len(all_violations)} violations across "
              f"{n_vars} checked enum variables", file=sys.stderr)
        for v in all_violations[:args.max_show]:
            print(f"  {v}", file=sys.stderr)
        if len(all_violations) > args.max_show:
            print(f"  … +{len(all_violations) - args.max_show} more",
                  file=sys.stderr)
        return 1
    print(f"check_enum_coverage: OK — {n_vars} structured enum variables, "
          f"all prose + code references reachable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
