"""Verify gate: every annotation entry has a well-shaped `name` + `role`.

This replaces the old hex/regex-based shape inference. After the
2026-05-16 schema split, each `[function|region]."$XXXX"` entry must
have explicit `name` (label, lowercase snake_case, ≤64 chars, no
RE-bookkeeping prefixes) and `role` (one-sentence semantic role,
≤200 chars target, ends in period). `[refuted]` entries need
`former_name` + `ruling`.

This is the schema-validation gate: it catches the *structural*
problems that produced RE-narrative leaks in earlier rounds (REFUTED_*
labels, missing name prefixes, multi-sentence rambling roles).

Exits 1 with a per-entry listing on any violation; exits 0 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"

_NAME_BAD_PREFIXES = ("REFUTED_", "loc_", "probe_", "unused_")
_NAME_SHAPE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")
_ROLE_SOFT_LIMIT = 200
_ROLE_HARD_LIMIT = 400
_NAME_MAX = 64

# Tokens whose case is meaningful. Any `_`-separated piece of a name
# that has uppercase letters must be one of these — everything else
# must be lowercase. Keeps the schema rule simple: snake_case by
# default, with a flat allow-list of conventional abbreviations.
_UPPER_TOKENS_OK = frozenset({
    # C64 hardware / KERNAL namespaces (prefix form)
    "SID", "SID2", "VIC", "CIA1", "CIA2", "KERNAL", "VEC", "COLOR",
    "NOTE", "CPU", "GATE", "NMI", "IRQ", "RAM", "ROM",
    # defMON tracker mode names
    "seqED", "seqLIST", "sidTAB",
    # C64 keyboard key labels
    "CRSRLR", "CRSRUD", "CBM",
    # SID voice IDs (used in V0/V1/V2 names)
    "V0", "V1", "V2",
    # 6502 undocumented opcodes
    "SAX", "LAX",
    # defMON internal abbreviations
    "JP", "DL", "PS", "SC",
})
# Single uppercase letters (e.g. disk_menu_R_handler where R is the key).
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    _UPPER_TOKENS_OK = _UPPER_TOKENS_OK | {_c}


_HW_NAMESPACES = frozenset({
    "SID", "SID2", "VIC", "CIA1", "CIA2", "KERNAL", "VEC", "COLOR", "CPU",
})

# `constraints` table — structured invariants the emitter+graph need
# to know (e.g. "this run of instructions must not be reordered because
# their operand bytes are aliased as a slide-oscillator accumulator").
# Replaces hand-written "DO NOT reorder — offsets are load-bearing"
# prose that the gate now bans in regular fields.
_CONSTRAINTS_KEYS_OK = frozenset({
    "do_not_reorder", "load_bearing_offsets", "because",
})
_RANGE_RE = re.compile(r"^\$[0-9A-F]{4}\.\.\$[0-9A-F]{4}$")

# `values` schema: a structured enum declaration. Either a string
# (legacy free-form prose) or a TOML sub-table { "$XX" = "name", … }.
# The sibling `values_kind` declares how strictly the enum is enforced:
#   exhaustive (default) — only declared values are valid
#   flagset              — any OR-combination of declared bits is valid
#   open                 — declared values are documentation only
_VALUES_KIND_OK = frozenset({"exhaustive", "flagset", "open"})
_VALUES_KEY_RE = re.compile(r"^\$[0-9A-Fa-f]{1,4}$")
_VALUES_NAME_MAX = 200


_VALUE_NAME_IDENT_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _value_names_violations(addr_text: str, value_names: object,
                            values: object) -> list[str]:
    out: list[str] = []
    if not isinstance(value_names, dict):
        out.append(f"{addr_text}.value_names: not a table "
                   f"({type(value_names).__name__})")
        return out
    if not isinstance(values, dict):
        out.append(f"{addr_text}.value_names: set without a structured "
                   "`values` sub-table")
        return out
    seen_names: set[str] = set()
    for k, v in value_names.items():
        if not isinstance(k, str) or not _VALUES_KEY_RE.match(k):
            out.append(f"{addr_text}.value_names: key {k!r} is not "
                       "`$HH..$HHHH` hex form")
            continue
        if k not in values:
            out.append(f"{addr_text}.value_names[{k}]: no matching entry "
                       "in `values` — every named constant must reference "
                       "a declared value")
        if not isinstance(v, str):
            out.append(f"{addr_text}.value_names[{k}]: not a string")
            continue
        if not _VALUE_NAME_IDENT_RE.match(v):
            out.append(f"{addr_text}.value_names[{k}]: {v!r} must be "
                       "UPPER_SNAKE_CASE (matches `[A-Z_][A-Z0-9_]*`)")
            continue
        if v in seen_names:
            out.append(f"{addr_text}.value_names[{k}]: duplicate name "
                       f"{v!r} within this variable")
        seen_names.add(v)
    return out


def _values_violations(addr_text: str, values: object,
                       kind: object) -> list[str]:
    out: list[str] = []
    if isinstance(values, str):
        if kind is not None:
            out.append(f"{addr_text}.values_kind: only valid when "
                       "values is a structured sub-table")
        return out
    if values is None:
        if kind is not None:
            out.append(f"{addr_text}.values_kind: set without a values "
                       "sub-table")
        return out
    if not isinstance(values, dict):
        out.append(f"{addr_text}.values: must be a string or a sub-table "
                   f"({type(values).__name__})")
        return out
    if not values:
        out.append(f"{addr_text}.values: empty sub-table")
    for k, v in values.items():
        if not isinstance(k, str) or not _VALUES_KEY_RE.match(k):
            out.append(f"{addr_text}.values: key {k!r} is not `$HH..$HHHH` "
                       "hex form")
            continue
        if not isinstance(v, str):
            out.append(f"{addr_text}.values[{k}]: not a string")
            continue
        if not v.strip():
            out.append(f"{addr_text}.values[{k}]: empty")
        if len(v) > _VALUES_NAME_MAX:
            out.append(f"{addr_text}.values[{k}]: {len(v)} chars "
                       f"(soft limit {_VALUES_NAME_MAX})")
    if kind is not None:
        if not isinstance(kind, str) or kind not in _VALUES_KIND_OK:
            out.append(f"{addr_text}.values_kind: must be one of "
                       f"{sorted(_VALUES_KIND_OK)} (got {kind!r})")
    if isinstance(kind, str) and kind == "flagset":
        for k in values:
            if not isinstance(k, str) or not _VALUES_KEY_RE.match(k):
                continue
            n = int(k.lstrip("$"), 16)
            if n == 0 or n & (n - 1) != 0:
                out.append(f"{addr_text}.values[{k}]: flagset entry must "
                           "be a single-bit value (1, 2, 4, 8, …)")
    return out



def _constraints_violations(addr_text: str, c: object) -> list[str]:
    out: list[str] = []
    if not isinstance(c, dict):
        return [f"{addr_text}.constraints: not a table"]
    unknown = sorted(set(c.keys()) - _CONSTRAINTS_KEYS_OK)
    if unknown:
        out.append(f"{addr_text}.constraints: unknown keys {unknown} "
                   f"(allowed: {sorted(_CONSTRAINTS_KEYS_OK)})")
    if "do_not_reorder" in c and not isinstance(c["do_not_reorder"], bool):
        out.append(f"{addr_text}.constraints.do_not_reorder: not a bool")
    if "because" in c and not isinstance(c["because"], str):
        out.append(f"{addr_text}.constraints.because: not a string")
    lbo = c.get("load_bearing_offsets")
    if lbo is not None:
        if not isinstance(lbo, list):
            out.append(f"{addr_text}.constraints.load_bearing_offsets: "
                       "not a list")
        else:
            for i, entry in enumerate(lbo):
                if not isinstance(entry, str) or not _RANGE_RE.match(entry):
                    out.append(f"{addr_text}.constraints."
                               f"load_bearing_offsets[{i}]: "
                               f"{entry!r} — expected '$XXXX..$YYYY'")
    # If any restrictive constraint is set, `because` is required —
    # rules out unexplained imperatives.
    has_restriction = (c.get("do_not_reorder") is True
                       or c.get("load_bearing_offsets"))
    if has_restriction and not c.get("because"):
        out.append(f"{addr_text}.constraints: `because` is required when "
                   "a restriction is set (every imperative needs a reason)")
    return out


def _derived_override_violations(addr_text: str, body: dict) -> list[str]:
    """Validate the `derived_override` escape hatch.

    `derived_override` is a non-empty string explaining why this entry
    needs a hand-written `callers` field that disagrees with the static
    call-graph's count. Typical reasons: SMC-patched JMP source, jump-
    table indirect target, computed JMP. Setting `derived_override`
    suppresses the callgraph-check mismatch error for this address.

    Required when set:
      - `callers` must be present (the override exists to keep a hand
        value that the graph can't reproduce).
      - the string is non-empty.
    """
    out: list[str] = []
    v = body.get("derived_override")
    if not isinstance(v, str):
        out.append(f"{addr_text}.derived_override: not a string")
        return out
    if not v.strip():
        out.append(f"{addr_text}.derived_override: empty — "
                   "every override needs an explanation")
    if not body.get("callers"):
        out.append(f"{addr_text}.derived_override: set without a "
                   "hand-written `callers` — the override exists to "
                   "justify a hand value that the graph can't see")
    return out


_INLINE_PC_RE = re.compile(r"^\$[0-9A-F]{4}$")


def _inline_comments_violations(addr_text: str, body: dict) -> list[str]:
    """Validate the `inline_comments` field.

    `inline_comments` is a TOML table keyed by `$XXXX` PC strings whose
    values are comment strings that the emitter renders as `;     <text>`
    lines above the matching instruction. Use it to attach
    per-instruction semantics (e.g. `"$0DBB" = "'T' status-line prefix"`)
    that would otherwise have to live as restatement prose in `notes`.

    Required when set:
      - Keys are `$XXXX` uppercase-hex addresses.
      - Values are non-empty strings, no newlines.
      - Comment length ≤ 160 chars (keep it inline-readable).
    """
    out: list[str] = []
    v = body.get("inline_comments")
    if v is None:
        return out
    if not isinstance(v, dict):
        out.append(f"{addr_text}.inline_comments: not a table")
        return out
    for k, val in v.items():
        if not isinstance(k, str) or not _INLINE_PC_RE.match(k):
            out.append(f"{addr_text}.inline_comments: key {k!r} not in "
                       "`$XXXX` form (uppercase hex)")
            continue
        if not isinstance(val, str):
            out.append(f"{addr_text}.inline_comments.{k}: not a string")
            continue
        if not val.strip():
            out.append(f"{addr_text}.inline_comments.{k}: empty string")
        if "\n" in val:
            out.append(f"{addr_text}.inline_comments.{k}: contains newline — "
                       "must fit on one comment line")
        if len(val) > 160:
            out.append(f"{addr_text}.inline_comments.{k}: too long "
                       f"({len(val)} chars; cap is 160)")
    return out


def _name_violations(addr_text: str, name: str) -> list[str]:
    out: list[str] = []
    if not _NAME_SHAPE_RE.match(name):
        out.append(f"{addr_text}.name: bad shape {name!r} "
                   "(must be [A-Za-z][A-Za-z0-9_]*)")
    if len(name) > _NAME_MAX:
        out.append(f"{addr_text}.name: too long ({len(name)} > {_NAME_MAX}): "
                   f"{name!r}")
    for bad in _NAME_BAD_PREFIXES:
        if name.startswith(bad):
            out.append(f"{addr_text}.name: bad prefix {bad!r} in {name!r} "
                       f"(RE bookkeeping doesn't belong in labels)")
    # Each `_`-separated token must be all-lowercase OR in the
    # allow-list of conventional abbreviations. Exception: names whose
    # first token is a C64 hardware namespace (SID/VIC/CIA1/...) may have
    # any uppercase tail token — these are by-the-book hardware register
    # mnemonics (e.g. VIC_SP0_X, CIA2_PRB, CPU_DDR).
    tokens = name.split("_")
    hw_namespaced = tokens and tokens[0] in _HW_NAMESPACES
    bad_tokens: list[str] = []
    for t in tokens:
        if t == t.lower():
            continue
        if t in _UPPER_TOKENS_OK:
            continue
        if hw_namespaced and t.isupper() and t.isalnum():
            continue
        bad_tokens.append(t)
    if bad_tokens:
        out.append(f"{addr_text}.name: non-conventional uppercase "
                   f"token(s) {bad_tokens} in {name!r} — use lowercase "
                   "or extend _UPPER_TOKENS_OK if this is a legitimate "
                   "C64/tracker convention")
    return out


def _role_violations(addr_text: str, role: str) -> list[str]:
    out: list[str] = []
    if not role:
        out.append(f"{addr_text}.role: empty (every entry needs a role)")
        return out
    if "\n" in role:
        out.append(f"{addr_text}.role: contains newline — move multi-line "
                   "content to notes")
    if not role.rstrip().endswith("."):
        out.append(f"{addr_text}.role: doesn't end with `.`")
    if len(role) > _ROLE_HARD_LIMIT:
        out.append(f"{addr_text}.role: too long ({len(role)} > "
                   f"{_ROLE_HARD_LIMIT}) — split content into notes")
    elif len(role) > _ROLE_SOFT_LIMIT:
        # Soft limit: only warn if also multi-sentence.
        n_sentences = len(re.split(r"\.\s+", role))
        if n_sentences > 1:
            out.append(f"{addr_text}.role: {len(role)} chars, "
                       f"{n_sentences} sentences — first sentence is the "
                       "role; move the rest to notes")
    return out


def check_catalog(raw: dict) -> list[str]:
    """Validate [function]/[region] entries."""
    violations: list[str] = []
    for section_name in ("function", "region"):
        section = raw.get(section_name, {})
        for addr_text, body in section.items():
            addr_disp = f"[{section_name}.\"{addr_text}\"]"
            if not isinstance(body, dict):
                violations.append(f"{addr_disp}: not a table")
                continue
            name = body.get("name")
            role = body.get("role")
            if name is None:
                violations.append(f"{addr_disp}: missing `name` field")
            elif not isinstance(name, str):
                violations.append(f"{addr_disp}.name: not a string")
            else:
                violations.extend(_name_violations(addr_disp, name))
            if role is None:
                violations.append(f"{addr_disp}: missing `role` field")
            elif not isinstance(role, str):
                violations.append(f"{addr_disp}.role: not a string")
            else:
                violations.extend(_role_violations(addr_disp, role))
            if "summary" in body:
                violations.append(f"{addr_disp}: stale `summary` field "
                                  "(should have been migrated to name+role)")
            if "constraints" in body:
                violations.extend(_constraints_violations(addr_disp,
                                                          body["constraints"]))
            if "values" in body or "values_kind" in body:
                violations.extend(_values_violations(
                    addr_disp,
                    body.get("values"),
                    body.get("values_kind")))
            if "value_names" in body:
                violations.extend(_value_names_violations(
                    addr_disp,
                    body.get("value_names"),
                    body.get("values")))
            if "derived_override" in body:
                violations.extend(_derived_override_violations(
                    addr_disp, body))
            if "inline_comments" in body:
                violations.extend(_inline_comments_violations(addr_disp, body))
    return violations


def check_refuted(raw: dict) -> list[str]:
    """Validate [refuted] entries."""
    violations: list[str] = []
    for addr_text, body in raw.get("refuted", {}).items():
        addr_disp = f"[refuted.\"{addr_text}\"]"
        if not isinstance(body, dict):
            violations.append(f"{addr_disp}: not a table")
            continue
        if "former_name" not in body:
            violations.append(f"{addr_disp}: missing `former_name` field")
        if "ruling" not in body:
            violations.append(f"{addr_disp}: missing `ruling` field")
        # name/role must NOT appear in refuted entries.
        if "name" in body or "role" in body:
            violations.append(f"{addr_disp}: catalog fields `name`/`role` "
                              "must not appear in [refuted] entries")
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-show", type=int, default=40)
    args = ap.parse_args(argv)

    raw = tomllib.loads(ANNOTATIONS.read_text())
    violations = check_catalog(raw) + check_refuted(raw)

    n_func = len(raw.get("function", {}))
    n_reg = len(raw.get("region", {}))
    n_ref = len(raw.get("refuted", {}))

    if not violations:
        print(f"check_schema: OK — {n_func} function + {n_reg} region + "
              f"{n_ref} refuted entries all conform.")
        return 0

    print(f"check_schema: {len(violations)} schema violations:")
    for v in violations[:args.max_show]:
        print(f"  {v}")
    if len(violations) > args.max_show:
        print(f"  ... +{len(violations) - args.max_show} more")
    return 1


if __name__ == "__main__":
    sys.exit(main())
