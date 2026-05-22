"""Substitute opaque `$XX` byte refs with enum constants in annotation prose.

For every two-digit `$XX` reference inside annotation prose where the
surrounding context (same line / same multiline-notes chunk) unambiguously
identifies which value_names enum to use, replace the hex byte with the
corresponding symbolic constant. The canonical enum mapping lives in the
matching `[region."$XXXX".value_names]` block — this tool just propagates
the symbol up into every prose mention.

Context-detection rule: scan each prose line for any enum-bound variable
name (the `name` field of a region that carries a `[...].value_names]`
block). When exactly one such variable is mentioned in a line, substitute
`$XX` byte refs in that line against its enum. When zero or more than one
are mentioned, leave the line alone — the substitution would be ambiguous.

Sibling of `substitute_hex_refs.py`, which handles 4-digit address refs.

Two modes:
  --check (default): exit 0 if no pending substitutions; exit 1 with a
    listing otherwise. Use in CI / `make verify`.
  --apply: rewrite tools/re/annotations.toml in place.

`evidence` and `internal_notes` fields are skipped (literal CLI commands
and historical narrative where the raw byte is meaningful).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"

SUB_FIELDS = {"role", "notes", "callers", "inputs",
              "outputs", "registers_clobbered", "variables_changed"}
SKIP_FIELDS = {"evidence", "internal_notes", "values", "kbd_probe_excluded"}

# A bare 2-digit `$XX` byte ref, NOT part of a larger 4+-digit hex token.
# Negative lookbehind/lookahead keep `$0801` and `$XXXX5` from matching.
_BYTE_REF_RE = re.compile(r"(?<![0-9A-Fa-f$])\$([0-9A-Fa-f]{2})(?![0-9A-Fa-f])")
_SECTION_RE = re.compile(r'^\[(function|region)\."(\$[0-9A-Fa-f]{4})"\]\s*$')
_FIELD_RE = re.compile(r"^([a-z_]+)\s*=\s*(.*)$")


def build_enum_map() -> dict[str, dict[int, str]]:
    """Load every region's `value_names` enum and key by variable name.

    Returned shape: ``{var_name: {byte_value: enum_constant_name}}``.

    Variables without a value_names block are skipped — there's no enum
    to substitute against. Regions whose `name` field collides with
    another region's are kept (the enum mapping per name still wins
    because TOML parses them as separate keys).
    """
    raw = tomllib.loads(ANNOTATIONS.read_text())
    regions = raw.get("region", {})
    out: dict[str, dict[int, str]] = {}
    for _addr_key, body in regions.items():
        if not isinstance(body, dict):
            continue
        name = body.get("name")
        vn = body.get("value_names")
        if not isinstance(name, str) or not isinstance(vn, dict):
            continue
        mapping: dict[int, str] = {}
        for hex_key, const in vn.items():
            if not isinstance(hex_key, str) or not isinstance(const, str):
                continue
            try:
                byte = int(hex_key.lstrip("$"), 16)
            except ValueError:
                continue
            mapping[byte] = const
        if mapping:
            out[name] = mapping
    return out


def _context_var(line: str, enum_vars: list[str]) -> str | None:
    """Return the single value_names-bound variable mentioned in ``line``,
    or None when zero or multiple are mentioned. Whole-word match keeps
    `super_cmd_flags` from also matching `super_cmd_flag_mask` etc."""
    mentioned: set[str] = set()
    for var in enum_vars:
        if re.search(rf"\b{re.escape(var)}\b", line):
            mentioned.add(var)
    if len(mentioned) == 1:
        return next(iter(mentioned))
    return None


def _substitute_line(line: str,
                     enum_map: dict[str, dict[int, str]],
                     enum_vars: list[str],
                     ) -> tuple[str, int]:
    """Apply byte→constant substitution to a single line.

    Returns (new_line, n_substitutions). Skipped when the line has no
    unambiguous value_names variable context."""
    var = _context_var(line, enum_vars)
    if var is None:
        return line, 0
    mapping = enum_map[var]
    n = 0

    def replace(m: re.Match) -> str:
        nonlocal n
        byte = int(m.group(1), 16)
        if byte in mapping:
            n += 1
            return mapping[byte]
        return m.group(0)

    return _BYTE_REF_RE.sub(replace, line), n


def _walk(text: str):
    """Yield (line_no, line, field) per line, tracking the active field
    across triple-quoted multi-line values."""
    field: str | None = None
    in_multiline = False
    for i, line in enumerate(text.split("\n"), start=1):
        if _SECTION_RE.match(line):
            field = None
            in_multiline = False
            yield i, line, None
            continue
        if in_multiline:
            yield i, line, field
            if '"""' in line:
                in_multiline = False
                field = None
            continue
        m_field = _FIELD_RE.match(line)
        if m_field:
            field = m_field.group(1)
            rest = m_field.group(2)
            in_multiline = rest.count('"""') == 1
            yield i, line, field
            if not in_multiline:
                field = None
            continue
        yield i, line, None


def scan(text: str, enum_map: dict[str, dict[int, str]],
         ) -> list[tuple[int, str, str, str, str]]:
    """Return list of pending substitutions:
        [(line_no, section, field, before_token, after_token), ...]
    """
    enum_vars = sorted(enum_map.keys(), key=len, reverse=True)
    out: list[tuple[int, str, str, str, str]] = []
    section = "(none)"
    for i, line, field in _walk(text):
        m_section = _SECTION_RE.match(line)
        if m_section:
            section = f"[{m_section.group(1)}.{m_section.group(2)}]"
            continue
        if field not in SUB_FIELDS:
            continue
        var = _context_var(line, enum_vars)
        if var is None:
            continue
        mapping = enum_map[var]
        for m in _BYTE_REF_RE.finditer(line):
            byte = int(m.group(1), 16)
            if byte in mapping:
                out.append((i, section, field, m.group(0), mapping[byte]))
    return out


def apply(text: str, enum_map: dict[str, dict[int, str]],
          ) -> tuple[str, int, int]:
    """Apply substitution in place. Returns (new_text, n_sub, n_lines)."""
    enum_vars = sorted(enum_map.keys(), key=len, reverse=True)
    out_lines: list[str] = []
    total_sub = 0
    lines_changed = 0
    for _, line, field in _walk(text):
        if field in SUB_FIELDS:
            new_line, n = _substitute_line(line, enum_map, enum_vars)
            if new_line != line:
                lines_changed += 1
            total_sub += n
            out_lines.append(new_line)
        else:
            out_lines.append(line)
    return "\n".join(out_lines), total_sub, lines_changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true", default=True,
                     help="(default) Exit 1 if any pending substitutions; "
                          "do not write.")
    grp.add_argument("--apply", action="store_true",
                     help="Rewrite tools/re/annotations.toml in place.")
    ap.add_argument("--max-show", type=int, default=30,
                    help="In --check mode, list up to this many pending "
                         "substitutions (default 30).")
    args = ap.parse_args(argv)

    enum_map = build_enum_map()
    text = ANNOTATIONS.read_text()

    if args.apply:
        new_text, n_sub, n_lines = apply(text, enum_map)
        if n_sub == 0 and new_text == text:
            print(f"substitute_byte_refs: no changes "
                  f"({len(enum_map)} enum-bound vars considered).")
            return 0
        ANNOTATIONS.write_text(new_text)
        print(f"substitute_byte_refs: applied {n_sub} substitutions "
              f"across {n_lines} lines.")
        return 0

    pending = scan(text, enum_map)
    if not pending:
        print(f"substitute_byte_refs: OK — no opaque $XX byte refs left "
              f"with unambiguous enum context "
              f"({len(enum_map)} enum-bound vars considered).")
        return 0

    print(f"substitute_byte_refs: {len(pending)} pending substitutions "
          f"in tools/re/annotations.toml:")
    for line_no, section, field, before, after in pending[:args.max_show]:
        print(f"  line {line_no:5d} {section} .{field}: {before} -> {after}")
    if len(pending) > args.max_show:
        print(f"  ... +{len(pending) - args.max_show} more")
    print()
    print("Run `python3 -m tools.re.substitute_byte_refs --apply` "
          "(or `make substitute-byte-refs`) to fix.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
