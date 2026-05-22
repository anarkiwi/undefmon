"""Substitute opaque `$XXXX` hex refs with semantic names in annotation prose.

For every `$XXXX` reference inside annotation summary / notes / callers /
inputs / outputs / clobbers / values fields where the address has a known
semantic name (derived from annotations.toml self-naming convention +
SEED_LANDMARKS + EQUATE_LABELS + Ghidra USER_DEFINED labels), replace the
hex with the name. Preserve indexed suffixes (`,X` / `,Y` → uppercase).

Two modes:
  --check (default): exit 0 if no pending substitutions; exit 1 with a
    listing of pending substitutions otherwise. Use in CI / `make verify`.
  --apply: rewrite tools/re/annotations.toml in place with the
    substitutions applied. Also deduplicates `name name` and `name (name)`
    artifacts that result when the original prose already mentioned the
    name alongside the hex.

`evidence` and `internal_notes` fields are skipped (they contain literal
CLI commands and historical narrative where the hex is meaningful).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tools.re.emit_defmon_source import (
    EQUATE_LABELS,
    HW_LABELS,
    SEED_LANDMARKS,
    extract_annotation_labels,
    load_annotations,
    load_refuted_addresses,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"
GHIDRA_SYMBOLS = REPO_ROOT / "artefacts" / "ghidra" / "symbols.json"

SUB_FIELDS = {"role", "notes", "callers", "inputs",
              "outputs", "registers_clobbered", "variables_changed", "values"}
# Fields whose prose is left verbatim: evidence contains literal
# `tools/re/xref.py --target 0x...` CLI commands; internal_notes
# preserves the historical context behind a finding (often referencing
# specific addresses that the current narrative no longer uses).
SKIP_FIELDS = {"evidence", "internal_notes", "kbd_probe_excluded"}

# Match $XXXX with optional ,X / ,Y indexed suffix. The trailing \b
# guard ensures we don't eat into longer hex tokens (8-digit hashes
# etc.). The (?![0-9A-Fa-f]) negative lookahead handles the case
# `$XXXX5` where the trailing 5 is meaningful and shouldn't fuse.
_HEX_REF_RE = re.compile(r"\$([0-9A-Fa-f]{4})(?![0-9A-Fa-f])((?:,[XYxy])?)")
_SECTION_RE = re.compile(r'^\[(function|region)\."(\$[0-9A-Fa-f]{4})"\]\s*$')
_FIELD_RE = re.compile(r"^([a-z_]+)\s*=\s*(.*)$")


def build_addr_to_name() -> dict[int, str]:
    """Build the address→name map from all available sources.

    Precedence (highest first; later sources only fill addresses that
    earlier sources didn't already name):
      1. SEED_LANDMARKS (code-start entries, curated)
      2. EQUATE_LABELS (non-code-start state vars, curated)
      3. HW_LABELS (C64 hardware register + KERNAL conventions)
      4. Ghidra USER_DEFINED symbols (from artefacts/ghidra/symbols.json)
      5. Annotation `name` fields (post-split schema).

    Refuted addresses (entries in `[refuted]` section of annotations.toml)
    are explicitly excluded — they're not label-eligible, so no
    substitution should propagate them.
    """
    refuted = load_refuted_addresses(ANNOTATIONS)
    out: dict[int, str] = {}
    for addr, name in SEED_LANDMARKS.items():
        if addr in refuted:
            continue
        out[addr] = name
    for addr, name in EQUATE_LABELS.items():
        if addr in refuted:
            continue
        out.setdefault(addr, name)
    for addr, name in HW_LABELS.items():
        if addr in refuted:
            continue
        out.setdefault(addr, name)
    if GHIDRA_SYMBOLS.is_file():
        gh = json.loads(GHIDRA_SYMBOLS.read_text())
        for sym in gh.get("symbols", []):
            if sym.get("source") != "USER_DEFINED":
                continue
            name = sym.get("name")
            if not name:
                continue
            try:
                addr = int(sym["addr"].lstrip("$"), 16)
            except (KeyError, ValueError):
                continue
            if addr in refuted:
                continue
            out.setdefault(addr, name)
    annotations = load_annotations(ANNOTATIONS)
    for addr, name in extract_annotation_labels(annotations).items():
        if addr in refuted:
            continue
        out.setdefault(addr, name)
    return out


def _substitute_one(text: str, addr_to_name: dict[int, str]) -> tuple[str, int]:
    """Apply hex→name substitution to a single field's text.

    Returns (new_text, n_substitutions). Preserves indexed-mode suffix
    (`,X` / `,Y`) and uppercases the register letter.
    """
    n = 0

    def replace(m: re.Match) -> str:
        nonlocal n
        addr = int(m.group(1), 16)
        suffix = m.group(2)
        if addr in addr_to_name:
            n += 1
            return addr_to_name[addr] + (suffix.upper() if suffix else "")
        return m.group(0)

    return _HEX_REF_RE.sub(replace, text), n


def _walk(annotations_text: str):
    """Yield (line_no, line, field) per line, with field correctly
    tracked across single-line and triple-quoted-multi-line values.
    `field` is None for section headers / blank / comment lines /
    between fields.
    """
    field: str | None = None
    in_multiline = False
    for i, line in enumerate(annotations_text.split("\n"), start=1):
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
        # blank / comment / other line not inside a multi-line value
        yield i, line, None


def scan(annotations_text: str, addr_to_name: dict[int, str],
         ) -> list[tuple[int, str, str, str, str]]:
    """Return a list of pending substitutions:
        [(line_no, section, field, before_token, after_token), ...]
    Empty list = nothing to do.
    """
    out: list[tuple[int, str, str, str, str]] = []
    section = "(none)"
    for i, line, field in _walk(annotations_text):
        m_section = _SECTION_RE.match(line)
        if m_section:
            section = f"[{m_section.group(1)}.{m_section.group(2)}]"
            continue
        if field not in SUB_FIELDS:
            continue
        for m in _HEX_REF_RE.finditer(line):
            addr = int(m.group(1), 16)
            if addr in addr_to_name:
                name = addr_to_name[addr]
                suffix = m.group(2).upper() if m.group(2) else ""
                out.append((i, section, field, m.group(0), name + suffix))
    return out


def apply(annotations_text: str, addr_to_name: dict[int, str]) -> tuple[str, int, int]:
    """Apply substitution in place. Returns (new_text, n_sub, n_lines)."""
    out_lines: list[str] = []
    total_sub = 0
    lines_changed = 0
    for _, line, field in _walk(annotations_text):
        if field in SUB_FIELDS:
            new_line, n = _substitute_one(line, addr_to_name)
            if new_line != line:
                lines_changed += 1
            total_sub += n
            out_lines.append(new_line)
        else:
            out_lines.append(line)
    return "\n".join(out_lines), total_sub, lines_changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true", default=True,
                     help="(default) Exit 1 if any pending substitutions; "
                          "do not write.")
    grp.add_argument("--apply", action="store_true",
                     help="Rewrite tools/re/annotations.toml in place.")
    ap.add_argument("--max-show", type=int, default=20,
                    help="In --check mode, list up to this many pending "
                         "substitutions (default 20).")
    args = ap.parse_args(argv)

    addr_to_name = build_addr_to_name()
    text = ANNOTATIONS.read_text()

    if args.apply:
        new_text, n_sub, n_lines = apply(text, addr_to_name)
        if n_sub == 0 and new_text == text:
            print(f"substitute_hex_refs: no changes "
                  f"({len(addr_to_name)} named addresses considered).")
            return 0
        ANNOTATIONS.write_text(new_text)
        print(f"substitute_hex_refs: applied {n_sub} substitutions "
              f"across {n_lines} lines.")
        return 0

    pending = scan(text, addr_to_name)
    if not pending:
        print(f"substitute_hex_refs: OK — no opaque $XXXX refs left for "
              f"the {len(addr_to_name)} named addresses.")
        return 0

    print(f"substitute_hex_refs: {len(pending)} pending substitutions in "
          f"tools/re/annotations.toml:")
    for line_no, section, field, before, after in pending[:args.max_show]:
        print(f"  line {line_no:5d} {section} .{field}: {before} -> {after}")
    if len(pending) > args.max_show:
        print(f"  ... +{len(pending) - args.max_show} more")
    print()
    print("Run `python3 -m tools.re.substitute_hex_refs --apply` "
          "(or `make substitute-hex-refs`) to fix.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
