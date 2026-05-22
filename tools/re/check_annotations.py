"""Linter: find addresses mentioned in AGENTS.md / SPEC.md without a
matching entry in tools/re/annotations.toml.

The point of this check is to keep the RE knowledge centralised. If a
new fact lands in AGENTS prose ("$8080 is the decoder"), the next
session should be able to find that fact by reading defmon.s around
$8080 — which only happens if annotations.toml has the entry.

Rules:
  - Scan AGENTS.md, tools/songfmt/SPEC.md, and anything else listed
    in SCAN_FILES for hex literals of the form $XXXX (4 hex digits).
  - For each unique address, check whether annotations.toml has a
    [function."$XXXX"] or [region."$XXXX"] entry.
  - Report:
      ORPHAN  — address mentioned at least N times in narrative,
                no annotation entry. Probably a fact worth centralising.
      THIN    — address has an annotation but with no role.
      OK      — address mentioned + annotation present (silent unless
                --verbose).
  - Mentions inside fenced code blocks count, since address references
    in code blocks are exactly the kind of fact we want centralised.

This is a soft check (advisory, not blocking). It exits 0 unless
``--strict`` is passed.

Usage:
    python3 -m tools.re.check_annotations
    python3 -m tools.re.check_annotations --strict   # exit 1 on orphans
    python3 -m tools.re.check_annotations --min-mentions 3
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS_PATH = REPO_ROOT / "tools" / "re" / "annotations.toml"

# Files that count as "narrative documentation" of the RE project.
# Addresses mentioned in these get checked. AGENTS.md and SPEC.md are
# the obvious ones; if you add another markdown reference doc, list it.
SCAN_FILES = (
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "tools" / "songfmt" / "SPEC.md",
)

# Address-mention regex. $XXXX with exactly 4 hex digits.
ADDR_RE = re.compile(r"\$([0-9A-Fa-f]{4})\b")

# Range expressions like $A000-$BFFF — count as a mention of BOTH endpoints.
RANGE_RE = re.compile(r"\$([0-9A-Fa-f]{4})\s*[-–]\s*\$([0-9A-Fa-f]{4})")

# Addresses we deliberately skip — these are KERNAL ROM entries, VIC/SID/
# CIA SFRs, or other system-defined points that don't need defMON-specific
# annotations.
SYSTEM_ADDRESSES = frozenset({
    # KERNAL entry points (jump table)
    0xFFA5, 0xFFA8, 0xFFAB, 0xFFAE, 0xFFB1, 0xFFB4, 0xFFB7, 0xFFBA,
    0xFFBD, 0xFFC0, 0xFFC3, 0xFFC6, 0xFFC9, 0xFFCC, 0xFFCF, 0xFFD2,
    0xFFD5, 0xFFD8, 0xFFDB, 0xFFDE, 0xFFE1, 0xFFE4, 0xFFE7, 0xFFEA,
    0xFFED, 0xFFF0, 0xFFF3,
    # Reset / IRQ / NMI vectors
    0xFFF6, 0xFFF7, 0xFFF8, 0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0xFFFD,
    0xFFFE, 0xFFFF,
    # VIC-II SFRs
    0xD000, 0xD001, 0xD002, 0xD003, 0xD004, 0xD005, 0xD006, 0xD007,
    0xD011, 0xD012, 0xD015, 0xD016, 0xD018, 0xD019, 0xD01A, 0xD020, 0xD021,
    # SID base addresses & CIA1/CIA2 ports we don't need to annotate
    0xD400, 0xD401, 0xD402, 0xD403, 0xD404, 0xD405, 0xD406,
    0xD407, 0xD408, 0xD409, 0xD40A, 0xD40B, 0xD40C, 0xD40D,
    0xD40E, 0xD40F, 0xD410, 0xD411, 0xD412, 0xD413, 0xD414,
    0xD415, 0xD416, 0xD417, 0xD418, 0xD41B,
    0xD420, 0xD500, 0xDC00, 0xDC01, 0xDC0D, 0xDD00, 0xDD0D,
    # VIC-II "test register" / C128 clock-control register (no-op on stock
    # C64). Cited only by external-tool prose (exomizer recrunch analysis).
    0xD030,
})


def load_annotated_addresses() -> set[int]:
    """Addresses with a [function]/[region]/[refuted] entry. Refuted
    counts as 'annotated' for orphan-detection purposes — the address
    is documented (with a dead-end ruling) even though it's not
    label-eligible."""
    if not ANNOTATIONS_PATH.is_file():
        return set()
    raw = tomllib.loads(ANNOTATIONS_PATH.read_text())
    out: set[int] = set()
    for section in ("function", "region", "refuted"):
        for addr_text in raw.get(section, {}):
            txt = addr_text[1:] if addr_text.startswith("$") else addr_text
            try:
                out.add(int(txt, 16))
            except ValueError:
                continue
    return out


def load_thin_addresses() -> set[int]:
    """Addresses with an annotation entry but no `role` field."""
    if not ANNOTATIONS_PATH.is_file():
        return set()
    raw = tomllib.loads(ANNOTATIONS_PATH.read_text())
    out: set[int] = set()
    for section in ("function", "region"):
        for addr_text, body in raw.get(section, {}).items():
            if isinstance(body, dict) and not body.get("role"):
                txt = addr_text[1:] if addr_text.startswith("$") else addr_text
                try:
                    out.add(int(txt, 16))
                except ValueError:
                    continue
    return out


def scan_mentions(paths: tuple[Path, ...]) -> dict[int, dict[str, int]]:
    """Return {addr: {path: mention_count}}."""
    out: dict[int, dict[str, int]] = {}
    for p in paths:
        if not p.is_file():
            continue
        text = p.read_text(errors="replace")
        rel = str(p.relative_to(REPO_ROOT))
        for m in ADDR_RE.finditer(text):
            addr = int(m.group(1), 16)
            out.setdefault(addr, {})[rel] = out.setdefault(addr, {}).get(rel, 0) + 1
        # Range endpoints: bump both ends so a single "$7400-$77FF" mention
        # counts toward both addresses being known.
        for m in RANGE_RE.finditer(text):
            for n in (1, 2):
                addr = int(m.group(n), 16)
                out.setdefault(addr, {})[rel] = out.setdefault(addr, {}).get(rel, 0) + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any ORPHAN addresses are reported")
    ap.add_argument("--min-mentions", type=int, default=2,
                    help="threshold for ORPHAN reporting (default: 2)")
    ap.add_argument("--verbose", action="store_true",
                    help="also list OK addresses (those with annotation + mention)")
    args = ap.parse_args()

    annotated = load_annotated_addresses()
    thin = load_thin_addresses()
    mentions = scan_mentions(SCAN_FILES)

    orphans: list[tuple[int, dict[str, int], int]] = []
    thins_seen: list[tuple[int, dict[str, int], int]] = []
    oks: list[tuple[int, dict[str, int], int]] = []
    for addr, per_file in sorted(mentions.items()):
        if addr in SYSTEM_ADDRESSES:
            continue
        total = sum(per_file.values())
        if addr in annotated:
            if addr in thin:
                thins_seen.append((addr, per_file, total))
            else:
                oks.append((addr, per_file, total))
        else:
            if total >= args.min_mentions:
                orphans.append((addr, per_file, total))

    # Sort each report by mention count (descending) so the highest-leverage
    # gaps come first.
    orphans.sort(key=lambda t: -t[2])
    thins_seen.sort(key=lambda t: -t[2])
    oks.sort(key=lambda t: -t[2])

    print(f"annotated addresses:    {len(annotated)}")
    print(f"system addresses (skipped): {len(SYSTEM_ADDRESSES)}")
    print(f"unique narrative addresses: {len(mentions)}")
    print()

    if orphans:
        print(f"ORPHANS ({len(orphans)} addresses with ≥{args.min_mentions} "
              "mentions but no annotation):")
        for addr, per_file, total in orphans:
            sources = " ".join(f"{k}:{v}" for k, v in per_file.items())
            print(f"  ${addr:04X}  total={total:3d}  {sources}")
    else:
        print(f"ORPHANS: none (above {args.min_mentions}-mention threshold).")

    if thins_seen:
        print()
        print(f"THIN ({len(thins_seen)} annotations missing 'role'):")
        for addr, per_file, total in thins_seen:
            print(f"  ${addr:04X}  total={total:3d}")

    if args.verbose and oks:
        print()
        print(f"OK ({len(oks)}):")
        for addr, per_file, total in oks[:50]:
            print(f"  ${addr:04X}  total={total:3d}")

    if args.strict and orphans:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
