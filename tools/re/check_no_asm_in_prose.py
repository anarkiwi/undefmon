"""Verify gate: no 6502 mnemonics in annotation `role` fields.

`role` fields should be prose describing what a function or state
variable does — not raw disassembly. Reach for the `notes` field
when a fragment of disassembly is genuinely the clearest exposition.

Flags any 3-uppercase-letter mnemonic from the standard 6502 set
(plus the LAX/SAX undocumented opcodes used by defMON's player)
inside a [function|region].role value.

Exits 1 with a per-entry listing if any are found; exits 0 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.re.emit_defmon_source import load_annotations

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"

# Standard 6502 NMOS mnemonics + LAX/SAX (undocumented; defMON uses
# them in the post-LOAD decoder + player). 56 mnemonics total.
MNEMONICS = frozenset({
    "LDA", "LDX", "LDY", "STA", "STX", "STY",
    "TAX", "TAY", "TXA", "TYA", "TSX", "TXS",
    "JSR", "JMP", "RTS", "RTI", "BRK",
    "PHP", "PHA", "PLA", "PLP",
    "BEQ", "BNE", "BCS", "BCC", "BPL", "BMI", "BVS", "BVC",
    "CMP", "CPX", "CPY", "BIT",
    "ADC", "SBC", "AND", "ORA", "EOR",
    "ASL", "LSR", "ROL", "ROR",
    "INC", "DEC", "INX", "INY", "DEX", "DEY",
    "SEC", "CLC", "SEI", "CLI", "SED", "CLD", "CLV",
    "NOP", "SAX", "LAX",
})

# Match standalone 3-uppercase-letter tokens. `\b` boundaries keep
# us off `CTRL+SHIFT` modifier tokens. Case-sensitive so we don't
# false-positive on prose words like "and" or "play".
_MNEM_RE = re.compile(r"\b([A-Z]{3})\b")


def find_mnemonic_hits(annotations: dict) -> list[tuple[str, str, list[str]]]:
    """Return [(kind_addr, summary_excerpt, hit_mnemonics), ...].

    `kind_addr` is "[kind.$XXXX]"; `summary_excerpt` is the first 200
    chars of the offending summary; `hit_mnemonics` is the sorted
    unique list of mnemonics found.
    """
    hits: list[tuple[str, str, list[str]]] = []
    for addr, body in sorted(annotations.items()):
        role = body.get("role", "")
        if not isinstance(role, str):
            continue
        found = {m.group(1) for m in _MNEM_RE.finditer(role)
                 if m.group(1) in MNEMONICS}
        if not found:
            continue
        addr_text = f"${addr:04X}"
        excerpt = role[:200].replace("\n", " ")
        hits.append((addr_text, excerpt, sorted(found)))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-show", type=int, default=20,
                    help="List up to this many offending entries "
                         "(default 20). Always shows the total count.")
    args = ap.parse_args(argv)

    annotations = load_annotations(ANNOTATIONS)
    hits = find_mnemonic_hits(annotations)

    if not hits:
        print(f"check_no_asm_in_prose: OK — none of "
              f"{len(annotations)} annotation roles contain "
              f"6502 mnemonics.")
        return 0

    print(f"check_no_asm_in_prose: {len(hits)} roles contain "
          f"6502 mnemonics (should be prose, not disasm):")
    for addr, excerpt, mnems in hits[:args.max_show]:
        print(f"  {addr}: {mnems}")
        print(f"    role: {excerpt}{'...' if len(excerpt) >= 200 else ''}")
    if len(hits) > args.max_show:
        print(f"  ... +{len(hits) - args.max_show} more")
    print()
    print("Rewrite the offending roles as prose; move disasm "
          "fragments to a [function|region].notes field if needed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
