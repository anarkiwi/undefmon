"""Verify gate: no $XXXX hex tokens in semantic annotation prose.

Covers role / notes / callers / inputs / outputs / registers_clobbered /
variables_changed / values. The `evidence` and `internal_notes` fields
are EXCLUDED — they preserve RE journal (probe CLI commands,
prior-incident references) where hex is meaningful.

The whole point of labels is to avoid hard-coded addresses in prose.
After substitute_hex_refs (1:1 addr→name), no `$[0-9A-Fa-f]{4}` token
should remain in these fields. This linter enforces that policy.

A `$XX` (2-digit, e.g. immediate-mode operand inside backticks) is NOT
flagged — those are byte values, not addresses.

Exits 1 with a per-entry listing if any hex tokens are found; exits 0
otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.re.emit_defmon_source import load_annotations

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"

CHECK_FIELDS = {"role", "notes", "callers", "inputs",
                "outputs", "registers_clobbered", "variables_changed", "values"}

# Match $XXXX where X is hex and not part of a longer hex run.
_HEX_RE = re.compile(r"\$([0-9A-Fa-f]{4})(?![0-9A-Fa-f])")


def find_hex_hits(annotations: dict) -> list[tuple[str, str, str, list[str]]]:
    """Return [(kind_addr, field, excerpt, hit_hex_tokens), ...]."""
    hits: list[tuple[str, str, str, list[str]]] = []
    for addr, body in sorted(annotations.items()):
        for field in CHECK_FIELDS:
            val = body.get(field, "")
            if not isinstance(val, str) or not val:
                continue
            found = sorted({m.group(0) for m in _HEX_RE.finditer(val)})
            if not found:
                continue
            addr_text = f"${addr:04X}"
            excerpt = val[:200].replace("\n", " ")
            hits.append((addr_text, field, excerpt, found))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-show", type=int, default=20)
    args = ap.parse_args(argv)

    annotations = load_annotations(ANNOTATIONS)
    hits = find_hex_hits(annotations)
    n_ann = len(annotations)

    if not hits:
        print(f"check_no_hex_in_prose: OK — none of {n_ann} "
              f"annotations have $XXXX hex tokens in any of "
              f"{sorted(CHECK_FIELDS)}.")
        return 0

    print(f"check_no_hex_in_prose: {len(hits)} prose-field entries "
          f"still contain $XXXX hex tokens (should be labels, not "
          f"addresses):")
    for addr, field, excerpt, refs in hits[:args.max_show]:
        print(f"  {addr}.{field}: {refs}")
        print(f"    {field}: {excerpt}{'...' if len(excerpt) >= 200 else ''}")
    if len(hits) > args.max_show:
        print(f"  ... +{len(hits) - args.max_show} more")
    print()
    print("Run `make substitute-hex-refs` to auto-handle. For residue, "
          "add EQUATE_LABELS / SEED_LANDMARKS or hand-rewrite the prose. "
          "(evidence / internal_notes are exempt.)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
