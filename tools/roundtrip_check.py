"""Byte-compare 64tass output against the static image.

Pass `--reassembled` for the bytes 64tass emitted from defmon.s, and
`--static` for the unpacked reference. The two are compared over the
defmon load range ($0800 .. $E787). Exit 0 on a 0-byte diff, exit 1 on
any mismatch with a sample of divergences printed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

LOAD_ADDR = 0x0800
END_ADDR_EXCL = 0xE787


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--static",
        default="artefacts/defmon-static.bin",
        help="64K flat reference image (the unpacked .d64 contents)",
    )
    ap.add_argument(
        "--reassembled",
        required=True,
        help="64tass --nostart output to compare against --static",
    )
    ap.add_argument("--start", type=lambda s: int(s, 0), default=LOAD_ADDR)
    ap.add_argument("--end", type=lambda s: int(s, 0), default=END_ADDR_EXCL)
    args = ap.parse_args()

    expected = Path(args.static).read_bytes()[args.start : args.end]
    rebuilt = Path(args.reassembled).read_bytes()

    if len(rebuilt) != len(expected):
        print(
            f"FAIL: length mismatch — rebuilt={len(rebuilt)}, "
            f"expected={len(expected)}",
            file=sys.stderr,
        )
        return 1

    diffs = [
        (i, expected[i], rebuilt[i])
        for i in range(len(expected))
        if expected[i] != rebuilt[i]
    ]
    if not diffs:
        print(
            f"PASS: 0-byte diff over {len(expected)} bytes "
            f"(${args.start:04X}-${args.end - 1:04X})"
        )
        return 0

    print(
        f"FAIL: {len(diffs)} differing bytes over {len(expected)} bytes",
        file=sys.stderr,
    )
    for offset, want, got in diffs[:20]:
        addr = args.start + offset
        print(f"  ${addr:04X}: expected ${want:02X}, got ${got:02X}", file=sys.stderr)
    if len(diffs) > 20:
        print(f"  ... and {len(diffs) - 20} more", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
