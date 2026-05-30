"""Cross-check the auto-generated memory map in defmon.s against ground
truth (the static image + Ghidra segments): each band's size and
zero-fill share are re-derived from the image and asserted against the
rendered map, so a wrong-offset attribution bug or an out-of-date map
both fail here (test_emit only catches byte-staleness of the whole file).
"""

import json
import re
import unittest
from pathlib import Path

from tools.re.emit_defmon_source import _fmt_map_size, LOAD_ADDR, END_ADDR_EXCL

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFMON_S = REPO_ROOT / "defmon.s"
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
SEGMENTS = REPO_ROOT / "artefacts" / "ghidra" / "segments.json"

IMAGE_END = 0x10000

GLYPH_KIND = {"█": "code", "▒": "data", "░": "hw", "·": "sys"}
ROW_RE = re.compile(r"^;\s+\$([0-9A-Fa-f]{4}).*?(\d[\d.]*)\s*([KB])\s\s+(.*\S)\s*$")
ZERO_RE = re.compile(r"\(~(\d+)% zero\)")


def _parse_main_map(text: str):
    """Return the main memory-map rows as dicts. Stops at the I/O overlay
    grid that follows (only the first grid is the $0000-$FFFF map)."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if "MEMORY MAP — auto-generated" in ln)
    rows = []
    for ln in lines[start:]:
        if "I/O overlay at" in ln:
            break
        m = ROW_RE.match(ln)
        if not m:
            continue
        addr, num, unit, label = m.groups()
        kind = next((k for g, k in GLYPH_KIND.items() if g in ln), "unused")
        rows.append(
            {
                "addr": int(addr, 16),
                "size": f"{num} {unit}",
                "label": label,
                "kind": kind,
                "zero": ZERO_RE.search(label),
            }
        )
    return rows


class TestMemoryMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Segments nest/overlap (arrangers inside sidtab_data), so a data
        band's extent is its own segment's clamped [start, end_excl) — as
        _emit_memory_map renders it — not the gap to the next row."""
        cls.rows = _parse_main_map(DEFMON_S.read_text())
        cls.mem = STATIC_BIN.read_bytes() if STATIC_BIN.is_file() else None
        cls.segs = {}
        for s in json.loads(SEGMENTS.read_text())["segments"]:
            start = max(int(s["start"].lstrip("$"), 16), LOAD_ADDR)
            end = min(int(s["end_excl"].lstrip("$"), 16), END_ADDR_EXCL)
            cls.segs[start] = (end, s["name"])
        cls.data_rows = [r for r in cls.rows if r["kind"] == "data"]

    def test_map_parses_and_is_ordered(self):
        self.assertGreater(len(self.rows), 10, "memory-map block did not parse")
        self.assertGreater(len(self.data_rows), 5, "no data bands parsed")
        addrs = [r["addr"] for r in self.rows]
        self.assertEqual(addrs, sorted(addrs), "map rows must be address-sorted")
        self.assertEqual(len(addrs), len(set(addrs)), "duplicate band start address")

    def test_data_bands_attributed_to_segments(self):
        """Each data band's start + name match a Ghidra segment (marker
        stripped). Guards against a band attributed to the wrong region."""
        for r in self.data_rows:
            name = ZERO_RE.sub("", r["label"]).strip()
            self.assertIn(
                r["addr"],
                self.segs,
                f"data band ${r['addr']:04X} ({name}) has no matching segment",
            )
            self.assertEqual(
                self.segs[r["addr"]][1],
                name,
                f"band ${r['addr']:04X} labelled {name!r} but segment is "
                f"{self.segs[r['addr']][1]!r}",
            )

    def test_sizes_match_segment_ranges(self):
        """Displayed size == the segment's clamped length."""
        for r in self.data_rows:
            end, _name = self.segs[r["addr"]]
            self.assertEqual(
                r["size"],
                _fmt_map_size(end - r["addr"]).strip(),
                f"size mismatch at ${r['addr']:04X} ({r['label']})",
            )

    def test_zero_fill_markers_accurate(self):
        """Every (~NN% zero) marker matches the actual image bytes over the
        segment range, and any data band without a marker is <50% zero.
        Catches the wrong-offset slicing class of bug directly."""
        if self.mem is None:
            self.skipTest(f"{STATIC_BIN} not present — run `make fetch-static`")
        for r in self.data_rows:
            end, _name = self.segs[r["addr"]]
            span = self.mem[r["addr"] : end]
            actual = 100 * span.count(0) // len(span)
            if r["zero"]:
                self.assertEqual(
                    int(r["zero"].group(1)),
                    actual,
                    f"zero%% wrong at ${r['addr']:04X} ({r['label']}): "
                    f"shown {r['zero'].group(1)}, actual {actual}",
                )
            else:
                self.assertLess(
                    actual,
                    50,
                    f"${r['addr']:04X} ({r['label']}) is {actual}%% zero "
                    "but carries no marker",
                )


if __name__ == "__main__":
    unittest.main()
