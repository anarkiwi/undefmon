"""Minimal C64 1541 / .d64 reader.

Just enough to walk the directory chain and extract a named PRG.
Standard 35-track layout (no error info, no extended images).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

# Sectors per track for a standard 35-track 1541 disk.
# Index 0 unused so track numbers can be 1-based.
_SECT_PER_TRACK = (
    0,
    21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    19, 19, 19, 19, 19, 19, 19,
    18, 18, 18, 18, 18, 18,
    17, 17, 17, 17, 17,
)
SECTOR_SIZE = 256


@dataclass
class DirEntry:
    name: str       # decoded ASCII (PETSCII high bits stripped); name only, no padding
    raw_name: bytes  # original 16 bytes from the dir entry, $A0-padded
    file_type: int  # 0..4 = DEL/SEQ/PRG/USR/REL; with bit 7 set = closed
    track: int      # first sector track
    sector: int     # first sector
    blocks: int     # 254-byte block count


def _offset(track: int, sector: int) -> int:
    if not 1 <= track < len(_SECT_PER_TRACK):
        raise ValueError(f"track out of range: {track}")
    if not 0 <= sector < _SECT_PER_TRACK[track]:
        raise ValueError(f"sector out of range for track {track}: {sector}")
    off = 0
    for t in range(1, track):
        off += _SECT_PER_TRACK[t] * SECTOR_SIZE
    return off + sector * SECTOR_SIZE


def _decode_name(b: bytes) -> str:
    return "".join(chr(c) if 0x20 <= c < 0x80 else "" for c in b).rstrip()


def list_directory(d64_path: Path) -> list[DirEntry]:
    data = Path(d64_path).read_bytes()
    if len(data) < _offset(35, 16) + SECTOR_SIZE:
        raise ValueError(f"image too small: {len(data)} bytes")

    out: list[DirEntry] = []
    track, sector = 18, 1
    seen = set()
    while track != 0 and (track, sector) not in seen:
        seen.add((track, sector))
        block = data[_offset(track, sector):_offset(track, sector) + SECTOR_SIZE]
        nt, ns = block[0], block[1]
        for i in range(8):
            entry = block[i * 32 + 2:i * 32 + 32]
            ftype = entry[0]
            if ftype == 0:
                continue
            raw_name = bytes(c if 0x20 <= c < 0x80 else 0xa0 for c in entry[3:19])
            blocks = struct.unpack("<H", entry[28:30])[0]
            out.append(DirEntry(
                name=_decode_name(raw_name).rstrip("\xa0").rstrip(),
                raw_name=raw_name.rstrip(b"\xa0"),
                file_type=ftype,
                track=entry[1],
                sector=entry[2],
                blocks=blocks,
            ))
        track, sector = nt, ns
    return out


def read_file_chain(d64_path: Path, track: int, sector: int) -> bytes:
    """Walk a sector chain starting at (track, sector) and concatenate
    the data bytes. The two-byte link header in each block is stripped;
    the final block's link header carries (0, last_byte_index)."""
    data = Path(d64_path).read_bytes()
    out = bytearray()
    seen = set()
    while track != 0 and (track, sector) not in seen:
        seen.add((track, sector))
        block = data[_offset(track, sector):_offset(track, sector) + SECTOR_SIZE]
        nt, ns = block[0], block[1]
        if nt == 0:
            # Final block: ns is the index of the last valid byte (1-based,
            # counted from the start of the block). Bytes 2..ns are payload.
            out.extend(block[2:1 + ns])
        else:
            out.extend(block[2:])
        track, sector = nt, ns
    return bytes(out)


def find_prg(d64_path: Path, name: str) -> DirEntry:
    """Find a PRG by case-insensitive name match. Comparison strips the
    leading '.' that defMON tunes use as a type marker."""
    target = name.lstrip(".").upper()
    for e in list_directory(d64_path):
        if (e.file_type & 0x0f) != 2:  # PRG
            continue
        candidate = e.name.lstrip(".").upper()
        if candidate == target:
            return e
    raise FileNotFoundError(f"PRG {name!r} not found in {d64_path}")


def extract_prg(d64_path: Path, name: str) -> bytes:
    """Return the raw PRG bytes (load address u16 LE prepended)."""
    e = find_prg(d64_path, name)
    return read_file_chain(d64_path, e.track, e.sector)
