"""Reproduce artefacts/defmon-static.bin from the upstream .d64.

Pipeline:
    1. Download defmon-20201008.zip from defmon.vandervecken.com
       (verify against a pinned sha256 so we notice if upstream changes)
    2. Extract the DEFMON-20201008 packed PRG from the .d64
    3. Run `exomizer desfx` to decrunch it
    4. Splat into a 64K flat image at the PRG's load address

The d64 + .zip + packed.prg + unpacked .prg + flat .bin all live under
artefacts/, which is gitignored. The script is idempotent: if the
output already exists with the expected sha it exits 0 without
re-doing the network and exomizer work.

Run:
    python3 -m tools.fetch_static

Requires `exomizer` on PATH. Build with:
    curl -L https://bitbucket.org/magli143/exomizer/get/3.1.2.tar.gz | tar xz
    make -C magli143-exomizer-*/src
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from .d64 import extract_prg

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTEFACTS = REPO_ROOT / "artefacts"

ZIP_URL = (
    "https://defmon.vandervecken.com/lib/exe/fetch.php"
    "?media=download:defmon-20201008.zip"
)
ZIP_PATH = ARTEFACTS / "defmon-20201008.zip"
D64_PATH = ARTEFACTS / "defmon-20201008.d64"
PACKED_PRG = ARTEFACTS / "defmon-packed.prg"
STATIC_PRG = ARTEFACTS / "defmon-static.prg"
STATIC_BIN = ARTEFACTS / "defmon-static.bin"

PRG_NAME = "DEFMON-20201008"

EXPECTED_D64_SHA = "b938847880a009c688d6d9b3f9b8fbea6ce93723772f31cf8c5b9a41b4db06e3"
EXPECTED_STATIC_BIN_SHA = (
    "bc78644c5597a91b86df54aabcc6fbc76ccedf5bf0f3ddc63ac475dc6527b329"
)


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_zip() -> None:
    if ZIP_PATH.is_file():
        return
    ARTEFACTS.mkdir(exist_ok=True)
    print(f"downloading {ZIP_URL}", file=sys.stderr)
    with urllib.request.urlopen(ZIP_URL) as resp:
        ZIP_PATH.write_bytes(resp.read())


def extract_d64() -> None:
    if D64_PATH.is_file() and _sha256_path(D64_PATH) == EXPECTED_D64_SHA:
        return
    with zipfile.ZipFile(ZIP_PATH) as zf:
        D64_PATH.write_bytes(zf.read(D64_PATH.name))
    got = _sha256_path(D64_PATH)
    if got != EXPECTED_D64_SHA:
        raise SystemExit(
            f"{D64_PATH.name} sha mismatch: got {got}, expected {EXPECTED_D64_SHA}"
        )


def extract_packed_prg() -> None:
    if PACKED_PRG.is_file():
        return
    PACKED_PRG.write_bytes(extract_prg(D64_PATH, PRG_NAME))


def run_desfx(exomizer_bin: str) -> None:
    if STATIC_PRG.is_file():
        return
    cmd = [exomizer_bin, "desfx", "-q", "-o", str(STATIC_PRG), str(PACKED_PRG)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(
            f"exomizer desfx failed (rc={result.returncode})\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


def flatten_to_bin() -> None:
    data = STATIC_PRG.read_bytes()
    load_addr = struct.unpack("<H", data[:2])[0]
    body = data[2:]
    end_addr = load_addr + len(body)
    if end_addr > 0x10000:
        raise SystemExit(
            f"PRG body overflows 64K: load=${load_addr:04X} body={len(body)}"
        )
    flat = bytearray(0x10000)
    flat[load_addr:end_addr] = body
    STATIC_BIN.write_bytes(bytes(flat))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--exomizer",
        default=shutil.which("exomizer") or "exomizer",
        help="path to exomizer binary (default: PATH lookup)",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="re-fetch and re-build even if outputs already exist",
    )
    args = ap.parse_args()

    if args.force:
        for path in (ZIP_PATH, D64_PATH, PACKED_PRG, STATIC_PRG, STATIC_BIN):
            path.unlink(missing_ok=True)

    if STATIC_BIN.is_file() and _sha256_path(STATIC_BIN) == EXPECTED_STATIC_BIN_SHA:
        print(f"{STATIC_BIN} already up to date", file=sys.stderr)
        return 0

    fetch_zip()
    extract_d64()
    extract_packed_prg()
    run_desfx(args.exomizer)
    flatten_to_bin()

    got = _sha256_path(STATIC_BIN)
    if got != EXPECTED_STATIC_BIN_SHA:
        raise SystemExit(
            f"{STATIC_BIN.name} sha mismatch: got {got}, "
            f"expected {EXPECTED_STATIC_BIN_SHA}"
        )
    print(f"wrote {STATIC_BIN} ({STATIC_BIN.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
