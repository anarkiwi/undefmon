"""Drive defMON in headlessvice and aggregate executed PCs to entrypoints.json.

Reproduces the per-tune sweep that originally produced
``trace/entrypoints.json``. For each tune in
``defmon_driver.tune_manifest.TUNES`` (9 tunes), boots a fresh
``anarkiwi/headlessvice`` container, loads the tune by cursor index,
then measures coverage over ``Defmon.all_documented_actions()`` plus
the documented disk actions. Per-action ``executed_pcs`` sets are
merged into the schema_version=1 layout the emitter consumes.

Each tune runs 5-30 minutes depending on the action set; the full
9-tune sweep takes 1-3 hours. Far too slow for PR CI — invoke
manually when ``trace/entrypoints.json`` needs to be rebuilt against a
new defMON release, a new action list, or a behaviour change in
defmon-driver.

Required pip packages (NOT installed by default; install on demand):
    pip install -r requirements-probes.txt   # pins defmon-driver==0.2.0
                                             # and vice-driver==0.2.0

Required runtime: a docker daemon with access to the
``anarkiwi/headlessvice`` container image. The headlessvice wiring
(image, ``--entrypoint x64sc``, VICE state-dir bind mounts) lives in
``tools._headlessvice``, which monkey-patches the ``ViceContainer``
name in ``defmon_driver._smoke_support``.

Required input: ``defmon-withtunes.d64`` (the tunes-included variant).
``tools/fetch_static.py`` already downloads the upstream .zip; the
withtunes .d64 sits next to defmon-20201008.d64 inside that archive
and is extracted on demand by this script if missing.

Run:
    python3 -m tools.sweep
        # extracts artefacts/defmon-withtunes.d64 if missing,
        # sweeps all 9 tunes, writes trace/entrypoints.json

    python3 -m tools.sweep --tune 4 --tune 5
        # restrict to two tunes (by TuneEntry.dir_index)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

log = logging.getLogger("sweep")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_D64 = REPO_ROOT / "artefacts" / "defmon-withtunes.d64"
DEFAULT_OUT = REPO_ROOT / "trace" / "entrypoints.json"
DEFAULT_PORT = 6502
SETTLE = 0.4

UPSTREAM_ZIP_URL = (
    "https://defmon.vandervecken.com/lib/exe/fetch.php"
    "?media=download:defmon-20201008.zip"
)
WITHTUNES_NAME = "defmon-withtunes.d64"


def ensure_withtunes(d64_path: Path) -> None:
    """Download + extract defmon-withtunes.d64 from upstream if missing."""
    if d64_path.is_file():
        return
    d64_path.parent.mkdir(parents=True, exist_ok=True)
    zip_path = d64_path.parent / "defmon-20201008.zip"
    if not zip_path.is_file():
        log.info("downloading %s", UPSTREAM_ZIP_URL)
        with urllib.request.urlopen(UPSTREAM_ZIP_URL) as resp:
            zip_path.write_bytes(resp.read())
    with zipfile.ZipFile(zip_path) as zf:
        d64_path.write_bytes(zf.read(WITHTUNES_NAME))
    log.info("extracted %s (%d bytes)", d64_path, d64_path.stat().st_size)


def _per_action(cov, name, fn):
    """Run one action under the Coverage harness; log + skip on failure."""
    try:
        return cov.measure(fn, name, settle=SETTLE)
    except (
        Exception
    ) as e:  # noqa: BLE001 — best-effort coverage; one bad action shouldn't kill the sweep
        log.warning("action %s raised: %s", name, e)
        return None


def sweep_tune(d64_path: Path, tune, port: int):
    """Boot one tune, measure coverage over every documented action."""
    # Side-effect import: rebinds smoke_session's ViceContainer to the
    # headlessvice factory. Must precede the smoke_session import below.
    from tools import _headlessvice  # noqa: F401, PLC0415
    from defmon_driver._smoke_support import smoke_session  # noqa: PLC0415
    from defmon_driver.tune_navigation import (  # noqa: PLC0415
        cursor_load_tune,
        state_reset,
    )
    from vice_driver.coverage import Coverage  # noqa: PLC0415

    captured = []
    with smoke_session(
        d64_path, port=port, prefix=f"sweep-{tune.dir_index}-"
    ) as session:
        d, bm = session.d, session.bm
        cursor_load_tune(d, tune)
        cov = Coverage(bm)
        cov.install()
        try:
            for name, fn in d.all_documented_actions():
                state_reset(d)
                ac = _per_action(cov, name, fn)
                if ac is not None:
                    captured.append(ac)
            try:
                d.open_disk_menu()
                for name, fn in d.all_documented_disk_actions():
                    ac = _per_action(cov, name, fn)
                    if ac is not None:
                        captured.append(ac)
            except Exception as e:  # noqa: BLE001
                log.warning("disk-menu actions skipped: %s", e)
        finally:
            cov.remove()
    return captured


def aggregate_sweep(all_action_covs, tune_count: int) -> dict:
    """Flatten per-action coverage into the schema_version=1 layout."""
    pc_occurrences: Counter = Counter()
    pages: set = set()
    for ac in all_action_covs:
        for pc in ac.executed_pcs:
            pc_occurrences[pc] += 1
            pages.add(pc >> 8)
        for page in ac.page_hits:
            pages.add(page)
    pcs = [
        {"pc": f"0x{pc:04x}", "page": f"0x{pc >> 8:02x}", "occurrences": n}
        for pc, n in sorted(pc_occurrences.items())
    ]
    return {
        "schema_version": 1,
        "tune_count": tune_count,
        "action_count": len(all_action_covs),
        "distinct_pcs": len(pc_occurrences),
        "pages_touched": len(pages),
        "pcs": pcs,
        "pages": [f"0x{p:02x}" for p in sorted(pages)],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--d64",
        default=str(DEFAULT_D64),
        help="defMON .d64 with the example tunes",
    )
    ap.add_argument(
        "--out", default=str(DEFAULT_OUT), help="aggregated entrypoints JSON output"
    )
    ap.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="binary monitor port headlessvice listens on",
    )
    ap.add_argument(
        "--tune",
        action="append",
        type=int,
        default=None,
        help="restrict sweep to one or more TuneEntry.dir_index values",
    )
    ap.add_argument(
        "--skip-fetch",
        action="store_true",
        help="do NOT download/extract the .d64; require --d64 to exist",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
    )

    try:
        from defmon_driver.tune_manifest import TUNES  # noqa: PLC0415
    except ImportError:
        log.error(
            "defmon-driver not installed; run `pip install -r requirements-probes.txt`"
        )
        return 1

    d64_path = Path(args.d64).resolve()
    if not args.skip_fetch:
        ensure_withtunes(d64_path)
    if not d64_path.is_file():
        log.error("missing .d64: %s", d64_path)
        return 1

    selected = (
        TUNES
        if args.tune is None
        else tuple(t for t in TUNES if t.dir_index in args.tune)
    )
    if not selected:
        log.error("no tunes matched --tune values: %s", args.tune)
        return 1

    all_covs = []
    for i, tune in enumerate(selected, 1):
        log.info(
            "tune %d/%d: %s (dir_index=%d)",
            i,
            len(selected),
            tune.name,
            tune.dir_index,
        )
        t0 = time.monotonic()
        try:
            covs = sweep_tune(d64_path, tune, args.port)
        except Exception as e:  # noqa: BLE001
            log.exception("tune %s failed: %s", tune.name, e)
            continue
        elapsed = time.monotonic() - t0
        log.info("tune %s: %d actions captured in %.1fs", tune.name, len(covs), elapsed)
        all_covs.extend(covs)

    out_obj = aggregate_sweep(all_covs, tune_count=len(selected))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_obj, indent=2))
    log.info(
        "wrote %s (action_count=%d, distinct_pcs=%d, pages=%d)",
        out_path,
        out_obj["action_count"],
        out_obj["distinct_pcs"],
        out_obj["pages_touched"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
