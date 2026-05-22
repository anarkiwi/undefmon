"""Run named dynamic-evidence probes against defMON in headlessvice.

Each probe is a small, self-contained investigation: boot defMON, run
a scripted sequence of actions, capture some state, write a JSON file
under trace/. Probes are the regeneration path for the dynamic-
evidence JSONs cited by `tools/re/annotations.toml`. Add a probe by
decorating a function with `@probe("name")`.

Required pip packages (NOT installed by default):
    pip install -r requirements-probes.txt   # pins defmon-driver==0.2.0
                                             # and vice-driver==0.2.0

Required runtime: a docker daemon with access to the
``anarkiwi/headlessvice`` container image. Headlessvice-specific wiring
(entrypoint + VICE state-dir bind mounts) lives in
``tools._headlessvice`` and is installed lazily by each probe before it
calls ``smoke_session``.

Required input: ``artefacts/defmon-withtunes.d64`` (the tunes-included
variant — auto-extracted from the upstream .zip if missing, same as
``tools.sweep``).

Usage:
    python3 -m tools.probe list
        # show every registered probe name

    python3 -m tools.probe run disasm_evidence
        # runs the probe, writes trace/disasm_evidence.json

    python3 -m tools.probe run disasm_evidence --out /tmp/d.json
        # custom output path

Add a new probe by writing a function and decorating it with
``@probe("name")``. The function receives a ``ProbeContext`` (booted
session + d64 path + output path) and is responsible for the JSON
write.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from tools.sweep import ensure_withtunes

log = logging.getLogger("probe")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_D64 = REPO_ROOT / "artefacts" / "defmon-withtunes.d64"
DEFAULT_TRACE_DIR = REPO_ROOT / "trace"
DEFAULT_BASE_PORT = 6502
DEFAULT_WORKERS = 1
MAX_WORKERS = 8

PROBES: dict[str, "ProbeFn"] = {}


@dataclass
class ProbeContext:
    """Per-probe handle yielded to the probe function."""

    d64_path: Path
    out_path: Path
    base_port: int
    workers: int


ProbeFn = Callable[[ProbeContext], None]


def run_per_tune(
    ctx: ProbeContext,
    tune_fn: Callable[[Any, int], Any],
    tunes: list | None = None,
) -> dict[str, Any]:
    """Run tune_fn(tune, port) for every tune, up to ctx.workers in parallel.

    Each submission is assigned a unique port (``base_port + submission_idx``)
    so concurrent headlessvice containers don't collide on the binmon socket.
    Returns ``{tune.name: result}`` for every tune whose ``tune_fn`` returned
    without raising. Per-tune failures are logged and skipped.
    """
    if tunes is None:
        from defmon_driver.tune_manifest import TUNES  # noqa: PLC0415

        tunes = list(TUNES)

    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=ctx.workers) as pool:
        futures = {
            pool.submit(tune_fn, tune, ctx.base_port + i): tune
            for i, tune in enumerate(tunes)
        }
        for fut in as_completed(futures):
            tune = futures[fut]
            try:
                value = fut.result()
            except Exception as e:  # noqa: BLE001
                log.exception("tune %s failed: %s", tune.name, e)
                continue
            if value is not None:
                results[tune.name] = value
    return results


def probe(name: str) -> Callable[[ProbeFn], ProbeFn]:
    """Decorator: register a probe function under the given name."""

    def _register(fn: ProbeFn) -> ProbeFn:
        if name in PROBES:
            raise ValueError(f"probe {name!r} already registered")
        PROBES[name] = fn
        return fn

    return _register


def _peek_byte(bm, addr: int) -> int:
    """Read one byte from main-memory address via the binary monitor."""
    from vice_driver.binmon import MEMSPACE_MAIN  # noqa: PLC0415

    data = bm.mem_get(addr, addr, MEMSPACE_MAIN)
    return data[0]


DISASM_EVIDENCE_TUNE = ".GLOW WORM"
DISK_MENU_BAND = (0x7400, 0x77FF)
RESIDUAL_SPANS = [
    ("$7A0A-$7F01", 0x7A0A, 0x7F01),
    ("$B413-$B595", 0xB413, 0xB595),
    ("$C6E3-$C7FF", 0xC6E3, 0xC7FF),
    ("$CE5E-$CF6B", 0xCE5E, 0xCF6B),
    ("$E036-$E13D", 0xE036, 0xE13D),
    ("$E357-$E41D", 0xE357, 0xE41D),
    ("$E491-$E52B", 0xE491, 0xE52B),
]
DISK_MENU_OPENERS = {"close_disk_menu"}


def _classify_span(pcs_hit: list[int], start: int, end_incl: int) -> str:
    if pcs_hit:
        return "code"
    return "data_or_unreachable"


@probe("disasm_evidence")
def disasm_evidence(ctx: ProbeContext) -> None:
    """Per-action PC coverage over the disk-menu code + 7 residual spans.

    Boots .GLOW WORM, opens the disk menu, then for each documented
    disk action installs byte-granularity Coverage over the disk-menu
    band ($7400-$77FF), fires the action, and snapshots executed_pcs.
    A second pass measures the 7 residual spans (defmon body areas
    cited in annotations.toml) under the full action sequence.
    """
    # Side-effect import: rebinds smoke_session's ViceContainer to the
    # headlessvice factory. Must precede the smoke_session import below.
    from tools import _headlessvice  # noqa: F401, PLC0415
    from defmon_driver._smoke_support import smoke_session  # noqa: PLC0415
    from defmon_driver.tune_manifest import TUNES  # noqa: PLC0415
    from defmon_driver.tune_navigation import (  # noqa: PLC0415
        cursor_load_tune,
        state_reset,
    )
    from vice_driver.coverage import Coverage  # noqa: PLC0415

    target_tune = next((t for t in TUNES if t.name == DISASM_EVIDENCE_TUNE), TUNES[0])

    out: dict = {
        "tune": target_tune.name,
        "d64": str(ctx.d64_path),
        "port": ctx.base_port,
        "section_1_boot_init_pcs": {"status": "DISABLED — see source comment"},
        "section_2_residual_span_hits": {"per_span": {}},
        "section_4_disk_menu_subroutines": {"per_action": {}},
    }

    t0 = time.monotonic()
    with smoke_session(
        ctx.d64_path, port=ctx.base_port, prefix="probe-disasm-"
    ) as session:
        d, bm = session.d, session.bm
        cursor_load_tune(d, target_tune)
        state_reset(d)

        cov_disk = Coverage(bm, start=DISK_MENU_BAND[0], end=DISK_MENU_BAND[1])
        cov_disk.install()
        try:
            try:
                ac = cov_disk.measure(d.open_disk_menu, "open_disk_menu", settle=0.4)
                out["section_4_disk_menu_subroutines"]["per_action"][
                    "open_disk_menu"
                ] = {
                    "pcs_hit": [f"${pc:04X}" for pc in sorted(ac.executed_pcs)],
                    "action": None,
                }
            except Exception as e:  # noqa: BLE001
                log.warning("open_disk_menu raised: %s", e)
            for name, fn in d.all_documented_disk_actions():
                try:
                    ac = cov_disk.measure(fn, name, settle=0.4)
                except Exception as e:  # noqa: BLE001
                    log.warning("disk action %s raised: %s", name, e)
                    continue
                pcs_hit = sorted(ac.executed_pcs)
                out["section_4_disk_menu_subroutines"]["per_action"][name] = {
                    "pcs_hit": [f"${pc:04X}" for pc in pcs_hit],
                    "action": None,
                }
                if name not in DISK_MENU_OPENERS:
                    try:
                        d.open_disk_menu()
                    except Exception:  # noqa: BLE001
                        pass
        finally:
            cov_disk.remove()

        for span_key, start, end_incl in RESIDUAL_SPANS:
            cov = Coverage(bm, start=start, end=end_incl)
            cov.install()
            try:
                ac = cov.measure(d.play_from_cursor, "play_from_cursor", settle=0.6)
                ac_stop = cov.measure(d.stop_playback, "stop_playback", settle=0.3)
                pcs_hit = sorted(ac.executed_pcs | ac_stop.executed_pcs)
            except Exception as e:  # noqa: BLE001
                log.warning("span %s measurement failed: %s", span_key, e)
                pcs_hit = []
            finally:
                cov.remove()
            out["section_2_residual_span_hits"]["per_span"][span_key] = {
                "pcs_hit": [f"${pc:04X}" for pc in pcs_hit],
                "classification": _classify_span(pcs_hit, start, end_incl),
                "span_len": None,
                "pct": None,
            }

    out["wall_seconds"] = time.monotonic() - t0
    ctx.out_path.parent.mkdir(parents=True, exist_ok=True)
    ctx.out_path.write_text(json.dumps(out, indent=2))
    log.info(
        "wrote %s (actions=%d, spans=%d, wall=%.1fs)",
        ctx.out_path,
        len(out["section_4_disk_menu_subroutines"]["per_action"]),
        len(out["section_2_residual_span_hits"]["per_span"]),
        out["wall_seconds"],
    )


def _resolve_out(name: str, override: str | None) -> Path:
    if override is not None:
        return Path(override)
    return DEFAULT_TRACE_DIR / f"{name}.json"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list registered probes")

    p_run = sub.add_parser("run", help="run one probe")
    p_run.add_argument("name", help="probe name (see `list`)")
    p_run.add_argument(
        "--d64",
        default=str(DEFAULT_D64),
        help="defMON .d64 with the example tunes",
    )
    p_run.add_argument("--out", default=None, help="JSON output path")
    p_run.add_argument(
        "--base-port",
        type=int,
        default=DEFAULT_BASE_PORT,
        help="first binmon port; workers use base + 0..N-1",
    )
    p_run.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"concurrent headlessvice emulators (1..{MAX_WORKERS})",
    )
    p_run.add_argument(
        "--skip-fetch",
        action="store_true",
        help="do NOT download/extract the .d64; require --d64 to exist",
    )
    p_run.add_argument("-v", "--verbose", action="store_true")

    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
    )

    if args.cmd == "list":
        for name in sorted(PROBES):
            print(name)
        return 0

    if args.name not in PROBES:
        log.error("unknown probe %r; known: %s", args.name, sorted(PROBES))
        return 1

    workers = max(1, min(MAX_WORKERS, args.workers))
    if workers != args.workers:
        log.warning("clamped workers %d -> %d", args.workers, workers)

    d64_path = Path(args.d64).resolve()
    if not args.skip_fetch:
        ensure_withtunes(d64_path)
    if not d64_path.is_file():
        log.error("missing .d64: %s", d64_path)
        return 1

    out_path = _resolve_out(args.name, args.out)
    ctx = ProbeContext(
        d64_path=d64_path,
        out_path=out_path,
        base_port=args.base_port,
        workers=workers,
    )
    PROBES[args.name](ctx)
    return 0


if __name__ == "__main__":
    sys.exit(main())
