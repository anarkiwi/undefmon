"""Wire ``defmon_driver._smoke_support.smoke_session`` to ``anarkiwi/headlessvice``.

``smoke_session`` instantiates ``vice_driver.vice_docker.ViceContainer``
directly, hard-coding ``mounts=`` so callers can't add bind mounts via
``container_kwargs``. The headlessvice image needs three extra mounts to
keep x64sc from segfaulting (VICE writes its log file to
``~/.local/state/vice/vice.log`` and expects the directory to exist),
plus the v0.2.0 ``entrypoint=`` override because the image's CMD is
``/bin/bash``, not ``x64sc``.

Importing this module rebinds ``defmon_driver._smoke_support.ViceContainer``
to a factory that:

* defaults ``image`` to ``anarkiwi/headlessvice:latest``;
* defaults ``entrypoint`` to ``x64sc``;
* allocates a per-container tempdir, binds its three subdirs to the VICE
  state paths, and rmtree-s it after the container stops.

The patch is idempotent and side-effect-free if the smoke session is
never invoked (e.g. ``python3 -m tools.probe list``).
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from vice_driver.vice_docker import DiskMount, ViceContainer

HEADLESSVICE_IMAGE = "anarkiwi/headlessvice:latest"
X64SC_ENTRYPOINT = "x64sc"

_VICE_STATE_DIRS = (
    ("config", "/root/.config/vice"),
    ("state", "/root/.local/state/vice"),
    ("cache", "/root/.cache/vice"),
)


def _headlessvice_container(**kw) -> ViceContainer:
    statedir = Path(tempfile.mkdtemp(prefix="hlv-state-"))
    for sub, _ in _VICE_STATE_DIRS:
        (statedir / sub).mkdir()
    extra_mounts = [
        DiskMount(str(statedir / sub), container_path)
        for sub, container_path in _VICE_STATE_DIRS
    ]
    kw.setdefault("image", HEADLESSVICE_IMAGE)
    kw.setdefault("entrypoint", X64SC_ENTRYPOINT)
    kw["mounts"] = list(kw.get("mounts") or []) + extra_mounts
    c = ViceContainer(**kw)
    orig_stop = c.stop

    def stop_and_clean(*a, **kw2):
        try:
            return orig_stop(*a, **kw2)
        finally:
            shutil.rmtree(statedir, ignore_errors=True)

    c.stop = stop_and_clean  # type: ignore[method-assign]
    return c


def install() -> None:
    """Rebind smoke_session's ViceContainer name to the headlessvice factory."""
    import defmon_driver._smoke_support as _ss  # noqa: PLC0415

    _ss.ViceContainer = _headlessvice_container  # type: ignore[assignment]


install()
