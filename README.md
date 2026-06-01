# undefmon

[`defmon.asm`](defmon.asm) — a 1.4 MB annotated [Kick
Assembler](http://theweb.dk/KickAssembler) disassembly of
[defMON](https://defmon.vandervecken.com), round-tripped byte-for-byte
against the original binary. Kick Assembler reproduces every NMOS
undocumented opcode defMON uses (LAX/SAX/AXS/ALR/ARR, and the
duplicate-encoding ANC `$2B` / SBC `$EB` via `anc2`/`sbc2`), so there
are no `.byte` escapes. The rest of the repo is the toolchain that emits
and verifies it.

## Build

    make distclean
    make verify          # fetch-static + emit + roundtrip + lint + ghidra-export,
                         # diffing every regenerated artefact vs the committed copy

Targets: `make` regenerates `defmon.asm`; `make roundtrip` assembles it
and byte-compares; `make lint` runs the annotation lint suite; `make
fetch-static` and `make ghidra-export` run their Docker builds.

`defmon.asm` is committed and reproduced byte-for-byte from `artefacts/`,
`trace/entrypoints.json`, and `tools/re/annotations.toml`.
`artefacts/defmon-static.bin` is not committed — `make fetch-static`
builds exomizer 3.1.2 in Docker, downloads the upstream `.d64`, and
`exomizer desfx`-unpacks it to a 64K image (pinned sha256). `make
ghidra-export` runs Ghidra in `Dockerfile.ghidra` to regenerate
`artefacts/ghidra/*.json`; promotion over the committed copies is a
manual review step.

Required for `make verify`: `docker`; `java` + Kick Assembler
(`KICKASS_JAR`, default `/usr/local/kickass/KickAss.jar`); Python ≥3.11.

## Tests

    python3 -m unittest discover tests

CI (`.github/workflows/tests.yml`) runs two jobs per push: `unittest`
(fetch + tests + round-trip + lint) and `ghidra-export` (the JSON diff).
The Ghidra test skips locally unless `build/ghidra-fresh/` is populated.

## Coverage

Static image `$0800–$E786` (57,223 bytes);
`python3 -m tools.re.data_region_coverage --profile` reproduces:

| bucket                                | bytes  | share |
| ------------------------------------- | -----: | ----: |
| instruction                           | 27,822 | 48.6% |
| data: zero-fill (buffers / init RAM)  | 20,233 | 35.4% |
| data: non-zero, documented (`notes`)  |  9,168 | 16.0% |
| data: non-zero, role-only residue     |      0 |  0.0% |

Every non-zero data byte is documented (residue 0). The catalogue in
`tools/re/annotations.toml` holds 357 `[function]` + 363 `[region]`
entries, 90 `[branch]` overrides, 16 text spans, the SMC
dispatch/opcode/branch tables, and 1 `[refuted]`. Comparison-site
dataflow (`build/cmp_facts.json`) covers 1,690 branches, every one with
a rendered condition — the lone `$B78B` BCC, whose carry is set across a
`jmp` join the in-range dataflow can't follow, via a manual `[branch]`
override.

## Reproducibility

`make verify` asserts each committed artefact regenerates from inputs:

- `defmon-static.bin` — downloaded + unpacked, pinned sha256.
- `artefacts/ghidra/*.json` — Ghidra 12.1 export, diffed by
  `tests/test_ghidra_export.py`.
- `defmon.asm` — byte-identical to the committed copy
  (`tests/test_emit.py`) and assembles back to `defmon-static.bin` over
  `$0800–$E786` (`tests/test_roundtrip.py`).

The one hand-curated input with no regeneration path is
**`tools/re/annotations.toml`** — the human RE knowledge base — guarded
against drift by `make lint` (schema, orphans, no raw hex/asm/narrative
in prose, enum coverage, ref substitution, data-region coverage,
callgraph). `trace/disasm_evidence.json` is reproducible via
`tools/probe.py` (needs defmon-driver + headlessvice).

## Version pins

A change in any of these can fail a test without an obvious cause:

- **Kick Assembler** 5.25 (Java 21); CI downloads the latest from
  `theweb.dk` — pin/vendor the jar if its output drifts.
- **exomizer** 3.1.2, built from Bitbucket inside the image.
- **upstream `.d64`** from `defmon.vandervecken.com` (pinned sha256).
- **Ghidra** 12.1; **Python** 3.12 in CI.

## Open RE items

- **Ghidra placeholders**: the export carries ~3,370 `DAT_`/`BYTE_`
  symbols, but `defmon.asm` names operands from its own layers, so no
  bare `$XXXX` operands remain — the placeholders matter only for the
  symbol export, not the disassembly.
- **SMC catalogue** is hand-curated: 11 `smc_opcode` flips + 9
  `smc_branch` gates carry descriptions; 24 register-aliased false
  positives are dropped at emit; a few discovery banners remain
  (`$8D26`, `$BDA4`, `$C28D`, `$E29B`).

## See also

`USER_GUIDE.md` — using defMON the tracker (concepts, walkthrough,
keychord reference).
