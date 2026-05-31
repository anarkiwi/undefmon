# undefmon

[`defmon.asm`](defmon.asm) — a 1.4 MB annotated [Kick
Assembler](http://theweb.dk/KickAssembler)-assemblable disassembly of
[defMON](https://defmon.vandervecken.com), produced semi-automatically
and round-tripped byte-for-byte against the original binary. defMON
leans on the NMOS undocumented opcodes (LAX/SAX/AXS/ALR/ARR and the
duplicate-encoding ANC `$2B` / SBC `$EB`); Kick Assembler reproduces
all of them as native mnemonics (the `$2B`/`$EB` duplicates via `anc2`
/`sbc2`), so the disassembly round-trips with zero `.byte` escapes. The
rest of this repo is the toolchain that emits and verifies it.

## Build

From a clean checkout, the full reproducibility check is two commands:

    make distclean
    make verify          # fetch-static + emit + roundtrip + lint + ghidra-export
                         # diffs every regenerated artefact against the committed copy

Individual steps:

    make fetch-static    # docker-builds artefacts/defmon-static.bin
    make                 # regenerates defmon.asm from the unpacked image
    make roundtrip       # assembles defmon.asm and verifies the bytes match
    make lint            # 10-check annotation lint suite over annotations.toml
    make ghidra-export   # reproduces artefacts/ghidra/*.json into build/ghidra-fresh/

`defmon.asm` is committed as a reference; `make` reproduces it byte-for-
byte from the inputs in `artefacts/`, `trace/entrypoints.json`, and
`tools/re/annotations.toml`.

`artefacts/defmon-static.bin` is not committed. `make fetch-static`
delegates to `docker build --target export --output artefacts .`,
which builds [`exomizer`](https://bitbucket.org/magli143/exomizer)
3.1.2 from source inside the image, downloads
[defmon-20201008.zip](https://defmon.vandervecken.com/lib/exe/fetch.php?media=download:defmon-20201008.zip),
extracts the PRG from the .d64, runs `exomizer desfx`, and flattens
to a 64K image. `exomizer` lives only inside the image.

`make ghidra-export` delegates to a second Dockerfile
(`Dockerfile.ghidra`) that installs Ghidra and `pyghidra`, runs
`tools/re/ghidra_import.py` against the static image + annotations
+ entrypoints, and emits the 5 JSON files into `build/ghidra-fresh/`.
Diff-as-JSON against the committed `artefacts/ghidra/*.json` is
asserted by `tests/test_ghidra_export.py`. Ghidra lives only inside
its image. The committed artefacts are NOT auto-overwritten —
promotion is a manual review step.

External tools required for `make verify`:

- `docker` (with BuildKit, default in modern releases) — for
  `fetch-static` + `ghidra-export`
- `java` + Kick Assembler — for `roundtrip`. Point `KICKASS_JAR` at
  your `KickAss.jar` (default `/usr/local/kickass/KickAss.jar`) and
  `JAVA` at the launcher (default `java`)
- Python ≥3.11 (`tomllib`) — for the emitter and lint suite

## Tests

    python3 -m unittest discover tests

The Ghidra-export test skips unless `build/ghidra-fresh/` is
populated; run `make ghidra-export` first to opt into it.

CI runs both pipelines on every push (`.github/workflows/tests.yml`):
the `unittest` job runs fetch + tests + round-trip; the
`ghidra-export` job runs `Dockerfile.ghidra` in parallel and asserts
the JSON diff. Build caching keeps incremental runs fast — both
Docker images cache aggressively against `type=gha`.

## Where the RE stands

The static image is `$0800–$E786` (57,223 bytes). Run
`python3 -m tools.re.data_region_coverage --profile` to reproduce:

| bucket                              | bytes  | share |
| ----------------------------------- | -----: | ----: |
| instruction bytes                   | 27,664 | 48.3% |
| data: zero-fill (buffers / init RAM)| 20,236 | 35.4% |
| data: non-zero, with `notes`        |  9,258 | 16.2% |
| data: non-zero, role-only residue   |     65 |  0.1% |

The largest data spans (`$2180-$5EFF` pattern RAM ≈75% zero, `$5FFF-$6DFF`
sidTAB and `$DD01-$DFFE` tail both 100% zero) are initialised working RAM,
named at their boundaries — not reverse-engineering gaps. The remaining
role-only residue is **65 non-zero bytes (0.1%)** across 8 small spans —
SMC operand slots, 1-byte state vars, and one screen template — whose
`role` already explains them; a `notes` line there would restate.

Annotation catalogue (`tools/re/annotations.toml`):

- 355 `[function.$XXXX]` entries (all have `role`; 293 have `notes`;
  89 have explicit `callers`; 72 have explicit `inputs`)
- 362 `[region.$XXXX]` entries
- 89 per-branch condition overrides, 16 text spans, 6 SMC-dispatch
  sites, 11 SMC-opcode-flip sites, 9 SMC-branch sites, 1
  refuted-hypothesis entry

Comparison-site dataflow (`build/cmp_facts.json`, 1,690 branches):

- 1,671 with a renderable lhs (98.9%) — operand-based, var-load,
  indirect-load, immediate, transformed, carried from the JSR caller,
  a register-level lhs (`A < #imm?`) for ALU-computed values, or a
  callee-result lhs (`kbd_scan->A was $FF?`) for values a JSR returned
- 1 unknown (0.1%) — stack-pull (PLA)
- 18 multi-source (flag-setter reachable from multiple lhs values)

## What is reproducible end-to-end

From a clean checkout + `make fetch-static && make ghidra-export && make roundtrip`:

- `artefacts/defmon-static.bin` is downloaded from upstream and unpacked.
  Pinned sha256 (`bc78644c…`) checked on output.
- `artefacts/ghidra/*.json` (5 files) are regenerated from
  `defmon-static.bin` + `annotations.toml` + `entrypoints.json` by
  running Ghidra 12.1 headlessly inside `Dockerfile.ghidra`. Diff-as-
  JSON against committed copies is asserted by
  `tests/test_ghidra_export.py`.
- `defmon.asm` is regenerated. Byte-for-byte identical to the committed
  copy (asserted by `tests/test_emit.py`).
- `defmon.asm` round-trips through Kick Assembler: the assembled bytes
  equal `defmon-static.bin` over `$0800-$E786` (asserted by
  `tests/test_roundtrip.py` and the `roundtrip` make target).

## What is *not* yet reproducible

Only one input remains hand-curated with no regeneration path:

1. **`tools/re/annotations.toml`** (407 KB). The human RE knowledge
   base — 317 function entries, 356 region entries, 89 branch
   overrides, value-name catalogues. Reproducible only in the sense
   that it's committed; the *content* is the result of human
   reverse-engineering. Drift is guarded by `make lint` (10
   checks: schema shape, orphan addresses, no raw `$XXXX` / asm
   mnemonics / RE narrative in prose, enum-value reachability, hex/
   byte ref substitution, data-region coverage, callgraph callers
   cross-check). CI runs `make lint` on every push.

`trace/disasm_evidence.json` is the only other committed evidence
file — referenced by `tools/re/annotations.toml` as code/data
classification for specific PC ranges. `tools/probe.py` is the
framework for reproducing it and adding new probes (boot session →
scripted actions → JSON output). Run with `make probe-list` /
`python3 -m tools.probe run disasm_evidence`. Same defmon-driver +
headlessvice prereqs as the sweep.

## Soft-pinning gaps

These are not unreproducible *per se*, but a change in any of them
could surface as a failing test without an obvious cause.

- **Kick Assembler version.** Developed against `5.25` (Java 21). A
  future release could in principle emit different bytes for the same
  source, breaking the round-trip. CI downloads the latest from
  `theweb.dk`; mitigation if it ever bites: pin a known release (vendor
  the jar) and set `KICKASS_JAR`.
- **exomizer version.** The Dockerfile builds `3.1.2` from
  `bitbucket.org/magli143/exomizer`. If the Bitbucket archive moves or
  the upstream changes 3.1.2's behaviour, the unpack hash diverges.
  Mitigation: vendor the tarball into the image.
- **Upstream .zip availability.** `tools/fetch_static.py` pulls from
  `defmon.vandervecken.com`. If the site goes away the cold-start
  pipeline fails. Mitigation: vendor the .d64 (174 KB) or pin an
  archive.org mirror.
- **Python version.** Emitter uses `tomllib` (3.11+); CI pins 3.12.
- **Ghidra version.** `Dockerfile.ghidra` pins Ghidra 12.1
  (`Ghidra_12.1_build` from NSA's GitHub releases). Behaviour-changing
  releases could perturb the auto-analysis output and fail the
  diff-as-JSON gate; bump the pin and re-export when that happens.

## Where the RE still has gaps

(These are about the disassembly's completeness, not about
reproducing the build.)

1. **Data residue is 86 non-zero bytes (0.2%).** Every data sub-span
   already starts at a `[region]`/`[function]`, and 35% of the image is
   zero-fill buffers (see the profile table above). The remaining 15
   spans (SMC operand slots, 1-byte state vars, one screen template) all
   carry a `role`; list them with
   `python3 -m tools.re.data_region_coverage --profile`. This is the
   floor — those `role`s already explain the bytes, so further `notes`
   would restate rather than inform.

2. **1 branch has `unknown` lhs** in `cmp_facts.json`. It is
   `pla`-from-stack — the tested register was pulled off the stack, so
   resolving it needs PHA/PLA stack-discipline tracking. Add manual
   `[branch."$XXXX"]` overrides, or extend `tools/re/cmp_facts.py`. List
   them with:

        python3 -c "import json; cf=json.load(open('build/cmp_facts.json'));\
        print('\n'.join(pc for pc,f in cf['facts'].items() \
        if f.get('lhs',{}).get('kind')=='unknown'))"

3. **Ghidra's symbol table has ~3,370 `DAT_`/`BYTE_` placeholders, but
   `defmon.asm` does not use them.** The emitter names addresses from its
   own layers (annotations + `SEED_LANDMARKS` + state/equate labels), so
   essentially every operand in `defmon.asm` already resolves to a label —
   a grep for bare `$XXXX` operands finds none. The placeholder count is
   Ghidra's internal view, not a `defmon.asm` readability gap; promoting a
   Ghidra `DAT_xxxx` only matters where it would feed the export's
   symbol table, not the disassembly the reader sees.

4. **`[refuted]` has 1 entry.** Record dead-end hypotheses there so
   future work doesn't re-walk them.

5. **Every code-start is statically reachable** (`make
   unreachable-triage` → 0). The duplicate-encoding bytes (`$2B` ANC,
   `$EB` SBC) are emitted as Kick Assembler's `anc2`/`sbc2` mnemonics,
   which assemble to those exact encodings — so they round-trip as real
   instructions with no `.byte` escape.

6. **SMC catalogue is curated** (dispatch + opcode + branch). 11
   genuine `smc_opcode` flips and the 9 `smc_branch` gate sites at
   `$1183-$12AF` (per-voice sidcall/note gates; BPL offsets set once at
   load by the `$D1B6-$D1E0` decoder) carry `[smc_opcode]`/`[smc_branch]`
   descriptions. The 24 VIC/SID register-aliased false positives (a
   write to a hardware register that aliases RAM-under-I/O code) are
   dropped at emit time (see `load_smc_opcode_catalogue`). Left as raw
   discovery banners: a few opcode sites in data buffers (`$8D26`,
   `$BDA4`) and the supercmd branch arms (`$C28D`, `$E29B`).

## See also

`USER_GUIDE.md` — how to actually use defMON the tracker (concepts,
walkthrough, full keychord reference).
