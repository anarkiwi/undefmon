# undefmon

[`defmon.s`](defmon.s) — a 1.3 MB annotated 64tass-assemblable
disassembly of [defMON](https://defmon.vandervecken.com), produced
semti-automatically and round-tripped byte-for-byte against the
original binary. The rest of this repo is the toolchain that emits
and verifies it.

## Build

From a clean checkout, the full reproducibility check is two commands:

    make distclean
    make verify          # fetch-static + emit + roundtrip + lint + ghidra-export
                         # diffs every regenerated artefact against the committed copy

Individual steps:

    make fetch-static    # docker-builds artefacts/defmon-static.bin
    make                 # regenerates defmon.s from the unpacked image
    make roundtrip       # assembles defmon.s and verifies the bytes match
    make lint            # 10-check annotation lint suite over annotations.toml
    make ghidra-export   # reproduces artefacts/ghidra/*.json into build/ghidra-fresh/

`defmon.s` is committed as a reference; `make` reproduces it byte-for-
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
- `64tass` (`apt-get install 64tass`) — for `roundtrip`
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
| instruction bytes                   | 26,610 | 46.5% |
| data: zero-fill (buffers / init RAM)| 20,283 | 35.4% |
| data: non-zero, with `notes`        |  9,926 | 17.3% |
| data: non-zero, role-only residue   |    404 |  0.7% |

The largest data spans (`$2180-$5EFF` pattern RAM ≈75% zero, `$5FFF-$6DFF`
sidTAB and `$DD01-$DFFE` tail both 100% zero) are initialised working RAM,
named at their boundaries — not reverse-engineering gaps. The genuinely
undocumented residue is **404 non-zero bytes (0.7%)** across 25 small
spans that already carry a `role` but no `notes`. (An earlier table here
reported "29% uncategorised"; that figure presented an instruction
*count*, 11,500, as a byte share and predated full region coverage.)

Annotation catalogue (`tools/re/annotations.toml`):

- 317 `[function.$XXXX]` entries (all have `role`; 283 have `notes`;
  89 have explicit `callers`; 72 have explicit `inputs`)
- 356 `[region.$XXXX]` entries
- 89 per-branch condition overrides, 16 text spans, 6 SMC-dispatch
  sites, 11 SMC-opcode-flip sites, 9 SMC-branch sites, 1
  refuted-hypothesis entry

Comparison-site dataflow (`build/cmp_facts.json`, 1,629 branches):

- 1,499 resolved (92.0%) — operand-based, var-load, indirect-load,
  immediate, transformed, or carried from the JSR caller
- 81 unknown (5.0%)
- 39 with no flag-setter in range
- 10 multi-source (flag-setter reachable from multiple lhs values)

## What is reproducible end-to-end

From a clean checkout + `make fetch-static && make ghidra-export && make roundtrip`:

- `artefacts/defmon-static.bin` is downloaded from upstream and unpacked.
  Pinned sha256 (`bc78644c…`) checked on output.
- `artefacts/ghidra/*.json` (5 files) are regenerated from
  `defmon-static.bin` + `annotations.toml` + `entrypoints.json` by
  running Ghidra 12.1 headlessly inside `Dockerfile.ghidra`. Diff-as-
  JSON against committed copies is asserted by
  `tests/test_ghidra_export.py`.
- `defmon.s` is regenerated. Byte-for-byte identical to the committed
  copy (asserted by `tests/test_emit.py`).
- `defmon.s` round-trips through 64tass: the assembled bytes equal
  `defmon-static.bin` over `$0800-$E786` (asserted by
  `tests/test_roundtrip.py` and the `roundtrip` make target).

## What is *not* yet reproducible

Only one input remains hand-curated with no regeneration path:

1. **`tools/re/annotations.toml`** (407 KB). The human RE knowledge
   base — 317 function entries, 356 region entries, 89 branch
   overrides, value-name catalogues. Reproducible only in the sense
   that it's committed; the *content* is the result of human
   reverse-engineering. Drift is now guarded by `make lint` (10
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

- **64tass version.** Currently `1.59.3120` (Ubuntu apt). A future
  release could in principle emit different bytes for the same source,
  breaking the round-trip. Mitigation if it ever bites: pin a known
  release in CI.
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

1. **Data residue is 404 non-zero bytes (0.7%).** Every data sub-span
   already starts at a `[region]`/`[function]`, and 35% of the image is
   zero-fill buffers (see the profile table above). The remaining gap is
   25 small spans with a `role` but no `notes` — list them with
   `python3 -m tools.re.data_region_coverage --profile`. Add `notes` to
   close it; this is polish, not a structural hole.

2. **81 branches have `unknown` lhs** in `cmp_facts.json` (down from 92
   once the `izy` indirect-load setters were modelled). The remainder
   need harder analysis — `unmodeled_jsr` (33, value is a JSR return),
   `clobber_adc/sbc/ora` (33, value computed by arithmetic before a
   `CMP #imm`), and `pla`-from-stack (15). Extend
   `tools/re/cmp_facts.py` with cross-call/arithmetic dataflow, or add
   manual `[branch."$XXXX"]` overrides. List them with:

        python3 -c "import json; cf=json.load(open('build/cmp_facts.json'));\
        print('\n'.join(pc for pc,f in cf['facts'].items() \
        if f.get('lhs',{}).get('kind')=='unknown'))"

3. **Ghidra symbol table is 3,580 entries but only 187 are merged**
   into `defmon.s`. The rest are `DAT_xxxx` / `BYTE_xxxx`
   placeholders. Promote interesting ones via `annotations.toml`.

4. **`[refuted]` has 1 entry.** Record dead-end hypotheses there so
   future work doesn't re-walk them.

5. **3,234 of 11,500 code-starts are statically unreachable.** Run
   `make unreachable-triage` to bucket them. ~96% sit inside a single
   `paint_page_*` data span — screen data that decodes as instructions,
   not dead code — so the headline number overstates the gap. The
   actionable residue is the `isolated` starts outside data regions and
   the `smc_io_band` bucket (reached via SMC / RAM-under-I/O banking).

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
