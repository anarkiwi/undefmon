# Minimal build: regenerate defmon.s from the static image.
#
#   make                — regenerate defmon.s (default)
#   make defmon.s       — same
#   make fetch-static   — reproduce artefacts/defmon-static.bin from the
#                         upstream .d64 (uses Docker; see Dockerfile)
#   make roundtrip      — assemble defmon.s with 64tass and verify the
#                         bytes match defmon-static.bin
#   make ghidra-export  — reproduce artefacts/ghidra/*.json from the repo's
#                         RE inputs by running Ghidra in Docker. Writes the
#                         5 JSON files into build/ghidra-fresh/ for diffing
#                         against the committed copies (see tests/).
#   make sweep          — reproduce trace/entrypoints.json by driving defMON
#                         in headlessvice via defmon-driver. SLOW (1-3 hours);
#                         requires pip install defmon-driver vice-driver and
#                         a docker daemon with headlessvice access. Never
#                         invoked by CI.
#   make unreachable-triage — bucket the unreachable code-starts in
#                         callgraph.json and list the regions harbouring
#                         the most (a worklist; read-only report)
#   make probe-list     — list dynamic-evidence probes registered in tools/probe.py
#   make probe-disasm   — run the disasm_evidence probe (regenerates
#                         trace/disasm_evidence.json). Same defmon-driver /
#                         headlessvice requirements as sweep.
#   make lint           — annotation lint suite: schema, orphan-check,
#                         no-hex/asm/narrative/literal in prose, enum
#                         coverage, hex/byte substitution, data-region
#                         coverage, callgraph callers cross-check.
#   make verify         — full reproducibility check: fetch-static, build
#                         defmon.s, round-trip, lint, ghidra-export, then
#                         diff every regenerated artefact against the
#                         committed copy. Skips headlessvice probes (sweep /
#                         probe-disasm) since they need a special image.
#   make clean          — remove build/ and defmon.s
#   make distclean      — also remove fetched artefacts under artefacts/
#
# Required external tools:
#   docker   — for `make fetch-static` + `make ghidra-export`
#              (exomizer and Ghidra live only inside their images)
#   64tass   — for `make roundtrip` (`apt-get install 64tass`)

OUT          := defmon.s
STATIC_BIN   := artefacts/defmon-static.bin
ANNOTATIONS  := tools/re/annotations.toml
ENTRYPOINTS  := trace/entrypoints.json
GHIDRA_DIR   := artefacts/ghidra
BUILD_DIR    := build

SHELL        := /bin/bash

PYTHON       ?= python3
DOCKER       ?= docker
TASS         ?= 64tass

GHIDRA_FRESH := $(BUILD_DIR)/ghidra-fresh

.PHONY: all defmon.s fetch-static roundtrip ghidra-export sweep \
        probe-list probe-disasm lint callgraph unreachable-triage \
        reg-effects verify clean distclean

all: $(OUT)

$(STATIC_BIN): Dockerfile tools/fetch_static.py tools/d64.py
	$(DOCKER) build --target export --output artefacts .

fetch-static: $(STATIC_BIN)

# defmon.s is regenerated whenever the static image, annotations, the
# emitter, or the comparison-site facts change. cmp_facts.json is the
# only intermediate build artefact and lives under build/.
$(OUT): $(STATIC_BIN) $(ANNOTATIONS) \
        tools/re/emit_defmon_source.py $(BUILD_DIR)/cmp_facts.json
	$(PYTHON) -m tools.re.emit_defmon_source

$(BUILD_DIR)/cmp_facts.json: $(STATIC_BIN) $(ANNOTATIONS) $(ENTRYPOINTS) \
                             tools/re/cmp_facts.py tools/re/callgraph.py \
                             tools/re/emit_defmon_source.py | $(BUILD_DIR)
	$(PYTHON) -m tools.re.cmp_facts --out $@

$(BUILD_DIR):
	mkdir -p $@

# Assemble defmon.s with 64tass and verify the resulting bytes match
# the unpacked static image at the original load address. This is the
# correctness gate the emitter's `make defmon.s` output is judged on.
roundtrip: $(OUT) $(STATIC_BIN)
	$(TASS) -i -b --nostart -o $(BUILD_DIR)/defmon-reassembled.bin $(OUT)
	$(PYTHON) -m tools.roundtrip_check \
	    --static $(STATIC_BIN) \
	    --reassembled $(BUILD_DIR)/defmon-reassembled.bin

# Run Ghidra in Docker to reproduce artefacts/ghidra/*.json. The build
# is heavy (~5-10 min cold; cached fast); the output lives under
# build/ghidra-fresh/ for diffing against the committed JSONs (see
# tests/test_ghidra_export.py). The committed artefacts/ghidra/*.json
# are NOT overwritten — that promotion is a manual step once a diff
# has been reviewed.
ghidra-export: $(STATIC_BIN) | $(BUILD_DIR)
	mkdir -p $(GHIDRA_FRESH)
	$(DOCKER) build -f Dockerfile.ghidra --target export \
	    --output $(GHIDRA_FRESH) .

# Drive defMON in headlessvice via defmon-driver to regenerate
# trace/entrypoints.json. Manual / opt-in only; see tools/sweep.py for
# prerequisites and timing.
sweep:
	$(PYTHON) -m tools.sweep

# Dynamic-evidence probes (one-off investigations writing into trace/).
# Currently only disasm_evidence.json is referenced by annotations.toml;
# see tools/probe.py for the registration pattern.
probe-list:
	$(PYTHON) -m tools.probe list

probe-disasm:
	$(PYTHON) -m tools.probe run disasm_evidence

# Static call graph (consumed by callgraph_check and by cmp_facts).
$(BUILD_DIR)/callgraph.json: $(STATIC_BIN) $(ANNOTATIONS) \
                             tools/re/callgraph.py \
                             tools/re/emit_defmon_source.py | $(BUILD_DIR)
	$(PYTHON) -m tools.re.callgraph --out $@

callgraph: $(BUILD_DIR)/callgraph.json

# Per-function register-clobber analysis (which of A/X/Y each [function]
# destroys, transitive over its callees). Read-only artifact + report;
# `--report` cross-checks the hand-written registers_clobbered fields.
$(BUILD_DIR)/reg_effects.json: $(STATIC_BIN) $(ANNOTATIONS) $(ENTRYPOINTS) \
                               tools/re/reg_effects.py \
                               tools/re/emit_defmon_source.py | $(BUILD_DIR)
	$(PYTHON) -m tools.re.reg_effects --out $@

reg-effects: $(BUILD_DIR)/reg_effects.json
	$(PYTHON) -m tools.re.reg_effects --report

# Triage the unreachable code-starts in callgraph.json into buckets
# (smc/io-band, data-xref-only, transitively-unreachable, isolated) and
# list the regions harbouring the most — a worklist for tightening data
# declarations and adding SMC/jump-table seeds. Read-only report.
unreachable-triage: $(BUILD_DIR)/callgraph.json
	$(PYTHON) -m tools.re.unreachable_triage

# Annotation lint suite — guards against drift in tools/re/annotations.toml.
# Each check must exit 0; CI runs `make lint` on every push.
lint: $(BUILD_DIR)/cmp_facts.json $(BUILD_DIR)/callgraph.json
	$(PYTHON) -m tools.re.check_schema
	$(PYTHON) -m tools.re.check_annotations --strict
	$(PYTHON) -m tools.re.check_no_hex_in_prose
	$(PYTHON) -m tools.re.check_no_asm_in_prose
	$(PYTHON) -m tools.re.check_no_re_narrative
	$(PYTHON) -m tools.re.check_enum_coverage
	$(PYTHON) -m tools.re.substitute_hex_refs --check
	$(PYTHON) -m tools.re.substitute_byte_refs --check
	$(PYTHON) -m tools.re.data_region_coverage
	$(PYTHON) -m tools.re.callgraph_check

# Full reproducibility check from inputs. Asserts that the committed
# defmon.s, ghidra/*.json, and trace/*.json are all reproducible from
# annotations.toml + entrypoints.json + the upstream .d64 (fetched via
# Docker). Does NOT exercise the headlessvice-dependent probes (sweep,
# probe-disasm) — those need a special docker image and run for too
# long to gate the build.
verify: $(STATIC_BIN) | $(BUILD_DIR)
	@git show HEAD:defmon.s > $(BUILD_DIR)/defmon.s.committed
	$(MAKE) $(OUT)
	@diff -q $(OUT) $(BUILD_DIR)/defmon.s.committed
	$(MAKE) roundtrip
	$(MAKE) lint
	$(MAKE) ghidra-export
	@for f in segments smc_branch smc_dispatch smc_opcode symbols; do \
	    diff <($(PYTHON) -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))" $(GHIDRA_DIR)/$$f.json) \
	         <($(PYTHON) -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))" $(GHIDRA_FRESH)/$$f.json) >/dev/null \
	         || { echo "FAIL: artefacts/ghidra/$$f.json diverges from fresh export"; exit 1; }; \
	done
	$(PYTHON) -m unittest discover tests -v
	@echo "verify: PASS — all committed artefacts are reproducible from inputs."

clean:
	rm -rf $(BUILD_DIR) $(OUT)

distclean: clean
	rm -f artefacts/defmon-static.bin
