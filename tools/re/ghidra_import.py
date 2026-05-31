"""Phase 3b: pyghidra import of defmon-static.bin.

Loads the 64K static image as a single 6502 program, seeds labels from
the 47 SEED_LANDMARKS pinned in `tools/re/emit_defmon_source.py` plus
every PC in `trace/entrypoints.json`, marks the known data segments
(arrangers, pattern bank, LUTs, sidTAB region, RAM-under-I/O), forces
disassembly on every seeded code start, runs auto-analysis, then
exports:

  artefacts/ghidra/symbols.json     - {addr: label} for every Ghidra symbol
  artefacts/ghidra/segments.json    - data-segment regions marked as data
  artefacts/ghidra/defmon.lst       - full listing dump
  artefacts/ghidra/decompile/       - per-function decompiled C (best-effort;
                                       6502 decompiler output is approximate)

Pass-2 of `emit_defmon_source.py` will consume `symbols.json` to replace
`_XXXX` placeholders with meaningful labels and `segments.json` to
collapse `.byte` runs over recognised data into structured directives.
The round-trip CI assertion in `tools/re/roundtrip_check.py` MUST
continue to pass — this exporter only records annotations, never
changes emitted bytes.

Idempotent: re-running on the same project picks up where the previous
run left off; analysis re-runs cleanly.

Usage:
    python3 -m tools.re.ghidra_import \\
        --bin artefacts/defmon-static.bin \\
        --entrypoints trace/entrypoints.json \\
        --project-dir .ghidra-projects \\
        --out artefacts/ghidra
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

# Reuse the curated landmark list so 3a and 3b never drift.
from tools.re.emit_defmon_source import SEED_LANDMARKS

LOAD_BASE = 0x0000  # BinaryLoader places the 64K image at $0000
CODE_BASE = 0x0800  # defMON occupies $0800-$E786
CODE_END_EXCL = 0xE787

# Data segments derived from AGENTS.md "Phase 3b" instructions plus the
# in-memory layout from the SID#1/SID#2 RE notes. Each entry is
# (start, end_exclusive, name, comment, element_size).
#  element_size: 1 = byte array, 2 = word array (lo-hi pairs).
DATA_SEGMENTS: list[tuple[int, int, str, str, int]] = [
    (0x1800, 0x1900, "song_position_arrays_lo",
     "Decoder scratch (lo): $11 markers on disk; $CF42 rewrites to runtime "
     "pointers $5F00 + X*$0F. $1800..$1825 below LOAD dest_floor — those "
     "38 bytes are no-ops on real LOAD. Not sidTAB data (which is at $5F00).", 1),
    (0x1900, 0x1A00, "song_position_arrays_hi",
     "Decoder scratch (hi): paired with $1800; $CF42 transform target", 1),
    (0x1A00, 0x1A80, "pat_base_lo",
     "Pattern base address (lo byte) per pattern number; $80 bytes = 128 patterns", 1),
    (0x1A80, 0x1B00, "pat_base_hi",
     "Pattern base address (hi byte) per pattern number; pairs with pat_base_lo", 1),
    (0x1B00, 0x1C00, "arranger_v0_sid1",
     "SID#1 V0 arranger column: pat_num per song row (256 rows max)", 1),
    (0x1C00, 0x1D00, "arranger_v1_sid1",
     "SID#1 V1 arranger column", 1),
    (0x1D00, 0x1E00, "arranger_v2_sid1",
     "SID#1 V2 arranger column", 1),
    (0x1F00, 0x5F00, "pattern_bank",
     "Pattern data bank: per-pattern $80-byte block, indexed via pat_base_{lo,hi}; "
     "within a pattern, 4-byte step row = (flag, slot_a, slot_b, note). flag bits: "
     "7=ALT, 6=GATE_A, 5=GATE_B, 4=GATE_N (must be set to play note), 3-0=duration", 4),
    (0x5F00, 0x7167, "sidtab_data",
     "Real sidTAB row data: 15-byte rows ($0F stride) per sidcall index. "
     "Rows 0..255 occupy $5F00..$6DFF; rows 256..313 occupy $6E00..$7166 "
     "which also overlaps the SID#2 arrangers when stereo is enabled.", 1),
    (0x6E00, 0x6F00, "arranger_v3_sid2",
     "SID#2 V3 arranger column (visible only when chip view = SID#2); "
     "overlays sidtab_data rows 192..207 — stereo tunes can't use both", 1),
    (0x6F00, 0x7000, "arranger_v4_sid2",
     "SID#2 V4 arranger column; overlays sidtab_data rows 208..223", 1),
    (0x7000, 0x7100, "arranger_v5_sid2",
     "SID#2 V5 arranger column; overlays sidtab_data rows 224..239", 1),
    (0x729A, 0x72BA, "key_pitch_lut",
     "Key-byte to base pitch LUT; reader at $AEB3 for note dispatch", 1),
    (0xD000, 0xE000, "ram_under_io",
     "RAM under I/O: defMON runs with $01=$35 to access this RAM region; "
     "static image preserves the boot-time bytes", 1),
]

# Editor + player state variables worth labelling. (addr, name, comment).
# Comment may be omitted for entries that already live in CODE_BASE
# (where the surrounding listing context speaks for itself).
StateLabel = tuple  # tuple[int, str] or tuple[int, str, str]
STATE_LABELS: list[StateLabel] = [
    (0x0E39, "kbd_matrix_mirror", "Keyboard matrix mirror (8 bytes) written by $0E47 scan"),
    (0x0E41, "kbd_modifiers",
     "Modifier byte: $04=CTRL, $10=SHIFT, $20=CBM (combinations OR together)"),
    (0x0E42, "kbd_voice_mute", "Voice-mute toggles set by $0F32"),
    (0x0E44, "kbd_decoded_key", "Single-key decoder result (post $0F90,Y LUT)"),
    (0x7167, "ui_mode",
     "Current editor mode: $01=seqED, $02=seqLIST, $04=sidTAB, $20=disk"),
    (0x7168, "ui_mode_prev", "Previous mode (saved across sidTAB toggle)"),
    (0x715D, "stereo_enable", "$00=mono, $01=stereo (CTRL+SHIFT+BACKARROW)"),
    (0x7164, "sid2_base_lo", "SID#2 base address low byte"),
    (0x7165, "sid2_base_hi", "SID#2 base address high byte"),
    (0x7171, "sid_chip_view", "Current chip view: $00=SID#1, $01=SID#2"),
    (0x71C0, "super_cmd_flags", "Super-command prefix bitmask (CTRL+S/R/W/Z/G…)"),
    (0x71C1, "super_cmd_extra", "Super-command extra mask (cleared at field-write entry)"),
    (0x71CA, "writer_loop_count", "Field-writer iteration count"),
    (0x71CB, "writer_stride", "Inter-iteration stride for range-fill writers"),
    (0x71CC, "writer_range_fill", "Range-fill mode flag ($0C = active, $00 = single cell)"),
    (0x71CD, "voice_selector",
     "Voice selector × 9: V0=$00, V1=$09, V2=$12 (gates $1B/$1C/$1D arranger pick)"),
    (0x71CE, "page_offset", "Step-page offset within current pattern"),
    (0x71D1, "page_pair_counter", "Page-pair counter (used by writer auto-advance)"),
    (0x71D2, "step_cursor", "Step within current page"),
    (0x71D3, "octave_offset", "Octave offset added to note key dispatch ($AEB3)"),
    (0x716D, "digit_phase", "0/1 nibble phase for two-digit hex inputs"),
    (0x7286, "seqlist_col_cursor",
     "seqLIST column cursor (advances mod-N with CRSRLR)"),
    (0x7287, "seqed_col_cursor", "seqED column cursor (auto-advance counter)"),
    (0x7289, "seqlist_scroll", "seqLIST scroll bookkeeping (page-right adds $16)"),
    (0x7295, "sidtab_scroll", "sidTAB scroll bookkeeping (page step = 8)"),
    (0x844C, "field_writer_dispatcher",
     "Self-modifying dispatcher: (X,Y) operand becomes JSR $YX to per-field writer"),
    (0x8504, "field_writer_offset_smc",
     "SMC site for ADC #imm in dispatcher; encodes per-cell offset"),
    (0x8575, "field_writer_jsr_smc",
     "SMC site for the dispatched JSR target (X,Y operand)"),
    (0x092C, "main_loop"),
    (0x092F, "main_loop_postscan",
     "PC-injection target for harness/keyhandler.press_via_loop"),
    (0x00BA, "cbm_drive_num",
     "Active CBM device # — mutated by the $75DB disk-menu loop on bare "
     "PERIOD (INC, next) / bare COMMA (DEC, prev), wrap at $7629-$7637"),
    (0x7F00, "encoder_state_flag",
     "Encoder/save state — gates the $8244 SHIFT+X handler at $823F BNE"),
    (0x9EC5, "save_ui_saved_state",
     "Saved value backed up across the $7423 save-UI entry/exit"),
]

# Structured data types applied on top of the generic byte/word fill.
# Each entry in STRUCT_SEGMENTS is a segment-name → spec dict; matching
# DATA_SEGMENTS entries get their range cleared and replaced with the
# named struct array instead of bare ByteDataType/WordDataType units.
PATTERN_STEP_FIELDS: list[tuple[str, str]] = [
    ("flag",   "bit 7=ALT, 6=GATE_A, 5=GATE_B, 4=GATE_N (must be set to play "
               "the note), 3..0=dur nibble fed to the row timer"),
    ("slot_a", "sidCALL1: row index into sidtab_data (env slot A)"),
    ("slot_b", "sidCALL2: row index into sidtab_data (env slot B)"),
    ("note",   "note byte; pitch index into key_pitch_lut at $729A"),
]
PATTERN_STEPS_PER_PATTERN = 32  # $80 B / 4 B = 32 step rows per pattern
PATTERN_COUNT = 128             # $4000 B / $80 B = 128 patterns

# SidtabRow is 15 B per row, but the byte layout is bitmap-packed (see
# preframr.defmon.SidtabRow.parse). The ONLY fixed field is byte 0
# (`low_bitmap`), which marks which low-half columns carry an override
# in the packed stream; bytes 1..14 are decoded dynamically.
SIDTAB_ROW_FIELDS: list[tuple[str, str]] = [
    ("low_bitmap",
     "bit 7=WGl, 6=WGh, 5=AD, 4=SR, 3=TR, 2=AF, 1=PW — present-bitmap "
     "for low-half columns; subsequent bytes 1..N decode in column-bit "
     "order. high_bitmap lives at byte 1+N (variable position)."),
]
SIDTAB_ROW_SIZE = 15
SIDTAB_ROW_COUNT_CLEAN = 256  # rows 0..255 in $5F00..$6DFF (no arranger overlap)

STRUCT_SEGMENTS: dict[str, dict] = {
    "pattern_bank": {
        "step_struct": "PatternStep",
        "step_fields": PATTERN_STEP_FIELDS,
        "container_struct": "Pattern",
        "steps_per_container": PATTERN_STEPS_PER_PATTERN,
        "container_count": PATTERN_COUNT,
    },
    "sidtab_data": {
        "step_struct": "SidtabRow",
        "step_fields": SIDTAB_ROW_FIELDS,
        # No container nesting — sidtab is a flat row array.
        "row_size": SIDTAB_ROW_SIZE,
        "clean_row_count": SIDTAB_ROW_COUNT_CLEAN,
    },
}

# SMC-JSR dispatcher catalogue is loaded from annotations.toml at
# import time via `_load_smc_dispatch_annotations` — see the
# `[smc_dispatch."$XXXX"]` schema documented in the annotations file header.
# For each entry with `targets`, Ghidra gets COMPUTED_CALL refs from
# switch_pc to every target so the call graph + xref UI are correct.
# Sites with empty `targets` get auto-discovery + warn only.


PROCESSOR_LANGUAGE = "6502:LE:16:default"


def _start_pyghidra(install_dir: str) -> None:
    os.environ.setdefault("GHIDRA_INSTALL_DIR", install_dir)
    import pyghidra  # noqa: PLC0415
    pyghidra.start(verbose=False)


def _load_entrypoints(path: Path) -> set[int]:
    data = json.loads(path.read_text())
    out: set[int] = set()
    for entry in data.get("pcs", []):
        pc_field = entry["pc"] if isinstance(entry, dict) else entry
        out.add(int(pc_field, 16))
    return out


def _addr(api, value: int):
    return api.toAddr(value)


def _ensure_label(api, sym_table, addr_int: int, name: str,
                  source_type) -> bool:
    """Create or update a primary label at addr_int. Returns True if changed."""
    addr = _addr(api, addr_int)
    existing = sym_table.getPrimarySymbol(addr)
    if existing is not None and str(existing.getName()) == name:
        return False
    sym_table.createLabel(addr, name, source_type)
    return True


def _force_disassemble(api, addr_int: int) -> bool:
    """Best-effort disassemble at addr_int. Returns True if at least one
    instruction was created."""
    addr = _addr(api, addr_int)
    listing = api.getCurrentProgram().getListing()
    instr = listing.getInstructionAt(addr)
    if instr is not None:
        return False
    try:
        api.disassemble(addr)
    except Exception:
        return False
    return listing.getInstructionAt(addr) is not None


def _create_function(api, addr_int: int, name: str | None) -> bool:
    addr = _addr(api, addr_int)
    program = api.getCurrentProgram()
    fn_mgr = program.getFunctionManager()
    if fn_mgr.getFunctionAt(addr) is not None:
        return False
    try:
        api.createFunction(addr, name)
        return True
    except Exception:
        return False


# Memory-band annotations: addresses that get plate comments on the
# flat BinaryLoader block describing the runtime memory map. defMON
# runs with $00=$2F, $01=$35 (BASIC OFF, KERNAL OFF, I/O ON), so most
# of the 64K is RAM; only $D000-$DFFF is dual-natured. See
# `_annotate_memory_bands` for the placement helper.
MEMORY_BANDS: list[tuple[int, str]] = [
    (0x0000, "ZP + stack ($0000-$01FF). 6510 on-chip I/O at $0000/$0001\n"
             "(CPU_DDR / CPU_PORT). defMON sets $01=$35 at boot (no\n"
             "BASIC, no KERNAL, I/O visible at $D000-$DFFF)."),
    (0x0200, "Low RAM ($0200-$03FF). KERNAL ZP-workspace, indirect\n"
             "vectors at $0314 (IRQ) / $0316 (BRK) / $0318 (NMI)."),
    (0x0400, "Default screen RAM ($0400-$07FF, 1 KB). defMON paints\n"
             "the 25×40 grid here; sees video matrix via CIA2_PRA bits."),
    (0x0800, "defMON static image starts here ($0800-$E786). Body of\n"
             "the loaded program; SMC throughout — `setExecutable(true)`\n"
             "and `setWrite(true)` reflect both."),
    (0xD000, "RAM-under-I/O band ($D000-$DFFF). When $01=$35 (defMON's\n"
             "default): bytes here are RAM — the LOAD decoder at\n"
             "load_decoder_setup_chain lives in this region. Reads/\n"
             "writes to VIC/SID/CIA registers temporarily flip $01\n"
             "to $37 (KERNAL+I/O) around the access; not modelled\n"
             "by Ghidra's static block layout."),
    (0xE000, "Static image tail ($E000-$E786) — seqLIST writer band +\n"
             "post-LOAD reconstruction. Above this address: KERNAL ROM\n"
             "image in the static binary, mostly $FF."),
]


def _annotate_memory_bands(api) -> int:
    """Set R+W+X on the main block and plate-comment each MEMORY_BANDS
    address with the runtime memory-map note. Doesn't split the block —
    just labels it densely."""
    program = api.getCurrentProgram()
    memory = program.getMemory()
    main_block = None
    for block in memory.getBlocks():
        if block.contains(_addr(api, CODE_BASE)):
            main_block = block
            break
    if main_block is None:
        print("WARN: no block contains $0800; skipping band annotation")
        return 0
    # BinaryLoader defaults vary by Ghidra version. Make permissions
    # explicit: defMON freely self-modifies + the static image's whole
    # range is code-or-data depending on context.
    try:
        main_block.setRead(True)
        main_block.setWrite(True)
        main_block.setExecute(True)
        main_block.setVolatile(False)
    except Exception as exc:
        print(f"  setRead/Write/Execute on main block: "
              f"{type(exc).__name__}: {exc}")

    annotated = 0
    for addr_int, text in MEMORY_BANDS:
        try:
            api.setPlateComment(_addr(api, addr_int), text)
            annotated += 1
        except Exception as exc:
            print(f"  setPlateComment @ ${addr_int:04X}: "
                  f"{type(exc).__name__}: {exc}")
    return annotated


def _apply_jump_table_override(api, switch_pc: int, ref_type_name: str,
                               targets: list[int]) -> int:
    """Install computed-call/jump references at `switch_pc` to each
    target. Populates Ghidra's call-graph + xref database so the UI
    shows all possible targets under the switch instruction.

    **PCode JumpTable.writeOverride attempted + rolled back.** Ghidra's
    `JumpTable.writeOverride()` is for COMPUTED_JUMP (indirect JMP),
    NOT COMPUTED_CALL (indirect JSR). When applied to a JSR site like
    `$8575` the decompiler raises a silent exception and stops emitting
    output for the containing function entirely (`$84F5` decompile
    timed out / crashed for both 60s and 300s timeouts). So we install
    only the references — Ghidra UI sees all 22 targets, but the
    decompile output for the dispatcher stays as `*func_ptr()`. The
    6502 decompiler has no switch-synthesis path for indirect calls.

    Returns the number of refs added."""
    from ghidra.program.model.symbol import RefType, SourceType  # type: ignore

    ref_type = getattr(RefType, ref_type_name, None)
    if ref_type is None:
        print(f"WARN: unknown RefType {ref_type_name!r}; skipping")
        return 0

    program = api.getCurrentProgram()
    ref_mgr = program.getReferenceManager()
    from_addr = _addr(api, switch_pc)

    # Drop any prior memory refs at the operand position so re-runs
    # don't accumulate duplicates. The instruction's own fall-through
    # ref + label-name ref are untouched (different reference kinds).
    existing = ref_mgr.getReferencesFrom(from_addr, 0)
    for r in existing:
        if r.getReferenceType() in (RefType.COMPUTED_CALL, RefType.COMPUTED_JUMP):
            ref_mgr.delete(r)

    added = 0
    for tgt in targets:
        to_addr = _addr(api, tgt)
        try:
            ref_mgr.addMemoryReference(
                from_addr, to_addr, ref_type,
                SourceType.USER_DEFINED, 0)
            added += 1
        except Exception as exc:
            print(f"  jumptable ref ${switch_pc:04X} -> ${tgt:04X} "
                  f"failed: {type(exc).__name__}: {exc}")
    return added


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ANNOTATIONS_PATH = REPO_ROOT / "tools" / "re" / "annotations.toml"
CMP_FACTS_PATH = REPO_ROOT / "build" / "cmp_facts.json"


def _load_value_names_from_annotations(path: Path) -> dict[int, dict[int, str]]:
    """Parse `[region."$XXXX".value_names]` tables from annotations.toml.

    Returns {var_addr_int: {value_int: symbolic_name}}. Each region key
    is the address of the variable whose scalar values should be rendered
    as the named constants — e.g. `$7167` → `{$01: "UI_MODE_SEQED", ...}`.
    """
    import tomllib  # noqa: PLC0415
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text())
    regions = raw.get("region", {})
    out: dict[int, dict[int, str]] = {}
    for region_key, body in regions.items():
        vn = body.get("value_names") if isinstance(body, dict) else None
        if not isinstance(vn, dict):
            continue
        try:
            region_addr = int(region_key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        mapping: dict[int, str] = {}
        for k, v in vn.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            try:
                val_int = int(k.lstrip("$"), 16)
            except ValueError:
                continue
            mapping[val_int] = v
        if mapping:
            out[region_addr] = mapping
    return out


def _collect_equate_sites(cmp_facts_path: Path,
                          value_names: dict[int, dict[int, str]]
                          ) -> list[tuple[int, int, str]]:
    """Walk cmp_facts.json; for each `var ↔ imm` comparison whose var is
    a value_names region and whose imm matches an entry, return the
    (setter_pc, value, name) triple — the instruction at setter_pc is the
    immediate-bearing CMP/CPX/CPY whose operand 0 should get the equate.
    """
    if not cmp_facts_path.is_file():
        return []
    facts = (json.loads(cmp_facts_path.read_text()).get("facts") or {})
    out: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int]] = set()  # (setter_pc, value) dedup
    for _branch_pc, v in facts.items():
        lhs = v.get("lhs") or {}
        rhs = v.get("rhs") or {}
        fs = v.get("flag_setter") or {}
        if (lhs.get("kind") != "var" or rhs.get("kind") != "imm"
                or fs.get("mode") != "imm"):
            continue
        va = lhs.get("var_addr")
        if not isinstance(va, str):
            continue
        try:
            var_addr = int(va.lstrip("$"), 16)
        except ValueError:
            continue
        names = value_names.get(var_addr)
        if not names:
            continue
        try:
            imm = int(str(rhs.get("value", "")).lstrip("$"), 16)
            setter_pc = int(str(fs.get("pc", "")).lstrip("$"), 16)
        except ValueError:
            continue
        name = names.get(imm)
        if name is None:
            continue
        key = (setter_pc, imm)
        if key in seen:
            continue
        seen.add(key)
        out.append((setter_pc, imm, name))
    return out


def _apply_value_name_equates(api, sites: list[tuple[int, int, str]]) -> int:
    """Push each (setter_pc, value, name) site into Ghidra's EquateTable so
    the decompiler renders the symbolic name instead of the raw scalar.

    Operand index is always 0 for the CMP/CPX/CPY-immediate forms cmp_facts
    surfaces. Idempotent: re-running merges equates onto the existing
    entries (Ghidra dedups by name+value).
    """
    program = api.getCurrentProgram()
    eqt = program.getEquateTable()
    listing = program.getListing()
    added = 0
    skipped = 0
    for setter_pc, value, name in sites:
        addr = _addr(api, setter_pc)
        instr = listing.getInstructionAt(addr)
        if instr is None:
            skipped += 1
            continue
        # Validate operand 0 is a scalar matching `value` before pushing.
        scalars = instr.getOpObjects(0)
        if scalars is None or len(scalars) == 0:
            skipped += 1
            continue
        from ghidra.program.model.scalar import Scalar  # type: ignore
        scalar_match = any(
            isinstance(s, Scalar) and s.getUnsignedValue() == value
            for s in scalars
        )
        if not scalar_match:
            skipped += 1
            continue
        try:
            eq = eqt.getEquate(name)
            if eq is None:
                eq = eqt.createEquate(name, value)
            elif eq.getValue() != value:
                # Name collision with a different value — skip to avoid
                # silently rebinding an existing equate.
                skipped += 1
                continue
            eq.addReference(addr, 0)
            added += 1
        except Exception as exc:
            print(f"  equate {name}=${value:02X} @ ${setter_pc:04X} "
                  f"failed: {type(exc).__name__}: {exc}")
            skipped += 1
    if skipped:
        print(f"  equate sites skipped: {skipped}")
    return added


def _load_smc_dispatch_annotations(path: Path) -> dict[int, dict]:
    """Parse `[smc_dispatch."$XXXX"]` entries from annotations.toml.

    Returns {jsr_pc_int: {"description": str, "patch_sources": [int],
    "targets": [{"addr": int, "name": str, "context": str}]}}.
    """
    import tomllib  # noqa: PLC0415
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text())
    entries = raw.get("smc_dispatch", {})
    out: dict[int, dict] = {}
    for key, body in entries.items():
        if not isinstance(body, dict):
            continue
        try:
            pc = int(key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        patch_sources_raw = body.get("patch_sources") or []
        patch_sources: list[int] = []
        for ps in patch_sources_raw:
            if isinstance(ps, str):
                try:
                    patch_sources.append(int(ps.lstrip("$"), 16))
                except ValueError:
                    pass
        targets_raw = body.get("targets") or []
        targets: list[dict] = []
        for t in targets_raw:
            if not isinstance(t, dict):
                continue
            addr_s = t.get("addr")
            if not isinstance(addr_s, str):
                continue
            try:
                addr = int(addr_s.lstrip("$"), 16)
            except ValueError:
                continue
            targets.append({
                "addr": addr,
                "name": str(t.get("name", "")),
                "context": str(t.get("context", "")),
            })
        out[pc] = {
            "description": str(body.get("description", "")),
            "patch_sources": patch_sources,
            "targets": targets,
        }
    return out


_SMC_DISPATCH_MNEMS = ("JSR", "JMP")
_SMC_BRANCH_MNEMS = ("BCC", "BCS", "BEQ", "BNE", "BMI", "BPL", "BVC", "BVS")


def _load_smc_branch_annotations(path: Path) -> dict[int, dict]:
    """Parse `[smc_branch."$XXXX"]` entries from annotations.toml.

    Returns {branch_pc: {description, patch_sources}}. SMC-branch sites
    don't have enumerable target lists (the offset byte is one byte —
    the patcher can pick any of the 256 reachable PCs), so the schema
    is smaller than [smc_dispatch.]: just a description + patch sources.
    """
    import tomllib  # noqa: PLC0415
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text())
    out: dict[int, dict] = {}
    for key, body in (raw.get("smc_branch", {}) or {}).items():
        if not isinstance(body, dict):
            continue
        try:
            pc = int(key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        sources_raw = body.get("patch_sources") or []
        sources: list[int] = []
        for ps in sources_raw:
            if isinstance(ps, str):
                try:
                    sources.append(int(ps.lstrip("$"), 16))
                except ValueError:
                    pass
        out[pc] = {
            "description": str(body.get("description", "")),
            "patch_sources": sources,
        }
    return out


def _discover_smc_branch_sites(api) -> dict[int, list[int]]:
    """Walk every conditional branch in the static image; return
    {branch_pc: [patch_source_pcs]} for every branch whose offset byte
    ($+1) has any WRITE refs.

    The patcher rewrites the offset byte to choose a different landing
    PC at runtime — the static disassembly shows the unpatched-default
    target, which can be very misleading.
    """
    program = api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    out: dict[int, list[int]] = {}
    cu_iter = listing.getInstructions(_addr(api, CODE_BASE), True)
    while cu_iter.hasNext():
        ins = cu_iter.next()
        a = ins.getAddress()
        if int(a.getOffset()) >= CODE_END_EXCL:
            break
        if str(ins.getMnemonicString()) not in _SMC_BRANCH_MNEMS:
            continue
        pc = int(a.getOffset())
        refs_to = ref_mgr.getReferencesTo(_addr(api, pc + 1))
        writers = sorted({int(r.getFromAddress().getOffset())
                          for r in refs_to if r.getReferenceType().isWrite()})
        if writers:
            out[pc] = writers
    return out


def _export_smc_branch(out_path: Path,
                       annotated: dict[int, dict],
                       discovered: dict[int, list[int]]) -> None:
    """Write artefacts/ghidra/smc_branch.json — merged view consumed by
    the emitter to render comment headers above SMC-patched branches."""
    merged: dict[str, dict] = {}
    for pc in sorted(set(annotated) | set(discovered)):
        ann = annotated.get(pc) or {}
        disc = discovered.get(pc) or []
        merged[f"${pc:04X}"] = {
            "branch_pc": pc,
            "description": ann.get("description", ""),
            "patch_sources_annotated": ann.get("patch_sources") or [],
            "patch_sources_discovered": disc,
            "annotated": pc in annotated,
            "discovered": pc in discovered,
        }
    out_path.write_text(json.dumps(merged, indent=2) + "\n")


# 6502 opcode → mnemonic table. Sparse — only entries for documented
# opcodes (the gaps are illegal/undocumented bytes). A byte that doesn't
# appear here is NOT a valid opcode, so a writer storing it indicates
# a likely false-positive opcode-flip candidate (the byte is being
# treated as data, not as a replacement instruction).
OPCODE_MNEMONICS: dict[int, str] = {
    0x00: "BRK", 0x01: "ORA", 0x05: "ORA", 0x06: "ASL", 0x08: "PHP",
    0x09: "ORA", 0x0A: "ASL", 0x0D: "ORA", 0x0E: "ASL",
    0x10: "BPL", 0x11: "ORA", 0x15: "ORA", 0x16: "ASL", 0x18: "CLC",
    0x19: "ORA", 0x1D: "ORA", 0x1E: "ASL",
    0x20: "JSR", 0x21: "AND", 0x24: "BIT", 0x25: "AND", 0x26: "ROL",
    0x28: "PLP", 0x29: "AND", 0x2A: "ROL", 0x2C: "BIT", 0x2D: "AND", 0x2E: "ROL",
    0x30: "BMI", 0x31: "AND", 0x35: "AND", 0x36: "ROL", 0x38: "SEC",
    0x39: "AND", 0x3D: "AND", 0x3E: "ROL",
    0x40: "RTI", 0x41: "EOR", 0x45: "EOR", 0x46: "LSR", 0x48: "PHA",
    0x49: "EOR", 0x4A: "LSR", 0x4C: "JMP", 0x4D: "EOR", 0x4E: "LSR",
    0x50: "BVC", 0x51: "EOR", 0x55: "EOR", 0x56: "LSR", 0x58: "CLI",
    0x59: "EOR", 0x5D: "EOR", 0x5E: "LSR",
    0x60: "RTS", 0x61: "ADC", 0x65: "ADC", 0x66: "ROR", 0x68: "PLA",
    0x69: "ADC", 0x6A: "ROR", 0x6C: "JMP", 0x6D: "ADC", 0x6E: "ROR",
    0x70: "BVS", 0x71: "ADC", 0x75: "ADC", 0x76: "ROR", 0x78: "SEI",
    0x79: "ADC", 0x7D: "ADC", 0x7E: "ROR",
    0x81: "STA", 0x84: "STY", 0x85: "STA", 0x86: "STX", 0x88: "DEY",
    0x8A: "TXA", 0x8C: "STY", 0x8D: "STA", 0x8E: "STX",
    0x90: "BCC", 0x91: "STA", 0x94: "STY", 0x95: "STA", 0x96: "STX",
    0x98: "TYA", 0x99: "STA", 0x9A: "TXS", 0x9D: "STA",
    0xA0: "LDY", 0xA1: "LDA", 0xA2: "LDX", 0xA4: "LDY", 0xA5: "LDA",
    0xA6: "LDX", 0xA8: "TAY", 0xA9: "LDA", 0xAA: "TAX", 0xAC: "LDY",
    0xAD: "LDA", 0xAE: "LDX",
    0xB0: "BCS", 0xB1: "LDA", 0xB4: "LDY", 0xB5: "LDA", 0xB6: "LDX",
    0xB8: "CLV", 0xB9: "LDA", 0xBA: "TSX", 0xBC: "LDY", 0xBD: "LDA", 0xBE: "LDX",
    0xC0: "CPY", 0xC1: "CMP", 0xC4: "CPY", 0xC5: "CMP", 0xC6: "DEC",
    0xC8: "INY", 0xC9: "CMP", 0xCA: "DEX", 0xCC: "CPY", 0xCD: "CMP", 0xCE: "DEC",
    0xD0: "BNE", 0xD1: "CMP", 0xD5: "CMP", 0xD6: "DEC", 0xD8: "CLD",
    0xD9: "CMP", 0xDD: "CMP", 0xDE: "DEC",
    0xE0: "CPX", 0xE1: "SBC", 0xE4: "CPX", 0xE5: "SBC", 0xE6: "INC",
    0xE8: "INX", 0xE9: "SBC", 0xEA: "NOP", 0xEC: "CPX", 0xED: "SBC", 0xEE: "INC",
    0xF0: "BEQ", 0xF1: "SBC", 0xF5: "SBC", 0xF6: "INC", 0xF8: "SED",
    0xF9: "SBC", 0xFD: "SBC", 0xFE: "INC",
}


def _load_smc_opcode_annotations(path: Path) -> dict[int, dict]:
    """Parse `[smc_opcode."$XXXX"]` entries.

    Returns {host_pc: {description, patch_sources, candidate_opcodes}}.
    `candidate_opcodes` is an optional curator-supplied list — if blank,
    the discovery pass fills it in via writer-value tracing.
    """
    import tomllib  # noqa: PLC0415
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text())
    out: dict[int, dict] = {}
    for key, body in (raw.get("smc_opcode", {}) or {}).items():
        if not isinstance(body, dict):
            continue
        try:
            pc = int(key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        sources_raw = body.get("patch_sources") or []
        sources: list[int] = []
        for ps in sources_raw:
            if isinstance(ps, str):
                try:
                    sources.append(int(ps.lstrip("$"), 16))
                except ValueError:
                    pass
        candidates_raw = body.get("candidate_opcodes") or []
        candidates = [c for c in candidates_raw if isinstance(c, str)]
        # Optional structured JMP/branch targets (same shape as
        # [smc_dispatch].targets) for sites whose flip is to a JMP — keeps
        # the landing address out of the free-text description.
        targets_raw = body.get("targets") or []
        targets: list[dict] = []
        for t in targets_raw:
            if not isinstance(t, dict) or not isinstance(t.get("addr"), str):
                continue
            try:
                taddr = int(t["addr"].lstrip("$"), 16)
            except ValueError:
                continue
            targets.append({
                "addr": taddr,
                "name": str(t.get("name", "")),
                "context": str(t.get("context", "")),
            })
        out[pc] = {
            "description": str(body.get("description", "")),
            "patch_sources": sources,
            "candidate_opcodes": candidates,
            "targets": targets,
        }
    return out


def _trace_writer_imm_value(listing, api, writer_pc: int,
                            max_back: int = 8) -> int | None:
    """Best-effort trace: starting at writer_pc, look backwards up to
    `max_back` bytes for an `LDA/LDX/LDY #imm` and return the imm value.

    Returns None if the trace is inconclusive (writer reads from a
    register/memory we can't follow without full data-flow analysis).
    """
    from ghidra.program.model.scalar import Scalar  # type: ignore
    for back in range(2, max_back):
        prev = listing.getInstructionAt(_addr(api, writer_pc - back))
        if prev is None:
            continue
        mnem = str(prev.getMnemonicString())
        if mnem in ("LDA", "LDX", "LDY"):
            scalars = prev.getOpObjects(0)
            for o in (scalars or []):
                if isinstance(o, Scalar):
                    return int(o.getUnsignedValue()) & 0xFF
            return None
        # Anything else terminates the trace — we hit a non-load
        # instruction before finding our immediate.
        return None
    return None


def _discover_smc_opcode_sites(api) -> dict[int, dict]:
    """Walk every instruction; for each whose OPCODE byte (pc+0) has
    a WRITE ref, trace the writer's source value. Returns
    {host_pc: {writers, current_mnem, candidate_mnems, inconclusive}}.

    `candidate_mnems` is the set of valid 6502 mnemonics the byte could
    flip to (writer's traced source value mapped through OPCODE_MNEMONICS,
    excluding the current opcode). `inconclusive` is True when no
    candidate could be traced — likely either a register-sourced writer
    or a data-overlay false positive.
    """
    program = api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    mem = program.getMemory()
    out: dict[int, dict] = {}
    cu_iter = listing.getInstructions(_addr(api, CODE_BASE), True)
    while cu_iter.hasNext():
        ins = cu_iter.next()
        pc = int(ins.getAddress().getOffset())
        if pc >= CODE_END_EXCL:
            break
        refs_to = ref_mgr.getReferencesTo(_addr(api, pc))
        writers = sorted({int(r.getFromAddress().getOffset())
                          for r in refs_to if r.getReferenceType().isWrite()})
        if not writers:
            continue
        cur_opcode = mem.getByte(_addr(api, pc)) & 0xFF
        cur_mnem = OPCODE_MNEMONICS.get(cur_opcode, f"??{cur_opcode:02X}")
        candidate_mnems: set[str] = set()
        for w_pc in writers:
            val = _trace_writer_imm_value(listing, api, w_pc)
            if val is None or val == cur_opcode:
                continue
            new_mnem = OPCODE_MNEMONICS.get(val)
            if new_mnem and new_mnem != cur_mnem:
                candidate_mnems.add(new_mnem)
        out[pc] = {
            "writers": writers,
            "current_mnem": cur_mnem,
            "candidate_mnems": sorted(candidate_mnems),
            "inconclusive": not candidate_mnems,
        }
    return out


def _export_smc_opcode(out_path: Path,
                       annotated: dict[int, dict],
                       discovered: dict[int, dict]) -> None:
    """Write artefacts/ghidra/smc_opcode.json — emitter consumes this
    to render headers above SMC-flipped opcode sites."""
    merged: dict[str, dict] = {}
    for pc in sorted(set(annotated) | set(discovered)):
        ann = annotated.get(pc) or {}
        disc = discovered.get(pc) or {}
        merged[f"${pc:04X}"] = {
            "host_pc": pc,
            "description": ann.get("description", ""),
            "patch_sources_annotated": ann.get("patch_sources") or [],
            "patch_sources_discovered": disc.get("writers") or [],
            "current_mnem": disc.get("current_mnem", ""),
            "candidate_opcodes_annotated": ann.get("candidate_opcodes") or [],
            "candidate_opcodes_discovered": disc.get("candidate_mnems") or [],
            "targets": [
                {"addr": f"${t['addr']:04X}", "name": t["name"],
                 "context": t["context"]}
                for t in (ann.get("targets") or [])
            ],
            "inconclusive": disc.get("inconclusive", False),
            "annotated": pc in annotated,
            "discovered": pc in discovered,
        }
    out_path.write_text(json.dumps(merged, indent=2) + "\n")


def _discover_smc_dispatch_sites(api) -> dict[int, list[int]]:
    """Walk every JSR/JMP in the static image; return
    {dispatch_pc: [patch_source_pcs]} for every site whose operand
    bytes ($+1 / $+2) have any WRITE refs.

    This is the structural definition of a "SMC-patched dispatcher" —
    some other instruction stores into the operand bytes, so the call
    or jump target is chosen at runtime. Covers both JSR (indirect
    function dispatch) and JMP (indirect tail-call / continuation).
    Surfaces undocumented dispatchers for the user to catalogue in
    annotations.toml as [smc_dispatch.] entries.
    """
    program = api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    out: dict[int, list[int]] = {}
    cu_iter = listing.getInstructions(_addr(api, CODE_BASE), True)
    while cu_iter.hasNext():
        ins = cu_iter.next()
        a = ins.getAddress()
        if int(a.getOffset()) >= CODE_END_EXCL:
            break
        if str(ins.getMnemonicString()) not in _SMC_DISPATCH_MNEMS:
            continue
        pc = int(a.getOffset())
        writers: set[int] = set()
        for op_off in (1, 2):
            refs_to = ref_mgr.getReferencesTo(_addr(api, pc + op_off))
            for r in refs_to:
                if r.getReferenceType().isWrite():
                    writers.add(int(r.getFromAddress().getOffset()))
        if writers:
            out[pc] = sorted(writers)
    return out


def _export_smc_dispatch(out_path: Path,
                    annotated: dict[int, dict],
                    discovered: dict[int, list[int]]) -> None:
    """Write artefacts/ghidra/smc_dispatch.json: merged view of annotated
    sites + auto-discovered sites for the emitter to consume.

    Schema:
      { "$XXXX": {"jsr_pc": int, "patch_sources_annotated": [int],
                  "patch_sources_discovered": [int], "description": str,
                  "targets": [...], "annotated": bool, "discovered": bool} }
    """
    merged: dict[str, dict] = {}
    for pc in sorted(set(annotated) | set(discovered)):
        ann = annotated.get(pc) or {}
        disc = discovered.get(pc) or []
        merged[f"${pc:04X}"] = {
            "jsr_pc": pc,
            "description": ann.get("description", ""),
            "patch_sources_annotated": ann.get("patch_sources") or [],
            "patch_sources_discovered": disc,
            "targets": ann.get("targets") or [],
            "annotated": pc in annotated,
            "discovered": pc in discovered,
        }
    out_path.write_text(json.dumps(merged, indent=2) + "\n")


def _load_function_and_region_annotations(path: Path) -> dict[int, dict]:
    """Parse all [function."$XXXX"] and [region."$XXXX"] tables.

    Returns {addr_int: {kind, name, role, notes, inputs, outputs,
    callers}}. Used by the annotation-comment push to seed Ghidra plate
    comments and the state-variable type push.
    """
    import tomllib  # noqa: PLC0415
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text())
    out: dict[int, dict] = {}
    for kind in ("function", "region"):
        for key, body in (raw.get(kind, {}) or {}).items():
            if not isinstance(body, dict):
                continue
            try:
                addr = int(key.lstrip("$"), 16)
            except (AttributeError, ValueError):
                continue
            out[addr] = {
                "kind": kind,
                "name": body.get("name"),
                "role": body.get("role"),
                "notes": body.get("notes"),
                "inputs": body.get("inputs"),
                "outputs": body.get("outputs"),
                "callers": body.get("callers"),
            }
    return out


def _build_plate_text(entry: dict) -> str:
    """Compose a multi-line plate comment from a function/region entry.

    Format:
        <name> — <role>

        <notes>

        Inputs:   <inputs>
        Outputs:  <outputs>
        Callers:  <callers>

    Empty sections are omitted. Lines are not hard-wrapped — Ghidra's
    plate-comment renderer wraps to the listing width automatically.
    """
    name = (entry.get("name") or "").strip()
    role = (entry.get("role") or "").strip()
    notes = (entry.get("notes") or "").strip()
    inputs = (entry.get("inputs") or "").strip()
    outputs = (entry.get("outputs") or "").strip()
    callers = (entry.get("callers") or "").strip()

    parts: list[str] = []
    if name and role:
        parts.append(f"{name} — {role}")
    elif role:
        parts.append(role)
    elif name:
        parts.append(name)
    if notes:
        parts.append("")
        parts.append(notes)
    extras = []
    if inputs:
        extras.append(f"Inputs:   {inputs}")
    if outputs:
        extras.append(f"Outputs:  {outputs}")
    if callers:
        extras.append(f"Callers:  {callers}")
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def _push_annotation_comments(api, annotations: dict[int, dict]) -> int:
    """Set a plate comment at every annotated address with the composed
    role+notes+inputs+outputs+callers block. Idempotent: re-running
    overwrites with the latest content."""
    program = api.getCurrentProgram()
    listing = program.getListing()
    pushed = 0
    for addr_int, entry in annotations.items():
        text = _build_plate_text(entry)
        if not text:
            continue
        try:
            listing.setComment(_addr(api, addr_int), 3, text)  # 3 = PLATE
            pushed += 1
        except Exception as exc:
            print(f"  plate comment @ ${addr_int:04X}: "
                  f"{type(exc).__name__}: {exc}")
    return pushed


def _apply_state_var_types(api, annotations: dict[int, dict],
                           data_segments: list[tuple[int, int, str, str, int]]
                           ) -> int:
    """Apply ByteDataType + label at each [region."$XXXX"] address that
    sits OUTSIDE the typed data segments (pattern_bank / sidtab_data
    have their own struct layouts). Result: decompile renders the
    symbolic name (`ui_mode`) instead of `bRAM7167` temporaries.

    Skips addresses currently disassembled as instructions — applying
    data to part of an instruction would clobber it. Skips addresses
    already typed (idempotent).
    """
    from ghidra.program.model.data import ByteDataType  # type: ignore
    program = api.getCurrentProgram()
    listing = program.getListing()
    # Build a fast "is this addr inside a data segment?" check.
    seg_ranges = [(s, e) for s, e, _n, _c, _es in data_segments]

    def _in_data_segment(a: int) -> bool:
        for s, e in seg_ranges:
            if s <= a < e:
                return True
        return False

    applied = 0
    skipped_instr = 0
    skipped_seg = 0
    skipped_typed = 0
    for addr_int, entry in annotations.items():
        if entry.get("kind") != "region":
            continue
        if not entry.get("name"):
            continue
        if _in_data_segment(addr_int):
            skipped_seg += 1
            continue
        addr = _addr(api, addr_int)
        if listing.getInstructionAt(addr) is not None:
            skipped_instr += 1
            continue
        existing = listing.getDefinedDataAt(addr)
        if existing is not None and not str(existing.getDataType().getName()).startswith("undefined"):
            skipped_typed += 1
            continue
        try:
            # `createData` errors with "Data conflict" if any code unit
            # already exists at the address — even `undefined1` (the
            # default for uninitialised RAM). Clear first so the apply
            # always succeeds; idempotent (the next run sees `byte` and
            # short-circuits via the `skipped_typed` check above).
            listing.clearCodeUnits(addr, addr, False)
            api.createData(addr, ByteDataType())
            applied += 1
        except Exception as exc:
            print(f"  state-var type @ ${addr_int:04X}: "
                  f"{type(exc).__name__}: {exc}")
    if skipped_seg:
        print(f"  state-var sites skipped (inside data segment): {skipped_seg}")
    if skipped_instr:
        print(f"  state-var sites skipped (inside instruction): {skipped_instr}")
    if skipped_typed:
        print(f"  state-var sites skipped (already typed): {skipped_typed}")
    return applied


def _load_function_signatures(path: Path) -> dict[int, str]:
    """Parse `[function."$XXXX"].signature` strings from annotations.toml.

    Returns {entry_pc_int: signature_string}. The signature uses C-like
    syntax with the 6502 .cspec mapping (arg1→A, arg2→X, arg3→Y, ret→A)
    — see `Ghidra/Processors/6502/data/languages/6502.cspec`. Functions
    that take their inputs from memory globals rather than registers
    should be `void fn(void)` — Ghidra will infer the global reads on
    its own. Functions that return via X or Y can't be expressed in the
    default cspec; signature stays `void` and the prose `outputs:` field
    documents the real return register.
    """
    import tomllib  # noqa: PLC0415
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text())
    fns = raw.get("function", {})
    out: dict[int, str] = {}
    for fn_key, body in fns.items():
        if not isinstance(body, dict):
            continue
        sig = body.get("signature")
        if not isinstance(sig, str) or not sig.strip():
            continue
        try:
            pc = int(fn_key.lstrip("$"), 16)
        except (AttributeError, ValueError):
            continue
        out[pc] = sig.strip()
    return out


def _apply_function_signatures(api, sigs: dict[int, str]) -> int:
    """Parse each signature via Ghidra's CParser and apply via
    `ApplyFunctionSignatureCmd`. Returns count of signatures applied.

    Skips entries whose PC has no function (caller is responsible for
    promoting landmarks to functions first). Re-applying the same
    signature is a no-op — `ApplyFunctionSignatureCmd` dedups via
    `SourceType`."""
    program = api.getCurrentProgram()
    fn_mgr = program.getFunctionManager()
    dtm = program.getDataTypeManager()
    from ghidra.app.util.cparser.C import CParser  # type: ignore
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    parser = CParser(dtm)
    applied = 0
    created_fn = 0
    parse_failed = 0
    import re as _re  # noqa: PLC0415
    name_re = _re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    for pc, sig in sigs.items():
        addr = _addr(api, pc)
        fn = fn_mgr.getFunctionAt(addr)
        if fn is None:
            # Pull the function name out of the signature and create.
            # Annotations point at fall-through helpers Ghidra didn't
            # promote (only reached via BEQ→JMP, not JSR).
            m = name_re.search(sig)
            fname = m.group(1) if m else None
            if fname and _create_function(api, pc, fname):
                created_fn += 1
                fn = fn_mgr.getFunctionAt(addr)
            if fn is None:
                print(f"  signature site ${pc:04X}: could not create function")
                continue
        # CParser wants a trailing semicolon for declarations.
        text = sig if sig.rstrip().endswith(";") else (sig + ";")
        try:
            fn_def = parser.parse(text)
        except Exception as exc:
            print(f"  signature parse failed for ${pc:04X} {sig!r}: "
                  f"{type(exc).__name__}: {exc}")
            parse_failed += 1
            continue
        try:
            cmd = ApplyFunctionSignatureCmd(
                addr, fn_def, SourceType.USER_DEFINED)
            if cmd.applyTo(program):
                applied += 1
            else:
                print(f"  signature apply failed for ${pc:04X}: "
                      f"{cmd.getStatusMsg()}")
        except Exception as exc:
            print(f"  signature apply raised for ${pc:04X}: "
                  f"{type(exc).__name__}: {exc}")
    if created_fn:
        print(f"  signature sites that promoted to function: {created_fn}")
    if parse_failed:
        print(f"  signature sites skipped (parse failed): {parse_failed}")
    return applied


def _build_pattern_dts(api):
    """Define (or replace) PatternStep + Pattern data types in the
    program's DataTypeManager and return (pattern_dt, step_dt). Both are
    namespaced under the `/defMON` category so re-runs don't pollute
    the root namespace."""
    from ghidra.program.model.data import (  # type: ignore
        ArrayDataType, ByteDataType, CategoryPath,
        DataTypeConflictHandler, StructureDataType,
    )
    program = api.getCurrentProgram()
    dtm = program.getDataTypeManager()
    cat = CategoryPath("/defMON")

    step = StructureDataType(cat, "PatternStep", 0)
    for fname, fcomment in PATTERN_STEP_FIELDS:
        step.add(ByteDataType(), 1, fname, fcomment)
    step_dt = dtm.addDataType(step, DataTypeConflictHandler.REPLACE_HANDLER)

    pattern = StructureDataType(cat, "Pattern", 0)
    steps_array = ArrayDataType(step_dt, PATTERN_STEPS_PER_PATTERN,
                                step_dt.getLength())
    pattern.add(
        steps_array, "steps",
        f"{PATTERN_STEPS_PER_PATTERN} step rows "
        f"($80 B = {PATTERN_STEPS_PER_PATTERN} × PatternStep)",
    )
    pattern_dt = dtm.addDataType(pattern, DataTypeConflictHandler.REPLACE_HANDLER)
    return pattern_dt, step_dt


def _apply_pattern_bank_struct(api, start: int, end_excl: int) -> tuple[int, dict]:
    """Place a `Pattern[PATTERN_COUNT]` array over [start, end_excl).
    Returns (PatternStep instances placed, export metadata). Refuses
    (returns (0, {})) if any instruction sits inside the range."""
    from ghidra.program.model.data import ArrayDataType  # type: ignore

    pattern_dt, step_dt = _build_pattern_dts(api)
    expected = pattern_dt.getLength() * PATTERN_COUNT
    actual = end_excl - start
    if actual != expected:
        raise SystemExit(
            f"pattern_bank size mismatch: segment is {actual} B but "
            f"Pattern[{PATTERN_COUNT}] = {expected} B")

    program = api.getCurrentProgram()
    listing = program.getListing()
    addr_start = _addr(api, start)
    addr_end = _addr(api, end_excl - 1)

    # Clear any DATA in the range so the array can sit cleanly; refuse
    # to touch instructions. Prior idempotent runs may have left
    # ByteDataType / WordDataType units placed by `_mark_data_segment`.
    cu_iter = listing.getCodeUnits(addr_start, True)
    to_clear: list = []
    blockers = 0
    while cu_iter.hasNext():
        cu = cu_iter.next()
        a = cu.getAddress()
        if a.compareTo(addr_end) > 0:
            break
        if listing.getInstructionAt(a) is not None:
            blockers += 1
            continue
        if listing.getDefinedDataAt(a) is not None:
            to_clear.append(a)
    if blockers:
        print(f"pattern_bank: WARN — {blockers} instructions inside "
              f"${start:04X}..${end_excl - 1:04X}; struct not applied")
        return 0, {}
    for a in to_clear:
        try:
            listing.clearCodeUnits(a, a, False)
        except Exception:
            pass

    arr_dt = ArrayDataType(pattern_dt, PATTERN_COUNT, pattern_dt.getLength())
    try:
        listing.createData(addr_start, arr_dt)
    except Exception as exc:
        print(f"pattern_bank: createData failed: "
              f"{type(exc).__name__}: {exc}")
        return 0, {}

    meta = {
        "container": {
            "name": "Pattern",
            "size": pattern_dt.getLength(),
            "element_count": PATTERN_COUNT,
        },
        "element": {
            "name": "PatternStep",
            "size": step_dt.getLength(),
            "count_per_container": PATTERN_STEPS_PER_PATTERN,
            "fields": [
                {"name": fname, "offset": idx, "size": 1, "comment": fcomment}
                for idx, (fname, fcomment) in enumerate(PATTERN_STEP_FIELDS)
            ],
        },
    }
    placed = PATTERN_COUNT * PATTERN_STEPS_PER_PATTERN
    return placed, meta


def _build_sidtab_row_dt(api):
    """Define (or replace) the SidtabRow data type. Single fixed field
    `low_bitmap` at offset 0; bytes 1..14 are a raw byte array (their
    semantics depend on low_bitmap + a later high_bitmap, see
    preframr.defmon.SidtabRow.parse)."""
    from ghidra.program.model.data import (  # type: ignore
        ArrayDataType, ByteDataType, CategoryPath,
        DataTypeConflictHandler, StructureDataType,
    )
    program = api.getCurrentProgram()
    dtm = program.getDataTypeManager()
    cat = CategoryPath("/defMON")

    row = StructureDataType(cat, "SidtabRow", 0)
    for fname, fcomment in SIDTAB_ROW_FIELDS:
        row.add(ByteDataType(), 1, fname, fcomment)
    remaining = SIDTAB_ROW_SIZE - len(SIDTAB_ROW_FIELDS)
    if remaining > 0:
        row.add(ArrayDataType(ByteDataType(), remaining, 1), "packed_columns",
                "Bitmap-decoded payload: low values (in bit-order WGh, WGl, "
                "AD, SR, TR, AF, PW), then high_bitmap, then high values "
                "(PS, RE, FV, CP, ACID — last is 2 B), then zero pad.")
    return dtm.addDataType(row, DataTypeConflictHandler.REPLACE_HANDLER)


def _apply_sidtab_data_struct(api, start: int, end_excl: int) -> tuple[int, dict]:
    """Place a `SidtabRow[256]` array at start. Covers rows 0..255 in
    $5F00..$6DFF (3840 B) — clean lower portion with no arranger
    overlap. Bytes from $6E00 onward (where stereo overlays SID#2
    arrangers v3/v4/v5) are left for the generic byte fill that the
    arranger DATA_SEGMENTS entries will place."""
    from ghidra.program.model.data import ArrayDataType  # type: ignore

    row_dt = _build_sidtab_row_dt(api)
    array_bytes = SIDTAB_ROW_COUNT_CLEAN * row_dt.getLength()
    if start + array_bytes > end_excl:
        raise SystemExit(
            f"sidtab_data clean portion ({array_bytes} B) exceeds segment "
            f"({end_excl - start} B)")

    program = api.getCurrentProgram()
    listing = program.getListing()
    addr_start = _addr(api, start)
    array_end = start + array_bytes - 1
    addr_array_end = _addr(api, array_end)

    cu_iter = listing.getCodeUnits(addr_start, True)
    to_clear: list = []
    blockers = 0
    while cu_iter.hasNext():
        cu = cu_iter.next()
        a = cu.getAddress()
        if a.compareTo(addr_array_end) > 0:
            break
        if listing.getInstructionAt(a) is not None:
            blockers += 1
            continue
        if listing.getDefinedDataAt(a) is not None:
            to_clear.append(a)
    if blockers:
        print(f"sidtab_data: WARN — {blockers} instructions inside "
              f"${start:04X}..${array_end:04X}; struct not applied")
        return 0, {}
    for a in to_clear:
        try:
            listing.clearCodeUnits(a, a, False)
        except Exception:
            pass

    arr_dt = ArrayDataType(row_dt, SIDTAB_ROW_COUNT_CLEAN, row_dt.getLength())
    try:
        listing.createData(addr_start, arr_dt)
    except Exception as exc:
        print(f"sidtab_data: createData failed: "
              f"{type(exc).__name__}: {exc}")
        return 0, {}

    meta = {
        # No container: sidtab is a flat row array. Emitter side
        # interprets missing `container` as one-level (element only).
        "element": {
            "name": "SidtabRow",
            "size": row_dt.getLength(),
            "fields": [
                {"name": fname, "offset": idx, "size": 1, "comment": fcomment}
                for idx, (fname, fcomment) in enumerate(SIDTAB_ROW_FIELDS)
            ],
        },
    }
    return SIDTAB_ROW_COUNT_CLEAN, meta


def _mark_data_segment(api, start: int, end_excl: int, element_size: int) -> int:
    """Mark [start, end_excl) as a homogeneous data array. Returns the
    number of elements actually marked. Skips elements that overlap an
    existing instruction (those are real code that the seg-table mis-
    classified — leave them alone)."""
    program = api.getCurrentProgram()
    listing = program.getListing()
    from ghidra.program.model.data import (  # type: ignore
        ByteDataType, WordDataType,
    )
    dt = ByteDataType() if element_size == 1 else WordDataType()
    created = 0
    addr_set_start = _addr(api, start)
    addr_set_end = _addr(api, end_excl - 1)
    # First sweep: clear any conflicting partial code-units inside our
    # range. We only clear DATA, never instructions.
    cu_iter = listing.getCodeUnits(addr_set_start, True)
    to_clear = []
    while cu_iter.hasNext():
        cu = cu_iter.next()
        a = cu.getAddress()
        if a.compareTo(addr_set_end) > 0:
            break
        # Don't touch instructions.
        if listing.getInstructionAt(a) is not None:
            continue
        # If it's already the right datatype, skip.
        defined = listing.getDefinedDataAt(a)
        if defined is not None and str(defined.getDataType().getName()) == str(dt.getName()):
            continue
        to_clear.append(a)
    for a in to_clear:
        try:
            listing.clearCodeUnits(a, a, False)
        except Exception:
            pass
    # Second sweep: place the data type at each element position.
    pos = start
    while pos < end_excl:
        addr = _addr(api, pos)
        if listing.getInstructionAt(addr) is not None:
            # Don't overwrite real instructions, even if SEG-table thought
            # this was data. emit_defmon_source.py handles overlaps the
            # same way.
            pos += 1
            continue
        try:
            listing.createData(addr, dt)
            created += 1
        except Exception:
            pass
        pos += element_size
    return created


def _decompile_functions(api, out_dir: Path, max_functions: int) -> int:
    """Best-effort decompile every function. 6502 decompiler output is
    rough but useful as a starting point for pass-2 annotations."""
    from ghidra.app.decompiler import DecompInterface  # type: ignore
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

    program = api.getCurrentProgram()
    fn_mgr = program.getFunctionManager()
    iface = DecompInterface()
    iface.openProgram(program)
    monitor = ConsoleTaskMonitor()
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for fn in fn_mgr.getFunctions(True):
        if written >= max_functions:
            break
        try:
            res = iface.decompileFunction(fn, 60, monitor)
        except Exception:
            continue
        if res is None or not res.decompileCompleted():
            continue
        c_text = res.getDecompiledFunction().getC()
        if not c_text:
            continue
        addr_int = int(fn.getEntryPoint().getOffset())
        path = out_dir / f"{addr_int:04x}_{fn.getName()}.c"
        try:
            path.write_text(str(c_text))
            written += 1
        except Exception:
            pass
    iface.dispose()
    return written


def _export_symbols(api, out_path: Path) -> int:
    program = api.getCurrentProgram()
    sym_table = program.getSymbolTable()
    rows: list[dict] = []
    for sym in sym_table.getAllSymbols(True):
        name = str(sym.getName())
        addr = int(sym.getAddress().getOffset())
        if not (LOAD_BASE <= addr <= 0xFFFF):
            continue
        rows.append({
            "addr": f"${addr:04X}",
            "name": name,
            "source": str(sym.getSource()),
            "is_primary": bool(sym.isPrimary()),
        })
    rows.sort(key=lambda r: (int(r["addr"][1:], 16), r["name"]))
    out_path.write_text(json.dumps({"symbols": rows}, indent=2))
    return len(rows)


def _export_segments(api, out_path: Path,
                     struct_meta: dict[str, dict] | None = None) -> int:
    program = api.getCurrentProgram()
    listing = program.getListing()
    struct_meta = struct_meta or {}
    rows: list[dict] = []
    for start, end_excl, name, comment, element_size in DATA_SEGMENTS:
        defined = 0
        addr = _addr(api, start)
        end = _addr(api, end_excl - 1)
        cu_iter = listing.getCodeUnits(addr, True)
        while cu_iter.hasNext():
            cu = cu_iter.next()
            if cu.getAddress().compareTo(end) > 0:
                break
            data = listing.getDefinedDataAt(cu.getAddress())
            if data is not None:
                defined += 1
        row = {
            "start": f"${start:04X}",
            "end_excl": f"${end_excl:04X}",
            "name": name,
            "element_size": element_size,
            "defined_units": defined,
            "comment": comment,
        }
        if name in struct_meta:
            row["struct"] = struct_meta[name]
        rows.append(row)
    out_path.write_text(json.dumps({"segments": rows}, indent=2))
    return len(rows)


def _export_listing(api, out_path: Path) -> int:
    """Dump the listing as plain text. Instructions get mnemonic + operand
    representation; data units get their value representation.

    Uses `CodeUnitFormat` for instructions so EquateTable entries render
    as their symbolic names (e.g. `CMP #UI_MODE_SEQED` rather than
    `CMP #0x1`). `getDefaultOperandRepresentation` does NOT honour
    equates."""
    from ghidra.program.model.listing import (  # type: ignore
        CodeUnitFormat, CodeUnitFormatOptions,
    )
    program = api.getCurrentProgram()
    listing = program.getListing()
    addr_start = _addr(api, CODE_BASE)
    addr_end = _addr(api, CODE_END_EXCL - 1)
    cu_iter = listing.getCodeUnits(addr_start, True)
    fmt = CodeUnitFormat(CodeUnitFormatOptions())
    lines: list[str] = []
    while cu_iter.hasNext():
        cu = cu_iter.next()
        a = cu.getAddress()
        if a.compareTo(addr_end) > 0:
            break
        addr_int = int(a.getOffset())
        sym = program.getSymbolTable().getPrimarySymbol(a)
        label = f"{sym.getName()}:" if sym is not None else ""
        mnem = str(cu.getMnemonicString())
        operand_text = ""
        if listing.getInstructionAt(a) is not None:
            try:
                # CodeUnitFormat returns "<mnem> <operands>" — strip the
                # mnemonic so we render it in the fixed-width column.
                full = str(fmt.getRepresentationString(cu)).strip()
                if full.startswith(mnem):
                    operand_text = full[len(mnem):].strip()
                else:
                    operand_text = full
            except Exception:
                operand_text = ""
        else:
            try:
                operand_text = str(cu.getDefaultValueRepresentation())
            except Exception:
                operand_text = ""
        lines.append(f"${addr_int:04X}  {label:<22} {mnem:<6} {operand_text}")
    out_path.write_text("\n".join(lines) + "\n")
    return len(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="artefacts/defmon-static.bin",
                    help="flat 64K static image")
    ap.add_argument("--entrypoints", default="trace/entrypoints.json",
                    help="JSON with executed PCs (code-start oracle)")
    ap.add_argument("--project-dir", default=".ghidra-projects",
                    help="local Ghidra project workspace dir (created if missing)")
    ap.add_argument("--project-name", default="defmon")
    ap.add_argument("--out", default="artefacts/ghidra",
                    help="output directory for symbols.json/segments.json/etc.")
    ap.add_argument("--ghidra-install", default="/scratch/anarkiwi/ghidra_12.0.4_PUBLIC")
    ap.add_argument("--no-decompile", action="store_true",
                    help="skip per-function decompile (saves ~30s)")
    ap.add_argument("--max-decompile", type=int, default=200,
                    help="cap per-function decompile output (6502 decomp is slow)")
    args = ap.parse_args()

    bin_path = Path(args.bin).resolve()
    if not bin_path.exists():
        raise SystemExit(f"missing static image: {bin_path}")
    entrypoints_path = Path(args.entrypoints).resolve()
    if not entrypoints_path.exists():
        raise SystemExit(f"missing entrypoints: {entrypoints_path}")
    project_dir = Path(args.project_dir).resolve()
    project_dir.mkdir(parents=True, exist_ok=True)
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    _start_pyghidra(args.ghidra_install)

    seeds = _load_entrypoints(entrypoints_path)
    seeds.update(SEED_LANDMARKS.keys())
    print(f"seed PCs: {len(seeds)} "
          f"({len(SEED_LANDMARKS)} landmarks + entrypoints)")

    import pyghidra  # noqa: PLC0415
    from ghidra.program.model.symbol import SourceType  # type: ignore

    with pyghidra.open_program(
        binary_path=bin_path,
        project_location=project_dir,
        project_name=args.project_name,
        analyze=False,
        language=PROCESSOR_LANGUAGE,
        loader="ghidra.app.util.opinion.BinaryLoader",
    ) as api:
        program = api.getCurrentProgram()
        sym_table = program.getSymbolTable()

        # 1) Apply landmark labels (idempotent).
        landmark_changes = 0
        for addr_int, name in SEED_LANDMARKS.items():
            if _ensure_label(api, sym_table, addr_int, name, SourceType.USER_DEFINED):
                landmark_changes += 1
        print(f"landmark labels applied/updated: {landmark_changes}")

        # 2) Apply state-variable labels.
        state_changes = 0
        for addr_int, name, *rest in STATE_LABELS:
            if _ensure_label(api, sym_table, addr_int, name, SourceType.USER_DEFINED):
                state_changes += 1
            if rest:
                comment = rest[0]
                api.setEOLComment(_addr(api, addr_int), comment)
        print(f"state labels applied/updated: {state_changes}")

        # 3) Force disassembly at every seed PC.
        disassembled = 0
        for pc in sorted(seeds):
            if not (CODE_BASE <= pc < CODE_END_EXCL):
                continue
            if _force_disassemble(api, pc):
                disassembled += 1
        print(f"newly disassembled instruction starts: {disassembled}")

        # 4) Promote each landmark to a function.
        promoted = 0
        for addr_int, name in SEED_LANDMARKS.items():
            if _create_function(api, addr_int, name):
                promoted += 1
        print(f"functions created from landmarks: {promoted}")

        # 5) Mark data segments. Segments named in STRUCT_SEGMENTS get
        # the corresponding struct/array layout; everything else gets the
        # bare ByteDataType/WordDataType fill.
        seg_units = 0
        struct_meta: dict[str, dict] = {}
        for start, end_excl, name, _comment, element_size in DATA_SEGMENTS:
            if name == "pattern_bank":
                placed, meta = _apply_pattern_bank_struct(
                    api, start, end_excl)
                seg_units += placed
                if meta:
                    struct_meta[name] = meta
                continue
            if name == "sidtab_data":
                placed, meta = _apply_sidtab_data_struct(
                    api, start, end_excl)
                seg_units += placed
                if meta:
                    struct_meta[name] = meta
                # The struct only covers the clean lower portion
                # ($5F00..$6DFF). Fall through to the generic byte fill
                # so the upper portion ($6E00..$7166) — which is
                # partially overlaid by arranger_v{3,4,5}_sid2 — still
                # gets ByteDataType units for any bytes the arrangers
                # don't claim.
                upper_start = start + SIDTAB_ROW_COUNT_CLEAN * SIDTAB_ROW_SIZE
                if upper_start < end_excl:
                    seg_units += _mark_data_segment(
                        api, upper_start, end_excl, element_size)
                continue
            if name in STRUCT_SEGMENTS:
                # Defined in STRUCT_SEGMENTS but no handler wired yet —
                # fall through to the generic fill rather than silently
                # skipping the segment.
                print(f"WARN: STRUCT_SEGMENTS[{name!r}] has no applicator; "
                      "using generic byte/word fill")
            seg_units += _mark_data_segment(api, start, end_excl, element_size)
        print(f"data units placed across segments: {seg_units}")
        if struct_meta:
            for sname, m in struct_meta.items():
                element = m["element"]
                container = m.get("container")
                if container:
                    layout = (f"{container['name']}"
                              f"[{container['element_count']}] "
                              f"(element = {element['name']}, "
                              f"{element['size']} B)")
                else:
                    layout = (f"{element['name']}[] "
                              f"({element['size']} B/element, flat array)")
                print(f"  struct: {sname} → {layout}")

        # Re-apply data-segment NAME labels (some might have been
        # clobbered by the data placement).
        for start, _end, name, comment, _es in DATA_SEGMENTS:
            _ensure_label(api, sym_table, start, name, SourceType.USER_DEFINED)
            api.setPlateComment(_addr(api, start), comment)

        # 6a) Memory-band annotations on the BinaryLoader block.
        n_bands = _annotate_memory_bands(api)
        if n_bands:
            print(f"memory bands annotated: {n_bands}")

        # 6b) SMC-dispatch catalogue: load from annotations.toml, push
        # COMPUTED_CALL (JSR) or COMPUTED_JUMP (JMP) refs into Ghidra
        # for every annotated target so the analyzer picks them up when
        # it traces flow.
        smc_annotated = _load_smc_dispatch_annotations(ANNOTATIONS_PATH)
        jt_refs = 0
        for switch_pc, body in smc_annotated.items():
            targets = [t["addr"] for t in body.get("targets", [])]
            if not targets:
                continue
            host = api.getCurrentProgram().getListing().getInstructionAt(
                _addr(api, switch_pc))
            host_mnem = str(host.getMnemonicString()) if host else "JSR"
            ref_type = ("COMPUTED_JUMP" if host_mnem == "JMP"
                        else "COMPUTED_CALL")
            jt_refs += _apply_jump_table_override(
                api, switch_pc, ref_type, targets)
        if jt_refs:
            print(f"SMC-dispatch COMPUTED_CALL/JUMP refs added: {jt_refs}")

        # 6c) Value-name equates: push annotations.toml value_names tables
        # into Ghidra's EquateTable so the decompiler renders symbolic
        # names (e.g. UI_MODE_SEQED) instead of raw `'\x01'` literals.
        # Driven by cmp_facts.json — only CMP/CPX/CPY-immediate sites
        # whose lhs variable matches a value_names region get equated.
        value_names = _load_value_names_from_annotations(ANNOTATIONS_PATH)
        if value_names:
            sites = _collect_equate_sites(CMP_FACTS_PATH, value_names)
            n_eq = _apply_value_name_equates(api, sites)
            print(f"value-name equates applied: {n_eq} "
                  f"(from {len(sites)} candidate sites across "
                  f"{len(value_names)} regions)")

        # 7) Run autoanalysis (lightweight — disassembly already done).
        try:
            api.analyzeAll(program)
        except Exception as exc:
            print(f"analyzeAll: {type(exc).__name__}: {exc}")

        # 7b) Function signatures: parse `signature = "..."` strings from
        # annotations.toml and apply via ApplyFunctionSignatureCmd. Done
        # AFTER analyzeAll so all landmark-promoted functions exist; the
        # decompile uses these signatures to render typed parameters.
        sigs = _load_function_signatures(ANNOTATIONS_PATH)
        if sigs:
            n_sig = _apply_function_signatures(api, sigs)
            print(f"function signatures applied: {n_sig} / {len(sigs)}")

        # 7c) SMC-JSR auto-discovery: scan every JSR for operand-byte
        # writes (the structural definition of a SMC dispatcher). Warn
        # if Ghidra found a site that annotations.toml didn't document,
        # and export the merged catalogue for the emitter to consume.
        smc_discovered = _discover_smc_dispatch_sites(api)
        for pc in sorted(set(smc_discovered) - set(smc_annotated)):
            ws = ", ".join(f"${w:04X}" for w in smc_discovered[pc])
            print(f"WARN: SMC-dispatch site ${pc:04X} (patched by {ws}) "
                  f"has no [smc_dispatch.] annotation")
        for pc in sorted(set(smc_annotated) - set(smc_discovered)):
            print(f"WARN: [smc_dispatch.\"${pc:04X}\"] annotated but no "
                  f"SMC patch writes discovered — stale entry?")
        _export_smc_dispatch(out_dir / "smc_dispatch.json",
                        smc_annotated, smc_discovered)
        print(f"SMC-dispatch sites: annotated={len(smc_annotated)}, "
              f"discovered={len(smc_discovered)} → smc_dispatch.json")

        # 7c.5) SMC-branch sites: branch offset bytes patched at runtime.
        smcb_annotated = _load_smc_branch_annotations(ANNOTATIONS_PATH)
        smcb_discovered = _discover_smc_branch_sites(api)
        for pc in sorted(set(smcb_discovered) - set(smcb_annotated)):
            ws = ", ".join(f"${w:04X}" for w in smcb_discovered[pc])
            print(f"WARN: SMC-branch site ${pc:04X} (patched by {ws}) "
                  f"has no [smc_branch.] annotation")
        for pc in sorted(set(smcb_annotated) - set(smcb_discovered)):
            print(f"WARN: [smc_branch.\"${pc:04X}\"] annotated but no "
                  f"SMC patch writes discovered — stale entry?")
        _export_smc_branch(out_dir / "smc_branch.json",
                           smcb_annotated, smcb_discovered)
        print(f"SMC-branch sites: annotated={len(smcb_annotated)}, "
              f"discovered={len(smcb_discovered)} → smc_branch.json")

        # 7c.6) SMC-opcode-flip sites: opcode bytes patched at runtime,
        # changing the instruction TYPE that executes. Discovery traces
        # writer-source values via preceding LDA/LDX/LDY #imm; if the
        # source resolves to a valid 6502 opcode, the candidate mnemonic
        # gets recorded for the emitter header. Inconclusive sites
        # (register-sourced writers) get a "writer trace unresolved"
        # marker — invites curation rather than silently hiding.
        smco_annotated = _load_smc_opcode_annotations(ANNOTATIONS_PATH)
        smco_discovered = _discover_smc_opcode_sites(api)
        real_flips = sum(1 for d in smco_discovered.values()
                         if not d["inconclusive"])
        inconclusive = len(smco_discovered) - real_flips
        for pc in sorted(set(smco_annotated) - set(smco_discovered)):
            print(f"WARN: [smc_opcode.\"${pc:04X}\"] annotated but no "
                  f"opcode-byte write discovered — stale entry?")
        _export_smc_opcode(out_dir / "smc_opcode.json",
                           smco_annotated, smco_discovered)
        print(f"SMC-opcode sites: discovered={len(smco_discovered)} "
              f"({real_flips} real flips, {inconclusive} inconclusive); "
              f"annotated={len(smco_annotated)} → smc_opcode.json")

        # 7d) Annotation comments + state-variable types.
        # `_push_annotation_comments` puts the role/notes/inputs/outputs
        # block from annotations.toml on each function/region as a plate
        # comment — makes Ghidra UI sessions show the human-curated
        # context inline. `_apply_state_var_types` declares the byte at
        # each region address as ByteDataType so the decompile renders
        # the symbolic name rather than `bRAM0xxx`.
        fr_ann = _load_function_and_region_annotations(ANNOTATIONS_PATH)
        if fr_ann:
            n_plates = _push_annotation_comments(api, fr_ann)
            print(f"annotation plate comments pushed: {n_plates} "
                  f"/ {len(fr_ann)}")
            n_types = _apply_state_var_types(api, fr_ann, DATA_SEGMENTS)
            n_regions = sum(1 for e in fr_ann.values()
                            if e.get("kind") == "region")
            print(f"state-variable types applied: {n_types} "
                  f"/ {n_regions} region annotations")

        # 7) Exports.
        sym_n = _export_symbols(api, out_dir / "symbols.json")
        seg_n = _export_segments(api, out_dir / "segments.json",
                                 struct_meta=struct_meta)
        list_n = _export_listing(api, out_dir / "defmon.lst")
        print(f"exported {sym_n} symbols → symbols.json")
        print(f"exported {seg_n} segment rows → segments.json")
        print(f"exported {list_n} listing lines → defmon.lst")

        if not args.no_decompile:
            n = _decompile_functions(api, out_dir / "decompile",
                                     max_functions=args.max_decompile)
            print(f"decompiled {n} functions → decompile/")


if __name__ == "__main__":
    main()
