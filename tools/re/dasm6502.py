"""Minimal 6502 disassembler for defMON RE work.

defMON is hand-assembled and mostly standard NMOS, but uses three
undocumented opcodes — LAX (zp),Y / LAX abs / SAX abs (see the OPS
table). Output is one line per instruction. Branch + jump targets
are computed and shown in operand. Address labels are emitted from a
caller-supplied label dict.

Usage as library:
    from tools.re.dasm6502 import disassemble
    for line in disassemble(mem, start, end_excl, labels={0x0B8B: "irq_main"}):
        print(line)

Usage as CLI:
    python3 -m tools.re.dasm6502 --bin artefacts/defmon-static.bin --start 0xB8B --len 200
"""

from __future__ import annotations

import argparse
from pathlib import Path

# 6502 NMOS opcode table.
# Each entry: (mnemonic, addressing_mode_code, operand_bytes)
# Addressing-mode codes:
#   imp   implicit (no operand)
#   imm   #$nn
#   zp    $nn
#   zpx   $nn,X
#   zpy   $nn,Y
#   izx   ($nn,X)
#   izy   ($nn),Y
#   abs   $nnnn
#   abx   $nnnn,X
#   aby   $nnnn,Y
#   ind   ($nnnn)         (JMP only)
#   rel   $nn (8-bit signed offset to branch target)
#   acc   A

OPS: dict[int, tuple[str, str, int]] = {
    # ADC
    0x69: ("ADC", "imm", 2),
    0x65: ("ADC", "zp", 2),
    0x75: ("ADC", "zpx", 2),
    0x6D: ("ADC", "abs", 3),
    0x7D: ("ADC", "abx", 3),
    0x79: ("ADC", "aby", 3),
    0x61: ("ADC", "izx", 2),
    0x71: ("ADC", "izy", 2),
    # AND
    0x29: ("AND", "imm", 2),
    0x25: ("AND", "zp", 2),
    0x35: ("AND", "zpx", 2),
    0x2D: ("AND", "abs", 3),
    0x3D: ("AND", "abx", 3),
    0x39: ("AND", "aby", 3),
    0x21: ("AND", "izx", 2),
    0x31: ("AND", "izy", 2),
    # ASL
    0x0A: ("ASL", "acc", 1),
    0x06: ("ASL", "zp", 2),
    0x16: ("ASL", "zpx", 2),
    0x0E: ("ASL", "abs", 3),
    0x1E: ("ASL", "abx", 3),
    # branches
    0x10: ("BPL", "rel", 2),
    0x30: ("BMI", "rel", 2),
    0x50: ("BVC", "rel", 2),
    0x70: ("BVS", "rel", 2),
    0x90: ("BCC", "rel", 2),
    0xB0: ("BCS", "rel", 2),
    0xD0: ("BNE", "rel", 2),
    0xF0: ("BEQ", "rel", 2),
    # BIT
    0x24: ("BIT", "zp", 2),
    0x2C: ("BIT", "abs", 3),
    # BRK
    0x00: ("BRK", "imp", 1),
    # CMP
    0xC9: ("CMP", "imm", 2),
    0xC5: ("CMP", "zp", 2),
    0xD5: ("CMP", "zpx", 2),
    0xCD: ("CMP", "abs", 3),
    0xDD: ("CMP", "abx", 3),
    0xD9: ("CMP", "aby", 3),
    0xC1: ("CMP", "izx", 2),
    0xD1: ("CMP", "izy", 2),
    # CPX/CPY
    0xE0: ("CPX", "imm", 2),
    0xE4: ("CPX", "zp", 2),
    0xEC: ("CPX", "abs", 3),
    0xC0: ("CPY", "imm", 2),
    0xC4: ("CPY", "zp", 2),
    0xCC: ("CPY", "abs", 3),
    # DEC
    0xC6: ("DEC", "zp", 2),
    0xD6: ("DEC", "zpx", 2),
    0xCE: ("DEC", "abs", 3),
    0xDE: ("DEC", "abx", 3),
    # EOR
    0x49: ("EOR", "imm", 2),
    0x45: ("EOR", "zp", 2),
    0x55: ("EOR", "zpx", 2),
    0x4D: ("EOR", "abs", 3),
    0x5D: ("EOR", "abx", 3),
    0x59: ("EOR", "aby", 3),
    0x41: ("EOR", "izx", 2),
    0x51: ("EOR", "izy", 2),
    # flags
    0x18: ("CLC", "imp", 1),
    0x38: ("SEC", "imp", 1),
    0x58: ("CLI", "imp", 1),
    0x78: ("SEI", "imp", 1),
    0xB8: ("CLV", "imp", 1),
    0xD8: ("CLD", "imp", 1),
    0xF8: ("SED", "imp", 1),
    # INC
    0xE6: ("INC", "zp", 2),
    0xF6: ("INC", "zpx", 2),
    0xEE: ("INC", "abs", 3),
    0xFE: ("INC", "abx", 3),
    # JMP / JSR / RTS / RTI
    0x4C: ("JMP", "abs", 3),
    0x6C: ("JMP", "ind", 3),
    0x20: ("JSR", "abs", 3),
    0x60: ("RTS", "imp", 1),
    0x40: ("RTI", "imp", 1),
    # LDA
    0xA9: ("LDA", "imm", 2),
    0xA5: ("LDA", "zp", 2),
    0xB5: ("LDA", "zpx", 2),
    0xAD: ("LDA", "abs", 3),
    0xBD: ("LDA", "abx", 3),
    0xB9: ("LDA", "aby", 3),
    0xA1: ("LDA", "izx", 2),
    0xB1: ("LDA", "izy", 2),
    # LDX
    0xA2: ("LDX", "imm", 2),
    0xA6: ("LDX", "zp", 2),
    0xB6: ("LDX", "zpy", 2),
    0xAE: ("LDX", "abs", 3),
    0xBE: ("LDX", "aby", 3),
    # LDY
    0xA0: ("LDY", "imm", 2),
    0xA4: ("LDY", "zp", 2),
    0xB4: ("LDY", "zpx", 2),
    0xAC: ("LDY", "abs", 3),
    0xBC: ("LDY", "abx", 3),
    # LSR
    0x4A: ("LSR", "acc", 1),
    0x46: ("LSR", "zp", 2),
    0x56: ("LSR", "zpx", 2),
    0x4E: ("LSR", "abs", 3),
    0x5E: ("LSR", "abx", 3),
    # NOP
    0xEA: ("NOP", "imp", 1),
    # ORA
    0x09: ("ORA", "imm", 2),
    0x05: ("ORA", "zp", 2),
    0x15: ("ORA", "zpx", 2),
    0x0D: ("ORA", "abs", 3),
    0x1D: ("ORA", "abx", 3),
    0x19: ("ORA", "aby", 3),
    0x01: ("ORA", "izx", 2),
    0x11: ("ORA", "izy", 2),
    # PHA/PLA/PHP/PLP
    0x48: ("PHA", "imp", 1),
    0x68: ("PLA", "imp", 1),
    0x08: ("PHP", "imp", 1),
    0x28: ("PLP", "imp", 1),
    # ROL/ROR
    0x2A: ("ROL", "acc", 1),
    0x26: ("ROL", "zp", 2),
    0x36: ("ROL", "zpx", 2),
    0x2E: ("ROL", "abs", 3),
    0x3E: ("ROL", "abx", 3),
    0x6A: ("ROR", "acc", 1),
    0x66: ("ROR", "zp", 2),
    0x76: ("ROR", "zpx", 2),
    0x6E: ("ROR", "abs", 3),
    0x7E: ("ROR", "abx", 3),
    # SBC
    0xE9: ("SBC", "imm", 2),
    0xE5: ("SBC", "zp", 2),
    0xF5: ("SBC", "zpx", 2),
    0xED: ("SBC", "abs", 3),
    0xFD: ("SBC", "abx", 3),
    0xF9: ("SBC", "aby", 3),
    0xE1: ("SBC", "izx", 2),
    0xF1: ("SBC", "izy", 2),
    # STA
    0x85: ("STA", "zp", 2),
    0x95: ("STA", "zpx", 2),
    0x8D: ("STA", "abs", 3),
    0x9D: ("STA", "abx", 3),
    0x99: ("STA", "aby", 3),
    0x81: ("STA", "izx", 2),
    0x91: ("STA", "izy", 2),
    # STX/STY
    0x86: ("STX", "zp", 2),
    0x96: ("STX", "zpy", 2),
    0x8E: ("STX", "abs", 3),
    0x84: ("STY", "zp", 2),
    0x94: ("STY", "zpx", 2),
    0x8C: ("STY", "abs", 3),
    # transfers
    0xAA: ("TAX", "imp", 1),
    0xA8: ("TAY", "imp", 1),
    0xBA: ("TSX", "imp", 1),
    0x8A: ("TXA", "imp", 1),
    0x9A: ("TXS", "imp", 1),
    0x98: ("TYA", "imp", 1),
    # INX/INY/DEX/DEY
    0xE8: ("INX", "imp", 1),
    0xC8: ("INY", "imp", 1),
    0xCA: ("DEX", "imp", 1),
    0x88: ("DEY", "imp", 1),
    # Undocumented NMOS opcodes defMON uses (Kick Assembler assembles
    # these natively). Without them the host renders as `.byte` and its
    # whole fall-through run is mis-classified as unreachable.
    #   LAX — load A and X together (count bytes, super-command args,
    #     pitch-LUT reads). Modes: (zp),Y / abs / #imm / zp / zp,Y /
    #     abs,Y / (zp,X).
    #   SAX — store A & X (row-timer dur-nibble writes; gate-mask SMC).
    #     Modes: abs / zp / zp,Y / (zp,X).
    #   ALR/ARR/AXS — AND-then-shift / AND-then-ROR / (A&X)-imm→X combine
    #     ops in the pitch-slide and sweep math.
    0xB3: ("LAX", "izy", 2),
    0xAF: ("LAX", "abs", 3),
    0xAB: ("LAX", "imm", 2),
    0xA7: ("LAX", "zp", 2),
    0xB7: ("LAX", "zpy", 2),
    0xBF: ("LAX", "aby", 3),
    0xA3: ("LAX", "izx", 2),
    0x8F: ("SAX", "abs", 3),
    0x87: ("SAX", "zp", 2),
    0x97: ("SAX", "zpy", 2),
    0x83: ("SAX", "izx", 2),
    0x4B: ("ALR", "imm", 2),
    0x6B: ("ARR", "imm", 2),
    0xCB: ("AXS", "imm", 2),
    # ANC ($2B) and SBC ($EB) are DUPLICATE encodings of $0B/$E9. Kick
    # Assembler distinguishes them with the dedicated `anc2`/`sbc2`
    # mnemonics, so they round-trip byte-exact (see KICKASS_DUP_MNEMONICS).
    0x2B: ("ANC", "imm", 2),
    0xEB: ("SBC", "imm", 2),
}

# Duplicate-encoding undocumented opcodes whose canonical mnemonic
# (`anc`/`sbc`) assembles to the OTHER encoding ($0B/$E9). Kick Assembler
# provides `anc2`/`sbc2` to reproduce these exact bytes; the emitter uses
# this map to pick the right mnemonic for them.
KICKASS_DUP_MNEMONICS = {0x2B: "anc2", 0xEB: "sbc2"}



# Operand suffix per addressing mode.
def fmt_operand(
    mode: str, p1: int, p2: int, pc: int, labels: dict[int, str]
) -> tuple[str, int | None]:
    """Returns (text, target_addr_or_None). target is set for abs/abx/aby/ind/rel
    so callers can build cross-references."""

    def lbl(addr: int) -> str:
        return labels.get(addr, f"${addr:04X}")

    if mode == "imp":
        return "", None
    if mode == "imm":
        return f"#${p1:02X}", None
    if mode == "zp":
        return f"${p1:02X}", p1
    if mode == "zpx":
        return f"${p1:02X},X", None
    if mode == "zpy":
        return f"${p1:02X},Y", None
    if mode == "izx":
        return f"(${p1:02X},X)", None
    if mode == "izy":
        return f"(${p1:02X}),Y", None
    if mode == "abs":
        addr = p1 | (p2 << 8)
        return lbl(addr), addr
    if mode == "abx":
        addr = p1 | (p2 << 8)
        return f"{lbl(addr)},X", addr
    if mode == "aby":
        addr = p1 | (p2 << 8)
        return f"{lbl(addr)},Y", addr
    if mode == "ind":
        addr = p1 | (p2 << 8)
        return f"({lbl(addr)})", addr
    if mode == "rel":
        # relative branch: target = pc + 2 + signed(p1)
        off = p1 if p1 < 0x80 else p1 - 256
        target = (pc + 2 + off) & 0xFFFF
        return lbl(target), target
    if mode == "acc":
        return "A", None
    return "?", None


def render_struct_offset(seg: dict, addr: int) -> str | None:
    """Render an address inside a struct-typed data segment as an
    assembler expression. Two modes:

    1. **Dotted-instance form** (preferred). When the segment carries
       an ``instances`` list of ``(name, addr)`` tuples — one entry per
       array element — the result is ``<instance>.<field>`` or
       ``<instance> + $<offset>`` when the field is unnamed. Backed by
       a ``.struct`` + per-instance ``.virtual`` / ``.dstruct`` emission
       in defmon.asm, so the dotted suffixes resolve at assemble time.

    2. **Flat-equate form** (legacy). For segments without
       ``instances`` the result is the prior
       ``<seg> + N*Container_size + N*Element_size + Element_<field>``
       expression — backed by the STRUCT EQUATES equate block.

    Returns None if the segment has no struct metadata or the element
    size is missing.

    Examples (dotted-instance form):
    * voice_record_v0/v1/v2 at $1019/$104A/$107B with element_size=$31.
      Address $1058 → element_idx 1, field_offset $0E (freq_lo) →
      ``voice_record_v1.freq_lo``.
    * sid2_voice_record_v0/v1/v2 at $C819/$C84A/$C87B. Address $C825
      → element_idx 0, field_offset $0C (pw_hi) →
      ``sid2_voice_record_v0.pw_hi``.

    Examples (flat-equate fallback):
    * pattern_bank at $1F00, ``Pattern[128]`` of ``PatternStep[32]``.
      Address $1F87 → ``pattern_bank + 1*Pattern_size +
      1*PatternStep_size + PatternStep_note``.
    """
    struct = seg.get("struct")
    if not struct:
        return None
    container = struct.get("container") or None
    element = struct.get("element", {})
    element_size = element.get("size")
    if not element_size:
        return None
    offset = addr - seg["start"]
    if container and container.get("size"):
        container_idx, inner = divmod(offset, container["size"])
    else:
        container_idx = 0
        inner = offset
    element_idx, field_offset = divmod(inner, element_size)
    field_name = None
    for f in element.get("fields", []):
        if f.get("offset") == field_offset:
            field_name = f.get("name")
            break
    instances = seg.get("instances")
    if instances and container_idx == 0 and 0 <= element_idx < len(instances):
        inst_name, _inst_addr = instances[element_idx]
        if field_offset == 0:
            return inst_name
        if field_name is not None:
            return f"{inst_name}.{field_name}"
        return f"{inst_name} + ${field_offset:02X}"
    parts: list[str] = []
    if container_idx and container:
        parts.append(f"{container_idx}*{container['name']}_size")
    if element_idx:
        parts.append(f"{element_idx}*{element['name']}_size")
    if field_offset:
        if field_name is not None:
            parts.append(f"{element['name']}_{field_name}")
        else:
            parts.append(f"${field_offset:02X}")
    if not parts:
        return seg["name"]
    return f"{seg['name']} + " + " + ".join(parts)


def emit_instruction(
    mode: str,
    p1: int,
    p2: int,
    pc: int,
    labels: dict[int, str] | None = None,
    imm_subs: dict[int, str] | None = None,
    branch_operand_override: dict[int, str] | None = None,
    struct_segments: list[dict] | None = None,
    name_spans: list[tuple[int, int, str]] | None = None,
    anchor_spans: list[tuple[int, int, str]] | None = None,
    bank_ram: bool = False,
    ram_banked_ranges: list[tuple[int, int]] | None = None,
) -> str:
    """Format a 6502 instruction operand.

    The operand syntax (``#$NN``, ``$NNNN``, ``($NN),y`` …) is identical
    across assemblers; this returns just the operand text and the caller
    supplies the mnemonic. defMON's image never encodes an ABS-mode
    instruction whose operand falls in the zero page, so no explicit
    addressing-mode width force is emitted — the round-trip check is the
    authoritative guard if that ever changes.

    ``struct_segments`` — list of segment dicts (start/end_excl/name/
    struct) for data regions with a defined struct layout. When an
    ABS/ABX/ABY/IND operand falls inside one of these ranges AND no
    explicit label exists at the exact byte, the operand is rendered as
    a struct field expression (see ``render_struct_offset``). Hand-
    curated labels in ``labels`` always win — the struct expression is
    a fallback for the long tail of intra-segment addresses.

    ``name_spans`` — sorted list of ``(start, end_excl, name)`` triples
    derived from the annotation catalogue ([function] + [region] entries
    with a ``name`` field). Fallback for ABS-mode operands whose target
    falls inside an annotated span but doesn't land on a named byte:
    rendered as ``name + $offset`` so SMC-operand-byte writes like
    ``sta $11A2`` surface as ``sta v0_gate_n_branch + $01``.

    ``anchor_spans`` — sorted list of ``(start, end_excl, name)`` triples
    for hardware/system RAM regions (COLOR_RAM at $D800, SCREEN_RAM at
    $0400, ...). Checked BEFORE ``name_spans``: an ABS write to $D823
    renders as ``COLOR_RAM + $23`` (the colour cell at row 0 col 35)
    rather than falling through to any static-image annotation that
    nominally spans that address (defMON's load-time PSID template at
    $D7F8..$D8FC overlaps the colour-RAM overlay numerically; runtime
    semantics are always the hardware overlay there).

    Returns just the operand text (mnemonic is the caller's job).
    """
    labels = labels or {}
    struct_segments = struct_segments or []
    name_spans = name_spans or []
    anchor_spans = anchor_spans or []

    def _struct_label(addr: int) -> str | None:
        for seg in struct_segments:
            if seg["start"] <= addr < seg["end_excl"]:
                return render_struct_offset(seg, addr)
        return None

    def _lookup_span(spans: list[tuple[int, int, str]], addr: int) -> str | None:
        import bisect

        idx = bisect.bisect_right([s[0] for s in spans], addr) - 1
        if idx < 0:
            return None
        start, end_excl, name = spans[idx]
        if not (start <= addr < end_excl):
            return None
        # Kick Assembler is case-sensitive, so an anchor reference must use
        # the exact spelling of the equate emitted at its base. When a
        # label is defined there that differs only in case (e.g. the
        # `screen_ram` equate vs the `SCREEN_RAM` anchor span), defer to
        # the defined label so the reference resolves.
        base = labels.get(start)
        if base is not None and base.lower() == name.lower():
            name = base
        offset = addr - start
        return name if offset == 0 else f"{name} + ${offset:02X}"

    def lbl(addr: int) -> str:
        # Bank-aware overlay resolution: a target address that lives inside a
        # RAM-banked routine's code (``ram_banked_ranges``) is RAM/code only
        # when the *referrer* also runs RAM-banked. A normal (I/O-mapped)
        # referrer sees that same address as the hardware overlay, so prefer
        # the anchor label (COLOR_RAM, ...) over the RAM-view code label.
        # Addresses outside those ranges (named colour-RAM rows, real I/O
        # registers) keep their normal label order.
        in_overlay = 0xD800 <= addr < 0xDC00
        if not bank_ram and ram_banked_ranges:
            for _s, _e in ram_banked_ranges:
                if _s <= addr < _e:
                    anchor_text = _lookup_span(anchor_spans, addr)
                    if anchor_text is not None:
                        return anchor_text
                    break
        if addr in labels:
            return labels[addr]
        struct_text = _struct_label(addr)
        if struct_text is not None:
            return struct_text
        # A RAM-banked referrer into the colour-RAM overlay addresses RAM,
        # not the COLOR_RAM hardware cells — skip the anchor so the operand
        # reads as a RAM name/hex rather than a misleading COLOR_RAM + $off.
        if not (in_overlay and bank_ram):
            anchor_text = _lookup_span(anchor_spans, addr)
            if anchor_text is not None:
                return anchor_text
        span_text = _lookup_span(name_spans, addr)
        if span_text is not None:
            return span_text
        return f"${addr:04X}"

    def lbl_zp(addr: int) -> str:
        return labels.get(addr, f"${addr:02X}")

    if mode == "imp":
        return ""
    if mode == "imm":
        if imm_subs and pc in imm_subs:
            return f"#{imm_subs[pc]}"
        return f"#${p1:02X}"
    if mode == "zp":
        return lbl_zp(p1)
    if mode == "zpx":
        return f"{lbl_zp(p1)},x"
    if mode == "zpy":
        return f"{lbl_zp(p1)},y"
    if mode == "izx":
        return f"({lbl_zp(p1)},x)"
    if mode == "izy":
        return f"({lbl_zp(p1)}),y"
    if mode == "abs":
        addr = p1 | (p2 << 8)
        return f"{lbl(addr)}"
    if mode == "abx":
        addr = p1 | (p2 << 8)
        return f"{lbl(addr)},x"
    if mode == "aby":
        addr = p1 | (p2 << 8)
        return f"{lbl(addr)},y"
    if mode == "ind":
        addr = p1 | (p2 << 8)
        return f"({lbl(addr)})"
    if mode == "rel":
        if branch_operand_override and pc in branch_operand_override:
            return branch_operand_override[pc]
        off = p1 if p1 < 0x80 else p1 - 256
        target = (pc + 2 + off) & 0xFFFF
        return lbl(target)
    if mode == "acc":
        # Kick Assembler uses the bare mnemonic for accumulator mode
        # (`lsr`, not `lsr a` — the latter parses `a` as a symbol).
        return ""
    return "?"


def disassemble(
    mem: bytes,
    start: int,
    end: int,
    labels: dict[int, str] | None = None,
    stop_on_rts: bool = False,
):
    """Yield disassembly lines from [start, end)."""
    labels = labels or {}
    pc = start
    while pc < end:
        op = mem[pc]
        if op not in OPS:
            yield f"  {pc:04X}  {op:02X}                    ??? .byte ${op:02X}"
            pc += 1
            continue
        mnem, mode, n = OPS[op]
        p1 = mem[pc + 1] if n >= 2 else 0
        p2 = mem[pc + 2] if n >= 3 else 0
        operand_text, _target = fmt_operand(mode, p1, p2, pc, labels)
        bytes_text = " ".join(f"{mem[pc + i]:02X}" for i in range(n))
        label_text = labels.get(pc, "")
        yield f"  {pc:04X}  {bytes_text:<10}  {mnem} {operand_text:<14}  {label_text}"
        pc += n
        if stop_on_rts and mnem in ("RTS", "RTI", "JMP"):
            break


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="artefacts/defmon-static.bin")
    ap.add_argument("--start", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--len", dest="length", type=lambda s: int(s, 0), default=64)
    ap.add_argument("--stop-rts", action="store_true")
    args = ap.parse_args()

    mem = Path(args.bin).read_bytes()
    end = min(args.start + args.length, 0x10000)
    for line in disassemble(mem, args.start, end, stop_on_rts=args.stop_rts):
        print(line)


if __name__ == "__main__":
    main()
