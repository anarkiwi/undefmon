"""Unit tests for the minimal 6502 disassembler used by emit_defmon_source."""

import unittest

from tools.re.dasm6502 import OPS, disassemble, emit_instruction, fmt_operand


class TestOpsTable(unittest.TestCase):
    def test_known_opcodes(self):
        cases = {
            0x00: ("BRK", "imp", 1),
            0xA9: ("LDA", "imm", 2),
            0xEA: ("NOP", "imp", 1),
            0x4C: ("JMP", "abs", 3),
            0x6C: ("JMP", "ind", 3),
            0x60: ("RTS", "imp", 1),
            0x20: ("JSR", "abs", 3),
            0xD0: ("BNE", "rel", 2),
            0xF0: ("BEQ", "rel", 2),
            0x8D: ("STA", "abs", 3),
        }
        for opcode, expected in cases.items():
            self.assertEqual(OPS[opcode], expected, f"opcode ${opcode:02X}")

    def test_lengths_are_one_to_three(self):
        for opcode, (_, _, length) in OPS.items():
            self.assertIn(length, (1, 2, 3), f"opcode ${opcode:02X} length {length}")

    def test_modes_are_known(self):
        valid_modes = {
            "imp",
            "imm",
            "zp",
            "zpx",
            "zpy",
            "izx",
            "izy",
            "abs",
            "abx",
            "aby",
            "ind",
            "rel",
            "acc",
        }
        for opcode, (_, mode, _) in OPS.items():
            self.assertIn(mode, valid_modes, f"opcode ${opcode:02X} mode {mode}")


class TestEmitInstruction(unittest.TestCase):
    def test_immediate(self):
        self.assertEqual(emit_instruction("imm", 0x42, 0, 0x0800), "#$42")

    def test_absolute_no_label(self):
        self.assertEqual(emit_instruction("abs", 0x00, 0x10, 0x0800), "$1000")

    def test_absolute_with_label(self):
        out = emit_instruction(
            "abs", 0x00, 0x10, 0x0800, labels={0x1000: "player_init"}
        )
        self.assertEqual(out, "player_init")

    def test_relative_branch_forward(self):
        self.assertEqual(emit_instruction("rel", 0x0E, 0, 0x0800), "$0810")

    def test_relative_branch_backward(self):
        self.assertEqual(emit_instruction("rel", 0xFE, 0, 0x0800), "$0800")

    def test_zero_page(self):
        self.assertEqual(emit_instruction("zp", 0xFB, 0, 0x0800), "$FB")

    def test_implicit(self):
        self.assertEqual(emit_instruction("imp", 0, 0, 0x0800), "")

    def test_accumulator_is_bare(self):
        self.assertEqual(emit_instruction("acc", 0, 0, 0x0800), "")


class TestFmtOperand(unittest.TestCase):
    def test_jmp_abs_returns_target(self):
        _operand, target = fmt_operand("abs", 0x00, 0x10, 0x0800, {})
        self.assertEqual(target, 0x1000)

    def test_branch_relative_target(self):
        _operand, target = fmt_operand("rel", 0x0E, 0, 0x0800, {})
        self.assertEqual(target, 0x0810)

    def test_immediate_has_no_target(self):
        _operand, target = fmt_operand("imm", 0x42, 0, 0x0800, {})
        self.assertIsNone(target)


class TestDisassemble(unittest.TestCase):
    def test_lda_imm_then_jmp(self):
        mem = bytearray(0x10000)
        mem[0x0800:0x0805] = b"\xa9\x42\x4c\x00\x10"
        lines = list(disassemble(bytes(mem), 0x0800, 0x0805))
        self.assertEqual(len(lines), 2)
        self.assertIn("LDA", lines[0])
        self.assertIn("#$42", lines[0])
        self.assertIn("JMP", lines[1])
        self.assertIn("$1000", lines[1])


if __name__ == "__main__":
    unittest.main()
