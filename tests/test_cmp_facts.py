"""Unit tests for cmp_facts lhs resolution of operand-based setters."""

import types
import unittest

from tools.re.cmp_facts import (
    _lhs_from_operand_setter,
    _resolve_lhs,
    _resolve_pla_source,
)


class TestResolvePlaSource(unittest.TestCase):
    def test_pla_matched_to_pha_resolves_to_pushed_var(self):
        """`LDA $1234; PHA; NOP; PLA` — the PLA matches the PHA across the
        intervening NOP and resolves to the variable pushed ($1234)."""
        mem = bytearray(0x10000)
        mem[0x1000:0x1003] = bytes([0xAD, 0x34, 0x12])
        mem[0x1003] = 0x48
        mem[0x1004] = 0xEA
        mem[0x1005] = 0x68
        instr_at = {
            0x1000: ("LDA", "abs", 3),
            0x1003: ("PHA", "imp", 1),
            0x1004: ("NOP", "imp", 1),
            0x1005: ("PLA", "imp", 1),
        }
        graph = types.SimpleNamespace(
            fall_through_in={0x1003: 0x1000, 0x1004: 0x1003, 0x1005: 0x1004},
            code_in={},
        )
        lhs = _resolve_pla_source(0x1005, mem, instr_at, graph)
        self.assertEqual(lhs["kind"], "var")
        self.assertEqual(lhs["var_addr"], 0x1234)

    def test_unbalanced_pla_pulls_caller_value(self):
        """A PLA with no matching PHA in the function (the push came from
        the caller) is unknown, not a phantom source."""
        mem = bytearray(0x10000)
        mem[0x1000] = 0x68
        mem[0x1001] = 0xEA
        instr_at = {0x0FFF: ("NOP", "imp", 1), 0x1000: ("PLA", "imp", 1)}
        graph = types.SimpleNamespace(fall_through_in={0x1000: 0x0FFF}, code_in={})
        lhs = _resolve_pla_source(0x1000, mem, instr_at, graph)
        self.assertEqual(lhs["kind"], "unknown")


class TestResolveLhsJsrReturn(unittest.TestCase):
    def test_jsr_before_setter_resolves_to_jsr_return(self):
        """Walking back the consumed register to a JSR yields a
        jsr_return lhs naming the callee + register. Lays out JSR $E000
        at $1000 then CMP #$05 (the A-consuming setter) at $1003."""
        mem = bytearray(0x10000)
        mem[0x1000:0x1003] = bytes([0x20, 0x00, 0xE0])
        mem[0x1003:0x1005] = bytes([0xC9, 0x05])
        instr_at = {0x1000: ("JSR", "abs", 3), 0x1003: ("CMP", "imm", 2)}
        graph = types.SimpleNamespace(fall_through_in={0x1003: 0x1000}, code_in={})
        lhs = _resolve_lhs(0x1003, "A", mem, instr_at, graph)
        self.assertEqual(lhs, {"kind": "jsr_return", "target": 0xE000, "reg": "A"})


class TestOperandSetterLhs(unittest.TestCase):
    def test_izy_load_resolves_to_var_indirect(self):
        """`LDA (zp),Y` flag-setter: the tested value is the indirect
        load, recorded as var_indirect at the zp pointer (operand byte
        $FB at pc+1)."""
        mem = bytes([0xB1, 0xFB, 0x00])
        lhs = _lhs_from_operand_setter(0, "LDA", "izy", 2, mem)
        self.assertEqual(lhs, {"kind": "var_indirect", "ptr_addr": "$FB", "index": "Y"})

    def test_pla_setter_is_unknown_with_stack_reason(self):
        """PLA pulls A from the stack — unresolvable, but the reason
        names the cause rather than a phantom addressing-mode gap."""
        lhs = _lhs_from_operand_setter(0, "PLA", "imp", 1, bytes([0x68]))
        self.assertEqual(lhs, {"kind": "unknown", "reason": "pla_from_stack"})

    def test_imm_and_abs_still_resolve(self):
        """Existing operand-based cases are unaffected."""
        self.assertEqual(
            _lhs_from_operand_setter(0, "LDA", "imm", 2, bytes([0xA9, 0x07])),
            {"kind": "imm", "value": "$07"},
        )
        abs_lhs = _lhs_from_operand_setter(
            0, "LDA", "abs", 3, bytes([0xAD, 0x34, 0x12])
        )
        self.assertEqual(abs_lhs, {"kind": "var", "var_addr": "$1234"})


if __name__ == "__main__":
    unittest.main()
