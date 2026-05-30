"""Unit tests for cmp_facts lhs resolution of operand-based setters."""

import unittest

from tools.re.cmp_facts import _lhs_from_operand_setter


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
