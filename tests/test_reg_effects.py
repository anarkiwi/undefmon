"""Unit + smoke tests for the per-function register-effect analyzer
(clobbers + inputs + outputs)."""

import json
import unittest
from pathlib import Path

from tools.re import reg_effects as R

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"


def _img(asm: dict[int, bytes]) -> bytes:
    mem = bytearray(0x10000)
    for addr, b in asm.items():
        mem[addr : addr + len(b)] = b
    return bytes(mem)


def _instr(items):
    return {pc: info for pc, info in items}


class TestAnalyze(unittest.TestCase):
    def test_direct_writes(self):
        """lda #; ldx #; rts -> clobbers A and X, not Y."""
        mem = _img({0x1000: bytes([0xA9, 0x00, 0xA2, 0x00, 0x60])})
        instr = _instr(
            [
                (0x1000, ("LDA", "imm", 2)),
                (0x1002, ("LDX", "imm", 2)),
                (0x1004, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000}))
        self.assertEqual(out["$1000"]["clobbers"], "AX")
        self.assertEqual(out["$1000"]["inputs"], "")
        self.assertFalse(out["$1000"]["uncertain"])

    def test_input_read_before_write(self):
        """tax; rts reads A before defining it -> A is an input; X is
        clobbered."""
        mem = _img({0x1000: bytes([0xAA, 0x60])})
        instr = _instr([(0x1000, ("TAX", "imp", 1)), (0x1001, ("RTS", "imp", 1))])
        out = R.analyze(mem, instr, frozenset({0x1000}))
        self.assertEqual(out["$1000"]["inputs"], "A")
        self.assertEqual(out["$1000"]["clobbers"], "X")

    def test_no_input_when_defined_first(self):
        """lda #; tax; rts -> A is written before tax reads it, so A is
        not an input."""
        mem = _img({0x1000: bytes([0xA9, 0x00, 0xAA, 0x60])})
        instr = _instr(
            [
                (0x1000, ("LDA", "imm", 2)),
                (0x1002, ("TAX", "imp", 1)),
                (0x1003, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000}))
        self.assertEqual(out["$1000"]["inputs"], "")
        self.assertEqual(out["$1000"]["clobbers"], "AX")

    def test_transitive_inputs_via_jsr(self):
        """A caller that calls a callee reading A, without defining A
        first, inherits A as an input."""
        mem = _img(
            {
                0x1000: bytes([0x20, 0x00, 0x20, 0x60]),
                0x2000: bytes([0xAA, 0x60]),
            }
        )
        instr = _instr(
            [
                (0x1000, ("JSR", "abs", 3)),
                (0x1003, ("RTS", "imp", 1)),
                (0x2000, ("TAX", "imp", 1)),
                (0x2001, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000, 0x2000}))
        self.assertEqual(out["$1000"]["inputs"], "A")

    def test_output_returned_value_consumed_by_caller(self):
        """Callee loads A and returns; caller reads A after the call, so A
        is a return register (output) of the callee."""
        mem = _img(
            {
                0x1000: bytes([0x20, 0x00, 0x20, 0x8D, 0x00, 0x04, 0x60]),
                0x2000: bytes([0xA9, 0x05, 0x60]),
            }
        )
        instr = _instr(
            [
                (0x1000, ("JSR", "abs", 3)),
                (0x1003, ("STA", "abs", 3)),
                (0x1006, ("RTS", "imp", 1)),
                (0x2000, ("LDA", "imm", 2)),
                (0x2002, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000, 0x2000}))
        self.assertEqual(out["$2000"]["outputs"], "A")

    def test_no_output_for_scratch_register(self):
        """Callee leaves a value in X but no caller reads X back, so X is
        scratch, not a return register."""
        mem = _img(
            {
                0x1000: bytes([0x20, 0x00, 0x20, 0xA9, 0x01, 0x8D, 0x00, 0x04, 0x60]),
                0x2000: bytes([0xA2, 0x00, 0x60]),
            }
        )
        instr = _instr(
            [
                (0x1000, ("JSR", "abs", 3)),
                (0x1003, ("LDA", "imm", 2)),
                (0x1005, ("STA", "abs", 3)),
                (0x1008, ("RTS", "imp", 1)),
                (0x2000, ("LDX", "imm", 2)),
                (0x2002, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000, 0x2000}))
        self.assertEqual(out["$2000"]["outputs"], "")

    def test_no_output_for_conditionally_defined_register(self):
        """X is written on only one path to the callee's RTS (not a must-
        define), so even though the caller reads X it is not a return
        register — the callee may pass X through unchanged."""
        mem = _img(
            {
                0x1000: bytes([0x20, 0x00, 0x20, 0x8E, 0x00, 0x04, 0x60]),
                0x2000: bytes([0xA5, 0x00, 0xF0, 0x02, 0xA2, 0x05, 0x60]),
            }
        )
        instr = _instr(
            [
                (0x1000, ("JSR", "abs", 3)),
                (0x1003, ("STX", "abs", 3)),
                (0x1006, ("RTS", "imp", 1)),
                (0x2000, ("LDA", "zp", 2)),
                (0x2002, ("BEQ", "rel", 2)),
                (0x2004, ("LDX", "imm", 2)),
                (0x2006, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000, 0x2000}))
        self.assertNotIn("X", out["$2000"]["outputs"])

    def test_no_output_for_function_without_caller(self):
        """A function no one calls returns nothing to a caller — its
        outputs set is empty regardless of what it computes."""
        mem = _img({0x1000: bytes([0xA9, 0x05, 0x60])})
        instr = _instr([(0x1000, ("LDA", "imm", 2)), (0x1002, ("RTS", "imp", 1))])
        out = R.analyze(mem, instr, frozenset({0x1000}))
        self.assertEqual(out["$1000"]["outputs"], "")

    def test_output_transitive_via_tail_call(self):
        """A tail-call function inherits the callee's must-define and the
        caller's demand: both the tail-caller and the tail callee return A."""
        mem = _img(
            {
                0x1000: bytes([0x20, 0x00, 0x20, 0x8D, 0x00, 0x04, 0x60]),
                0x2000: bytes([0x4C, 0x00, 0x30]),
                0x3000: bytes([0xA9, 0x05, 0x60]),
            }
        )
        instr = _instr(
            [
                (0x1000, ("JSR", "abs", 3)),
                (0x1003, ("STA", "abs", 3)),
                (0x1006, ("RTS", "imp", 1)),
                (0x2000, ("JMP", "abs", 3)),
                (0x3000, ("LDA", "imm", 2)),
                (0x3002, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000, 0x2000, 0x3000}))
        self.assertEqual(out["$2000"]["outputs"], "A")
        self.assertEqual(out["$3000"]["outputs"], "A")

    def test_memory_only_clobbers_nothing(self):
        """sta (zp),y; rts writes memory, not a register."""
        mem = _img({0x1000: bytes([0x91, 0xFB, 0x60])})
        instr = _instr([(0x1000, ("STA", "izy", 2)), (0x1002, ("RTS", "imp", 1))])
        out = R.analyze(mem, instr, frozenset({0x1000}))
        self.assertEqual(out["$1000"]["clobbers"], "")

    def test_transitive_clobbers_via_jsr(self):
        """A caller inherits its callee's clobbers: $1000 is `jsr $2000;
        rts` and $2000 is `tay; rts`, so $1000 clobbers Y."""
        mem = _img(
            {
                0x1000: bytes([0x20, 0x00, 0x20, 0x60]),
                0x2000: bytes([0xA8, 0x60]),
            }
        )
        instr = _instr(
            [
                (0x1000, ("JSR", "abs", 3)),
                (0x1003, ("RTS", "imp", 1)),
                (0x2000, ("TAY", "imp", 1)),
                (0x2001, ("RTS", "imp", 1)),
            ]
        )
        out = R.analyze(mem, instr, frozenset({0x1000, 0x2000}))
        self.assertEqual(out["$1000"]["clobbers"], "Y")

    def test_computed_jsr_forces_uncertain_axy(self):
        """A JSR to a target that isn't a classified instruction is
        computed/self-modified — clobbers conservatively to A,X,Y. Here
        $1000 is `jsr $5500; rts` and $5500 is not classified code."""
        mem = _img({0x1000: bytes([0x20, 0x00, 0x55, 0x60])})
        instr = _instr([(0x1000, ("JSR", "abs", 3)), (0x1003, ("RTS", "imp", 1))])
        out = R.analyze(mem, instr, frozenset({0x1000}))
        self.assertTrue(out["$1000"]["uncertain"])
        self.assertEqual(out["$1000"]["clobbers"], "AXY")


class TestRealImageSmoke(unittest.TestCase):
    def setUp(self):
        if not STATIC_BIN.is_file():
            self.skipTest(f"{STATIC_BIN} not present — run `make fetch-static`")

    def test_analyzes_most_functions_with_valid_regs(self):
        mem, instr_at, fn_entries, _ = R._load(STATIC_BIN, R.ENTRYPOINTS, R.ANNOTATIONS)
        facts = R.analyze(mem, instr_at, fn_entries)
        self.assertGreater(len(facts), 250)
        for v in facts.values():
            self.assertTrue(set(v["clobbers"]) <= set("AXY"))
            self.assertTrue(set(v["direct"]) <= set(v["clobbers"]) | set("AXY"))
            self.assertTrue(set(v["outputs"]) <= set("AXY"))
            if not v["uncertain"]:
                self.assertTrue(set(v["outputs"]) <= set(v["clobbers"]))


if __name__ == "__main__":
    unittest.main()
