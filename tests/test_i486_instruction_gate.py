#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real assembled modern-opcode controls; no control binary is executed."""
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from i486_instruction_gate import decode


class InstructionGate(unittest.TestCase):
    def assembled(self, body):
        with tempfile.TemporaryDirectory(prefix="m98-i486-control-") as directory:
            source, obj = Path(directory) / "control.s", Path(directory) / "control.o"
            source.write_text(".text\n.globl sentinel\nsentinel:\n" + body + "\n")
            subprocess.run(["i686-w64-mingw32-as", "--32", str(source), "-o", str(obj)], check=True,
                           capture_output=True, timeout=10)
            result = subprocess.run(["i686-w64-mingw32-objdump", "-d", "-z", "--show-raw-insn",
                                     "--insn-width=16", str(obj)], check=True, capture_output=True,
                                    timeout=10)
            return result.stdout.decode("ascii")

    def test_actual_modern_after_no_operand(self):
        for predecessor in ("nop", "ret", "fldz"):
            for modern in ("mfence", "vzeroupper", "cpuid", "ud2", "cmove %eax,%eax",
                           "fcomip %st(1),%st", "fxsave (%eax)", "tzcnt %eax,%eax",
                           "mov %cr4,%eax"):
                with self.subTest(predecessor=predecessor, modern=modern):
                    with self.assertRaises(ValueError):
                        decode(self.assembled(predecessor + "\n" + modern + "\nret"))

    def test_actual_base_with_prefixes(self):
        row = decode(self.assembled("nop\nrep movsl\nlock cmpxchg %ecx,(%eax)\nfnsave (%eax)\nfrstor (%eax)\nbtl $1,(%eax)\nbtsl $1,(%eax)\nbtrl $1,(%eax)\nbtcl $1,(%eax)\nbsfl (%eax),%eax\nbsrl (%eax),%eax\nret"))
        self.assertGreaterEqual(row["instructions_decoded"], 12)

    def test_unknown_truncated_prefix_and_coverage(self):
        for row in ("401000: 90 nop\n401001: 0f .byte 0xf", "401000: 90 lock",
                    "401000: 90 (bad)", "401000: 90 rep vzeroupper"):
            with self.subTest(row=row), self.assertRaises(ValueError):
                decode(row)
        with self.assertRaises(ValueError):
            decode("Disassembly of section .text:\n401000: 90 nop", {
                ".text": {"address": 0x401000, "data": b"\x90\xc3"}})


if __name__ == "__main__":
    unittest.main()
