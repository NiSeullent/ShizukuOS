#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reject real newer opcodes and missing decode coverage; no PE execution."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("tested_i486_gate", HERE / "i486_gate.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def row(raw, mnemonic, operands="", address=0x401000):
    return f" {address:x}:\t{' '.join(f'{x:02x}' for x in raw)}\t{mnemonic}\t{operands}".rstrip()


def minimal_pe(code, second=b"\x90", machine=0x14c):
    data = bytearray(1536)
    data[:2] = b"MZ"; struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 2, 0, 0, 0, 224, 0x102)
    o = 0x98
    struct.pack_into("<H", data, o, 0x10b)
    struct.pack_into("<IIIIII", data, o+4, 1024, 0, 0, 0x1000, 0x1000, 0)
    struct.pack_into("<III", data, o+28, 0x400000, 4096, 512)
    struct.pack_into("<HH", data, o+40, 4, 10)
    struct.pack_into("<HH", data, o+48, 4, 10)
    struct.pack_into("<II", data, o+56, 0x3000, 512)
    struct.pack_into("<H", data, o+68, 3)
    struct.pack_into("<IIIIII", data, o+72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    for i, name in enumerate((b".text", b".extra")):
        struct.pack_into("<8sIIIIIIHHI", data, o+224+i*40, name, 512, 0x1000+i*4096,
                         512, 512+i*512, 0, 0, 0, 0, 0x60000020)
    data[512:1024] = code + b"\x90"*(512-len(code))
    data[1024:1536] = second + b"\x90"*(512-len(second))
    return data


class InstructionGateTests(unittest.TestCase):
    def test_legacy_string_aliases_and_x87(self):
        cases = [(b"\xf3\xaa", "rep", "stos %al,%es:(%edi)"),
                 (b"\xf3\xab", "rep", "stos %eax,%es:(%edi)"),
                 (b"\x66\x90", "xchg", "%ax,%ax"),
                 (b"\x0f\xc8", "bswap", "%eax"),
                 (b"\x0f\xb1\xd0", "cmpxchg", "%edx,%eax"),
                 (b"\xd9\xe8", "fld1", ""), (b"\xdf\x3c\x24", "fistpll", "(%esp)")]
        for raw, name, operands in cases:
            with self.subTest(name=name, raw=raw.hex()):
                self.assertTrue(GATE.acceptable(name, operands, raw))

    def test_newer_mnemonics_and_multibyte_nop_rejected(self):
        cases = [(b"\x0f\x4f\xd8", "cmovg", "%eax,%ebx"),
                 (b"\x0f\x31", "rdtsc", ""), (b"\x0f\xa2", "cpuid", ""),
                 (b"\x0f\x1f\x00", "nopl", "(%eax)"),
                 (b"\x0f\x1f\x00", "nop", "(%eax)"),
                 (b"\x66\x0f\xef\xc0", "pxor", "%xmm0,%xmm0"),
                 (b"\x0f\xc7\x08", "cmpxchg8b", "(%eax)"),
                 (b"\xdf\xf1", "fcomip", "%st(1),%st"),
                 (b"\xf3\x90", "pause", ""), (b"\x90", "mov", "%xmm0,%eax")]
        for raw, name, operands in cases:
            with self.subTest(name=name):
                self.assertFalse(GATE.acceptable(name, operands, raw))

    def test_exact_byte_address_coverage_and_symbol(self):
        code = b"\x90\x0f\x4f\xd8"
        sections = {".text": {"address": 0x401000, "bytes": code}}
        text = "Disassembly of section .text:\n00401000 <linked_formatter>:\n" + \
            row(b"\x90", "nop") + "\n" + row(code[1:], "cmovg", "%eax,%ebx", 0x401001)
        result = GATE.inspect_decode(text, sections)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["coverage_errors"], [])
        self.assertEqual(result["non_i486_instructions"][0]["symbol"], "linked_formatter")
        self.assertEqual(result["non_i486_instructions"][0]["raw"], "0f4fd8")

    def test_gap_tampered_bytes_and_missing_section(self):
        sections = {".text": {"address": 0x401000, "bytes": b"\x90"}}
        for text in ("Disassembly of section .text:\n" + row(b"\x90", "nop", address=0x401001),
                     "Disassembly of section .text:\n" + row(b"\xc3", "ret"),
                     "Disassembly of section .other:\n" + row(b"\x90", "nop"),
                     "Disassembly of section .text:\n 401000: 90", "no instructions"):
            with self.subTest(text=text):
                self.assertEqual(GATE.inspect_decode(text, sections)["status"], "FAIL")

    def test_all_real_pe_sections_are_decoded(self):
        with tempfile.TemporaryDirectory(prefix="ntwst-isa-", dir=HERE.parents[1]/"build") as tmp:
            path = Path(tmp)/"fixture.exe"
            path.write_bytes(minimal_pe(b"\xc3"))
            report, _ = GATE.scan(path)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(set(report["sections"]), {".text", ".extra"})
            self.assertEqual(sum(x["decoded_bytes"] for x in report["sections"].values()), 1024)
            path.write_bytes(minimal_pe(b"\xc3", b"\x0f\x4f\xd8"))
            report, _ = GATE.scan(path)
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["non_i486_instructions"][0]["section"], ".extra")
            path.write_bytes(minimal_pe(b"\xc3", machine=0x8664))
            with self.assertRaises(ValueError): GATE.scan(path)


if __name__ == "__main__":
    unittest.main()
