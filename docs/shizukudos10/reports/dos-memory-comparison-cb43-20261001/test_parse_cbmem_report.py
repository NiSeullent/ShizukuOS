#!/usr/bin/env python3
"""Synthetic parser fixtures only: no DOS/BIOS execution or guest memory proof."""
import unittest
from parse_cbmem_report import parse_and_interpret, ReportFormatError

KERNEL = "62194db22e7d157865f9767c78ca3ecf7d7977d720a99a1afe8c8c02b1aebb3f"
PROBE = "0a93f6402ada0478ae6d95f1e02169e8f7fdd5b30c1353c0ec9d54bf00048c18"
NAMES = (
    "PHASE INT12_TOTAL_KB COM_CS CURRENT_PSP AX3306_AX AX3306_BX AX3306_DX "
    "AX3306_FLAGS AX3306_DH_BIT4_RAW AX5800_STRATEGY AX5800_FLAGS AX5802_RAW_AX "
    "AX5802_FLAGS MCB_TYPE_BEFORE MCB_OWNER_BEFORE MCB_PARAS_BEFORE PSP_END_BEFORE "
    "SELF_KEEP_PARAS AH4A_AX AH4A_BX AH4A_FLAGS MCB_TYPE_AFTER MCB_OWNER_AFTER "
    "MCB_PARAS_AFTER PSP_END_AFTER AH48_AX AH48_LARGEST_PARAS AH48_FLAGS "
    "LARGEST_KB_FLOOR UNEXPECTED_OWN_SEG CLEANUP_AH49_AX CLEANUP_AH49_FLAGS "
    "CHECKS FAILURES"
).split()
VALUES = [7,639,0x2000,0x2000,0x3306,0x0a07,0,0x202,0,0,0x202,0x5800,
          0x202,ord('Z'),0x2000,0x7fc0,0x9fc0,322,0x4a00,322,0x202,ord('M'),
          0x2000,322,0x9fc0,8,0x7000,0x203,448,0xffff,0xffff,0xffff,11,0]


def synthetic_report(changes=None):
    fields = dict(zip(NAMES, VALUES))
    fields.update(changes or {})
    lines = ["CB43 DOS MEMORY V1",
             "All values are raw 16-bit hexadecimal; FFFF can mean not measured."]
    lines += [f"{name}={fields[name]:04X}" for name in NAMES]
    lines += ["END=0001", "I/O and process outcome require actual DOS ERRORLEVEL."]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def interpret(changes=None, marker=b"CBMEM_ERRORLEVEL=0\r\n", kernel=KERNEL, probe=PROBE):
    return parse_and_interpret(synthetic_report(changes), marker, kernel, probe)


class ReportTests(unittest.TestCase):
    def test_valid_low_below_580_is_scoped_pass_and_never_windows_proof(self):
        r = interpret()
        self.assertTrue(r["acceptance_passed"])
        self.assertEqual(r["reported_memory"]["largest_kib_floor"],448)
        self.assertFalse(r["reported_HMA"]["DOS_in_HMA"])
        self.assertFalse(r["native_execution_verified"])
        self.assertFalse(r["Windows98_verified"])
        self.assertFalse(r["MSDOS_replacement_under_Windows98"])

    def test_high_uses_actual_raw_bit(self):
        r = interpret({"AX3306_DX":0x1000,"AX3306_DH_BIT4_RAW":0x1000})
        self.assertTrue(r["acceptance_passed"])
        self.assertTrue(r["reported_HMA"]["DOS_in_HMA"])

    def test_zero_largest_is_a_valid_measurement_not_580_gate(self):
        self.assertTrue(interpret({"AH48_LARGEST_PARAS":0,"LARGEST_KB_FLOOR":0})["acceptance_passed"])

    def test_preserves_undefined_success_registers_and_raw_flags(self):
        changes={"AH4A_AX":0xffee,"AH4A_BX":0xface,"AX3306_FLAGS":0xffff,
                 "AX5802_RAW_AX":0xab00,"PSP_END_AFTER":0xffff,"AH48_FLAGS":0xffff}
        r=interpret(changes)
        self.assertTrue(r["acceptance_passed"])
        for k,v in changes.items():self.assertEqual(r["raw_fields"][k],v)
        self.assertEqual(r["raw_fields"]["CLEANUP_AH49_AX"],0xffff)

    def test_header_footer_and_crlf_malformed(self):
        report=synthetic_report()
        cases=[report.replace(b"MEMORY V1",b"MEMORY V2"),report[:-2],
               report.replace(b"END=0001",b"END=0000"),report.replace(b"\r\n",b"\n"),
               report+b"EXTRA=0000\r\n",report.replace(b"PHASE=0007",b"PHASE=000g"),
               report.replace(b"CURRENT_PSP=2000",b"CURRENT_PSP=20000"),
               report.replace(b"COM_CS=2000",b"COM_CS=20\xff0")]
        for data in cases:
            with self.subTest(data=data[:40]):
                with self.assertRaises(ReportFormatError):parse_and_interpret(data,b"CBMEM_ERRORLEVEL=0\r\n",KERNEL,PROBE)

    def test_duplicate_missing_unknown_and_reordered_fields_rejected(self):
        data=synthetic_report()
        cases=[data.replace(b"AX3306_BX=0A07",b"AX3306_AX=0A07"),
               data.replace(b"CURRENT_PSP=2000\r\n",b""),
               data.replace(b"CURRENT_PSP=2000",b"PRIVATE_PSP=2000"),
               data.replace(b"COM_CS=2000\r\nCURRENT_PSP=2000",b"CURRENT_PSP=2000\r\nCOM_CS=2000")]
        for r in cases:
            with self.assertRaises(ReportFormatError):parse_and_interpret(r,b"CBMEM_ERRORLEVEL=0\r\n",KERNEL,PROBE)

    def test_exact_separate_marker_required(self):
        for marker in [b"",b"CBMEM_ERRORLEVEL=0",b"CBMEM_ERRORLEVEL=0\n",b"CBMEM_ERRORLEVEL=00\r\n",
                       b"CBMEM_ERRORLEVEL=-1\r\n",b"CBMEM_ERRORLEVEL=256\r\n",b"CBMEM_ERRORLEVEL=0\r\nCBMEM_ERRORLEVEL=0\r\n",
                       b"CBMEM_ERRORLEVEL=0  \r\n",b"CBMEM_ERRORLEVEL=0\t\r\n"]:
            with self.subTest(marker=marker):
                with self.assertRaises(ReportFormatError):parse_and_interpret(synthetic_report(),marker,KERNEL,PROBE)

    def test_single_FreeCOM_trailing_space_marker_preserved(self):
        marker=b"CBMEM_ERRORLEVEL=0 \r\n"
        r=interpret(marker=marker)
        self.assertTrue(r["acceptance_passed"])
        self.assertEqual(r["marker_bytes"],21)

    def test_nonzero_real_errorlevel_rejects_even_complete_report(self):
        for code in [1,2,255]:
            self.assertFalse(interpret(marker=f"CBMEM_ERRORLEVEL={code}\r\n".encode())["acceptance_passed"])

    def test_normal_path_phase_counter_and_failure_gates(self):
        for changes in [{"PHASE":6},{"CHECKS":10},{"FAILURES":1}]:
            self.assertFalse(interpret(changes)["acceptance_passed"])

    def test_only_actual_owned_valid_block_is_accepted(self):
        for changes in [{"CURRENT_PSP":0x2001},{"COM_CS":0,"CURRENT_PSP":0},
                        {"MCB_OWNER_BEFORE":8},{"MCB_OWNER_AFTER":0},
                        {"MCB_TYPE_BEFORE":0},{"MCB_TYPE_AFTER":0},
                        {"MCB_PARAS_BEFORE":321},{"MCB_PARAS_AFTER":323},{"SELF_KEEP_PARAS":321},
                        {"MCB_PARAS_BEFORE":0xffff}]:
            with self.subTest(changes=changes):self.assertFalse(interpret(changes)["acceptance_passed"])

    def test_resize_allocator_raw_carry_and_ax_contracts(self):
        for changes in [{"AH4A_FLAGS":0x203},{"AH48_FLAGS":0x202},{"AH48_AX":7},
                        {"UNEXPECTED_OWN_SEG":0x9000},{"CLEANUP_AH49_FLAGS":0}]:
            self.assertFalse(interpret(changes)["acceptance_passed"])

    def test_allocator_and_umb_are_measured_not_inferred(self):
        for strategy in [0,1,2]:self.assertTrue(interpret({"AX5800_STRATEGY":strategy})["acceptance_passed"])
        for changes in [{"AX5800_STRATEGY":0x40},{"AX5800_FLAGS":0x203},
                        {"AX5802_RAW_AX":0x5801},{"AX5802_FLAGS":0x203}]:
            self.assertFalse(interpret(changes)["acceptance_passed"])

    def test_kib_and_bios_consistency(self):
        for changes in [{"LARGEST_KB_FLOOR":449},{"INT12_TOTAL_KB":0},{"INT12_TOTAL_KB":641},
                        {"AH48_LARGEST_PARAS":0x9fc0,"LARGEST_KB_FLOOR":639},
                        {"INT12_TOTAL_KB":128},{"AH48_LARGEST_PARAS":0xffff,"LARGEST_KB_FLOOR":1023}]:
            self.assertFalse(interpret(changes)["acceptance_passed"])

    def test_unknown_source_identity_preserves_raw_but_never_decodes_hma(self):
        for kernel,probe in [("0"*64,PROBE),(KERNEL,"0"*64)]:
            r=interpret(kernel=kernel,probe=probe)
            self.assertFalse(r["acceptance_passed"])
            self.assertFalse(r["reported_HMA"]["interpretable"])
            self.assertIsNone(r["reported_HMA"]["DOS_in_HMA"])
            self.assertEqual(r["raw_fields"]["AX3306_DX"],0)

    def test_true_version_and_raw_hma_consistency(self):
        for changes in [{"AX3306_BX":0x6407},{"AX3306_BX":0x0a04},
                        {"AX3306_AX":0x33ff},{"AX3306_DH_BIT4_RAW":0x1000}]:
            self.assertFalse(interpret(changes)["acceptance_passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
