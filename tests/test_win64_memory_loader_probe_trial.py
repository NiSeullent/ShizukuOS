# SPDX-License-Identifier: GPL-2.0-only
"""Reject stale/spoofed guest evidence and preserve honest loader-only failures."""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("loader_order_trial_tests", ROOT / "tools/win64_memory_loader_probe_trial.py")
trial = importlib.util.module_from_spec(spec); spec.loader.exec_module(trial)
NONCE = "1234567890abcdef1234567890abcdef"


def fixture(loaded=True):
    prefix = "[win64 LOADP64.EXE pid 60] "
    lines = ["K64 autorun: starting D:\\loadprobe\\LOADP64.EXE (cwd D:\\loadprobe, timeout 30 s)", "K64 autorun: started pid 60"]
    records = ["LP64 BEGIN " + NONCE, "LP64 PASS relocated_probe_anchor",
               "LP64 ORDER fiber_exw_system32_then_kbase_exw_exa_plain_absolute_before_file_io",
               "LP64 VALUE fiber_first_exw_system32 value=0000000000000000 error=126",
               "LP64 PASS exact_unprovided_fiber_contract_refused"]
    names = ["relocated_probe_anchor", "exact_unprovided_fiber_contract_refused"]
    failures = 0
    for value_name, check_name in (
        ("load_first_exw_system32", "kernelbase_load_first_exw_system32_before_file_io"),
        ("load_exa_system32", "kernelbase_load_exa_system32_before_file_io"),
        ("load_lower_basename", "kernelbase_load_lower_basename"),
        ("load_upper_basename", "kernelbase_load_upper_basename"),
        ("load_absolute", "kernelbase_load_absolute"),
    ):
        records.append(f"LP64 VALUE {value_name} value={0x180000000 if loaded else 0:016x} error={0 if loaded else 126}")
        records.append("LP64 " + ("PASS " if loaded else "FAIL ") + check_name)
        names.append(check_name); failures += not loaded
    records.append("LP64 ORDER all_initial_kbase_load_attempts_complete_before_file_io")
    other_names = ["serial_output_complete", "kernelbase_file_attributes_a", "kernelbase_file_attributes_w", "kernelbase_live_file_read_open"]
    if loaded:
        other_names += ["kernelbase_live_file_exact_size", "kernelbase_live_file_mz_header", "genuine_kernel32_forwarder"]
    for name in other_names:
        good = loaded or name == "serial_output_complete"
        records.append("LP64 " + ("PASS " if good else "FAIL ") + name)
        failures += not good
    names += other_names
    values = {"attributes_a": 0x80 if loaded else 0xffffffff, "attributes_w": 0x80 if loaded else 0xffffffff,
              "file_open": 0x888 if loaded else 0}
    if loaded:
        values.update(file_size=69609, file_read_bytes=64, file_mz=0x5a4d,
                      VirtualAlloc2=0x180001040, MapViewOfFile3=0x180001010, UnmapViewOfFile2=0x180001020, GetCurrentProcessId=0x181002020)
        records += ["LP64 PASS " + name for name in ("VirtualAlloc2", "MapViewOfFile3", "UnmapViewOfFile2", "GetCurrentProcessId")]
        names += ["VirtualAlloc2", "MapViewOfFile3", "UnmapViewOfFile2", "GetCurrentProcessId"]
    for name, value in values.items(): records.append(f"LP64 VALUE {name} value={value:016x} error={0 if loaded else 2}")
    if loaded:
        records += ["LP64 MEMORY BEGIN"] + ["LP64 PASS " + name for name in trial.MANDATORY_MEMORY] + ["LP64 MEMORY DONE"]
        names += list(trial.MANDATORY_MEMORY)
    records += [f"LP64 COUNTS checks={len(names)} failures={failures}", "LP64 FINAL " + ("PASS " if loaded else "FAIL ") + NONCE]
    lines += [prefix + line for line in records]
    lines += [f"K64 autorun: result exited exit={0 if loaded else 1} faulted=0 reaped=0 after 200 ms"]
    return "\n".join(lines) + "\n"


class Evidence(unittest.TestCase):
    def test_real_complete_gate(self):
        data = trial.parse_evidence(fixture(), NONCE)
        self.assertEqual(data["status"], "PASS"); self.assertTrue(data["basic_memory_subset_verified"])
        self.assertEqual(data["normal_exit_code"], 0); self.assertEqual(data["proc_wait_return_code"], 0)

    def test_absent_module_diagnostic_is_honest(self):
        data = trial.parse_evidence(fixture(False), NONCE)
        self.assertEqual(data["status"], "FAIL"); self.assertFalse(data["basic_memory_subset_verified"])
        self.assertEqual(data["normal_exit_code"], 1); self.assertTrue(data["kernel_child_reaped"])
        self.assertEqual(data["values"]["load_absolute"]["last_error"], 126)

    def test_loader_failure_does_not_erase_independent_memory(self):
        serial = fixture().replace("LP64 PASS kernelbase_load_lower_basename", "LP64 FAIL kernelbase_load_lower_basename")
        serial = serial.replace("load_lower_basename value=0000000180000000", "load_lower_basename value=0000000000000000")
        serial = serial.replace("failures=0", "failures=1").replace("LP64 FINAL PASS", "LP64 FINAL FAIL").replace("exit=0", "exit=1")
        data = trial.parse_evidence(serial, NONCE)
        self.assertEqual(data["status"], "FAIL"); self.assertTrue(data["basic_memory_subset_verified"])
        self.assertFalse(data["loader_basename_and_absolute_verified"])

    def test_extra_memory_failure_prevents_subset_claim(self):
        serial = fixture().replace("[win64 LOADP64.EXE pid 60] LP64 MEMORY DONE",
                                   "[win64 LOADP64.EXE pid 60] LP64 FAIL extra_memory_protection\n[win64 LOADP64.EXE pid 60] LP64 MEMORY DONE")
        serial = re.sub(r"COUNTS checks=(\d+) failures=0", lambda m: f"COUNTS checks={int(m[1]) + 1} failures=1", serial)
        serial = serial.replace("LP64 FINAL PASS", "LP64 FINAL FAIL").replace("exit=0", "exit=1")
        data = trial.parse_evidence(serial, NONCE)
        self.assertEqual(data["status"], "FAIL"); self.assertFalse(data["basic_memory_subset_verified"])

    def test_missing_memory_scope_prevents_claim(self):
        data = trial.parse_evidence(fixture().replace("LP64 MEMORY BEGIN", "LP64 SCOPE IGNORED"), NONCE)
        self.assertFalse(data["basic_memory_subset_verified"]); self.assertEqual(data["status"], "FAIL")

    def rejected(self, old, new):
        with self.assertRaises(ValueError): trial.parse_evidence(fixture().replace(old, new), NONCE)

    def test_wrong_nonce(self): self.rejected("LP64 BEGIN " + NONCE, "LP64 BEGIN " + "0" * 32)
    def test_wrong_pid(self): self.rejected("LOADP64.EXE pid 60", "LOADP64.EXE pid 61")
    def test_wrong_exe(self): self.rejected("[win64 LOADP64.EXE", "[win64 OTHER.EXE")
    def test_unprefixed(self): self.rejected("[win64 LOADP64.EXE pid 60] ", "")
    def test_wrong_volume(self): self.rejected("D:\\loadprobe\\LOADP64.EXE", "D:\\other\\LOADP64.EXE")
    def test_ambiguous_autorun(self): self.rejected("K64 autorun: started pid 60", "K64 autorun: started pid 60\nK64 autorun: started pid 61")
    def test_missing_begin(self): self.rejected("LP64 BEGIN", "IGNORED BEGIN")
    def test_duplicate_final(self):
        self.rejected("LP64 FINAL PASS " + NONCE, "LP64 FINAL PASS " + NONCE + "\n[win64 LOADP64.EXE pid 60] LP64 FINAL PASS " + NONCE)
    def test_counts_mismatch(self): self.rejected("failures=0", "failures=1")
    def test_no_individual_memory_check(self): self.rejected("LP64 PASS copy_view_private_write", "LP64 VALUE ignored value=0000000000000000 error=0")
    def test_zero_api_address(self): self.rejected("VirtualAlloc2 value=0000000180001040", "VirtualAlloc2 value=0000000000000000")
    def test_load_handle_assertion_disagreement(self): self.rejected("load_absolute value=0000000180000000", "load_absolute value=0000000000000000")
    def test_attributes_disagreement(self): self.rejected("attributes_a value=0000000000000080", "attributes_a value=00000000ffffffff")
    def test_size_disagreement(self): self.rejected("file_size value=0000000000010fe9", "file_size value=0000000000000000")
    def test_mz_disagreement(self): self.rejected("file_mz value=0000000000005a4d", "file_mz value=0000000000000000")
    def test_no_external_exit(self): self.rejected("K64 autorun: result exited", "SHZEXIT result exited")
    def test_nonzero_external_exit(self): self.rejected("exit=0", "exit=1")
    def test_failure_exit_missing(self):
        with self.assertRaises(ValueError): trial.parse_evidence(fixture(False).replace("exit=1", "exit=0"), NONCE)
    def test_timeout(self): self.rejected("result exited", "result timeout")
    def test_faulted(self): self.rejected("faulted=0", "faulted=1")
    def test_not_reaped(self): self.rejected("reaped=0", "reaped=-1")
    def test_early_alive_semantics(self): self.rejected("reaped=0 after", "reaped=0 (1 thread(s) still alive) after")
    def test_exception(self): self.rejected("after 200 ms", "after 200 ms\nK64 EXCEPTION bad memory")
    def test_duplicate_values(self):
        self.rejected("LP64 VALUE file_mz value=0000000000005a4d error=0", "LP64 VALUE file_mz value=0000000000005a4d error=0\n[win64 LOADP64.EXE pid 60] LP64 VALUE file_mz value=0000000000005a4d error=0")

    def test_missing_order_begin(self):
        self.rejected("LP64 ORDER fiber_exw_system32_then_kbase_exw_exa_plain_absolute_before_file_io", "LP64 IGNORED")
    def test_missing_order_end(self):
        self.rejected("LP64 ORDER all_initial_kbase_load_attempts_complete_before_file_io", "LP64 IGNORED")
    def test_reversed_ex_order(self):
        self.rejected("LP64 VALUE load_first_exw_system32", "LP64 VALUE wrong_first")
    def test_file_inspection_before_loads(self):
        self.rejected("LP64 ORDER fiber_exw_system32_then_kbase_exw_exa_plain_absolute_before_file_io",
                      "LP64 VALUE attributes_prewarm value=0000000000000080 error=0\n[win64 LOADP64.EXE pid 60] LP64 ORDER fiber_exw_system32_then_kbase_exw_exa_plain_absolute_before_file_io")
    def test_wrong_fiber_error(self):
        self.rejected("fiber_first_exw_system32 value=0000000000000000 error=126", "fiber_first_exw_system32 value=0000000000000000 error=2")
    def test_unexpected_fiber_module(self):
        self.rejected("fiber_first_exw_system32 value=0000000000000000", "fiber_first_exw_system32 value=0000000180000000")
    def test_ex_value_assertion_disagreement(self):
        self.rejected("load_first_exw_system32 value=0000000180000000", "load_first_exw_system32 value=0000000000000000")
    def test_ex_failure_preserves_memory_evidence(self):
        serial = fixture().replace("LP64 PASS kernelbase_load_first_exw_system32_before_file_io", "LP64 FAIL kernelbase_load_first_exw_system32_before_file_io")
        serial = serial.replace("load_first_exw_system32 value=0000000180000000", "load_first_exw_system32 value=0000000000000000")
        serial = serial.replace("failures=0", "failures=1").replace("LP64 FINAL PASS", "LP64 FINAL FAIL").replace("exit=0", "exit=1")
        data = trial.parse_evidence(serial, NONCE)
        self.assertEqual(data["status"], "FAIL"); self.assertTrue(data["basic_memory_subset_verified"])
        self.assertFalse(data["loader_basename_and_absolute_verified"])


if __name__ == "__main__": unittest.main()
