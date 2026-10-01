#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Adversarial protocol controls; every native row here is synthetic."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from wasm_native_log import component, observer, oracle

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "build/wasm-native-probe-v6/host-test.log"
NONCE = "wasm-numeric-5abe-20261001-v5"


def encode(rows):
    return ("\r\n".join(rows) + "\r\n").encode("ascii")


def fixture():
    # Explicit Win98 frontend order is independent of parser's expected table.
    rows = ["M98_WASM_PROBE=1", "NONCE=" + NONCE, "CHECK:actual_os_query=1",
        "OS_PLATFORM=1", "OS_MAJOR=4", "OS_MINOR=10", "OS_BUILD_LOW=2222", "ACP=949",
        "CHECK:actual_win98_se_korean_identity=1", "CHECK:exact_native_probe_path=1",
        "CHECK:load_exact_adjacent_runtime=1", "CHECK:actual_adjacent_runtime_path=1",
        "MODULE_PATH=C:\\GOPLAB\\M98WASM.DLL",
        "CHECK:resolve_m98_wasm_open=1", "CHECK:resolve_m98_wasm_close=1",
        "CHECK:resolve_m98_wasm_load=1", "CHECK:resolve_m98_wasm_unload=1",
        "CHECK:resolve_m98_wasm_instantiate=1", "CHECK:resolve_m98_wasm_instance_close=1",
        "CHECK:resolve_m98_wasm_call=1", "CHECK:resolve_m98_wasm_memory_size=1",
        "CHECK:resolve_m98_wasm_memory_grow=1", "CHECK:resolve_m98_wasm_memory_read=1",
        "CHECK:resolve_m98_wasm_memory_write=1", "CHECK:resolve_m98_wasm_inspect=1",
        "CHECK:runtime_original_crt_loaded=1", "CHECK:actual_system_directory=1",
        "CHECK:original_system_crt_exact_path=1", "SYSTEM_CRT_PATH=C:\\WINDOWS\\SYSTEM\\MSVCRT.DLL"]
    host = HOST.read_bytes().decode("ascii").split("\r\n")
    rows += host[2:-4]
    rows += ["CHECK:owned_runtime_module_released=1", "REAL_NUMERIC_WAMR=1",
             "FULL_BROWSER_WASM=0", "CHECKS=265", "FAILURES=0", "STATUS=PASS"]
    return rows


def observer_fixture():
    return dict(scope="actual-win98-wasm-owned-child-observer", nonce=NONCE,
        profile="genuine-wamr-numeric-c-abi", WIN98_IDENTIFIED="1",
        **{"os.major": "4", "os.minor": "10", "os.build-low": "2222", "os.platform": "1",
           "child.path": "C:\\GOPLAB\\WAS13PR.EXE", "child.stdout": "C:\\GOPLAB\\WAOUT.LOG",
           "child.created": "1", "child.create-error": "0", "child.wait": "0", "child.exit-query": "1",
           "child.exit-query-error": "0", "child.exit-code": "0", "child.stdout-flushed": "1",
           "child.handles-closed": "1", "child.success": "1", "supervisor.requested-exit-code": "0",
           "child.pid": "4321"})


class Protocol(unittest.TestCase):
    def setUp(self):
        self.host = HOST.read_bytes()
        self.rows = fixture()

    def parse(self, rows):
        return component(encode(rows), NONCE, self.host)

    def test_valid_component_stays_bounded(self):
        result = self.parse(self.rows)
        self.assertEqual(result["checks"], 265)
        self.assertFalse(result["browser_webassembly_verified"])
        self.assertFalse(result["full_modern_wasm_verified"])
        self.assertEqual(len(oracle(self.host)), 244)

    def test_every_required_row_missing_or_extra_rejected(self):
        for index in range(len(self.rows)):
            with self.subTest(index=index):
                with self.assertRaises(ValueError): self.parse(self.rows[:index] + self.rows[index + 1:])
                with self.assertRaises(ValueError): self.parse(self.rows[:index] + [self.rows[index]] + self.rows[index:])

    def test_every_check_failure_rejected(self):
        for index, row in enumerate(self.rows):
            if row.startswith("CHECK:"):
                bad = self.rows.copy(); bad[index] = row[:-1] + "0"
                with self.subTest(index=index), self.assertRaises(ValueError): self.parse(bad)

    def test_reordered_distinct_checks_and_generation_rejected(self):
        a = self.rows.copy(); a[25], a[26] = a[26], a[25]
        with self.assertRaises(ValueError): self.parse(a)
        for before, after in (("NONCE=" + NONCE, "NONCE=old"), ("ACP=949", "ACP=1252"),
            ("CHECKS=265", "CHECKS=264"), ("FULL_BROWSER_WASM=0", "FULL_BROWSER_WASM=1"),
            ("MODULE_PATH=C:\\GOPLAB\\M98WASM.DLL", "MODULE_PATH=C:\\OTHER\\M98WASM.DLL"),
            ("SYSTEM_CRT_PATH=C:\\WINDOWS\\SYSTEM\\MSVCRT.DLL", "SYSTEM_CRT_PATH=C:\\GOPLAB\\MSVCRT.DLL")):
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.parse([after if row == before else row for row in self.rows])

    def test_partial_non_ascii_and_wrong_host_oracle_rejected(self):
        valid = encode(self.rows)
        for bad in (b"", valid[:-1], valid.replace(b"\r\n", b"\n"), valid + b"\xff\r\n", b"x=" + b"a" * 65536):
            with self.assertRaises(ValueError): component(bad, NONCE, self.host)
        with self.assertRaises(ValueError): component(valid, NONCE, self.host.replace(b"=1\r\n", b"=0\r\n", 1))
        with self.assertRaises(ValueError): component(valid, NONCE, self.host.replace(b"CHECKS=244", b"CHECKS=243"))

    def test_actual_full_dword_and_lifecycle_required(self):
        base = observer_fixture()
        self.assertEqual(observer(encode([k + "=" + v for k, v in base.items()]), NONCE), 4321)
        for key, bad in (("child.exit-code", "3221225477"), ("child.exit-code", "259"),
            ("child.pid", "0"), ("child.pid", "4294967296"), ("child.pid", "04321"),
            ("child.stdout-flushed", "0"), ("child.handles-closed", "0"),
            ("child.exit-query", "0"), ("supervisor.requested-exit-code", "1")):
            values = base | {key: bad}
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                observer(encode([k + "=" + v for k, v in values.items()]), NONCE)
        for key in base:
            with self.subTest(missing=key), self.assertRaises(ValueError):
                observer(encode([k + "=" + v for k, v in base.items() if k != key]), NONCE)
        with self.assertRaises(ValueError): observer(encode([k + "=" + v for k, v in base.items()] + ["child.pid=4321"]), NONCE)


if __name__ == "__main__":
    unittest.main()
