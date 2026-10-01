#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict ordered numeric WAMR protocol; logs alone are not native evidence."""
import re

from css_mshtml_native_log import fields, uint

PREFIX = "C:\\GOPLAB\\"
EXPORTS = ("open", "close", "load", "unload", "instantiate", "instance_close",
           "call", "memory_size", "memory_grow", "memory_read", "memory_write", "inspect")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def lines(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 65536 and raw.endswith(b"\r\n"),
         "empty, oversized or partial numeric log")
    result = raw[:-2].decode("ascii").split("\r\n")
    need(all(0 < len(line) <= 512 and "=" in line and "\r" not in line and "\n" not in line
             for line in result), "malformed numeric log row")
    return result


def oracle(host_raw):
    observed = lines(host_raw)
    need(observed[:2] == ["SCOPE=actual-host-engine-guest-oracles", "NATIVE_EXECUTION=0"] and
         observed[-3:] == ["CHECKS=244", "FAILURES=0", "STATUS=PASS"],
         "approved actual host oracle profile/count required")
    checks = observed[2:-3]
    need(len(checks) == 244 and all(re.fullmatch(r"CHECK:[a-z0-9_]{1,96}=1", c) for c in checks),
         "host oracle is incomplete or contains failures")
    return checks


def component(raw, nonce, host_raw):
    need(isinstance(nonce, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", nonce), "invalid nonce")
    expected = ["M98_WASM_PROBE=1", "NONCE=" + nonce, "CHECK:actual_os_query=1",
        "OS_PLATFORM=1", "OS_MAJOR=4", "OS_MINOR=10", "OS_BUILD_LOW=2222", "ACP=949",
        "CHECK:actual_win98_se_korean_identity=1", "CHECK:exact_native_probe_path=1",
        "CHECK:load_exact_adjacent_runtime=1", "CHECK:actual_adjacent_runtime_path=1",
        "MODULE_PATH=" + PREFIX + "M98WASM.DLL"]
    expected += ["CHECK:resolve_m98_wasm_" + n + "=1" for n in EXPORTS]
    expected += ["CHECK:runtime_original_crt_loaded=1", "CHECK:actual_system_directory=1",
        "CHECK:original_system_crt_exact_path=1", "SYSTEM_CRT_PATH=", *oracle(host_raw),
        "CHECK:owned_runtime_module_released=1", "REAL_NUMERIC_WAMR=1", "FULL_BROWSER_WASM=0",
        "CHECKS=265", "FAILURES=0", "STATUS=PASS"]
    observed = lines(raw)
    need(len(observed) == len(expected), "numeric log row count differs")
    system_crt = None
    for actual, wanted in zip(observed, expected):
        if wanted.startswith("MODULE_PATH="):
            need(actual.lower() == wanted.lower(), "wrong adjacent runtime path")
        elif wanted == "SYSTEM_CRT_PATH=":
            need(re.fullmatch(r"SYSTEM_CRT_PATH=[A-Za-z]:\\[A-Za-z0-9 _-]{1,64}\\SYSTEM\\MSVCRT\.DLL",
                              actual, re.I), "wrong original system CRT path")
            system_crt = actual.split("=", 1)[1]
        else:
            need(actual == wanted, "missing, reordered or failed numeric check: " + wanted)
    return dict(checks=265, shared_real_engine_checks=244, complete_x87_boundary=True,
                original_system_crt=system_crt, numeric_component_only=True,
                browser_webassembly_verified=False, full_modern_wasm_verified=False)


def observer(raw, nonce):
    observed = fields(raw)
    expected = dict(scope="actual-win98-wasm-owned-child-observer", nonce=nonce,
        profile="genuine-wamr-numeric-c-abi", WIN98_IDENTIFIED="1")
    expected.update({"os.major": "4", "os.minor": "10", "os.build-low": "2222", "os.platform": "1",
        "child.path": PREFIX + "WAS13PR.EXE", "child.stdout": PREFIX + "WAOUT.LOG",
        "child.created": "1", "child.create-error": "0", "child.wait": "0", "child.exit-query": "1",
        "child.exit-query-error": "0", "child.exit-code": "0", "child.stdout-flushed": "1",
        "child.handles-closed": "1", "child.success": "1", "supervisor.requested-exit-code": "0"})
    need(set(observed) == set(expected) | {"child.pid"} and
         all(observed[k] == v for k, v in expected.items()), "actual owned child completion missing")
    pid = uint(observed["child.pid"])
    need(pid > 0, "actual child PID required")
    return pid
