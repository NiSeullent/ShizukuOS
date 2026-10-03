#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production NTW64RUN host fault controls and actual i486 PE32 build, no VM."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SCENARIOS = (
    "normal", "remote7", "remote-fault", "remote255", "receive-fail",
    "stdin-read-fail", "stdin-send-fail", "stdin-short", "stdin-close-fail",
    "stdout-fail", "stdout-short", "stdout-zero", "wait-fail", "release-fail",
    "query", "query-output-fail", "early-child", "native-input-eof",
    "close-input-eof", "create-fail", "stderr-fail", "usage", "kill-fail",
    "receive-zero", "receive-overreported", "stdout-overreported",
)
NTW_IMPORTS = {
    "NtwQuerySubsystem64", "NtwCreateProcess64W", "NtwWaitProcess64",
    "NtwReadConsole64", "NtwWriteConsole64", "NtwCloseConsole64",
    "NtwKillProcess64", "NtwCloseProcess64",
}
NATIVE_IMPORTS = {
    "GetCommandLineA", "GetStdHandle", "WriteFile", "ReadFile",
    "MultiByteToWideChar", "GetLastError", "SetLastError", "ExitProcess",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--baseline", type=Path, help="preserved production body for an expected RED epoch")
    args = parser.parse_args()
    source = (args.baseline or ROOT / "ntwin32/win64/ntw64run.c").resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    inputs = [source, HERE / "runner_result_host.c", Path(__file__).resolve(),
              HERE / "mock/windows.h", HERE.parent / "ntw64.h", HERE.parent / "ntw32imp.def",
              ROOT / "ntwin32/prepare.py", ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"]
    before = {str(p): {"sha256": sha(p), "bytes": p.stat().st_size} for p in inputs}
    commands, hosts, pe_gate, errors = [], [], None, []

    def invoke(label, command, timeout=60):
        record = {"label": label, "command": [str(x) for x in command], "timeout_seconds": timeout}
        started = time.monotonic()
        try:
            p = subprocess.run(record["command"], cwd=ROOT, capture_output=True, timeout=timeout,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            stdout, stderr, code = p.stdout, p.stderr, p.returncode
            record["timed_out"] = False
        except subprocess.TimeoutExpired as e:
            stdout, stderr, code = e.stdout or b"", e.stderr or b"", 124
            record["timed_out"] = True
        record.update({"elapsed_seconds": time.monotonic() - started, "returncode": code})
        for stream, value in (("stdout", stdout), ("stderr", stderr)):
            p = out / f"{label}.{stream}.log"
            p.write_bytes(value)
            record[stream] = {"path": str(p), "sha256": sha(p), "bytes": len(value)}
        commands.append(record)
        return code, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")

    try:
        for compiler, extra in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            if not shutil.which(compiler):
                errors.append(f"missing compiler: {compiler}")
                continue
            _, version, _ = invoke(f"{compiler}-version", [compiler, "--version"])
            target = out / f"runner-{compiler}"
            flags = ["-std=c11", "-D_WIN32=1", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-I", HERE / "mock", "-I", HERE.parent, *extra,
                     f'-DNTW64RUN_SOURCE="{source}"']
            code, _, _ = invoke(f"{compiler}-compile", [compiler, *flags, HERE / "runner_result_host.c", "-o", target])
            profile = {"compiler": version.splitlines()[0], "sanitizers": bool(extra), "compile_returncode": code,
                       "artifact": None, "cases": []}
            hosts.append(profile)
            if code:
                errors.append(f"{compiler} host compile failed")
                continue
            profile["artifact"] = {"path": str(target), "sha256": sha(target), "bytes": target.stat().st_size}
            for scenario in SCENARIOS:
                code, stdout, stderr = invoke(f"{compiler}-{scenario}", [target, scenario], timeout=5)
                passed = code == 0 and stdout.startswith(f"PASS {scenario}:") and not stderr
                profile["cases"].append({"scenario": scenario, "returncode": code, "passed": passed})
        cc, dlltool = "i686-w64-mingw32-gcc", "i686-w64-mingw32-dlltool"
        _, cc_version, _ = invoke("mingw-version", [cc, "--version"])
        library, exe = out / "libntw32.a", out / "NTW64RUN.EXE"
        code, _, _ = invoke("mingw-importlib", [dlltool, "-k", "-d", HERE.parent / "ntw32imp.def", "-l", library])
        if code:
            raise RuntimeError("original NTW32 import library build failed")
        flags = ["-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-march=i486", "-mno-sse", "-mno-mmx",
                 "-fno-builtin", "-ffreestanding", "-fno-stack-protector", "-nostdlib",
                 "-Wl,--subsystem,console:4.10", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
                 "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp", "-Wl,--major-os-version,4",
                 "-Wl,--minor-os-version,10", "-Wl,--entry,_mainCRTStartup", "-I", HERE.parent]
        code, _, _ = invoke("mingw-frontend", [cc, *flags, "-o", exe, source, library, "-lkernel32"])
        if code:
            raise RuntimeError("actual i486 frontend PE build failed")
        spec = importlib.util.spec_from_file_location("ntw_prepare", ROOT / "ntwin32/prepare.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pe = module.PE(exe.read_bytes())
        imported = {(d["dll"].upper(), e[1]) for d in pe.imports() for e in d["entries"]}
        expected = {("NTW32.DLL", name) for name in NTW_IMPORTS} | {("KERNEL32.DLL", name) for name in NATIVE_IMPORTS}
        exports = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]["KERNEL32.DLL"]
        checks = {
            "i386": pe.u16(pe.pe + 4) == 0x14c,
            "pe32": pe.u16(pe.opt) == 0x10b,
            "os_4_10": (pe.u16(pe.opt + 40), pe.u16(pe.opt + 42)) == (4, 10),
            "subsystem_4_10": (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50)) == (4, 10),
            "console": pe.u16(pe.opt + 68) == 3,
            "exact_original_eight_ntw32_and_native_imports": imported == expected,
            "native_names_in_pinned_oem_manifest": NATIVE_IMPORTS <= set(exports),
            "no_tls_delay_clr_loadconfig": all(pe.directory(n) == (0, 0) for n in (9, 10, 13, 14)),
        }
        pe_gate = {"compiler": cc_version.splitlines()[0], "checks": checks, "artifact": {
            "path": str(exe), "sha256": sha(exe), "bytes": exe.stat().st_size},
            "imports": sorted([list(x) for x in imported]), "executed": False}
        if not all(checks.values()):
            errors.append("actual PE inspection gate failed")
    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")
    after = {str(p): {"sha256": sha(p), "bytes": p.stat().st_size} for p in inputs}
    stable = before == after
    total = sum(len(p["cases"]) for p in hosts)
    failures = sum(not c["passed"] for p in hosts for c in p["cases"])
    ready = not errors and stable and len(hosts) == 2 and total == 2 * len(SCENARIOS) and pe_gate is not None
    accepted = ready and (failures >= 8 if args.baseline else failures == 0)
    result = {
        "schema": 1, "scope": "literal NTW64RUN host callbacks + actual frontend PE compilation; no guest/app execution",
        "status": "EXPECTED_PRECHANGE_FAILURE" if args.baseline and accepted else "PASS_COMPONENT_NOT_RUN" if accepted else "FAIL",
        "accepted": accepted, "baseline": bool(args.baseline), "requested_source": str(source),
        "sources_before": before, "sources_after": after, "source_unchanged": stable,
        "host_cases": total, "host_failures": failures, "host_profiles": hosts, "PE": pe_gate,
        "commands": commands, "errors": errors, "VM_executed": False, "application_executed": False,
    }
    receipt = out / "result.json"
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "host_cases": total, "host_failures": failures,
                      "receipt": str(receipt), "receipt_sha256": sha(receipt), "errors": errors}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
