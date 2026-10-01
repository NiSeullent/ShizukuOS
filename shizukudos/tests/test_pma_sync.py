#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check shared PMA atomics and exact driver-host spinlock/IRQL bodies.

Only local output files and bounded host compiler/test processes are created.
No guest, download, installed software, boot or client configuration changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FUNCTIONS = (
    "set_irql", "ntdrv_isr_enter", "ntdrv_isr_leave", "KeInitializeSpinLock",
    "spin_acquire", "spin_release", "KeAcquireSpinLock", "KeReleaseSpinLock",
    "KfAcquireSpinLock", "KfReleaseSpinLock", "KeAcquireSpinLockAtDpcLevel",
    "KeReleaseSpinLockFromDpcLevel", "KeAcquireSpinLockRaiseToDpc",
)


def body(source, name):
    match = re.search(r"^[^\n;{}]*\b" + re.escape(name) + r"\([^;{}]*\)\s*\{", source, re.M)
    if not match:
        raise ValueError("missing production function: " + name)
    pos = match.end() - 1
    depth = 0
    quote = None
    while pos < len(source):
        char = source[pos]
        if quote:
            if char == "\\":
                pos += 2
                continue
            if char == quote:
                quote = None
        elif source.startswith("/*", pos):
            pos = source.index("*/", pos + 2) + 2
            continue
        elif source.startswith("//", pos):
            pos = source.index("\n", pos + 2)
            continue
        elif char in ('"', "'"):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if not depth:
                return source[match.start():pos + 1]
        pos += 1
    raise ValueError("unterminated production function: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--driver-only", action="store_true", help="run the production driver regression first")
    parser.add_argument("--tsan", action="store_true", help="also require a working Clang thread-sanitizer run")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("choose a fresh output directory to preserve prior receipts")
    out.mkdir(parents=True)
    source = ROOT / "shizukudos/kernel64/ntdrv_ke.c"
    # Every extraction and receipt digest must describe these same exact bytes.
    # Capture compiled inputs before extraction can race a disk edit.
    inputs = [source, Path(__file__).resolve(), ROOT / "shizukudos/kernel64/tests/test_ntdrv_spin_host.c",
              ROOT / "shizukudos/kernel64/ntddk.h", ROOT / "shizukudos/kcommon/pma_sync.h"]
    if not args.driver_only:
        inputs += [ROOT / "shizukudos/tests/test_pma_sync.c"]
    snapshots = {path: path.read_bytes() for path in inputs}
    original_bytes = snapshots[source]
    original = original_bytes.decode("utf-8")
    bodies = {name: body(original, name) for name in FUNCTIONS}
    (out / "ntdrv_spin_production.inc").write_text("\n\n".join(bodies.values()) + "\n")
    before = {str(path.relative_to(ROOT)): hashlib.sha256(value).hexdigest()
              for path, value in snapshots.items()}
    receipt = {"status": "FAIL", "source_sha256": hashlib.sha256(original_bytes).hexdigest(),
               "sources_sha256": before,
               "production_functions": {name: hashlib.sha256(value.encode()).hexdigest()
                                        for name, value in bodies.items()},
               "guest_executed": False, "SMP_kernel_executed": False, "runs": []}

    def disk_matches_snapshot():
        return all(path.exists() and path.read_bytes() == value for path, value in snapshots.items())

    receipt["source_precompile_match"] = disk_matches_snapshot()
    if not receipt["source_precompile_match"]:
        receipt["source_before_after_match"] = False
        (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return 1

    def run(command, name):
        if not disk_matches_snapshot():
            result = subprocess.CompletedProcess(command, 125, "", "input changed before command; refused\n")
            (out / (name + ".log")).write_text(result.stderr)
            receipt["runs"].append({"name": name, "command": list(map(str, command)),
                                    "returncode": 125, "output": result.stderr})
            return False
        try:
            result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=90)
        except subprocess.TimeoutExpired as error:
            result = subprocess.CompletedProcess(command, 124,
                       (error.stdout or b"").decode() if isinstance(error.stdout, bytes) else error.stdout or "",
                       "timeout after 90 seconds\n" +
                       ((error.stderr or b"").decode() if isinstance(error.stderr, bytes) else error.stderr or ""))
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        receipt["runs"].append({"name": name, "command": list(map(str, command)),
                                "returncode": result.returncode, "output": result.stdout + result.stderr})
        print(name, result.returncode, (result.stdout + result.stderr).strip()[-800:])
        return result.returncode == 0

    passed = True
    fixture = ROOT / "shizukudos/kernel64/tests/test_ntdrv_spin_host.c"
    for cc, flags in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        exe = out / ("ntdrv-" + cc)
        common = [cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-I", out,
                  "-fno-pie", "-no-pie"]
        built = run([*common, *flags, fixture, "-o", exe], "ntdrv-build-" + cc)
        passed = built and passed
        if built:
            passed = run([exe], "ntdrv-run-" + cc) and passed
        if not args.driver_only:
            sync = ROOT / "shizukudos/tests/test_pma_sync.c"
            exe = out / ("sync-" + cc)
            built = run([*common, *flags, "-pthread", sync, "-o", exe], "sync-build-" + cc)
            passed = built and passed
            if built:
                passed = run([exe], "sync-run-" + cc) and passed
    if not args.driver_only:
        compile_source = out / "freestanding.c"
        compile_source.write_text('#include "shizukudos/kcommon/pma_sync.h"\n'
                                  'uint32_t check(pma_ticketlock_t *l, uintptr_t *w) {\n'
                                  'pma_ticket_init(l); pma_word_init(w);\n'
                                  'uint32_t t = pma_ticket_lock(l);\n'
                                  'pma_ticket_unlock(l, t);\n'
                                  'pma_ticket_trylock(l, &t); pma_ticket_unlock(l, t);\n'
                                  'int held = pma_word_try_lock(w);\n'
                                  'return held ? pma_word_unlock(w) : 0; }\n')
        obj = out / "i486.o"
        passed = run(["gcc", "-std=c11", "-m32", "-march=i486", "-O2", "-Wall", "-Wextra", "-Werror",
                      "-ffreestanding", "-fno-pie", "-fno-pic", "-I", ROOT, "-c", compile_source, "-o", obj],
                     "i486-build") and passed
        if obj.exists():
            result = subprocess.run(["nm", "-u", str(obj)], capture_output=True, text=True)
            passed = result.returncode == 0 and not result.stdout.strip() and passed
            (out / "i486-undefined.log").write_text(result.stdout + result.stderr)
        if args.tsan:
            exe = out / "sync-tsan"
            built = run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pthread",
                         "-fsanitize=thread", "-DPMA_SYNC_TSAN_SMALL",
                         ROOT / "shizukudos/tests/test_pma_sync.c", "-o", exe], "tsan-build")
            passed = built and passed
            if built:
                passed = run([exe], "tsan-run") and passed
    receipt["source_before_after_match"] = disk_matches_snapshot()
    passed = receipt["source_before_after_match"] and passed
    receipt["status"] = "PASS_HOST_SYNC_AND_DRIVER_CONTRACTS" if passed else "FAIL"
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
