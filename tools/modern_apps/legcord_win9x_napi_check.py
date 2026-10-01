#!/usr/bin/env python3
"""Memory-only real source/API checks; no addon, PE, Electron or app execution.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def pin(path):
    path = path.resolve()
    before = path.stat()
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("Actual checked input changed")
    return {"path": str(path), "bytes": after.st_size, "sha256": value}


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


HOST_CONTROL = r'''
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const binding = require(process.argv[1]);
const nativeProbe = require(process.argv[2]);
const entryBootstrap = require(process.argv[3]);
const { EventEmitter } = require('node:events');
const good = ['C:\\GOPLAB\\MAIN.JS', 'D:\\SOURCE DIR\\src\\main.js'];
const bad = ['relative.txt', '\\\\server\\share\\a.js', 'C:/src/a.js', 'C:\\src\\..\\a.js',
    'C:\\src\\.\\a.js', 'C:\\src\\a.', 'C:\\src\\a ', 'C:\\src\\NUL.txt',
    'C:\\src\\COM1.js', 'C:\\src\\CLOCK$', 'C:\\src\\a:stream', 'C:\\src\\*.js',
    'C:\\src\\\uD55C.js', 'C:\\src\\a\u0000.js', 'C:\\src\\\\a.js', 'C:\\src\\' + 'a'.repeat(260)];
bad.push(...['\n', '\r', '\u2028', '\u2029'].map(ending => 'C:\\GOPLAB\\a' + ending));
for (const value of good) assert.equal(binding.dosPath(value), value);
for (const value of bad) assert.throws(() => binding.dosPath(value));
assert.throws(() => binding.parseInventory('C:\\GOPLAB\\ABSENT.JSON', 'not-a-digest'), /caller manifest SHA/);
assert.throws(() => binding.parseInventory('C:\\GOPLAB\\ABSENT.JSON', 'A'.repeat(64)), /caller manifest SHA/);
const malformedPins = ['a'.repeat(63), 'a'.repeat(65), ...['\n', '\r', '\u2028', '\u2029'].map(ending => 'a'.repeat(64) + ending)];
for (const value of malformedPins)
    assert.throws(() => binding.parseInventory('C:\\GOPLAB\\ABSENT.JSON', value), /caller manifest SHA/);
assert.throws(() => entryBootstrap.requireNativeTreeLease({}, good), /native Win98/);
// These are actual JS listener controls, not a native lease or runtime substitute.
let released = 0;
const lifetime = new EventEmitter();
const earlyRelease = entryBootstrap.retainLeaseToProcessExit(lifetime, { release() { ++released; } });
lifetime.emit('will-quit', { preventDefault() {} });
assert.equal(released, 0);
lifetime.emit('exit'); lifetime.emit('exit'); earlyRelease();
assert.equal(released, 1);
let failedSetupRelease = 0;
const failedSetup = new EventEmitter();
const cleanup = entryBootstrap.retainLeaseToProcessExit(failedSetup, { release() { ++failedSetupRelease; } });
cleanup(); cleanup(); failedSetup.emit('exit');
assert.equal(failedSetupRelease, 1);
assert.equal(failedSetup.listenerCount('exit'), 0);
let ioCalls = 0;
const originalOpen = fs.openSync;
fs.openSync = (...arguments_) => { ++ioCalls; return originalOpen(...arguments_); };
(async () => {
    assert.notEqual(process.platform, 'win32');
    await assert.rejects(binding.loadAndStart('C:\\GOPLAB\\ABSENT.JSON', '0'.repeat(64)), /actual x86 Electron/);
    const invalidNonces = ['', 'a'.repeat(81), 'a!', '\uD55C', 'a\n'];
    for (const nonce of invalidNonces)
        await assert.rejects(nativeProbe.probe('C:\\GOPLAB\\ABSENT.node', 'C:\\GOPLAB\\NEWTEST', nonce), /fresh bounded nonce/);
    assert.equal(ioCalls, 0); // actual wrong-host gate runs before file/addon loading
    fs.openSync = originalOpen;
    process.stdout.write(JSON.stringify({ actualHost: { platform: process.platform, arch: process.arch,
        versions: process.versions }, acceptedPathControls: good.length,
        rejectedPathControls: bad.length, rejectedCallerPins: 2 + malformedPins.length, wrongHostRejectedBeforeIo: true,
        rejectedNativeProbeNoncesBeforeIo: invalidNonces.length,
        missingNativeBindingRejected: true, actualJsExitListenerControlsPassed: true,
        nativeLeaseCreated: false, actualAddonLoaded: false, lifecycleExecuted: false, appPass: false }) + '\n');
})().catch(error => { fs.openSync = originalOpen; process.stderr.write(String(error)); process.exitCode = 2; });
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    receipt = args.receipt.resolve()
    if receipt.exists() or not receipt.is_relative_to(ROOT / "build"):
        raise ValueError("Require a new checkpoint under the owned private build directory")
    headers = args.headers.resolve()
    extraction = headers / "extraction.json"
    frozen = json.loads(extraction.read_text())
    expected = ("694c4868c187d4a435a86d617346e2c81676c30a9bbf6fc65cce8eb50038dcaf",
                "bef9da935120ac15bf09277b29ef5f95134552f5b5d3b4c7c733791fb234ecb6")
    if (frozen["node_archive"]["sha256"], frozen["electron_archive"]["sha256"]) != expected:
        raise ValueError("Require the exact official complete-archive verified headers")
    compiler = Path(shutil.which("i686-w64-mingw32-gcc"))
    node = Path(shutil.which("node"))
    addon = HERE / "legcord_win9x_napi.c"
    helper = HERE / "legcord_win9x_source_lease.c"
    probe = HERE / "legcord_win9x_napi_native_probe.c"
    inputs = [*sorted(HERE.glob("legcord_win9x_napi*")), helper,
              HERE / "legcord_win9x_source_lease.h", HERE / "legcord_win9x_entry.cjs",
              extraction, compiler, node, *[Path(row["path"]) for row in frozen["files"]]]
    for name in ("cc1", "as", "ld"):
        selected = subprocess.run([str(compiler), "-print-prog-name=" + name], check=True,
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        inputs.append(Path(selected if Path(selected).is_absolute() else shutil.which(selected)))
    before = {str(path.resolve()): pin(path) for path in inputs}
    for row in frozen["files"]:
        if before[str(Path(row["path"]).resolve())]["sha256"] != row["sha256"]:
            raise ValueError("Official selected header evidence changed")
    flags = [str(compiler), "-std=gnu11", "-fsyntax-only", "-Wall", "-Wextra", "-Werror",
             "-Wno-cast-function-type", "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410",
             "-D_WIN32_WINNT=0x0400", "-I" + str(HERE)]
    defines = ['-DLEG_NAPI_PROBE_SHA="' + before[str(probe)]["sha256"] + '"',
               '-DLEG_LEASE_SOURCE_SHA="' + before[str(helper)]["sha256"] + '"',
               '-DLEG_LEASE_HEADER_SHA="' + before[str(HERE / "legcord_win9x_source_lease.h")]["sha256"] + '"']
    commands = [("actual-electron-header-signatures", flags + ["-I" + str(headers / "electron"), str(addon)]),
                ("actual-node-header-signatures", flags + ["-I" + str(headers / "node"), str(addon)]),
                ("native-helper-probe-api-signatures", flags + defines + [str(probe), str(helper)])]
    commands += [("javascript-syntax:" + path.name, [str(node), "--max-old-space-size=128", "--check", str(path)])
                 for path in sorted(HERE.glob("legcord_win9x_napi*.cjs"))]
    commands.append(("actual-host-bootstrap-rejection", [str(node), "--max-old-space-size=128", "-e", HOST_CONTROL,
                        str(HERE / "legcord_win9x_napi_bootstrap.cjs"), str(HERE / "legcord_win9x_napi_probe.cjs"),
                        str(HERE / "legcord_win9x_entry.cjs")]))
    report = {"schema": "legcord-win9x-napi-memory-only-source-checkpoint-v1", "inputs": list(before.values()),
              "commands": [], "cpu_limit_per_child_seconds": 45, "child_file_limit_bytes": 0,
              "pe_built": False, "addon_loaded": False, "native_electron_executed": False,
              "native_lifecycle_pass": False, "whole_application_pass": False, "source_checks_passed": False}
    started = time.monotonic()
    cpu_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        for label, argv in commands:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       cwd=ROOT, start_new_session=True, preexec_fn=limits)
            try:
                data, _ = process.communicate(timeout=45)
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL); process.wait(); raise
            if len(data) > 65536:
                raise ValueError("Source validation output exceeded its memory bound")
            row = {"label": label, "argv": argv, "returncode": process.returncode,
                   "output": data.decode("utf8", errors="replace")}
            report["commands"].append(row)
            if process.returncode:
                raise RuntimeError(label + " failed: " + row["output"])
        for key, row in before.items():
            if pin(Path(key)) != row:
                raise ValueError("Source/header/compiler input changed across validation")
        report["all_checked_inputs_unchanged"] = True
        report["source_checks_passed"] = True
    except BaseException as error:
        report["failure"] = str(error)
    cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    report["elapsed_seconds"] = time.monotonic() - started
    report["children_cpu_seconds"] = cpu.ru_utime + cpu.ru_stime - cpu_start.ru_utime - cpu_start.ru_stime
    report["children_peak_resident_kib"] = cpu.ru_maxrss
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open("x") as stream:
        json.dump(report, stream, indent=2); stream.write("\n")
    print(json.dumps({"receipt": pin(receipt), "source_checks_passed": report["source_checks_passed"],
                      "failure": report.get("failure"), "children_cpu_seconds": report["children_cpu_seconds"]}))
    if not report["source_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
