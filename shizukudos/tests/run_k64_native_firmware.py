#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the normal kernel/stub and verify real firmware ownership on native CPUs."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHZ = REPO / "shizukudos"
HELPERS = ("shizukudos/tools/shzlib.py", "shizukudos/kbuild.py")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def capture_sources():
    """Capture the entire closure before executing either repository helper.

    This inventory is checked against the builder's own inventory after loading,
    so a new builder dependency cannot silently escape the initial snapshot.
    """
    directories = [SHZ / name for name in
                   ("kernel32", "kernel64", "kcommon", "abi", "pma_bridge", "win64/include", "dead_screen")]
    directories += [REPO / "shizukufs/v1/libsfs", REPO / "drivers/ahci_native"]
    paths = {p for directory in directories for p in directory.rglob("*")
             if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld")}
    paths.update([SHZ / "kbuild.py", SHZ / "tools/shzlib.py", SHZ / "win64/pe_parse.c",
                  SHZ / "supervisor/src/font8x8_basic.h", Path(__file__).resolve()])
    return {str(p.relative_to(REPO)): p.read_bytes() for p in sorted(paths)}


def load_builder(captured):
    """Execute precisely the captured helper bytes, independent of .pyc/cache."""
    saved_path = list(sys.path)
    saved_shzlib = sys.modules.get("shzlib")
    try:
        library = types.ModuleType("shzlib")
        library.__file__ = str(REPO / HELPERS[0])
        sys.modules["shzlib"] = library
        exec(compile(captured[HELPERS[0]], library.__file__, "exec"), library.__dict__)
        builder = types.ModuleType("kbuild")
        builder.__file__ = str(REPO / HELPERS[1])
        exec(compile(captured[HELPERS[1]], builder.__file__, "exec"), builder.__dict__)
        return builder
    finally:
        sys.path[:] = saved_path
        if saved_shzlib is None:
            sys.modules.pop("shzlib", None)
        else:
            sys.modules["shzlib"] = saved_shzlib


def reuse_compiled(receipt_path, before, tools, out):
    """Reuse only identical C/stubs/helpers/tools and exact prior machine bytes."""
    raw = receipt_path.read_bytes()
    previous = json.loads(raw)
    producer = str(Path(__file__).resolve().relative_to(REPO))
    old_sources = previous.get("sources_sha256", {})
    if previous.get("status") != "PASS" or previous.get("sources_unchanged") is not True or \
       len(previous.get("runs", [])) != 3 or not all(row.get("expected_behavior") for row in previous["runs"]):
        raise SystemExit("reuse rejected: prior native gate did not pass")
    if set(old_sources) != set(before) or producer not in before or \
       any(old_sources[name] != sha for name, sha in before.items() if name != producer):
        raise SystemExit("reuse rejected: compiled source/helper closure changed")
    if previous.get("tools") != tools:
        raise SystemExit("reuse rejected: tool or firmware bytes changed")
    inputs = previous.get("compiled_inputs_sha256", {})
    expected_names = {"KERNEL64S.BIN", "kernel64s.elf", "boot.elf"}
    if len(inputs) != 3 or {Path(name).name for name in inputs} != expected_names:
        raise SystemExit("reuse rejected: unexpected compiled input set")
    copied = {}
    for name, sha in inputs.items():
        data = Path(name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise SystemExit("reuse rejected: compiled input bytes changed")
        destination = out / "compiled-reused" / Path(name).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        copied[destination.name] = (destination, sha)
    if receipt_path.read_bytes() != raw:
        raise SystemExit("reuse rejected: origin receipt changed during validation")
    provenance = {"mode": "reused exact previously compiled bytes; no compiler run",
                  "source_receipt": str(receipt_path.resolve()),
                  "source_receipt_sha256": hashlib.sha256(raw).hexdigest(),
                  "source_entries_unchanged_except": producer,
                  "original_compiled_inputs_sha256": inputs}
    return ({"bin": copied["KERNEL64S.BIN"][0], "sha256": copied["KERNEL64S.BIN"][1],
             "elf": copied["kernel64s.elf"][0], "elf_sha256": copied["kernel64s.elf"][1]},
            {"elf": copied["boot.elf"][0], "sha256": copied["boot.elf"][1]}, provenance)


def identities(qemu, bios):
    names = ("gcc", "nasm", "ld", "nm", "objcopy", "objdump")
    paths = {name: Path(shutil.which(name)).resolve(strict=True) for name in names}
    cc1 = subprocess.run([str(paths["gcc"]), "-print-prog-name=cc1"], capture_output=True,
                         text=True, check=True, timeout=10).stdout.strip()
    paths.update(cc1=Path(cc1).resolve(strict=True), qemu=Path(qemu).resolve(strict=True),
                 bios=Path(bios).resolve(strict=True), python=Path(sys.executable).resolve(strict=True))
    return {name: {"path": str(path), "sha256": digest(path)} for name, path in paths.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--qemu", default=shutil.which("qemu-system-x86_64") or "/usr/libexec/qemu-kvm")
    parser.add_argument("--bios", default="/usr/share/seabios/bios-256k.bin")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--reuse-receipt", type=Path,
                        help="reuse exact compiled bytes only if every compiled source/helper/tool still matches")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tool_before = identities(args.qemu, args.bios)
    captured = capture_sources()
    before = {name: hashlib.sha256(data).hexdigest() for name, data in captured.items()}
    kbuild = load_builder(captured)
    kbuild.BUILD = out / "compiled"
    def sources():
        return {**kbuild.source_hashes(), str(Path(__file__).relative_to(REPO)): digest(__file__)}
    if sources() != before:
        raise SystemExit("helper/source closure changed while loading; no compiler or VM launched")
    if args.reuse_receipt:
        kernel, stub, compiled_provenance = reuse_compiled(args.reuse_receipt, before, tool_before, out)
        (out / "build.log").write_text("Exact prior compiled inputs copied after source/helper/tool verification; no compiler run.\n")
    else:
        compiled_provenance = {"mode": "fresh build from captured source/helper closure"}
        with (out / "build.log").open("w") as log:
            previous = kbuild.run
            def logged(command, **kw):
                if kw.get("capture"):
                    return previous(command, **kw)
                result = subprocess.run([str(x) for x in command], stdout=log, stderr=subprocess.STDOUT)
                result.check_returncode()
                return result
            kbuild.run = logged
            extra = [SHZ / "win64/pe_parse.c", kbuild.STUB_DIR / "standalone64.c",
                     REPO / "drivers/ahci_native/ahci.c", *sorted((REPO / "shizukufs/v1/libsfs").glob("*.c")),
                     *kbuild.dead_screen_sources()]
            kernel = kbuild.build_kernel("kernel64s", "kernel64", kbuild.K64_FLAGS + ["-DSHZ_STANDALONE"],
                                        "elf64", "elf_x86_64", "KERNEL64S.BIN", extra_c=extra)
            stub = kbuild.build_standalone_stub()
    def origin_stable():
        return not args.reuse_receipt or digest(args.reuse_receipt) == compiled_provenance["source_receipt_sha256"]
    if sources() != before or identities(args.qemu, args.bios) != tool_before or not origin_stable():
        raise SystemExit("build closure changed; no VM launched")
    inputs = {str(kernel["bin"]): kernel["sha256"], str(kernel["elf"]): kernel["elf_sha256"],
              str(stub["elf"]): stub["sha256"]}
    runs = []
    for cpus, enabled in ((2, True), (4, True), (4, False)):
        label = f"normal-smp{cpus}-{'firmware' if enabled else 'off'}"
        serial = out / (label + ".serial.log")
        command = [tool_before["qemu"]["path"], "-machine", "pc", "-bios", tool_before["bios"]["path"],
                   "-accel", args.accel, "-cpu", "max", "-m", "256", "-smp", str(cpus),
                   "-kernel", str(stub["elf"]), "-initrd", str(kernel["bin"]), "-append",
                   "shz.pma=test shz.smp=firmware-test" + (" smp=off" if not enabled else ""),
                   "-display", "none", "-monitor", "none", "-serial", f"file:{serial}", "-no-reboot",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        if sources() != before or not origin_stable() or any(digest(p) != h for p, h in inputs.items()):
            raise SystemExit("source or compiled input changed before launch")
        start = time.monotonic()
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            rc, timeout = run.returncode, False
            error = run.stderr
        except subprocess.TimeoutExpired as exc:
            rc, timeout, error = None, True, str(exc.stderr)
        (out / (label + ".qemu.log")).write_text(error or "")
        text = serial.read_text(errors="replace") if serial.exists() else ""
        metadata = re.findall(r"SMP-FIRMWARE: retained=(\d+) original=(\d+) machine_ram=([0-9a-f]+) managed_ram=([0-9a-f]+)", text)
        ownership = re.findall(r"SMP-FIRMWARE: test page_admitted=(\d+) reserved_reads=(\d+)", text)
        okay = not timeout and rc == 1 and "SHZ-EXIT:0\n" in text
        if enabled:
            okay = okay and len(metadata) == len(ownership) == 1
            if okay:
                kept, original, machine, managed = metadata[0]
                okay = 1 <= int(kept) <= 64 and 1 <= int(original) <= 64 and int(machine, 16) == 0x10000000 and \
                    int(managed, 16) < int(machine, 16) and ownership[0][0] == "1" and int(ownership[0][1]) > 0
        else:
            okay = okay and not metadata and not ownership and "SMP-BRINGUP:" not in text
        stable = sources() == before and origin_stable() and all(digest(p) == h for p, h in inputs.items())
        runs.append({"cpus": cpus, "firmware_enabled": enabled, "command": command, "qemu_returncode": rc,
                     "timed_out": timeout, "elapsed_seconds": time.monotonic() - start,
                     "expected_behavior": bool(okay and stable), "sources_and_inputs_unchanged": stable,
                     "serial_sha256": digest(serial) if serial.exists() else None})
        print(f"normal smp{cpus} firmware={enabled}: rc={rc} valid={okay and stable}", flush=True)
    stable = sources() == before and origin_stable() and identities(args.qemu, args.bios) == tool_before
    okay = stable and all(r["expected_behavior"] for r in runs)
    receipt = {"scope": "normal main.c and production Multiboot stub firmware handoff; AP/scheduler/Windows VMM not yet acceptance",
               "status": "PASS" if okay else "FAIL", "sources_sha256": before, "sources_unchanged": stable,
               "executed_helpers_sha256": {name: before[name] for name in HELPERS},
               "helper_execution": "compile/exec of captured pre-import bytes; current closure checked before compiler",
               "compiled_input_provenance": compiled_provenance,
               "compiled_inputs_sha256": inputs, "tools": tool_before, "runs": runs}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
