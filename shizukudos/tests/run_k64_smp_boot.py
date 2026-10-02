#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and boot an isolated real Kernel64 AP component probe, never a model."""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHZ = REPO / "shizukudos"
TEST_SOURCES = [Path(__file__), SHZ / "tests/k64_smp_boot_probe.c", SHZ / "tests/k64_smp_boot_stub.c",
                SHZ / "tests/k64_smp_firmware.h"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=64)
def hash_work(cpu, loops):
    value = 0x5a17c0de ^ cpu
    for i in range(loops):
        value = (((value << 5) | (value >> 27)) & 0xffffffff) ^ 0x9e3779b9
        value = (value + i) & 0xffffffff
    return value


def evaluate(output, returncode, timed_out, cpus, acpi, ipi, expect_red=False, returning=False):
    rows = re.findall(r"SMP-CPU: slot=(\d+) apic=(\d+) actual=(\d+) physical=(\d+) cr3=([0-9a-f]+) stack=([0-9a-f]+) hash=([0-9a-f]+) progress=(\d+) overlap=(\d+) observed=(\d+)", output)
    interrupts = re.findall(r"SMP-IPI: slot=(\d+) resched=(\d+) tlb=(\d+) irqstack=([0-9a-f]+)", output)
    if timed_out:
        return False
    if returning:
        records = re.findall(r"SMP-RETURN-CONTROL: started=(-?\d+) failed=(\d+) online=(\d+) cpu=(\d+) physical=(\d+) retained=(\d+) rejected=(-?\d+) retry=(-?\d+) bootinfo=(\d+)", output)
        admissions = re.findall(r"SMP-ADMISSION: initial=1000 final=([0-9a-f]+) wrong-initial=-2 wrong-active=-2 IF-on=-2", output)
        return (returncode == 13 and not rows and not interrupts and len(admissions) == 1 and
                int(admissions[0], 16) >= 0xf00000 and not (int(admissions[0], 16) & 4095) and len(records) == 1 and
                records[0][0] in ("2", "-7") and records[0][1:] == ("1", "1", "1", "1", "1", "-1", "-2", "1") and "SHZ-EXIT:6\n" in output)
    if not acpi or expect_red:
        expected_error = "startup failed rc=-1\n" if not acpi else "startup failed rc=-3\n"
        return returncode == 5 and expected_error in output and not rows and not interrupts and "SHZ-EXIT:2\n" in output
    if len(rows) != cpus or len(interrupts) != cpus:
        return False
    admissions = re.findall(r"SMP-ADMISSION: initial=([0-9a-f]+) final=([0-9a-f]+) wrong-initial=(-?\d+) wrong-active=(-?\d+) IF-on=(-?\d+)", output)
    pages = re.findall(r"SMP-BOOT-PAGES: retired=([0-9a-f]+) initial=([0-9a-f]+) active=([0-9a-f]+) bootstrap=([0-9a-f]+) low-pages=(\d+) bad=(\d+) retry=(-?\d+) bootinfo=(\d+)", output)
    if len(admissions) != 1 or len(pages) != 1:
        return False
    initial, final, wrong_initial, wrong_active, if_on = admissions[0]
    retired, original, active, bootstrap, low_pages, bad, retry, bootinfo = pages[0]
    if initial != "1000" or wrong_initial != "-2" or wrong_active != "-2" or if_on != "-2":
        return False
    if retired != "1000" or original != initial or active != final or bootstrap in (active, initial):
        return False
    if not int(bootstrap, 16) or int(bootstrap, 16) & 4095 or (low_pages, bad, retry, bootinfo) != ("1", "0", "-2", "1"):
        return False
    if len({row[0] for row in rows}) != cpus or len({row[1] for row in rows}) != cpus:
        return False
    if len({row[4] for row in rows}) != 1 or len({row[5] for row in rows}) != cpus:
        return False
    cr3 = int(rows[0][4], 16)
    if not cr3 or cr3 & 4095 or cr3 != int(final, 16):
        return False
    for row in rows:
        slot, apic_id, actual, physical = map(int, row[:4])
        if slot >= cpus or actual != slot or physical != apic_id or not int(row[5], 16):
            return False
        if int(row[6], 16) != hash_work(slot, 16000000 if slot == 0 else 2000000):
            return False
        if slot and (int(row[7]) <= 1 or row[8:10] != ("1", "1")):
            return False
    if len({row[0] for row in interrupts}) != cpus:
        return False
    for slot, resched, tlb, stack in interrupts:
        slot, resched, tlb = int(slot), int(resched), int(tlb)
        expected = (1 if slot else cpus) if ipi else 0
        if slot >= cpus or resched != expected or tlb != expected or bool(int(stack, 16)) != ipi:
            return False
    if ipi:
        return returncode == 1 and len({row[3] for row in interrupts}) == cpus and f"CPUs={cpus} completed={cpus-1} bad=0\n" in output and "SHZ-EXIT:0\n" in output
    # This actual native control executes all AP work but deliberately omits
    # physical IPIs. Every CPU's delivery gate must fail, with an abnormal test
    # exit that is recognized only for this explicitly labeled negative case.
    return returncode == 9 and f"CPUs={cpus} completed={cpus-1} bad={cpus}\n" in output and "SHZ-EXIT:4\n" in output


def tool_identities(qemu):
    names = ("gcc", "as", "nasm", "ld", "nm", "objcopy", "objdump", "readelf")
    paths = {name: Path(shutil.which(name) or name).resolve(strict=True) for name in names}
    paths["qemu"] = Path(qemu).resolve(strict=True)
    paths["python"] = Path(sys.executable).resolve(strict=True)
    cc1 = subprocess.run([str(paths["gcc"]), "-print-prog-name=cc1"], check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    paths["cc1"] = Path(cc1).resolve(strict=True)
    return {name: {"path": str(path), "sha256": digest(path)} for name, path in paths.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--qemu", default=shutil.which("qemu-system-x86_64") or "/usr/libexec/qemu-kvm")
    parser.add_argument("--expect-red", action="store_true", help="record initial missing-startup RED, not a PASS")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("output must be a new unique directory")
    out.mkdir(parents=True)
    tools_before = tool_identities(args.qemu)
    args.qemu = tools_before["qemu"]["path"]
    spec = importlib.util.spec_from_file_location("kbuild", SHZ / "kbuild.py")
    kbuild = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kbuild)
    kbuild.BUILD = out / "build"
    sources = kbuild.sources
    kbuild.sources = lambda d, s: [p for p in sources(d, s) if p.name != "main.c"]
    before = kbuild.source_hashes()
    before.update({str(p.relative_to(REPO)): digest(p) for p in TEST_SOURCES})
    # Retain the exact public inputs so an independent reviewer can inspect an
    # earlier RED/GREEN epoch after the mutable worktree advances. No private
    # disk/media/firmware VARS is part of this repository source closure.
    for relative, expected in before.items():
        data = (REPO / relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit("source changed before its compilation snapshot")
        captured = out / "captured-source-inputs" / relative
        captured.parent.mkdir(parents=True, exist_ok=True)
        captured.write_bytes(data)
    (out / "captured-source-inputs.json").write_text(json.dumps({"sources_sha256": before}, indent=2) + "\n")
    extra = [SHZ / "win64/pe_parse.c", kbuild.STUB_DIR / "standalone64.c",
             REPO / "drivers/ahci_native/ahci.c", SHZ / "tests/k64_smp_boot_probe.c",
             *sorted((REPO / "shizukufs/v1/libsfs").glob("*.c")), *kbuild.dead_screen_sources()]
    with (out / "build.log").open("w") as log:
        previous = kbuild.run
        def logged_run(cmd, **kw):
            if kw.get("capture"):
                return previous(cmd, **kw)
            result = subprocess.run([str(x) for x in cmd], stdout=log, stderr=subprocess.STDOUT)
            result.check_returncode()
            return result
        kbuild.run = logged_run
        kernel = kbuild.build_kernel("kernel64s", "kernel64", kbuild.K64_FLAGS + ["-DSHZ_STANDALONE"],
                                    "elf64", "elf_x86_64", "KERNEL64S.BIN", extra_c=extra)
        stub_out = out / "build/kernel64s"
        asm_o, c_o, elf = stub_out / "boot.asm.o", stub_out / "boot32.o", stub_out / "boot.elf"
        kbuild.run(["nasm", "-f", "elf32", "-w+all", "-o", asm_o, kbuild.STUB_DIR / "boot.asm"])
        kbuild.run(["gcc", "-m32", "-march=i486", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
                    "-fno-builtin", "-fno-pie", "-fno-stack-protector", "-mno-sse", "-mno-mmx", "-fno-asynchronous-unwind-tables",
                    "-fno-ident", "-c", SHZ / "tests/k64_smp_boot_stub.c", "-o", c_o])
        kbuild.run(["ld", "-m", "elf_i386", "-nostdlib", "-z", "noexecstack", "--no-warn-rwx-segments", "-T",
                    kbuild.STUB_DIR / "boot.ld", "-o", elf, asm_o, c_o])
        assert not kbuild.run(["nm", "-u", elf], capture=True).stdout.strip()
        stub = {"elf": elf, "sha256": digest(elf)}
    relocations = subprocess.run([tools_before["readelf"]["path"], "-r", str(out / "build/kernel64s/obj/smp_ap_trampoline.asm.o")],
                                 check=True, capture_output=True, text=True, timeout=10).stdout
    (out / "trampoline-relocations.txt").write_text(relocations)
    if "There are no relocations in this file." not in relocations:
        raise SystemExit("AP trampoline must remain relocation-free")
    compiled_sources = kbuild.source_hashes()
    compiled_sources.update({str(p.relative_to(REPO)): digest(p) for p in TEST_SOURCES})
    if compiled_sources != before:
        raise SystemExit("sources changed during compilation; no VM launched")
    runs = []
    for cpus, acpi, ipi, returning in ((1, True, True, False), (2, True, True, False), (4, True, True, False),
                                      (2, False, False, False), (2, True, False, False), (2, True, False, True)):
        label = f"smp{cpus}-{'acpi' if acpi else 'no-acpi'}" + ("-return-ap" if returning else "-no-ipi" if acpi and not ipi else "")
        serial = out / (label + ".serial.log")
        if digest(kernel["bin"]) != kernel["sha256"] or digest(stub["elf"]) != stub["sha256"]:
            raise SystemExit("compiled VM inputs changed before launch")
        cmd = [args.qemu, "-machine", "pc" if acpi else "pc,acpi=off", "-accel", args.accel,
               "-cpu", "max", "-m", "256", "-smp", str(cpus), "-kernel", str(stub["elf"]),
               "-initrd", str(kernel["bin"]), "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
               "-nic", "none", "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        if acpi and not ipi:
            cmd += ["-append", "smp-return-ap" if returning else "smp-no-ipi"]
        start = time.monotonic()
        try:
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            rc, timed_out = run.returncode, False
        except subprocess.TimeoutExpired as exc:
            rc, timed_out = None, True
            run = exc
        output = serial.read_text(errors="replace") if serial.exists() else ""
        (out / (serial.stem + ".qemu.log")).write_text(str(run.stderr or ""))
        inputs_unchanged = digest(kernel["bin"]) == kernel["sha256"] and digest(stub["elf"]) == stub["sha256"]
        valid = inputs_unchanged and evaluate(output, rc, timed_out, cpus, acpi, ipi, args.expect_red, returning)
        runs.append({"cpus": cpus, "acpi": acpi, "ipi": ipi, "returning_ap": returning, "command": cmd, "qemu_returncode": rc,
                     "timed_out": timed_out, "elapsed_seconds": time.monotonic()-start, "expected_behavior": valid,
                     "inputs_unchanged": inputs_unchanged, "serial_sha256": digest(serial) if serial.exists() else None})
        print(f"{'RED captured' if args.expect_red and acpi else 'check'}: smp{cpus} acpi={acpi} ipi={ipi} returning={returning} rc={rc} valid={valid}", flush=True)
    after = kbuild.source_hashes()
    after.update({str(p.relative_to(REPO)): digest(p) for p in TEST_SOURCES})
    tools_after = tool_identities(args.qemu)
    captured_unchanged = all(digest(out / "captured-source-inputs" / relative) == expected for relative, expected in before.items())
    valid = before == after and captured_unchanged and tools_before == tools_after and all(r["expected_behavior"] for r in runs)
    result = {"scope": "actual native Kernel64 AP bootstrap, private IRQ stacks and physical IPI component; no scheduler/Windows VMM claim",
              "checked_at_utc": datetime.now(timezone.utc).isoformat(), "native_component_pass": valid and not args.expect_red,
              "initial_red": args.expect_red, "accel": args.accel, "all_expected": valid,
              "sources_unchanged": before == after, "sources_sha256": before,
              "captured_sources_unchanged": captured_unchanged, "captured_source_count": len(before),
              "tools_unchanged": tools_before == tools_after, "tools": tools_before,
              "kernel_sha256": kernel["sha256"], "stub_sha256": stub["sha256"], "runs": runs}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
