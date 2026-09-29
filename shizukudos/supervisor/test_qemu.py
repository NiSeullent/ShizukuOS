#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""UEFI profile test: OVMF -> Supervisor loader -> VMX -> DOS16 in virtual Real Mode.

Environment layers (kept separate in the record):
  L0 = this Linux host with KVM (QEMU only provides the L1 test machine)
  L1 = the QEMU/KVM guest that runs OVMF and the Shizuku Supervisor (VMX root)
  L2 = the DOS16 domain the Supervisor creates with its own VMX backend
Success needs L1 to expose VMX (detected by the Supervisor itself from inside L1,
never assumed from L0 flags) and the L2 DOS conformance programs to leave their
results on the RAM disk, which the harness extracts from L1 physical memory.
"""
import argparse
import json
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "tools"))
sys.path.insert(0, str(HERE.parents[0] / "dos16"))
import fatimg  # noqa: E402
import qemu  # noqa: E402
import shzinfo  # noqa: E402
import shzlib  # noqa: E402
import verify  # noqa: E402
from shzlib import BUILD, REPO, sha256_file  # noqa: E402

OUT = BUILD / "supervisor"


def read_info(qmp, workdir):
    raw = qemu.read_guest_memory(qmp, shzinfo.REGION_BASE, shzinfo.INFO_BYTES, Path(workdir) / "info.bin")
    info = shzinfo.Info.parse(raw)
    return info if info.magic == shzinfo.MAGIC else None


def check(name, ok, detail=""):
    return verify._check(name, ok, detail)


def ev(dom, slot):
    return dom["evidence"][slot]


def check_kernel32(d):
    """Guest-generated evidence from Kernel32 compared with independent expectations and with
    values the Supervisor itself read from the VMCS (CR3/CR0/CS)."""
    c = []
    c.append(check("K32 exited cleanly under the Supervisor", d["state"] == 3 and d["exit_code"] == 0 and not d["error"],
                   f"state={d['state']} code={d['exit_code']} {d['error']}"))
    c.append(check("K32 CR0 (read by the guest) has PE|WP|PG", ev(d, 0) & 0x80010001 == 0x80010001, hex(ev(d, 0))))
    c.append(check("K32 CR3 read by guest equals CR3 the Supervisor read from the VMCS",
                   ev(d, 1) == d["last_cr3"] and ev(d, 1) & 0xfff == 0 and ev(d, 1) != 0,
                   f"guest={ev(d, 1):#x} supervisor={d['last_cr3']:#x}"))
    c.append(check("K32 Supervisor saw 32-bit PM: CS=0x08, EFER=0, CR0.PE", d["last_cs"] == 8 and d["last_efer"] == 0
                   and d["last_cr0"] & 1 == 1, f"cs={d['last_cs']:#x} efer={d['last_efer']:#x}"))
    c.append(check("K32 timer preempted CPU-bound threads (>=10 switches)", ev(d, 2) >= 10, str(ev(d, 2))))
    c.append(check("K32 mutex-protected counter == 4 x 5000", ev(d, 3) == 20000))
    c.append(check("K32 heap pattern sum", ev(d, 4) == 10000))
    c.append(check("K32 demand-paged 16 pages", ev(d, 5) == 16))
    c.append(check("K32 ring-3 exit code 42, #GP and #PF contained",
                   ev(d, 6) == 42 and ev(d, 7) == 0x8000000d and ev(d, 8) == 0x8000000e,
                   f"{ev(d, 6)} {ev(d, 7):#x} {ev(d, 8):#x}"))
    c.append(check("K32 ring-3 computed 500500 and pid 1", ev(d, 17) == 500500 and ev(d, 16) == 1))
    c.append(check("K32 leaked no pages", ev(d, 12) == 0))
    c.append(check("K32 timed wait(30 ms) and sleep(50 ms) measured by the Supervisor clock",
                   28000 <= ev(d, 13) <= 150000 and 45000 <= ev(d, 14) <= 300000, f"{ev(d, 13)} us, {ev(d, 14)} us"))
    c.append(check("K32 completion marker and zero self-test failures", ev(d, 29) == 0x4b333221 and ev(d, 28) == 0))
    c.append(check("K32 served IPC requests, dropped 4 malformed slots, refused 3 buffers, rejected 1 stale",
                   ev(d, 9) >= 60 and ev(d, 10) == 4 and ev(d, 25) == 3 and ev(d, 26) == 1,
                   f"served={ev(d, 9)} proto_err={ev(d, 10)} refused={ev(d, 25)} stale={ev(d, 26)}"))
    c.append(check("K32 received doorbell interrupts", ev(d, 27) >= 40, str(ev(d, 27))))
    return c


def check_kernel64(d):
    c = []
    c.append(check("K64 exited cleanly under the Supervisor", d["state"] == 3 and d["exit_code"] == 0 and not d["error"],
                   f"state={d['state']} code={d['exit_code']} {d['error']}"))
    c.append(check("K64 CR0 (read by the guest) has PE|WP|PG", ev(d, 0) & 0x80010001 == 0x80010001, hex(ev(d, 0))))
    c.append(check("K64 CR3 read by guest equals CR3 the Supervisor read from the VMCS",
                   ev(d, 1) == d["last_cr3"] and ev(d, 1) & 0xfff == 0, f"guest={ev(d, 1):#x} supervisor={d['last_cr3']:#x}"))
    c.append(check("K64 Supervisor saw Long Mode: EFER.LME|LMA|SCE|NXE, CR4.PAE, CS=0x08",
                   d["last_efer"] & 0x901 == 0x901 and d["last_efer"] & 0x500 == 0x500 and d["last_cr4"] & 0x20
                   and d["last_cs"] == 8, f"efer={d['last_efer']:#x} cr4={d['last_cr4']:#x} cs={d['last_cs']:#x}"))
    c.append(check("K64 kernel RIP is in the higher half (above 4 GiB)", d["last_rip"] >= 0xffffffff80000000,
                   f"{d['last_rip']:#x}"))
    c.append(check("K64 timer preempted CPU-bound threads (>=10 switches)", ev(d, 2) >= 10, str(ev(d, 2))))
    c.append(check("K64 mutex counter, heap sum, 16 demand pages", ev(d, 3) == 20000 and ev(d, 4) == 10000 and ev(d, 5) == 16))
    c.append(check("K64 two SSE ring-3 processes exited 42/42", ev(d, 6) == 0x2a002a, hex(ev(d, 6))))
    c.append(check("K64 user faults contained: privileged insn, kernel write, freed-memory access",
                   ev(d, 7) & 0xffffffff == 0xc0000096 and ev(d, 8) & 0xffffffff == 0xc0000005
                   and ev(d, 9) & 0xffffffff == 0xc0000005,
                   f"{ev(d, 7) & 0xffffffff:#x} {ev(d, 8) & 0xffffffff:#x} {ev(d, 9) & 0xffffffff:#x}"))
    c.append(check("K64 user process used virtual address 0x200000000 (8 GiB) and read back its pattern",
                   ev(d, 16) == 0x200000000 and ev(d, 17) == 0x1122334455667788, f"{ev(d, 16):#x} {ev(d, 17):#x}"))
    c.append(check("K64 leaked no pages", ev(d, 12) == 0))
    c.append(check("K64 exceptions counted: >=1 #GP and >=2 #PF from user mode", (ev(d, 24) & 0xffff) >= 1 and
                   (ev(d, 24) >> 16) >= 2, hex(ev(d, 24))))
    c.append(check("K64 IPC: 25 echoes and all 13 sub-tests passed", ev(d, 10) == 25 and ev(d, 13) == 0x1fff,
                   f"echo={ev(d, 10)} mask={ev(d, 13):#x}"))
    sent, full = ev(d, 14) & 0xffff, ev(d, 14) >> 16
    c.append(check("K64 IPC saturation: QUEUE_FULL seen and every accepted request answered",
                   full > 0 and sent >= 30 and ev(d, 15) == sent, f"sent={sent} full={full} replies={ev(d, 15)}"))
    c.append(check("K64 shared-buffer bytes verified by the peer", ev(d, 25) >= 14000, str(ev(d, 25))))
    c.append(check("K64 completion marker and zero self-test failures", ev(d, 29) == 0x4b363421 and ev(d, 28) == 0))
    c += check_win64(d)
    return c


def check_win64(d):
    """Win64 app run by Kernel64's self-test: PE32+ loader + user-mode ntdll/kernel32 from WIN64.IMG.
    Slot 30: bits 0..31 exit code of run 2, bit 32 any fault, bit 33 both runs created and reaped,
    bit 34 both runs returned the same code. Slots 19..21 are written by the app itself, 22/23 by the kernel."""
    res = ev(d, 30)
    c = []
    c.append(check("Win64: Kernel64 mounted WIN64.IMG (ntdll, kernel32, test app)", ev(d, 23) >= 3,
                   f"files={ev(d, 23)}"))
    c.append(check("Win64: T_HELLO.EXE ran twice under the PE32+ loader, exit code 7, no fault",
                   res & 0xffffffff == 7 and not res >> 32 & 1 and bool(res >> 33 & 1) and bool(res >> 34 & 1),
                   f"slot30={res:#x}"))
    c.append(check("Win64: app saw image base 0x140000000 (above 4 GiB), PROCESSOR_ARCHITECTURE=AMD64, argc=2",
                   ev(d, 19) == 0x140000000 and ev(d, 20) == 1 and ev(d, 21) == 2,
                   f"base={ev(d, 19):#x} arch_ok={ev(d, 20)} argc={ev(d, 21)}"))
    c.append(check("Win64: second process returned every physical page", res != 0 and ev(d, 22) == 0,
                   f"delta={ev(d, 22)} pages"))
    return c


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    parser.add_argument("--firmware-code", default=qemu.DEFAULT_OVMF_CODE)
    parser.add_argument("--firmware-vars", default=qemu.DEFAULT_OVMF_VARS)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--cpu", default="host,+vmx", help="L1 CPU model (must expose VMX)")
    parser.add_argument("--no-vmx", action="store_true", help="negative test: hide VMX from L1")
    parser.add_argument("--memory", default="512M")
    args = parser.parse_args()

    esp = OUT / "esp.img"
    loader = OUT / "BOOTX64.EFI"
    receipt = OUT / "build-result.json"
    if not (esp.exists() and receipt.exists()):
        raise SystemExit("Run shizukudos/supervisor/build.py first")
    built = json.loads(receipt.read_text())
    for name, digest in built["sources_sha256"].items():
        if sha256_file(REPO / name) != digest:
            raise SystemExit(f"Stale build, source changed: {name}")
    shzinfo.selfcheck(REPO)

    run_dir = OUT / ("run-novmx" if args.no_vmx else "run-uefi-vreal")
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    variables = run_dir / "OVMF_VARS.fd"
    shutil.copyfile(args.firmware_vars, variables)
    disk_copy = run_dir / "esp.img"
    shutil.copyfile(esp, disk_copy)
    serial = run_dir / "serial.log"
    cpu = args.cpu if not args.no_vmx else "host,-vmx"

    with tempfile.TemporaryDirectory(prefix="shz-qmp-") as tmp:
        sock = Path(tmp) / "qmp.sock"
        command = [args.qemu, "-name", "shz-uefi-supervisor", "-machine", "q35", "-accel", "kvm", "-cpu", cpu,
                   "-m", args.memory, "-smp", "1", "-nodefaults", "-nic", "none", "-display", "none",
                   "-device", "VGA", "-no-reboot",
                   "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={Path(args.firmware_code).resolve()}",
                   "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
                   "-drive", f"if=none,id=esp,format=raw,file={disk_copy}",
                   "-device", "virtio-blk-pci,drive=esp,bootindex=1",
                   "-serial", f"file:{serial}", "-qmp", f"unix:{sock},server=on,wait=off"]
        proc = qemu.launch(command, run_dir)
        qmp = None
        record = {"profile": "uefi-supervisor-vreal-dos16", "boot_path": "UEFI x64 (OVMF) -> ExitBootServices",
                  "layers": {"L0": "Linux host KVM", "L1": f"QEMU q35 -cpu {cpu} (OVMF + Supervisor)",
                             "L2": "DOS16 domain, virtual Real Mode"},
                  "command": command}
        samples = []
        info = None
        final = None
        try:
            qmp = qemu.QMP(sock, timeout=20)
            deadline = time.time() + args.timeout
            sampled_running = False
            while time.time() < deadline:
                time.sleep(0.5)
                if proc.poll() is not None:
                    break
                info = read_info(qmp, run_dir)
                if info is None:
                    continue
                if info.stage == 5 and not sampled_running:
                    # Independent L0/KVM view of the vCPU while the L2 guest is executing.
                    sampled_running = True
                    samples.append({"when": "L2 running", "registers": qemu.cpu_state(qmp)})
                if info.stage in (6, 0xdead):
                    break
            info = read_info(qmp, run_dir) or info
            record["final_stage"] = info.stage_name() if info else "no info page"
            if info and info.stage >= 4:
                time.sleep(0.5)
                samples.append({"when": "after session", "registers": qemu.cpu_state(qmp)})
                qmp.call("screendump", {"filename": str(run_dir / "screen.ppm")})
                text = qemu.read_guest_memory(qmp, info.guest_ram_base + 0xb8000, 4000, run_dir / "b8000.bin")
                record["text_screen"] = qemu.decode_text_page(text)
                qemu.read_guest_memory(qmp, info.disk_base, info.disk_size, run_dir / "disk_after.img")
                final = info
            qmp.call("quit")
        except Exception as exc:  # keep the evidence collected so far
            record["harness_error"] = repr(exc)
        finally:
            if qmp:
                qmp.close()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        record["qemu_exit_code"] = proc.returncode

    serial_text = serial.read_text(errors="replace") if serial.exists() else ""
    checks = []
    if args.no_vmx:
        # Negative test: without VMX the loader must refuse and return to firmware.
        checks.append(check("loader refused (no VMX exposed to L1)",
                            "Intel VMX backend unusable" in serial_text or info is None,
                            (info.stage_name() if info else "Supervisor never ran")))
        checks.append(check("Supervisor payload never started", info is None or info.stage < 2))
        status = verify.overall(checks)
        record.update({"status": status, "checks": checks, "serial_tail": serial_text[-2000:]})
        shzlib.write_json(run_dir / "result.json", record)
        for c in checks:
            print(f"  [{c['status']}] {c['check']}  {c['detail']}")
        print(status)
        return 0 if status == "PASS" else 1

    checks.append(check("Supervisor reached guest-exit stage", final is not None and final.stage == 6,
                        (info.stage_name() + ": " + info.last_error.decode(errors="replace")) if info else "no info"))
    if final is not None:
        caps = set(final.caps())
        checks.append(check("capabilities detected from inside L1",
                            {"LONG_MODE", "VMX", "VMX_ENABLED", "EPT", "UNRESTRICTED", "BACKEND_VMX"} <= caps,
                            ",".join(sorted(caps))))
        checks.append(check("vendor read by Supervisor CPUID", final.vendor() == "GenuineIntel", final.vendor()))
        checks.append(check("host (VMX root) was 64-bit paging with CR4.VMXE",
                            bool(final.host_cr4 & (1 << 13)) and bool(final.host_efer & (1 << 10))
                            and bool(final.host_cr0 & 1) and bool(final.host_cr0 & (1 << 31)),
                            f"cr0={final.host_cr0:#x} cr4={final.host_cr4:#x} efer={final.host_efer:#x}"))
        checks.append(check("DOS guest first exit had CR0.PE=0 (Real Mode)",
                            final.first_exit.valid == 1 and not final.first_exit.cr0 & 1,
                            f"cr0={final.first_exit.cr0:#x} cs={final.first_exit.cs_sel:#x}"))
        checks.append(check("DOS guest last exit had CR0.PE=0 and EFER=0",
                            final.last_exit.valid == 1 and not final.last_exit.cr0 & 1 and final.last_exit.efer == 0,
                            f"cr0={final.last_exit.cr0:#x} efer={final.last_exit.efer:#x}"))
        checks.append(check("virtual timer interrupts were injected", final.injected_irqs > 0,
                            str(final.injected_irqs)))
        checks.append(check("guest hypercalls and I/O exits counted", final.hypercalls > 50 and final.io_exits > 100,
                            f"hypercalls={final.hypercalls} io_exits={final.io_exits}"))
        checks.append(check("guest requested exit code 0", final.guest_exit_requested == 1 and final.guest_exit_code == 0))
        disk_after = run_dir / "disk_after.img"
        if disk_after.exists():
            d_checks, result_text = verify.verify_disk(disk_after)
            for c in d_checks:
                c["check"] = "L2 " + c["check"]
            checks += d_checks
            record["result_txt"] = result_text
        checks += verify.verify_screen(record.get("text_screen", []))
        domains = final.to_dict()["domains"]
        if "KERNEL32" in domains:
            checks += check_kernel32(domains["KERNEL32"])
        if "KERNEL64" in domains:
            checks += check_kernel64(domains["KERNEL64"])
        checks.append(check("all three domains were scheduled by the Supervisor",
                            {"DOS16", "KERNEL32", "KERNEL64"} <= set(domains), ",".join(domains)))
    # Independent view from L0/KVM. While L2 runs, KVM reports the register state of whichever
    # level is executing at that instant, so a sample is valid if it matches EITHER the DOS
    # domain in real mode OR the Supervisor's own VMX-root state recorded in the info page.
    views = []
    for sample in samples:
        regs = sample["registers"]
        cr0 = re.search(r"CR0=([0-9a-fA-F]{8})", regs)
        cr3 = re.search(r"CR3=([0-9a-fA-F]{16}|[0-9a-fA-F]{8})", regs)
        cs = re.search(r"CS =([0-9a-f]{4}) ([0-9a-f]{8,16})", regs)
        efer = re.search(r"EFER=([0-9a-fA-F]{16})", regs)
        real_mode = bool(cr0) and not int(cr0.group(1), 16) & 1 and cs is not None and \
            int(cs.group(2), 16) == int(cs.group(1), 16) << 4
        root = final is not None and cr3 is not None and int(cr3.group(1), 16) == final.host_cr3 and \
            cs is not None and cs.group(1) == "0008" and efer is not None and int(efer.group(1), 16) & 0x400
        views.append({"when": sample["when"], "l2_real_mode": real_mode, "supervisor_root_mode": bool(root)})
    record["independent_views"] = views
    checks.append(check("independent L0/KVM register samples match L2 real mode or Supervisor root state",
                        bool(views) and all(v["l2_real_mode"] or v["supervisor_root_mode"] for v in views),
                        str([(v["when"], "L2" if v["l2_real_mode"] else "root" if v["supervisor_root_mode"] else "??")
                             for v in views])))
    checks.append(check("guest console marker in physical serial log", "SHZ-EXIT:0" in serial_text))

    status = verify.overall(checks)
    record.update({"status": status, "checks": checks, "samples": samples,
                   "info": final.to_dict() if final else (info.to_dict() if info else None),
                   "esp_sha256": sha256_file(esp), "loader_sha256": sha256_file(loader),
                   "git": shzlib.git_state(), "qemu": qemu.qemu_version(args.qemu), "utc": shzlib.utc_now(),
                   "serial_tail": serial_text[-3000:]})
    shzlib.write_json(run_dir / "result.json", record)
    for c in checks:
        print(f"  [{c['status']}] {c['check']}  {c['detail']}")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
