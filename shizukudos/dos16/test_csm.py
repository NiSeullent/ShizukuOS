#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""CSM/Legacy-BIOS profile test: FreeDOS DOS16 on a real BIOS in actual Real Mode.

QEMU's SeaBIOS plays the role of the legacy firmware, so this validates the DOS16
runtime (kernel, shell, COM/MZ execution, file I/O) and the conformance programs.
It says nothing about the Shizuku Supervisor or UEFI paths.

Default: shizukudos-dos16-hd32.img on `-machine pc` (IDE, 64 MiB, 1 vCPU).
`--image dual` boots shizukudos-dos16-dual.img instead and adds the T_INTS BIOS
interrupt checks plus firmware identification; shizukudos/csm/test_qemu.py runs it
with exactly the hardware of its UEFI run (q35, AHCI, same RAM and vCPUs) so the
two boot paths of one image can be compared.
"""
import argparse
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import qemu  # noqa: E402
import shzlib  # noqa: E402
import verify  # noqa: E402
from shzlib import BUILD, sha256_file  # noqa: E402

IMAGES = {"hd32": "shizukudos-dos16-hd32.img", "dual": "shizukudos-dos16-dual.img"}
SEABIOS_CANDIDATES = ("/usr/share/qemu/bios-256k.bin", "/usr/share/seabios/bios-256k.bin")
HIGH_ALIAS = 0x1_0000_0000 - 0x40000          # last 256 KiB below 4 GiB: the firmware ROM/flash as mapped


def resolve_accel(accel):
    if accel != "auto":
        return accel
    return "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"


def hardware_args(machine, accel, memory, smp, disk):
    """The emulated PC shared by the legacy and the UEFI+CSMWrap runs (firmware excluded)."""
    args = ["-machine", machine, "-accel", accel, "-cpu", "host" if accel == "kvm" else "qemu64",
            "-m", str(memory), "-smp", str(smp), "-display", "none", "-monitor", "none", "-vga", "std"]
    if machine == "q35":      # q35's ide.0 is the ICH9 AHCI controller (00:1f.2), port 0
        args += ["-drive", f"file={disk},format=raw,if=none,id=d0,cache=writethrough",
                 "-device", "ide-hd,drive=d0,bus=ide.0,bootindex=1"]
    else:
        args += ["-drive", f"file={disk},format=raw,if=ide,cache=writethrough"]
    return args + ["-net", "none", "-no-reboot"]


def seabios_rom():
    return next((Path(p) for p in SEABIOS_CANDIDATES if Path(p).exists()), None)


def seabios_version(rom_bytes):
    """Version string that follows the 'SeaBIOS (version %s)' format in a SeaBIOS image."""
    at = rom_bytes.find(b"SeaBIOS (version")
    m = re.search(rb"(\d+\.\d+\.\d+-[\x21-\x7e]+)\x00", rom_bytes[at:]) if at >= 0 else None
    return m.group(1) if m else None


def ef_fingerprint(ef, csm16, qemu_rom):
    """Which BIOS occupies E0000h-FFFFFh at run time?

    SeaBIOS reuses its init area for tables after POST, so version strings there are gone. What stays:
    CSM-only signatures ('IFE$' = EFI_COMPATIBILITY16_TABLE, 'CSMPPrxy' = CSMWrap's BIOS-proxy mailbox)
    at the same offsets as in the pinned Csm16.bin, and the runtime F segment's bytes."""
    fseg = ef[0x10000:]

    def same(a, b):
        return round(sum(1 for x, y in zip(a, b) if x == y) / max(1, len(a)), 3)
    csm_sigs = {sig.decode(): (ef.find(sig), csm16.find(sig) if csm16 else -2) for sig in (b"IFE$", b"CSMPPrxy")}
    qv = seabios_version(qemu_rom) if qemu_rom else None
    return {"csm_signatures": csm_sigs,
            "csm_signatures_at_csm16_offsets": all(a >= 0 and a == b for a, b in csm_sigs.values()),
            "csm_signatures_absent": all(a < 0 for a, _ in csm_sigs.values()),
            "fseg_same_as_csm16": same(fseg, csm16[0x10000:]) if len(csm16 or b"") == 0x20000 else None,
            "fseg_same_as_qemu_seabios": same(fseg, qemu_rom[-0x10000:]) if qemu_rom else None,
            "qemu_seabios_version": qv.decode() if qv else None,
            "qemu_seabios_version_present": bool(qv) and qv in ef}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    parser.add_argument("--accel", choices=("kvm", "tcg", "auto"), default="kvm")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--image", default="hd32", help="hd32 (default), dual, or a path")
    parser.add_argument("--machine", choices=("pc", "q35"), default="pc")
    parser.add_argument("--memory", type=int, default=64, help="MiB")
    parser.add_argument("--smp", type=int, default=1)
    parser.add_argument("--run-name", default=None, help="run directory under build/shizukudos/dos16")
    args = parser.parse_args()
    accel = resolve_accel(args.accel)

    out = BUILD / "dos16"
    image = out / IMAGES[args.image] if args.image in IMAGES else Path(args.image).resolve()
    dual = args.image == "dual" or image.name == IMAGES["dual"]
    if not image.exists():
        raise SystemExit("Run shizukudos/dos16/build.py first")
    run_dir = out / (args.run_name or ("run-csm-dual" if dual else "run-csm"))
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    disk = run_dir / "disk.img"
    shutil.copy2(image, disk)
    serial = run_dir / "serial.log"
    with tempfile.TemporaryDirectory(prefix="shz-qmp-") as tmp:
        sock = Path(tmp) / "qmp.sock"
        if args.machine == "pc" and args.smp == 1 and not dual:
            # the original legacy profile command line, unchanged
            command = [args.qemu, "-name", "shz-dos16-csm", "-machine", "pc", "-accel", accel,
                       "-cpu", "host" if accel == "kvm" else "qemu64", "-m", str(args.memory),
                       "-display", "none", "-monitor", "none", "-vga", "std",
                       "-qmp", f"unix:{sock},server=on,wait=off", "-serial", f"file:{serial}",
                       "-drive", f"file={disk},format=raw,if=ide,cache=writethrough",
                       "-boot", "c", "-net", "none", "-no-reboot"]
        else:
            command = [args.qemu, "-name", "shz-dos16-csm", *hardware_args(args.machine, accel, args.memory,
                                                                           args.smp, disk),
                       "-qmp", f"unix:{sock},server=on,wait=off", "-serial", f"file:{serial}"]
        run_utc = shzlib.utc_now()
        proc = qemu.launch(command, run_dir)
        record = {"profile": "csm-real-mode-dos16", "boot_path": "SeaBIOS (legacy BIOS) -> MBR -> real mode",
                  "host_mode": "n/a (firmware is the platform)", "guest_mode": "real mode (16-bit)",
                  "kernel_instance": "dos16-freedos", "image": str(image), "accel": accel,
                  "hardware": {"machine": args.machine, "memory_mib": args.memory, "smp": args.smp},
                  "command": command}
        qmp = None
        firmware = {}
        try:
            qmp = qemu.QMP(sock)
            seen = qemu.wait_for(serial, "SHZ-EXIT:0", args.timeout)
            regs = qemu.cpu_state(qmp)
            record["independent_cpu_state"] = regs
            screen = qemu.decode_text_page(qemu.read_guest_memory(qmp, 0xB8000, 4000, run_dir / "b8000.bin"))
            (run_dir / "screen.txt").write_text("\n".join(screen) + "\n")
            if dual:
                firmware["high_alias"] = qemu.read_guest_memory(qmp, HIGH_ALIAS, 0x40000, run_dir / "fw-high.bin")
                firmware["ef_segment"] = qemu.read_guest_memory(qmp, 0xE0000, 0x20000, run_dir / "ef-seg.bin")
            qmp.call("quit")
        finally:
            if qmp:
                qmp.close()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        record["qemu_exit_code"] = proc.returncode
    checks, text = verify.verify_disk(disk)
    checks += verify.verify_screen(screen)
    cr0 = re.search(r"CR0=([0-9a-fA-F]{8})", regs)
    checks.append(verify._check("independent CR0.PE=0 (accelerator state)", bool(cr0) and not int(cr0.group(1), 16) & 1,
                                cr0.group(0) if cr0 else "missing"))
    checks.append(verify._check("guest requested end through COM1 marker", seen))
    if dual:
        more, ix = verify.verify_ints(disk, image, run_utc=run_utc)
        checks += more
        record["ints"] = ix
        rom = seabios_rom()
        rom_bytes = rom.read_bytes() if rom else b""
        csm16 = BUILD / "csm" / "Csm16.bin"
        fp = ef_fingerprint(firmware.get("ef_segment", b""), csm16.read_bytes() if csm16.exists() else b"", rom_bytes)
        checks.append(verify._check("firmware: 4 GiB-256 KiB ROM alias == QEMU SeaBIOS image (legacy BIOS path)",
                                    bool(rom_bytes) and firmware.get("high_alias") == rom_bytes[-0x40000:],
                                    str(rom)))
        checks.append(verify._check("firmware: E/F segment is QEMU's SeaBIOS (version string, >= 90% of F segment), "
                                    "no CSM signatures",
                                    fp["qemu_seabios_version_present"] and fp["csm_signatures_absent"]
                                    and (fp["fseg_same_as_qemu_seabios"] or 0) >= 0.9,
                                    f"{fp['qemu_seabios_version']} F-seg same as QEMU SeaBIOS "
                                    f"{fp['fseg_same_as_qemu_seabios']}, as CSM16 {fp['fseg_same_as_csm16']}"))
        checks.append(verify._check("firmware: screen line 1 is QEMU SeaBIOS's banner",
                                    bool(fp["qemu_seabios_version"]) and screen[:1] == [
                                        f"SeaBIOS (version {fp['qemu_seabios_version']})"], screen[0] if screen else ""))
        record["firmware"] = {"seabios_rom": str(rom), "seabios_rom_sha256": sha256_file(rom) if rom else None,
                              "ef_fingerprint": fp}
    status = verify.overall(checks)
    record.update({"status": status, "checks": checks, "result_txt": text,
                   "image_sha256": sha256_file(image), "disk_after_sha256": sha256_file(disk),
                   "git": shzlib.git_state(), "qemu": qemu.qemu_version(args.qemu), "utc": run_utc,
                   "screen": screen})
    shzlib.write_json(run_dir / "result.json", record)
    for c in checks:
        print(f"  [{c['status']}] {c['check']}  {c['detail']}")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
