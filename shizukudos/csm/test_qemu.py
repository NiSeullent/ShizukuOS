#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""UEFI -> CSMWrap -> SeaBIOS CSM16 -> MBR -> FreeDOS, on the dual BIOS/UEFI disk.

Boots build/shizukudos/dos16/shizukudos-dos16-dual.img under OVMF (q35, OVMF CODE
as read-only pflash, a per-run copy of the VARS store, disk on the ICH9 AHCI port
as bootindex=1). OVMF has no CSM of its own; the firmware's default boot option
starts \\EFI\\BOOT\\BOOTX64.EFI = CSMWrap (external, LGPL-2.1), which installs the
SeaBIOS CSM16 (LGPL-3.0) below 1 MiB, exits boot services and legacy-boots the MBR
of the disk it came from. The DOS16 conformance run (T_MODE/T_BIOS/T_INTS/T_COM/
T_EXE) must then give the same results as the legacy BIOS path.

By default the same image is also booted on the legacy path (QEMU SeaBIOS) with
identical emulated hardware (dos16/test_csm.py --image dual --machine q35 ...),
and the two T_INTS results are compared value by value. A third, short run with
one vCPU checks CSMWrap's documented requirement of a spare logical CPU.

This runs QEMU as a development tool; nothing here involves VMX or the Shizuku
Supervisor. Evidence: build/shizukudos/csm/run-uefi-csmwrap/result.json.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, str(HERE.parent / "dos16"))
import ints  # noqa: E402
import qemu  # noqa: E402
import shzlib  # noqa: E402
import test_csm  # noqa: E402
import verify  # noqa: E402
from shzlib import BUILD, SHZ, sha256_file  # noqa: E402

OUT = BUILD / "csm"
IMAGE = BUILD / "dos16" / "shizukudos-dos16-dual.img"
LEGACY_RUN = "run-csm-dual"

# Serial lines, in boot order, that only the UEFI -> CSMWrap path produces.
UEFI_MARKERS = [
    ("OVMF BDS starts the disk's UEFI boot option", re.compile(r"BdsDxe: starting Boot\w+ .*(Sata|HD|Scsi)\(")),
    ("CSMWrap read csmwrap.ini from the ESP", re.compile(r"^\s*serial = true", re.M)),
    ("CSMWrap unlocked the legacy BIOS region (PAM)", re.compile(r"^Unlock!", re.M)),
    ("CSMWrap placed CSM16 at E0000h", re.compile(r"csm_bin_base: 0xe0000")),
    ("CSMWrap BIOS proxy running on a reserved AP", re.compile(r"BIOS proxy ready \(AP (\d+)\)")),
    ("CSMWrap boot device = this AHCI disk", re.compile(r"bootdev: Boot device: PCI 00:1f\.2 type=HDD")),
    ("CSMWrap built E820 from the UEFI memory map", re.compile(r"csmwrap e820 map has \d+ items")),
    ("DOS ran to the end (SHZEXIT on COM1)", re.compile(r"SHZ-EXIT:0")),
]


def check(name, ok, detail=""):
    return {"check": name, "status": "PASS" if ok else "FAIL", "detail": detail}


def ordered_markers(text):
    """Each marker must appear, and after the previous one."""
    out, pos = [], 0
    for name, rx in UEFI_MARKERS:
        m = rx.search(text, pos)
        out.append(check(f"UEFI path serial: {name}", bool(m), m.group(0).strip()[:90] if m else "missing / out of order"))
        if m:
            pos = m.end()
    return out


def boot(args, run_dir, smp, wait_for, timeout, dump=True):
    """One OVMF run of a private copy of the dual image. Returns dict with paths, text and dumps."""
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    disk, vars_copy, serial = run_dir / "disk.img", run_dir / "OVMF_VARS.fd", run_dir / "serial.log"
    shutil.copy2(IMAGE, disk)
    shutil.copy2(args.firmware_vars, vars_copy)
    res = {"disk": disk, "serial": serial, "dumps": {}}
    with tempfile.TemporaryDirectory(prefix="shz-csm-qmp-") as tmp:
        sock = Path(tmp) / "qmp.sock"
        command = [args.qemu, "-name", "shz-csm-uefi",
                   "-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={args.firmware_code}",
                   "-drive", f"if=pflash,unit=1,format=raw,file={vars_copy}",
                   *test_csm.hardware_args("q35", args.accel, args.memory, smp, disk),
                   "-qmp", f"unix:{sock},server=on,wait=off", "-serial", f"file:{serial}"]
        res["command"] = command
        res["utc"] = shzlib.utc_now()
        started = time.time()
        proc = qemu.launch(command, run_dir)
        qmp = None
        try:
            qmp = qemu.QMP(sock)
            res["seen"] = wait_for_any(serial, wait_for, timeout, proc)
            res["seconds"] = round(time.time() - started, 1)
            if dump:
                res["regs"] = qemu.cpu_state(qmp)
                res["screen"] = qemu.decode_text_page(qemu.read_guest_memory(qmp, 0xB8000, 4000, run_dir / "b8000.bin"))
                (run_dir / "screen.txt").write_text("\n".join(res["screen"]) + "\n")
                res["dumps"]["high_alias"] = qemu.read_guest_memory(qmp, test_csm.HIGH_ALIAS, 0x40000,
                                                                    run_dir / "fw-high.bin")
                res["dumps"]["ef_segment"] = qemu.read_guest_memory(qmp, 0xE0000, 0x20000, run_dir / "ef-seg.bin")
            qmp.call("quit")
        finally:
            if qmp:
                qmp.close()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
                proc.wait()
        res["qemu_exit_code"] = proc.returncode
    res["serial_text"] = serial.read_bytes().decode("ascii", "replace").replace("\r", "") if serial.exists() else ""
    return res


def wait_for_any(path, needles, timeout, proc):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = path.read_bytes() if path.exists() else b""
        for n in needles:
            if n.encode() in data:
                return n
        if proc.poll() is not None:
            return None
        time.sleep(0.2)
    return None


def legacy_run(args):
    rj = BUILD / "dos16" / LEGACY_RUN / "result.json"
    if args.legacy_result:
        return json.loads(Path(args.legacy_result).read_text()), Path(args.legacy_result)
    cmd = [sys.executable, SHZ / "dos16" / "test_csm.py", "--qemu", args.qemu, "--image", "dual", "--machine", "q35",
           "--memory", str(args.memory), "--smp", str(args.smp), "--accel", args.accel,
           "--timeout", str(args.timeout), "--run-name", LEGACY_RUN]
    subprocess.run([str(x) for x in cmd], check=False, timeout=args.timeout + 120)
    return (json.loads(rj.read_text()) if rj.exists() else None), rj


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    parser.add_argument("--firmware-code", default=qemu.DEFAULT_OVMF_CODE)
    parser.add_argument("--firmware-vars", default=qemu.DEFAULT_OVMF_VARS)
    parser.add_argument("--accel", choices=("kvm", "tcg", "auto"), default="auto")
    parser.add_argument("--memory", type=int, default=256, help="MiB (same for both paths)")
    parser.add_argument("--smp", type=int, default=2, help="vCPUs; CSMWrap needs >= 2 (one AP is its system thread)")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--legacy-result", help="reuse this dos16/test_csm.py --image dual result.json")
    parser.add_argument("--no-legacy", action="store_true", help="UEFI path only, no comparison")
    parser.add_argument("--no-negative", action="store_true", help="skip the 1-vCPU CSMWrap refusal run")
    args = parser.parse_args()
    args.accel = test_csm.resolve_accel(args.accel)
    if not IMAGE.exists():
        raise SystemExit("Run shizukudos/dos16/build.py first")
    for fw in (args.firmware_code, args.firmware_vars):
        if not Path(fw).exists():
            raise SystemExit(f"OVMF firmware missing: {fw}")
    manifest = shzlib.load_manifest()["upstreams"]["csmwrap"]
    csm_version = f"{manifest['seabios_version']}-CSMWrap-{manifest['build_version']}".encode()
    dual_receipt = json.loads((BUILD / "dos16" / "build-result.json").read_text())
    run_dir = OUT / "run-uefi-csmwrap"
    OUT.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- UEFI path
    r = boot(args, run_dir, args.smp, ["SHZ-EXIT:0", "*** PANIC"], args.timeout)
    checks, text = verify.verify_disk(r["disk"])
    checks += verify.verify_screen(r.get("screen", []))
    cr0 = re.search(r"CR0=([0-9a-fA-F]{8})", r.get("regs", ""))
    checks.append(check("independent CR0.PE=0 (accelerator state)", bool(cr0) and not int(cr0.group(1), 16) & 1,
                        cr0.group(0) if cr0 else "missing"))
    checks.append(check("guest requested end through COM1 marker", r.get("seen") == "SHZ-EXIT:0", str(r.get("seen"))))
    more, uefi_ix = verify.verify_ints(r["disk"], IMAGE, run_utc=r["utc"])
    checks += more
    # evidence that this really was UEFI -> CSMWrap, not a legacy BIOS
    cmd = r["command"]
    checks.append(check("QEMU: OVMF CODE as read-only pflash, per-run VARS copy, no -bios",
                        f"if=pflash,unit=0,format=raw,readonly=on,file={args.firmware_code}" in cmd
                        and any(str(run_dir) in c and "unit=1" in c for c in cmd) and "-bios" not in cmd))
    code = Path(args.firmware_code).read_bytes()
    checks.append(check("firmware: 4 GiB-256 KiB flash alias == tail of OVMF CODE (UEFI firmware at the reset vector)",
                        r["dumps"].get("high_alias") == code[-0x40000:], args.firmware_code))
    checks.append(check("firmware: no SeaBIOS image in the reset-vector flash", b"SeaBIOS" not in r["dumps"].get(
        "high_alias", b"SeaBIOS")))
    rom = test_csm.seabios_rom()
    csm16 = (OUT / "Csm16.bin").read_bytes()
    fp = test_csm.ef_fingerprint(r["dumps"].get("ef_segment", b""), csm16, rom.read_bytes() if rom else b"")
    record_fp = dict(fp, csm16_sha256=sha256_file(OUT / "Csm16.bin"), csm16_version=csm_version.decode(),
                     csm16_version_in_build=csm_version in csm16)
    checks.append(check("firmware: E/F segment is the pinned CSMWrap SeaBIOS CSM16 (IFE$ + CSMPPrxy at Csm16.bin "
                        "offsets, >= 90% of F segment), not QEMU's SeaBIOS",
                        fp["csm_signatures_at_csm16_offsets"] and (fp["fseg_same_as_csm16"] or 0) >= 0.9
                        and not fp["qemu_seabios_version_present"] and csm_version in csm16,
                        f"{fp['csm_signatures']} F-seg same as Csm16.bin {fp['fseg_same_as_csm16']}, "
                        f"as QEMU SeaBIOS {fp['fseg_same_as_qemu_seabios']}"))
    screen = r.get("screen") or [""]
    checks.append(check("firmware: screen line 1 is the pinned CSMWrap SeaBIOS banner",
                        screen[0] == f"SeaBIOS (version {csm_version.decode()})", screen[0]))
    serial_text = r["serial_text"]
    checks += ordered_markers(serial_text)
    m = re.search(r"removed (\d+) CPU entries, system thread APIC ID (\d+)", serial_text)
    mp = re.search(r"mptable: (\d+) CPUs", serial_text)
    checks.append(check(f"CSMWrap reserved one of {args.smp} vCPUs as system thread; MADT/MP table show the rest",
                        bool(m and mp) and int(m.group(1)) == 1 and int(mp.group(1)) == args.smp - 1,
                        f"system thread APIC ID {m.group(2) if m else '?'}, MP table CPUs {mp.group(1) if mp else '?'}"))
    csm_e820 = ints.csmwrap_e820_from_serial(serial_text)
    if uefi_ix is not None and csm_e820:
        ok, detail = ints.e820_explained_by_csmwrap(ints.e820_entries(uefi_ix), csm_e820)
        checks.append(check("E820 seen by DOS == CSMWrap's map of the UEFI memory map (+SeaBIOS RAM/reserved moves)",
                            ok, detail))
    else:
        checks.append(check("E820 seen by DOS == CSMWrap's map of the UEFI memory map", False, "no data"))

    record = {"profile": "uefi-csmwrap-dos16",
              "boot_path": "OVMF (UEFI, no CSM) -> \\EFI\\BOOT\\BOOTX64.EFI = CSMWrap -> SeaBIOS CSM16 -> MBR -> "
                           "FreeDOS boot sector -> KERNEL.SYS (real mode)",
              "external_code": {"csmwrap": manifest["commit"], "seabios": manifest["submodules"]["seabios"]["commit"],
                                "licenses": "CSMWrap LGPL-2.1, SeaBIOS LGPL-3.0 (see shizukudos/upstream/manifest.json)"},
              "accel": args.accel, "hardware": {"machine": "q35", "memory_mib": args.memory, "smp": args.smp},
              "command": [str(c) for c in cmd], "seconds_to_shz_exit": r.get("seconds"),
              "image_sha256": sha256_file(IMAGE), "dual_img_build_sha256": dual_receipt["artifacts"]["dual.img"]["sha256"],
              "bootx64_sha256": dual_receipt["artifacts"]["BOOTX64.EFI"]["sha256"],
              "disk_after_sha256": sha256_file(r["disk"]), "result_txt": text, "screen": r.get("screen"),
              "ovmf": {"code": args.firmware_code, "code_sha256": sha256_file(args.firmware_code),
                       "vars_template": args.firmware_vars},
              "firmware": record_fp, "ints": uefi_ix, "utc": r["utc"], "qemu": qemu.qemu_version(args.qemu), "git": shzlib.git_state()}

    # ---------------------------------------------------------------- legacy path, same image and hardware
    if not args.no_legacy:
        legacy, legacy_path = legacy_run(args)
        record["legacy_result"] = str(legacy_path)
        checks.append(check("same image on legacy BIOS (QEMU SeaBIOS, q35/AHCI): DOS16 conformance + T_INTS",
                            bool(legacy) and legacy.get("status") == "PASS",
                            f"{legacy_path}: {legacy.get('status') if legacy else 'missing'}"))
        if legacy:
            same_hw = (legacy.get("hardware") == record["hardware"] and legacy.get("accel") == args.accel
                       and legacy.get("image_sha256") == record["image_sha256"]
                       and not any("pflash" in str(c) for c in legacy.get("command", [])))
            checks.append(check("legacy and UEFI runs: same image, machine, RAM, vCPUs, accelerator; only firmware differs",
                                same_hw, f"legacy={legacy.get('hardware')} {legacy.get('accel')} "
                                         f"uefi={record['hardware']} {args.accel}"))
            leg_checks = {c["check"]: c["status"] for c in legacy.get("checks", []) if not c["check"].startswith(
                "firmware:")}
            uefi_checks = {c["check"]: c["status"] for c in checks if c["check"] in leg_checks}
            checks.append(check("DOS16 + T_INTS host checks: identical verdicts on both paths",
                                bool(leg_checks) and uefi_checks == leg_checks and set(leg_checks.values()) == {"PASS"},
                                f"{len(leg_checks)} checks"))
            leg_lines = [l for l in (legacy.get("result_txt") or "").splitlines() if l.strip()]
            uefi_lines = [l for l in (text or "").splitlines() if l.strip()]
            strip = [re.sub(r" EXT=[0-9A-F]{8}", " EXT=*", l) for l in leg_lines]
            ustrip = [re.sub(r" EXT=[0-9A-F]{8}", " EXT=*", l) for l in uefi_lines]
            checks.append(check("RESULT.TXT identical on both paths except T_BIOS EXT (= INT 15h AH=88h, see T_INTS)",
                                strip == ustrip and len(strip) == 7 and strip[-1] == "DONE",
                                "; ".join(f"legacy {a} / uefi {b}" for a, b in zip(leg_lines, uefi_lines) if a != b)))
            if legacy.get("ints") and uefi_ix:
                rows = ints.compare(legacy["ints"], uefi_ix)
                bad = [x for x in rows if x["class"] == "UNEXPECTED-DIFF"]
                counts = {k: sum(1 for x in rows if x["class"] == k) for k in ("MATCH", "EXPECTED-DIFF",
                                                                                 "UNEXPECTED-DIFF")}
                checks.append(check("T_INTS legacy vs UEFI+CSMWrap: all values match except documented differences",
                                    not bad, f"{counts}" + (f" unexpected: {[x['item'] for x in bad]}" if bad else "")))
                record["ints_compare"] = ints.pack_rows(rows)
                record["ints_compare_counts"] = counts
                record["freedos_use"] = ints.FREEDOS_USE
                lines = [f"{x['class']:15} {x['item']:16} legacy: {x['legacy']}\n{'':32}uefi:   {x['uefi']}"
                         + (f"\n{'':32}reason: {x['reason']}" if x["reason"] else "") for x in record["ints_compare"]]
                (run_dir / "ints-compare.txt").write_text("\n".join(lines) + "\n")

    # ---------------------------------------------------------------- CSMWrap needs a spare logical CPU
    if not args.no_negative:
        n = boot(args, OUT / "run-uefi-csmwrap-1cpu", 1, ["No AP available for BIOS proxy", "SHZ-EXIT:0"],
                 min(args.timeout, 180), dump=False)
        checks.append(check("negative: with 1 vCPU CSMWrap refuses (no AP for the BIOS proxy) and DOS never starts",
                            n.get("seen") == "No AP available for BIOS proxy" and "SHZ-EXIT" not in n["serial_text"],
                            str(n.get("seen"))))
        record["negative_1cpu"] = {"seen": n.get("seen"), "command": [str(c) for c in n["command"]]}

    status = verify.overall(checks)
    record.update({"status": status, "checks": checks})
    shzlib.write_json(run_dir / "result.json", record)
    for c in checks:
        print(f"  [{c['status']}] {c['check']}  {c['detail']}")
    if record.get("ints_compare_counts"):
        print(f"  T_INTS comparison: {record['ints_compare_counts']} -> {run_dir / 'ints-compare.txt'}")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
