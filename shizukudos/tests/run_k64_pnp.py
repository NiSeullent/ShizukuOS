#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""A real driver package installs AND runs on Kernel64: boot the standalone Kernel64 under QEMU with an Intel e1000 NIC
(-device e1000, PCI 8086:100e) and drive the whole path a vendor package takes, with the unmodified ReactOS e1000
NDIS miniport (shizukudos/ntdrv/corpus/build.py --packages) and the unmodified ReactOS ndis.sys it imports:

  store.py add <package>  ->  \\DRIVERS\\e1000 on the medium (initrd here)
  SHZPNP.EXE add-driver C:\\DRIVERS\\e1000\\nete1000.inf --legacy --install   (INF -> files, Services\\e1000, Enum devnode,
                                                                          the Net class installer's registry output)
  SHZPNP.EXE load e1000   ->  NtLoadDriver: ndis.sys loaded first (import dependency), e1000.sys mapped, DriverEntry,
                              the Enum-bound function claimed (ntdrv:e1000), AddDevice + IRP_MN_START_DEVICE
  SHZPNP.EXE status       ->  the adapter's device object and PCI function

The guest program \\SHZ\\TESTS\\T_PNP_LOAD.EXE issues these commands and checks the results (registry, claim registry,
device object, an IRP_MJ_CREATE to the adapter); the kernel log carries the loader/PnP evidence. The initrd is
composed here from WIN64.IMG (system DLLs, SHZPNP.EXE, T_HELLO.EXE), T_PNP_LOAD.EXE, ndis.sys under \\SHZ\\SYS64\\DRIVERS
and the driver store built with store.py, so the default WIN64.IMG is untouched.

Exit codes: 0 PASS, 1 FAIL (any FAIL line, missing evidence, timeout), 2 BLOCKED (the corpus is not built here:
run shizukudos/ntdrv/corpus/fetch.py and build.py --packages first).
"""
import argparse
import importlib.util
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, REPO  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
CORPUS = BUILD / "ntdrv"
PACKAGE = CORPUS / "packages" / "e1000"
NDIS = CORPUS / "corpus" / "ndis" / "gcc" / "ndis.sys"
STORE_PY = REPO / "shizukudos" / "ntdrv" / "store.py"


def check(name, ok, detail=""):
    return {"check": name, "status": "PASS" if ok else "FAIL", "detail": detail}


def unpack_archive(data):
    """SHZARC01 -> [(path, bytes)] (the format win64/build.py pack_archive writes)."""
    if data[:8] != b"SHZARC01":
        raise SystemExit("WIN64.IMG is not a SHZARC01 archive")
    count = struct.unpack_from("<I", data, 8)[0]
    files = []
    for i in range(count):
        raw, off, size = struct.unpack_from("<120sQQ", data, 16 + 136 * i)
        files.append((raw.split(b"\0", 1)[0].decode("ascii"), data[off:off + size]))
    return files


def load_pack_archive():
    spec = importlib.util.spec_from_file_location("win64_build", REPO / "shizukudos" / "win64" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.pack_archive


def compose_initrd(out_dir):
    """WIN64.IMG minus the other T_*.EXE, plus T_PNP_LOAD.EXE, ndis.sys and the driver store."""
    files = [(p, d) for p, d in unpack_archive((WIN64 / "WIN64.IMG").read_bytes())
             if not (p.upper().startswith("\\SHZ\\TESTS\\T_") and p.upper() != "\\SHZ\\TESTS\\T_HELLO.EXE")]
    files.append(("\\SHZ\\TESTS\\T_PNP_LOAD.EXE", (WIN64 / "t_pnp_load.exe").read_bytes()))
    files.append(("\\SHZ\\SYS64\\DRIVERS\\ndis.sys", NDIS.read_bytes()))
    root = Path(tempfile.mkdtemp(prefix="shzpnpstore"))
    try:
        subprocess.run([sys.executable, str(STORE_PY), "--root", str(root), "add", str(PACKAGE), "--name", "e1000"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        drivers = root / "DRIVERS"
        for p in sorted(drivers.rglob("*")):
            if p.is_file():
                files.append(("\\DRIVERS\\" + "\\".join(p.relative_to(drivers).parts), p.read_bytes()))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    img = out_dir / "WIN64_PNP.IMG"
    img.write_bytes(load_pack_archive()(files))
    return img, [p for p, _ in files]


def parse(serial):
    m = re.search(r"^SHZ-EXIT:([0-9a-f]+)$", serial, re.M)
    return int(m.group(1), 16) if m else None


def evaluate(serial, exit_code):
    c = []
    c.append(check("Kernel64 finished its self-tests and exited 0", exit_code == 0 and "K64 test FAIL" not in serial, f"exit={exit_code}"))
    c.append(check("the e1000 function is on the bus (kernel PCI scan reports 8086:100e)", bool(re.search(r"K64 pci: \S+ 8086:100e", serial))))
    c.append(check("T_PNP_LOAD.EXE ran to PASS", "t_pnp_load: PASS" in serial, "t_pnp_load: FAIL" if "t_pnp_load: FAIL" in serial else ""))
    fails = re.findall(r"T_PNP_LOAD\.EXE pid \d+\] (FAIL: .*)", serial)
    c.append(check("no FAIL line from T_PNP_LOAD.EXE", not fails, "; ".join(fails[:5])))
    c.append(check("e1000.sys imports ndis.sys, which the host loaded first (unmodified ReactOS ndis.sys, DriverEntry run)",
                   "K64 ntdrv: e1000 imports ndis.sys: loading it first" in serial and
                   bool(re.search(r"K64 ntdrv: ndis mapped at [0-9a-f]+ \(\d+ bytes\), calling DriverEntry", serial))))
    c.append(check("e1000.sys mapped and its DriverEntry called", bool(re.search(r"K64 ntdrv: e1000 mapped at [0-9a-f]+ \(\d+ bytes\), calling DriverEntry", serial))))
    c.append(check("no unresolved import for ndis.sys or e1000.sys", "K64 ntdrv: unresolved import" not in serial,
                   "; ".join(re.findall(r"K64 ntdrv: unresolved import \S+", serial)[:8])))
    c.append(check("the Enum-bound function is claimed for the hosted driver (pci_claim ntdrv:e1000)",
                   bool(re.search(r"K64 ntdrv: e1000 owns PCI [0-9a-f]+:[0-9a-f]+\.[0-9a-f]+ \(8086:100e\)", serial))))
    c.append(check("AddDevice succeeded (the NDIS FDO was attached to the PDO)", bool(re.search(r"K64 ntdrv: e1000 AddDevice\(PCI [^)]*\) = 0\b", serial)),
                   "; ".join(re.findall(r"K64 ntdrv: e1000 AddDevice.*", serial)[:2])))
    c.append(check("IRP_MN_START_DEVICE completed with STATUS_SUCCESS (MiniportInitialize ran on the NIC)",
                   bool(re.search(r"K64 ntdrv: e1000 IRP_MN_START_DEVICE\(PCI [^)]*\) = 0 \(started\)", serial)),
                   "; ".join(re.findall(r"K64 ntdrv: e1000 IRP_MN_START_DEVICE.*", serial)[:2])))
    c.append(check("no kernel fault or bug check", "KeBugCheck" not in serial and "K64 panic" not in serial and "#PF" not in serial))
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(K64S / "pnp-run"))
    args = ap.parse_args()
    stub, kernel = K64S / "boot.elf", K64S / "KERNEL64S.BIN"
    for f in (stub, kernel, WIN64 / "WIN64.IMG", WIN64 / "t_pnp_load.exe"):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    missing = [str(p) for p in (PACKAGE / "e1000.sys", PACKAGE / "nete1000.inf", NDIS) if not p.exists()]
    if missing:
        record = {"profile": "kernel64-standalone + e1000 (NT driver host PnP, no Supervisor, no VMX)", "status": "BLOCKED",
                  "reason": "driver corpus not built: " + ", ".join(missing),
                  "needed": "python3 shizukudos/ntdrv/corpus/fetch.py && python3 shizukudos/ntdrv/corpus/build.py --packages",
                  "utc": shzlib.utc_now(), "git": shzlib.git_state()}
        shzlib.write_json(out / "result.json", record)
        print("BLOCKED: " + record["reason"])
        print("  needed: " + record["needed"])
        return 2
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    initrd, packed = compose_initrd(out)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults",
           "-display", "none", "-kernel", str(stub), "-initrd", f"{kernel},{initrd}",
           "-netdev", "user,id=n0", "-device", "e1000,netdev=n0", "-serial", f"file:{serial_path}",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    exit_code = parse(serial)
    checks = evaluate(serial, exit_code)
    if timed_out:
        checks.insert(0, check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"profile": "kernel64-standalone + e1000 (NT driver host PnP, no Supervisor, no VMX)", "accel": accel,
              "status": status, "checks": checks, "exit_code": exit_code, "seconds": round(time.time() - started, 1),
              "package": {"inf": "nete1000.inf", "sys_sha256": shzlib.sha256_file(PACKAGE / "e1000.sys"),
                          "ndis_sha256": shzlib.sha256_file(NDIS)},
              "initrd_files": packed, "command": cmd, "qemu_output": qemu_out[-1500:], "serial_tail": serial[-8000:],
              "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-6000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
