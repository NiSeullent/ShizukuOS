#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot standalone Kernel64 with NVMe and SD cards attached and verify the storage path from the host side.

Profile: the standalone profile of run_k64_standalone.py (QEMU -kernel stub, no Supervisor, TCG or KVM) plus
  -device nvme (one controller, two namespaces: 256 MiB with 512-byte LBAs + GPT, 64 MiB with 4096-byte LBAs + MBR/EBR)
  -device sdhci-pci + sd-card twice (128 MiB SDSC card with an MBR, 4 GiB SDHC card with a GPT, sparse)
Every image is generated here from fixed seeds (tests/blk_images.py) and attached writable (no snapshot), NVMe with
discard=unmap. The guest programs T_BLK_PERF.EXE and T_BLK_RAW.EXE (win64/tests/t_blk_*.c) run as part of the normal
app list. The host then
  * checks the device and partition list the guest reports against the tables it wrote (names, sizes, starts, types),
  * replays the serial log in order on a model of every image: each BLK-W line (a guest write) is applied with the same
    pattern generator after checking the guest's CRC of what it wrote, each BLK-TRIM with the zeros the guest saw, and
    each BLK-CRC line (a guest read) is compared with the model at that moment,
  * compares every image file with its model after QEMU exited (all data extents): every guest write is where it
    should be and nothing else changed,
  * checks the driver-level results (NVMe MSI-X/INTx/poll, queue depth, timeout -> reset, error paths, SD PIO vs
    ADMA2) and turns BLK-PERF lines into MiB/s and IOPS (as measured in this run; reported, never asserted).
All checks of run_k64_standalone.py must still pass in this configuration.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, str(HERE))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402
import run_k64_standalone as base  # noqa: E402
import blk_images  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
MiB = 1 << 20
GiB = 1 << 30

# name -> image description. "parts": what blk_part.c must report, in its order: (start, sectors, scheme, type, name).
DEVICES = {
    "nvme0n1": {"size": 256 * MiB, "ss": 512, "seed": 101, "gpt": [(2048, 65536, "SHZ-DATA"), (67584, 65536, "SHZ-SCRATCH"),
                                                                   (133120, 32768, "SHZ-LAST")]},
    "nvme0n2": {"size": 64 * MiB, "ss": 4096, "seed": 102,
                "mbr": ([(256, 2048, 0x83, True), (2304, 2048, 0xDA, False)], (4352, 4096, [(16, 1024, 0x83), (16, 1024, 0x83)]))},
    "mmcblk0": {"size": 128 * MiB, "ss": 512, "seed": 103, "mbr": ([(2048, 32768, 0x83, False), (34816, 65536, 0xDA, False)], None)},
    "mmcblk1": {"size": 4 * GiB, "ss": 512, "seed": 104, "sparse": [(0, 16 * MiB), (1 * GiB, 4 * MiB), (4 * GiB - 2 * MiB, 2 * MiB)],
                "gpt": [(2048, 131072, "SD-DATA"), (2097152, 1048576, "SD-BIG")]},
}


def expected_partitions(name, d):
    if "gpt" in d:
        return [(s, n, 2, 0xEE, nm) for s, n, nm in d["gpt"]]
    prim, ext = d["mbr"]
    return [(s, n, 1, t, "") for s, n, t in blk_images.mbr_partitions(prim, ext)]


def build_image(path, d):
    """Writes the image (sparse where declared) and returns it."""
    path.unlink(missing_ok=True)
    with open(path, "wb") as fh:
        fh.truncate(d["size"])
        regions = d.get("sparse", [(0, d["size"])])
        for i, (off, n) in enumerate(regions):
            fh.seek(off)
            fh.write(blk_images.content(n, d["seed"] * 100 + i))
        if "gpt" in d:
            blobs = blk_images.gpt_blobs(d["size"], d["ss"], d["gpt"], seed=d["seed"])
        else:
            prim, ext = d["mbr"]
            fh.flush()
            with open(path, "rb") as rf:
                head = rf.read(d["ss"])
            blobs = blk_images.mbr_blobs(prim, ext, d["ss"], head)
        for off, blob in blobs:
            fh.seek(off)
            fh.write(blob)


def copy_sparse(src, dst):
    subprocess.run(["cp", "--sparse=always", str(src), str(dst)], check=True)


def data_extents(path):
    """[(start, end)] of the data (non-hole) ranges of a file."""
    out = []
    size = os.path.getsize(path)
    fd = os.open(path, os.O_RDONLY)
    try:
        pos = 0
        while pos < size:
            try:
                start = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError:
                break
            end = os.lseek(fd, start, os.SEEK_HOLE)
            out.append((start, end))
            pos = end
    finally:
        os.close(fd)
    return out


def files_equal(a, b):
    """Compares two equally sized files over the union of their data extents (holes read as zeros)."""
    if os.path.getsize(a) != os.path.getsize(b):
        return False, "sizes differ"
    ranges = sorted(data_extents(a) + data_extents(b))
    merged = []
    for s, e in ranges:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    with open(a, "rb") as fa, open(b, "rb") as fb:
        for s, e in merged:
            pos = s
            while pos < e:
                n = min(16 * MiB, e - pos)
                fa.seek(pos)
                fb.seek(pos)
                x, y = fa.read(n), fb.read(n)
                if x != y:
                    i = next(k for k in range(len(x)) if x[k] != y[k])
                    return False, f"first difference at byte {pos + i:#x}"
                pos += n
    return True, f"{sum(e - s for s, e in merged)} bytes compared"


class Model:
    """Expected content of every image while the serial log is replayed."""

    def __init__(self, out):
        self.files = {}
        self.dev_map = {}                          # guest name -> (image name, byte base, sector size)
        for name, d in DEVICES.items():
            self.files[name] = out / f"{name}.model"
            self.dev_map[name] = (name, 0, d["ss"])
            for k, (s, n, _, _, _) in enumerate(expected_partitions(name, d)):
                self.dev_map[f"{name}p{k + 1}"] = (name, s * d["ss"], d["ss"])

    def locate(self, dev, lba, count):
        img, base_off, ss = self.dev_map[dev]
        return img, base_off + lba * ss, count * ss, ss

    def read(self, dev, lba, count):
        img, off, n, _ = self.locate(dev, lba, count)
        with open(self.files[img], "rb") as fh:
            fh.seek(off)
            return fh.read(n)

    def write(self, dev, lba, data):
        img, off, _, _ = self.locate(dev, lba, 0)
        with open(self.files[img], "r+b") as fh:
            fh.seek(off)
            fh.write(data)


def replay(serial, model):
    """Applies BLK-W / BLK-TRIM and verifies BLK-CRC in log order. Returns (checks, stats)."""
    bad_w, bad_crc, n_w, n_crc, w_bytes = [], [], 0, 0, 0
    for m in re.finditer(r"^\[win64 (T_BLK_\w+)\.EXE pid \d+\] (BLK-(?:W|CRC|TRIM)) (.*)$", serial, re.M):
        kind, f = m.group(2), m.group(3).split()
        dev = f[0]
        if dev not in model.dev_map:
            bad_w.append(f"{dev}: unknown device")
            continue
        if kind == "BLK-W":
            lba, count, ss, tag, crc = int(f[1]), int(f[2]), int(f[3]), int(f[4]), int(f[5], 16)
            data = blk_images.app_pattern(lba * ss // 512, count * ss, tag)
            if zlib.crc32(data) & 0xffffffff != crc:
                bad_w.append(f"{dev} lba {lba}: guest pattern crc {crc:#x} != host {zlib.crc32(data) & 0xffffffff:#x}")
            model.write(dev, lba, data)
            n_w += 1
            w_bytes += len(data)
        elif kind == "BLK-TRIM":
            lba, count, tag, zeros = int(f[1]), int(f[2]), int(f[3]), int(f[4])
            ss = model.dev_map[dev][2]
            model.write(dev, lba, bytes(count * ss) if zeros else blk_images.app_pattern(lba * ss // 512, count * ss, tag))
        else:
            lba, count, crc = int(f[1]), int(f[2]), int(f[3], 16)
            want = zlib.crc32(model.read(dev, lba, count)) & 0xffffffff
            n_crc += 1
            if want != crc:
                bad_crc.append(f"{dev} {lba}+{count}: guest {crc:#x} host {want:#x}")
    checks = [base.check("replay: every guest write's pattern CRC matches the host generator", not bad_w and n_w > 0,
                         "; ".join(bad_w[:6]) or f"{n_w} writes, {w_bytes} bytes"),
              base.check("replay: every guest CRC-32 of a device/partition range equals the host image at that moment",
                         not bad_crc and n_crc > 0, "; ".join(bad_crc[:6]) or f"{n_crc} ranges")]
    return checks, {"writes": n_w, "write_bytes": w_bytes, "crc_ranges": n_crc}


def device_checks(serial):
    c = []
    got = {}
    for m in re.finditer(r"^\[win64 T_BLK_RAW\.EXE pid \d+\] BLK-DEV (\S+) (\S+) (\d+) (\d+) ([0-9a-f]+) (\d+) (\S+) (-?\d+) (\d+) (\d+) (\d+) ([0-9a-f]+) (.*)$",
                         serial, re.M):
        g = m.groups()
        got[g[0]] = {"driver": g[1], "sectors": int(g[2]), "ss": int(g[3]), "flags": int(g[4], 16), "qd": int(g[5]), "irq": g[6],
                     "part_index": int(g[8]), "start": int(g[9]), "scheme": int(g[10]), "type": int(g[11], 16), "ids": g[12]}
    bad = []
    for name, d in DEVICES.items():
        w = got.get(name)
        if not w:
            bad.append(f"{name}: missing")
            continue
        if (w["sectors"], w["ss"]) != (d["size"] // d["ss"], d["ss"]):
            bad.append(f"{name}: {w['sectors']} x {w['ss']} != {d['size'] // d['ss']} x {d['ss']}")
        for k, (s, n, scheme, ptype, pname) in enumerate(expected_partitions(name, d)):
            pn = f"{name}p{k + 1}"
            p = got.get(pn)
            if not p:
                bad.append(f"{pn}: missing")
                continue
            if (p["start"], p["sectors"], p["scheme"], p["type"], p["part_index"]) != (s, n, scheme, ptype, k + 1):
                bad.append(f"{pn}: start/size/scheme/type/index {p['start']}/{p['sectors']}/{p['scheme']}/{p['type']:#x}/{p['part_index']} "
                           f"!= {s}/{n}/{scheme}/{ptype:#x}/{k + 1}")
            if pname and not p["ids"].endswith("|" + pname):
                bad.append(f"{pn}: GPT name {p['ids']!r} does not end in {pname!r}")
        extra = [n for n in got if n.startswith(name + "p") and n not in {f"{name}p{k + 1}" for k in range(len(expected_partitions(name, d)))}]
        if extra:
            bad.append(f"{name}: unexpected partitions {extra}")
    c.append(base.check("guest enumerates nvme0n1 (512 B) / nvme0n2 (4 KiB LBA) / mmcblk0 (SDSC) / mmcblk1 (SDHC) with their exact "
                        "sizes and every GPT, MBR and EBR partition the host wrote", not bad, "; ".join(bad[:8]) or f"{len(got)} devices"))
    nv = [got.get(n, {}) for n in ("nvme0n1", "nvme0n2")]
    c.append(base.check("NVMe: completion by MSI-X, queue depth 32", all(x.get("irq") == "msix" and x.get("qd") == 32 for x in nv),
                        str([(x.get("irq"), x.get("qd")) for x in nv])))
    return c, got


def line(serial, pattern):
    return re.findall(pattern, serial, re.M)


def driver_checks(serial):
    c = []
    modes = {(m[0], m[1]): (int(m[2]), int(m[3])) for m in line(serial, r"BLK-MODE (\S+) (\S+) (\d+) (\d)$")}
    ok = all(modes.get((d, "intx"), (0, 0))[0] > 0 and modes.get((d, "poll"), (1, 0))[0] == 0 and modes.get((d, "best"), (0, 0))[0] > 0
             and all(modes.get((d, k), (0, 0))[1] == 1 for k in ("intx", "poll", "best")) for d in ("nvme0n1", "nvme0n2"))
    c.append(base.check("NVMe: identical data with INTx (interrupts > 0), polling (0 interrupts) and MSI-X again (interrupts > 0)",
                        ok, str(modes)))
    qd = {m[0]: int(m[1]) for m in line(serial, r"BLK-QD (\S+) (\d+)$")}
    c.append(base.check("NVMe: more than one command in flight at once (batches, split requests)",
                        all(qd.get(d, 0) > 1 for d in ("nvme0n1", "nvme0n2")), str(qd)))
    to = {m[0]: tuple(int(x) for x in m[1:]) for m in line(serial, r"BLK-TIMEOUT (\S+) (\d) (\d+) (\d+) (\d+)$")}
    c.append(base.check("NVMe: a command never doorbelled times out, the controller is reset and the command is resubmitted "
                        "and returns the right data", all(to.get(d, (0, 0, 0, 0))[0] == 1 and to[d][1] >= 1 and to[d][2] >= 1
                                                          for d in ("nvme0n1", "nvme0n2")), str(to)))
    c.append(base.check("NVMe: kernel log shows the reset and the resubmission",
                        bool(line(serial, r"K64 nvme0: controller reset \(command timeout\)")) and
                        bool(line(serial, r"K64 nvme0: recovered \(msix mode\), 1 command\(s\) resubmitted, 0 failed"))))
    err = {m[0]: (int(m[1]), int(m[2], 16)) for m in line(serial, r"BLK-ERRTEST (\S+) (\d) ([0-9a-f]+)$")}
    ok = all(err.get(d, (0, 0))[0] == 1 and err[d][1] & 0x7ff == 0x80 for d in ("nvme0n1", "nvme0n2")) and \
        all(err.get(d, (0, 0))[0] == 1 and err[d][1] & 0xc0000000 for d in ("mmcblk0", "mmcblk1"))
    c.append(base.check("error paths: NVMe READ past the end -> LBA Out of Range (SC 80h), SD read past the end -> "
                        "OUT_OF_RANGE/ADDRESS_ERROR in R1; both devices keep working", ok, str({k: (v[0], hex(v[1])) for k, v in err.items()})))
    trim = {m[0]: int(m[4]) for m in line(serial, r"BLK-TRIM (\S+) (\d+) (\d+) (\d+) (\d)$")}
    c.append(base.check("NVMe: DSM deallocate accepted on both namespaces (zeros read back where the backend punched a hole)",
                        set(trim) == {"nvme0n1", "nvme0n2"}, str(trim)))
    pio = {m[0]: (m[1], m[2], int(m[3])) for m in line(serial, r"BLK-PIO (\S+) ([0-9a-f]+) ([0-9a-f]+) (\d+)$")}
    c.append(base.check("SDHCI: PIO and ADMA2 reads of the same 512 KiB agree on both cards, PIO writes verified",
                        all(pio.get(d, ("a", "b", 0))[0] == pio[d][1] and pio[d][2] > 0 for d in ("mmcblk0", "mmcblk1")), str(pio)))
    sd = line(serial, r"K64 sdhci(\d): .*card (SDSC|SDHC/SDXC) .* (\d+) sectors \(\d+ MiB\), (byte|block) addressing, 4-bit bus")
    c.append(base.check("SDHCI: 128 MiB SDSC card (CSD 1.0, byte addressing) and 4 GiB SDHC card (CSD 2.0, block addressing), 4-bit bus",
                        sorted((k, int(n), a) for _, k, n, a in sd) == [("SDHC/SDXC", 8388608, "block"), ("SDSC", 262144, "byte")], str(sd)))
    c.append(base.check("T_BLK_RAW.EXE and T_BLK_PERF.EXE ran (no SKIP) and exited 0",
                        bool(line(serial, r"K64 win64 app: T_BLK_RAW\.EXE exit=0 faulted=0")) and
                        bool(line(serial, r"K64 win64 app: T_BLK_PERF\.EXE exit=0 faulted=0")) and "SKIP: no NVMe/SDHCI" not in serial))
    return c


def perf_numbers(serial):
    res = {}
    for dev, test, amount, ms in line(serial, r"BLK-PERF (\S+) (\S+) (\d+) (\d+)$"):
        amount, ms = int(amount), max(int(ms), 1)
        r = res.setdefault(dev, {})
        if test.startswith("seq"):
            r[test] = {"bytes": amount, "ms": ms, "MiB_per_s": round(amount / MiB / (ms / 1000), 1)}
        else:
            r[test] = {"ops": amount, "ms": ms, "IOPS": round(amount / (ms / 1000))}
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run_storage"))
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)

    t_img = time.time()
    model = Model(out)
    for name, d in DEVICES.items():
        build_image(out / f"{name}.img", d)
        copy_sparse(out / f"{name}.img", model.files[name])
    t_img = time.time() - t_img
    sector0 = (out / "nvme0n1.img").read_bytes()[:512]

    img = {n: out / f"{n}.img" for n in DEVICES}
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-drive", f"if=none,id=nv1,file={img['nvme0n1']},format=raw,discard=unmap",
           "-drive", f"if=none,id=nv2,file={img['nvme0n2']},format=raw,discard=unmap",
           "-device", "nvme,id=nvme0,serial=SHZNVME0",
           "-device", "nvme-ns,drive=nv1,bus=nvme0,nsid=1",
           "-device", "nvme-ns,drive=nv2,bus=nvme0,nsid=2,logical_block_size=4096,physical_block_size=4096",
           "-drive", f"if=none,id=sd0,file={img['mmcblk0']},format=raw",
           "-drive", f"if=none,id=sd1,file={img['mmcblk1']},format=raw",
           "-device", "sdhci-pci,id=sdhci0", "-device", "sd-card,drive=sd0,bus=/i440FX-pcihost/pci.0/sdhci0/sd-bus",
           "-device", "sdhci-pci,id=sdhci1", "-device", "sd-card,drive=sd1,bus=/i440FX-pcihost/pci.0/sdhci1/sd-bus"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    qemu_secs = time.time() - started
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    ev, exit_code = base.parse(serial)
    checks = base.evaluate(serial, ev, exit_code, proc.returncode)
    e = lambda s: ev.get(s, 0)  # noqa: E731
    checks.append(base.check("disk_init: sector 0 of the first whole device (nvme0n1) read by NVMe matches the host image",
                             e(13) == ((DEVICES["nvme0n1"]["size"] // 512) << 32) | (zlib.crc32(sector0) & 0xffffffff), f"{e(13):#x}"))
    dc, _ = device_checks(serial)
    checks += dc
    checks += driver_checks(serial)
    rc, stats = replay(serial, model)
    checks += rc
    for name in DEVICES:
        ok, detail = files_equal(img[name], model.files[name])
        checks.append(base.check(f"{name}: image file after the run equals the host model (guest writes landed exactly, nothing else changed)",
                                 ok, detail))
    if timed_out:
        checks.insert(0, base.check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    perf = perf_numbers(serial)
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"profile": "kernel64-standalone + NVMe (2 namespaces) + 2 x SDHCI/SD (no Supervisor, no VMX)", "accel": accel,
              "status": status, "checks": checks, "seconds": round(time.time() - started, 1), "qemu_seconds": round(qemu_secs, 1),
              "image_seconds": round(t_img, 1), "replay": stats, "throughput": perf,
              "evidence": {str(k): hex(v) for k, v in sorted(ev.items())}, "command": cmd, "qemu_output": qemu_out[-1500:],
              "serial_tail": serial[-4000:], "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    for dev, r in perf.items():
        print(f"  perf {dev}: " + ", ".join(f"{k} {v.get('MiB_per_s', v.get('IOPS'))}{' MiB/s' if 'MiB_per_s' in v else ' IOPS'}"
                                           for k, v in r.items()))
    print(f"{status} (accel={accel}, QEMU {qemu_secs:.0f}s)")
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    for name in DEVICES:                                 # the models are only needed for the comparison
        model.files[name].unlink(missing_ok=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
