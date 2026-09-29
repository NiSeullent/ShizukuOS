#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Cross-check of the C INF engine used by the Win64 CLI shzpnp (shizukudos/win64/apps/shzpnp/shzinf.c) against the
Python reference shizukudos/ntdrv/inf.py.

shzinf.c is compiled for the host together with tests/shzinf_host.c; both implementations then produce the same
canonical dump (models, DDInstall resolution, CopyFiles, AddReg, services, ranks) for every INF under tests/inf and,
when fetched, every INF of the ReactOS and virtio-win trees, under Windows x64 rules and with the ReactOS-style
undecorated fallback; and the same device IDs and identifier scores for a set of PCI devices. Any difference fails.

Run: python3 shizukudos/ntdrv/tests/test_shzpnp.py [--quick]
"""
import argparse
import difflib
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
import inf as I  # noqa: E402

SRC = REPO / "shizukudos" / "win64" / "apps" / "shzpnp"
OUT = REPO / "build" / "shizukudos" / "ntdrv" / "shzinf_host"
DEVICES = ["8086:100E", "8086:100E:001E8086:03:020000", "1AF4:1000:00011AF4:00:020000", "1AF4:1001", "8086:2922::02:010601",
           "1AF4:7001:00011AF4:01:020000", "1AF4:7005:00051AF4:02:020000", "1AF4:1052", "10EC:8139", "1022:2000",
           "8086:7010:-:-:010180", "PCI\\VEN_8086&DEV_7111", "K64 pci: 0:3.0 8086:100e class 020000 irq 11"]


def build_host():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    cc = shutil.which("gcc") or shutil.which("cc")
    cmd = [cc, "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-I", str(SRC), str(SRC / "shzinf.c"), str(HERE / "shzinf_host.c"), "-o", str(OUT)]
    subprocess.run(cmd, check=True)
    return OUT


def esc(s):
    return (s or "").replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("|", "\\|")


def reg_line(tag, e):
    t, f = e["type"], e["flags"] & 0xFFFFFFFF
    d = e["data"]
    if d is None:
        data = "-"
    elif t in (I.Inf.REG_DWORD, I.Inf.REG_QWORD):
        data = f"n:{d}"
    elif t in (I.Inf.REG_BINARY, I.Inf.REG_NONE) or (e["flags"] & I.Inf.FLG_BINVALUETYPE):
        data = "b:" + d.hex()
    elif t == I.Inf.REG_MULTI_SZ:
        data = f"m{len(d)}:" + esc("\n".join(d))
    else:
        data = "s:" + esc(d)
    return f"{tag} {esc(e['root'])}|{esc(e['subkey'])}|{esc(e['name'])}|{f}|{t}|{data}"


def num(v):
    return "-" if v is None or v < 0 else str(v)


def py_dump(path, legacy, build):
    t = I.Target(build=build, legacy=bool(legacy))
    inf = I.Inf.load(path)
    v = inf.version
    out = [f"VERSION class={esc(v['Class'])} provider={esc(v['Provider'])} driverver={esc(v['DriverVer'])} catalog={esc(v['CatalogFile'])}"]
    for m in inf.models(t):
        inst = inf.install(m["install"], t)
        out.append(f"MODEL {m['lineno']} {esc(m['section'])}|{esc(m['install'])}|{esc(m['hwids'][0])}|"
                   f"{';'.join(esc(c) for c in m['compat_ids'])}|{esc(m['description'])}")
        fs = inst["feature_score"]
        decorated = bool(inst["section"]) and inst["section"].lower() != m["install"].lower()
        rank = ((I.SIGNATURE_UNSIGNED_NT if decorated else I.SIGNATURE_UNSIGNED) << 24) | (((fs if fs is not None else 0xFF) & 0xFF) << 16)
        kmdf = (inst["wdf"] or {}).get("KmdfLibraryVersion") if inst["wdf"] and inst["wdf"].get("kind") == "KMDF" else None
        out.append(f"INSTALL {esc(inst['section'] or '-')} feature={num(fs)} driverver={esc(inst['driverver'] or '-')} "
                   f"kmdf={esc(kmdf or '-')} rank={rank:08x}")
        for c in inst["copyfiles"]:
            out.append(f"COPY {esc(c['dest'])}|{esc(c['source'])}|{c['dirid'][0]}|{esc(c['dirid'][1])}|{c['flags'] & 0xFFFFFFFF}|{esc(c['section'] or '-')}")
        out += [reg_line("REG", e) for e in inst["addreg"]]
        out += [reg_line("HWREG", e) for e in inst["hw_addreg"]]
        for s in inst["services"]:
            if s.get("delete"):
                out.append(f"SVC {esc(s['name'])}|delete")
                continue
            out.append(f"SVC {esc(s['name'])}|{s['flags'] & 0xFFFFFFFF}|{esc(s['section'])}|{num(s['ServiceType'])}|{num(s['StartType'])}|"
                       f"{num(s['ErrorControl'])}|{esc(s['ServiceBinary'] or '-')}|{esc(s['LoadOrderGroup'] or '-')}|"
                       f"{esc(s['DisplayName'] or '-')}|{';'.join(esc(d) for d in s['Dependencies'][:16])}")
            out += [reg_line("SVCREG", e) for e in s["AddReg"]]
    return out


def py_match(spec, paths, legacy, build):
    t = I.Target(build=build, legacy=bool(legacy))
    try:
        dev = I.Device.parse(spec)
    except ValueError:
        return ["BADDEVICE"]
    out = [f"HW {x}" for x in dev.hwids] + [f"CP {x}" for x in dev.compat_ids]
    for n, p in enumerate(paths):
        inf = I.Inf.load(p)
        for m in inf.models(t):
            best = I.identifier_score(dev, m)
            if not best:
                continue
            inst = inf.install(m["install"], t)
            fs = inst["feature_score"] if inst["feature_score"] is not None else 0xFF
            decorated = bool(inst["section"]) and inst["section"].lower() != m["install"].lower()
            rank = ((I.SIGNATURE_UNSIGNED_NT if decorated else I.SIGNATURE_UNSIGNED) << 24) | ((fs & 0xFF) << 16) | best[0]
            out.append(f"HIT {n} {m['lineno']} {esc(m['install'])} {rank:08x} {best[0]:04x} {best[1]:04x} {esc(best[2])}")
    return out


def c_run(exe, args):
    r = subprocess.run([str(exe), *map(str, args)], capture_output=True, check=False)
    return r.stdout.decode("utf-8", errors="replace").splitlines()


def compare(label, a, b):
    if a == b:
        return True
    diff = list(difflib.unified_diff(a, b, "inf.py", "shzinf.c", lineterm="", n=1))
    print(f"MISMATCH {label}:")
    for line in diff[:24]:
        print("   " + line)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="synthetic INFs only")
    args = ap.parse_args()
    exe = build_host()
    infs = sorted((HERE / "inf").glob("*.inf"))
    if not args.quick:
        for sub in ("reactos", "virtio-win"):
            base = REPO / "build" / "upstream" / sub
            if base.is_dir():
                infs += sorted(p for p in base.rglob("*.inf") if p.is_file())
    ok = bad = lines = 0
    for p in infs:
        for legacy in (0, 1):
            for build in (22631, 14393):
                a, b = py_dump(p, legacy, build), c_run(exe, ["dump", p, legacy, build])
                lines += len(a)
                if compare(f"dump {p.name} legacy={legacy} build={build}", a, b):
                    ok += 1
                else:
                    bad += 1
    match_infs = [p for p in infs if p.parent.name == "inf"] + [p for p in infs if p.name in (
        "nete1000.inf", "netrtl.inf", "netamd.inf", "netkvm.inf", "storahci.inf", "uniata_comm.inf", "machine.inf", "hdaudio.inf")]
    for spec in DEVICES:
        for legacy in (0, 1):
            a, b = py_match(spec, match_infs, legacy, 22631), c_run(exe, ["match", legacy, 22631, spec, *match_infs])
            if compare(f"match {spec} legacy={legacy}", a, b):
                ok += 1
            else:
                bad += 1
    print(f"test_shzpnp: {len(infs)} INF files, {ok} comparisons identical, {bad} differ ({lines} canonical dump lines from inf.py)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
