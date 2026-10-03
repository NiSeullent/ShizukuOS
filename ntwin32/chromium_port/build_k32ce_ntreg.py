#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build + receipt for M98K32CE.DLL and M98NTREG.DLL (chrome_elf 157 providers).

Freezes the exact sources, runs the ASan/UBSan host controls (with the pinned
chrome_elf.dll when --chrome-elf is given), cross-compiles both providers for
i486 and gates each PE: i386, PE32, subsystem 4.10, DllCharacteristics 0, no
TLS/load-config/delay/CLR directory, every import present in the Win98 SE OEM
export inventory, and every contract-routed symbol exported. No VM, no target
application execution; a PASS receipt is host/compile evidence only."""
import argparse, datetime, hashlib, json, shutil, subprocess, sys
from pathlib import Path
import pefile

ROOT = Path(__file__).resolve().parents[2]
CP = "ntwin32/chromium_port/"
FILES = [CP + n for n in ("k32_compat.h", "k32_compat.c", "k32_native.c", "k32_native.def", "k32_host_test.c",
         "k32_ext_host_test.c", "nt_registry.h", "nt_registry.c", "nt_registry_native.c", "nt_registry_native.def",
         "nt_registry_host_test.c", "api_contract.h", "api_contract.c", "build_k32ce_ntreg.py")] + [
         "src/m98_fls.c", "src/m98_fls.h", "src/m98_initonce.c", "src/m98_initonce.h", "src/m98_slist.c", "src/m98_slist.h",
         "ntwin32/native_environment/environment.h", "ntwin32/native_environment/environment.c",
         "benchmarks/win98se-ko-oem-native-exports-v1.json"]
ELF_PIN = "54ffa9edd24ed9251fefca50abd27d4542fe81b63757d0ed0df2304a36ad1473"
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def gate(path, inventory, required):
    pe = pefile.PE(str(path)); oh = pe.OPTIONAL_HEADER; dd = oh.DATA_DIRECTORY; bad = []
    if pe.FILE_HEADER.Machine != 0x14c or oh.Magic != 0x10b: bad.append("not i386 PE32")
    if (oh.MajorSubsystemVersion, oh.MinorSubsystemVersion) != (4, 10): bad.append("subsystem not 4.10")
    if oh.DllCharacteristics: bad.append("DllCharacteristics nonzero")
    for i, n in ((9, "TLS"), (10, "LOAD_CONFIG"), (13, "DELAY_IMPORT"), (14, "CLR")):
        if dd[i].VirtualAddress or dd[i].Size: bad.append(n + " directory present")
    imports = sorted((d.dll.decode().upper(), i.name.decode() if i.name else f"#{i.ordinal}")
                     for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in d.imports)
    bad += [f"import {d}!{n} not in Win98 SE inventory" for d, n in imports if n not in inventory.get(d, ())]
    exports = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    bad += [f"missing export {n}" for n in sorted(required - exports)]
    return {"sha256": sha(path), "bytes": path.stat().st_size, "imports": [f"{d}!{n}" for d, n in imports],
            "exports": len(exports), "subsystem": f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}"}, bad

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--chrome-elf", type=Path, help="pinned chrome_elf.dll (sha256 54ffa9ed...) for contract controls")
    a = ap.parse_args(); out = a.out.resolve()
    clang, cross = shutil.which("clang"), shutil.which("i686-w64-mingw32-gcc")
    if out.exists() or not (str(out).startswith("/dev/shm/") or out.is_relative_to(ROOT / "build")) or not clang or not cross:
        ap.error("fresh output under /dev/shm or build/ and clang + i686-w64-mingw32-gcc required")
    if a.chrome_elf and sha(a.chrome_elf) != ELF_PIN: ap.error("chrome_elf.dll is not the pinned 157 bytes")
    out.mkdir(parents=True); pins = {}
    for n in FILES:
        dest = out / "frozen" / n; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ROOT / n, dest); pins[n] = sha(dest)
    fz = out / "frozen"; cp = fz / CP; env = fz / "ntwin32/native_environment/environment.c"
    san = [clang, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
           "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-pthread"]
    cross_flags = [cross, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                   "-Wno-array-bounds", "-fno-builtin", "-fno-tree-loop-distribute-patterns", "-fno-stack-protector",
                   "-ffunction-sections", "-fdata-sections", "-nostdlib", "-shared", "-Wl,--gc-sections",
                   "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,0",
                   "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
                   "-Wl,--no-insert-timestamp", "-Wl,--entry,_dll_entry@12"]
    elf = [str(a.chrome_elf)] if a.chrome_elf else []
    steps = [("host-k32", san + [str(cp / "k32_compat.c"), str(cp / "k32_host_test.c"), str(cp / "api_contract.c"), str(env), "-o", str(out / "host-k32")], elf),
             ("host-k32-ext", san + [str(cp / "k32_compat.c"), str(cp / "k32_ext_host_test.c"), str(cp / "api_contract.c"), str(env), "-o", str(out / "host-k32-ext")], elf),
             ("host-ntreg", san + [str(cp / "nt_registry.c"), str(cp / "nt_registry_host_test.c"), "-o", str(out / "host-ntreg")], []),
             ("M98K32CE.DLL", cross_flags + [str(cp / "k32_compat.c"), str(cp / "k32_native.c"), str(fz / "src/m98_fls.c"),
               str(fz / "src/m98_initonce.c"), str(fz / "src/m98_slist.c"), str(cp / "k32_native.def"),
               "-o", str(out / "M98K32CE.DLL"), "-lkernel32", "-ladvapi32", "-lgcc"], None),
             ("M98NTREG.DLL", cross_flags + [str(cp / "nt_registry.c"), str(cp / "nt_registry_native.c"), str(cp / "nt_registry_native.def"),
               "-o", str(out / "M98NTREG.DLL"), "-lkernel32", "-ladvapi32", "-lgcc"], None)]
    receipt = {"schema": "win98modern.chromium-elf-providers.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "sources": pins,
               "compilers": {"host": {"path": clang, "sha256": sha(clang)}, "native": {"path": cross, "sha256": sha(cross)}},
               "chrome_elf_sha256": ELF_PIN if a.chrome_elf else None, "steps": {}, "native_executed": False,
               "application_executed": False, "scope": "host ASan/UBSan controls + i486 cross-compile/PE import gate only"}
    inventory = {k.upper(): set(v) for k, v in json.loads((fz / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"].items()}
    k32_required = {l.split("=")[0].strip() for l in (cp / "k32_native.def").read_text().splitlines()[2:] if "=" in l}
    nt_required = {l.split("=")[0].strip() for l in (cp / "nt_registry_native.def").read_text().splitlines()[2:] if l.strip() and not l.strip().startswith(("LIBRARY", "EXPORTS"))}
    ok = True
    try:
        for name, cmd, run_args in steps:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=ROOT)
            step = {"command": cmd, "rc": r.returncode, "log": (r.stdout + r.stderr)[-2000:]}
            if not r.returncode and run_args is not None:
                t = subprocess.run([cmd[cmd.index("-o") + 1]] + run_args, capture_output=True, text=True, timeout=60, cwd=ROOT)
                step["run"] = {"rc": t.returncode, "stdout": t.stdout[-1500:], "stderr": t.stderr[-1500:]}
                ok &= t.returncode == 0 and not t.stderr and t.stdout.rstrip().splitlines()[-1].startswith("PASS")
            elif not r.returncode:
                info, bad = gate(out / name, inventory, k32_required if name == "M98K32CE.DLL" else nt_required)
                step.update(info); step["gate_failures"] = bad; ok &= not bad
            ok &= r.returncode == 0; receipt["steps"][name] = step
        receipt["status"] = "PASS" if ok else "FAIL"
    finally:
        (out / "receipt.json").write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
    for n, s in receipt["steps"].items():
        print(n, "rc", s["rc"], s.get("run", {}).get("stdout", "").strip().splitlines()[-1:] if "run" in s else s.get("sha256"),
              s.get("gate_failures", ""), s["log"][-600:] if s["rc"] else "")
    print("RECEIPT", receipt["status"], out / "receipt.json")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
