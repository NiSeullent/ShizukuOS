#!/usr/bin/env python3
"""Build OFFNLS.DLL and OFNLSPRB.EXE for genuine Windows 98 and gate imports.

Runs the host logic controls, compiles both i486 PE32 images, and refuses any
import absent from the Windows 98 SE native KERNEL32 export manifest. Launches
no VM or application. SPDX-License-Identifier: GPL-2.0-only
"""
import argparse, hashlib, json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANIFEST = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
CC = "i686-w64-mingw32-gcc"
COMMON = ["-std=c99", "-O2", "-march=i486", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
          "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-mno-stack-arg-probe",
          "-nostdlib", "-Wl,--major-subsystem-version,4", "-Wl,--minor-subsystem-version,10",
          "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10", "-Wl,--no-insert-timestamp",
          "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise SystemExit(f"FAIL {' '.join(map(str, cmd))}\n{result.stdout}{result.stderr}")
    return result.stdout


def gate(binary, exported, own_exports=None):
    import pefile
    pe = pefile.PE(str(binary))
    opt = pe.OPTIONAL_HEADER
    if (pe.FILE_HEADER.Machine, opt.Magic, opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14C, 0x10B, 4, 10):
        raise SystemExit(f"{binary.name}: not a classic i386 4.10 image")
    if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)):
        raise SystemExit(f"{binary.name}: requires TLS/load-config/delay/CLR state")
    imports = {}
    for desc in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = desc.dll.decode().upper()
        names = sorted(i.name.decode() for i in desc.imports if i.name)
        if dll == "OFFNLS.DLL" and own_exports is not None and not set(names) - set(own_exports):
            imports[dll] = names
            continue
        if dll not in ("KERNEL32.DLL", "USER32.DLL") or set(names) - set(exported[dll]):
            raise SystemExit(f"{binary.name}: import unavailable on Win98 SE: {dll} {set(names) - set(exported.get(dll, []))}")
        imports[dll] = names
    exports = sorted(e.name.decode() for e in getattr(pe, "DIRECTORY_ENTRY_EXPORT", type("", (), {"symbols": []})).symbols if e.name)
    pe.close()
    return {"bytes": binary.stat().st_size, "sha256": sha(binary), "imports": imports, "exports": exports,
            "native_import_gate": "PASS", "native_executed": False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    out = pathlib.Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=False)
    run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O1", "-o", out / "host_test",
         HERE / "office_nls.c", HERE / "host_test.c"])
    host = run([out / "host_test"]).strip()
    if not host.endswith(", 0 failures"):
        raise SystemExit(host)
    dll, exe = out / "OFFNLS.DLL", out / "OFNLSPRB.EXE"
    run([CC, *COMMON, "-shared", "-Wl,--kill-at", "-Wl,-e,_DllMain@12", "-o", dll, HERE / "office_nls_win98.c",
         HERE / "office_nls.c", HERE / "office_nls.def", "-lkernel32", "-lgcc"])
    run([CC, *COMMON, "-mwindows", "-Wl,-e,_probe_entry@0", "-o", exe, HERE / "native_probe.c", "-lkernel32", "-luser32", "-lgcc"])
    implib = out / "libOFFNLS.a"
    run(["i686-w64-mingw32-dlltool", "-k", "-d", HERE / "office_nls.def", "-D", "OFFNLS.DLL", "-l", implib])
    link = out / "OFNLSLNK.EXE"
    run([CC, *COMMON, "-Wl,-e,_link_entry@0", "-o", link, HERE / "link_check.c", implib, "-lkernel32", "-lgcc"])
    exported = json.loads(MANIFEST.read_text())["dlls"]
    dll_receipt = gate(dll, exported)
    receipt = {"schema": "shizuku.office-nls-build.v1", "host_controls": host,
               "sources": {p.name: sha(p) for p in sorted(HERE.glob("*")) if p.suffix in (".c", ".h", ".def", ".py")},
               "artifacts": {dll.name: dll_receipt, exe.name: gate(exe, exported),
                             link.name: gate(link, exported, dll_receipt["exports"])},
               "scope": "host logic controls and native import gate only; no Windows 98 execution"}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
