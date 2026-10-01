#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/audit a separate Win98 GDI diagnostic; never run it or rebuild the driver package."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "shizukudos/tools"))
import shzlib

ALLOWED = {
    "KERNEL32.DLL": set("CloseHandle CreateFileA ExitProcess GetCurrentProcessId GetLastError GetModuleHandleA GetProcAddress GetTickCount GetVersionExA Sleep WriteFile".split()),
    "USER32.DLL": set("AdjustWindowRect BeginPaint ClientToScreen CreateWindowExA DefWindowProcA DestroyWindow DispatchMessageA EndPaint GetDC LoadCursorA PeekMessageA RegisterClassA ReleaseDC ShowWindow TranslateMessage UnregisterClassA UpdateWindow".split()),
    "GDI32.DLL": set("BitBlt CreateCompatibleDC CreateDIBSection CreateSolidBrush DeleteDC DeleteObject GdiFlush GetDeviceCaps PatBlt SelectObject".split()),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=shzlib.BUILD / "shizuku-gop-probe")
    args = parser.parse_args()
    out = args.out.resolve()
    if out == shzlib.BUILD.resolve() or not out.is_relative_to(shzlib.BUILD.resolve()):
        parser.error("--out must be a component directory under build/shizukudos")
    out.mkdir(parents=True, exist_ok=True)
    artifact = out / "SHZPROBE.EXE"
    inputs = {str(path.relative_to(REPO)): sha(path) for path in (HERE / "probe.c", Path(__file__), REPO / "ntwin32/prepare.py")}
    cmd = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-march=i486",
           "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
           "-mno-stack-arg-probe", "-fno-ident", "-fno-asynchronous-unwind-tables", "-nostdlib",
           "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
           "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
           "-Wl,--entry,_mainCRTStartup", "-Wl,--strip-all", str(HERE / "probe.c"), "-lkernel32", "-luser32", "-lgdi32", "-o", str(artifact)]
    env = dict(os.environ, LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="1785283200", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(cmd, cwd=REPO, env=env, text=True, capture_output=True)
    log = out / "build.log"
    log.write_text(" ".join(cmd) + "\n" + result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"Probe build failed; see {log}")
    spec = importlib.util.spec_from_file_location("shzgop_probe_pe", REPO / "ntwin32/prepare.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pe = module.PE(artifact.read_bytes())
    if pe.u16(pe.pe + 4) != 0x14c or pe.u16(pe.opt + 68) != 2 or (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50)) != (4, 10):
        raise RuntimeError("Expected i386 GUI PE32 Windows 4.10")
    if (pe.u16(pe.opt + 40), pe.u16(pe.opt + 42)) != (4, 10) or pe.u16(pe.pe + 22) & 0x2000 or pe.u16(pe.opt + 70) & (0x40 | 0x100 | 0x4000):
        raise RuntimeError("Unexpected DLL or modern PE loader flags")
    pe.offset(pe.u32(pe.opt + 16))
    for directory in (4, 9, 10, 13, 14):
        if any(pe.directory(directory)):
            raise RuntimeError("Unexpected security/TLS/load-config/delay/CLR directory")
    imports = {}
    for descriptor in pe.imports():
        dll = descriptor["dll"].upper()
        names = [entry[1] for entry in descriptor["entries"]]
        if dll not in ALLOWED or not set(names).issubset(ALLOWED[dll]):
            raise RuntimeError("Unexpected runtime or non-classic import: " + repr(descriptor))
        imports[dll] = sorted(names)
    if set(imports) != set(ALLOWED):
        raise RuntimeError("Missing native GDI/User/Kernel imports")
    if any(sha(REPO / name) != value for name, value in inputs.items()):
        raise RuntimeError("Probe source changed while building")
    receipt = {"schema": 1, "status": "HOST-BUILD-PASS", "artifact": artifact.name, "sha256": sha(artifact), "bytes": artifact.stat().st_size,
               "machine": "i386", "cpu": "i486 without SSE/MMX; no CRT", "subsystem": "GUI 4.10", "imports": imports, "source_sha256": inputs,
               "command": cmd, "build_log_sha256": sha(log), "output_guest_file": "C:\\VXDLAB\\SHZPRB.LOG", "output_creation": "CREATE_NEW; stale file causes exit 20",
               "bounded_effects": "two 160x96 DIBs, transient display window for approximately 5 seconds, at most 4096 report bytes",
               "scope": "primary adapter enumeration + native GDI fill/copy/display readback; no physical framebuffer or backend-load proof",
               "native_win98_execution": "pending",
               "primary_api_reference": "https://ftp.zx.net.nz/pub/mirror/ftp.microsoft.com/MISC/KB/en-us/197/671.HTM"}
    shzlib.write_json(out / "build-result.json", receipt)
    print(json.dumps({"status": receipt["status"], "artifact": str(artifact), "sha256": receipt["sha256"], "bytes": receipt["bytes"]}, indent=2))


if __name__ == "__main__":
    main()
