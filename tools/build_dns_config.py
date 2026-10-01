#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded configuration-only build; never install or start a guest."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/dns-config-v2"
SOURCES = ["src/m98_dns_config.h", "src/m98_dns_config.c", "src/m98_dns_win32.c",
           "src/m98_dns_win32.def", "src/m98_dns_config_HANDOFF.md",
           "tests/m98_dns_config_host.c", "tests/m98_dns_config_guest.c",
           "tools/build_dns_config.py", "platform/freestanding/memory.c",
           "platform/freestanding/memory.h", "benchmarks/win98se-ko-oem-native-exports-v1.json"]

def run(command, env=None):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def gate(path, dll):
    exports = json.loads((ROOT / SOURCES[-1]).read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        h = pe.OPTIONAL_HEADER
        assert pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b
        assert pe.FILE_HEADER.TimeDateStamp == 0 and pe.is_dll() == dll
        assert (h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion) == (4, 10)
        assert h.Subsystem == 2 and (h.MajorSubsystemVersion, h.MinorSubsystemVersion) == (4, 10)
        assert h.AddressOfEntryPoint and not h.DllCharacteristics & (0x40 | 0x100 | 0x8000)
        assert h.SizeOfStackReserve == 2097152 and h.SizeOfStackCommit == 65536
        assert h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics & 1
        assert all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14))
        imports = {}
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            name = module.dll.decode().upper()
            assert name == "KERNEL32.DLL", name
            names = [row.name.decode() if row.name else f"#{row.ordinal}" for row in module.imports]
            assert set(names) <= set(exports[name]), set(names) - set(exports[name])
            imports[name] = sorted(names)
        names = sorted(x.name.decode() for x in pe.DIRECTORY_ENTRY_EXPORT.symbols) if dll else []
        assert names == (["DnsQueryConfig"] if dll else [])
        return {"pe98_gate": "pass", "sha256": digest(path), "size": path.stat().st_size,
                "imports": imports, "exports": names}

def main():
    if not __debug__:
        raise RuntimeError("Python optimized execution disables required validation; build refused")
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / "result.json"
    receipt.unlink(missing_ok=True)
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    common = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Isrc"]
    host = BUILD / "dns-host"
    host_san = BUILD / "dns-host-sanitize"
    core = ["src/m98_dns_config.c", "tests/m98_dns_config_host.c"]
    run(["clang"] + common + core + ["-o", str(host)])
    normal = run([str(host)])
    run(["clang"] + common + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] + core + ["-o", str(host_san)])
    sanitized = run([str(host_san)], dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
    native = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-Isrc",
              "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
              "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
              "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
              "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
              "-Xlinker", "--stack", "-Xlinker", "2097152,65536"]
    dll = BUILD / "M98DNS.DLL"
    guest = BUILD / "M98DNSPR.EXE"
    run(native + ["-shared", "-Wl,--entry,_DllMain@12", "src/m98_dns_config.c", "src/m98_dns_win32.c",
                  "src/m98_dns_win32.def", "platform/freestanding/memory.c", "-lkernel32", "-o", str(dll)])
    run(native + ["-Wl,--entry,_mainCRTStartup", "src/m98_dns_config.c", "tests/m98_dns_config_guest.c",
                  "platform/freestanding/memory.c", "-lkernel32", "-o", str(guest)])
    artifacts = {p.name: gate(p, is_dll) for p, is_dll in ((dll, True), (guest, False))}
    assert hashes == {name: digest(ROOT / name) for name in SOURCES}, "source drift during build"
    result = {"passed": True, "host": normal, "sanitizer": sanitized, "source_sha256": hashes,
              "artifacts": artifacts, "native_win98": "not_tested", "dns_transactions": "not_implemented",
              "global_installation": "not_performed", "modern_app_operation": "not_tested"}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(normal)
    print(sanitized)
    print("PASS: two GUI PE32/4.10 original OEM import gates; native execution pending")
    print(receipt)

if __name__ == "__main__":
    main()
