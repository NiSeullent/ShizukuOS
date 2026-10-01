#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fresh bounded opt-in transport build. No VM/network/client installation.

Only the host fixture binds a temporary 127.0.0.1 listener. Frozen native
backend/interop checkpoints are inputs and never rebuilt or changed here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import pefile

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SHA = "8691fa74eeb9dbf02d53f7dc45a5c15c8f9d3c9960f222112621ef6351d621b9"
CLIENT_RECEIPT_SHA = "73ac0880829c4d924873aa219fc13dec8de102f8dd759c858f69508f46adaf31"
EXPORTS = sorted("m98_net_open m98_net_write m98_net_read m98_net_shutdown m98_net_close m98_net_info".split())
TLS_EXPORTS = sorted("m98_tls_create m98_tls_handshake m98_tls_write m98_tls_read m98_tls_shutdown m98_tls_backend_error m98_tls_verify_flags m98_tls_is_established m98_tls_free".split())
DYNAMIC = {
    "WSOCK32.DLL": "WSAStartup WSACleanup socket ioctlsocket connect select getsockopt send recv closesocket shutdown WSAGetLastError".split(),
    "ADVAPI32.DLL": "CryptAcquireContextA CryptGenRandom CryptReleaseContext".split(),
}
SOURCES = ["src/m98_tls13_native.h", "src/m98_tls13_native.c", "src/m98_tls13_native_win32.c",
           "src/m98_tls13_native.def", "src/m98_tls13_native_HANDOFF.md", "src/m98_tls13.h",
           "tests/m98_tls13_native_controller.c", "tests/m98_tls13_native_win32_mock.c",
           "tests/m98_tls13_native_win32_mock.h", "tests/m98_tls13_native_posix.c",
           "tests/m98_tls13_native_integration.py", "tests/m98_tls13_native_guest.c",
           "tools/build_tls13_native.py", "platform/freestanding/memory.c", "platform/freestanding/memory.h",
           "benchmarks/win98se-ko-oem-native-exports-v1.json"]
LIBS = ["build/tls13/host/libm98tls13.a", "build/tls13/host/upstream/library/libmbedtls.a",
        "build/tls13/host/upstream/library/libmbedx509.a", "build/tls13/host/upstream/library/libtfpsacrypto.a"]
INPUTS = ["build/tls13/pe32/M98TLS13.dll", "build/tls13/pe32/build-result.json",
          "build/tls13/host/build-result.json"] + LIBS


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), f"regular input required: {path}")
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def pins(names):
    return {name: digest(ROOT / name) for name in names}


def pe_gate(path, dll, exports, oem, backend=False):
    with pefile.PE(str(path)) as pe:
        h = pe.OPTIONAL_HEADER
        require(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and pe.is_dll() == dll, "PE32/type")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and h.AddressOfEntryPoint != 0, "timestamp/entry")
        require((h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion) == (4, 10), "OS version")
        require(h.Subsystem == 2 and (h.MajorSubsystemVersion, h.MinorSubsystemVersion) == (4, 10), "GUI version")
        require(not h.DllCharacteristics & (0x40 | 0x100 | 0x8000), "unsupported modern flags")
        if not backend:
            require(h.SizeOfStackReserve == 2097152 and h.SizeOfStackCommit == 65536, "stack bounds")
        require(h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics & 1, "relocations")
        require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)), "TLS/load-config/delay/CLR")
        imports = {}
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            name = module.dll.decode("ascii").upper()
            require(name in ({"KERNEL32.DLL", "MSVCRT.DLL"} if backend else {"KERNEL32.DLL"}), f"import module {name}")
            names = []
            for row in module.imports:
                require(row.name is not None, "ordinal import")
                names.append(row.name.decode("ascii"))
            require(set(names) <= set(oem[name]), f"non-OEM imports {name}: {set(names)-set(oem[name])}")
            require(name not in imports, "duplicate import module")
            imports[name] = sorted(names)
        actual = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for row in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                require(row.name is not None and not row.forwarder, "ordinal-only or forwarded export")
                actual.append(row.name.decode("ascii"))
        require(sorted(actual) == exports, "exact export names")
        require(imports, "imports missing")
        return {"sha256": digest(path), "size": path.stat().st_size, "pe98_gate": "pass",
                "imports": imports, "exports": sorted(actual),
                "stack_reserve": h.SizeOfStackReserve, "stack_commit": h.SizeOfStackCommit}


def main():
    require(__debug__, "optimized Python disables required validation; refused before output writes")
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9_-]{12,96}", args.nonce), "bounded ASCII nonce required")
    out = args.output if args.output.is_absolute() else ROOT / args.output
    out = out.absolute()
    require(out.parent.resolve().is_relative_to((ROOT / "build").resolve()), "output must be a fresh build subdirectory")
    require(not out.exists() and not out.is_symlink(), "output already exists; preserve earlier checkpoint")
    source = pins(SOURCES)
    inputs = pins(INPUTS)
    require(inputs[INPUTS[0]] == CLIENT_SHA and inputs[INPUTS[1]] == CLIENT_RECEIPT_SHA, "frozen latest backend identity")
    receipt = json.loads((ROOT / INPUTS[1]).read_text())
    host_receipt = json.loads((ROOT / INPUTS[2]).read_text())
    for r in (receipt, host_receipt):
        require(r["dependency"]["version"] == "4.2.0" and r["dependency"]["tf_psa_crypto_version"] == "1.2.0", "latest backend versions")
        for item in r["source_files"]:
            require(digest(Path(item["path"])) == item["sha256"], "backend source drift")
        for item in r["artifacts"]:
            require(digest(Path(item["path"])) == item["sha256"], "backend artifact drift")
    oem = json.loads((ROOT / SOURCES[-1]).read_text())["dlls"]
    for module, names in DYNAMIC.items():
        require(set(names) <= set(oem[module]), f"dynamic non-OEM exports {module}")
    backend_gate = pe_gate(ROOT / INPUTS[0], True, TLS_EXPORTS, oem, backend=True)
    out.mkdir(parents=True, exist_ok=False)
    steps = []

    def run(command, name, env=None, timeout=60):
        p = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
        log = out / (name + ".log")
        log.write_text(p.stdout + p.stderr)
        steps.append({"argv": command, "returncode": p.returncode, "log": str(log), "sha256": digest(log)})
        require(p.returncode == 0, f"{name} failed: {p.stderr[-4000:]}")
        return p.stdout.strip()

    common = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Isrc"]
    models = {}
    for name, unit in (("controller", "tests/m98_tls13_native_controller.c"),
                       ("win32-platform", "tests/m98_tls13_native_win32_mock.c")):
        binary = out / name
        run(common + [unit, "-o", str(binary)], name + "-build")
        normal = run([str(binary)], name + "-normal")
        require(normal.startswith("PASS:"), "model verdict")
        sanitized = out / (name + "-sanitize")
        run(common + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", unit, "-o", str(sanitized)], name + "-sanitize-build")
        clean = run([str(sanitized)], name + "-sanitize", dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
        require(clean == normal, "normal/sanitized model verdict mismatch")
        models[name] = {"normal": normal, "asan_ubsan": clean, "native_api_execution": False}
    host = out / "posix-client"
    run(common + ["src/m98_tls13_native.c", "tests/m98_tls13_native_posix.c", "-Wl,--start-group"] + LIBS + ["-Wl,--end-group", "-o", str(host)], "posix-build")
    host_out = out / "host-integration"
    run([sys.executable, "-B", "tests/m98_tls13_native_integration.py", "--output", str(host_out), "--client", str(host)], "host-integration", timeout=60)
    host_result = json.loads((host_out / "result.json").read_text())
    require(host_result["passed"] is True and host_result["host_only"] is True and len(host_result["tests"]) == 8, "host-only integration verdict")
    require(host_result["client_sha256"] == digest(host) and host_result["native_guest_network_verified"] is False, "host/native claim boundary")
    native = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-Isrc",
              "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float", "-fno-builtin",
              "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib", "-Wl,--subsystem,windows:4.10",
              "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10", "-Wl,--disable-dynamicbase",
              "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
              "-Xlinker", "--stack", "-Xlinker", "2097152,65536"]
    dll = out / "M98NET.DLL"
    probe = out / "NET13PR.EXE"
    run(native + ["-shared", "-Wl,--entry,_DllMain@12", "src/m98_tls13_native.c", "src/m98_tls13_native_win32.c",
                  "src/m98_tls13_native.def", "platform/freestanding/memory.c", "-lkernel32", "-lgcc", "-o", str(dll)], "native-dll")
    dll_gate = pe_gate(dll, True, EXPORTS, oem)
    run(native + ['-DM98_NET_PROBE_NONCE="' + args.nonce + '"', '-DM98_NET_SHA256="' + digest(dll) + '"',
                  '-DM98_CLIENT_SHA256="' + CLIENT_SHA + '"', "-Wl,--entry,_mainCRTStartup", "tests/m98_tls13_native_guest.c",
                  "platform/freestanding/memory.c", "-lkernel32", "-lgcc", "-o", str(probe)], "native-probe")
    probe_gate = pe_gate(probe, False, [], oem)
    copied = out / "M98TLS13.DLL"
    shutil.copyfile(ROOT / INPUTS[0], copied)
    require(digest(copied) == CLIENT_SHA, "copied backend drift")
    # Preserve the exact reviewed new source profile beside the receipts.
    for name in SOURCES:
        target = out / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        require(digest(target) == source[name], "frozen source copy mismatch")
    require(source == pins(SOURCES) and inputs == pins(INPUTS), "source/input drift during build")
    result = {"passed": True, "profile": "explicit-native-tls-transport-v1", "nonce": args.nonce,
              "source_sha256": source, "input_sha256": inputs, "models": models,
              "host_integration": {"path": str(host_out / "result.json"), "sha256": digest(host_out / "result.json"), "cases": 8, "host_only": True},
              "artifacts": {dll.name: dll_gate, probe.name: probe_gate, copied.name: backend_gate},
              "dynamic_original_oem_exports": DYNAMIC, "steps": steps,
              "native_guest_network_verified": False, "os_tls_integrated": False,
              "applications_verified": False, "user_objective_complete": False,
              "installation": "not_performed", "guest_network": "not_enabled", "guest_endpoint_ca": "not_supplied"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": True, "model_tests": models, "real_host_tls_cases": 8,
                      "native_pe_gates": 2, "native_guest_network_verified": False, "receipt": str(out / "result.json")}))


if __name__ == "__main__":
    main()
