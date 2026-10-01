#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a native latest-client/LTS-server probe; never launch/install a guest.

The optional server handoff is an explicit DLL, frozen build receipt and fixture
directory. There is no dependency on a peer checkout or its build scripts.
Each successful invocation creates a fresh output directory and binds every
input. Static success is never a native execution/protocol acceptance claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pefile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_LIMIT = 1 << 20
SERVER_ABI_SHA256 = "7f3f364ab97fd58d94c03f80432a94b99c0ad28b71b48bc4d0ee4920e3191cda"
BASELINE = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
CLIENT_EXPORTS = {"m98_tls_create", "m98_tls_handshake", "m98_tls_write", "m98_tls_read",
                  "m98_tls_shutdown", "m98_tls_backend_error", "m98_tls_verify_flags",
                  "m98_tls_is_established", "m98_tls_free"}
SERVER_EXPORTS = {"ntwst_runtime_init", "ntwst_runtime_fini", "ntwst_native_runtime_init",
                  "ntwst_native_runtime_fini", "ntwst_create", "ntwst_destroy",
                  "ntwst_handshake", "ntwst_write", "ntwst_read", "ntwst_close_notify",
                  "ntwst_version", "ntwst_verify_flags", "ntwst_engine_error"}
OWN_SOURCES = ["tests/m98_tls13_guest_interop.c", "tools/build_tls13_guest_interop.py",
               "tests/m98_tls13_interop_controller.c",
               "tests/m98_tls13_guest_runner.c", "tests/m98_tls13_guest_runner_mock.c",
               "tests/m98_tls13_guest_runner_mock.h",
               "src/m98_tls13.h", "benchmarks/win98se-ko-oem-native-exports-v1.json"]
FIXTURES = {"CA.PEM": "ca.pem", "SRV.PEM": "server.pem", "SRV.KEY": "server.key",
            "BADCA.PEM": "other-ca.pem"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_frozen(path):
    path = path.resolve(strict=True)
    if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError(f"not a bounded regular input: {path}")
    data = path.read_bytes()
    return path, data, hashlib.sha256(data).hexdigest()


def pe_gate(path, exports=None):
    native = json.loads(BASELINE.read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine != 0x14C or opt.Magic != 0x10B or
            pe.is_dll() != (exports is not None) or not opt.AddressOfEntryPoint or
            opt.Subsystem != 2 or
            (opt.MajorOperatingSystemVersion, opt.MinorOperatingSystemVersion) != (4, 10) or
            (opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (4, 10)):
            raise ValueError(f"not native PE32 Windows GUI/OS 4.10: {path}")
        if not opt.DATA_DIRECTORY[5].VirtualAddress or pe.FILE_HEADER.Characteristics & 1:
            raise ValueError(f"missing relocations: {path}")
        # Preserve the publisher-bound peer library, including its ASLR/NX
        # metadata. Loading it is an actual guest gate, never a static claim.
        # Our generated executable deliberately advertises neither feature.
        if exports is None and opt.DllCharacteristics & (0x40 | 0x100 | 0x8000):
            raise ValueError(f"unexpected modern probe flags: {path}")
        if exports is None and (opt.SizeOfStackReserve < 2 * 1024 * 1024 or
                                opt.SizeOfStackCommit < 65536):
            raise ValueError("unprobed controller frames require a committed 64 KiB stack")
        if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)):
            raise ValueError(f"unexpected static TLS/load config/delay/CLR: {path}")
        symbols = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        found = {s.name.decode("ascii") for s in symbols if s.name}
        if found != (exports or set()) or len(symbols) != len(found) or any(s.forwarder for s in symbols):
            raise ValueError(f"unexpected export ABI: {path}: {sorted(found)}")
        imports = {}
        allowed_modules = {"KERNEL32.DLL"} if exports is None else {
            "KERNEL32.DLL", "MSVCRT.DLL", "ADVAPI32.DLL"}
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            module = descriptor.dll.decode("ascii").upper()
            symbols = [s.name.decode("ascii") if s.name else f"#{s.ordinal}"
                       for s in descriptor.imports]
            if module not in allowed_modules or not set(symbols) <= set(native.get(module, [])):
                raise ValueError(f"not original Win98 imports: {module}: {symbols}")
            imports[module] = sorted(symbols)
        return {"pe32_oem_gate": "PASS", "imports": imports, "exports": sorted(found),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "dll_characteristics": opt.DllCharacteristics, "sha256": digest(path),
                "stack_reserve": opt.SizeOfStackReserve, "stack_commit": opt.SizeOfStackCommit,
                "bytes": path.stat().st_size}


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=ROOT / "build/tls13-guest-interop")
    p.add_argument("--nonce", required=True)
    p.add_argument("--client-dll", type=Path, default=ROOT / "build/tls13/pe32/M98TLS13.dll")
    p.add_argument("--client-receipt", type=Path, default=ROOT / "build/tls13/pe32/build-result.json")
    p.add_argument("--server-dll", type=Path)
    p.add_argument("--server-receipt", type=Path)
    p.add_argument("--server-receipt-sha256")
    p.add_argument("--fixtures-dir", type=Path,
                   help="Explicit DOS8.3 fixture directory bound by the server receipt")
    args = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,96}", args.nonce):
        p.error("nonce must contain 8..96 ASCII letters, digits, '_' or '-'")
    supplied = [args.server_dll, args.server_receipt, args.server_receipt_sha256, args.fixtures_dir]
    if any(x is not None for x in supplied) and not all(x is not None for x in supplied):
        p.error("server staging requires --server-dll/--server-receipt/--server-receipt-sha256/--fixtures-dir")
    if args.server_receipt_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.server_receipt_sha256):
        p.error("server receipt digest must be lowercase SHA256")
    return args


def main():
    args = arguments()
    output = args.output.resolve()
    if output.exists():
        raise ValueError("output must be a fresh directory; prior evidence is preserved")
    frozen = {}
    client_path, client_bytes, client_hash = read_frozen(args.client_dll)
    frozen[client_path] = client_hash
    client_receipt_path, client_receipt_bytes, client_receipt_hash = read_frozen(args.client_receipt)
    frozen[client_receipt_path] = client_receipt_hash
    client_receipt = json.loads(client_receipt_bytes)
    if (client_receipt.get("profile") != "pe32" or
        client_receipt.get("dependency", {}).get("version") != "4.2.0" or
        client_receipt.get("dependency", {}).get("tf_psa_crypto_version") != "1.2.0" or not any(
        x.get("sha256") == client_hash and Path(x.get("path", "")).name == "M98TLS13.dll"
        for x in client_receipt.get("artifacts", []))):
        raise ValueError("client DLL is not bound by its PE32 build receipt")
    client_gate = pe_gate(client_path, CLIENT_EXPORTS)
    server_hash = "UNSTAGED"
    server_bytes = None
    fixture_bytes = {}
    server_gate = None
    if args.server_dll:
        server_path, server_bytes, server_hash = read_frozen(args.server_dll)
        frozen[server_path] = server_hash
        server_receipt_path, server_receipt_bytes, server_receipt_hash = read_frozen(args.server_receipt)
        frozen[server_receipt_path] = server_receipt_hash
        if server_receipt_hash != args.server_receipt_sha256:
            raise ValueError("server build receipt changed")
        server_receipt = json.loads(server_receipt_bytes)
        library = server_receipt.get("native_library", {})
        if (server_receipt.get("status") != "PASS" or
            server_receipt.get("target") != "win98-x86" or
            server_receipt.get("upstream", {}).get("version") != "3.6.7" or
            server_receipt.get("source_sha256", {}).get("transport.h") != SERVER_ABI_SHA256 or
            library.get("sha256") != server_hash or library.get("bytes") != len(server_bytes)):
            raise ValueError("server DLL does not match frozen native LTS build")
        server_gate = pe_gate(server_path, SERVER_EXPORTS)
        for dos, original in FIXTURES.items():
            fixture, data, sha = read_frozen(args.fixtures_dir / dos)
            if sha != server_receipt.get("fixtures", {}).get(original):
                raise ValueError(f"fixture does not match frozen server receipt: {dos}")
            frozen[fixture] = sha
            fixture_bytes[dos] = data
    source_hashes = {name: digest(ROOT / name) for name in OWN_SOURCES}
    output.mkdir(parents=True)
    executable = output / "TLSDLL.EXE"
    command = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
               "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
               "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
               "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
               "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
               "-Xlinker", "--stack", "-Xlinker", "2097152,65536",
               "-Wl,--no-insert-timestamp", "-Wl,--entry,_mainCRTStartup",
               f'-DM98_INTEROP_NONCE="{args.nonce}"', f'-DM98_CLIENT_SHA256="{client_hash}"',
               f'-DM98_SERVER_SHA256="{server_hash}"', f"-I{ROOT / 'src'}",
               str(ROOT / "tests/m98_tls13_guest_interop.c"), "-lkernel32", "-lgcc", "-o", str(executable)]
    result = subprocess.run(command, text=True, capture_output=True, timeout=90, cwd=ROOT)
    (output / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"native probe build failed: {result.stderr}")
    controller = output / "host-controller-sanitize"
    controller_command = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                          "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                          f"-I{ROOT / 'src'}", str(ROOT / "tests/m98_tls13_interop_controller.c"),
                          "-o", str(controller)]
    compiled = subprocess.run(controller_command, text=True, capture_output=True, timeout=60, cwd=ROOT)
    if compiled.returncode:
        raise RuntimeError(f"host controller build failed: {compiled.stderr}")
    controller_result = subprocess.run([str(controller)], text=True, capture_output=True,
        env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"),
        timeout=30, cwd=ROOT)
    (output / "host-controller.log").write_text(controller_result.stdout + controller_result.stderr)
    if (controller_result.returncode or
        controller_result.stdout.strip() != "HOST CONTROLLER PASS: 15 assertions; no TLS/native Windows claim"):
        raise RuntimeError(f"host controller failed: {controller_result.stdout}{controller_result.stderr}")
    probe_gate = pe_gate(executable)
    if probe_gate["timestamp"]:
        raise ValueError("probe build timestamp is not deterministic")
    runner = output / "T13RUN.EXE"
    runner_command = [value for value in command if not value.startswith(
        ("-DM98_INTEROP_NONCE=", "-DM98_CLIENT_SHA256=", "-DM98_SERVER_SHA256="))]
    runner_command[runner_command.index(str(ROOT / "tests/m98_tls13_guest_interop.c"))] = str(
        ROOT / "tests/m98_tls13_guest_runner.c")
    runner_command[runner_command.index(str(executable))] = str(runner)
    runner_command.append(f'-DM98_RUN_NONCE="{args.nonce}"')
    built_runner = subprocess.run(runner_command, text=True, capture_output=True, timeout=60, cwd=ROOT)
    (output / "runner-build.log").write_text(built_runner.stdout + built_runner.stderr)
    if built_runner.returncode:
        raise RuntimeError(f"native single-child supervisor build failed: {built_runner.stderr}")
    runner_gate = pe_gate(runner)
    if runner_gate["timestamp"]:
        raise ValueError("runner build timestamp is not deterministic")
    runner_host = output / "host-runner-sanitize"
    runner_host_command = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(ROOT / "tests/m98_tls13_guest_runner_mock.c"), "-o", str(runner_host)]
    built_runner_host = subprocess.run(runner_host_command, text=True, capture_output=True,
                                      timeout=60, cwd=ROOT)
    if built_runner_host.returncode:
        raise RuntimeError(f"single-child supervisor host build failed: {built_runner_host.stderr}")
    runner_host_result = subprocess.run([str(runner_host)], text=True, capture_output=True, timeout=30,
        env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"), cwd=ROOT)
    (output / "host-runner.log").write_text(runner_host_result.stdout + runner_host_result.stderr)
    if runner_host_result.returncode or not re.fullmatch(
        r"PASS: [0-9]+ supervisor API/lifecycle assertions across 18 injected scenarios\n",
        runner_host_result.stdout):
        raise RuntimeError(f"single-child supervisor host tests failed: {runner_host_result.stdout}{runner_host_result.stderr}")
    (output / "client-build.json").write_bytes(client_receipt_bytes)
    staged = {"TLSDLL.EXE": probe_gate}
    if server_bytes is not None:
        (output / "M98TLS13.DLL").write_bytes(client_bytes)
        (output / "M98TLS.DLL").write_bytes(server_bytes)
        (output / "server-build.json").write_bytes(server_receipt_bytes)
        for name, data in fixture_bytes.items():
            (output / name).write_bytes(data)
        for name in ["M98TLS13.DLL", "M98TLS.DLL", *FIXTURES, "T13RUN.EXE"]:
            file = output / name
            staged[name] = {"sha256": digest(file), "bytes": file.stat().st_size}
            if file.stat().st_size > FIXTURE_LIMIT:
                raise ValueError(f"guest input exceeds harness bound: {name}")
    for file, sha in frozen.items():
        if digest(file) != sha:
            raise ValueError(f"input changed while building: {file}")
    if any(digest(ROOT / name) != sha for name, sha in source_hashes.items()):
        raise ValueError("source changed while building")
    receipt = {"schema": "win98modern.latest-tls-dll-interop.v1", "status": "PASS",
               "scope": "Build/static/staging only; no native execution claim",
               "nonce": args.nonce, "command": command, "source_sha256": source_hashes,
               "frozen_inputs": {str(p): sha for p, sha in frozen.items()},
               "client_gate": client_gate, "server_gate": server_gate, "probe_gate": probe_gate,
               "runner_gate": runner_gate, "runner_command": runner_command,
               "artifacts": staged, "client_receipt_sha256": client_receipt_hash,
               "server_receipt_sha256": args.server_receipt_sha256,
               "build_log_sha256": digest(output / "build.log"),
               "host_controller": {"passed": True, "assertions": 15,
                   "scope": "Controller API doubles only; not TLS cryptography or native Windows",
                   "command": controller_command, "artifact_sha256": digest(controller),
                   "log_sha256": digest(output / "host-controller.log"),
                   "result": controller_result.stdout.strip()},
               "host_runner": {"passed": True, "scenarios": 18,
                   "scope": "Supervisor API doubles only; no Windows process execution claim",
                   "command": runner_host_command, "artifact_sha256": digest(runner_host),
                   "log_sha256": digest(output / "host-runner.log"),
                   "result": runner_host_result.stdout.strip()},
               "child_timeout_ms": 120000, "reap_timeout_ms": 5000,
               "child_exit_evidence": "Supervisor observes actual full DWORD child exit after WaitForSingleObject",
               "supervisor_exit_limit": "requested-exit-code precedes final close; actual supervisor exit requires an outer observer",
               "native_guest_verified": False, "system_tls_verified": False,
               "application_functionality_verified": False,
               "required_guest_checks": ["WIN98_IDENTIFIED", "LOAD_BOTH_DLLS_AND_9_13_EXPORTS",
                   "TLS13_HANDSHAKE_BOTH_DLLS", "AUTHENTICATED_BIDIRECTIONAL_PAYLOAD",
                   "AUTHENTICATED_CLOSE_NOTIFY", "WRONG_HOST_REJECTED_WITHOUT_PLAINTEXT",
                   "UNTRUSTED_CA_REJECTED_WITHOUT_PLAINTEXT", "ENTROPY_ZERO_REJECTED",
                   "ENTROPY_MINUS1_REJECTED", "ENTROPY_TWO_REJECTED", "LATE_ENTROPY_FAILURE_DENIED",
                   "LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT", "SERVER_RUNTIME_SHUTDOWN",
                   "SERVER_DLL_UNLOADED", "CLIENT_DLL_UNLOADED"]}
    receipt_path = output / "build-result.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    if server_bytes is not None:
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                    "inputs": [{"source": str(output / name), "guest": "C:\\GOPLAB\\" + name,
                                "bytes": info["bytes"], "sha256": info["sha256"]}
                               for name, info in staged.items()],
                    "outputs": ["C:\\GOPLAB\\TLSDLL.LOG", "C:\\GOPLAB\\T13RUN.LOG", "C:\\GOPLAB\\TLSOUT.LOG"], "backups": [],
                    "source_receipts": [{"path": str(receipt_path), "sha256": digest(receipt_path)}],
                    "nonce": args.nonce, "command": "C:\\GOPLAB\\T13RUN.EXE",
                    "guest_execution": "NOT-VERIFIED", "network_required": False,
                    "scope": "Native latest-client/LTS-server DLL interop only; no sockets/OS/app acceptance",
                    "exit_evidence": "T13RUN.LOG records actual owned child exit; supervisor requested-exit remains distinct from its actual exit"}
        (output / "guest-files.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "receipt": str(receipt_path),
                      "receipt_sha256": digest(receipt_path), "guest_verified": False}))


if __name__ == "__main__":
    main()
