#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze and build TLS1.3 engine/probe from the verified upstream archive.

No download, guest, service, installation, or client configuration changes.
Output must be a new directory. Private certificate keys are test inputs only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VERSION = "3.6.7"
ARCHIVE_SHA256 = "a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
ARCHIVE_BYTES = 5473689
SOURCES = ("transport.h", "transport.c", "probe.c", "user_config.h", "native_time.c",
           "native_time_probe.c", "native_runtime.h", "native_runtime.c", "native_crt.c",
           "native.def", "build.py")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixtures(output):
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    def instant(year):
        return datetime(year, 1, 1, tzinfo=timezone.utc)

    def name(label):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])

    def ca(label):
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (x509.CertificateBuilder().subject_name(name(label)).issuer_name(name(label))
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(instant(2010)).not_valid_after(instant(2040))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                       .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                       .sign(key, hashes.SHA256()))
        return key, certificate

    output.mkdir()
    ca_key, ca_certificate = ca("Win98 TLS13 private test CA")
    _, other_ca = ca("Untrusted private test CA")
    files = {}
    for filename, certificate in (("ca.pem", ca_certificate), ("other-ca.pem", other_ca)):
        (output / filename).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        files[filename] = sha(output / filename)
    for prefix, start, end in (("server", 2020, 2035), ("expired", 2011, 2012)):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(name("tls13.win98.test"))
                .issuer_name(ca_certificate.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(instant(start)).not_valid_after(instant(end))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls13.win98.test")]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .sign(ca_key, hashes.SHA256()))
        for filename, data in ((prefix + ".pem", cert.public_bytes(serialization.Encoding.PEM)),
                               (prefix + ".key", key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
            path = output / filename
            path.write_bytes(data)
            path.chmod(0o600)
            files[filename] = sha(path)
    return files


def audit_pe(path):
    import pefile
    baseline_path = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    baseline = json.loads(baseline_path.read_text())["dlls"]
    pe = pefile.PE(str(path), fast_load=False)
    imports, absent = {}, []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("ascii").upper()
        names = [row.name.decode("ascii") if row.name else "#" + str(row.ordinal) for row in entry.imports]
        imports[dll] = names
        for symbol in names:
            if symbol not in baseline.get(dll, []):
                absent.append({"dll": dll, "symbol": symbol})
    unexpected = [index for index in (9, 10, 13, 14)
                  if pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress or
                  pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size]
    version = [pe.OPTIONAL_HEADER.MajorSubsystemVersion, pe.OPTIONAL_HEADER.MinorSubsystemVersion]
    passed = (pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.Magic == 0x10b
              and version <= [4, 10] and not absent and not unexpected and bool(imports))
    return {"machine": pe.FILE_HEADER.Machine, "format_magic": pe.OPTIONAL_HEADER.Magic,
            "subsystem_version": version, "imports": imports,
            "absent_from_oem_exports": absent, "unexpected_directories": unexpected,
            "baseline_sha256": sha(baseline_path), "static_gate_passed": passed,
            "native_guest_verified": False}


def build(archive, output, target, jobs, run_probe):
    archive, output = archive.resolve(), output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Preserve earlier builds; output must be a new directory")
    if archive.stat().st_size != ARCHIVE_BYTES or sha(archive) != ARCHIVE_SHA256:
        raise ValueError("Upstream archive differs from the pinned publisher asset")
    sources = {name: (HERE / name).read_bytes() for name in SOURCES}
    output.mkdir(parents=True, mode=0o700)
    upstream = output / "upstream"
    upstream.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(upstream, filter="data")
    source = upstream / ("mbedtls-" + VERSION)
    project = output / "project"
    project.mkdir()
    for name, data in sources.items():
        (project / name).write_bytes(data)
    (project / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.16)
project(Win98SecureTransport C)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
add_compile_definitions(MBEDTLS_USER_CONFIG_FILE="user_config.h")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
add_subdirectory("${UPSTREAM_SOURCE}" upstream)
add_library(ntwst STATIC transport.c native_time.c)
target_link_libraries(ntwst PUBLIC mbedtls mbedx509 mbedcrypto)
add_executable(TLS13PROB probe.c native_time.c)
target_link_libraries(TLS13PROB PRIVATE ntwst)
if(WIN32)
  target_sources(TLS13PROB PRIVATE native_crt.c)
  target_link_options(TLS13PROB PRIVATE -Wl,--entry,_mainCRTStartup)
  target_link_libraries(TLS13PROB PRIVATE advapi32)
  add_executable(TIMEPROB native_time_probe.c native_crt.c)
  target_link_options(TIMEPROB PRIVATE -Wl,--entry,_mainCRTStartup)
  target_include_directories(TIMEPROB PRIVATE "${UPSTREAM_SOURCE}/include")
  add_library(M98TLS SHARED transport.c native_time.c native_runtime.c native_crt.c native.def)
  target_compile_definitions(M98TLS PRIVATE NTWST_DLL_STARTUP=1)
  target_link_options(M98TLS PRIVATE -Wl,--entry,_DllMainCRTStartup@12)
  target_link_libraries(M98TLS PRIVATE mbedtls mbedx509 mbedcrypto advapi32)
  set_target_properties(M98TLS PROPERTIES PREFIX "" OUTPUT_NAME "M98TLS")
endif()
''')
    toolchain = project / "toolchain.cmake"
    if target == "win98-x86":
        toolchain.write_text('''set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
set(CMAKE_RC_COMPILER i686-w64-mingw32-windres)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_C_FLAGS_INIT "-Os -march=i486 -ffunction-sections -fdata-sections -DWINVER=0x0410 -D_WIN32_WINDOWS=0x0410 -D_WIN32_WINNT=0x0400")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-nostartfiles -static -static-libgcc -Wl,--gc-sections,--no-insert-timestamp,--subsystem,console:4.10,--major-os-version,4,--minor-os-version,10")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-nostartfiles -static -static-libgcc -Wl,--gc-sections,--no-insert-timestamp,--subsystem,windows:4.10,--major-os-version,4,--minor-os-version,10")
''')
    else:
        toolchain.write_text('set(CMAKE_C_FLAGS_INIT "-O2 -ffunction-sections -fdata-sections")\n')
    commands = []

    def run(argv, timeout=600):
        commands.append([str(x) for x in argv])
        with (output / "build.log").open("a") as log:
            result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Build failed; inspect " + str(output / "build.log"))

    receipt = {"schema": "win98modern.secure-transport-build.v1", "target": target,
               "upstream": {"version": VERSION, "archive_sha256": ARCHIVE_SHA256,
                 "url": "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2",
                 "license": "Apache-2.0 OR GPL-2.0-or-later"},
               "source_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()},
               "commands": commands, "host_probe_passed": False, "native_guest_verified": False,
               "system_schannel_verified": False, "application_functionality_verified": False}
    try:
        binary_dir = output / "cmake"
        run(["cmake", "-S", str(project), "-B", str(binary_dir), "-G", "Ninja",
             "-DCMAKE_TOOLCHAIN_FILE=" + str(toolchain), "-DUPSTREAM_SOURCE=" + str(source)])
        run(["cmake", "--build", str(binary_dir), "--parallel", str(jobs)])
        binary = binary_dir / ("TLS13PROB.exe" if target == "win98-x86" else "TLS13PROB")
        receipt["binary"] = {"path": str(binary.resolve()), "sha256": sha(binary), "bytes": binary.stat().st_size}
        receipt["fixtures"] = fixtures(output / "fixtures")
        if target == "win98-x86":
            receipt["pe_audit"] = audit_pe(binary)
            clock_binary = binary_dir / "TIMEPROB.exe"
            receipt["clock_probe"] = {"path": str(clock_binary.resolve()),
              "sha256": sha(clock_binary), "bytes": clock_binary.stat().st_size,
              "pe_audit": audit_pe(clock_binary)}
            dll = binary_dir / "M98TLS.dll"
            receipt["native_library"] = {"path": str(dll.resolve()), "sha256": sha(dll),
              "bytes": dll.stat().st_size, "pe_audit": audit_pe(dll)}
            if not all(item["static_gate_passed"] for item in (receipt["pe_audit"],
                  receipt["clock_probe"]["pe_audit"], receipt["native_library"]["pe_audit"])):
                raise RuntimeError("Native import/directory gate failed; inspect build-result.json")
        if run_probe:
            if target != "host":
                raise ValueError("Only the host probe may be automatically executed")
            inputs = output / "fixtures"
            argv = [str(binary), "--server-cert", str(inputs / "server.pem"),
                    "--server-key", str(inputs / "server.key"), "--ca", str(inputs / "ca.pem"),
                    "--untrusted-ca", str(inputs / "other-ca.pem"), "--expired-cert", str(inputs / "expired.pem"),
                    "--expired-key", str(inputs / "expired.key"), "--output", str(output / "probe.log"),
                    "--nonce", "host-" + sha(binary)[:16]]
            run(argv, timeout=120)
            receipt["host_probe_passed"] = True
            receipt["host_probe_log_sha256"] = sha(output / "probe.log")
        if any((HERE / name).read_bytes() != data for name, data in sources.items()):
            raise RuntimeError("Source changed during build; retry with a new output")
        receipt["status"] = "PASS"
    except Exception as error:
        receipt["status"] = "FAIL"
        receipt["error"] = str(error)
        raise
    finally:
        (output / "build-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return {"status": receipt["status"], "target": target, "binary": receipt["binary"],
            "receipt": str(output / "build-result.json"), "host_probe_passed": receipt["host_probe_passed"],
            "native_guest_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=("host", "win98-x86"), required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--run-probe", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 4:
        parser.error("jobs must be between one and four")
    if args.run_probe and args.target != "host":
        parser.error("--run-probe is host-only")
    print(json.dumps(build(args.archive, args.output, args.target, args.jobs, args.run_probe)))


if __name__ == "__main__":
    main()
