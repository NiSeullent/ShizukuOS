#!/usr/bin/env python3
"""Isolated Win98 GUI probe build; never stages, registers or runs a guest."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ADAPTER = ROOT / "build/secure-transport/sspi-native-v1/native-root-readonly"
FROZEN = ROOT / "build/secure-transport/native-v5-crt"
UPSTREAM = ROOT / "build/secure-transport/native-v3/upstream/mbedtls-3.6.7/include"
DLL_SHA = "ac3392d878f1e35a107d14111166401d3efb8f7507df3e7e19d61d59b4d2d2b2"
DLL_BYTES = 1638356
SOURCES = ("sspi_guest_probe.c", "sspi_guest_probe_build.py", "sspi_native.h",
           "native_runtime.h", "transport.h")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def future_certificate(key_bytes):
    """Use the retained key with explicit future validity and DNS identity."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    secret = serialization.load_pem_private_key(key_bytes, password=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls13.win98.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(secret.public_key()).serial_number(12345)
            .not_valid_before(datetime(2038, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2039, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls13.win98.test")]), critical=False)
            .sign(secret, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def retained_inputs():
    receipt_path = ADAPTER / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    dll = ADAPTER / "M98SSPI.dll"
    require(receipt["passed"] and receipt["audit"]["sha256"] == DLL_SHA and
            receipt["audit"]["bytes"] == DLL_BYTES, "require corrected read-only ROOT adapter receipt")
    require(digest(dll) == DLL_SHA and dll.stat().st_size == DLL_BYTES, "corrected DLL binding changed")
    for name, value in receipt["source_sha256"].items():
        require(digest(HERE / name) == value, "reviewed adapter dependency changed: " + name)
    for name, value in receipt["retained_input_sha256"].items():
        require(digest(Path(name)) == value, "reviewed retained dependency changed: " + name)
    cmake = FROZEN / "cmake"
    objects = [cmake / "CMakeFiles/M98TLS.dir" / (name + ".c.obj")
               for name in ("native_runtime", "native_time")]
    archives = [cmake / "libntwst.a"]
    archives += [cmake / "upstream/library" / ("lib" + name + ".a")
                 for name in ("mbedtls", "mbedx509", "mbedcrypto")]
    archives += [cmake / "upstream/3rdparty/everest/libeverest.a",
                 cmake / "upstream/3rdparty/p256-m/libp256m.a"]
    fixtures = [FROZEN / "fixtures" / name for name in
                ("ca.pem", "other-ca.pem", "server.pem", "server.key", "expired.pem", "expired.key")]
    inputs = [receipt_path, dll] + [Path(name) for name in receipt["retained_input_sha256"]]
    inputs += fixtures
    return objects + archives, fixtures, {str(path): digest(path) for path in inputs}


def pe_audit(binary, baseline, symbol_output):
    import pefile
    pe = pefile.PE(str(binary))
    inventory = json.loads(baseline.read_text())["dlls"]
    imports, missing = {}, []
    for row in pe.DIRECTORY_ENTRY_IMPORT:
        dll = row.dll.decode("ascii").upper()
        names = [s.name.decode("ascii") if s.name else "#" + str(s.ordinal) for s in row.imports]
        imports[dll] = names
        missing += [[dll, name] for name in names if name not in inventory.get(dll, [])]
    forbidden = {str(index): pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size for index in (9, 10, 13, 14)}
    relocs = sum(s.type == 3 for row in pe.DIRECTORY_ENTRY_BASERELOC for s in row.entries)
    entry_symbol = None
    for line in symbol_output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "_M98SspiProbeEntry@0":
            entry_symbol = int(parts[0], 16) - pe.OPTIONAL_HEADER.ImageBase
    audit = {"machine": pe.FILE_HEADER.Machine, "optional_magic": pe.OPTIONAL_HEADER.Magic,
             "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
             "timestamp": pe.FILE_HEADER.TimeDateStamp, "subsystem": pe.OPTIONAL_HEADER.Subsystem,
             "os_version": [pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion],
             "subsystem_version": [pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                                   pe.OPTIONAL_HEADER.MinorSubsystemVersion],
             "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
             "entry_symbol_rva": entry_symbol,
             "imports": imports, "import_count": sum(map(len, imports.values())),
             "imports_absent_from_original_win98_inventory": missing,
             "forbidden_directory_sizes": forbidden, "highlow_relocations": relocs,
             "export_directory_size": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
             "bytes": binary.stat().st_size, "sha256": digest(binary)}
    passed = (audit["machine"] == 0x14c and audit["optional_magic"] == 0x10b and not audit["dll"] and
              audit["timestamp"] == 0 and audit["subsystem"] == 2 and audit["os_version"] == [4, 10] and
              audit["subsystem_version"] == [4, 10] and audit["entry_rva"] == entry_symbol and
              entry_symbol is not None and entry_symbol > 0 and not missing and not any(forbidden.values()) and
              relocs > 0 and not audit["export_directory_size"] and
              not any(name.startswith("WS2_") or name in ("WSOCK32.DLL", "SECUR32.DLL", "SCHANNEL.DLL")
                      for name in imports))
    return audit, passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("preserve prior runs: output must be a new directory")
    output.mkdir(parents=True, mode=0o700)
    receipt = {"schema": "win98modern.sspi-guest-probe-native-build.v1", "passed": False,
               "native_guest_proven": False, "actual_Windows_DLL_execution": False,
               "native_default_ROOT_certificate_validation": False, "sockets_verified": False,
               "os_provider_registered": False, "full_toolchain_provenance_closed": False}
    try:
        hashes = {name: digest(HERE / name) for name in SOURCES}
        for name in SOURCES:
            shutil.copyfile(HERE / name, output / name)
        retained, fixtures, input_hashes = retained_inputs()
        config = FROZEN / "project/user_config.h"
        shutil.copyfile(config, output / "user_config.h")
        # Bind the retained header set, separately from the implicit SDK/toolchain.
        header_hashes = {str(path): digest(path) for path in sorted(UPSTREAM.rglob("*.h"))}
        require(header_hashes, "retained Mbed TLS include tree missing")
        guest = output / "guest-files"
        guest.mkdir(mode=0o700)
        shutil.copyfile(ADAPTER / "M98SSPI.dll", guest / "M98SSPI.DLL")
        names = ("CA.PEM", "BADCA.PEM", "SRV.PEM", "SRV.KEY", "EXP.PEM", "EXP.KEY")
        for fixture, name in zip(fixtures, names):
            shutil.copyfile(fixture, guest / name)
        (guest / "FUT.PEM").write_bytes(future_certificate((guest / "SRV.KEY").read_bytes()))
        binary = guest / "TLS13PRB.EXE"
        command = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-march=i486", "-Wall", "-Wextra",
                   "-Werror", "-Wpedantic", "-ffunction-sections", "-fdata-sections", "-MD",
                   "-MF", str(output / "compiler.dependencies"),
                   "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
                   '-DMBEDTLS_USER_CONFIG_FILE="user_config.h"', "-I" + str(output), "-I" + str(UPSTREAM),
                   "-nostartfiles", "-static", "-static-libgcc",
                   "-Wl,--gc-sections,--no-insert-timestamp,--subsystem,windows:4.10,"
                   "--major-os-version,4,--minor-os-version,10,--entry,_M98SspiProbeEntry@0",
                   str(output / "sspi_guest_probe.c")]
        command += list(map(str, retained)) + ["-ladvapi32", "-o", str(binary)]
        proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
        (output / "compiler.stdout").write_text(proc.stdout)
        (output / "compiler.stderr").write_text(proc.stderr)
        receipt.update(source_sha256=hashes, retained_input_sha256=input_hashes,
                       retained_mbed_header_sha256=header_hashes, compiler_argv=command,
                       compiler_exit=proc.returncode, DLL_sha256=DLL_SHA, DLL_bytes=DLL_BYTES)
        if proc.returncode == 0:
            symbols = subprocess.run(["i686-w64-mingw32-nm", str(binary)], text=True,
                                     capture_output=True, timeout=30, check=True)
            (output / "native-symbols.txt").write_text(symbols.stdout)
            audit, passed = pe_audit(binary, ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json", symbols.stdout)
            receipt["audit"] = audit
            receipt["passed"] = passed
            deps = (output / "compiler.dependencies").read_text().replace("\\\n", " ").split(":", 1)[1].split()
            receipt["compiler_header_dependency_sha256"] = {
                str(Path(name).resolve()): digest(Path(name)) for name in deps}
            compiler = Path(shutil.which(command[0])).resolve()
            receipt["compiler_binary"] = {"path": str(compiler), "sha256": digest(compiler)}
            support = {}
            for name in ("libgcc.a", "libmingw32.a", "libmingwex.a", "libmsvcrt.a", "libkernel32.a", "libadvapi32.a"):
                result = subprocess.run([command[0], "-print-file-name=" + name], text=True,
                                        capture_output=True, timeout=10, check=True)
                path = Path(result.stdout.strip()).resolve()
                require(path.is_file(), "compiler support input missing: " + name)
                support[str(path)] = digest(path)
            receipt["compiler_support_input_sha256"] = support
            files = [{"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)}
                     for path in sorted(guest.iterdir())]
            write_json(output / "staging-plan.json", {
                "schema": "win98modern.sspi-guest-probe-staging-plan.v1", "staged": False,
                "target_directory": "C:\\GOPLAB", "files": files,
                "child_command": "C:\\GOPLAB\\TLS13PRB.EXE --nonce <fresh-[A-Za-z0-9-]{16,64}>",
                "child_log": "SSPI13.LOG", "outer_observer_required": "separate SSPWATCH.EXE",
                "existing_TLSWATCH_compatible": False, "new_clone_and_fresh_logs_required": True,
                "observer_deadline_ms": 90000, "child_cooperative_deadline_ms": 70000,
                "pair_deadline_ms": 8000, "pair_count": 7,
                "default_ROOT_case": "acquisition-only; native validation remains false",
                "sockets_verified": False, "os_provider_registered": False})
            receipt["guest_file_sha256"] = {str(guest / row["name"]): row["sha256"] for row in files}
        if hashes != {name: digest(HERE / name) for name in SOURCES} or any(
                digest(Path(name)) != value for name, value in input_hashes.items()) or any(
                digest(Path(name)) != value for name, value in header_hashes.items()):
            receipt["passed"] = False
            receipt["error"] = "input changed during isolated build"
    except Exception as error:
        receipt["passed"] = False
        receipt["error"] = str(error)
    write_json(output / "receipt.json", receipt)
    print(json.dumps({"passed": receipt["passed"], "receipt": str(output / "receipt.json"),
                      "compiler_exit": receipt.get("compiler_exit"), "error": receipt.get("error"),
                      "audit": receipt.get("audit")}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
