#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pin/build transport TLS 1.3 privately; never install into an OS or guest.

Downloads only the hash-pinned official source archive when absent. Writes to
build/tls13, runs CMake/compiler, and optionally a host test executable. The
separate integration test starts temporary loopback-only OpenSSL servers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/tls13"
VERSION = "4.2.0"
ARCHIVE_HASH = "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea"
URL = f"https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-{VERSION}/mbedtls-{VERSION}.tar.bz2"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, log, timeout=300):
    argv = [str(x) for x in argv]
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, cwd=ROOT)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"Step failed ({result.returncode}): {log}\n{result.stdout[-6000:]}")
    return {"argv": argv, "log": str(log), "log_sha256": sha(log), "returncode": 0}


def source():
    upstream = OUT / "upstream"
    upstream.mkdir(parents=True, exist_ok=True)
    archive = upstream / f"mbedtls-{VERSION}.tar.bz2"
    if not archive.exists():
        temporary = archive.with_suffix(".download")
        try:
            urllib.request.urlretrieve(URL, temporary)
            if sha(temporary) != ARCHIVE_HASH:
                raise ValueError("Official Mbed TLS archive hash mismatch")
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    if sha(archive) != ARCHIVE_HASH:
        raise ValueError("Cached Mbed TLS archive hash mismatch")
    tree = upstream / f"mbedtls-{VERSION}"
    # Verify every extracted regular source file on every build. A modified
    # private source cannot silently produce a receipt for the official pin.
    with tarfile.open(archive) as bundle:
        if not tree.exists():
            bundle.extractall(upstream, filter="data")
        for member in bundle.getmembers():
            if not member.isfile():
                continue
            item = upstream / member.name
            if not item.is_file() or sha(item) != hashlib.sha256(bundle.extractfile(member).read()).hexdigest():
                raise ValueError(f"Pinned extracted source changed: {item}")
    licenses = []
    for path in (tree / "LICENSE", tree / "tf-psa-crypto/LICENSE"):
        if "GPL-2.0-or-later" not in path.read_text():
            raise ValueError("Pinned dependency does not provide the chosen GPL2 license option")
        licenses.append({"path": str(path), "sha256": sha(path)})
    return tree, licenses


def effective_config(bdir, tree):
    """Check the real generated compiler flags for every distinct flag set."""
    entries = json.loads((bdir / "compile_commands.json").read_text())
    groups = {}
    for entry in entries:
        original = entry.get("arguments") or shlex.split(entry["command"])
        flags, skip = [], False
        for arg in original:
            if skip:
                skip = False
                continue
            if arg in ("-o", "-MF", "-MT", "-MQ"):
                skip = True
            elif arg in ("-c", "-MD", "-MMD", entry["file"]):
                continue
            else:
                flags.append(arg)
        if any(arg.startswith("@") for arg in flags):
            raise ValueError("Cannot audit response-file compiler flags")
        groups.setdefault(tuple(flags), []).append(entry["file"])
    crypto_required = {"MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG", "MBEDTLS_PLATFORM_GMTIME_R_ALT",
                       "MBEDTLS_PLATFORM_TIME_MACRO", "MBEDTLS_PLATFORM_TIME_TYPE_MACRO"}
    crypto_forbidden = {"MBEDTLS_PSA_BUILTIN_GET_ENTROPY", "MBEDTLS_PSA_DRIVER_GET_ENTROPY",
                        "MBEDTLS_THREADING_C", "MBEDTLS_FS_IO", "MBEDTLS_PSA_ITS_FILE_C"}
    tls_required = {"MBEDTLS_SSL_PROTO_TLS1_3", "MBEDTLS_SSL_CLI_C", "MBEDTLS_SSL_TLS_C",
                    "MBEDTLS_X509_CRT_PARSE_C",
                    "MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED"}
    tls_forbidden = {"MBEDTLS_SSL_PROTO_TLS1_2", "MBEDTLS_SSL_PROTO_DTLS", "MBEDTLS_SSL_SRV_C", "MBEDTLS_NET_C",
                 "MBEDTLS_SSL_SESSION_TICKETS", "MBEDTLS_SSL_EARLY_DATA",
                 "MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED",
                 "MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED"}
    receipts = []
    for number, (flags, units) in enumerate(groups.items()):
        is_tls = any(arg.startswith("-DMBEDTLS_USER_CONFIG_FILE=") for arg in flags)
        if not is_tls and any(not Path(unit).is_relative_to(tree / "tf-psa-crypto") for unit in units):
            raise ValueError(f"TLS translation unit lacks the pinned protocol config: {units}")
        required = crypto_required | (tls_required if is_tls else set())
        forbidden = crypto_forbidden | (tls_forbidden if is_tls else set())
        header = tree / ("include/mbedtls/build_info.h" if is_tls else
                         "tf-psa-crypto/include/tf-psa-crypto/build_info.h")
        probe = bdir / f"effective-config-{number}.c"
        probe.write_text(f'#include "{header}"\n')
        log = bdir / f"effective-config-{number}.log"
        step = run([*flags, "-E", "-dM", "-x", "c", probe], log)
        macros = set(re.findall(r"^#define (\w+)", log.read_text(), re.MULTILINE))
        if required - macros or forbidden & macros:
            raise ValueError(f"Unsafe effective TLS config: missing {sorted(required - macros)}, "
                             f"enabled {sorted(forbidden & macros)}; {log}")
        receipts.append({"translation_units": units, "tls_translation_units": is_tls,
                         "probe_sha256": sha(probe), "preprocessor": step,
                         "required_present": sorted(required), "forbidden_absent": sorted(forbidden)})
    if not receipts:
        raise ValueError("No compiler translation units to audit")
    return receipts


def build(profile, jobs):
    bdir = OUT / profile
    (bdir / "build-result.json").unlink(missing_ok=True)
    inputs = sorted(p for p in (ROOT / "src").glob("m98_tls13*") if p.suffix in (".c", ".h", ".def"))
    inputs += [Path(__file__).resolve(), ROOT / "tests/m98_tls13_host.c"]
    frozen = {str(p): sha(p) for p in inputs}
    tree, licenses = source()
    project = OUT / "project"
    project.mkdir(parents=True, exist_ok=True)
    project_text = f'''cmake_minimum_required(VERSION 3.16)
project(m98_tls13_port C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE "{ROOT / 'src/m98_tls13_protocol_config.h'}" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "{ROOT / 'src/m98_tls13_config.h'}" CACHE FILEPATH "" FORCE)
add_subdirectory("{tree}" upstream)
add_library(m98tls13 STATIC "{ROOT / 'src/m98_tls13.c'}")
target_include_directories(m98tls13 PUBLIC "{ROOT / 'src'}")
target_link_libraries(m98tls13 PUBLIC mbedtls mbedx509 tfpsacrypto)
target_compile_options(m98tls13 PRIVATE -Wall -Wextra -Werror)
if(WIN32)
  add_library(m98tls13_pe32 SHARED "{ROOT / 'src/m98_tls13.c'}" "{ROOT / 'src/m98_tls13.def'}")
  target_include_directories(m98tls13_pe32 PRIVATE "{ROOT / 'src'}")
  target_link_libraries(m98tls13_pe32 PRIVATE mbedtls mbedx509 tfpsacrypto)
  target_link_options(m98tls13_pe32 PRIVATE -nostartfiles -static-libgcc -Wl,--entry,_m98_tls_dll_entry@12,--subsystem,windows,--gc-sections,--major-os-version,4,--minor-os-version,10,--major-subsystem-version,4,--minor-subsystem-version,10,--disable-dynamicbase,--disable-nxcompat,--no-insert-timestamp)
  set_target_properties(m98tls13_pe32 PROPERTIES PREFIX "" OUTPUT_NAME "M98TLS13")
else()
  add_executable(m98_tls13_host "{ROOT / 'tests/m98_tls13_host.c'}")
  target_compile_options(m98_tls13_host PRIVATE -Wall -Wextra -Werror)
  target_link_libraries(m98_tls13_host PRIVATE m98tls13)
endif()
'''
    (project / "CMakeLists.txt").write_text(project_text)
    command = ["cmake", "-S", project, "-B", bdir, "-G", "Ninja",
               "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_FLAGS=-ffunction-sections -fdata-sections"]
    if profile == "pe32":
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if not compiler:
            raise RuntimeError("i686-w64-mingw32-gcc is required for --profile pe32")
        command += ["-DCMAKE_SYSTEM_NAME=Windows", f"-DCMAKE_C_COMPILER={compiler}",
                    "-DCMAKE_C_FLAGS=-ffunction-sections -fdata-sections -D_WIN32_WINNT=0x0400"]
    steps = [run(command, bdir / "configure.log")]
    config_receipts = effective_config(bdir, tree)
    steps.append(run(["cmake", "--build", bdir, "--parallel", jobs], bdir / "build.log"))
    for path, expected in frozen.items():
        if sha(Path(path)) != expected:
            raise RuntimeError(f"Input changed during build; no successful receipt published: {path}")
    artifacts = [bdir / "libm98tls13.a"]
    artifacts += [bdir / ("M98TLS13.dll" if profile == "pe32" else "m98_tls13_host")]
    result = {"profile": profile, "dependency": {"name": "Mbed TLS", "version": VERSION,
              "url": URL, "archive_sha256": ARCHIVE_HASH, "tf_psa_crypto_version": "1.2.0",
              "license_selected": "GPL-2.0-or-later (GPL version 2)", "licenses": licenses},
              "source_files": [{"path": path, "sha256": expected} for path, expected in frozen.items()],
              "effective_configuration": config_receipts,
              "steps": steps, "artifacts": [{"path": str(p), "sha256": sha(p)} for p in artifacts],
              "guest_validated": False, "os_schannel_integrated": False}
    (bdir / "build-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"built": profile, "artifacts": [str(x) for x in artifacts],
                      "guest_validated": False, "os_schannel_integrated": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["host", "pe32"], default="host")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error("jobs must be 1..8")
    build(args.profile, args.jobs)
