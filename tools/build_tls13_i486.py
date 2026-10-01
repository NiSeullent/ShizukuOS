#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fresh source-built i486 TLS backends; no guest launch, install or download.

Uses existing pinned official archives and an immutable LTS adapter snapshot.
Actual host interop runs two separately owned processes on loopback only.
"""
import argparse
import hashlib
import json
import math
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import select
import shlex
import shutil
import subprocess
import tarfile
import time
import pefile

from i486_instruction_gate import scan

ROOT = Path(__file__).resolve().parents[1]
LATEST_ARCHIVE = ROOT / "build/tls13/upstream/mbedtls-4.2.0.tar.bz2"
LATEST_SHA = "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea"
LATEST_RECEIPT = ROOT / "build/tls13/pe32/build-result.json"
LATEST_RECEIPT_SHA = "73ac0880829c4d924873aa219fc13dec8de102f8dd759c858f69508f46adaf31"
FIXTURE_RECEIPT = ROOT / "build/tls13-guest-interop-v4/build-result.json"
FIXTURE_RECEIPT_SHA = "e1685828dbbbe2c58596193f47d6596a9a7c9fb40d12c6570b7bf4ff3cb8252e"
LTS_ROOT = Path("/root/Win98-Modern-tls13-7707/build/secure-transport/native-v3")
LTS_ARCHIVE = LTS_ROOT.parent / "upstream/mbedtls-3.6.7.tar.bz2"
LTS_SHA = "a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
LTS_RECEIPT = ROOT / "build/tls13-guest-interop-v4/server-build.json"
LTS_RECEIPT_SHA = "e80ac28e5ea1ac5c719c4f2223a0f1017d3f27ae03d5972d625d560b6f688494"
GATE_SHA = "6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973"
GATE_TEST_SHA = "6a0ff7367a2c32d09bebda68283b4be710cf27ddae67b21a571424655edabe51"
LATEST_ADAPTER = ["src/m98_tls13.c", "src/m98_tls13.h", "src/m98_tls13.def",
                  "src/m98_tls13_config.h", "src/m98_tls13_protocol_config.h"]
LTS_ADAPTER = ["transport.c", "transport.h", "native_time.c", "native_runtime.c",
               "native_runtime.h", "native_crt.c", "native.def", "user_config.h"]
OWN = ["tools/build_tls13_i486.py", "src/m98_tls_i486_format.c", "src/m98_tls_i486_format.h",
       "tests/m98_tls_i486_format_host.c", "tests/test_tls13_i486_startup.py", "docs/TLS13_I486_HANDOFF.md",
       "tools/i486_instruction_gate.py", "tests/test_i486_instruction_gate.py",
       "benchmarks/win98se-ko-oem-native-exports-v1.json", "tests/m98_tls13_host.c",
       "tests/m98_tls13_lts_loopback_server.c"] + LATEST_ADAPTER
CLIENT_EXPORTS = set("m98_tls_create m98_tls_handshake m98_tls_write m98_tls_read m98_tls_shutdown m98_tls_backend_error m98_tls_verify_flags m98_tls_is_established m98_tls_free".split())
SERVER_EXPORTS = set("ntwst_runtime_init ntwst_runtime_fini ntwst_native_runtime_init ntwst_native_runtime_fini ntwst_create ntwst_destroy ntwst_handshake ntwst_write ntwst_read ntwst_close_notify ntwst_version ntwst_verify_flags ntwst_engine_error".split())
CPU_FLAGS = "-march=i486 -mtune=i486 -mno-sse -mno-sse2 -mno-mmx -msoft-float -fno-stack-protector -mno-stack-arg-probe -fno-isolate-erroneous-paths-dereference"
BASE_FLAGS = "-ffunction-sections -fdata-sections -fno-builtin -D__USE_MINGW_ANSI_STDIO=0"
CALL_NAMES = {"snprintf": 2, "vsnprintf": 2, "sprintf": 1, "vsprintf": 1,
              "printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1,
              "mbedtls_snprintf": 2, "mbedtls_vsnprintf": 2, "mbedtls_printf": 0,
              "mbedtls_fprintf": 1, "m98_tls_i486_snprintf": 2, "m98_tls_i486_vsnprintf": 2,
              "mbedtls_debug_snprintf": 2, "mbedtls_platform_win32_snprintf": 2,
              "mbedtls_platform_win32_vsnprintf": 2,
              "_snprintf": 2, "_vsnprintf": 2, "__mingw_snprintf": 2, "__mingw_vsnprintf": 2,
              "__mingw_printf": 0, "__mingw_vprintf": 0, "__mingw_fprintf": 1, "__mingw_vfprintf": 1}
C_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]', re.S)
DIRECTIVE = re.compile(r"%([-+ #0]*)(\*|[0-9]*)(?:\.(\*|[0-9]*))?(hh|h|ll|l|j|z|t|I64|I32|I)?([diuoxXscp%])")


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    need(path.is_file() and not path.is_symlink(), "regular source/input required: " + str(path))
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def literal_support(value):
    errors = []
    if len(value.encode()) > 4096:
        errors.append("format-length-bound")
    p = 0
    while p < len(value):
        if value[p] != "%":
            p += 1
            continue
        m = DIRECTIVE.match(value, p)
        if not m:
            errors.append("unsupported-directive:" + value[p:p + 16])
            break
        flags, width, precision, length, code = m.groups()
        if (width.isdigit() and int(width) > 4096) or (precision and precision.isdigit() and int(precision) > 4096):
            errors.append("width-precision-bound")
        if code in "sc" and (length or any(x in flags for x in "+ #0") or (code == "c" and precision is not None)):
            errors.append("unsupported-string-character-form")
        if code == "%" and m.group() != "%%":
            errors.append("unsupported-percent-form")
        if code == "p" and (length or precision is not None or any(x in flags for x in "+ #")):
            errors.append("unsupported-pointer-form")
        p = m.end()
    return errors


def c_string(token):
    need(len(token) >= 2 and token[0] == token[-1] == '"', "ordinary C string required")
    output, i = [], 1
    simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
              "'": "'", '"': '"', "?": "?", "\\": "\\"}
    while i < len(token) - 1:
        if token[i] != "\\":
            output.append(token[i]); i += 1
            continue
        i += 1
        need(i < len(token) - 1, "truncated C escape")
        code = token[i]; i += 1
        if code in simple:
            output.append(simple[code])
        elif code == "\n":
            pass  # C escaped source-line continuation.
        elif code in "01234567":
            digits = code
            while i < len(token) - 1 and len(digits) < 3 and token[i] in "01234567":
                digits += token[i]; i += 1
            value = int(digits, 8)
            need(value <= 255, "implementation-dependent C octal byte")
            output.append(chr(value))
        elif code == "x":
            begin = i
            while i < len(token) - 1 and token[i] in "0123456789abcdefABCDEF":
                i += 1
            need(i > begin and int(token[begin:i], 16) <= 255, "unsupported C hex byte")
            output.append(chr(int(token[begin:i], 16)))
        elif code in {"u", "U"}:
            size = 4 if code == "u" else 8
            digits = token[i:i + size]
            need(len(digits) == size and all(d in "0123456789abcdefABCDEF" for d in digits), "invalid C universal escape")
            value = int(digits, 16); i += size
            need(value <= 0x10ffff and not 0xd800 <= value <= 0xdfff, "invalid C universal scalar")
            output.append(chr(value))
        else:
            raise RuntimeError("unsupported C escape")
    return "".join(output)


def format_uses(text):
    tokens = [m.group() for m in C_TOKEN.finditer(text) if not m.group().startswith(("//", "/*"))]
    uses = []
    for index, name in enumerate(tokens[:-1]):
        if tokens[index + 1] != "(" or not (name in CALL_NAMES or re.fullmatch(r"[A-Za-z_]\w*printf", name)):
            continue
        args, one, depth, end = [], [], 0, index + 2
        for end in range(index + 2, len(tokens)):
            token = tokens[end]
            if token == ")" and not depth:
                args.append(one)
                break
            if token == "," and not depth:
                args.append(one); one = []
            else:
                one.append(token)
                if token in {"(", "[", "{"}:
                    depth += 1
                elif token in {")", "]", "}"}:
                    depth -= 1
        if name not in CALL_NAMES:
            uses.append({"function": name, "kind": "unclassified-format-related-call",
                         "arguments": [" ".join(a)[:1024] for a in args],
                         "policy": "no format position, routing, supported-directive or C99 behavior inferred"})
            continue
        argument = CALL_NAMES[name]
        if len(args) <= argument:
            continue
        value = args[argument]
        if value and value[0] in {"const", "char"} and "*" in value and not any(t in value for t in ("(", ")", "=")):
            continue  # A function declaration, retained in the original source pin.
        row = {"function": name, "expression": " ".join(value)[:1024]}
        if value and all(x.startswith('"') for x in value):
            try:
                constant = "".join(c_string(x) for x in value).split("\0", 1)[0]
                row.update(kind="constant", value=constant, unsupported=literal_support(constant))
            except (ValueError, RuntimeError):
                row.update(kind="unresolved-constant", unsupported=["C-literal-decode"])
        else:
            row.update(kind="dynamic", policy=("bounded runtime directive/count validation; unsupported => -1 before output"
                       if name in {"m98_tls_i486_snprintf", "m98_tls_i486_vsnprintf"} else
                       "not proven routed; no bounded/custom-formatter or C99 semantics inferred"))
        uses.append(row)
    return uses


def unpack(archive, expected, destination):
    need(sha(archive) == expected, "official cached archive pin mismatch")
    copied = destination / archive.name
    destination.mkdir(parents=True)
    shutil.copyfile(archive, copied)
    need(sha(copied) == expected, "copied archive changed")
    pins, roots, names, links, count, allocation = {}, set(), set(), {}, 0, 0
    with tarfile.open(copied) as bundle:
        for member in bundle:
            parts = PurePosixPath(member.name)
            need(parts.parts and not parts.is_absolute() and ".." not in parts.parts and len(member.name) <= 1024,
                 "noncanonical archive member")
            name = str(parts)
            need(name not in names, "duplicate archive member")
            names.add(name)
            need(len(names) <= 40000, "archive member count bound")
            roots.add(parts.parts[0])
            if member.isdir():
                (destination / name).mkdir(parents=True, exist_ok=True)
                continue
            if member.issym():
                need(member.linkname and not PurePosixPath(member.linkname).is_absolute() and
                     len(member.linkname) <= 1024, "noncanonical original archive alias")
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                need(PurePosixPath(resolved).parts[0] == parts.parts[0] and ".." not in PurePosixPath(resolved).parts,
                     "original archive alias escapes root")
                links[name] = {"target": member.linkname, "normalized_target": resolved}
                continue
            need(member.isfile(), "unexpected nonregular original archive member")
            count += 1; allocation += member.size
            need(count <= 40000 and 0 <= member.size <= 16 * 1024 * 1024 and allocation <= 512 * 1024 * 1024,
                 "archive extraction bound")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            data = bundle.extractfile(member).read()
            need(len(data) == member.size, "archive short read")
            target.write_bytes(data)
            pins[str(target)] = hashlib.sha256(data).hexdigest()
    need(len(roots) == 1, "original archive root")
    root = destination / roots.pop()
    ancestors = {str(p) for n in names for p in PurePosixPath(n).parents if str(p) != "."}
    declared = names | ancestors
    # Preserve exact relative aliases only after all regular members are written.
    # Alias ancestors and undeclared targets are rejected before creating a link.
    for name, item in links.items():
        need(item["normalized_target"] in declared, "undeclared original alias target")
        need(not any(str(parent) in links for parent in PurePosixPath(name).parents),
             "original alias under alias parent")
        need(name not in ancestors, "original alias overlaps archive member ancestor")
    for name, item in links.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        need(not target.exists() and not target.is_symlink(), "original alias path collision")
        target.symlink_to(item["target"])
    for name, item in links.items():
        target = destination / name
        resolved = target.resolve(strict=True)
        need(resolved.is_relative_to(root) and os.readlink(target) == item["target"],
             "original alias target/metadata mismatch")
    return root, pins, {str(destination / n): item for n, item in links.items()}


def command_flags(entry):
    args = entry.get("arguments") or shlex.split(entry["command"])
    flags, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg in {"-o", "-MF", "-MT", "-MQ"}:
            skip = True
        elif arg not in {"-c", "-MD", "-MMD", entry["file"]}:
            flags.append(arg)
    need(not any(x.startswith("@") for x in flags), "response-file flags not audited")
    return flags


def native_gate(path, exports):
    baseline = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        h = pe.OPTIONAL_HEADER
        need(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and pe.is_dll(), "native PE32 DLL")
        need(pe.FILE_HEADER.TimeDateStamp == 0 and h.Subsystem == 2 and h.AddressOfEntryPoint and
             (h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion) == (4, 10) and
             (h.MajorSubsystemVersion, h.MinorSubsystemVersion) == (4, 10), "native Win98 loader fields")
        need(h.DllCharacteristics == 0 and h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics & 1,
             "original legacy relocations/flags")
        need((h.SizeOfStackReserve, h.SizeOfStackCommit) == (2097152, 65536), "explicit stack fields")
        need(all(not h.DATA_DIRECTORY[i].VirtualAddress and not h.DATA_DIRECTORY[i].Size for i in (9, 10, 13, 14)),
             "unsupported TLS/load-config/delay/CLR directory")
        symbols = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        names = {x.name.decode() for x in symbols if x.name}
        need(names == exports and len(names) == len(symbols) and not any(x.forwarder for x in symbols), "exact original export ABI")
        imports = {}
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            module = descriptor.dll.decode().upper()
            need(module in {"KERNEL32.DLL", "MSVCRT.DLL", "ADVAPI32.DLL"} and module not in imports,
                 "original native import modules")
            need(all(x.name for x in descriptor.imports), "original named imports")
            names = sorted(x.name.decode() for x in descriptor.imports)
            need(set(names) <= set(baseline.get(module, [])), "original Win98 OEM export names")
            imports[module] = names
        need(imports, "actual DLL imports")
    return {"pe98_gate": "pass", "imports": imports, "exports": sorted(exports),
            "stack_reserve": 2097152, "stack_commit": 65536}


def read_owned_port(stdout, timeout=5.0):
    """Read one bounded startup line without a blocking buffered read.

    A single absolute deadline covers every partial byte. The caller owns and
    reaps the child in its finally block; this function never controls peers.
    """
    need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 5,
         "bounded owned server startup timeout")
    fd = stdout.fileno()
    blocking = os.get_blocking(fd)
    deadline = time.monotonic() + timeout
    data = bytearray()
    os.set_blocking(fd, False)
    try:
        while len(data) < 64:
            remaining = deadline - time.monotonic()
            need(remaining > 0, "owned loopback server startup deadline")
            try:
                ready = select.select([fd], [], [], remaining)[0]
            except InterruptedError:
                continue
            need(ready and time.monotonic() < deadline,
                 "owned loopback server startup deadline")
            try:
                byte = os.read(fd, 1)
            except (BlockingIOError, InterruptedError):
                continue
            need(time.monotonic() < deadline, "owned loopback server startup deadline")
            need(byte, "owned loopback server startup EOF")
            data.extend(byte)
            if byte == b"\n":
                line = bytes(data)
                match = re.fullmatch(rb"PORT=([0-9]+)\n", line)
                need(match and 0 < int(match[1]) <= 65535,
                     "actual isolated LTS loopback port")
                return line
        raise RuntimeError("owned loopback server startup line exceeds 64 bytes")
    finally:
        os.set_blocking(fd, blocking)


def host_interop(out, result):
    fixtures = out / "fixtures"; fixtures.mkdir()
    stage = ROOT / "build/tls13-guest-interop-v4"
    need(sha(FIXTURE_RECEIPT) == FIXTURE_RECEIPT_SHA, "frozen fixture receipt changed")
    source_receipt = json.loads(FIXTURE_RECEIPT.read_text())
    fixture_names = ["CA.PEM", "SRV.PEM", "SRV.KEY", "BADCA.PEM"]
    for name in fixture_names:
        item = source_receipt["artifacts"][name]
        need(sha(stage / name) == item["sha256"], "frozen private fixture identity")
        shutil.copyfile(stage / name, fixtures / name)
        (fixtures / name).chmod(0o600 if name.endswith(".KEY") else 0o644)
        need(sha(fixtures / name) == item["sha256"], "copied private fixture identity")
    client = Path(result["profiles"]["latest-host"]["host_probe"])
    server = Path(result["profiles"]["lts-host"]["host_probe"])
    cases = []
    for mode, hostname, trust in [("valid", "tls13.win98.test", "CA.PEM"), ("retry", "tls13.win98.test", "CA.PEM"),
             ("wrong-host", "wrong.example", "CA.PEM"), ("untrusted", "tls13.win98.test", "BADCA.PEM"),
             ("corrupt-record", "tls13.win98.test", "CA.PEM"), *[(m, "tls13.win98.test", "CA.PEM") for m in
             ("entropy", "entropy-negative", "entropy-partial", "entropy-late", "entropy-late-negative", "entropy-late-partial", "clock")]]:
        child = subprocess.Popen([str(server), str(fixtures / "SRV.PEM"), str(fixtures / "SRV.KEY")],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=out)
        try:
            port_line = read_owned_port(child.stdout)
            match = re.fullmatch(rb"PORT=([0-9]+)\n", port_line)
            command = [str(client), match[1].decode(), str(fixtures / trust), hostname, mode]
            probe = subprocess.run(command, capture_output=True, timeout=15, cwd=out)
            client_log = out / ("host-interop-" + mode + "-client.log")
            client_log.write_bytes(probe.stdout + probe.stderr)
            response = json.loads(probe.stdout)
            server_out, server_error = child.communicate(timeout=8)
            server_log = out / ("host-interop-" + mode + "-server.log")
            server_log.write_bytes(port_line + server_out + server_error)
            need(probe.returncode == 0 and response["passed"] is True, "actual latest/LTS client case: " + mode)
            if mode in {"valid", "retry"}:
                need(child.returncode == 0 and b"HOST_LTS_ENCRYPTED_HTTP=PASS" in server_out and b"SERVER_VERSION=TLSv1.3" in server_out,
                     "actual positive LTS encrypted HTTP completion")
            cases.append({"mode": mode, "actual_client_exit": probe.returncode, "client_result": response,
                "actual_server_exit": child.returncode, "client_log": str(client_log), "client_log_sha256": sha(client_log),
                "server_log": str(server_log), "server_log_sha256": sha(server_log),
                "scope": "separate Linux latest/LTS library processes; native Windows/network/OS acceptance false"})
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=3)
            if child.stdout:
                child.stdout.close()
            if child.stderr:
                child.stderr.close()
    result["host_latest_lts_interop"] = {"passed": True, "cases": cases, "loopback_only": True,
         "latest_probe_sha256": sha(client), "lts_probe_sha256": sha(server),
         "native_windows": False, "system_tls": False, "mutual_client_authentication": False}


def compatibility_receipts(out, result):
    # Explicit handoffs retain the existing published ABI/build profiles. The
    # corrected complete source/CPU evidence is included, not inferred from a
    # compiler option or from header/import compatibility alone.
    latest = result["profiles"]["latest-native"]
    server = result["profiles"]["lts-native"]
    source_files = [{"path": str(ROOT / n), "sha256": h} for n, h in result["source_sha256"].items()]
    shared = {"original_source_pins": result["original_source_pins"],
              "original_alias_metadata": result["original_alias_metadata"],
              "host_full_response_oracle": result["host_full_response_oracle"],
              "generated_recipe_sha256": result["generated_recipe_sha256"],
              "corrected_instruction_gate_sha256": GATE_SHA,
              "all_upstream_format_inventory": result["all_upstream_format_inventory"],
              "native_guest_verified": False, "system_tls_verified": False,
              "application_functionality_verified": False}
    client_receipt = {"profile": "pe32", "dependency": {"name": "Mbed TLS", "version": "4.2.0",
                      "archive_sha256": LATEST_SHA, "tf_psa_crypto_version": "1.2.0",
                      "license_selected": "GPL-2.0-or-later (GPL version 2)"},
                      "source_files": source_files, "artifacts": [{"path": latest["artifact"], "sha256": latest["sha256"]}],
                      "effective_configuration": latest["effective_configuration"],
                      "corrective_i486_build": latest, "host_latest_lts_interop": result["host_latest_lts_interop"], **shared}
    fixture_map = {a: sha(out / "fixtures" / b) for a, b in {"ca.pem": "CA.PEM", "server.pem": "SRV.PEM",
                   "server.key": "SRV.KEY", "other-ca.pem": "BADCA.PEM"}.items()}
    server_receipt = {"schema": "win98modern.secure-transport-build.v1", "status": "PASS", "target": "win98-x86",
                      "upstream": {"version": "3.6.7", "archive_sha256": LTS_SHA,
                                   "license": "Apache-2.0 OR GPL-2.0-or-later"},
                      "source_sha256": result["lts_original_source_sha256"], "fixtures": fixture_map,
                      "native_library": {"path": server["artifact"], "sha256": server["sha256"], "bytes": server["bytes"],
                                         "pe_audit": server["pe"], "i486": server["i486"]},
                      "corrective_i486_build": server, "host_probe_passed": True,
                      "host_latest_lts_interop": result["host_latest_lts_interop"], **shared}
    result["handoff_receipts"] = {}
    for name, receipt in (("client-build.json", client_receipt), ("server-build.json", server_receipt)):
        path = out / name
        path.write_text(json.dumps(receipt, indent=2) + "\n")
        result["handoff_receipts"][name] = {"path": str(path), "sha256": sha(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    out = args.output.absolute()
    need(out.resolve() == out and out.parent == ROOT / "build" and not out.exists(), "fresh owned build output required")
    need(1 <= args.jobs <= 2, "bounded 1..2 compiler jobs")
    need(c_string(r'"\?\?="') == "??=" and c_string(r'"\045d\x2f\n"') == "%d/\n" and
         c_string(r'"\\\"\t"') == '\\"\t', "C constant escape controls")
    need(sha(ROOT / "tools/i486_instruction_gate.py") == GATE_SHA and
         sha(ROOT / "tests/test_i486_instruction_gate.py") == GATE_TEST_SHA, "reviewed corrected instruction gate pin")
    need(sha(LTS_RECEIPT) == LTS_RECEIPT_SHA, "frozen LTS receipt")
    need(sha(LATEST_RECEIPT) == LATEST_RECEIPT_SHA and sha(FIXTURE_RECEIPT) == FIXTURE_RECEIPT_SHA,
         "frozen original latest/fixture receipts")
    lts_receipt = json.loads(LTS_RECEIPT.read_text())
    own_pins = {name: sha(ROOT / name) for name in OWN}
    original_latest = {x["path"]: x["sha256"] for x in json.loads(LATEST_RECEIPT.read_text())["source_files"]}
    need(all(original_latest.get(str(ROOT / n)) == own_pins[n] for n in LATEST_ADAPTER),
         "original latest adapter/configuration bytes")
    fixture_receipt = json.loads(FIXTURE_RECEIPT.read_text())
    need(all(sha(FIXTURE_RECEIPT.parent / n) == fixture_receipt["artifacts"][n]["sha256"]
             for n in ("CA.PEM", "SRV.PEM", "SRV.KEY", "BADCA.PEM")), "original private fixture pins")
    lts_pins = {name: sha(LTS_ROOT / "project" / name) for name in LTS_ADAPTER}
    need(all(lts_pins[n] == lts_receipt["source_sha256"][n] for n in LTS_ADAPTER), "frozen LTS adapter source changed")
    need(sha(LATEST_ARCHIVE) == LATEST_SHA and sha(LTS_ARCHIVE) == LTS_SHA, "official source archive pins")
    out.mkdir()
    result = {"schema": 1, "kind": "original-latest-lts-i486-corrective-port", "passed": False,
              "source_sha256": own_pins, "lts_original_source_sha256": lts_pins, "steps": [],
              "native_execution": False, "native_network": False, "system_tls": False,
              "modern_apps": False, "original_stages_modified": False}
    result["input_authorities"] = {str(p): h for p, h in
        ((LATEST_RECEIPT, LATEST_RECEIPT_SHA), (LTS_RECEIPT, LTS_RECEIPT_SHA), (FIXTURE_RECEIPT, FIXTURE_RECEIPT_SHA))}

    def run(command, name, env=None, timeout=300):
        log = out / (name + ".log")
        try:
            process = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                                     capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            log.write_bytes((error.stdout or b"") + (error.stderr or b""))
            result["steps"].append({"name": name, "command": [str(x) for x in command],
                                   "returncode": None, "timed_out": True, "deadline_seconds": timeout,
                                   "log": str(log), "sha256": sha(log)})
            raise RuntimeError("owned command deadline: " + str(log)) from error
        log.write_bytes(process.stdout + process.stderr)
        result["steps"].append({"name": name, "command": [str(x) for x in command],
                                "returncode": process.returncode, "log": str(log), "sha256": sha(log)})
        need(process.returncode == 0, "failed " + name + ": " + str(log))
        return process.stdout

    try:
        for name in OWN:
            target = out / "source" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
            need(sha(target) == own_pins[name], "own source copy drift")
        for n, p in (("latest-build.json", LATEST_RECEIPT), ("lts-build.json", LTS_RECEIPT), ("fixtures-build.json", FIXTURE_RECEIPT)):
            target = out / "source/authorities" / n
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, target)
            need(sha(target) == result["input_authorities"][str(p)], "authority copy drift")
        for mode, extra in (("normal", []), ("sanitize", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            binary = out / ("formatter-" + mode)
            run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Isrc", *extra,
                 "src/m98_tls_i486_format.c", "tests/m98_tls_i486_format_host.c", "-o", binary], "formatter-" + mode + "-build")
            verdict = run([binary], "formatter-" + mode + "-test", dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
            need(verdict.startswith(b"PASS bounded TLS i486 formatter:"), "real formatter verdict")
            result["formatter_" + mode] = verdict.decode().strip()
            result["formatter_" + mode + "_binary"] = {"path": str(binary), "sha256": sha(binary),
                                                        "bytes": binary.stat().st_size}
        run(["python3", "-B", "tests/test_i486_instruction_gate.py"], "i486-parser-controls")
        run(["python3", "-B", "tests/test_tls13_i486_startup.py"], "startup-controls")
        result["owned_server_startup_controls"] = {"passed": True, "log": str(out / "startup-controls.log"),
            "sha256": sha(out / "startup-controls.log"), "deadline_seconds": 5, "line_limit_bytes": 64,
            "scope": "owned pipe children only; no network/native claim"}
        # Independent full response bytes strengthen the unchanged host probe's
        # original status-line oracle. The original test file stays immutable.
        client_source = (ROOT / "tests/m98_tls13_host.c").read_text()
        old_break = "if (got > 12 && memchr(response, '\\n', got)) break;"
        old_oracle = 'ok = got >= 12 && !memcmp(response, "HTTP/1.0 200", 12);'
        expected_response = '"HTTP/1.0 200 OK\\r\\nContent-Length: 21\\r\\n\\r\\nlatest-LTS-TLS13-ok!\\n"'
        need(client_source.count(old_break) == 1 and client_source.count(old_oracle) == 1,
             "exact frozen host client oracle anchors")
        client_source = client_source.replace(old_break, f'if (got == sizeof({expected_response}) - 1) break;')
        client_source = client_source.replace(old_oracle,
            f'ok = got == sizeof({expected_response}) - 1 && !memcmp(response, {expected_response}, got);')
        prepared_client = out / "host-client-full-response.c"
        prepared_client.write_text(client_source)
        result["host_full_response_oracle"] = {"source": str(prepared_client), "sha256": sha(prepared_client),
            "original_source_sha256": own_pins["tests/m98_tls13_host.c"],
            "scope": "exact independent 60-byte encrypted HTTP response; no application/native/OS claim"}
        latest_tree, latest_original, latest_aliases = unpack(LATEST_ARCHIVE, LATEST_SHA, out / "original/latest")
        lts_tree, lts_original, lts_aliases = unpack(LTS_ARCHIVE, LTS_SHA, out / "original/lts")
        originals = latest_original | lts_original
        aliases = latest_aliases | lts_aliases
        alias_pin = out / "original-source-aliases.json"
        alias_pin.write_text(json.dumps(aliases, indent=2) + "\n")
        result["original_alias_metadata"] = {"path": str(alias_pin), "sha256": sha(alias_pin), "aliases": len(aliases)}
        lts = out / "original/lts-adapter"; lts.mkdir()
        for name in LTS_ADAPTER:
            shutil.copyfile(LTS_ROOT / "project" / name, lts / name)
            need(sha(lts / name) == lts_pins[name], "LTS copied original drift")
            originals[str(lts / name)] = lts_pins[name]
        original_pin = out / "original-source-pins.json"
        original_pin.write_text(json.dumps(originals, indent=2) + "\n")
        result["original_source_pins"] = {"path": str(original_pin), "sha256": sha(original_pin), "files": len(originals)}
        result["profiles"] = {}
        # Config extensions use upstream's documented platform hooks. No byte
        # patch or change to original cryptographic/TLS source is made.
        common_config = '''
#undef MBEDTLS_HAVE_ASM
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_PADLOCK_C
#undef MBEDTLS_HAVE_SSE2
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_ALT
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_PLATFORM_SNPRINTF_MACRO
#undef MBEDTLS_PLATFORM_VSNPRINTF_MACRO
#include "m98_tls_i486_format.h"
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO m98_tls_i486_snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO m98_tls_i486_vsnprintf
'''
        for flavor, tree in (("latest", latest_tree), ("lts", lts_tree)):
            project = out / (flavor + "-project"); project.mkdir()
            config = project / "port_config.h"
            original_config = ROOT / "src/m98_tls13_config.h" if flavor == "latest" else lts / "user_config.h"
            config.write_text('#include "' + str(original_config) + '"\n' + common_config)
            for native in (False, True):
                profile = flavor + ("-native" if native else "-host")
                build = out / profile
                library = "M98TLS13" if flavor == "latest" else "M98TLS"
                adapter = ROOT / "src/m98_tls13.c" if flavor == "latest" else lts / "transport.c"
                dependencies = "mbedtls mbedx509 tfpsacrypto" if flavor == "latest" else "mbedtls mbedx509 mbedcrypto"
                config_setup = (f'set(MBEDTLS_USER_CONFIG_FILE "{ROOT / "src/m98_tls13_protocol_config.h"}" CACHE FILEPATH "" FORCE)\n'
                                f'set(TF_PSA_CRYPTO_USER_CONFIG_FILE "{config}" CACHE FILEPATH "" FORCE)') if flavor == "latest" else f'add_compile_definitions(MBEDTLS_USER_CONFIG_FILE="{config}")'
                sources = f'"{adapter}" "{ROOT / "src/m98_tls_i486_format.c"}"'
                if native and flavor == "lts":
                    sources += f' "{lts / "native_time.c"}" "{lts / "native_runtime.c"}" "{lts / "native_crt.c"}" "{lts / "native.def"}"'
                elif native:
                    sources += f' "{ROOT / "src/m98_tls13.def"}"'
                body = f'''cmake_minimum_required(VERSION 3.16)
project(TLS_i486_port C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
{config_setup}
include_directories("{ROOT / "src"}" "{lts}")
add_subdirectory("{tree}" upstream)
add_library({library} {"SHARED" if native else "STATIC"} {sources})
target_link_libraries({library} PRIVATE {dependencies})
set_target_properties({library} PROPERTIES PREFIX "" OUTPUT_NAME "{library}")
'''
                if native:
                    entry = "_m98_tls_dll_entry@12" if flavor == "latest" else "_DllMainCRTStartup@12"
                    if flavor == "lts":
                        body += f'target_compile_definitions({library} PRIVATE NTWST_DLL_STARTUP=1)\n'
                    body += f'target_link_options({library} PRIVATE -nostdlib -Wl,--entry,{entry},--gc-sections,--subsystem,windows:4.10,--major-os-version,4,--minor-os-version,10,--disable-dynamicbase,--disable-nxcompat,--disable-tsaware,--no-insert-timestamp "SHELL:-Xlinker --stack -Xlinker 2097152,65536")\n'
                    body += f'target_link_libraries({library} PRIVATE msvcrt kernel32 {"advapi32" if flavor == "lts" else ""} gcc)\n'
                else:
                    test = prepared_client if flavor == "latest" else ROOT / "tests/m98_tls13_lts_loopback_server.c"
                    body += f'add_executable(host_probe "{test}" "{ROOT / "src/m98_tls_i486_format.c"}")\ntarget_link_libraries(host_probe PRIVATE {library} {dependencies})\n'
                # Use a distinct project per target, avoiding mutation of prior
                # configure inputs between the Windows and host builds.
                target_project = out / (profile + "-project"); target_project.mkdir()
                (target_project / "CMakeLists.txt").write_text(body)
                flags = BASE_FLAGS + ((" " + CPU_FLAGS + " -D_WIN32_WINNT=0x0400 -DWINVER=0x0410 -D_WIN32_WINDOWS=0x0410") if native else "")
                configure = ["cmake", "-S", target_project, "-B", build, "-G", "Ninja",
                             "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_FLAGS=" + flags,
                             "-DCMAKE_C_FLAGS_RELEASE=-Os -DNDEBUG"]
                if native:
                    configure += ["-DCMAKE_SYSTEM_NAME=Windows", "-DCMAKE_C_COMPILER=i686-w64-mingw32-gcc"]
                run(configure, profile + "-configure")
                entries = json.loads((build / "compile_commands.json").read_text())
                groups, active_uses, actual_unit_macros = {}, [], []
                for number, entry in enumerate(entries):
                    compiler_flags = command_flags(entry)
                    if native:
                        need([x for x in compiler_flags if x.startswith("-march=")] == ["-march=i486"] and
                             [x for x in compiler_flags if x.startswith("-mtune=")] == ["-mtune=i486"] and
                             [x for x in compiler_flags if x in {"-fisolate-erroneous-paths-dereference",
                                  "-fno-isolate-erroneous-paths-dereference"}] == ["-fno-isolate-erroneous-paths-dereference"] and
                             all(x in compiler_flags for x in CPU_FLAGS.split()), "every actual native translation-unit CPU contract")
                    groups.setdefault(tuple(compiler_flags), []).append(entry["file"])
                    preprocessed = run([*compiler_flags, "-E", "-P", entry["file"]], profile + f"-format-{number}")
                    unit_uses = format_uses(preprocessed.decode())
                    for use in unit_uses:
                        active_uses.append({"translation_unit": entry["file"], **use})
                    actual_macros = run([*compiler_flags, "-E", "-dM", entry["file"]], profile + f"-unit-macros-{number}")
                    values = {m[0]: m[1].strip() for m in re.findall(rb"^#define (\w+)[ \t]*(.*)$", actual_macros, re.M)}
                    actual_exact = {b"__USE_MINGW_ANSI_STDIO": b"0"}
                    actual_forbidden = set()
                    config_assertion_unit = flavor == "latest" and Path(entry["file"]) == tree / "library/mbedtls_config.c"
                    if native:
                        actual_exact[b"__i486__"] = b"1"
                        actual_forbidden |= {b"__i686__", b"__SSE__", b"__SSE2__", b"__MMX__"}
                    if b"MBEDTLS_PLATFORM_C" in values:
                        # This exact upstream assertion-only TU undefines then
                        # restores presence macros empty for configuration checks.
                        # No formatter call is permitted in this narrow context.
                        if config_assertion_unit:
                            need(not unit_uses, "upstream config assertion TU gained format calls")
                        actual_exact |= {b"MBEDTLS_PLATFORM_SNPRINTF_MACRO": b"" if config_assertion_unit else b"m98_tls_i486_snprintf",
                                         b"MBEDTLS_PLATFORM_VSNPRINTF_MACRO": b"" if config_assertion_unit else b"m98_tls_i486_vsnprintf"}
                        actual_forbidden |= {b"MBEDTLS_HAVE_ASM", b"MBEDTLS_AESNI_C", b"MBEDTLS_PADLOCK_C",
                                             b"MBEDTLS_HAVE_SSE2", b"MBEDTLS_SELF_TEST", b"MBEDTLS_DEBUG_C"}
                        need(b"MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG" in values, "actual TU external RNG configuration")
                    need(all(values.get(n) == v for n, v in actual_exact.items()) and not actual_forbidden & values.keys(),
                         "actual translation-unit macro values")
                    actual_unit_macros.append({"translation_unit": entry["file"],
                        "actual_dump_log": str(out / (profile + f"-unit-macros-{number}.log")),
                        "exact_macro_values": {n.decode(): v.decode() for n, v in actual_exact.items()},
                        "mbedtls_platform_in_actual_unit": b"MBEDTLS_PLATFORM_C" in values,
                        "upstream_assertion_terminal_presence_only": config_assertion_unit,
                        "forbidden_absent": sorted(n.decode() for n in actual_forbidden)})
                macro_groups = []
                for number, (compiler_flags, units) in enumerate(groups.items()):
                    header = tree / "include/mbedtls/build_info.h"
                    if flavor == "latest" and not any(x.startswith("-DMBEDTLS_USER_CONFIG_FILE=") for x in compiler_flags):
                        header = tree / "tf-psa-crypto/include/tf-psa-crypto/build_info.h"
                    probe = build / f"effective-{number}.c"; probe.write_text('#include "' + str(header) + '"\n')
                    macros_text = run([*compiler_flags, "-E", "-dM", "-x", "c", probe], profile + f"-effective-{number}")
                    macro_values = {m[0]: m[1].strip() for m in re.findall(rb"^#define (\w+)[ \t]*(.*)$", macros_text, re.M)}
                    macros = set(macro_values)
                    required = {b"MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG", b"MBEDTLS_PLATFORM_C"}
                    forbidden = {b"MBEDTLS_HAVE_ASM", b"MBEDTLS_AESNI_C", b"MBEDTLS_PADLOCK_C", b"MBEDTLS_HAVE_SSE2", b"MBEDTLS_SELF_TEST", b"MBEDTLS_DEBUG_C", b"MBEDTLS_THREADING_C", b"MBEDTLS_FS_IO", b"MBEDTLS_NET_C", b"MBEDTLS_PSA_ITS_FILE_C"}
                    if flavor == "lts" or any(x.startswith("-DMBEDTLS_USER_CONFIG_FILE=") for x in compiler_flags):
                        required |= {b"MBEDTLS_SSL_PROTO_TLS1_3", b"MBEDTLS_SSL_CLI_C", b"MBEDTLS_X509_CRT_PARSE_C", b"MBEDTLS_HAVE_TIME", b"MBEDTLS_HAVE_TIME_DATE"}
                        if flavor == "latest":
                            forbidden |= {b"MBEDTLS_SSL_PROTO_TLS1_2", b"MBEDTLS_SSL_PROTO_DTLS", b"MBEDTLS_SSL_SRV_C", b"MBEDTLS_SSL_SESSION_TICKETS", b"MBEDTLS_SSL_EARLY_DATA"}
                        else:
                            required |= {b"MBEDTLS_SSL_SRV_C"}
                    if flavor == "latest":
                        forbidden |= {b"MBEDTLS_PSA_BUILTIN_GET_ENTROPY", b"MBEDTLS_PSA_DRIVER_GET_ENTROPY"}
                    if native:
                        required |= {b"__i486__"}
                        forbidden |= {b"__i686__", b"__SSE__", b"__SSE2__", b"__MMX__"}
                    need(required <= macros and not forbidden & macros, "actual effective config/CPU macros")
                    exact = {b"MBEDTLS_PLATFORM_SNPRINTF_MACRO": b"m98_tls_i486_snprintf",
                             b"MBEDTLS_PLATFORM_VSNPRINTF_MACRO": b"m98_tls_i486_vsnprintf",
                             b"__USE_MINGW_ANSI_STDIO": b"0"}
                    if native:
                        exact[b"__i486__"] = b"1"
                    need(all(macro_values.get(n) == value for n, value in exact.items()),
                         "actual formatter/ANSI/i486 macro values")
                    macro_groups.append({"translation_units": units, "required": sorted(x.decode() for x in required),
                        "required_values": {n.decode(): macro_values[n].decode() for n in required},
                        "exact_macro_values": {n.decode(): v.decode() for n, v in exact.items()},
                        "forbidden_absent": sorted(x.decode() for x in forbidden)})
                inventory_path = out / (profile + "-actual-format-uses.json")
                inventory_path.write_text(json.dumps({"scope": "every actual configured translation unit, preprocessed",
                    "uses": active_uses, "dynamic_policy": "only resolved m98_tls_i486_* calls use bounded parser; other families unproven",
                    "floating_wide_percent_n": "explicitly unsupported"}, indent=2) + "\n")
                routed = [u for u in active_uses if u["function"] in {"m98_tls_i486_snprintf", "m98_tls_i486_vsnprintf"}]
                need(not any(u.get("unsupported") for u in routed), "unsupported active constant TLS formatter call")
                run(["cmake", "--build", build, "--parallel", str(args.jobs)], profile + "-build")
                record = {"translation_units": len(entries), "compiler_database_sha256": sha(build / "compile_commands.json"),
                          "effective_configuration": macro_groups, "format_inventory": {"path": str(inventory_path), "sha256": sha(inventory_path), "uses": len(active_uses)}}
                record["actual_translation_unit_macro_checks"] = actual_unit_macros
                if native:
                    artifact = build / (library + ".dll")
                    pe = native_gate(artifact, CLIENT_EXPORTS if flavor == "latest" else SERVER_EXPORTS)
                    record.update(artifact=str(artifact), sha256=sha(artifact), bytes=artifact.stat().st_size, pe=pe)
                    result["profiles"][profile] = record
                    try:
                        machine, listing = scan(artifact)
                    except Exception:
                        # Retain the actual entire failed artifact decode while
                        # preserving the common scanner's fail-closed decision.
                        name = profile + "-failed-full-byte-disassembly"
                        run(["i686-w64-mingw32-objdump", "-d", "-z", "--show-raw-insn", "--insn-width=16", artifact], name, timeout=60)
                        record["failed_disassembly_log"] = str(out / (name + ".log"))
                        record["failed_disassembly_sha256"] = sha(out / (name + ".log"))
                        raise
                    log = out / (profile + "-full-byte-disassembly.log"); log.write_bytes(listing)
                    record.update(artifact=str(artifact), sha256=sha(artifact), bytes=artifact.stat().st_size,
                                  pe=pe, i486=machine, disassembly_log=str(log), disassembly_sha256=sha(log))
                else:
                    record.update(host_probe=str(build / "host_probe"), sha256=sha(build / "host_probe"))
                result["profiles"][profile] = record
                print(profile + ": source build and bounded inventory complete", flush=True)
        raw_uses = []
        for tree in (latest_tree, lts_tree):
            for file in sorted(tree.rglob("*")):
                if file.is_file() and not file.is_symlink() and file.suffix in {".c", ".h"}:
                    for use in format_uses(file.read_text(errors="strict")):
                        raw_uses.append({"file": str(file), **use})
        raw = out / "all-upstream-raw-format-uses.json"
        raw.write_text(json.dumps({"scope": "all original archive C/header files, including excluded tests/programs/configs",
            "uses": raw_uses, "not_selected_unsupported_forms": "retained and explicitly inventoried; no complete CRT claim"}, indent=2) + "\n")
        result["all_upstream_format_inventory"] = {"path": str(raw), "sha256": sha(raw), "uses": len(raw_uses)}
        host_interop(out, result)
        generated = {}
        for file in sorted(out.glob("*-project/*")):
            if file.is_file():
                generated[str(file)] = sha(file)
        for build in result["profiles"]:
            for file in sorted((out / build).glob("effective-*.c")):
                generated[str(file)] = sha(file)
        result["generated_recipe_sha256"] = generated
        result["original_dependency_pins"] = {"latest_version": "4.2.0", "tf_psa_crypto_version": "1.2.0",
             "latest_archive_sha256": LATEST_SHA, "lts_version": "3.6.7", "lts_archive_sha256": LTS_SHA,
             "license_selected": "GPL-2.0-or-later (GPL version 2)", "no_downloads": True}
        compatibility_receipts(out, result)
        need(all(sha(Path(p)) == h for p, h in originals.items()), "original source mutation during build")
        need(all(Path(p).is_symlink() and os.readlink(p) == item["target"] and
                 Path(p).resolve(strict=True) == Path(p).parent.joinpath(item["target"]).resolve(strict=True)
                 for p, item in aliases.items()), "original archive alias mutation during build")
        need(own_pins == {n: sha(ROOT / n) for n in OWN} and lts_pins == {n: sha(LTS_ROOT / "project" / n) for n in LTS_ADAPTER}, "input source drift")
        need(all(sha(Path(p)) == h for p, h in result["input_authorities"].items()), "input authority drift")
        result["passed"] = True
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(out / "result.json")


if __name__ == "__main__":
    main()
