#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify frozen source, build and DOS handoff evidence; never executes a guest."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES = {
    "zero_size_random_has_no_os_call", "valid_bidirectional_payload_and_close",
    "wrong_host_rejected", "untrusted_ca_rejected", "expired_certificate_rejected",
    "partial_write_and_truncation", "tls12_only_peer_rejected",
    "os_random_failure_during_handshake", "modified_ciphertext_rejected",
    "record_boundary_eof_rejected", "failed_os_random_rejected",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receipt(path, expected, target):
    require(sha(path) == expected, "Receipt differs from frozen SHA256")
    data = json.loads(path.read_text())
    require(data["schema"] == "win98modern.secure-transport-build.v1" and
            data["status"] == "PASS" and data["target"] == target,
            "Wrong receipt type, target or build status")
    for name, digest in data["source_sha256"].items():
        source = HERE / name
        require(source.resolve().is_relative_to(HERE), "Source path escapes adapter")
        require(sha(source) == digest, "Compiled source changed: " + name)
    for field in ("native_guest_verified", "system_schannel_verified",
                  "application_functionality_verified"):
        require(data[field] is False, "Unexpected guest/system/app completion claim")
    return data


def artifact(row, build):
    path = Path(row["path"]).resolve()
    require(path.is_relative_to(build.resolve()), "Artifact escapes private build")
    require(path.stat().st_size == row["bytes"] and sha(path) == row["sha256"],
            "Artifact differs from build receipt")
    return path


def verify(args):
    import pefile
    host_path = args.host_build / "build-result.json"
    native_path = args.native_build / "build-result.json"
    host = receipt(host_path, args.host_sha256, "host")
    native = receipt(native_path, args.native_sha256, "win98-x86")
    artifact(host["binary"], args.host_build)
    log = args.host_build / "probe.log"
    require(host["host_probe_passed"] is True and
            sha(log) == host["host_probe_log_sha256"], "Host log differs from receipt")
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    cases = [row for row in rows if row.get("case") in CASES]
    require(len(cases) == len(CASES) and {row["case"] for row in cases} == CASES,
            "Host log lacks the exact unique protocol cases")
    require(all(row["passed"] is True for row in cases) and rows[-1]["passed"] is True,
            "Host protocol check failed")
    nonce = "host-" + host["binary"]["sha256"][:16]
    require(all(row["nonce"] == nonce for row in rows), "Host log nonce mismatch")
    require(rows[0].get("platform") == "linux-host-build", "Wrong host execution domain")
    baseline_path = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    baseline = json.loads(baseline_path.read_text())["dlls"]
    for name, row, audit in (
            ("probe", native["binary"], native["pe_audit"]),
            ("clock", native["clock_probe"], native["clock_probe"]["pe_audit"]),
            ("library", native["native_library"], native["native_library"]["pe_audit"])):
        path = artifact(row, args.native_build)
        require(audit["static_gate_passed"] is True and
                audit["baseline_sha256"] == sha(baseline_path), "Static receipt gate failed")
        pe = pefile.PE(str(path))
        require(pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.Magic == 0x10b,
                "Expected PE32/i386")
        require([pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                 pe.OPTIONAL_HEADER.MinorSubsystemVersion] <= [4, 10], "New subsystem version")
        require(all(not pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress and
                    not pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size for i in (9, 10, 13, 14)),
                "Unexpected PE static TLS/load-config/delay/CLR directory")
        require(bool(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])), "Missing import table")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii").upper()
            for imported in entry.imports:
                symbol = imported.name.decode("ascii") if imported.name else "#" + str(imported.ordinal)
                require(symbol in baseline.get(dll, []), "Import absent from original Win98 OEM")
        if name == "library":
            symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
            require(all(entry.name and not entry.forwarder for entry in symbols),
                    "Unnamed or forwarded DLL export")
            exports = {entry.name.decode() for entry in symbols}
            expected = {line.strip() for line in (HERE / "native.def").read_text().splitlines()[2:]}
            require(exports == expected and len(symbols) == len(expected), "Unexpected DLL exports")
            relocations = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
            require(bool(relocations.VirtualAddress and relocations.Size) and
                    not pe.FILE_HEADER.Characteristics & 1 and
                    any(entry.type == 3 for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
                        for entry in block.entries), "DLL lacks usable x86 relocations")
    manifest = json.loads(args.staged.read_text())
    require(manifest["kind"] == "isolated-guest-file-inputs" and len(manifest["inputs"]) == 8,
            "Wrong handoff type or input count")
    expected_inputs = {r"C:\GOPLAB\TLS13PRB.EXE": native["binary"]["sha256"]}
    for filename, guest in (("server.pem", "SRV.PEM"), ("server.key", "SRV.KEY"),
                            ("ca.pem", "CA.PEM"), ("other-ca.pem", "BADCA.PEM"),
                            ("expired.pem", "EXP.PEM"), ("expired.key", "EXP.KEY")):
        expected_inputs["C:\\GOPLAB\\" + guest] = native["fixtures"][filename]
    expected_guests = set(expected_inputs) | {r"C:\GOPLAB\TLSRUN.BAT"}
    require({row["guest"] for row in manifest["inputs"]} == expected_guests,
            "Missing, duplicate or unexpected guest input")
    for row in manifest["inputs"]:
        path = Path(row["source"]).resolve()
        require(path.is_relative_to(args.staged.parent.resolve()), "Staged input escapes handoff")
        require(re.fullmatch(r"C:\\GOPLAB\\[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}", row["guest"]),
                "Guest input lacks an explicit DOS 8.3 name")
        require(0 < path.stat().st_size == row["bytes"] <= 1024 ** 2 and
                sha(path) == row["sha256"], "Staged input hash/size differs")
        if row["guest"] in expected_inputs:
            require(row["sha256"] == expected_inputs[row["guest"]],
                    "Staged input differs from frozen native build")
    require(manifest["outputs"] == [r"C:\GOPLAB\TLS13.LOG", r"C:\GOPLAB\TLSRET.LOG"] and
            manifest["command"] == r"C:\GOPLAB\TLSRUN.BAT" and manifest["backups"] == [],
            "Unexpected guest outputs, command or backup operation")
    retained = manifest["source_receipts"]
    require(len(retained) == 1 and retained[0]["sha256"] == args.native_sha256 and
            Path(retained[0]["path"]).resolve().is_relative_to(args.staged.parent.resolve()) and
            sha(Path(retained[0]["path"])) == args.native_sha256, "Handoff build receipt mismatch")
    require(manifest["guest_execution"] == "NOT-VERIFIED" and
            manifest["network_required"] is False, "Unexpected handoff execution/network claim")
    batch = (args.staged.parent / "TLSRUN.BAT").read_bytes()
    nonce = manifest["nonce"]
    require(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", nonce), "Invalid guest nonce")
    command = ("TLS13PRB.EXE --server-cert SRV.PEM --server-key SRV.KEY --ca CA.PEM "
               "--untrusted-ca BADCA.PEM --expired-cert EXP.PEM --expired-key EXP.KEY "
               "--output TLS13.LOG --nonce " + nonce)
    expected_batch = ("@echo off\r\nC:\r\ncd \\GOPLAB\r\n" + command +
        "\r\nif errorlevel 1 goto failed\r\necho exit_nonzero=0>TLSRET.LOG\r\n"
        "goto end\r\n:failed\r\necho exit_nonzero=1>TLSRET.LOG\r\n:end\r\n").encode("ascii")
    require(batch == expected_batch, "Unexpected launcher, nonce or exit observation")
    require(all(len(line) <= 254 for line in batch.split(b"\r\n")), "Long COMMAND.COM line")
    return {"status": "PASS", "scope": "Frozen build/static/handoff evidence only",
            "host_protocol_checks": len(cases), "native_pe_artifacts": 3,
            "dll_exports": len(exports), "dll_relocations": True, "guest_83_inputs": 8,
            "host_receipt_sha256": sha(host_path), "native_receipt_sha256": sha(native_path),
            "manifest_sha256": sha(args.staged), "verifier_sha256": sha(Path(__file__)),
            "native_guest_verified": False, "system_schannel_verified": False,
            "application_functionality_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-build", type=Path, required=True)
    parser.add_argument("--host-sha256", required=True)
    parser.add_argument("--native-build", type=Path, required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--staged", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args)))


if __name__ == "__main__":
    main()
