#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare digest-bound offline TLS test files; never starts or modifies a VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(build, receipt_sha, output, nonce):
    build, output = build.resolve(), output.absolute()
    receipt = build / "build-result.json"
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be a new private directory")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", nonce):
        raise ValueError("Require a bounded fresh nonce")
    if sha(receipt) != receipt_sha:
        raise ValueError("Native build receipt differs from frozen hash")
    data = json.loads(receipt.read_text())
    if (data.get("schema") != "win98modern.secure-transport-build.v1" or
            data.get("status") != "PASS" or data.get("target") != "win98-x86" or
            not data.get("pe_audit", {}).get("static_gate_passed") or
            data.get("native_guest_verified") is not False):
        raise ValueError("Require the native build-only PASS receipt")
    binary = Path(data["binary"]["path"]).resolve()
    if not binary.is_relative_to(build) or sha(binary) != data["binary"]["sha256"]:
        raise ValueError("Native executable differs from frozen build")
    entries = [(binary, "TLS13PRB.EXE", data["binary"]["sha256"])]
    for original, guest in (("server.pem", "SRV.PEM"), ("server.key", "SRV.KEY"),
                            ("ca.pem", "CA.PEM"), ("other-ca.pem", "BADCA.PEM"),
                            ("expired.pem", "EXP.PEM"), ("expired.key", "EXP.KEY")):
        source = build / "fixtures" / original
        expected = data["fixtures"][original]
        if sha(source) != expected:
            raise ValueError("Certificate fixture differs from frozen build")
        entries.append((source, guest, expected))
    command = ("TLS13PRB.EXE --server-cert SRV.PEM --server-key SRV.KEY --ca CA.PEM "
               "--untrusted-ca BADCA.PEM --expired-cert EXP.PEM --expired-key EXP.KEY "
               "--output TLS13.LOG --nonce " + nonce)
    if len(command) > 254:
        raise ValueError("COMMAND.COM line exceeds the selected bound")
    for source, name, expected in entries:
        if not re.fullmatch(r"[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}", name):
            raise ValueError("Guest input must use an explicit DOS 8.3 name")
        if not 0 < source.stat().st_size <= 1024 ** 2:
            raise ValueError("Guest input size gate failed")
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for source, name, expected in entries:
        dest = output / name
        shutil.copyfile(source, dest)
        dest.chmod(0o600)
        if sha(dest) != expected or not 0 < dest.stat().st_size <= 1024 ** 2:
            raise ValueError("Copied input hash/size gate failed")
        inputs.append({"source": str(dest.resolve()), "guest": "C:\\GOPLAB\\" + name,
                       "bytes": dest.stat().st_size, "sha256": expected})
    batch = output / "TLSRUN.BAT"
    batch.write_bytes(("@echo off\r\nC:\r\ncd \\GOPLAB\r\n" + command +
        "\r\nif errorlevel 1 goto failed\r\necho exit_nonzero=0>TLSRET.LOG\r\n"
        "goto end\r\n:failed\r\necho exit_nonzero=1>TLSRET.LOG\r\n:end\r\n").encode("ascii"))
    inputs.append({"source": str(batch.resolve()), "guest": r"C:\GOPLAB\TLSRUN.BAT",
                   "bytes": batch.stat().st_size, "sha256": sha(batch)})
    retained = output / "build-result.json"
    retained.write_bytes(receipt.read_bytes())
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": [r"C:\GOPLAB\TLS13.LOG", r"C:\GOPLAB\TLSRET.LOG"],
                "backups": [], "source_receipts": [{"path": str(retained.resolve()), "sha256": sha(retained)}],
                "nonce": nonce, "command": r"C:\GOPLAB\TLSRUN.BAT",
                "guest_execution": "NOT-VERIFIED", "network_required": False,
                "scope": "Offline real TLS1.3 protocol/cert/RNG fixture only; no socket, Schannel or app acceptance.",
                "exit_evidence": "Batch observes zero vs nonzero; exact exit and CRT teardown require an outer observer."}
    manifest_path = output / "guest-files.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return {"manifest": str(manifest_path), "sha256": sha(manifest_path),
            "inputs": len(inputs), "bytes": sum(row["bytes"] for row in inputs),
            "nonce": nonce, "guest_execution": "NOT-VERIFIED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args.build, args.receipt_sha256, args.output, args.nonce)))


if __name__ == "__main__":
    main()
