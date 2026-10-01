#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pack pinned public CA/chain inputs for the real guest CryptoAPI regression.

This reads public certificates and validates their ordinary host chain. It changes
neither host trust nor TLS policy. Guest verification must still run separately.
"""
import hashlib
import json
from pathlib import Path
import re
import ssl
import struct
import subprocess
import tempfile

FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/public-trust"


def certificates(data):
    if b"PRIVATE KEY" in data:
        raise ValueError("only public certificate inputs are accepted")
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
    result = [ssl.PEM_cert_to_DER_cert(block.decode("ascii")) for block in blocks]
    if not result or len(result) > 512 or any(not 1 <= len(item) <= 65536 for item in result):
        raise ValueError("bounded public certificate inputs required")
    return result


def load_fixtures(directory=FIXTURES):
    directory = Path(directory)
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    expected = {"ca-bundle.pem", "server-0.pem", "server-1.pem", "server-2.pem"}
    if (manifest.get("schema") != "shizuku-public-trust-fixtures/1" or
            manifest.get("server_hostname") != "client-update.steamstatic.com" or
            manifest.get("server_certificates") != 3 or set(manifest.get("files", {})) != expected):
        raise ValueError("exact public trust fixture manifest required")
    data = {}
    for name, pin in manifest["files"].items():
        value = (directory / name).read_bytes()
        if len(value) != pin["bytes"] or hashlib.sha256(value).hexdigest() != pin["sha256"]:
            raise ValueError("public trust fixture identity changed: " + name)
        data[name] = value
    anchors = certificates(data["ca-bundle.pem"])
    identities = [{"index": i, "sha256": hashlib.sha256(item).hexdigest(), "bytes": len(item)}
                  for i, item in enumerate(anchors)]
    if identities != manifest["anchors"]:
        raise ValueError("public anchor identities changed")
    server = []
    for i in range(3):
        name = f"server-{i}.pem"
        values = certificates(data[name])
        if len(values) != 1 or hashlib.sha256(values[0]).hexdigest() != manifest["files"][name]["der_sha256"]:
            raise ValueError("public server DER identity changed")
        server.append(values[0])
    with tempfile.TemporaryDirectory(prefix="shz-public-chain-") as temporary:
        work = Path(temporary)
        (work / "ca.pem").write_bytes(data["ca-bundle.pem"])
        (work / "leaf.pem").write_bytes(data["server-0.pem"])
        (work / "support.pem").write_bytes(data["server-1.pem"] + data["server-2.pem"])
        check = subprocess.run(["openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", str(work / "ca.pem"),
                                "-untrusted", str(work / "support.pem"), "-verify_hostname", manifest["server_hostname"],
                                str(work / "leaf.pem")], capture_output=True, text=True, timeout=30)
        if check.returncode:
            raise ValueError("captured public chain failed ordinary verification; refresh expired inputs: " + check.stderr)
    if (directory / "manifest.json").read_bytes() != manifest_bytes or any((directory / name).read_bytes() != value for name, value in data.items()):
        raise ValueError("public certificate inputs changed during packaging")
    roots = b"SHZCA001" + struct.pack("<II", 1, len(anchors))
    roots += b"".join(struct.pack("<I", len(item)) + item for item in anchors)
    files = [("\\SHZ\\CERTS\\ROOTS.BIN", roots)]
    files += [(f"\\SHZ\\CERTS\\SERVER{i}.CER", item) for i, item in enumerate(server)]
    receipt = {"manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "public_anchor_count": len(anchors),
               "captured_utc": manifest["captured_utc"], "host_chain_verified": True, "guest_chain_verified": False,
               "host_trust_modified": False, "tls_verification_disabled": False,
               "files": {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()} for name, value in files}}
    return files, receipt
