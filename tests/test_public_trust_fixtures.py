#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Public certificate packaging retains actual signature and identity checks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import ssl
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("public_fixtures", ROOT / "shizukudos/win64/tools/public_trust_fixtures.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicTrust(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "fixtures"
        shutil.copytree(MODULE.FIXTURES, self.directory)

    def test_actual_pinned_public_chain_and_complete_archive_bytes(self):
        files, receipt = MODULE.load_fixtures(self.directory)
        self.assertTrue(receipt["host_chain_verified"])
        self.assertFalse(receipt["guest_chain_verified"])
        self.assertFalse(receipt["host_trust_modified"])
        self.assertFalse(receipt["tls_verification_disabled"])
        roots = dict(files)["\\SHZ\\CERTS\\ROOTS.BIN"]
        self.assertEqual(roots[:8], b"SHZCA001")
        version, count = struct.unpack_from("<II", roots, 8)
        self.assertEqual((version, count), (1, 146))
        offset = 16
        actual = []
        for _ in range(count):
            size = struct.unpack_from("<I", roots, offset)[0]
            offset += 4
            actual.append(roots[offset:offset + size])
            offset += size
        self.assertEqual(offset, len(roots))
        self.assertEqual(actual, MODULE.certificates((self.directory / "ca-bundle.pem").read_bytes()))
        self.assertEqual(len(files), 4)

    def test_changed_certificate_is_refused_before_packaging(self):
        leaf = self.directory / "server-0.pem"
        leaf.write_bytes(leaf.read_bytes() + b"changed source\n")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            MODULE.load_fixtures(self.directory)

    def test_matching_repin_cannot_hide_tampered_signature(self):
        leaf = self.directory / "server-0.pem"
        der = bytearray(MODULE.certificates(leaf.read_bytes())[0])
        der[-1] ^= 1
        leaf.write_text(ssl.DER_cert_to_PEM_cert(bytes(der)))
        path = self.directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["files"][leaf.name] = {"bytes": leaf.stat().st_size,
                                      "sha256": hashlib.sha256(leaf.read_bytes()).hexdigest(),
                                      "der_sha256": hashlib.sha256(der).hexdigest()}
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "ordinary verification"):
            MODULE.load_fixtures(self.directory)

    def test_private_keys_and_manifest_path_changes_are_refused(self):
        with self.assertRaisesRegex(ValueError, "only public"):
            MODULE.certificates(b"-----BEGIN PRIVATE KEY-----\n")
        path = self.directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["files"]["../outside.pem"] = manifest["files"].pop("server-0.pem")
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "exact public"):
            MODULE.load_fixtures(self.directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
