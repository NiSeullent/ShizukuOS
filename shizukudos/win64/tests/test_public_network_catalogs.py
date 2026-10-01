# SPDX-License-Identifier: GPL-2.0-only
"""Offline public-source pin and packaging contracts; no guest or networking."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("public_network_catalogs", HERE / "tools/public_network_catalogs.py")
PUBLIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLIC)


class PublicNetworkCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shz-public-netdb-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "catalogs"
        shutil.copytree(PUBLIC.CATALOGS, self.directory)

    def rewrite_manifest(self, change):
        path = self.directory / "manifest.json"
        manifest = json.loads(path.read_text())
        change(manifest)
        path.write_text(json.dumps(manifest))

    def repin(self, name):
        data = (self.directory / name).read_bytes()
        self.rewrite_manifest(lambda m: m["files"][name].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))

    def test_real_public_sources_and_license_ship_byte_exact(self):
        files, receipt = PUBLIC.load_catalogs(self.directory)
        members = dict(files)
        self.assertEqual(len(members), 5)
        for name in ("services", "protocols", "hosts"):
            self.assertEqual(members[PUBLIC.GUEST_DIRECTORY + name.upper()], (PUBLIC.CATALOGS / (name + ".txt")).read_bytes())
        self.assertIn(b"License: GPL-2", members[PUBLIC.GUEST_DIRECTORY + "NETBASE-COPYRIGHT.TXT"])
        self.assertIn(b"GNU GENERAL PUBLIC LICENSE", members[PUBLIC.GUEST_DIRECTORY + "NETBASE-GPL2.TXT"])
        self.assertFalse(receipt["host_configuration_read"])
        self.assertFalse(receipt["network_access"])
        self.assertFalse(receipt["guest_Winsock_verified"])
        for name, data in files:
            self.assertEqual(receipt["files"][name]["sha256"], hashlib.sha256(data).hexdigest())

    def test_missing_catalog_is_fatal(self):
        (self.directory / "protocols.txt").unlink()
        with self.assertRaises(FileNotFoundError): PUBLIC.load_catalogs(self.directory)

    def test_content_and_size_drift_refused(self):
        for name in ("services.txt", "protocols.txt", "hosts.txt", "GPL-2.txt"):
            with self.subTest(name=name):
                p = self.directory / name; original = p.read_bytes()
                p.write_bytes(original + b"# altered\n")
                with self.assertRaises(ValueError): PUBLIC.load_catalogs(self.directory)
                p.write_bytes(original)

    def test_updated_local_pin_cannot_inject_catalog_records(self):
        name = "services.txt"
        (self.directory / name).write_bytes((self.directory / name).read_bytes() + b"test-specific 65000/tcp\n")
        self.repin(name)
        with self.assertRaisesRegex(ValueError, "upstream recipe"): PUBLIC.load_catalogs(self.directory)

    def test_updated_local_pin_cannot_copy_private_hosts(self):
        name = "hosts.txt"
        (self.directory / name).write_bytes(b"127.0.0.1 localhost localhost.localdomain\n192.0.2.1 private-host\n")
        self.repin(name)
        with self.assertRaisesRegex(ValueError, "public package recipe"): PUBLIC.load_catalogs(self.directory)

    def test_public_source_urls_and_commit_are_required(self):
        self.rewrite_manifest(lambda m: m.update(alpine_aports_commit="0" * 40))
        with self.assertRaises(ValueError): PUBLIC.load_catalogs(self.directory)

    def test_recipe_itself_cannot_be_replaced_by_repinning(self):
        name = "alpine-APKBUILD.txt"
        (self.directory / name).write_bytes((self.directory / name).read_bytes() + b"# changed recipe\n")
        self.repin(name)
        with self.assertRaisesRegex(ValueError, "public recipe"): PUBLIC.load_catalogs(self.directory)

    def test_catalog_symlink_refused_even_with_identical_data(self):
        p = self.directory / "services.txt"; outside = self.directory.parent / "same-services"
        p.rename(outside); p.symlink_to(outside)
        with self.assertRaises(ValueError): PUBLIC.load_catalogs(self.directory)

    def test_malformed_manifest_shape_is_refused(self):
        for value in (None, [], "source", {"schema": "shizuku-public-network-catalogs/1", "files": []}):
            with self.subTest(value=value):
                (self.directory / "manifest.json").write_text(json.dumps(value))
                with self.assertRaises(ValueError): PUBLIC.load_catalogs(self.directory)

    def test_extra_path_and_traversal_manifest_refused(self):
        self.rewrite_manifest(lambda m: m["files"].update({"../outside": {}}))
        with self.assertRaises(ValueError): PUBLIC.load_catalogs(self.directory)

    def test_bounded_source_read_refuses_oversized_file(self):
        (self.directory / "services.txt").write_bytes(b"#" * (1024 * 1024 + 1))
        with self.assertRaises(ValueError): PUBLIC.load_catalogs(self.directory)


if __name__ == "__main__": unittest.main()
