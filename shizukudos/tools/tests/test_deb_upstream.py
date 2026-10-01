#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real Debian ar/tar fixtures and pinned-cache checks; no downloads or VMs."""
import io
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shzlib


def ar(members):
    data = bytearray(b"!<arch>\n")
    for name, payload in members:
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n".encode("ascii")
        assert len(header) == 60
        data.extend(header + payload + (b"\n" if len(payload) & 1 else b""))
    return bytes(data)


def tar(entries, mode="w:gz"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, kind, payload in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if kind in ("file", "hard") else 0o644
            if kind == "file":
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            else:
                member.type = {"sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE, "dev": tarfile.CHRTYPE}[kind]
                if kind in ("sym", "hard"):
                    member.linkname = payload
                archive.addfile(member)
    return buffer.getvalue()


def deb(payload, name="data.tar.gz"):
    control = tar([("control", "file", b"Package: test\nVersion: 1\n")])
    return ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control), (name, payload)])


class DebFallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shz-deb-test-")
        self.base = Path(self.temp.name)
        self.package = self.base / "fixture.deb"
        self.root = self.base / "root"

    def tearDown(self):
        self.temp.cleanup()

    def extract(self, entries):
        self.package.write_bytes(deb(tar(entries)))
        shzlib._extract_deb_payload(self.package, self.root)

    def test_real_ar_and_supported_compressions_preserve_bytes_modes_and_internal_links(self):
        entries = [("./usr/bin/tool", "file", b"pinned executable bytes"),
                   ("usr/bin/alias", "sym", "tool"), ("usr/bin/hard", "hard", "usr/bin/tool")]
        for suffix, mode in (("", "w:"), (".gz", "w:gz"), (".xz", "w:xz"), (".bz2", "w:bz2")):
            with self.subTest(compression=suffix):
                root = self.base / ("root" + suffix)
                self.package.write_bytes(deb(tar(entries, mode), "data.tar" + suffix))
                shzlib._extract_deb_payload(self.package, root)
                self.assertEqual((root / "usr/bin/tool").read_bytes(), b"pinned executable bytes")
                self.assertEqual((root / "usr/bin/tool").stat().st_mode & 0o777, 0o755)
                self.assertEqual((root / "usr/bin/alias").readlink(), Path("tool"))
                self.assertEqual((root / "usr/bin/hard").stat().st_ino, (root / "usr/bin/tool").stat().st_ino)

    def test_malformed_ar_and_debian_version_are_rejected(self):
        valid = deb(tar([("file", "file", b"ok")]))
        variants = [b"not-ar", valid[:-1], valid.replace(b"2.0\n", b"1.0\n", 1),
                    ar([("debian-binary", b"2.0\n"), ("data.tar.gz", tar([]))]),
                    ar([("debian-binary", b"2.0\n"), ("control.tar.gz", tar([])),
                        ("data.tar.gz", tar([])), ("data.tar.xz", tar([], "w:xz"))])]
        for payload in variants:
            with self.subTest(payload=payload[:12]):
                self.package.write_bytes(payload)
                with self.assertRaises(RuntimeError):
                    shzlib._extract_deb_payload(self.package, self.root)
                self.assertFalse(self.root.exists())

    def test_unsafe_member_paths_are_rejected_before_writes(self):
        for name in ("../escape", "/escape", "C:/escape", r"C:\escape"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.extract([("safe", "file", b"ok"), (name, "file", b"bad")])
            self.assertFalse(self.root.exists())

    def test_links_outside_root_and_devices_are_rejected(self):
        for kind, target in (("sym", "../outside"), ("hard", "../outside"),
                             ("sym", "/outside"), ("hard", "C:/outside"), ("dev", "")):
            with self.subTest(kind=kind, target=target), self.assertRaises(RuntimeError):
                self.extract([("safe", "file", b"ok"), ("link", kind, target)])
            self.assertFalse(self.root.exists())

    def test_existing_symlink_cannot_redirect_regular_file_writes(self):
        outside = self.base / "outside"
        outside.mkdir()
        self.root.mkdir()
        (self.root / "redirect").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.extract([("redirect/payload", "file", b"bad")])
        self.assertFalse((outside / "payload").exists())

    def test_duplicate_tar_paths_and_bad_tar_are_rejected(self):
        with self.assertRaises(RuntimeError):
            self.extract([("./same", "file", b"1"), ("same", "file", b"2")])
        self.package.write_bytes(deb(b"not-a-tar"))
        with self.assertRaises(RuntimeError):
            shzlib._extract_deb_payload(self.package, self.root)
        self.assertFalse(self.root.exists())

    def manifest_fixture(self, file_digest=None):
        payload = deb(tar([("usr/bin/tool", "file", b"pinned executable bytes")]))
        upstream = self.base / "upstream"
        downloads = upstream / "fixture/downloads"
        downloads.mkdir(parents=True)
        (downloads / "fixture.deb").write_bytes(payload)
        spec = {"kind": "debian-binary-packages", "packages": {"test": {
                    "file": "fixture.deb", "url": "https://invalid.test/no-download",
                    "sha256": shzlib.sha256_bytes(payload)}}, "source": {},
                "files": {"usr/bin/tool": file_digest or shzlib.sha256_bytes(b"pinned executable bytes")}}
        return upstream, spec

    def test_manifest_member_pin_still_gates_fallback_and_success_stamp(self):
        upstream, spec = self.manifest_fixture("0" * 64)
        with patch.object(shzlib, "UPSTREAM_DIR", upstream), patch.object(shzlib, "load_manifest", return_value={"upstreams": {"fixture": spec}}), \
             patch.object(shzlib.shutil, "which", return_value=None), patch.object(shzlib.urllib.request, "urlretrieve") as fetch:
            with self.assertRaisesRegex(RuntimeError, "not the pinned file"):
                shzlib.ensure_deb_upstream("fixture")
            self.assertFalse((upstream / "fixture/root/.unpacked-from").exists())
            fetch.assert_not_called()

    def test_package_pin_rejects_a_download_with_different_bytes(self):
        dest = self.base / "package.deb"
        def fetch(url, partial):
            Path(partial).write_bytes(b"different package bytes")
        with patch.object(shzlib.urllib.request, "urlretrieve", side_effect=fetch):
            with self.assertRaisesRegex(RuntimeError, "refusing a different file"):
                shzlib._fetch_pinned("https://invalid.test/package", dest, "0" * 64)
        self.assertFalse(dest.exists())
        self.assertFalse(dest.with_name("package.deb.partial").exists())

    def test_dpkg_deb_is_preferred_when_present(self):
        upstream, spec = self.manifest_fixture()
        spec["files"] = {}
        with patch.object(shzlib, "UPSTREAM_DIR", upstream), patch.object(shzlib, "load_manifest", return_value={"upstreams": {"fixture": spec}}), \
             patch.object(shzlib.shutil, "which", return_value="/existing/dpkg-deb"), \
             patch.object(shzlib, "run") as run, patch.object(shzlib, "_extract_deb_payload") as fallback:
            shzlib.ensure_deb_upstream("fixture")
            self.assertEqual(run.call_args.args[0][:2], ["/existing/dpkg-deb", "-x"])
            fallback.assert_not_called()

    def test_actual_cached_syslinux_packages_zstd_and_all_manifest_file_pins(self):
        spec = shzlib.load_manifest()["upstreams"]["syslinux"]
        packages = [shzlib.UPSTREAM_DIR / "syslinux/downloads" / p["file"] for p in spec["packages"].values()]
        if not all(p.is_file() for p in packages):
            self.skipTest("pinned Syslinux packages are not cached; tests never download")
        if not shutil.which("zstd"):
            self.skipTest("actual Ubuntu packages require existing zstd")
        for package, pin in zip(packages, spec["packages"].values()):
            self.assertEqual(shzlib.sha256_file(package), pin["sha256"])
            shzlib._extract_deb_payload(package, self.root)
        for relative, digest in spec["files"].items():
            with self.subTest(member=relative):
                self.assertEqual(shzlib.sha256_file(self.root / relative), digest)
        for relative in spec["license_files"]:
            self.assertTrue((self.root / relative).is_file(), relative)
        self.assertTrue((self.root / "usr/bin/syslinux").stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
