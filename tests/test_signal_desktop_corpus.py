"""Publisher integrity and unsafe-package boundaries for the two required apps."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("signal_corpus", ROOT / "tools/signal_desktop_corpus.py")
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)


def minimal_pe(x64=False):
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if x64 else 224
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if x64 else 0x14c, 1, 0, 0, 0, optional_size, 0x102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20b if x64 else 0x10b)
    struct.pack_into("<I", data, opt + 56, 0x2000)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<H", data, opt + 68, 2)
    directory = opt + (112 if x64 else 96)
    struct.pack_into("<I", data, directory - 4, 16)
    section = opt + optional_size
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    return bytes(data)


def asar(package, *, offset="0", unpacked=False):
    payload = json.dumps(package).encode()
    header = json.dumps({"files": {"package.json": {"size": len(payload), "offset": offset, "unpacked": unpacked}}}).encode()
    padding = b"\0" * (-(len(header) + 4) % 4)
    header_payload = struct.pack("<I", len(header)) + header + padding
    header_bytes = struct.pack("<I", len(header_payload)) + header_payload
    return struct.pack("<II", 4, len(header_bytes)) + header_bytes + payload


class PublisherIntegrity(unittest.TestCase):
    def test_exact_size_and_both_publisher_digest_encodings(self):
        data = b"publisher artifact\0" * 11
        for algorithm, encoding in (("sha512", "base64"), ("sha256", "hex")):
            digest = hashlib.new(algorithm, data)
            value = base64.b64encode(digest.digest()).decode() if encoding == "base64" else digest.hexdigest()
            pin = {"bytes": len(data), "algorithm": algorithm, "encoding": encoding, "digest": value}
            with tempfile.TemporaryFile() as stream:
                stream.write(data)
                stream.flush()
                report = corpus.artifact_digest(stream, pin)
                self.assertTrue(report["publisher_digest_verified"])
                self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
                stream.seek(0)
                stream.write(b"X")
                stream.flush()
                with self.assertRaises(corpus.CorpusError):
                    corpus.artifact_digest(stream, pin)
                with self.assertRaises(corpus.CorpusError):
                    corpus.artifact_digest(stream, {**pin, "bytes": len(data) + 1})

    def test_pinned_versions_and_non_native_win98_claim(self):
        self.assertEqual(corpus.PINS["signal"]["version"], "8.28.0")
        self.assertEqual(corpus.PINS["signal"]["architecture"], "x64")
        self.assertEqual(corpus.PINS["onlyoffice"]["version"], "9.4.0")
        self.assertEqual(corpus.PINS["onlyoffice"]["architecture"], "ia32")


class ArchiveBoundaries(unittest.TestCase):
    def test_windows_paths_reject_traversal_alias_devices_and_ads(self):
        for name in ("../Signal.exe", "/Signal.exe", "C:\\Signal.exe", "a//b", "a/./b", "a/../b", "a:stream", "nul.txt", "Com1.exe", "a/b.", "a/b ", "a/\x00b"):
            with self.subTest(name=name), self.assertRaises(corpus.CorpusError):
                corpus.safe_member(name)
        self.assertEqual(corpus.safe_member("resources\\app.asar"), "resources/app.asar")

    def test_archive_size_count_link_and_case_collision(self):
        invalid = ([{"name": "a", "bytes": -1}], [{"name": "a", "bytes": True}],
                   [{"name": "a", "bytes": corpus.MAX_MEMBER + 1}],
                   [{"name": "a", "bytes": 1, "link": True}],
                   [{"name": "Signal.exe", "bytes": 1}, {"name": "SIGNAL.exe", "bytes": 1}])
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(corpus.CorpusError):
                corpus.checked_entries(rows)
        with patch.object(corpus, "MAX_MEMBERS", 1), self.assertRaises(corpus.CorpusError):
            corpus.checked_entries([{"name": "a", "bytes": 0}, {"name": "b", "bytes": 0}])
        with patch.object(corpus, "MAX_EXPANDED", 1), self.assertRaises(corpus.CorpusError):
            corpus.checked_entries([{"name": "a", "bytes": 2}])

    def test_zip_symlinks_and_case_aliases_are_rejected_before_read(self):
        for entries in (("A.dll", "a.dll"), ("link",)):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for name in entries:
                    entry = zipfile.ZipInfo(name)
                    if name == "link":
                        entry.create_system = 3
                        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(entry, b"target")
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive, self.assertRaises(corpus.CorpusError):
                corpus.zip_entries(archive)

    def test_traversing_zip_rejected(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../DesktopEditors.exe", minimal_pe())
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive, self.assertRaises(corpus.CorpusError):
            corpus.zip_entries(archive)

    def test_zip_windows_separators_preserve_original_member_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "windows.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("DesktopEditors\\DesktopEditors.exe", minimal_pe())
            data = path.read_bytes()
            pin = {**corpus.PINS["onlyoffice"], "bytes": len(data), "digest": hashlib.sha256(data).hexdigest()}
            with patch.dict(corpus.PINS, {"onlyoffice": pin}):
                report = corpus.inspect_artifact("onlyoffice", path)
            self.assertEqual(report["entry_point"], "DesktopEditors/DesktopEditors.exe")

    def test_stream_declared_extent_cannot_hide_extra_bytes(self):
        with self.assertRaises(corpus.CorpusError):
            corpus.bounded_read(io.BytesIO(b"long"), 3)
        with self.assertRaises(corpus.CorpusError):
            corpus.bounded_read(io.BytesIO(b"short"), 6)

    def test_seven_zip_listing_needs_unique_regular_bounded_members(self):
        good = b"Header\n----------\nPath = $PLUGINSDIR/app-64.7z\nSize = 123\nAttributes = A\n"
        self.assertEqual(corpus.seven_entries(good)[0]["bytes"], 123)
        for bad in (b"no separator", good + b"Path = duplicate\n", good.replace(b"123", b"-1"), good.replace(b"Attributes = A", b"Symbolic Link = target")):
            with self.subTest(bad=bad), self.assertRaises(corpus.CorpusError):
                corpus.seven_entries(bad)

    def test_host_tool_output_is_bounded_and_nonzero_is_failure(self):
        with self.assertRaises(corpus.CorpusError):
            corpus.seven_zip([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*100000)"], 4096)
        with self.assertRaises(corpus.CorpusError):
            corpus.seven_zip([sys.executable, "-c", "raise SystemExit(3)"], 4096)
        self.assertEqual(corpus.seven_zip([sys.executable, "-c", "print('ok')"], 16), b"ok\n")

    def test_host_tool_timeout_is_reaped(self):
        with self.assertRaises(corpus.CorpusError):
            corpus.seven_zip([sys.executable, "-c", "import time;time.sleep(10)"], 16, timeout=0.02)


    def test_nsis_unknown_size_helpers_are_skipped_only_in_outer_installer(self):
        listing = (b"header\n----------\nPath = $PLUGINSDIR/System.dll\nSize = \nMethod = Deflate\n\n"
                   b"Path = $PLUGINSDIR/app-64.7z\nSize = 123\nMethod = Copy\n")
        with self.assertRaises(corpus.CorpusError):
            corpus.seven_entries(listing)
        rows = corpus.seven_entries(listing, allow_unknown_installer_sizes=True)
        self.assertEqual([(row["name"], row["bytes"]) for row in rows], [("$PLUGINSDIR/app-64.7z", 123)])
        for changed in (listing.replace(b"System.dll", b"../escape.dll"),
                        listing.replace(b"app-64.7z", b"System.dll"),
                        listing.replace(b"Size = 123", b"Size = ")):
            with self.subTest(changed=changed):
                with self.assertRaises(corpus.CorpusError):
                    corpus.seven_entries(changed, allow_unknown_installer_sizes=True)


class PackagedSignal(unittest.TestCase):
    def package(self):
        return {"name": "signal-desktop", "version": "8.28.0", "dependencies": dict(corpus.PINS["signal"]["native_dependencies"])}

    def members(self, package=None, native=True, x64=True):
        files = {"Signal.exe": minimal_pe(x64), "resources/app.asar": asar(self.package() if package is None else package)}
        if native:
            files["resources/app.asar.unpacked/node_modules/@signalapp/libsignal-client/signal_client.node"] = minimal_pe(True)
        entries = [{"name": name, "bytes": len(data)} for name, data in files.items()]
        return entries, lambda row: files[row["name"]]

    def test_packaged_version_and_real_native_metadata_required(self):
        entries, reader = self.members()
        report = corpus.inspect_members("signal", entries, reader)
        self.assertEqual(report["packaged_app_version"], "8.28.0")
        self.assertEqual(len(report["native_files"]), 2)
        self.assertFalse(report["native_files"][0]["guest_execution_verified"])
        self.assertFalse(report["native_files"][0]["app_functionality_verified"])

    def test_wrong_version_dependency_or_missing_addons_do_not_pass(self):
        wrong = self.package()
        wrong["version"] = "8.27.0"
        no_dependencies = {**self.package(), "dependencies": {}}
        for entries, reader in (self.members(wrong), self.members(no_dependencies), self.members(native=False), self.members(x64=False)):
            with self.assertRaises(corpus.CorpusError):
                corpus.inspect_members("signal", entries, reader)

    def test_asar_links_unpacked_and_overflow_do_not_become_metadata(self):
        for data in (b"short", asar(self.package(), unpacked=True), asar(self.package(), offset="-1"), asar(self.package(), offset="9999999999999999")):
            with self.subTest(data=data[:20]), self.assertRaises(corpus.CorpusError):
                corpus.asar_package(data)
        self.assertEqual(corpus.asar_package(asar(self.package())), self.package())

    def test_declared_size_and_ambiguous_entry_point_fail(self):
        entries, reader = self.members()
        with self.assertRaises(corpus.CorpusError):
            corpus.inspect_members("signal", [{**entries[0], "bytes": 0}, *entries[1:]], reader)
        files = {"DesktopEditors.exe": minimal_pe(), "duplicate/DesktopEditors.exe": minimal_pe()}
        with self.assertRaises(corpus.CorpusError):
            corpus.inspect_members("onlyoffice", [{"name": k, "bytes": len(v)} for k, v in files.items()], lambda e: files[e["name"]])

    def test_onlyoffice_streamed_artifact_receipt_never_claims_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "office.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("DesktopEditors/DesktopEditors.exe", minimal_pe())
                archive.writestr("DesktopEditors/notes.txt", b"resource retained only in original archive")
            data = path.read_bytes()
            pin = {**corpus.PINS["onlyoffice"], "bytes": len(data), "digest": hashlib.sha256(data).hexdigest()}
            with patch.dict(corpus.PINS, {"onlyoffice": pin}):
                report = corpus.inspect_artifact("onlyoffice", path)
            self.assertTrue(report["artifact"]["publisher_digest_verified"])
            self.assertFalse(report["windows98_execution_verified"])
            self.assertFalse(report["standalone_kernel64_execution_verified"])
            self.assertFalse(report["app_functionality_verified"])
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_symlink_artifact_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file"
            path.write_bytes(b"data")
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                corpus.inspect_artifact("onlyoffice", alias)

    def test_existing_receipt_is_retained_before_any_artifact_read(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            output.write_text("prior evidence")
            with patch.object(corpus, "inspect_artifact") as inspect, self.assertRaises(SystemExit):
                corpus.main(["--app", "signal", "--artifact", "absent.exe", "--output", str(output)])
            inspect.assert_not_called()
            self.assertEqual(output.read_text(), "prior evidence")


if __name__ == "__main__":
    unittest.main()
