# SPDX-License-Identifier: GPL-2.0-only
"""Regression tests for untrusted publisher archive boundaries and honest claims."""
import hashlib
import importlib.util
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "steam_client_corpus.py"
SPEC = importlib.util.spec_from_file_location("steam_client_corpus", SOURCE)
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


class ManifestTests(unittest.TestCase):
    def manifest(self, **changes):
        package = {"file": "steam_win64.zip." + "a" * 40, "size": "10", "sha2": "b" * 64}
        package.update(changes)
        return {"win64": {"version": "1788652215", "ostype": "win10", "steam_win64": package}}

    def test_nested_bootstrap_variant_and_signatures(self):
        parsed = corpus.parse_vdf('''// fixture
            "win64" { "version" "1788652215" "steam_win64" {
                "steamrow" { "IsBootstrapperPackage" "1" }
                "file" "steam_win64.zip.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "size" "10" "sha2" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }} "kvsignatures" { "win64" "signature" }''')
        specs = corpus.package_specs(parsed, ["steam_win64"])
        self.assertEqual(specs[0]["size"], 10)
        self.assertEqual(parsed["win64"]["steam_win64"]["steamrow"]["IsBootstrapperPackage"], "1")

    def test_duplicate_or_truncated_manifest_rejected(self):
        for raw in ('"win64" {} "win64" {}', '"win64" { "version" "1"', '"win64" { "version" }'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                corpus.parse_vdf(raw)

    def test_manifest_cannot_choose_external_download_or_unbounded_size(self):
        for changes in ({"file": "https://example.com/payload.zip"}, {"file": "../steam.zip." + "a" * 40},
                        {"size": str(corpus.MAX_DOWNLOAD + 1)}, {"sha2": "b" * 63}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                corpus.package_specs(self.manifest(**changes), ["steam_win64"])

    def test_win32_cannot_be_substituted_for_current_target(self):
        with self.assertRaisesRegex(ValueError, "win64"):
            corpus.package_specs({"win32": {"version": "1769731672"}}, ["steam_win64"])


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, name, files):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as zipped:
            for member, data in files:
                zipped.writestr(member, data)
        return path

    def extract(self, paths):
        return corpus.extract_packages(paths, self.root / "client", [{"name": path.name} for path in paths])

    def test_windows_path_escape_rejected_before_any_write(self):
        for member in ("../outside.exe", "bin/../../outside.exe", "C:\\outside.exe", "\\outside.exe", "bin/stream:payload"):
            with self.subTest(member=member):
                path = self.archive("unsafe.zip", [("steam.exe", b"valid"), (member, b"bad")])
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    self.extract([path])
                self.assertFalse((self.root / "client").exists())

    def test_symlink_rejected(self):
        info = zipfile.ZipInfo("steam.exe")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        path = self.archive("symlink.zip", [(info, b"/etc/passwd")])
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.extract([path])

    def test_case_insensitive_collision_across_packages_rejected(self):
        one = self.archive("one.zip", [("bin/Steam.dll", b"one")])
        two = self.archive("two.zip", [("BIN/steam.DLL", b"two")])
        with self.assertRaisesRegex(ValueError, "collision"):
            self.extract([one, two])

    def test_exact_publisher_duplicate_allowed_only_when_bytes_match(self):
        one = self.archive("one.zip", [("resource/sourceinit.dat", b"one")])
        two = self.archive("two.zip", [("resource/sourceinit.dat", b"one")])
        rows = self.extract([one, two])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["shared_packages"], ["one.zip", "two.zip"])

    def test_same_path_cannot_overwrite_another_package(self):
        one = self.archive("one.zip", [("resource/sourceinit.dat", b"one")])
        two = self.archive("two.zip", [("resource/sourceinit.dat", b"two")])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.extract([one, two])

    def test_bounded_expansion_rejected_before_writes(self):
        path = self.archive("large.zip", [("steam.exe", b"123456")])
        with mock.patch.object(corpus, "MAX_EXPANDED", 5), self.assertRaisesRegex(ValueError, "bounds"):
            self.extract([path])
        self.assertFalse((self.root / "client").exists())

    def test_windows_member_separators_and_identity(self):
        path = self.archive("good.zip", [("bin\\Steam.dll", b"binary")])
        rows = self.extract([path])
        self.assertEqual((self.root / "client/bin/Steam.dll").read_bytes(), b"binary")
        self.assertEqual(rows[0]["sha256"], hashlib.sha256(b"binary").hexdigest())

    def test_corrupt_cached_download_not_silently_accepted(self):
        archives = self.root / "archives"
        archives.mkdir()
        spec = {"file": "p.zip." + "a" * 40, "size": 3, "sha256": hashlib.sha256(b"yes").hexdigest()}
        (archives / spec["file"]).write_bytes(b"bad")
        with self.assertRaisesRegex(ValueError, "pinned manifest"):
            corpus.download_package(spec, archives)


class EvidenceTests(unittest.TestCase):
    def image(self, path, imports=(), exports=None, machine="0x8664"):
        return {"path": path, "machine": machine, "imports": list(imports), "exports": exports or {}}

    def imp(self, dll, symbol):
        return {"kind": "direct", "dll": dll, "symbol": symbol}

    def test_ordinal_thunk_is_not_replaced_by_pefile_name_hint(self):
        import types
        symbol = types.SimpleNamespace(name=b"GetAcceptExSockaddrs", ordinal=1142, import_by_ordinal=True)
        descriptor = types.SimpleNamespace(dll=b"WSOCK32.dll", imports=[symbol])
        directory = types.SimpleNamespace(VirtualAddress=0, Size=0)
        opt = types.SimpleNamespace(DATA_DIRECTORY=[directory] * 16, Magic=0x20b,
                                    MajorOperatingSystemVersion=6, MinorOperatingSystemVersion=0,
                                    MajorSubsystemVersion=6, MinorSubsystemVersion=0,
                                    Subsystem=2, DllCharacteristics=0x8160)
        fake = types.SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[descriptor], OPTIONAL_HEADER=opt,
                                     FILE_HEADER=types.SimpleNamespace(Machine=0x8664),
                                     parse_data_directories=lambda **kwargs: None, close=lambda: None)
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            executable = root / "steam.exe"
            executable.write_bytes(b"fixture")
            with mock.patch("pefile.PE", return_value=fake):
                record = corpus.pe_record(executable, root)
        self.assertEqual(record["imports"], [{"kind": "direct", "dll": "wsock32.dll", "symbol": "#1142",
                                              "ordinal_name_hint": "GetAcceptExSockaddrs"}])

    def test_missing_wrong_arch_forwarder_and_api_set_are_not_passes(self):
        image = self.image("steam.exe", [self.imp("wrong.dll", "F"), self.imp("forward.dll", "F"),
                                        self.imp("api-ms-win-example.dll", "F"), self.imp("real.dll", "F")])
        runtime = [self.image("wrong.dll", exports={"F": None}, machine="0x014c"),
                   self.image("forward.dll", exports={"F": "missing.F"}),
                   self.image("real.dll", exports={"F": None})]
        result = corpus.static_closure([image], runtime)
        self.assertEqual(result["export_names_present"], 1)
        self.assertEqual({row["reason"] for row in result["unresolved_imports"]},
                         {"architecture_mismatch", "forwarder_requires_resolution", "api_set_requires_loader_mapping"})
        self.assertFalse(result["guest_startup_verified"])
        self.assertFalse(result["steam_desktop_functionality_verified"])


if __name__ == "__main__":
    unittest.main()
