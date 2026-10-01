"""Offline application preflight contracts using synthetic, non-running PEs.

The fixtures contain headers and import tables, not executable application
code. All writes belong to a TemporaryDirectory; diagnosis must preserve the
input bytes and must not turn static preparation into a runtime claim.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app_preflight as preflight


PE_OFFSET = 0x80
OPTIONAL = PE_OFFSET + 24
RAW_OFFSET = 0x200
DATA_RVA = 0x1000
RAW_SIZE = 0x1000


def synthetic_pe(*, pe64: bool = False, version: tuple[int, int] = (4, 10),
                 subsystem: int = 3,
                 imports: tuple[tuple[str, tuple[str | int, ...]], ...] = (
                     ("kernel32.dll", ("GetTickCount64", "CreateFileA", 5)),
                 ),
                 delay: bool = False, signed: bool = False,
                 clr: bool = False) -> bytes:
    """Build a file-backed PE accepted by the existing PE32 preparer.

    Named and ordinal entries occupy distinct ILT/IATs. PE32+ uses its own
    optional-header layout and eight-byte thunks rather than changing only a
    magic word, so architecture tests exercise genuine 64-bit input metadata.
    """
    image = bytearray(RAW_OFFSET + RAW_SIZE)
    optional_size = 240 if pe64 else 224
    directory_base = OPTIONAL + (112 if pe64 else 96)
    width = 8 if pe64 else 4
    thunk_format = "<Q" if pe64 else "<I"

    def put(rva: int, value: bytes) -> None:
        offset = RAW_OFFSET + rva - DATA_RVA
        if not RAW_OFFSET <= offset <= offset + len(value) <= len(image):
            raise ValueError("fixture data is outside its section")
        image[offset:offset + len(value)] = value

    def directory(index: int, address: int, size: int) -> None:
        struct.pack_into("<II", image, directory_base + index * 8, address, size)

    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, PE_OFFSET)
    image[PE_OFFSET:PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, PE_OFFSET + 4,
                     0x8664 if pe64 else 0x14C, 1, 0, 0, 0,
                     optional_size, 0x0002 if pe64 else 0x0102)
    struct.pack_into("<H", image, OPTIONAL, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", image, OPTIONAL + 8, RAW_SIZE)
    if pe64:
        struct.pack_into("<Q", image, OPTIONAL + 24, 0x140000000)
    else:
        struct.pack_into("<I", image, OPTIONAL + 28, 0x400000)
    struct.pack_into("<II", image, OPTIONAL + 32, 0x1000, 0x200)
    struct.pack_into("<HH", image, OPTIONAL + 40, 4, 0)
    struct.pack_into("<HH", image, OPTIONAL + 48, *version)
    struct.pack_into("<II", image, OPTIONAL + 56, 0x2000, RAW_OFFSET)
    struct.pack_into("<H", image, OPTIONAL + 68, subsystem)
    struct.pack_into("<I", image, OPTIONAL + (108 if pe64 else 92), 16)
    struct.pack_into("<8sIIIIIIHHI", image, OPTIONAL + optional_size,
                     b".idata\0\0", RAW_SIZE, DATA_RVA, RAW_SIZE, RAW_OFFSET,
                     0, 0, 0, 0, 0xC0000040)

    if imports:
        directory(1, 0x1100, 20 * (len(imports) + 1))
    for index, (dll, symbols) in enumerate(imports):
        if index >= 3 or len(symbols) > 3:
            raise ValueError("fixture import table is intentionally small")
        base = 0x1200 + index * 0x180
        lookup, iat, dll_rva = base, base + 0x40, base + 0x80
        put(0x1100 + index * 20,
            struct.pack("<IIIII", lookup, 0, 0, dll_rva, iat))
        put(dll_rva, dll.encode("ascii") + b"\0")
        for item, symbol in enumerate(symbols):
            if isinstance(symbol, int):
                value = (1 << (width * 8 - 1)) | symbol
            else:
                value = base + 0xC0 + item * 0x30
                put(value, b"\0\0" + symbol.encode("ascii") + b"\0")
            put(lookup + item * width, struct.pack(thunk_format, value))
            put(iat + item * width, struct.pack(thunk_format, value))

    if delay:
        directory(13, 0x1800, 64)
        put(0x1800, struct.pack("<8I", 1, 0x1880, 0x18D0,
                                0x18C0, 0x18A0, 0, 0, 0))
        put(0x1880, b"KERNEL32.DLL\0")
        put(0x18A0, struct.pack(thunk_format, 0x18E0))
        put(0x18C0, struct.pack(thunk_format, 0x18E0))
        put(0x18E0, b"\0\0GetTickCount64\0")
    if clr:
        directory(14, 0x1A00, 72)
        put(0x1A00, struct.pack("<IHH", 72, 2, 5) + bytes(64))
    if signed:
        certificate = struct.pack("<IHH", 16, 0x0200, 2) + bytes(8)
        # The security directory contains a file offset, not an RVA.
        directory(4, len(image), len(certificate))
        image.extend(certificate)
    return bytes(image)


class AppPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def diagnose(self, image: bytes, name: str = "app.exe") -> dict:
        path = self.folder / name
        path.write_bytes(image)
        return preflight.analyze(path)

    def assert_unexecuted(self, report: dict) -> None:
        self.assertIs(report["guest_executed"], False)
        self.assertEqual(report["runtime_compatibility"], "unverified")

    def test_pe32_route_is_static_eligibility_not_runtime_success(self) -> None:
        image = synthetic_pe()
        report = self.diagnose(image)
        self.assertEqual(report["schema"], "win98modern.app-preflight.v1")
        self.assertEqual(report["input"]["sha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(report["input"]["size_bytes"], len(image))
        self.assertEqual(Path(report["input"]["path"]), self.folder / "app.exe")
        self.assertEqual(report["pe"]["machine"], 0x14C)
        self.assertEqual(report["pe"]["format"], "PE32")
        self.assertEqual(report["pe"]["subsystem"], 3)
        self.assertEqual(report["pe"]["subsystem_version"], [4, 10])
        self.assertEqual(report["paths"]["stock_win98"]["status"], "unverified")
        self.assertEqual(report["paths"]["stock_win98"]["blockers"], [])
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "eligible")
        self.assertIsNone(report["paths"]["ntw32"]["reason"])
        self.assertIs(report["import_inventory_complete"], True)
        self.assert_unexecuted(report)

    def test_only_supported_named_load_imports_from_source_dll_are_candidates(self) -> None:
        report = self.diagnose(synthetic_pe(imports=(
            ("kernel32.dll", ("GetTickCount64", "CreateFileA", 5)),
            ("USER32.dll", ("GetTickCount64",)),
        ), delay=True))
        self.assertEqual(report["imports"], [
            {"dll": "KERNEL32.DLL", "symbol": "GetTickCount64", "kind": "load",
             "ntw32_route_candidate": True},
            {"dll": "KERNEL32.DLL", "symbol": "CreateFileA", "kind": "load",
             "ntw32_route_candidate": False},
            {"dll": "KERNEL32.DLL", "symbol": "#5", "kind": "load",
             "ntw32_route_candidate": False},
            {"dll": "USER32.DLL", "symbol": "GetTickCount64", "kind": "load",
             "ntw32_route_candidate": False},
            {"dll": "KERNEL32.DLL", "symbol": "GetTickCount64", "kind": "delay",
             "ntw32_route_candidate": False},
        ])
        self.assertIs(report["import_inventory_complete"], True)
        self.assert_unexecuted(report)

    def test_no_supported_load_routes_rejects_preparation(self) -> None:
        report = self.diagnose(synthetic_pe(imports=(
            ("KERNEL32.DLL", ("CreateFileA", 5)),
        ), delay=True))
        self.assertFalse(any(row["ntw32_route_candidate"] for row in report["imports"]))
        ntw32 = report["paths"]["ntw32"]
        self.assertEqual(ntw32["preparation_status"], "rejected")
        self.assertIn("no supported imports", ntw32["reason"])
        self.assert_unexecuted(report)

    def test_api_set_name_does_not_impersonate_the_route_source_dll(self) -> None:
        report = self.diagnose(synthetic_pe(imports=(
            ("api-ms-win-core-sysinfo-l1-2-1.dll", ("GetTickCount64",)),
        )))
        self.assertEqual(report["imports"], [{
            "dll": "API-MS-WIN-CORE-SYSINFO-L1-2-1.DLL",
            "symbol": "GetTickCount64", "kind": "load",
            "ntw32_route_candidate": False,
        }])
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "rejected")
        self.assert_unexecuted(report)

    def test_extensionless_kernel32_does_not_become_a_route_candidate(self) -> None:
        report = self.diagnose(synthetic_pe(imports=(
            ("KERNEL32", ("GetTickCount64",)),
        )))
        self.assertEqual(len(report["imports"]), 1)
        self.assertEqual(report["imports"][0]["symbol"], "GetTickCount64")
        self.assertIs(report["imports"][0]["ntw32_route_candidate"], False)
        ntw32 = report["paths"]["ntw32"]
        self.assertEqual(ntw32["preparation_status"], "rejected")
        self.assertIn("no supported imports", ntw32["reason"])
        self.assert_unexecuted(report)

    def test_subsystem_10_is_blocked_without_version_downgrade(self) -> None:
        image = synthetic_pe(version=(10, 0))
        report = self.diagnose(image)
        self.assertEqual(report["pe"]["subsystem_version"], [10, 0])
        stock = report["paths"]["stock_win98"]
        self.assertEqual(stock["status"], "blocked")
        self.assertTrue(any("subsystem" in reason.lower() for reason in stock["blockers"]))
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "eligible")
        self.assertEqual((self.folder / "app.exe").read_bytes(), image)
        self.assert_unexecuted(report)

    def test_x64_pe32_plus_is_inventoried_but_rejected_for_ntw32(self) -> None:
        report = self.diagnose(synthetic_pe(pe64=True))
        self.assertEqual(report["pe"]["machine"], 0x8664)
        self.assertEqual(report["pe"]["format"], "PE32+")
        self.assertEqual([row["symbol"] for row in report["imports"]],
                         ["GetTickCount64", "CreateFileA", "#5"])
        self.assertEqual(report["paths"]["stock_win98"]["status"], "blocked")
        self.assertTrue(report["paths"]["stock_win98"]["blockers"])
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "rejected")
        self.assertTrue(report["paths"]["ntw32"]["reason"])
        self.assertIs(report["import_inventory_complete"], True)
        self.assert_unexecuted(report)

    def test_pe32_plus_delay_inventory_is_explicitly_incomplete(self) -> None:
        report = self.diagnose(synthetic_pe(pe64=True, delay=True))
        self.assertIs(report["import_inventory_complete"], False)
        self.assertTrue(report["import_inventory_notes"])
        self.assertTrue(any("delay" in note.lower()
                            for note in report["import_inventory_notes"]))
        self.assertEqual([row["kind"] for row in report["imports"]], ["load"] * 3)
        self.assert_unexecuted(report)

    def test_clr_and_signed_images_require_separate_preparation_paths(self) -> None:
        for kind, options in (("CLR", {"clr": True}),
                              ("signed image", {"signed": True})):
            with self.subTest(kind=kind):
                image = synthetic_pe(**options)
                report = self.diagnose(image)
                ntw32 = report["paths"]["ntw32"]
                self.assertEqual(ntw32["preparation_status"], "rejected")
                self.assertIn(kind.lower(), ntw32["reason"].lower())
                if kind == "CLR":
                    self.assertEqual(report["paths"]["stock_win98"]["status"], "blocked")
                    self.assertTrue(any("clr" in reason.lower()
                                        for reason in report["paths"]["stock_win98"]["blockers"]))
                self.assertEqual((self.folder / "app.exe").read_bytes(), image)
                self.assert_unexecuted(report)

    def test_native_subsystem_is_blocked_for_stock_and_ntw32(self) -> None:
        report = self.diagnose(synthetic_pe(subsystem=1))
        self.assertEqual(report["paths"]["stock_win98"]["status"], "blocked")
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "rejected")
        self.assert_unexecuted(report)

    def test_diagnosis_never_writes_a_prepared_copy_or_changes_source(self) -> None:
        path = self.folder / "source.exe"
        image = synthetic_pe(delay=True)
        path.write_bytes(image)
        before = {p.name for p in self.folder.iterdir()}
        report = preflight.analyze(path)
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "eligible")
        self.assertEqual(path.read_bytes(), image)
        self.assertEqual({p.name for p in self.folder.iterdir()}, before)

    def test_hash_headers_imports_and_preparation_share_one_immutable_snapshot(self) -> None:
        path = self.folder / "changing.exe"
        first = synthetic_pe(imports=(("KERNEL32.DLL", ("GetTickCount64",)),))
        second = synthetic_pe(pe64=True, version=(10, 0),
                              imports=(("USER32.DLL", ("MessageBoxA",)),))
        path.write_bytes(first)
        original_read = Path.read_bytes
        source_reads: list[Path] = []

        def change_on_read(selected: Path) -> bytes:
            if selected == path:
                source_reads.append(selected)
                return first if len(source_reads) == 1 else second
            return original_read(selected)

        with mock.patch.object(Path, "read_bytes", autospec=True,
                               side_effect=change_on_read):
            report = preflight.analyze(path)
        self.assertEqual(source_reads, [path])
        self.assertEqual(report["input"]["sha256"], hashlib.sha256(first).hexdigest())
        self.assertEqual(report["input"]["size_bytes"], len(first))
        self.assertEqual(report["pe"]["machine"], 0x14C)
        self.assertEqual(report["pe"]["format"], "PE32")
        self.assertEqual(report["pe"]["subsystem_version"], [4, 10])
        self.assertEqual([row["symbol"] for row in report["imports"]], ["GetTickCount64"])
        self.assertEqual(report["paths"]["ntw32"]["preparation_status"], "eligible")
        self.assertEqual(original_read(path), first)
        self.assert_unexecuted(report)

    def test_truncated_headers_and_bad_signatures_fail_closed(self) -> None:
        good = synthetic_pe()
        bad_signature = bytearray(good)
        bad_signature[PE_OFFSET:PE_OFFSET + 4] = b"NOPE"
        distant_header = bytearray(good)
        struct.pack_into("<I", distant_header, 0x3C, len(good) + 1)
        for image in (b"", b"MZ", good[:63], good[:PE_OFFSET + 12],
                      good[:OPTIONAL + 100], bytes(bad_signature), bytes(distant_header)):
            with self.subTest(length=len(image), signature=image[PE_OFFSET:PE_OFFSET + 4]):
                with self.assertRaises(preflight.PEError):
                    self.diagnose(image)

    def test_directory_count_cannot_escape_optional_header(self) -> None:
        for pe64 in (False, True):
            with self.subTest(pe64=pe64):
                image = bytearray(synthetic_pe(pe64=pe64))
                struct.pack_into("<I", image, OPTIONAL + (108 if pe64 else 92), 17)
                with self.assertRaises(preflight.PEError):
                    self.diagnose(bytes(image))

    def test_section_raw_size_cannot_extend_past_file(self) -> None:
        for pe64 in (False, True):
            with self.subTest(pe64=pe64):
                with self.assertRaises(preflight.PEError):
                    self.diagnose(synthetic_pe(pe64=pe64)[:-1])

    def test_import_directory_must_be_complete_and_file_backed(self) -> None:
        for address, size in ((0x1100, 19), (0x900000, 40), (0x1FF0, 40),
                              (0, 40), (0x1100, 0)):
            with self.subTest(address=address, size=size):
                image = bytearray(synthetic_pe())
                struct.pack_into("<II", image, OPTIONAL + 96 + 8, address, size)
                with self.assertRaises(preflight.PEError):
                    self.diagnose(bytes(image))

    def test_virtual_only_section_tail_cannot_supply_import_descriptors(self) -> None:
        image = bytearray(synthetic_pe())
        struct.pack_into("<I", image, OPTIONAL + 224 + 8, 0x2000)
        struct.pack_into("<II", image, OPTIONAL + 96 + 8, 0x2100, 40)
        with self.assertRaises(preflight.PEError):
            self.diagnose(bytes(image))

    def test_import_descriptor_must_terminate_inside_declared_directory(self) -> None:
        image = bytearray(synthetic_pe())
        struct.pack_into("<II", image, OPTIONAL + 96 + 8, 0x1100, 20)
        with self.assertRaises(preflight.PEError):
            self.diagnose(bytes(image))

    def test_import_lookup_table_cannot_read_from_virtual_only_tail(self) -> None:
        image = bytearray(synthetic_pe())
        struct.pack_into("<I", image, OPTIONAL + 224 + 8, 0x2000)
        struct.pack_into("<I", image, RAW_OFFSET + 0x100, 0x2100)
        with self.assertRaises(preflight.PEError):
            self.diagnose(bytes(image))

    def test_import_strings_and_thunks_cannot_terminate_in_overlay(self) -> None:
        for kind in ("string", "thunk"):
            with self.subTest(kind=kind):
                image = bytearray(synthetic_pe())
                if kind == "string":
                    # A named import ends in the section without a NUL; a
                    # NUL in the overlay must not make it a valid PE string.
                    struct.pack_into("<I", image, RAW_OFFSET + 0x200, 0x1FF0)
                    image[-16:] = b"\0\0" + b"A" * 14
                else:
                    # The final raw cell contains a real name but its lookup
                    # table has no terminator before the section boundary.
                    struct.pack_into("<I", image, RAW_OFFSET + 0x100, 0x1FFC)
                    struct.pack_into("<I", image, len(image) - 4, 0x12C0)
                image.extend(bytes(8))
                with self.assertRaises(preflight.PEError):
                    self.diagnose(bytes(image))

    def test_certificate_directory_is_bounded_as_a_file_offset(self) -> None:
        image = bytearray(synthetic_pe(signed=True))
        struct.pack_into("<II", image, OPTIONAL + 96 + 4 * 8, len(image) - 8, 16)
        with self.assertRaises(preflight.PEError):
            self.diagnose(bytes(image))

    def test_delay_directory_bounds_and_termination_are_enforced(self) -> None:
        for address, size in ((0x1800, 31), (0x1800, 32), (0x1FF0, 64)):
            with self.subTest(address=address, size=size):
                image = bytearray(synthetic_pe(delay=True))
                struct.pack_into("<II", image, OPTIONAL + 96 + 13 * 8, address, size)
                with self.assertRaises(preflight.PEError):
                    self.diagnose(bytes(image))

    def test_markdown_exposes_evidence_and_unverified_runtime(self) -> None:
        report = self.diagnose(synthetic_pe())
        markdown = preflight.render_markdown(report)
        self.assertIsInstance(markdown, str)
        self.assertIn(report["input"]["sha256"], markdown)
        self.assertIn("GetTickCount64", markdown)
        self.assertIn("KERNEL32.DLL", markdown)
        self.assertIn("unverified", markdown.lower())
        self.assertIn("eligible", markdown.lower())

    def test_cli_emits_json_and_markdown_to_stdout_without_file_writes(self) -> None:
        path = self.folder / "app.exe"
        image = synthetic_pe()
        path.write_bytes(image)
        for arguments in ([str(path)], [str(path), "--format", "json"],
                          [str(path), "--format", "markdown"]):
            with self.subTest(arguments=arguments):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = preflight.main(arguments)
                self.assertEqual(result, 0)
                self.assertEqual(stderr.getvalue(), "")
                if arguments[-1] == "markdown":
                    self.assertIn("GetTickCount64", stdout.getvalue())
                    self.assertIn("unverified", stdout.getvalue().lower())
                else:
                    report = json.loads(stdout.getvalue())
                    self.assertEqual(report["input"]["sha256"], hashlib.sha256(image).hexdigest())
                    self.assert_unexecuted(report)
                self.assertEqual(path.read_bytes(), image)
                self.assertEqual({p.name for p in self.folder.iterdir()}, {path.name})

    def test_cli_missing_or_malformed_input_returns_error_without_report(self) -> None:
        malformed = self.folder / "bad.exe"
        malformed.write_bytes(b"MZ")
        for path in (self.folder / "missing.exe", malformed):
            with self.subTest(path=path):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = preflight.main([str(path)])
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertTrue(stderr.getvalue().strip())


if __name__ == "__main__":
    unittest.main()
