"""Real archive bounds, PE export resolution and private handoff integration."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("theme_runtime", ROOT / "tools/required_theme_runtime.py")
theme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(theme)


def dll(exports, imports=()):
    """Small actual AMD64 PE with EAT, names, ordinals, forwarders and ILT/IAT."""
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 1, 0, 0, 0, 240, 0x2102)
    struct.pack_into("<H", data, 152, 0x20B)
    struct.pack_into("<II", data, 208, 8192, 512)
    struct.pack_into("<H", data, 220, 2)
    struct.pack_into("<I", data, 260, 16)
    data[392:400] = b".rdata\0\0"
    struct.pack_into("<IIII", data, 400, 3584, 4096, 3584, 512)

    def at(rva):
        return rva - 4096 + 512

    def string(rva, text):
        value = text.encode("ascii") + b"\0"
        data[at(rva):at(rva) + len(value)] = value

    base = min(row[1] for row in exports)
    count = max(row[1] for row in exports) - base + 1
    named = [row for row in exports if row[0] is not None]
    struct.pack_into("<II", data, 264, 0x1000, 0x400)
    struct.pack_into("<IIHHIIIIIII", data, at(0x1000), 0, 0, 0, 0, 0, base, count, len(named), 0x1080, 0x1180, 0x11C0)
    text_rva = 0x1280
    for name, ordinal, forwarder in exports:
        target = 0x1500
        if forwarder:
            target = text_rva
            string(text_rva, forwarder)
            text_rva += len(forwarder) + 1
        struct.pack_into("<I", data, at(0x1080) + (ordinal - base) * 4, target)
    for index, (name, ordinal, _) in enumerate(named):
        struct.pack_into("<I", data, at(0x1180) + index * 4, text_rva)
        struct.pack_into("<H", data, at(0x11C0) + index * 2, ordinal - base)
        string(text_rva, name)
        text_rva += len(name) + 1
    if imports:
        struct.pack_into("<II", data, 272, 0x1800, (len(imports) + 1) * 20)
        for index, (module, symbols) in enumerate(imports):
            lookup, iat, module_rva, name_rva = 0x1880 + index * 0x40, 0x1980 + index * 0x40, 0x1B00 + index * 0x40, 0x1C00 + index * 0x80
            struct.pack_into("<5I", data, at(0x1800) + index * 20, lookup, 0, 0, module_rva, iat)
            string(module_rva, module)
            for ordinal_index, symbol in enumerate(symbols):
                if symbol.startswith("#"):
                    value = (1 << 63) | int(symbol[1:])
                else:
                    value = name_rva
                    struct.pack_into("<H", data, at(name_rva), 0)
                    string(name_rva + 2, symbol)
                    name_rva += len(symbol) + 3
                struct.pack_into("<Q", data, at(lookup) + ordinal_index * 8, value)
                struct.pack_into("<Q", data, at(iat) + ordinal_index * 8, value)
    return bytes(data)


class ArchiveCase(unittest.TestCase):
    def setUp(self):
        self.files = [("\\SHZ\\SYS64\\user32.dll", dll([("Paint", 7, None)])),
                      ("\\SHZ\\DATA\\empty.dat", b""), ("\\SHZ\\DATA\\asset.txt", b"exact original asset")]
        self.raw = theme.pack_archive(self.files)

    def test_roundtrip_retains_order_empty_member_and_all_original_bytes(self):
        self.assertEqual(theme.parse_archive(self.raw), self.files)
        self.assertEqual(theme.pack_archive(theme.parse_archive(self.raw)), self.raw)
        self.assertEqual(theme.parse_archive(theme.pack_archive(self.files + [(theme.THEME_PATH, b"new")]))[:-1], self.files)

    def test_rejects_directory_and_extent_corruption(self):
        cases = []
        for field, value in ((8, 4097), (12, 1)):
            raw = bytearray(self.raw)
            struct.pack_into("<I", raw, field, value)
            cases.append(raw)
        for offset, size in ((16, 8), (2**64 - 16, 1), (432, 2**64 - 1), (433, 1)):
            raw = bytearray(self.raw)
            struct.pack_into("<QQ", raw, 16 + 120, offset, size)
            cases.append(raw)
        raw = bytearray(self.raw)
        first_offset = struct.unpack_from("<Q", raw, 16 + 120)[0]
        struct.pack_into("<QQ", raw, 16 + 2 * 136 + 120, first_offset, 1)
        cases.append(raw)
        cases.extend((self.raw[:-1], self.raw + b"\0"))
        for raw in cases:
            with self.subTest(extent=bytes(raw[:24])), self.assertRaises(theme.ThemeRuntimeError):
                theme.parse_archive(bytes(raw))

    def test_rejects_names_case_aliases_traversal_links_and_file_parent_collision(self):
        for name in ("\\SHZ\\..\\evil", "\\SHZ\\SYS64\\x.dll:stream", "\\\\host\\file", "relative", "\\SHZ\\bad.", "\\SHZ\\bad/name"):
            raw = bytearray(self.raw)
            raw[16:136] = name.encode().ljust(120, b"\0")
            with self.subTest(name=name), self.assertRaises(theme.ThemeRuntimeError):
                theme.parse_archive(bytes(raw))
        for extra in (("\\SHZ\\SYS64\\USER32.DLL", b"alias"), ("\\shz\\DATA\\new", b"parent alias"), ("\\SHZ\\DATA", b"file collides with directory")):
            with self.subTest(extra=extra), self.assertRaises(theme.ThemeRuntimeError):
                theme.pack_archive(self.files + [extra])
        raw = bytearray(self.raw)
        raw[135] = 1
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "name padding"):
            theme.parse_archive(bytes(raw))

    def test_actual_named_and_ordinal_imports_resolve_to_real_export_table(self):
        provider = dll([("DrawThemeBackgroundEx", 47, None)], [("user32.dll", ["Paint", "#7"])])
        gate = theme.import_gate(provider, self.files)
        self.assertEqual([row["symbol"] for row in gate["resolved_imports"]], ["Paint", "#7"])
        self.assertEqual(gate["provider_exports"]["DrawThemeBackgroundEx"], 47)
        self.assertFalse(gate["abi_semantics_verified"])

    def test_actual_forwarder_chain_resolves_ordinal_and_rejects_cycle_or_missing_symbol(self):
        modules = theme.archive_modules([
            ("\\SHZ\\SYS64\\user32.dll", dll([("Paint", 1, "GDI32.#9")])),
            ("\\SHZ\\SYS64\\gdi32.dll", dll([(None, 9, None)]))])
        chain = theme.resolve_export(modules, "USER32", "Paint")
        self.assertEqual([(row["module"], row["symbol"]) for row in chain], [("USER32.DLL", "Paint"), ("GDI32.DLL", "#9")])
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "missing archive export"):
            theme.resolve_export(modules, "GDI32", "#8")
        modules["GDI32.DLL"]["ordinals"][9]["forwarder"] = "USER32.Paint"
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "cyclic"):
            theme.resolve_export(modules, "USER32", "Paint")

    def test_null_ordinal_and_export_table_overflow_fail(self):
        raw = bytearray(dll([("Paint", 7, None)]))
        struct.pack_into("<I", raw, 512 + 0x80, 0)
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "null named"):
            theme.pe_exports(bytes(raw))
        raw = bytearray(dll([("Paint", 7, None)]))
        struct.pack_into("<I", raw, 512 + 20, 70000)
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "counts"):
            theme.pe_exports(bytes(raw))


class OverlayCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.build = self.folder / "build"
        self.build.mkdir()
        self.out = self.build / "theme-v1"
        self.peer = self.folder / "peer"
        self.win64 = self.peer / "build/shizukudos/win64"
        self.win64.mkdir(parents=True)
        for name in theme.handoff.PEER_FILES:
            path = self.peer / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("frozen peer helper " + name)
        packer = self.peer / theme.PACKER_PATH
        packer.parent.mkdir(parents=True, exist_ok=True)
        packer.write_text('def pack_archive(files):\n    return b"SHZARC01"\n')
        self.peer_hashes = {name: theme.handoff.digest_file(self.peer / name) for name in theme.handoff.PEER_FILES}
        self.runner = SimpleNamespace(WIN64=self.win64)
        self.productivity = SimpleNamespace(runner=self.runner)
        self.base = self.win64 / "WIN64.IMG"
        self.base.write_bytes(theme.pack_archive([( "\\SHZ\\SYS64\\user32.dll", dll([("Paint", 7, None)])),
                                                  ("\\SHZ\\DATA\\asset.bin", b"retain exactly")]))
        self.provider_root = self.folder / "provider"
        self.provider_root.mkdir()
        for name in (theme.PROVIDER_BUILDER, "LICENSE"):
            path = self.provider_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("frozen provider source " + name)
        self.provider = self.provider_root / "UXTHEME.DLL"
        self.provider.write_bytes(dll([("DrawThemeBackgroundEx", 47, None)], [("USER32.DLL", ["Paint"])]))
        adapter = self.provider_root / "adapter.c"
        adapter.write_text("status = m98w_create_default(&desc, 2u, &engine);")
        font = self.provider_root / "font.c"
        font.write_text("frozen generated font compiler input")
        self.provider_receipt = self.provider_root / "result.json"
        self.provider_record = {"schema": 1, "status": "STATIC_CANDIDATE_READY_FOR_GUEST_TEST", "structural_build_status": "PASS",
                                "source_root": str(self.provider_root),
                                "source_hashes": {name: theme.handoff.digest_file(self.provider_root / name) for name in (theme.PROVIDER_BUILDER, "LICENSE")},
                                "default_style": {"selection": "modern", "value": 2, "application_local_only": True,
                                                  "lazy_initialization": True, "dllmain_initialization": False,
                                                  "public_api_called_during_initialization": False},
                                "artifact": {"path": str(self.provider), "bytes": self.provider.stat().st_size,
                                             "sha256": theme.handoff.digest_file(self.provider),
                                             "pe_gate": {"status": "PASS", "machine": "AMD64", "format": "PE32+",
                                                         "imports": {"USER32.DLL": ["Paint"]},
                                                         "exports": {"DrawThemeBackgroundEx": 47}}},
                                "adapter_port": {"lazy_creation_replacements": 1,
                                                 "creation_replacement": "status = m98w_create_default(&desc, 2u, &engine);",
                                                 "generated_path": str(adapter), "generated_sha256": theme.handoff.digest_file(adapter)},
                                "private_unicode_transport": {"generated_font_path": str(font),
                                                              "generated_font_sha256": theme.handoff.digest_file(font)},
                                "lineage": {"license": "GPL-2.0-only"}}
        self.rewrite_provider()
        self.image_receipt = self.build / "image.json"
        self.image_receipt.write_text(json.dumps({"app": "signal", "runtime_worktree": str(self.peer),
                                                "runtime_source_hashes": self.peer_hashes}))
        for target, attribute, value in ((theme, "OWN_BUILD", self.build),
                                          (theme.handoff, "check_space", None),
                                          (theme.handoff, "load_peer", None)):
            patcher = patch.object(target, attribute, value) if value is not None else patch.object(target, attribute)
            mock = patcher.start()
            self.addCleanup(patcher.stop)
            if attribute == "load_peer":
                mock.return_value = (self.productivity, self.peer_hashes)
            if attribute == "check_space":
                self.space = mock

    def rewrite_provider(self):
        self.provider_receipt.write_text(json.dumps(self.provider_record))
        self.provider_sha = theme.handoff.digest_file(self.provider_receipt)

    def prepare(self):
        return theme.prepare_overlay(self.base, self.peer, self.provider_receipt, self.provider_sha, self.out)

    def test_private_append_freezes_recipe_and_preserves_every_original_member(self):
        base = self.base.read_bytes()
        result = self.prepare()
        self.assertEqual(self.base.read_bytes(), base)
        self.assertEqual(theme.parse_archive((self.out / "WIN64.IMG").read_bytes())[:-1], theme.parse_archive(base))
        self.assertEqual(theme.verified_overlay(self.out / "theme-overlay.json"), result)
        self.assertEqual(result["actual_archive_import_gate"]["module_count"], 1)
        self.assertFalse(result["vm_started"])
        self.assertFalse(result["app_functionality_verified"])
        self.space.assert_any_call(self.build, unittest.mock.ANY)

    def test_default_off_or_classic_is_rejected_before_writes(self):
        for style, value in (("off", 0), ("classic", 1)):
            self.provider_record["default_style"].update(selection=style, value=value)
            self.rewrite_provider()
            with self.subTest(style=style), self.assertRaisesRegex(theme.ThemeRuntimeError, "Modern"):
                self.prepare()
            self.assertFalse(self.out.exists())

    def test_changed_provider_source_or_pe_receipt_cannot_publish_overlay(self):
        self.provider_record["artifact"]["pe_gate"]["exports"]["DrawThemeBackgroundEx"] = 46
        self.rewrite_provider()
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "PE gate differs"):
            self.prepare()
        self.assertFalse(self.out.exists())
        self.provider_record["artifact"]["pe_gate"]["exports"]["DrawThemeBackgroundEx"] = 47
        self.rewrite_provider()
        (self.provider_root / "LICENSE").write_text("changed source")
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "provider source changed"):
            self.prepare()
        self.assertFalse(self.out.exists())

    def test_baseline_missing_import_is_rejected_without_partial_output(self):
        self.base.write_bytes(theme.pack_archive([( "\\SHZ\\SYS64\\user32.dll", dll([("Other", 1, None)]))]))
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "missing archive export"):
            self.prepare()
        self.assertFalse(self.out.exists())

    def test_generated_adapter_hash_and_modern_initializer_are_bound(self):
        adapter = Path(self.provider_record["adapter_port"]["generated_path"])
        adapter.write_text("status = m98w_create_default(&desc, 0u, &engine);")
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "generated compiler input changed"):
            self.prepare()
        self.assertFalse(self.out.exists())
        self.provider_record["adapter_port"]["generated_sha256"] = theme.handoff.digest_file(adapter)
        self.rewrite_provider()
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "Modern creation anchor"):
            self.prepare()
        self.assertFalse(self.out.exists())

    def test_changed_source_baseline_or_frozen_archive_fails_reverification(self):
        self.prepare()
        self.base.write_bytes(self.base.read_bytes() + b"changed original")
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "original overlay input changed"):
            theme.verified_overlay(self.out / "theme-overlay.json")

    def test_changed_frozen_member_cannot_pass_manifest_gate(self):
        self.prepare()
        target = self.out / "WIN64.IMG"
        raw = bytearray(target.read_bytes())
        raw[-1] ^= 1
        target.chmod(0o600)
        target.write_bytes(raw)
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "derived archive changed"):
            theme.verified_overlay(self.out / "theme-overlay.json")

    def test_run_supplies_derived_archive_then_restores_loader_and_peer_globals(self):
        self.prepare()
        out = self.build / "diagnostic-v1"
        original_loader = theme.handoff.load_peer
        original_sources = theme.handoff.source_hashes()
        def original_run(*args):
            productivity, hashes = theme.handoff.load_peer(self.peer)
            self.assertIs(productivity, self.productivity)
            self.assertEqual(hashes, self.peer_hashes)
            self.assertEqual(productivity.runner.WIN64, self.out)
            self.assertEqual(theme.handoff.source_hashes(), original_sources)
            out.mkdir()
            return 1
        with patch.object(theme.handoff, "run_image", side_effect=original_run):
            code = theme.run_overlay(self.out / "theme-overlay.json", self.image_receipt, out, Path("/fixture/qemu"), "kvm", 90, 2048, [])
        self.assertEqual(code, 1)
        self.assertIs(theme.handoff.load_peer, original_loader)
        self.assertEqual(self.runner.WIN64, self.win64)
        record = theme.handoff.read_json(out / "theme-runtime-result.json")
        self.assertEqual(record["status"], "FAIL")
        self.assertTrue(record["overlay_inputs_preserved"])
        self.assertFalse(record["sealed_theme_runtime_input_verified"])
        self.assertFalse(record["theme_painting_verified"])

    def test_exception_before_original_run_returns_still_restores_global_paths(self):
        self.prepare()
        out = self.build / "diagnostic-v1"
        original_loader = theme.handoff.load_peer
        def failing_run(*args):
            theme.handoff.load_peer(self.peer)
            raise ValueError("fixture preflight failure")
        with patch.object(theme.handoff, "run_image", side_effect=failing_run), self.assertRaisesRegex(ValueError, "preflight"):
            theme.run_overlay(self.out / "theme-overlay.json", self.image_receipt, out, Path("/fixture/qemu"), "kvm", 90, 2048, [])
        self.assertIs(theme.handoff.load_peer, original_loader)
        self.assertEqual(self.runner.WIN64, self.win64)
        self.assertFalse(out.exists())

    def test_reserve_gate_and_unowned_output_prevent_any_payload_write(self):
        self.space.side_effect = theme.handoff.HandoffError("disk reserve gate")
        with self.assertRaisesRegex(ValueError, "reserve gate"):
            self.prepare()
        self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(theme.ThemeRuntimeError, "beneath"):
            theme.prepare_overlay(self.base, self.peer, self.provider_receipt, self.provider_sha, self.folder / "outside")


if __name__ == "__main__":
    unittest.main()
