# SPDX-License-Identifier: GPL-2.0-only
"""Host-only safety gates and independent standard-media validation."""
import importlib.util
import io
import json
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vlc_staging", ROOT / "tools/prepare_vlc_staging.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        for name, mode in entries:
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = mode << 16
            z.writestr(item, b"fixture")
    stream.seek(0)
    return zipfile.ZipFile(stream)


class VlcPreparationTests(unittest.TestCase):
    def rejected(self, entries):
        with archive(entries) as z, self.assertRaises(ValueError):
            module.archive_members(z)

    def test_parent_escape(self):
        self.rejected([("vlc-3.0.24/../outside.dll", stat.S_IFREG)])

    def test_absolute_path(self):
        self.rejected([("/vlc-3.0.24/vlc.exe", stat.S_IFREG)])

    def test_backslash_path(self):
        self.rejected([("vlc-3.0.24/dir\\outside.dll", stat.S_IFREG)])

    def test_symlink(self):
        self.rejected([("vlc-3.0.24/link.dll", stat.S_IFLNK)])

    def test_special_file(self):
        self.rejected([("vlc-3.0.24/device", stat.S_IFCHR)])

    def test_case_collision(self):
        self.rejected([("vlc-3.0.24/vlc.exe", stat.S_IFREG), ("vlc-3.0.24/VLC.EXE", stat.S_IFREG)])

    def test_ordinary_nested_file_and_directory(self):
        with archive([("vlc-3.0.24/plugins/", stat.S_IFDIR),
                      ("vlc-3.0.24/plugins/test.dll", stat.S_IFREG)]) as z:
            self.assertEqual(len(module.archive_members(z)), 2)

    def test_logging_profile_requires_real_publisher_module_not_obsolete_stub(self):
        path = ROOT / "benchmarks/media/vlc-3.0.24/vlc-3.0.24-win32.zip"
        with zipfile.ZipFile(path) as z:
            real = z.read(module.PREFIX + module.FILE_LOGGER)
            stub = z.read(module.PREFIX + "plugins/misc/liblogger_plugin.dll")
        self.assertIn(b"file-logging\0", real)
        self.assertIn(b"logfile\0", real)
        self.assertIn(b"The logger interface no longer exists.", stub)
        self.assertEqual(module.logging_profile({module.FILE_LOGGER: real})["required_options"],
                         ["file-logging", "logfile"])
        for selected in ({}, {module.FILE_LOGGER: stub}, {module.FILE_LOGGER: real[:-1]}):
            with self.assertRaisesRegex(ValueError, "option plugin required"):
                module.logging_profile(selected)

    def test_compiled_provider_table_pointer_and_function_corruptions(self):
        source = ROOT / "build/app-prerequisites-20260930/providers-freestanding/M98WRAP.DLL"
        raw = bytearray(source.read_bytes())
        self.assertIn("FlsAlloc", module.linked_kex_tables(raw)["KERNEL32.DLL"])
        with pefile.PE(data=raw) as pe:
            export = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table")
            offset = pe.get_offset_from_rva(export.address)
        altered = bytearray(raw)
        altered[offset] = 0xCC
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            module.linked_kex_tables(altered)
        altered = bytearray(raw)
        struct.pack_into("<I", altered, offset + 1, 0xFFFFFFFF)
        with self.assertRaisesRegex(ValueError, "file-backed"):
            module.linked_kex_tables(altered)

    def test_original_compiled_kex_copy_initializer_corruption(self):
        source = ROOT / "build/native-npp-controls/installed-core-20260930T1630/KEXBASES.DLL"
        raw = bytearray(source.read_bytes())
        self.assertIn("CreateFileW", module.linked_kex_tables(raw)["KERNEL32.DLL"])
        with pefile.PE(data=raw) as pe:
            export = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table")
            at = pe.get_offset_from_rva(export.address)
            init_rva = export.address + 5 + struct.unpack_from("<i", raw, at + 1)[0]
            copy_at = pe.get_offset_from_rva(init_rva) + 2
        raw[copy_at + 1] = 6
        with self.assertRaisesRegex(ValueError, "descriptor-copy"):
            module.linked_kex_tables(raw)

    def test_new_source_bound_providers_supply_fourteen_candidates(self):
        source = ROOT / "build/vlc-providers-suite-20260930T1826/result.json"
        files, catalog, frozen, receipt = module.provider_inputs(source)
        self.assertEqual(set(files), {"PROVIDE/M98VLC.DLL", "PROVIDE/M98LOC.DLL", "PROVIDE/M98CTX.DLL"})
        self.assertEqual(sum(map(len, catalog.values())), 14)
        self.assertIn("RtlCaptureContext", catalog["KERNEL32.DLL"])
        self.assertIn("RealGetWindowClassW", catalog["USER32.DLL"])
        self.assertIn("RemoveFontResourceExW", catalog["GDI32.DLL"])
        self.assertEqual(len(frozen), 3)
        self.assertEqual(receipt["path"], str(source))

    def test_compiled_indexed_metadata_preserves_three_actual_module_indexes(self):
        raw = (ROOT / "build/vlc-providers-suite-20260930T1826/M98VLC.DLL").read_bytes()
        tables = module.linked_kex_tables(raw, local_functions=True, indexed=True)
        self.assertEqual([(t["index"], t["module"]) for t in tables],
                         [(0, "KERNEL32.DLL"), (1, "GDI32.DLL"), (2, "USER32.DLL")])
        self.assertEqual(tables[1]["names"], ["RemoveFontMemResourceEx", "RemoveFontResourceExW"])
        self.assertEqual(tables[2]["names"], ["RealGetWindowClassW"])
        self.assertTrue(all(not t["ordinals"] for t in tables))
        self.assertEqual([t["target_library"] for t in tables],
                         ["KERNEL32.DLL", "GDI32.DLL", "USER32.DLL"])
        ordinary = module.linked_kex_tables(raw)
        self.assertEqual(ordinary, {t["module"]: set(t["names"]) for t in tables})

    def test_indexed_variants_preserve_duplicate_order_without_changing_catalog_contract(self):
        raw = bytearray((ROOT / "build/vlc-providers-suite-20260930T1826/M98VLC.DLL").read_bytes())
        with pefile.PE(data=raw) as pe:
            export = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table")
            code = pe.get_offset_from_rva(export.address)
            table = struct.unpack_from("<I", raw, code + 1)[0]
            base = pe.OPTIONAL_HEADER.ImageBase
            names = struct.unpack_from("<I", raw, pe.get_offset_from_rva(table - base) + 4)[0]
            offset = pe.get_offset_from_rva(names - base)
        first_name = struct.unpack_from("<I", raw, offset)[0]
        struct.pack_into("<I", raw, offset + 8, first_name)
        tables = module.linked_kex_tables(raw, local_functions=True, indexed=True)
        self.assertEqual(tables[0]["names"],
                         ["GetNativeSystemInfo", "GetNativeSystemInfo", "SetFilePointerEx"])
        with self.assertRaisesRegex(ValueError, "duplicate new provider"):
            module.linked_kex_tables(raw, local_functions=True)

    def test_indexed_variant_metadata_rejects_unsorted_declared_name_array(self):
        raw = bytearray((ROOT / "build/vlc-providers-suite-20260930T1826/M98VLC.DLL").read_bytes())
        with pefile.PE(data=raw) as pe:
            export = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table")
            code = pe.get_offset_from_rva(export.address)
            table = struct.unpack_from("<I", raw, code + 1)[0]
            base = pe.OPTIONAL_HEADER.ImageBase
            names = struct.unpack_from("<I", raw, pe.get_offset_from_rva(table - base) + 4)[0]
            offset = pe.get_offset_from_rva(names - base)
        third_name = struct.unpack_from("<I", raw, offset + 16)[0]
        struct.pack_into("<I", raw, offset, third_name)
        with self.assertRaisesRegex(ValueError, "sorted declaration"):
            module.linked_kex_tables(raw, local_functions=True, indexed=True)

    def test_indexed_variant_metadata_refuses_null_slot_instead_of_shifting_variants(self):
        raw = bytearray((ROOT / "build/vlc-providers-suite-20260930T1826/M98VLC.DLL").read_bytes())
        with pefile.PE(data=raw) as pe:
            export = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table")
            code = pe.get_offset_from_rva(export.address)
            table = struct.unpack_from("<I", raw, code + 1)[0]
            base = pe.OPTIONAL_HEADER.ImageBase
            names = struct.unpack_from("<I", raw, pe.get_offset_from_rva(table - base) + 4)[0]
            offset = pe.get_offset_from_rva(names - base)
        struct.pack_into("<I", raw, offset + 4, 0)
        with self.assertRaisesRegex(ValueError, "null named variant"):
            module.linked_kex_tables(raw, local_functions=True, indexed=True)
        self.assertNotIn("GetNativeSystemInfo", module.linked_kex_tables(raw)["KERNEL32.DLL"])

    def test_new_provider_api_pointer_must_reference_actual_executable_bytes(self):
        path = ROOT / "build/vlc-providers-suite-20260930T1826/M98VLC.DLL"
        raw = bytearray(path.read_bytes())
        module.linked_kex_tables(raw, local_functions=True)
        with pefile.PE(data=raw) as pe:
            export = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table")
            at = pe.get_offset_from_rva(export.address)
            table = struct.unpack_from("<I", raw, at + 1)[0]
            base = pe.OPTIONAL_HEADER.ImageBase
            names = struct.unpack_from("<I", raw, pe.get_offset_from_rva(table - base) + 4)[0]
            function_at = pe.get_offset_from_rva(names - base) + 4
        struct.pack_into("<I", raw, function_at, table)
        with self.assertRaisesRegex(ValueError, "local executable"):
            module.linked_kex_tables(raw, local_functions=True)

    def test_provider_build_native_success_cannot_substitute_compile_only_receipt(self):
        source = ROOT / "build/vlc-providers-suite-20260930T1826/result.json"
        document = json.loads(source.read_text())
        document["native_execution"] = True
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            receipt = Path(directory) / "result.json"
            receipt.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "compile-only"):
                module.provider_inputs(receipt)

    def test_pcm_fixture_standard_library_reads_all_samples(self):
        import wave
        with wave.open(io.BytesIO(module.wav_fixture()), "rb") as media:
            self.assertEqual((media.getnchannels(), media.getsampwidth(), media.getframerate(), media.getnframes()), (1, 2, 22050, 110250))
            self.assertEqual(len(media.readframes(media.getnframes())), 220500)

    def test_avi_fixture_independent_decoder_sixty_distinct_frames(self):
        ffprobe, ffmpeg = shutil.which("ffprobe"), shutil.which("ffmpeg")
        if not ffprobe or not ffmpeg:
            self.skipTest("existing independent media decoder not available")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "VIDEO.AVI"
            path.write_bytes(module.avi_fixture())
            probe = subprocess.run([ffprobe, "-v", "error", "-select_streams", "v:0", "-count_frames", "-show_entries", "stream=codec_name,width,height,r_frame_rate,nb_read_frames", "-of", "json", str(path)], capture_output=True, text=True, timeout=30, check=True)
            stream = json.loads(probe.stdout)["streams"][0]
            self.assertEqual((stream["codec_name"], stream["width"], stream["height"], stream["r_frame_rate"], stream["nb_read_frames"]), ("rawvideo", 160, 120, "2/1", "60"))
            decoded = subprocess.run([ffmpeg, "-v", "error", "-i", str(path), "-f", "framemd5", "-"], capture_output=True, text=True, timeout=30, check=True)
            hashes = [line.rsplit(",", 1)[1].strip() for line in decoded.stdout.splitlines() if line and not line.startswith("#")]
            self.assertEqual(len(hashes), 60)
            self.assertEqual(len(set(hashes)), 60)


if __name__ == "__main__":
    unittest.main()
