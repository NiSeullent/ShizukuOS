# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic media only: hidden OEM boot files validate input, never boot it."""
from __future__ import annotations

import hashlib
import importlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_shizuku_se_iso as builder

PAYLOADS = {"IO.SYS": b"SYNTHETIC-IO-" * 58 + b"END!",
            "MSDOS.SYS": b"SYNTHETIC-MSDOS\r\n", "COMMAND.COM": b"SYNTHETIC-COMMAND\r\n"}
BOOT_OFFSET = 24 * 2048
ROOT_OFFSET = 19 * 512
DATA_OFFSET = 33 * 512


def set_fat(image, cluster, value):
    for start in (512, 10 * 512):
        offset = start + cluster * 3 // 2
        word = struct.unpack_from("<H", image, offset)[0]
        word = (word & 15) | (value << 4) if cluster & 1 else (word & 0xf000) | value
        struct.pack_into("<H", image, offset, word)


def floppy():
    image = bytearray(1474560)
    image[:11] = b"\xeb\x3c\x90SYNTHDOS"
    struct.pack_into("<HBHBHHBHHHII", image, 11, 512, 1, 1, 2, 224, 2880, 0xf0, 9, 18, 2, 0, 0)
    image[510:512] = b"\x55\xaa"
    image[512:515] = image[5120:5123] = b"\xf0\xff\xff"
    for cluster, value in ((2, 3), (3, 0xfff), (4, 0xfff), (5, 0xfff)):
        set_fat(image, cluster, value)
    for n, (name, content) in enumerate(PAYLOADS.items()):
        stem, ext = name.split(".")
        entry = ROOT_OFFSET + n * 32
        image[entry:entry + 11] = (stem.ljust(8) + ext.ljust(3)).encode()
        image[entry + 11] = 0x27 if name.endswith("SYS") else 0x20
        cluster = (2, 4, 5)[n]
        struct.pack_into("<H", image, entry + 26, cluster)
        struct.pack_into("<I", image, entry + 28, len(content))
        offset = DATA_OFFSET + (cluster - 2) * 512
        image[offset:offset + len(content)] = content
    return image


def sparse_write(path, data):
    with path.open("wb") as handle:
        handle.truncate(len(data))
        for start in range(0, len(data), 4096):
            chunk = data[start:start + 4096]
            if any(chunk):
                handle.seek(start)
                handle.write(chunk)


def synthetic_iso(path, boot=None):
    image = bytearray(768 * 2048)
    for sector, kind in ((16, 1), (17, 0), (18, 255)):
        start = sector * 2048
        image[start:start + 7] = bytes([kind]) + b"CD001\x01"
    struct.pack_into("<I", image, 16 * 2048 + 80, 768)
    struct.pack_into(">I", image, 16 * 2048 + 84, 768)
    struct.pack_into("<H", image, 16 * 2048 + 128, 2048)
    struct.pack_into(">H", image, 16 * 2048 + 130, 2048)
    image[17 * 2048 + 7:17 * 2048 + 39] = b"EL TORITO SPECIFICATION".ljust(32, b"\0")
    struct.pack_into("<I", image, 17 * 2048 + 71, 20)
    catalog = bytearray(2048)
    catalog[0], catalog[30], catalog[31] = 1, 0x55, 0xaa
    struct.pack_into("<H", catalog, 28, (-sum(struct.unpack("<16H", catalog[:32]))) & 0xffff)
    catalog[32], catalog[33] = 0x88, 2
    struct.pack_into("<H", catalog, 38, 1)
    struct.pack_into("<I", catalog, 40, 24)
    image[20 * 2048:21 * 2048] = catalog
    image[BOOT_OFFSET:BOOT_OFFSET + 1474560] = boot if boot is not None else floppy()
    sparse_write(path, image)
    return path


class BootMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.iso = synthetic_iso(self.base / "synthetic.iso")

    def helper(self):
        return importlib.import_module("win98_boot_media")

    def test_reads_all_three_hidden_files_without_source_writes(self):
        self.iso.chmod(0o444)
        before = self.iso.stat()
        report = self.helper().inspect_boot_media(self.iso)
        self.assertEqual(report["boot_offset"], 49152)
        self.assertEqual(report["boot_bytes"], 1474560)
        self.assertEqual(set(report["files"]), {"IO.SYS", "MSDOS.SYS", "COMMAND.COM"})
        for name, data in PAYLOADS.items():
            self.assertEqual(report["files"][name]["bytes"], len(data))
            self.assertEqual(report["files"][name]["sha256"], hashlib.sha256(data).hexdigest())
        after = self.iso.stat()
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode),
                         (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode))
        self.assertFalse(report["DOS_replacement_verified"])

    def test_rejects_bad_catalog_checksum(self):
        with self.iso.open("r+b") as handle:
            handle.seek(20 * 2048 + 4)
            handle.write(b"!")
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().inspect_boot_media(self.iso)

    def test_rejects_boot_extent_outside_iso(self):
        with self.iso.open("r+b") as handle:
            handle.seek(20 * 2048 + 40)
            handle.write(struct.pack("<I", 767))
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().inspect_boot_media(self.iso)

    def test_rejects_truncated_iso(self):
        with self.iso.open("r+b") as handle:
            handle.truncate(BOOT_OFFSET + 1000)
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().inspect_boot_media(self.iso)

    def test_rejects_invalid_iso_descriptors_and_catalog_profile(self):
        for offset, value in ((16 * 2048 + 84, b"\0\0\0\0"),
                              (17 * 2048 + 71, struct.pack("<I", 769)),
                              (20 * 2048 + 33, b"\0")):
            with self.subTest(offset=offset):
                synthetic_iso(self.iso)
                with self.iso.open("r+b") as handle:
                    handle.seek(offset)
                    handle.write(value)
                with self.assertRaises(self.helper().BootMediaError):
                    self.helper().inspect_boot_media(self.iso)

    def test_rejects_invalid_bpb_and_required_file_size(self):
        for offset, value in ((11, struct.pack("<H", 4096)), (17, struct.pack("<H", 65535)),
                              (ROOT_OFFSET + 28, struct.pack("<I", 0xffffffff))):
            with self.subTest(offset=offset):
                image = floppy()
                image[offset:offset + len(value)] = value
                synthetic_iso(self.iso, image)
                with self.assertRaises(self.helper().BootMediaError):
                    self.helper().inspect_boot_media(self.iso)

    def test_rejects_source_symlink(self):
        alias = self.base / "source-alias.iso"
        alias.symlink_to(self.iso)
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().inspect_boot_media(alias)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_rejects_fifo_without_waiting_for_a_writer(self):
        fifo = self.base / "source.fifo"
        os.mkfifo(fifo)
        code = ("import sys; sys.path.insert(0,sys.argv[1]); import win98_boot_media as m\n"
                "try: m.inspect_boot_media(sys.argv[2])\n"
                "except m.BootMediaError: sys.exit(0)\n"
                "sys.exit(1)\n")
        try:
            child = subprocess.run([sys.executable, "-B", "-c", code, str(ROOT / "tools"), str(fifo)],
                                   timeout=2, capture_output=True)
        except subprocess.TimeoutExpired:
            self.fail("non-regular FIFO input blocked waiting for a writer")
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))

    def test_rejects_fat_copy_disagreement(self):
        image = floppy()
        image[512 + 3] ^= 1
        synthetic_iso(self.iso, image)
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().inspect_boot_media(self.iso)

    def test_rejects_loop_and_premature_or_overlong_chains(self):
        for cluster, value in ((2, 2), (2, 0xfff), (3, 4), (2, 0xff7)):
            with self.subTest(cluster=cluster, value=value):
                image = floppy()
                set_fat(image, cluster, value)
                synthetic_iso(self.iso, image)
                with self.assertRaises(self.helper().BootMediaError):
                    self.helper().inspect_boot_media(self.iso)

    def test_rejects_missing_and_duplicate_required_file(self):
        for duplicate in (False, True):
            image = floppy()
            if duplicate:
                image[ROOT_OFFSET + 96:ROOT_OFFSET + 128] = image[ROOT_OFFSET:ROOT_OFFSET + 32]
            else:
                image[ROOT_OFFSET] = 0xe5
            synthetic_iso(self.iso, image)
            with self.assertRaises(self.helper().BootMediaError):
                self.helper().inspect_boot_media(self.iso)

    def test_rejects_unsafe_root_name_and_required_directory(self):
        for unsafe in (False, True):
            image = floppy()
            if unsafe:
                image[ROOT_OFFSET + 96:ROOT_OFFSET + 107] = b"BAD/PATHSYS"
                image[ROOT_OFFSET + 107] = 0x20
            else:
                image[ROOT_OFFSET + 11] = 0x10
            synthetic_iso(self.iso, image)
            with self.assertRaises(self.helper().BootMediaError):
                self.helper().inspect_boot_media(self.iso)

    def test_extracts_only_fixed_names_into_existing_ignored_private_directory(self):
        stage = self.base / "private"
        stage.mkdir(mode=0o700)
        report = self.helper().extract_boot_files(self.iso, stage)
        self.assertEqual({p.name for p in stage.iterdir()}, set(PAYLOADS))
        for name, data in PAYLOADS.items():
            self.assertEqual((stage / name).read_bytes(), data)
        self.assertFalse(report["DOS_replacement_verified"])

    def test_extraction_refuses_existing_files_and_symlink_stage(self):
        stage = self.base / "private"
        stage.mkdir(mode=0o700)
        (stage / "IO.SYS").write_bytes(b"KEEP")
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().extract_boot_files(self.iso, stage)
        self.assertEqual((stage / "IO.SYS").read_bytes(), b"KEEP")
        self.assertEqual(len(list(stage.iterdir())), 1)
        alias = self.base / "alias"
        alias.symlink_to(stage, target_is_directory=True)
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().extract_boot_files(self.iso, alias)

    def test_extraction_refuses_repository_source_directory(self):
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().extract_boot_files(self.iso, ROOT / "tests")

    def test_extraction_refuses_private_but_unignored_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix="synthetic-media-test-") as temp:
            stage = Path(temp)
            with self.assertRaises(self.helper().BootMediaError):
                self.helper().extract_boot_files(self.iso, stage)
            self.assertEqual(list(stage.iterdir()), [])

    def test_extraction_refuses_dangling_output_symlink_before_other_copies(self):
        stage = self.base / "private"
        stage.mkdir(mode=0o700)
        (stage / "COMMAND.COM").symlink_to(self.base / "absent")
        with self.assertRaises(self.helper().BootMediaError):
            self.helper().extract_boot_files(self.iso, stage)
        self.assertEqual([p.name for p in stage.iterdir()], ["COMMAND.COM"])


class Win98BuilderFallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def tree(self, with_cab=True):
        tree = self.base / "tree"
        (tree / "WIN98").mkdir(parents=True)
        if with_cab:
            cab = bytearray(36 + 16)
            cab[:4] = b"MSCF"
            struct.pack_into("<I", cab, 16, 36)
            struct.pack_into("<H", cab, 28, 1)
            cab.extend(b"COMMAND.COM\0")
            (tree / "WIN98" / "SYNTH.CAB").write_bytes(cab)
        return tree

    def real_iso(self, corrupt=False):
        if not shutil.which("xorriso"):
            self.skipTest("xorriso not installed")
        tree = self.tree()
        sparse_write(tree / "OEMBOOT.IMG", floppy())
        iso = self.base / "fixture.iso"
        subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-b", "OEMBOOT.IMG", "-o", str(iso), str(tree)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if corrupt:
            with iso.open("r+b") as handle:
                handle.seek(17 * 2048 + 71)
                catalog_lba = struct.unpack("<I", handle.read(4))[0]
                handle.seek(catalog_lba * 2048 + 4)
                handle.write(b"!")
        return iso

    def test_valid_hidden_oem_files_are_accepted_as_media_reference(self):
        iso = self.real_iso()
        before = iso.stat()
        try:
            report = builder.inspect_win98_media(iso, self.base / "work")
        except builder.Win98MediaError as error:
            self.fail(f"valid hidden OEM boot files must satisfy media input validation: {error}")
        self.assertEqual(report["cabinets"], 1)
        self.assertIn("El Torito", report["required"]["IO.SYS"])
        self.assertIn("El Torito", report["required"]["MSDOS.SYS"])
        self.assertEqual(report["required"]["COMMAND.COM"], "inside a WIN98 cabinet")
        self.assertFalse(report["boot_media"]["DOS_replacement_verified"])
        self.assertEqual(before.st_mtime_ns, iso.stat().st_mtime_ns)

    def test_corrupt_hidden_boot_catalog_is_rejected_and_stage_removed(self):
        iso = self.real_iso(corrupt=True)
        with self.assertRaises(builder.Win98MediaError):
            builder.inspect_win98_media(iso, self.base / "work")
        self.assertFalse((self.base / "work" / "win98-media-tree").exists())

    def test_directory_input_still_rejects_missing_files(self):
        with self.assertRaises(builder.Win98MediaError):
            builder.inspect_win98_media(self.tree(), self.base / "work")

    def test_no_cab_directory_cannot_be_rescued_by_hidden_file_metadata(self):
        with self.assertRaises(builder.Win98MediaError):
            builder.find_win98_layout(self.tree(with_cab=False), boot_files={name: {} for name in PAYLOADS})

    def test_existing_loose_and_cab_validation_still_works(self):
        tree = self.tree()
        (tree / "IO.SYS").write_bytes(b"SYNTHETIC IO")
        (tree / "MSDOS.SYS").write_bytes(b"SYNTHETIC MSDOS")
        report = builder.find_win98_layout(tree)
        self.assertEqual(report["required"], {"IO.SYS": "loose file", "MSDOS.SYS": "loose file",
                                              "COMMAND.COM": "inside a WIN98 cabinet"})

    def test_complete_iso_tree_does_not_need_an_oem_boot_entry(self):
        if not shutil.which("xorriso"):
            self.skipTest("xorriso not installed")
        tree = self.tree()
        (tree / "IO.SYS").write_bytes(b"SYNTHETIC IO")
        (tree / "MSDOS.SYS").write_bytes(b"SYNTHETIC MSDOS")
        iso = self.base / "fixture.iso"
        subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-o", str(iso), str(tree)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report = builder.inspect_win98_media(iso, self.base / "work")
        self.assertNotIn("boot_media", report)

    def test_symlink_tree_remains_rejected_even_with_boot_metadata(self):
        tree = self.tree()
        (tree / "IO.SYS").symlink_to(tree / "WIN98" / "SYNTH.CAB")
        with self.assertRaises(builder.Win98MediaError):
            builder.find_win98_layout(tree, boot_files={name: {} for name in PAYLOADS})


if __name__ == "__main__":
    unittest.main()
