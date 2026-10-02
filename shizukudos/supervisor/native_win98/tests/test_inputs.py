#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual descriptor, Linux lease, copy and config guards; no Windows media/VM."""
import hashlib
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_win98_builder", HERE.parent / "build.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class InputTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="win98-domain-host-")
        self.root = Path(self.folder.name)
        self.input = self.root / "source"
        self.data = b"owned real host fixture\r\n" * 100
        self.input.write_bytes(self.data)
        self.pin = hashlib.sha256(self.data).hexdigest()
        if os.environ.get('SHZ_NATIVE_INPUT_TEST_ROOT'):
            # Tiny host tmpfs has no 17 GiB production media capacity. Model
            # that capacity only for this fixture; keep actual 6 GiB+160 MiB
            # RAM/FS floors and production space() arithmetic unchanged.
            real_space = BUILDER.space
            def fixture_space(path, remaining=0):
                stats = os.statvfs(self.root)
                free = stats.f_bavail * stats.f_frsize
                mem = int(next(row.split()[1] for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith('MemAvailable:'))) * 1024
                assert free >= (6 << 30) + (160 << 20) and mem >= (6 << 30) + (160 << 20)
                assert self.root == Path(path).parent or self.root in Path(path).parents
                usage = shutil._ntuple_diskusage(free + BUILDER.RESERVE, 0, free + BUILDER.RESERVE)
                with mock.patch.object(BUILDER.shutil, 'disk_usage', return_value=usage):
                    real_space(path, remaining)
            capacity = mock.patch.object(BUILDER, 'space', fixture_space)
            capacity.start();self.addCleanup(capacity.stop)
            spec = importlib.util.spec_from_file_location('input_fixture_capacity', HERE/'test_input_lease_lifetime.py')
            helper = importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
            child_capacity = mock.patch.object(BUILDER, 'command', helper.fixture_worker_capacity_command(BUILDER.command))
            child_capacity.start();self.addCleanup(child_capacity.stop)

    def tearDown(self):
        self.folder.cleanup()

    def test_real_exact_sha_and_copy(self):
        self.assertEqual(BUILDER.pinned_hash(self.input, self.pin, len(self.data)), len(self.data))
        with BUILDER.read_leased(self.input, self.pin, len(self.data)) as (fd, checkpoint):
            target = self.root / "owned-copy"
            BUILDER.copy_fd(fd, checkpoint, target, self.pin, len(self.data))
        self.assertEqual(target.read_bytes(), self.data)
        self.assertNotEqual(target.stat().st_ino, self.input.stat().st_ino)
        self.assertEqual(self.input.read_bytes(), self.data)

    def test_bad_identity_and_geometry(self):
        for pin, size in (("0" * 64, len(self.data)), (self.pin, len(self.data) + 1), ("invalid", len(self.data))):
            with self.subTest(pin=pin, size=size), self.assertRaises((ValueError, OSError)):
                BUILDER.pinned_hash(self.input, pin, size)

    def test_alias_and_fifo_refused_without_blocking(self):
        alias = self.root / "alias"
        alias.symlink_to(self.input)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (alias, fifo):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                BUILDER.pinned_hash(path, self.pin, len(self.data))

    def test_symlink_parent_and_lexical_device_bypass(self):
        alias = self.root / "linked"
        alias.symlink_to(self.root, target_is_directory=True)
        for path in (alias / "source", Path("/root/../dev/m98-refused"), Path("/root/../proc/m98-refused"), Path("/root/../sys/m98-refused")):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                BUILDER.safe_path(path)

    def test_actual_existing_writer_refuses_lease(self):
        writer = os.open(self.input, os.O_WRONLY | os.O_NONBLOCK)
        try:
            with self.assertRaises((ValueError, OSError, RuntimeError)):
                with BUILDER.read_leased(self.input, self.pin, len(self.data)):
                    self.fail("source with an active writer accepted")
        finally:
            os.close(writer)

    def test_actual_lease_break_and_no_source_write(self):
        with self.assertRaises((ValueError, RuntimeError)):
            with BUILDER.read_leased(self.input, self.pin, len(self.data)) as (_, checkpoint):
                try:
                    writer = os.open(self.input, os.O_WRONLY | os.O_NONBLOCK)
                except BlockingIOError:
                    writer = None
                if writer is not None:
                    os.close(writer)
                    self.fail("incompatible writer acquired leased source")
                checkpoint()
        self.assertEqual(self.input.read_bytes(), self.data)

    def test_existing_copy_destination_is_preserved(self):
        destination = self.root / "existing"
        destination.write_bytes(b"keep this")
        with BUILDER.read_leased(self.input, self.pin, len(self.data)) as (fd, checkpoint):
            with self.assertRaises(FileExistsError):
                BUILDER.copy_fd(fd, checkpoint, destination, self.pin, len(self.data))
        self.assertEqual(destination.read_bytes(), b"keep this")

    def test_actual_lease_break_after_read_before_owned_data_write(self):
        destination = self.root / "interrupted-owned-copy"
        original_read = os.read
        broke = False

        def read_then_request_writer(fd, count):
            nonlocal broke
            block = original_read(fd, count)
            if block and not broke:
                broke = True
                try:
                    writer = os.open(self.input, os.O_WRONLY | os.O_NONBLOCK)
                except BlockingIOError:
                    writer = None
                if writer is not None:
                    os.close(writer)
                    self.fail("writer acquired a read-leased source")
            return block

        with self.assertRaises(RuntimeError):
            with BUILDER.read_leased(self.input, self.pin, len(self.data)) as (fd, checkpoint):
                with mock.patch.object(BUILDER.os, "read", read_then_request_writer):
                    BUILDER.copy_fd(fd, checkpoint, destination, self.pin, len(self.data))
        self.assertTrue(broke)
        self.assertEqual(destination.read_bytes(), b"")
        self.assertEqual(self.input.read_bytes(), self.data)

    def test_semantic_checks_use_actual_pinned_descriptor(self):
        config = self.root / "config"
        config.write_bytes(BUILDER.config_bytes())
        rom = self.root / "rom"
        rom_bytes = bytearray(BUILDER.ROM_BYTES)
        rom_bytes[:7] = b"SeaBIOS"
        rom_bytes[-16] = 0xEA
        rom.write_bytes(rom_bytes)
        mbr = self.root / "mbr"
        mbr.write_bytes(bytes(510) + b"\x55\xaa")
        for name, path in (("WIN98CFG.BIN", config), ("SEABIOS.BIN", rom), ("DISK.IMG", mbr)):
            with self.subTest(name=name):
                data = path.read_bytes()
                pin = hashlib.sha256(data).hexdigest()
                with BUILDER.read_leased(path, pin, len(data)) as (fd, checkpoint):
                    BUILDER.validate_contents(name, fd)
                    checkpoint()
                    self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
                path.write_bytes(bytes(len(data)))
                pin = BUILDER.file_sha(path)
                with BUILDER.read_leased(path, pin, len(data)) as (fd, _):
                    with self.assertRaises(ValueError):
                        BUILDER.validate_contents(name, fd)

    def test_config_bytes_and_refusal(self):
        config = BUILDER.config_bytes()
        self.assertEqual(config.hex(), "53573938010000008000000000000000")
        self.assertIsNone(BUILDER.validate_config(config))
        for changed in (config[:-1], config + b"\0", bytes(16), config[:4] + bytes.fromhex("02000000") + config[8:], config[:-4] + bytes.fromhex("01000000")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                BUILDER.validate_config(changed)

    def test_owned_output_no_devices_or_existing_tree(self):
        for path in (self.root, Path("/root/../dev/m98-refused")):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                BUILDER.fresh_output(path)
        self.assertEqual(BUILDER.fresh_output(self.root / "new"), self.root / "new")

    def test_cli_exact_geometry_validate_only_is_not_os_validation(self):
        disk = self.root / "synthetic-2g-mbr"
        with disk.open("xb") as stream:
            stream.truncate(BUILDER.DISK_BYTES)
            stream.seek(510)
            stream.write(b"\x55\xaa")
        rom = self.root / "synthetic-rom"
        data = bytearray(BUILDER.ROM_BYTES)
        data[:7] = b"SeaBIOS"
        data[-16] = 0xEA
        rom.write_bytes(data)
        config = self.root / "config"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(BUILDER.main(["--make-config", str(config)]), 0)
        kernel32, kernel64 = self.root / "synthetic-kernel32", self.root / "synthetic-kernel64"
        kernel32.write_bytes(b"synthetic Kernel32 input; not executable")
        kernel64.write_bytes(b"synthetic Kernel64 input; not executable")
        args = []
        for name, path in (("disk", disk), ("rom", rom), ("config", config),
                           ("kernel32", kernel32), ("kernel64", kernel64)):
            args += ["--" + name, str(path), "--" + name + "-sha256", BUILDER.file_sha(path)]
        output = io.StringIO()
        before = set(self.root.iterdir())
        with contextlib.redirect_stdout(output):
            self.assertEqual(BUILDER.main(args + ["--validate-only"]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "PASS_EXPLICIT_INPUT_VALIDATION_NO_BUILD_OR_VM")
        self.assertFalse(result["Windows98_installation_identity_verified"])
        self.assertFalse(result["Windows98_executed"])
        self.assertEqual(set(self.root.iterdir()), before)
        with self.assertRaises(FileExistsError), contextlib.redirect_stdout(io.StringIO()):
            BUILDER.main(["--make-config", str(config)])
        self.assertEqual(config.read_bytes(), BUILDER.config_bytes())

    def test_cli_missing_foundation_worker_refuses_before_private_reads(self):
        # The actual publisher needs both real worker domains. A disk-only ESP
        # must fail before media reads/copies, not later during native boot.
        for absent in ('kernel32', 'kernel64'):
            args = []
            for name in ('disk', 'rom', 'config', 'kernel32', 'kernel64'):
                if name != absent:
                    args += ['--' + name, str(self.input), '--' + name + '-sha256', self.pin]
            output = self.root / ('refused-' + absent)
            with self.subTest(absent=absent), mock.patch.object(BUILDER, 'pinned_hash', side_effect=AssertionError('private read before required worker check')), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    BUILDER.main(args + ['--out', str(output), '--validate-only'])
                self.assertEqual(error.exception.code, 2)
                self.assertFalse(output.exists())

    def test_cli_missing_private_pins_refuses_without_output(self):
        output = self.root / "refused-output"
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            BUILDER.main(["--disk", str(self.input), "--out", str(output)])
        self.assertFalse(output.exists())

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("mkfs.vfat", "mmd", "mcopy")), "mtools/dosfstools absent")
    def test_actual_fat_member_byte_readback_synthetic_profile(self):
        # A small FAT fixture tests actual packaging, never a Windows/VM proof.
        out = self.root / "synthetic-fat"
        out.mkdir()
        loader = self.root / "fixture-loader"
        loader.write_bytes(b"synthetic EFI fixture; not executable\r\n")
        copies = {}
        for name, data in (("DISK.IMG", self.data), ("SEABIOS.BIN", b"synthetic fixture ROM"), ("WIN98CFG.BIN", BUILDER.config_bytes())):
            path = out / name
            path.write_bytes(data)
            copies[name] = path
        receipt = {"commands": []}
        with mock.patch.object(BUILDER, "ESP_MIB", 64):
            esp, members = BUILDER.assemble(out, copies, loader, receipt)
        self.assertEqual(esp.stat().st_size, 64 << 20)
        self.assertEqual(set(members), {"EFI/BOOT/BOOTX64.EFI", "EFI/SHIZUKU/BOOT.INI", "SHZDOS/DISK.IMG", "SHZDOS/SEABIOS.BIN", "SHZDOS/WIN98CFG.BIN"})
        self.assertEqual(members["EFI/BOOT/BOOTX64.EFI"]["sha256"], BUILDER.file_sha(loader))
        self.assertEqual((out / "BOOT.INI").read_bytes(), b"mode=supervisor\r\nmenu_timeout=0\r\n")
        self.assertFalse((out / "readback-owned.tmp").exists())
        self.assertEqual(copies["DISK.IMG"].read_bytes(), self.data)

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("mkfs.vfat", "mmd", "mcopy")), "mtools/dosfstools absent")
    def test_actual_fat_corrupt_readback_refuses_and_preserves_failed_output(self):
        out = self.root / "synthetic-corrupt-fat"
        out.mkdir()
        loader = self.root / "fixture-loader"
        loader.write_bytes(b"synthetic EFI fixture; not executable\r\n")
        original = BUILDER.command

        def corrupt_after_readback(argv, receipt, *args, **kwargs):
            original(argv, receipt, *args, **kwargs)
            if str(argv[0]) == "mcopy" and str(argv[-1]) == "::/EFI/BOOT/BOOTX64.EFI":
                corrupt = out / "owned-corruption-fixture"
                corrupt.write_bytes(b"corrupted actual FAT member")
                original(["mcopy", "-o", "-i", argv[2], corrupt, argv[-1]], receipt)

        with mock.patch.object(BUILDER, "ESP_MIB", 64), mock.patch.object(BUILDER, "command", corrupt_after_readback):
            with self.assertRaisesRegex(ValueError, "ESP byte readback mismatch"):
                BUILDER.assemble(out, {}, loader, {"commands": []})
        self.assertTrue((out / "esp-win98.img").is_file())
        self.assertFalse((out / "readback-owned.tmp").exists())
        self.assertEqual((out / "owned-corruption-fixture").read_bytes(), b"corrupted actual FAT member")
        self.assertEqual(loader.read_bytes(), b"synthetic EFI fixture; not executable\r\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
