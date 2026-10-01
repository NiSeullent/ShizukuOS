#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed evidence checks for the desktop runner; never starts a VM."""
import json
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_k64_desktop as runner


class DesktopEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.args = types.SimpleNamespace(timeout=5, step_timeout=0.025, memory=512, accel="tcg", qemu="qemu",
                                          firmware_code="CODE.fd", firmware_vars="VARS.fd")
        self.proc = types.SimpleNamespace(poll=lambda: None)
        self.qmp = types.SimpleNamespace(call=lambda *a: {"running": True})
        self.items = []
        self.guest = runner.Guest(self.proc, self.qmp, self.work, self.args, self.items)

    def tearDown(self):
        self.tmp.cleanup()

    def log(self, text):
        (self.work / "serial.log").write_text(text)

    def test_early_exit_is_not_a_persistent_desktop(self):
        self.log("SHZ-DESKTOP READY width=1024 height=768\nSHZ-EXIT:0\n")
        with self.assertRaisesRegex(runner.EvidenceError, "before an explicit F10"):
            self.guest.healthy()

    def test_fatal_import_or_process_fault_cannot_be_hidden_by_ready(self):
        for line in ("K64 desktop: result start-failed status=c0000135", "SHZ-DESKTOP ERROR operation=Save error=5",
                     "K64: process 7 killed", "K64 desktop: result wait-failed pid=7 rc=-1"):
            self.log("SHZ-DESKTOP READY width=1024 height=768\n" + line)
            with self.assertRaises(runner.EvidenceError):
                self.guest.healthy()

    def test_old_marker_cannot_satisfy_a_later_action(self):
        self.log("SHZ-DESKTOP OPENED path=D:\\DESKTOP.TXT bytes=25\n")
        offset = len(self.guest.serial())
        with self.assertRaisesRegex(runner.EvidenceError, "missing marker"):
            self.guest.wait(runner.OPENED, offset)
        self.log(self.guest.serial() + "SHZ-DESKTOP OPENED path=D:\\DESKTOP.TXT bytes=25\n")
        self.assertEqual(self.guest.wait(runner.OPENED, offset).group(1), "25")

    def test_paused_guest_is_not_idle_persistence(self):
        self.qmp.call = lambda *a: {"running": False, "status": "paused"}
        with self.assertRaises(runner.EvidenceError):
            self.guest.observe(0, "still running")

    def test_command_uses_private_writable_data_disk_before_boot_esp(self):
        cmd = runner.command_for(self.args, self.work, self.work / "qmp.sock", "private-esp.img", "private-data.img", "private-vars.fd")
        disks = [cmd[i + 1] for i, value in enumerate(cmd[:-1]) if value == "-drive"]
        self.assertIn("file=private-data.img", disks[2])
        self.assertIn("file=private-esp.img", disks[3])
        self.assertTrue(all("snapshot=on" not in x for x in disks))
        self.assertNotIn("-kernel", cmd)
        self.assertEqual(cmd[cmd.index("-net") + 1], "none")

    def test_iso_is_a_readonly_cd_on_port_one_and_data_remains_writable(self):
        self.args.boot_iso = Path("shipped.iso")
        cmd = runner.command_for(self.args, self.work, self.work / "qmp.sock", "frozen.iso", "private-data.img", "private-vars.fd")
        disks = [cmd[i + 1] for i, value in enumerate(cmd[:-1]) if value == "-drive"]
        self.assertIn("id=data", disks[2])
        self.assertNotIn("readonly=on", disks[2])
        self.assertIn("file=frozen.iso", disks[3])
        self.assertIn("readonly=on,media=cdrom", disks[3])
        self.assertIn("ide-cd,drive=boot,bus=ide.1,bootindex=1", cmd)
        self.assertNotIn("-kernel", cmd)

    def test_selftest_or_conflicting_shipped_iso_config_is_rejected(self):
        runner.verify_shipped_config(b"mode = kernel64\r\n", b"cmdline = shz.desktop\r\n", [])
        for boot, kernel in ((b"mode=auto\n", b"cmdline=shz.desktop\n"),
                             (b"mode=kernel64\n", b"cmdline=shz.selftest\n"),
                             (b"mode=kernel64\nmode=auto\n", b"cmdline=shz.desktop\n")):
            with self.assertRaises(runner.EvidenceError):
                runner.verify_shipped_config(boot, kernel, [])

    def test_catalog_selects_actual_uefi_image_and_rejects_corruption(self):
        iso = self.work / "test.iso"
        data = bytearray(32 * 2048)
        record = bytearray(2048)
        record[0] = 0
        record[1:6] = b"CD001"
        record[7:30] = b"EL TORITO SPECIFICATION"
        struct.pack_into("<I", record, 0x47, 20)
        data[16 * 2048:17 * 2048] = record
        catalog = bytearray(2048)
        catalog[0] = 1
        catalog[30:32] = b"\x55\xaa"
        struct.pack_into("<H", catalog, 28, (-sum(struct.unpack_from("<16H", catalog))) & 0xFFFF)
        catalog[64:66] = b"\x91\xef"
        struct.pack_into("<H", catalog, 66, 1)
        catalog[96:98] = b"\x88\x00"
        struct.pack_into("<I", catalog, 104, 25)
        data[20 * 2048:21 * 2048] = catalog
        iso.write_bytes(data)
        self.assertEqual(runner.iso_uefi_lba(iso), 25)
        data[20 * 2048 + 30] = 0
        iso.write_bytes(data)
        with self.assertRaises(runner.EvidenceError):
            runner.iso_uefi_lba(iso)

    def test_runtime_without_source_binding_or_with_stale_source_is_rejected(self):
        files = {n: self.work / n for n in runner.ARTIFACTS}
        for name, path in files.items():
            path.write_bytes(name.encode())
        src = self.work / "runtime.c"
        src.write_bytes(b"new source")
        receipts = {
            "loader": {"artifacts": {"BOOTX64.EFI": {"sha256": runner.sha(files["BOOTX64.EFI"])}},
                       "sources_sha256": {"runtime.c": runner.sha(src)}},
            "kernel": {"kernels": {"kernel64-standalone": {"sha256": runner.sha(files["KERNEL64S.BIN"])}},
                       "sources_sha256": {"runtime.c": runner.sha(src)}},
            "runtime": {"archive": {"sha256": runner.sha(files["WIN64.IMG"]), "files": [runner.SHELL_PATH]}}}
        paths = {n: self.work / (n + ".json") for n in receipts}
        for n, data in receipts.items():
            paths[n].write_text(json.dumps(data))
        with patch.object(runner, "ARTIFACTS", files), patch.object(runner, "RECEIPTS", paths), patch.object(runner, "REPO", self.work):
            with self.assertRaisesRegex(runner.EvidenceError, "runtime build records source hashes"):
                runner.verify_inputs([])
            receipts["runtime"]["sources_sha256"] = {"runtime.c": "0" * 64}
            paths["runtime"].write_text(json.dumps(receipts["runtime"]))
            with self.assertRaisesRegex(runner.EvidenceError, "runtime build matches current source"):
                runner.verify_inputs([])

    def test_exact_saved_bytes_include_the_editor_lf_not_crlf(self):
        self.assertEqual(runner.EXPECTED, b"uefi desktop persistence\n")
        self.assertEqual(len(runner.EXPECTED), 25)
        self.assertEqual(runner.content_line(runner.EXPECTED), "uefi desktop persistence\\n")


if __name__ == "__main__":
    unittest.main()
