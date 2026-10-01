#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real owned-file copying and exact pinned VM-plan guards; no VM is launched."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_vm_preparation", Path(__file__).resolve().parents[1] / "prepare_vm.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class VmPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shz-vm-plan-")
        self.root = Path(self.temp.name)
        self.files = {}
        for name, size in (("esp", 4 << 20), ("firmware-code", 3 << 20), ("firmware-vars", 1 << 20)):
            path = self.root / name
            with path.open("xb") as stream:
                stream.truncate(size)
                stream.write(b"synthetic fixture; not executable firmware\r\n")
            self.files[name] = path
        qemu = self.root / "fixture-qemu"
        qemu.write_bytes(b"#!/bin/sh\nexit 99\n")
        qemu.chmod(0o700)
        self.files["qemu"] = qemu
        self.receipt = {"status": "PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN", "private": True,
                        "VM_executed": False, "source_before_after_match": True, "originals_before_after_match": True,
                        "artifact": {"bytes": 4 << 20, "sha256": PREPARE.BUILDER.file_sha(self.files["esp"])},
                        "members": {"SHZDOS/" + name: {"bytes": size, "sha256": "a" * 64}
                                    for name, size in (("DISK.IMG", 2 << 30), ("SEABIOS.BIN", 256 << 10), ("WIN98CFG.BIN", 16))}}
        path = self.root / "fixture-builder-receipt.json"
        path.write_text(json.dumps(self.receipt))
        self.files["build-receipt"] = path

    def tearDown(self):
        self.temp.cleanup()

    def arguments(self, out):
        args = ["--out", str(out)]
        for name, path in self.files.items():
            args += ["--" + name, str(path), "--" + name + "-sha256", PREPARE.BUILDER.file_sha(path)]
        return args

    def test_actual_distinct_copies_and_exact_no_launch_plan(self):
        output = self.root / "fresh"
        before = {name: PREPARE.BUILDER.file_sha(path) for name, path in self.files.items()}
        with mock.patch.object(PREPARE.BUILDER, "ESP_MIB", 4), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(PREPARE.main(self.arguments(output)), 0)
        result = json.loads((output / "vm-plan.json").read_text())
        self.assertEqual(result["status"], "PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN")
        self.assertTrue(result["private"])
        self.assertFalse(result["VM_executed"])
        self.assertFalse(result["Windows98_boot_verified"])
        self.assertFalse(result["MS_DOS_replaced"])
        command = result["qemu_argv"]
        self.assertEqual(command[0], str(self.files["qemu"]))
        self.assertIn("host,+vmx", command)
        self.assertIn("4096M", command)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertTrue(any("readonly=on,file=" + str(output / "OVMF_CODE.fd") in arg for arg in command))
        self.assertTrue(any("file=" + str(output / "esp.img") in arg for arg in command))
        for key, name in (("esp", "esp.img"), ("firmware-code", "OVMF_CODE.fd"), ("firmware-vars", "OVMF_VARS.fd")):
            target = output / name
            self.assertEqual(PREPARE.BUILDER.file_sha(target), before[key])
            self.assertNotEqual(target.stat().st_ino, self.files[key].stat().st_ino)
        self.assertEqual({name: PREPARE.BUILDER.file_sha(path) for name, path in self.files.items()}, before)
        self.assertFalse((output / "serial.log").exists())
        self.assertFalse((output / "qmp.sock").exists())

    def test_wrong_firmware_flash_geometry_refuses(self):
        for code, variables in ((0, 4 << 20), (4 << 20, 0), (3 << 20, 512 << 10), (5 << 20, 1 << 20)):
            with self.subTest(code=code, variables=variables), self.assertRaises(ValueError):
                PREPARE.firmware_geometry(code, variables)

    def test_builder_receipt_and_esp_pin_must_match_before_output(self):
        path = self.files["build-receipt"]
        for field, value in (("status", "FAIL_BUILD_PRESERVED"), ("VM_executed", True), ("private", False)):
            with self.subTest(field=field):
                changed = {**self.receipt, field: value}
                path.write_text(json.dumps(changed))
                output = self.root / ("refused-" + field)
                with mock.patch.object(PREPARE.BUILDER, "ESP_MIB", 4), self.assertRaises(ValueError):
                    PREPARE.main(self.arguments(output))
                self.assertFalse(output.exists())
        changed = {**self.receipt, "artifact": {"bytes": 4 << 20, "sha256": "0" * 64}}
        path.write_text(json.dumps(changed))
        output = self.root / "refused-esp"
        with mock.patch.object(PREPARE.BUILDER, "ESP_MIB", 4), self.assertRaises(ValueError):
            PREPARE.main(self.arguments(output))
        self.assertFalse(output.exists())

    def test_qemu_option_injection_and_socket_extent_refused(self):
        for qemu, out in ((Path("/tmp/qemu,invalid"), self.root / "new"),
                          (self.files["qemu"], Path("/tmp/" + "x" * 110))):
            with self.subTest(out=out), self.assertRaises(ValueError):
                PREPARE.recipe(qemu, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
