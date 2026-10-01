"""Actual command-boundary controls; no QEMU process or licensed disk access."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audio_adapter", ROOT / "tools/prepare_audio_qemu_adapter.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AudioAdapterBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="run-win98-gop-audio-hostguard-", dir=ROOT / "build/shizukudos/csm")
        self.qmp_temp = tempfile.TemporaryDirectory(prefix="shz-win98-uefi-audio-hostguard-", dir="/tmp")
        self.run = Path(self.temp.name)
        for name in ("windows-uefi.raw", "OVMF_VARS.fd"):
            (self.run / name).write_bytes(b"synthetic host guard only")
        self.config = {"repository_root": str(ROOT), "build_receipt": {"path": str(ROOT / "build/private-qemu/result.json")},
                       "binary": {"path": str(ROOT / "build/private-qemu/qemu-system-x86_64")},
                       "bios_directory": str(ROOT / "build/private-qemu/pc-bios"), "mode": "baseline",
                       "firmware_code": {"path": "/usr/share/edk2/ovmf/OVMF_CODE.fd"}}
        self.argv = ["-name", "shz-disposable-win98-uefi", "-machine", "q35,hpet=off",
                     "-accel", "kvm", "-cpu", "qemu64", "-smp", "2", "-m", "128",
                     "-nodefaults", "-nic", "none", "-display", "none", "-device", "VGA",
                     "-drive", "if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd",
                     "-drive", "if=pflash,unit=1,format=raw,file=" + str(self.run / "OVMF_VARS.fd"),
                     "-drive", "file=" + str(self.run / "windows-uefi.raw") + ",format=raw,if=none,id=win98",
                     "-device", "ide-hd,drive=win98,bus=ide.0,bootindex=1", "-serial", "file:" + str(self.run / "serial.log"),
                     "-qmp", "unix:" + self.qmp_temp.name + "/qmp.sock,server=on,wait=off", "-no-reboot"]

    def tearDown(self):
        self.temp.cleanup()
        self.qmp_temp.cleanup()

    def test_baseline_only_explicit_machine_and_bios_change(self):
        actual = adapter.validate_arguments(self.argv, self.run, self.config)
        expected = list(self.argv)
        expected[3] = "pc-q35-11.1,hpet=off"
        self.assertEqual(actual, [self.config["binary"]["path"]] + expected + ["-L", self.config["bios_directory"]])
        self.assertNotIn("-audiodev", actual)

    def test_sb16_only_fixed_private_wav_endpoint(self):
        self.config["mode"] = "sb16"
        actual = adapter.validate_arguments(self.argv, self.run, self.config)
        self.assertEqual(actual[-4:], ["-audiodev", "wav,id=sb16audio,path=" + str(self.run / "sb16-capture.wav") + ",out.frequency=44100,out.channels=2",
                                      "-device", "sb16,audiodev=sb16audio,iobase=0x220,irq=5,dma=1,dma16=5"])
        self.assertFalse((self.run / "sb16-capture.wav").exists())

    def test_network_display_resource_and_extra_argument_refused(self):
        for index, value in ((14, "user"), (16, "gtk"), (11, "512"), (9, "1"), (5, "tcg"), (3, "pc,hpet=off")):
            bad = list(self.argv); bad[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                adapter.validate_arguments(bad, self.run, self.config)
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv + ["-monitor", "stdio"], self.run, self.config)

    def test_original_or_other_run_backing_refused(self):
        for index, value in ((24, "file=/root/original.raw,format=raw,if=none,id=win98"),
                             (22, "if=pflash,unit=1,format=raw,file=/root/original-VARS.fd"),
                             (28, "file:/root/global.log"), (30, "tcp:127.0.0.1:4444,server=on")):
            bad = list(self.argv); bad[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                adapter.validate_arguments(bad, self.run, self.config)

    def test_symlink_backing_and_existing_recording_refused(self):
        p = self.run / "windows-uefi.raw"; p.unlink(); p.symlink_to(self.run / "OVMF_VARS.fd")
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, self.run, self.config)
        p.unlink(); p.write_bytes(b"host guard")
        self.config["mode"] = "sb16"; (self.run / "sb16-capture.wav").write_bytes(b"prior")
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, self.run, self.config)

    def test_repository_identity_and_run_scope_refused(self):
        self.config["repository_root"] = "/root/other"
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, self.run, self.config)
        self.config["repository_root"] = str(ROOT)
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, ROOT / "build/unowned", self.config)

    def test_qmp_traversal_option_injection_and_serial_symlink_refused(self):
        for endpoint in ("unix:/tmp/shz-win98-uefi-x/../../outside/qmp.sock,server=on,wait=off",
                         "unix:" + self.qmp_temp.name + "/qmp.sock,server=on,wait=off,logfile=/root/out",
                         "unix:" + self.qmp_temp.name + "/qmp.sock\n,server=on,wait=off"):
            bad = list(self.argv); bad[30] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                adapter.validate_arguments(bad, self.run, self.config)
        serial = self.run / "serial.log"; serial.symlink_to(self.run / "OVMF_VARS.fd")
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, self.run, self.config)

    def test_qmp_parent_privacy_and_existing_socket_refused(self):
        parent = Path(self.qmp_temp.name); parent.chmod(0o755)
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, self.run, self.config)
        parent.chmod(0o700)
        (parent / "qmp.sock").symlink_to(self.run / "OVMF_VARS.fd")
        with self.assertRaises(ValueError):
            adapter.validate_arguments(self.argv, self.run, self.config)


if __name__ == "__main__":
    unittest.main()
