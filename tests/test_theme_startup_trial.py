# SPDX-License-Identifier: GPL-2.0-only
"""Real disposable FAT/COW and strict refusal checks. Never launch a VM."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("theme_startup_tests", ROOT / "tools/theme_startup_trial.py")
startup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(startup)
INI = b"[windows]\r\nload=\r\nrun=\r\nNullPort=None\r\n[Desktop]\r\nWallpaper=\xbe\xf8\xc0\xbd\r\n[other]\r\nrun=unchanged.exe\r\n"


class ByteINI(unittest.TestCase):
    def test_only_one_empty_value_changes_and_opaque_ansi_bytes_survive(self):
        result, edit = startup.insert_empty_run(INI)
        self.assertEqual(result, INI.replace(b"run=\r\n", b"run=" + startup.STARTUP_EXE.encode() + b"\r\n", 1))
        self.assertTrue(edit["other_bytes_preserved"])

    def test_spelling_whitespace_and_existing_line_endings_are_preserved(self):
        before = b";run=ignored\n [WINDOWS] \n\tRuN \t= \t\n[x]\nz=1"
        after, _ = startup.insert_empty_run(before)
        self.assertEqual(after, before.replace(b"= \t", b"=" + startup.STARTUP_EXE.encode() + b" \t", 1))

    def test_refuses_nonempty_quoted_commented_missing_duplicate_or_ambiguous_entries(self):
        examples = [b"[windows]\nrun=old.exe\n", b'[windows]\nrun=""\n', b"[windows]\nrun=;existing\n",
                    b"[windows]\nload=\n", b"[windows]\nrun=\nRUN=\n", b"[windows]\nrun=\n[WINDOWS]\nx=1\n",
                    b"[windows] ;suffix\nrun=\n", b"[windows]\nrun\n", b"[else]\nrun=\n",
                    b"[windows]\rRun=\r", b"[windows]\nrun=\x00\n", b"[windows]\nrun=\x1a\n",
                    b"\xff\xfe[windows]\nrun=\n", b"x" * (startup.MAX_INI + 1)]
        for value in examples:
            with self.subTest(value=value[:40]), self.assertRaises(startup.StartupError):
                startup.insert_empty_run(value)

    def test_command_arguments_or_other_executable_cannot_be_inserted(self):
        with self.assertRaises(startup.StartupError):
            startup.insert_empty_run(INI, startup.OBSERVER + " --nonce=" + "a" * 32)


class PrivateLimits(unittest.TestCase):
    def test_duration_changes_only_one_private_numeric_bound(self):
        for canonical, old in ((False, b"not 1 <= args.timeout <= 900"), (True, b"not 10 <= args.timeout <= 900")):
            original = b"RESERVE=20\nQUOTA=256\nif " + old + b": reject()\n"
            changed = startup.timeout_adaptation(original, canonical=canonical)
            self.assertEqual(changed.replace(b"1200", b"900"), original)
            for wrong in (b"nothing", original + original):
                with self.assertRaises(startup.StartupError):
                    startup.timeout_adaptation(wrong, canonical=canonical)

    def test_real_child_file_limit_fails_and_does_not_change_parent_limits(self):
        import resource
        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            target = Path(temp) / "bounded.bin"
            with self.assertRaises(startup.StartupError):
                startup.output_command([sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'x'*8192)", target], limit=4096)
            self.assertLessEqual(target.stat().st_size, 4096)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before)


@unittest.skipUnless(all(shutil.which(x) for x in ("mformat", "mmd", "mcopy", "mdir", "mattrib", "cp")), "mtools required")
class RealFATCOW(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "base"
        self.source.mkdir()
        self.base = self.source / "windows-uefi.raw"
        with self.base.open("wb") as stream:
            stream.truncate(64 * 1024**2 + 63 * 512)
            stream.seek(510)
            stream.write(b"\x55\xaa")
        self.spec_base = str(self.base) + "@@32256"
        startup.command(["mformat", "-i", self.spec_base, "-F", "-T", "131072", "::"])
        startup.command(["mmd", "-i", self.spec_base, "::/WINDOWS", "::/VXDLAB"])
        self.stage = self.root / "stage"
        self.stage.mkdir()
        ini = self.stage / "source-WIN.INI"
        ini.write_bytes(INI)
        startup.command(["mcopy", "-i", self.spec_base, ini, startup.GUEST_INI])
        inputs = []
        for name in startup.NAMES:
            path = self.stage / name
            path.write_bytes(b"a" * 32 if name == "THNONCE.TXT" else name.encode() * 3)
            startup.command(["mcopy", "-i", self.spec_base, path, "::/VXDLAB/" + name])
            inputs.append({"source": str(path), "guest": startup.GUEST_DIR + name,
                           "bytes": path.stat().st_size, "sha256": startup.sha(path)})
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                    "outputs": [startup.GUEST_DIR + name for name in startup.OUTPUTS], "backups": [r"C:\WINDOWS\WIN.INI"]}
        (self.stage / "guest-files.json").write_text(json.dumps(manifest))
        receipt = self.stage / "build-result.json"
        receipt.write_text(json.dumps({"status": "PASS", "source_root": str(self.root), "source_hashes": {}}))
        self.run = self.root / "owned"
        self.run.mkdir()
        self.disk = self.run / "windows-uefi.raw"
        startup.command(["cp", "--reflink=always", "--", self.base, self.disk])
        self.spec = str(self.disk) + "@@32256"
        startup.command(["mcopy", "-i", self.spec, startup.GUEST_INI, self.run / "before-install-WIN.INI"])
        with self.disk.open("rb") as stream:
            mbr = stream.read(512); stream.seek(32256); boot = stream.read(512)
        self.partition = {"start_lba": 63, "mbr_sha256": hashlib.sha256(mbr).hexdigest(),
                          "boot_sector_sha256": hashlib.sha256(boot).hexdigest()}
        self.base_sha = startup.sha(self.base)
        self.plan = {"run_directory": str(self.run), "base_disk": str(self.base), "base_disk_sha256": self.base_sha,
                     "partition": dict(self.partition), "source_win_ini_sha256": startup.sha(ini),
                     "edited_win_ini_sha256": hashlib.sha256(startup.insert_empty_run(INI)[0]).hexdigest(),
                     "guest_manifest": str(self.stage / "guest-files.json"), "guest_manifest_sha256": startup.sha(self.stage / "guest-files.json"),
                     "nonce": "a" * 32, "startup_executable": startup.STARTUP_EXE,
                     "observer_command": startup.OBSERVER + " --nonce=" + "a" * 32,
                     "theme_build_receipt": str(receipt), "immutable_sources": []}
        self.args = SimpleNamespace(reserve_gib=20, replace_installed_gop=False,
                                    guest_files_manifest=Path(self.plan["guest_manifest"]), guest_files_manifest_sha=self.plan["guest_manifest_sha256"])
        self.provenance = {"source_run": str(self.source), "source_disk_sha256": self.base_sha, "copy_mode": "cp --reflink=always; test-only actual private clone"}
        self.cow = startup.load_module(ROOT / "build/theme-native-consumer-6970-20261001-v11/original/shizukudos/iosys_uefi/cow_accounting.py", "startup_test_cow") if (ROOT / "build/theme-native-consumer-6970-20261001-v11/original/shizukudos/iosys_uefi/cow_accounting.py").exists() else None
        # Repository tests use a caller-supplied actual FIEMAP helper. No peer
        # runner or QEMU module is loaded and there is no VM launch function.
        if self.cow is None:
            self.skipTest("Pinned FIEMAP helper not available in this local lab")
        self.consumer = startup.load_module(ROOT / "tools/theme_native_runner.py", "startup_test_consumer")

    def apply(self, **changes):
        return startup.apply_startup(self.disk, self.run, self.partition, self.args, self.plan, self.cow,
                                     self.consumer.ensure_unopened, provenance=changes.get("provenance", self.provenance))

    def original_guest(self):
        result = self.run / "check-current-WIN.INI"
        startup.command(["mcopy", "-o", "-i", self.spec, startup.GUEST_INI, result])
        return result.read_bytes()

    def test_actual_fat_readback_sector_attributes_and_base_preservation(self):
        record = self.apply()
        self.assertEqual(record["status"], "PREPARED-NATIVE-UNVERIFIED")
        self.assertEqual(self.original_guest(), startup.insert_empty_run(INI)[0])
        self.assertEqual(startup.sha(self.base), self.base_sha)
        self.assertTrue(record["attributes_preserved"] and record["boot_sectors_preserved"])
        self.assertLessEqual(record["cow_net_exclusive_growth_bytes"], startup.QUOTA)

    def test_existing_output_is_refused_before_ini_write(self):
        f = self.run / "old.log"; f.write_bytes(b"old")
        startup.command(["mcopy", "-i", self.spec, f, "::/VXDLAB/THBOOT.LOG"])
        with self.assertRaisesRegex(startup.StartupError, "already exists"):
            self.apply()
        self.assertEqual(self.original_guest(), INI)

    def test_same_inode_hardlink_symlink_and_open_writer_are_refused(self):
        with self.disk.open("rb"), self.assertRaisesRegex(Exception, "opened"):
            self.apply()
        self.assertEqual(self.original_guest(), INI)
        hardlink = self.run / "alias.raw"; os.link(self.disk, hardlink)
        with self.assertRaisesRegex(startup.StartupError, "private inode"):
            self.apply()
        hardlink.unlink()
        self.disk.rename(self.run / "saved.raw")
        self.disk.symlink_to(self.run / "saved.raw")
        with self.assertRaisesRegex(startup.StartupError, "Symlink"):
            self.apply()

    def test_unrelated_existing_startup_cannot_be_replaced_on_real_fat(self):
        value = INI.replace(b"run=\r\n", b"run=OLD.EXE\r\n", 1)
        path = self.run / "new-source.ini"; path.write_bytes(value)
        startup.command(["mcopy", "-o", "-i", self.spec, path, startup.GUEST_INI])
        (self.run / "before-install-WIN.INI").write_bytes(value)
        self.plan["source_win_ini_sha256"] = startup.sha(path)
        with self.assertRaisesRegex(startup.StartupError, "nonempty"):
            self.apply()
        self.assertEqual(self.original_guest(), value)

    def test_artifact_tampering_and_backup_mismatch_block_mutation(self):
        (self.stage / "NTTHRUN.EXE").write_bytes(b"changed")
        with self.assertRaisesRegex(startup.StartupError, "artifact"):
            self.apply()
        self.assertEqual(self.original_guest(), INI)

    def test_plan_nonce_artifact_backup_and_sector_mismatch_are_refused(self):
        self.plan["nonce"] = "b" * 32
        with self.assertRaisesRegex(startup.StartupError, "challenge"):
            self.apply()
        self.plan["nonce"] = "a" * 32
        self.partition["mbr_sha256"] = "0" * 64
        with self.assertRaisesRegex(startup.StartupError, "Partition"):
            self.apply()
        self.assertEqual(self.original_guest(), INI)

    def test_low_space_is_refused_without_ini_write(self):
        with patch.object(startup.shutil, "disk_usage", return_value=SimpleNamespace(free=startup.RESERVE)), self.assertRaises(startup.StartupError):
            self.apply()
        self.assertEqual(self.original_guest(), INI)

    def test_quota_failure_restores_original_ini_and_retains_failure(self):
        with patch.object(self.cow, "net_exclusive_growth_bytes", return_value=startup.QUOTA + 1), self.assertRaises(startup.StartupError):
            self.apply()
        self.assertEqual(self.original_guest(), INI)
        record = json.loads((self.run / "automatic-startup-preparation.json").read_text())
        self.assertEqual(record["status"], "FAIL")
        self.assertTrue(record["INI_rollback_matches_original"])
        self.assertEqual(startup.sha(self.base), self.base_sha)

    def test_source_hash_change_is_refused_before_any_guest_write(self):
        source = self.run / "helper-source"; source.write_bytes(b"changed")
        self.plan["immutable_sources"] = [{"path": str(source), "sha256": "0" * 64}]
        with self.assertRaisesRegex(startup.StartupError, "source changed"):
            self.apply()
        self.assertEqual(self.original_guest(), INI)


if __name__ == "__main__":
    unittest.main()
