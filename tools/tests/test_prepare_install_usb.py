"""Real ISO/FAT packaging fixtures. These never run Windows or a guest OS."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "prepare_install_usb.py"
TOOLS = ("xorriso", "mkfs.fat", "mmd", "mcopy")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(all(shutil.which(name) for name in TOOLS), "ISO/FAT fixture tools missing")
class CopyPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        requested_tmp = os.environ.get("TMPDIR")
        if requested_tmp and Path(tempfile.gettempdir()).resolve() != Path(requested_tmp).resolve():
            self.fail("Requested TMPDIR is unavailable; refusing fallback fixture storage")
        self.temp = tempfile.TemporaryDirectory(prefix="shz-usb-test-")
        self.root = Path(self.temp.name)
        self.tree = self.root / "iso-tree"
        self.tree.mkdir()
        self.efi = {
            "EFI/BOOT/BOOTX64.EFI": b"MZ synthetic packaging fixture; not executable",
            "EFI/SHIZUKU/CSMWRAP.EFI": b"MZ synthetic CSM packaging fixture",
            "EFI/SHIZUKU/CSMWRAP.INI": b"serial=true\r\n",
            "EFI/SHIZUKU/BOOT.INI": b"mode = install\r\nmenu_timeout = 0\r\n",
            "EFI/SHIZUKU/README.TXT": b"synthetic fixture\r\n",
            "SHZ/SETUP/INSTALL.IMG": b"owned installer fixture",
            "SHZDOS/DISK.IMG": b"DOS fixture",
            "SHZDOS/KERNEL32.BIN": b"K32 fixture",
            "SHZDOS/KERNEL64.BIN": b"K64 fixture",
            "SHZDOS/KERNEL64S.BIN": b"standalone fixture",
            "SHZDOS/WIN64.IMG": b"runtime fixture",
        }
        image = self.tree / "ShizukuDOS10/efiboot.img"
        image.parent.mkdir()
        with image.open("wb") as stream:
            stream.truncate(8 << 20)
        self.run_tool(["mkfs.fat", "-F", "16", "-s", "1", str(image)])
        self.run_tool(["mmd", "-i", str(image), "::/EFI", "::/EFI/BOOT", "::/EFI/SHIZUKU", "::/SHZDOS", "::/SHZ", "::/SHZ/SETUP"])
        for i, (name, data) in enumerate(self.efi.items()):
            member = self.root / f"member-{i}"
            member.write_bytes(data)
            self.run_tool(["mcopy", "-i", str(image), str(member), f"::/{name}"])
        for name in ("SHZ/K64/BOOT.ELF", "SHZ/K64/KERNEL64S.BIN", "SHZ/K64/WIN64.IMG",
                     "SHZ/SETUP/INSTALL.IMG", "SHZ/SETUP/MANIFEST.JSON", "DRIVERS/README.TXT",
                     "ShizukuDOS10/GPL-NOTICE.TXT", "ShizukuDOS10/SOURCE/shizukudos-source.tar.gz",
                     "ShizukuDOS10/LICENSES/Shizuku-LICENSE-GPL-2.0.txt"):
            member = self.tree / name
            member.parent.mkdir(parents=True, exist_ok=True)
            member.write_bytes(f"Synthetic packaging fixture: {name}\n".encode())
        (self.tree / "SHZ/SETUP/INSTALL.IMG").write_bytes(self.efi["SHZ/SETUP/INSTALL.IMG"])
        bios = self.tree / "isolinux/isolinux.cfg"
        bios.parent.mkdir()
        bios.write_text("SERIAL 0 115200\nDEFAULT setup\nPROMPT 0\nNOESCAPE 1\nLABEL setup\n"
                        "  KERNEL mboot.c32\n  APPEND /SHZ/K64/BOOT.ELF shz.setup=interactive shz.noapps --- "
                        "/SHZ/K64/KERNEL64S.BIN --- /SHZ/SETUP/INSTALL.IMG\n", encoding="ascii")
        self.iso = self.root / "public.iso"
        self.make_iso(self.tree, self.iso)
        self.receipt = self.root / "public.json"
        self.proof = {
            "private": False, "boot_profile": "installer", "boot_mode": "install",
            "installed_system_profile": "desktop",
            "setup": {"present": True}, "git": {"revision": "1" * 40, "dirty": False},
            "sha256": sha(self.iso), "bytes": self.iso.stat().st_size,
            "efi_members": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                            for name, data in self.efi.items()},
        }
        self.write_receipt()
        windows = self.root / "own-tree/WIN98"
        windows.mkdir(parents=True)
        (windows / "SETUP.EXE").write_bytes(b"Synthetic media-shape fixture, not Windows Setup")
        (windows / "WIN98_01.CAB").write_bytes(b"Synthetic cabinet-name fixture")
        self.win98 = self.root / "own.iso"
        self.make_iso(windows.parent, self.win98)
        self.out = self.root / "usb-copy"

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def run_tool(argv: list[str]) -> None:
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)

    def make_iso(self, tree: Path, target: Path) -> None:
        self.run_tool(["xorriso", "-as", "mkisofs", "-R", "-J", "-o", str(target), str(tree)])

    def write_receipt(self) -> None:
        self.receipt.write_text(json.dumps(self.proof), encoding="utf-8")

    def stage(self, *extra: str, script: Path = SCRIPT) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(script), "stage", "--iso", str(self.iso),
                               "--receipt", str(self.receipt), "--out", str(self.out), *extra],
                              capture_output=True, text=True, timeout=60)

    def test_menu_and_wrong_installer_archive_are_rejected_after_exact_iso_rehash(self):
        for mutation in ("menu", "archive"):
            with self.subTest(mutation=mutation):
                cfg = self.tree / "isolinux/isolinux.cfg"
                original = cfg.read_bytes()
                archive = self.tree / "SHZ/SETUP/INSTALL.IMG"
                if mutation == "menu":
                    cfg.write_bytes(original + b"UI menu.c32\n")
                else:
                    archive.write_bytes(b"different installer archive")
                self.make_iso(self.tree, self.iso)
                self.proof.update(sha256=sha(self.iso), bytes=self.iso.stat().st_size)
                self.write_receipt()
                result = self.stage()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(self.out.exists())
                cfg.write_bytes(original)
                archive.write_bytes(self.efi["SHZ/SETUP/INSTALL.IMG"])

    def copied_helper(self):
        """Load a private helper copy so race injection cannot alter project inputs."""
        copy = self.root / "portable/prepare_install_usb.py"
        copy.parent.mkdir(exist_ok=True)
        shutil.copyfile(SCRIPT, copy)
        spec = importlib.util.spec_from_file_location("usb_preparation_fixture", copy)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def combination_fixture(self) -> argparse.Namespace:
        """Model only the producer CLI boundary; the output never boots Windows."""
        source = self.root / "synthetic-producer"
        (source / "tools").mkdir(parents=True)
        builder = source / "tools/build_shizuku_se_iso.py"
        builder.write_text(
            "import argparse, hashlib, json\n"
            "from pathlib import Path\n"
            "parser = argparse.ArgumentParser(description='Synthetic producer boundary only')\n"
            "parser.add_argument('--desktop', action='store_true')\n"
            "parser.add_argument('--win98-media', required=True)\n"
            "parser.add_argument('--output', type=Path, required=True)\n"
            "parser.add_argument('--reuse-builds', action='store_true')\n"
            "args = parser.parse_args()\n"
            "data = b'Synthetic combination fixture; no ISO or Windows boot claim'\n"
            "args.output.write_bytes(data)\n"
            "proof = {'private': True, 'git': {'revision': '1' * 40, 'dirty': False},\n"
            "         'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}\n"
            "args.output.with_suffix('.json').write_text(json.dumps(proof), encoding='utf-8')\n",
            encoding="utf-8")
        return argparse.Namespace(win98_iso=self.win98, source_root=source,
                                  out=self.root / "synthetic-combination.iso", reuse_builds=False)

    def replacement_after_parse(self, module, receipt: Path, private: bool):
        """Persistently replace validated policy bytes at the old parse/hash boundary."""
        loads = module.json.loads
        observed = {}

        def replace(data, *args, **kwargs):
            parsed = loads(data, *args, **kwargs)
            self.assertFalse(observed, "Only the producer receipt should be parsed")
            original = receipt.read_bytes()
            replacement = dict(parsed)
            replacement["private"] = private
            replacement["git"] = {"revision": "2" * 40, "dirty": True}
            changed = json.dumps(replacement).encode("utf-8")
            receipt.write_bytes(changed)
            observed.update(original=original, replacement=changed)
            return parsed

        return mock.patch.object(module.json, "loads", side_effect=replace), observed

    def test_stage_rejects_receipt_replaced_after_parse(self) -> None:
        helper = self.copied_helper()
        patch, observed = self.replacement_after_parse(helper, self.receipt, private=True)
        args = argparse.Namespace(iso=self.iso, receipt=self.receipt, out=self.out, win98_iso=None)
        with patch, self.assertRaisesRegex(helper.PreparationError, "changed"):
            helper.stage(args)
        self.assertNotEqual(observed["original"], observed["replacement"])
        self.assertEqual(self.receipt.read_bytes(), observed["replacement"])
        self.assertFalse(self.out.exists())

    def test_combine_rejects_receipt_replaced_after_parse(self) -> None:
        helper = self.copied_helper()
        args = self.combination_fixture()
        receipt = args.out.with_suffix(".json")
        patch, observed = self.replacement_after_parse(helper, receipt, private=False)
        with patch, self.assertRaisesRegex(helper.PreparationError, "changed"):
            helper.combine(args)
        self.assertNotEqual(observed["original"], observed["replacement"])
        self.assertEqual(receipt.read_bytes(), observed["replacement"])
        self.assertFalse(args.out.with_suffix(".combination.json").exists())

    def test_synthetic_combine_binds_exact_producer_receipt(self) -> None:
        helper = self.copied_helper()
        args = self.combination_fixture()
        result = helper.combine(args)
        raw = args.out.with_suffix(".json").read_bytes()
        self.assertEqual(result["producer_receipt"],
                         {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual(result["source_commit"], "1" * 40)
        self.assertTrue(result["private"])
        self.assertFalse(any(result["claims"].values()))

    def test_public_bundle_contains_all_iso_and_exact_efi_files(self) -> None:
        before = sha(self.iso)
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, data in self.efi.items():
            self.assertEqual((self.out / name).read_bytes(), data)
        for path in self.tree.rglob("*"):
            if path.is_file():
                self.assertEqual((self.out / path.relative_to(self.tree)).read_bytes(), path.read_bytes())
        self.assertEqual(sha(self.iso), before)
        proof = json.loads((self.out / "USB-MANIFEST.JSON").read_text())
        self.assertFalse(proof["private"])
        self.assertFalse(proof["claims"]["windows98_setup_verified"])
        self.assertFalse((self.out / "OWNMEDIA").exists())

    def test_own_iso_is_copied_exactly_and_reported_private(self) -> None:
        before = sha(self.win98)
        result = self.stage("--win98-iso", str(self.win98))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.out / "OWNMEDIA/WIN98.ISO").read_bytes(), self.win98.read_bytes())
        self.assertEqual(sha(self.win98), before)
        self.assertTrue(json.loads((self.out / "USB-MANIFEST.JSON").read_text())["private"])

    def test_wrong_public_hash_does_not_create_output(self) -> None:
        self.proof["sha256"] = "0" * 64
        self.write_receipt()
        self.assertNotEqual(self.stage().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_wrong_efi_member_hash_does_not_publish_partial_output(self) -> None:
        self.proof["efi_members"]["SHZDOS/WIN64.IMG"]["sha256"] = "0" * 64
        self.write_receipt()
        self.assertNotEqual(self.stage().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_existing_output_is_preserved(self) -> None:
        self.out.mkdir()
        (self.out / "keep.txt").write_bytes(b"keep")
        self.assertNotEqual(self.stage().returncode, 0)
        self.assertEqual((self.out / "keep.txt").read_bytes(), b"keep")

    def test_symlink_input_is_refused(self) -> None:
        link = self.root / "link.iso"
        link.symlink_to(self.win98)
        self.assertNotEqual(self.stage("--win98-iso", str(link)).returncode, 0)
        self.assertFalse(self.out.exists())

    def test_oversize_fat32_iso_is_rejected_without_reading_it(self) -> None:
        big = self.root / "too-big.iso"
        with big.open("wb") as stream:
            stream.truncate(1 << 32)
        result = self.stage("--win98-iso", str(big))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAT32", result.stderr)
        self.assertFalse(self.out.exists())

    def test_standalone_script_runs_outside_source_checkout(self) -> None:
        standalone = self.root / "portable/prepare_install_usb.py"
        standalone.parent.mkdir()
        shutil.copyfile(SCRIPT, standalone)
        result = self.stage(script=standalone)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verify_detects_changed_runtime_bytes_and_user_added_iso(self) -> None:
        self.assertEqual(self.stage().returncode, 0)
        (self.out / "OWNMEDIA").mkdir()
        shutil.copyfile(self.win98, self.out / "OWNMEDIA/WIN98.ISO")
        argv = [sys.executable, str(SCRIPT), "verify", "--root", str(self.out), "--with-win98"]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["private"])
        (self.out / "SHZDOS/WIN64.IMG").write_bytes(b"changed runtime")
        self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=60).returncode, 0)


if __name__ == "__main__":
    unittest.main()
