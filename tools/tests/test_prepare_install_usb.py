"""Real ISO/FAT packaging fixtures. These never run Windows or a guest OS."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "prepare_install_usb.py"
TOOLS = ("xorriso", "mkfs.fat", "mmd", "mcopy")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(all(shutil.which(name) for name in TOOLS), "ISO/FAT fixture tools missing")
class CopyPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="shz-usb-test-")
        self.root = Path(self.temp.name)
        self.tree = self.root / "iso-tree"
        self.tree.mkdir()
        self.efi = {
            "EFI/BOOT/BOOTX64.EFI": b"MZ synthetic packaging fixture; not executable",
            "EFI/SHIZUKU/CSMWRAP.EFI": b"MZ synthetic CSM packaging fixture",
            "EFI/SHIZUKU/CSMWRAP.INI": b"serial=true\r\n",
            "EFI/SHIZUKU/BOOT.INI": b"mode = kernel64\r\nmenu_timeout = 5\r\n",
            "EFI/SHIZUKU/README.TXT": b"synthetic fixture\r\n",
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
        self.run_tool(["mmd", "-i", str(image), "::/EFI", "::/EFI/BOOT", "::/EFI/SHIZUKU", "::/SHZDOS"])
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
        self.iso = self.root / "public.iso"
        self.make_iso(self.tree, self.iso)
        self.receipt = self.root / "public.json"
        self.proof = {
            "private": False, "boot_profile": "desktop", "boot_mode": "kernel64",
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
