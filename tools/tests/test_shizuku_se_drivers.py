"""INF hardware-ID extraction and driver-store staging, on synthetic INFs only (no real drivers)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shizuku_se_drivers as drivers  # noqa: E402

WIN9X_INF = (
    "[version]\n"
    "signature=\"$CHICAGO$\"\n"
    "Class=Display\n"
    "Provider=%Mfg%\n"
    "[Manufacturer]\n"
    "%Mfg%=Mfg\n"
    "[Mfg]\n"
    "%Card% = Card.Install, PCI\\VEN_5333&DEV_8811 ; trailing comment\n"
    "%Card2%= Card.Install,,*PNP0900\n"
    "[Strings]\n"
    "Mfg=\"Example Graphics\"\n"
    "Card=\"Example Card\"\n"
    "Card2=\"Example Card (compatible only)\"\n"
)


class InfReaderTests(unittest.TestCase):
    def test_synthetic_package_inf(self) -> None:
        inf = drivers.Inf(drivers.SYNTHETIC_INF.encode("ascii"), "shzsynth.inf")
        summary = inf.summary()
        self.assertEqual(summary["signature"], "$Windows NT$")
        self.assertEqual(summary["provider"], "Shizuku Synthetic")
        self.assertEqual(summary["catalogfile"], "shzsynth.cat")
        sections = {m["section"]: m for m in summary["models"]}
        self.assertEqual(set(sections), {"ShizukuModels", "ShizukuModels.NTx86", "shizukumodels.ntamd64"})
        base = sections["ShizukuModels"]
        self.assertTrue(base["windows9x"])
        device = base["devices"][0]
        self.assertEqual(device["description"], "Synthetic 100% Test Device")
        self.assertEqual(device["install"], "Synth_Install")
        self.assertEqual(device["hardware_id"], "PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4")
        self.assertEqual(device["compatible_ids"], ["PCI\\VEN_1AF4&DEV_1000"])  # joined across the '\' line
        amd64 = sections["shizukumodels.ntamd64"]["devices"][0]
        self.assertEqual(amd64["description"], "Quoted; description, with comma")
        self.assertEqual(amd64["hardware_id"], "USB\\VID_1234&PID_5678")
        self.assertEqual(summary["hardware_ids"], ["PCI\\VEN_1AF4&DEV_1000", "PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4",
                                                   "USB\\VID_1234&PID_5678"])
        self.assertEqual(summary["source_disks_files"], ["shzsynth.sys"])
        self.assertEqual(summary["warnings"], [])

    def test_utf16_and_win9x_layout(self) -> None:
        raw = b"\xff\xfe" + WIN9X_INF.replace("\n", "\r\n").encode("utf-16-le")
        summary = drivers.Inf(raw, "w9x.inf").summary()
        self.assertEqual(summary["encoding"], "utf-16-le")
        self.assertEqual(summary["signature"], "$CHICAGO$")
        self.assertEqual(summary["provider"], "Example Graphics")
        self.assertEqual(summary["hardware_ids"], ["*PNP0900", "PCI\\VEN_5333&DEV_8811"])
        devices = summary["models"][0]["devices"]
        self.assertIsNone(devices[1]["hardware_id"] and None)
        self.assertEqual(devices[1]["hardware_id"], "*PNP0900")  # empty first ID field is skipped

    def test_missing_models_and_strings_are_warnings(self) -> None:
        text = "[Version]\nProvider=%Nope%\n[Manufacturer]\n%Nope%=Gone\n"
        summary = drivers.Inf(text.encode("ascii"), "bad.inf").summary()
        self.assertEqual(summary["hardware_ids"], [])
        self.assertTrue(any("Gone" in w for w in summary["warnings"]))
        self.assertTrue(any("%Nope%" in w for w in summary["warnings"]))


class StoreTests(unittest.TestCase):
    def test_store_copies_bytes_unchanged_and_lists_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = drivers.make_synthetic(Path(temp) / "synthpkg")
            (package / "sub").mkdir()
            (package / "sub" / "Extra File.dll").write_bytes(b"\x00\x01binary")
            payload, manifest = drivers.store_payload([str(package), f"pkg two={package}"])
            self.assertEqual(payload["DRIVERS/synthpkg/shzsynth.sys"], (package / "shzsynth.sys").read_bytes())
            self.assertEqual(payload["DRIVERS/synthpkg/shzsynth.inf"], drivers.SYNTHETIC_INF.encode("ascii"))
            self.assertEqual(payload["DRIVERS/pkg_two/sub/Extra File.dll"], b"\x00\x01binary")
            decoded = json.loads(payload["DRIVERS/MANIFEST.JSON"])
            self.assertEqual(decoded, manifest)
            first = manifest["packages"][0]
            self.assertEqual(first["provider"], "Shizuku Synthetic")
            self.assertIn("PCI\\VEN_1AF4&DEV_1000", first["hardware_ids"])
            self.assertEqual(first["infs"][0]["missing_source_disks_files"], [])
            self.assertEqual(len(first["files"]), 4)
            self.assertIn(b"Packages on this medium: 2", payload["DRIVERS/README.TXT"])
            index = payload["DRIVERS/HWIDS.TXT"].decode("utf-8").splitlines()
            rows = [line.split("\t") for line in index if not line.startswith(";")]
            self.assertEqual(len(rows), 2 * 4)  # 4 IDs over the three models sections, two packages
            self.assertIn(["PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4", "hw", "synthpkg", "shzsynth.inf",
                           "ShizukuModels", "Synthetic 100% Test Device"], rows)
            self.assertIn(["USB\\VID_1234&PID_5678", "hw", "pkg_two", "shzsynth.inf", "shizukumodels.ntamd64",
                           "Quoted; description, with comma"], rows)
            self.assertEqual([r[0].upper() for r in rows], sorted(r[0].upper() for r in rows))

    def test_empty_store_and_errors(self) -> None:
        payload, manifest = drivers.store_payload([])
        self.assertEqual(manifest["packages"], [])
        self.assertEqual(set(payload), {"DRIVERS/MANIFEST.JSON", "DRIVERS/HWIDS.TXT", "DRIVERS/README.TXT"})
        with tempfile.TemporaryDirectory() as temp:
            empty = Path(temp) / "noinf"
            empty.mkdir()
            (empty / "a.sys").write_bytes(b"x")
            with self.assertRaises(drivers.DriverPackageError):
                drivers.store_payload([str(empty)])
            package = drivers.make_synthetic(Path(temp) / "same")
            with self.assertRaises(drivers.DriverPackageError):
                drivers.store_payload([str(package), str(package)])
            for bad in (f"vendor/pkg={package}", f"HWIDS.TXT={package}"):
                with self.assertRaises(drivers.DriverPackageError):
                    drivers.store_payload([bad])


if __name__ == "__main__":
    unittest.main()
