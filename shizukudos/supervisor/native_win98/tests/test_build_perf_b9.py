"""build.py read-amplification controls (batch 9): coalesced mtype readback keeps
exact byte/SHA refusal; held DISK.IMG lease reuse refuses a mismatched source."""
import hashlib, importlib.util, os, shutil, subprocess, tempfile, unittest
from pathlib import Path
from unittest import mock
spec = importlib.util.spec_from_file_location("nbuild_perf_b9", Path(__file__).resolve().parents[1] / "build.py")
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)

@unittest.skipUnless(all(shutil.which(t) for t in ("mkfs.vfat", "mcopy", "mtype")), "mtools absent")
class CoalescedReadback(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()); self.esp = self.root / "esp.img"
        with self.esp.open("wb") as s: s.truncate(64 << 20)
        subprocess.run(["mkfs.vfat", "-F", "32", "-g", "1/1", str(self.esp)], check=True, stdout=subprocess.DEVNULL)
        self.data = b"".join(hashlib.sha256(b"%d" % i).digest() * 128 for i in range(2048))  # 8 MiB
        self.src = self.root / "M.BIN"; self.src.write_bytes(self.data)
        subprocess.run(["mcopy", "-i", str(self.esp), str(self.src), "::/M.BIN"], check=True)
        self.pin = hashlib.sha256(self.data).hexdigest()
    def tearDown(self): shutil.rmtree(self.root)

    def test_exact_bytes_with_bounded_pipe_reads(self):
        reads = []; real = os.read
        def counting(fd, n):
            b = real(fd, n); reads.append(len(b)); return b
        with mock.patch.object(B.os, "read", counting):
            got = B.verify_esp_member(self.esp, "M.BIN", self.pin, len(self.data), {"commands": []})
        self.assertEqual(got, {"bytes": len(self.data), "sha256": self.pin, "method": "mtype-streaming-SHA256"})
        self.assertEqual(sum(reads), len(self.data))
        # Uncoalesced mtools 1 KiB writes gave ~4000 reads for 8 MiB.
        self.assertLess(len(reads), 400, len(reads))

    def test_member_mutated_after_write_refuses(self):
        self.src.write_bytes(self.data[:-1] + b"\x00")
        subprocess.run(["mcopy", "-o", "-i", str(self.esp), str(self.src), "::/M.BIN"], check=True)
        with self.assertRaisesRegex(ValueError, "readback mismatch"):
            B.verify_esp_member(self.esp, "M.BIN", self.pin, len(self.data), {"commands": []})

    def test_short_and_long_member_refuse(self):
        with self.assertRaisesRegex(ValueError, "readback mismatch"):
            B.verify_esp_member(self.esp, "M.BIN", self.pin, len(self.data) + 1, {"commands": []})
        with self.assertRaisesRegex(ValueError, "readback mismatch"):
            B.verify_esp_member(self.esp, "M.BIN", self.pin, len(self.data) - 1, {"commands": []})

    def test_held_disk_lease_must_name_inserted_source(self):
        other = self.root / "OTHER.IMG"; other.write_bytes(self.data)
        out = self.root / "out"; out.mkdir()
        loader = self.root / "L.EFI"; loader.write_bytes(b"fixture loader, not executable")
        with B.read_leased(other, self.pin, len(self.data)) as (fd, check), \
             mock.patch.object(B, "ESP_MIB", 64), mock.patch.object(B, "RESERVE", 0):
            with self.assertRaisesRegex(ValueError, "held DISK.IMG lease does not name"):
                B._assemble(out, {"DISK.IMG": self.src}, loader, {"commands": []},
                            held_disk=(fd, check, len(self.data), self.pin))

if __name__ == "__main__":
    unittest.main()
