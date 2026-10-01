# SPDX-License-Identifier: GPL-2.0-or-later
"""Actual small-file XFS reflink overwrite and fail-closed accounting checks.

Run from any directory:
  python3 /root/Win98-Modern-boot/shizukudos/iosys_uefi/test_cow_accounting.py

Only fresh, temporary 4 MiB files are used, with a 20 GiB host free-space floor.
No licensed image, repository runner, VM, service or network is touched.
A JSON receipt is written under build/shizukudos/iosys-uefi-port/cow-accounting-tests.
"""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from cow_accounting import (AccountingError, EXTENT_SHARED, MAX_FILE_BYTES,
                            _decode_extent, net_exclusive_growth_bytes,
                            observe_allocations)


REPO = Path(__file__).resolve().parents[2]
OUTPUT = REPO / "build/shizukudos/iosys-uefi-port/cow-accounting-tests"
FREE_FLOOR = 20 * 1024 ** 3
TEST_HEADROOM = 32 * 1024 ** 2
MIB = 1024 ** 2


class CowAllocationChecks(unittest.TestCase):
    receipt = {"schema": "xfs-cow-accounting-test-v1", "status": "NOT-RUN",
               "full_windows_boot": False, "guest_operations": False}

    @classmethod
    def setUpClass(cls):
        OUTPUT.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(OUTPUT).free
        if free < FREE_FLOOR + TEST_HEADROOM:
            raise unittest.SkipTest("20 GiB floor plus 32 MiB test headroom is unavailable")
        cls.temporary = tempfile.TemporaryDirectory(prefix="actual-xfs-", dir=OUTPUT)
        cls.folder = Path(cls.temporary.name)
        try:
            source = cls.folder / "source.bin"
            clone = cls.folder / "private.bin"
            original = bytes(range(256)) * (4 * MIB // 256)
            with source.open("xb") as stream:
                stream.write(original)
                stream.flush()
                os.fsync(stream.fileno())
            # Verify this host/volume supports trustworthy XFS FIEMAP first.
            source_before_copy = observe_allocations(source)
            subprocess.run(["cp", "--reflink=always", "--sparse=auto", "--", str(source), str(clone)],
                           check=True, capture_output=True, timeout=30)
            if (source.stat().st_dev, source.stat().st_ino) == (clone.stat().st_dev, clone.stat().st_ino):
                raise AssertionError("reflink clone aliases the source inode")
            cls.baseline = observe_allocations(clone)
            cls.source_shared = observe_allocations(source)
            cls.blocks_before = clone.stat().st_blocks * 512
            if shutil.disk_usage(OUTPUT).free < FREE_FLOOR + 2 * MIB:
                raise AssertionError("free-space floor would be violated before the overwrite")
            changed = bytearray(original)
            changed[MIB:2 * MIB] = b"\xa5" * MIB
            with clone.open("r+b") as stream:
                stream.seek(MIB)
                if stream.write(b"\xa5" * MIB) != MIB:
                    raise AssertionError("short COW fixture write")
                stream.flush()
                os.fsync(stream.fileno())
            cls.current = observe_allocations(clone)
            cls.source_after = observe_allocations(source)
            cls.blocks_after = clone.stat().st_blocks * 512
            cls.source = source
            cls.clone = clone
            cls.original_sha = hashlib.sha256(original).hexdigest()
            cls.expected_sha = hashlib.sha256(changed).hexdigest()
            cls.receipt.update({
                "observed_ns": time.time_ns(), "free_floor_bytes": FREE_FLOOR,
                "free_before_bytes": free, "free_after_bytes": shutil.disk_usage(OUTPUT).free,
                "source_before_reflink": source_before_copy.to_dict(),
                "private_before_overwrite": cls.baseline.to_dict(),
                "private_after_overwrite": cls.current.to_dict(),
                "source_after_overwrite": cls.source_after.to_dict(),
                "overwritten_bytes": MIB, "st_blocks_bytes_before": cls.blocks_before,
                "st_blocks_bytes_after": cls.blocks_after,
                "st_blocks_delta_bytes": cls.blocks_after - cls.blocks_before,
                "fiemap_exclusive_growth_bytes": net_exclusive_growth_bytes(cls.baseline, cls.current),
                "source_expected_sha256": cls.original_sha,
                "source_observed_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "private_expected_sha256": cls.expected_sha,
                "private_observed_sha256": hashlib.sha256(clone.read_bytes()).hexdigest(),
            })
        except BaseException:
            cls.temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_cow_growth_is_invisible_to_st_blocks(self):
        self.assertEqual(self.baseline.mapped_bytes, 4 * MIB)
        self.assertEqual(self.baseline.shared_bytes, 4 * MIB)
        self.assertEqual(self.baseline.exclusive_bytes, 0)
        self.assertEqual(self.current.mapped_bytes, 4 * MIB)
        self.assertEqual(self.current.exclusive_bytes, MIB)
        self.assertEqual(self.current.shared_bytes, 3 * MIB)
        self.assertEqual(net_exclusive_growth_bytes(self.baseline, self.current), MIB)
        self.assertLess(self.blocks_after - self.blocks_before, MIB)
        self.assertGreaterEqual(self.receipt["free_after_bytes"], FREE_FLOOR)

    def test_source_and_private_content_are_independently_verified(self):
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.original_sha)
        self.assertEqual(hashlib.sha256(self.clone.read_bytes()).hexdigest(), self.expected_sha)
        self.assertEqual(self.source_after.exclusive_bytes, MIB)
        self.assertEqual(self.source_after.shared_bytes, 3 * MIB)

    def test_real_fragmented_map_rejects_insufficient_budget(self):
        self.assertGreaterEqual(self.current.extent_count, 3)
        with self.assertRaisesRegex(AccountingError, "count exceeds"):
            observe_allocations(self.clone, max_extents=1)

    def test_hardlink_and_symlink_are_rejected(self):
        link = self.folder / "alias.bin"
        os.link(self.clone, link)
        try:
            with self.assertRaisesRegex(AccountingError, "hard link"):
                observe_allocations(self.clone)
        finally:
            link.unlink()
        link.symlink_to(self.clone)
        with self.assertRaisesRegex(AccountingError, "open private file safely"):
            observe_allocations(link)

    def test_wrong_file_identity_or_helper_cannot_use_baseline(self):
        with self.assertRaisesRegex(AccountingError, "same private file"):
            net_exclusive_growth_bytes(self.baseline, self.source_after)
        with self.assertRaisesRegex(AccountingError, "same private file"):
            net_exclusive_growth_bytes(self.baseline, replace(self.current, helper_sha256="0" * 64))

    def test_sparse_oversize_and_nonregular_files_are_rejected(self):
        large = self.folder / "oversize-sparse.bin"
        with large.open("xb") as stream:
            stream.truncate(MAX_FILE_BYTES + 1)
        with self.assertRaisesRegex(AccountingError, "2 GiB"):
            observe_allocations(large)
        with self.assertRaisesRegex(AccountingError, "regular file"):
            observe_allocations(self.folder)

    def test_unknown_kernel_flags_and_physical_overflow_are_rejected(self):
        with self.assertRaisesRegex(AccountingError, "unsupported FIEMAP flags"):
            _decode_extent((0, 4096, 4096, 0, 0, 0x00000002, 0, 0, 0),
                           cursor=0, previous_end=0, logical_limit=4096, block_bytes=4096)
        with self.assertRaisesRegex(AccountingError, "address range"):
            _decode_extent((0, (1 << 64) - 4096, 4096, 0, 0, EXTENT_SHARED, 0, 0, 0),
                           cursor=0, previous_end=0, logical_limit=4096, block_bytes=4096)

    def test_non_xfs_fails_closed(self):
        if not Path("/dev/shm").is_dir():
            self.skipTest("non-XFS tmpfs fixture is unavailable")
        with tempfile.NamedTemporaryFile(dir="/dev/shm", prefix="cow-accounting-") as stream:
            with self.assertRaisesRegex(AccountingError, "requires XFS"):
                observe_allocations(stream.name)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CowAllocationChecks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = CowAllocationChecks.receipt
    receipt.update({"status": "PASS" if result.wasSuccessful() and not result.skipped else "FAIL",
                    "tests_run": result.testsRun, "failures": len(result.failures),
                    "errors": len(result.errors), "skipped": len(result.skipped),
                    "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "temporary_files_removed": True})
    OUTPUT.mkdir(parents=True, exist_ok=True)
    output = OUTPUT / f"receipt-{time.time_ns()}.json"
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(output)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
