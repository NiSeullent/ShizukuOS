#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""SFS_MOUNT_CLEAN_ON_SYNC (the Kernel64 mount mode): after every sfs_sync() the media must be a cleanly
unmounted volume (needs_recovery clear, journal empty; VALID_FS set without a journal), the first update after
that re-marks it in use, and at no point may the journal hold data while needs_recovery is clear (e2fsck would
report "needs_recovery flag is clear, but journal has data"). Checked from inside one mount with `sfstool ondisk`
(reads the superblock and the journal superblock from the device), with and without a journal, and e2fsck -fn
must pass on the final image. A crash (-K) right after a second sync must leave an image e2fsck -fn accepts.
"""
import os
import subprocess
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "build", "sfstool")

BATCH = """ondisk clean
pattern /a 0 100000 1
ondisk
sync
ondisk clean
sync
ondisk clean
sync
ondisk clean
mkdir /d
pattern /d/b 0 5000000 2
rm /a
ondisk
sync
ondisk clean
truncate /d/b 10
sync
sync
ondisk clean
"""


def main():
    tmp = tempfile.mkdtemp(prefix="sfsclean-", dir=os.environ.get("SFS_TMP"))
    fails = 0
    try:
        for name, opts in (("journal", []), ("no-journal", ["-O", "^has_journal"]), ("1k", ["-b", "1024"])):
            img = os.path.join(tmp, name + ".img")
            subprocess.run(["mkfs.ext4", "-q", "-F"] + opts + [img, "64M"], check=True)
            p = subprocess.run([TOOL, "-q", "-C", img, "batch"], input=BATCH, text=True, capture_output=True)
            f = subprocess.run(["e2fsck", "-fn", img], capture_output=True, text=True)
            ok = p.returncode == 0 and f.returncode == 0
            print("%-10s %s: %d ondisk checks, e2fsck -fn rc %d %s" % (name, "PASS" if ok else "FAIL", p.stdout.count("ondisk"),
                                                                     f.returncode, p.stderr.strip()[-300:]))
            fails += not ok
            # crash right after the second sync of a new session: whatever reached the disk must be acceptable
            for k in (3, 6, 12, 25):
                subprocess.run([TOOL, "-q", "-C", "-K", str(k), img, "batch"], input="pattern /c 0 300000 3\nsync\nsync\npattern /c 0 10 4\n",
                               text=True, capture_output=True)
                f = subprocess.run(["e2fsck", "-fn", img], capture_output=True, text=True)
                bad = [l for l in f.stdout.splitlines() if "journal has data" in l]
                if bad:
                    print("  crash after %d writes: %s" % (k, bad))
                    fails += 1
                subprocess.run(["e2fsck", "-fy", img], capture_output=True, text=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("clean-on-sync: %s" % ("PASS" if not fails else "FAIL (%d)" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
