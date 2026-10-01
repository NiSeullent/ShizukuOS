# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded, fail-closed observations of private XFS reflink data allocations.

Linux FIEMAP's SHARED flag distinguishes shared data from exclusive data;
st_blocks does not measure new physical allocations caused by COW overwrites.
Only the Linux 64-bit generic ioctl ABI and XFS are supported. Unsupported,
unstable or ambiguous observations raise AccountingError: callers must stop
or decline acceptance, never substitute st_blocks or zero.

observe_allocations() checks two complete, identical extent maps and unchanged
file metadata. This is a sampled observation, not an atomic filesystem-wide
snapshot. Keep the frozen source inode alive; removing another reflink owner
can make data exclusive without changing this file. Retain an independent
free-space guard. The result excludes filesystem metadata, COW staging blocks
not visible in FIEMAP, and cumulative historical writes. For a strict final
receipt, quiesce the writer before observing. Runtime callers should fail closed
if ongoing writes prevent a stable observation.

No source/helper/guest is executed or changed by importing this module.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import time


# Layout and flags: Linux UAPI linux/{fiemap.h,fs.h,magic.h}.
FS_IOC_FIEMAP = 0xC020660B
XFS_SUPER_MAGIC = 0x58465342
FIEMAP_FLAG_SYNC = 0x00000001
EXTENT_LAST = 0x00000001
EXTENT_UNWRITTEN = 0x00000800
EXTENT_SHARED = 0x00002000
ALLOWED_EXTENT_FLAGS = EXTENT_LAST | EXTENT_UNWRITTEN | EXTENT_SHARED
HEADER = struct.Struct("=QQIIII")
EXTENT = struct.Struct("=QQQQQIIII")
UINT64_MAX = (1 << 64) - 1
MAX_FILE_BYTES = 2 * 1024 ** 3
BATCH_EXTENTS = 256
DEFAULT_MAX_EXTENTS = 8192
HARD_MAX_EXTENTS = 65536


class AccountingError(RuntimeError):
    """The allocation observation cannot safely support an acceptance check."""


@dataclass(frozen=True)
class AllocationObservation:
    schema: str
    path: str
    observed_ns: int
    filesystem: str
    device: int
    inode: int
    file_bytes: int
    block_bytes: int
    mapped_bytes: int
    exclusive_bytes: int
    shared_bytes: int
    unwritten_bytes: int
    extent_count: int
    extents_sha256: str
    ioctl_calls: int
    stable_scans: int
    helper_sha256: str
    accounting_scope: str = "current file data extents; filesystem metadata and COW staging excluded"

    def to_dict(self) -> dict:
        return asdict(self)


def _metadata(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_nlink, value.st_uid, value.st_gid,
            value.st_mtime_ns, value.st_ctime_ns)


def _validate_file(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise AccountingError("only regular files can be measured")
    if value.st_nlink != 1:
        raise AccountingError("private file must have exactly one hard link")
    if value.st_uid != os.geteuid():
        raise AccountingError("private file must be owned by the observing user")
    if not 0 <= value.st_size <= MAX_FILE_BYTES:
        raise AccountingError("file exceeds the 2 GiB accounting range")


def _filesystem_block_bytes(fd: int) -> int:
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64"):
        raise AccountingError("unverified Linux ioctl/statfs ABI")
    # Native struct statfs starts with a signed long f_type on these ABIs.
    # The 256-byte buffer exceeds their native struct size; no pointer escapes.
    native_statfs = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
    libc.fstatfs.restype = ctypes.c_int
    if libc.fstatfs(fd, ctypes.byref(native_statfs)) != 0:
        error = ctypes.get_errno()
        raise AccountingError(f"fstatfs failed: {os.strerror(error)}")
    if ctypes.c_long.from_buffer(native_statfs).value != XFS_SUPER_MAGIC:
        raise AccountingError("exclusive extent accounting requires XFS")
    fs = os.fstatvfs(fd)
    block_bytes = fs.f_frsize or fs.f_bsize
    if not 512 <= block_bytes <= 65536 or block_bytes & (block_bytes - 1):
        raise AccountingError("unsupported filesystem allocation block size")
    return block_bytes


def _decode_extent(raw: tuple, *, cursor: int, previous_end: int,
                   logical_limit: int, block_bytes: int) -> tuple:
    logical, physical, length, reserved64a, reserved64b, flags, r0, r1, r2 = raw
    if reserved64a or reserved64b or r0 or r1 or r2:
        raise AccountingError("FIEMAP extent has nonzero reserved fields")
    if flags & ~ALLOWED_EXTENT_FLAGS:
        raise AccountingError(f"ambiguous or unsupported FIEMAP flags: {flags:#x}")
    if not length or not physical:
        raise AccountingError("empty or unknown physical FIEMAP extent")
    if logical < cursor or logical < previous_end:
        raise AccountingError("FIEMAP logical extents overlap or move backwards")
    if logical + length > logical_limit or physical + length > UINT64_MAX:
        raise AccountingError("FIEMAP extent exceeds the supported file/address range")
    if logical % block_bytes or physical % block_bytes or length % block_bytes:
        raise AccountingError("FIEMAP extent is not allocation-block aligned")
    return logical, physical, length, flags


def _scan(fd: int, file_bytes: int, block_bytes: int,
          max_extents: int) -> tuple[list[tuple], int]:
    logical_limit = (file_bytes + block_bytes - 1) // block_bytes * block_bytes
    cursor = 0
    extents: list[tuple] = []
    calls = 0
    # At most max_extents data records plus one bounded empty completion query.
    while calls <= (max_extents + BATCH_EXTENTS - 1) // BATCH_EXTENTS:
        capacity = min(BATCH_EXTENTS, max_extents - len(extents) + 1)
        buf = bytearray(HEADER.size + capacity * EXTENT.size)
        requested_length = UINT64_MAX - cursor
        HEADER.pack_into(buf, 0, cursor, requested_length, FIEMAP_FLAG_SYNC, 0, capacity, 0)
        try:
            fcntl.ioctl(fd, FS_IOC_FIEMAP, buf, True)
        except OSError as error:
            raise AccountingError(f"FIEMAP unsupported or failed: {error}") from error
        calls += 1
        start, length, flags, mapped, count, reserved = HEADER.unpack_from(buf)
        if (start != cursor or length != requested_length or flags != FIEMAP_FLAG_SYNC
                or count != capacity or reserved or mapped > capacity):
            raise AccountingError("invalid or unsupported FIEMAP response header")
        if not mapped:
            if extents:
                raise AccountingError("nonempty FIEMAP map ended without LAST")
            return extents, calls
        if len(extents) + mapped > max_extents:
            raise AccountingError("FIEMAP extent count exceeds the bounded scan budget")
        for index in range(mapped):
            item = _decode_extent(EXTENT.unpack_from(buf, HEADER.size + index * EXTENT.size),
                                  cursor=cursor, previous_end=cursor,
                                  logical_limit=logical_limit, block_bytes=block_bytes)
            if item[3] & EXTENT_LAST and index != mapped - 1:
                raise AccountingError("FIEMAP LAST appears before the final returned extent")
            extents.append(item)
            cursor = item[0] + item[2]
        if extents[-1][3] & EXTENT_LAST:
            # Exclusive physical extents must not alias another logical range.
            ordered = sorted(extents, key=lambda item: item[1])
            highest_end = 0
            exclusive_highest_end = 0
            for item in ordered:
                _, physical, size, extent_flags = item
                if physical < exclusive_highest_end or (
                        not extent_flags & EXTENT_SHARED and physical < highest_end):
                    raise AccountingError("exclusive physical FIEMAP extents overlap")
                highest_end = max(highest_end, physical + size)
                if not extent_flags & EXTENT_SHARED:
                    exclusive_highest_end = max(exclusive_highest_end, physical + size)
            return extents, calls
    raise AccountingError("FIEMAP scan did not complete within its bounded ioctl budget")


def observe_allocations(path: str | os.PathLike, *,
                        max_extents: int = DEFAULT_MAX_EXTENTS,
                        stability_attempts: int = 2) -> AllocationObservation:
    """Observe a private inode, or fail closed; never fall back to st_blocks.

    The work bound is <=2*stability_attempts*(ceil(max_extents/256)+1)
    FIEMAP calls with <=256 records each. Kernel syscall latency is not bounded.
    Beyond-EOF preallocation, unknown flags, multiple hard links and non-XFS
    files are rejected. The final path component must not be a symlink.
    """
    if type(max_extents) is not int or not 1 <= max_extents <= HARD_MAX_EXTENTS:
        raise AccountingError("invalid extent scan budget")
    if type(stability_attempts) is not int or not 1 <= stability_attempts <= 3:
        raise AccountingError("invalid stability attempt budget")
    absolute = os.path.abspath(os.fspath(path))
    try:
        fd = os.open(absolute, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise AccountingError(f"cannot open private file safely: {error}") from error
    try:
        initial = os.fstat(fd)
        _validate_file(initial)
        block_bytes = _filesystem_block_bytes(fd)
        calls = 0
        for _ in range(stability_attempts):
            before = os.fstat(fd)
            _validate_file(before)
            first, count = _scan(fd, before.st_size, block_bytes, max_extents)
            calls += count
            middle = os.fstat(fd)
            second, count = _scan(fd, before.st_size, block_bytes, max_extents)
            calls += count
            after = os.fstat(fd)
            if (_metadata(before) != _metadata(middle) or _metadata(before) != _metadata(after)
                    or first != second):
                continue
            named = os.stat(absolute, follow_symlinks=False)
            if _metadata(named) != _metadata(after):
                raise AccountingError("private pathname changed during observation")
            digest = hashlib.sha256()
            for item in second:
                digest.update(struct.pack("=QQQI", *item))
            return AllocationObservation(
                schema="xfs-fiemap-exclusive-data-v1", path=absolute,
                observed_ns=time.time_ns(), filesystem="xfs", device=after.st_dev,
                inode=after.st_ino, file_bytes=after.st_size, block_bytes=block_bytes,
                mapped_bytes=sum(item[2] for item in second),
                exclusive_bytes=sum(item[2] for item in second if not item[3] & EXTENT_SHARED),
                shared_bytes=sum(item[2] for item in second if item[3] & EXTENT_SHARED),
                unwritten_bytes=sum(item[2] for item in second if item[3] & EXTENT_UNWRITTEN),
                extent_count=len(second), extents_sha256=digest.hexdigest(),
                ioctl_calls=calls, stable_scans=2,
                helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        raise AccountingError("file metadata or FIEMAP mapping changed during bounded observation")
    except OSError as error:
        raise AccountingError(f"allocation observation failed: {error}") from error
    finally:
        os.close(fd)


def net_exclusive_growth_bytes(baseline: AllocationObservation,
                               current: AllocationObservation) -> int:
    """Signed current-minus-baseline private data occupancy, not write volume.

    Freeze the baseline after guest-image preparation. Keep its original
    reflink owner alive and retain a separate reserve for filesystem metadata.
    An AccountingError must cause the consuming guard to stop/fail acceptance.
    """
    if (baseline.schema != "xfs-fiemap-exclusive-data-v1" or current.schema != baseline.schema
            or baseline.helper_sha256 != current.helper_sha256
            or (baseline.device, baseline.inode, baseline.file_bytes, baseline.block_bytes)
            != (current.device, current.inode, current.file_bytes, current.block_bytes)):
        raise AccountingError("baseline and current observation are not the same private file")
    return current.exclusive_bytes - baseline.exclusive_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--max-extents", type=int, default=DEFAULT_MAX_EXTENTS)
    args = parser.parse_args()
    try:
        print(json.dumps(observe_allocations(args.file, max_extents=args.max_extents).to_dict(),
                         sort_keys=True, indent=2))
        return 0
    except AccountingError as error:
        print(json.dumps({"status": "FAIL", "reason": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
