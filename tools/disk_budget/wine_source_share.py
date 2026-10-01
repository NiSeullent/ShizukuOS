#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Plan or share identical, unmodified Wine source pages in three fixed caches."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import sys
import time

ROOTS = tuple(Path(p) / "build/upstream/wine" for p in (
    "/root/Win98-Modern-boot", "/root/Win98-Modern-apps-cb43",
    "/root/Win98-Modern-codex-20260930"))
SOURCE, DESTINATION = ROOTS[1], ROOTS[0]
REPORTS = ROOTS[0].parents[1] / "disk-c009"
SOURCE_DIRS = {"dlls", "include", "libs", "loader", "programs", "server", "tools"}
SOURCE_SUFFIXES = {".c", ".h", ".idl", ".spec", ".rc", ".y", ".l", ".m",
                   ".pl", ".pm", ".rh", ".inl", ".in", ".ac", ".m4"}
PAGE = 4096
CHUNK = 1024 * 1024
FIEMAP = 0xC020660B
FIDEDUPERANGE = 0xC0189436
SHARED = 0x2000
# Unknown, delayed, encoded, encrypted, unaligned, inline, tail, unwritten, merged.
UNSUITABLE = 0x2 | 0x4 | 0x8 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000
MAX_FILES, MAX_BYTES = 2048, 128 * 1024 * 1024
AGE_NS = 120 * 10**9


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def git(root, *arguments):
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root),
                                    *arguments], stderr=subprocess.PIPE)


def heads():
    return {str(root): git(root, "rev-parse", "HEAD").decode().strip() for root in ROOTS}


def relative_source(name):
    if not isinstance(name, str):
        raise ValueError("source name must be text")
    p = PurePosixPath(name)
    if (p.is_absolute() or str(p) != name or
            ".." in p.parts or not p.parts or p.parts[0] not in SOURCE_DIRS or
            p.suffix not in SOURCE_SUFFIXES):
        raise ValueError("outside the tracked source allowlist")
    return name


def tracked(root):
    result = {}
    for row in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not row:
            continue
        info, name = row.split(b"\t", 1)
        mode, kind, blob = info.split()
        name = os.fsdecode(name)
        if mode not in (b"100644", b"100755") or kind != b"blob":
            continue
        try:
            relative_source(name)
        except ValueError:
            continue
        result[name] = blob.decode()
    return result


def identity(fd):
    s = os.fstat(fd)
    return {"device": s.st_dev, "inode": s.st_ino, "bytes": s.st_size,
            "mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid,
            "links": s.st_nlink, "mtime_ns": s.st_mtime_ns,
            "atime_ns": s.st_atime_ns, "ctime_ns": s.st_ctime_ns,
            "allocated_bytes": s.st_blocks * 512}


def stable(item):
    return {k: v for k, v in item.items() if k not in ("ctime_ns", "allocated_bytes")}


def open_source(root, name, writable=False):
    relative_source(name)
    path = root / name
    if path.resolve(strict=True) != path:
        raise ValueError("symlinked source path")
    fd = os.open(path, (os.O_RDWR if writable else os.O_RDONLY) |
                 os.O_NOFOLLOW | os.O_NOATIME | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or
                os.readlink(f"/proc/self/fd/{fd}") != str(path)):
            raise ValueError("exact singly linked regular source required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def bound_name(root, name, fd):
    path = root / relative_source(name)
    s, actual = os.stat(path, follow_symlinks=False), os.fstat(fd)
    if (path.resolve(strict=True) != path or
            (s.st_dev, s.st_ino) != (actual.st_dev, actual.st_ino) or
            os.readlink(f"/proc/self/fd/{fd}") != str(path)):
        raise ValueError("original source pathname moved")


def digest(fd):
    before = identity(fd)
    sha = hashlib.sha256()
    blob = hashlib.sha1(("blob %d\0" % before["bytes"]).encode())
    for off in range(0, before["bytes"], CHUNK):
        data = os.pread(fd, min(CHUNK, before["bytes"] - off), off)
        if not data:
            raise ValueError("source truncated during read")
        sha.update(data)
        blob.update(data)
    if stable(before) != stable(identity(fd)):
        raise ValueError("source identity changed during read")
    return sha.hexdigest(), blob.hexdigest()


def extent_pages(fd):
    end = os.fstat(fd).st_size // PAGE * PAGE
    ranges, shared, start = [], 0, 0
    while start < end:
        buf = bytearray(32 + 256 * 56)
        # No FIEMAP_FLAG_SYNC: this audit does not flush unrelated dirty data.
        struct.pack_into("=QQIIII", buf, 0, start, end-start, 0, 0, 256, 0)
        fcntl.ioctl(fd, FIEMAP, buf, True)
        count = struct.unpack_from("=I", buf, 20)[0]
        if not count:
            break
        previous = start
        for i in range(count):
            logical, _, length, _, _, flags, _, _, _ = struct.unpack_from(
                "=QQQQQIIII", buf, 32 + 56*i)
            lo, hi = (logical + PAGE-1) // PAGE * PAGE, min(end, logical+length) // PAGE * PAGE
            if hi > lo and not flags & UNSUITABLE:
                if flags & SHARED:
                    shared += hi-lo
                else:
                    ranges.append([lo, hi-lo])
            start = logical+length
        if start <= previous:
            raise ValueError("nonadvancing extent map")
        if flags & 1:
            break
    return ranges, shared


def holders():
    """Snapshot all foreign fd/mapping identities and cache working directories."""
    refs, working = set(), set()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            cwd = os.readlink(proc / "cwd")
            for root in ROOTS:
                if cwd == str(root) or cwd.startswith(str(root) + "/"):
                    working.add(str(root))
            for path in (proc / "fd").iterdir():
                try:
                    s = path.stat()
                    refs.add((s.st_dev, s.st_ino))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            for row in (proc / "maps").read_text().splitlines():
                fields = row.split(None, 5)
                if len(fields) >= 5 and fields[4] != "0":
                    major, minor = (int(v, 16) for v in fields[3].split(":"))
                    refs.add((os.makedev(major, minor), int(fields[4])))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return refs, working


def idle(item, refs):
    return ((item["device"], item["inode"]) not in refs and
            time.time_ns() - item["mtime_ns"] >= AGE_NS)


def report_path(path):
    path = path.absolute()
    if path.parent != REPORTS or path.name in ("", ".", ".."):
        raise ValueError("new report must be directly under build/disk-c009")
    REPORTS.mkdir(exist_ok=True)
    if REPORTS.resolve(strict=True) != REPORTS:
        raise ValueError("symlinked report directory")
    return path


def new_report(path):
    return os.fdopen(os.open(report_path(path), os.O_WRONLY | os.O_CREAT |
                            os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")


def make_plan(path):
    revisions = heads()
    if len(set(revisions.values())) != 1:
        raise ValueError("cache HEAD revisions differ")
    source_tree, destination_tree = tracked(SOURCE), tracked(DESTINATION)
    refs, working = holders()
    if str(SOURCE) in working or str(DESTINATION) in working:
        raise ValueError("a foreign process is working inside a source cache")
    rows, scanned, modified, busy = [], 0, 0, 0
    for name, blob in sorted(destination_tree.items()):
        if source_tree.get(name) != blob:
            continue
        try:
            dest = open_source(DESTINATION, name)
        except FileNotFoundError:
            continue
        try:
            di = identity(dest)
            ranges, already_shared = extent_pages(dest)
            if not ranges:
                continue
            if not idle(di, refs):
                busy += 1
                continue
            try:
                src = open_source(SOURCE, name)
            except FileNotFoundError:
                continue
            try:
                si = identity(src)
                if not idle(si, refs):
                    busy += 1
                    continue
                scanned += 1
                dh, db = digest(dest)
                sh, sb = digest(src)
                if db != blob or sb != blob or dh != sh:
                    modified += 1
                    continue
                bound_name(SOURCE, name, src)
                bound_name(DESTINATION, name, dest)
                if si["device"] != di["device"] or si["inode"] == di["inode"]:
                    continue
                rows.append({"relative": name, "git_blob": blob, "sha256": sh,
                             "source": str(SOURCE/name), "destination": str(DESTINATION/name),
                             "source_identity": si, "destination_identity": di,
                             "exclusive_page_ranges": ranges,
                             "already_shared_page_bytes": already_shared})
            finally:
                os.close(src)
        finally:
            os.close(dest)
    if heads() != revisions:
        raise ValueError("cache HEAD changed during planning")
    planned = sum(n for row in rows for _, n in row["exclusive_page_ranges"])
    if len(rows) > MAX_FILES or planned > MAX_BYTES:
        raise ValueError("source sharing plan exceeds its bounded allowance")
    result = {"schema": "win98modern.wine-source-share.v1", "created_utc": utc(),
              "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "heads": revisions, "files": rows,
              "summary": {"files": len(rows), "planned_exclusive_page_bytes": planned,
                          "candidate_logical_bytes": sum(r["destination_identity"]["bytes"] for r in rows),
                          "hashed_pairs": scanned, "modified_pairs_excluded": modified,
                          "busy_pairs_excluded": busy}}
    with new_report(path) as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print(json.dumps({"plan": str(path), **result["summary"]}), flush=True)


def valid_ranges(ranges, size):
    end = 0
    if type(size) is not int or size < 0 or not isinstance(ranges, list) or not ranges:
        raise ValueError("nonempty source ranges required")
    for pair in ranges:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("invalid range")
        off, length = pair
        if (type(off) is not int or type(length) is not int or off < end or
                length <= 0 or off % PAGE or length % PAGE or off+length > min(size, MAX_BYTES)):
            raise ValueError("range must be sorted, disjoint, aligned and inside the source")
        end = off+length


def apply_plan(path, result_path):
    if path.stat().st_size > 2 * CHUNK or path.is_symlink():
        raise ValueError("bounded regular plan required")
    plan = json.loads(path.read_text())
    if (plan.get("schema") != "win98modern.wine-source-share.v1" or
            plan.get("tool_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest() or
            plan.get("heads") != heads()):
        raise ValueError("reviewed tool and cache revision pins required")
    rows = plan["files"]
    if not isinstance(rows, list) or len(rows) > MAX_FILES:
        raise ValueError("bounded source file list required")
    allowed, destinations, total = tracked(DESTINATION), set(), 0
    for row in rows:
        name = relative_source(row["relative"])
        if (row["source"] != str(SOURCE/name) or row["destination"] != str(DESTINATION/name) or
                name in destinations or allowed.get(name) != row["git_blob"]):
            raise ValueError("exact distinct tracked source paths required")
        destinations.add(name)
        valid_ranges(row["exclusive_page_ranges"], row["destination_identity"]["bytes"])
        total += sum(n for _, n in row["exclusive_page_ranges"])
    if total > MAX_BYTES:
        raise ValueError("bounded page allowance exceeded")
    processed = compared = released = 0
    start_free = os.statvfs(DESTINATION).f_bavail * os.statvfs(DESTINATION).f_frsize
    with new_report(result_path) as out:
        def record(value):
            out.write(json.dumps(value) + "\n")
            out.flush()
            os.fsync(out.fileno())
        record({"event": "start", "utc": utc(), "plan_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "free_bytes": start_free, "planned_exclusive_page_bytes": total})
        try:
            for row in rows:
                src = open_source(SOURCE, row["relative"])
                try:
                    dest = open_source(DESTINATION, row["relative"], writable=True)
                    try:
                        for fd in (src, dest):
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        si, di = identity(src), identity(dest)
                        if stable(si) != stable(row["source_identity"]) or stable(di) != stable(row["destination_identity"]):
                            raise ValueError("planned source identity changed")
                        refs, working = holders()
                        if (str(SOURCE) in working or str(DESTINATION) in working or
                                not idle(si, refs) or not idle(di, refs)):
                            raise ValueError("source cache file is now active")
                        for fd in (src, dest):
                            sha, blob = digest(fd)
                            if sha != row["sha256"] or blob != row["git_blob"]:
                                raise ValueError("planned original source bytes changed")
                        bound_name(SOURCE, row["relative"], src)
                        bound_name(DESTINATION, row["relative"], dest)
                        before_ranges, _ = extent_pages(dest)
                        before_exclusive = sum(n for _, n in before_ranges)
                        shared = 0
                        operation_error = None
                        try:
                            for start, length in row["exclusive_page_ranges"]:
                                for off in range(start, start+length, CHUNK):
                                    size = min(CHUNK, start+length-off)
                                    request = bytearray(struct.pack("=QQHHIqQQiI", off, size, 1, 0, 0, dest, off, 0, 0, 0))
                                    fcntl.ioctl(src, FIDEDUPERANGE, request, True)
                                    values = struct.unpack("=QQHHIqQQiI", request)
                                    done, status = values[-3:-1]
                                    if status != 0 or done != size:
                                        raise ValueError("kernel did not share the entire identical range")
                                    shared += done
                        except BaseException as error:
                            operation_error = error
                        # Verify this file even if an earlier chunk succeeded and
                        # a subsequent kernel call failed. Never retry that plan.
                        os.fsync(dest)
                        for fd, old in ((src, si), (dest, di)):
                            if stable(identity(fd)) != stable(old) or digest(fd) != (row["sha256"], row["git_blob"]):
                                raise ValueError("source preservation verification failed")
                        bound_name(SOURCE, row["relative"], src)
                        bound_name(DESTINATION, row["relative"], dest)
                        after_ranges, _ = extent_pages(dest)
                        change = before_exclusive - sum(n for _, n in after_ranges)
                        processed += 1
                        compared += shared
                        released += change
                        record({"event": "file", "relative": row["relative"],
                                "status": "FAIL" if operation_error else "PASS",
                                "operation_error": str(operation_error) if operation_error else None,
                                "source_preservation_verified": True,
                                "sha256_before_after": row["sha256"], "logical_bytes": di["bytes"],
                                "kernel_compared_shared_bytes": shared, "exclusive_page_bytes_released": change,
                                "source_before": si, "source_after": identity(src),
                                "destination_before": di, "destination_after": identity(dest)})
                        if operation_error:
                            raise operation_error
                        if processed % 64 == 0:
                            print(json.dumps({"verified_files": processed, "exclusive_page_bytes_released": released}), flush=True)
                    finally:
                        os.close(dest)
                finally:
                    os.close(src)
            if heads() != plan["heads"]:
                raise ValueError("cache HEAD changed during sharing")
            s = os.statvfs(DESTINATION)
            summary = {"event": "complete", "status": "PASS", "utc": utc(),
                       "verified_files": processed, "kernel_compared_shared_bytes": compared,
                       "exclusive_page_bytes_released": released, "free_bytes_before": start_free,
                       "free_bytes_after": s.f_bavail*s.f_frsize, "concurrent_host_writes_possible": True,
                       "deleted_files": 0, "logical_file_changes": 0}
            record(summary)
            print(json.dumps(summary), flush=True)
        except BaseException as error:
            record({"event": "failed", "status": "FAIL", "utc": utc(), "verified_files": processed,
                    "exclusive_page_bytes_released": released, "error": str(error)})
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--plan", type=Path)
    actions.add_argument("--apply", type=Path)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or sys.byteorder != "little" or os.sysconf("SC_PAGESIZE") != PAGE:
        parser.error("Linux little-endian 4096-byte host required")
    if struct.calcsize("=QQHHI") != 24 or struct.calcsize("=QQHHIqQQiI") != 56:
        parser.error("24-byte UAPI header and 56-byte one-destination request required")
    for root in ROOTS:
        if root.resolve(strict=True) != root:
            parser.error("fixed original cache roots required")
    if args.plan:
        if args.result:
            parser.error("--result belongs to --apply")
        make_plan(args.plan)
    elif not args.result:
        parser.error("--apply requires a new --result JSONL path")
    else:
        apply_plan(args.apply, args.result)


if __name__ == "__main__":
    main()
