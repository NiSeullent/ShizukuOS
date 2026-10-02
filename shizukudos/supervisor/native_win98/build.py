#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare a private opt-in installed-Win98 Supervisor ESP, without running a VM.

Every disk/ROM/config/kernel input is explicit and SHA-pinned. The selected
private disk's DOS and Windows boot must be verified in a separate actual run.
"""
import argparse
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DISK_BYTES = 2 << 30
ROM_BYTES = 256 << 10
ESP_MIB = 2304
RESERVE = 17 << 30
CONFIG = (0x38395753, 1, 128, 0)


def safe_path(path):
    raw = Path(path).expanduser().absolute()
    if any(part.is_symlink() for part in (raw, *raw.parents)):
        raise ValueError("symlink input/output or parent is refused")
    resolved = raw.resolve()
    if any(resolved == base or base in resolved.parents for base in map(Path, ("/dev", "/proc", "/sys"))):
        raise ValueError("device and virtual filesystem paths are refused")
    return resolved


def fresh_output(path):
    path = safe_path(path)
    if path.exists() or not path.parent.is_dir():
        raise ValueError("a new owned output directory with an existing parent is required")
    if ROOT in path.parents:
        relative = path.relative_to(ROOT)
        if relative.parts[0] != "build":
            raise ValueError("private outputs inside the source tree must be under ignored build/")
        if (ROOT / ".git").exists():
            check = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index", str(path)],
                                   capture_output=True, timeout=10)
            if check.returncode:
                raise ValueError("private output is not git-ignored")
    return path


def stable(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def pin_format(expected):
    expected = expected.lower()
    if not re.fullmatch("[0-9a-f]{64}", expected):
        raise ValueError("an exact SHA-256 identity pin is required")
    return expected


def pinned_hash(path, expected, size=None, maximum=DISK_BYTES):
    path, expected = safe_path(path), pin_format(expected)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum or (size is not None and before.st_size != size):
            raise ValueError("nonempty regular file with the required bounded geometry is required")
        digest = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            digest.update(block)
        if stable(before) != stable(os.fstat(fd)) or stable(before) != stable(path.stat()) or digest.hexdigest() != expected:
            raise ValueError("input SHA/identity changed or differs")
        return before.st_size
    finally:
        os.close(fd)


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class ReadLeaseRegistry:
    """One break latch and complete live-FD checks; nested leases propagate SIGIO."""
    def __init__(self):
        self.broken = False
        self.checkpoints = []

    def __enter__(self):
        self.previous = signal.getsignal(signal.SIGIO)
        signal.signal(signal.SIGIO, self.break_requested)
        return self

    def break_requested(self, *args):
        self.broken = True
        if callable(self.previous):
            self.previous(*args)

    def check(self):
        if self.broken:
            raise RuntimeError("source read lease break requested")
        for checkpoint in self.checkpoints:
            checkpoint()

    def __exit__(self, *unused):
        try:
            self.check()
        finally:
            signal.signal(signal.SIGIO, self.previous)


@contextlib.contextmanager
def read_leased(path, expected, size=None, maximum=DISK_BYTES, *, registry=None):
    """An actual Linux read lease blocks writers; a break request fails the run."""
    path, expected = safe_path(path), pin_format(expected)
    with contextlib.ExitStack() as stack:
        if registry is None:
            registry = stack.enter_context(ReadLeaseRegistry())
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        leased, checkpoint = False, None
        try:
            before = os.fstat(fd)
            if size is None:
                size = before.st_size
            if not stat.S_ISREG(before.st_mode) or type(size) is not int or not 0 < size <= maximum or before.st_size != size:
                raise ValueError("leased regular input geometry mismatch")
            fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            leased = True

            def checkpoint():
                if registry.broken or safe_path(path) != path or stable(before) != stable(os.fstat(fd)) or stable(before) != stable(path.stat()) or fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_RDLCK:
                    raise RuntimeError("source read lease or identity changed")

            registry.checkpoints.append(checkpoint)
            registry.check()
            digest, consumed = hashlib.sha256(), 0
            while block := os.read(fd, min(1 << 20, size - consumed + 1)):
                registry.check()
                consumed += len(block)
                if consumed > size:
                    raise ValueError("leased source exceeds its exact extent")
                digest.update(block)
            registry.check()
            if consumed != size or digest.hexdigest() != expected:
                raise ValueError("leased source SHA/extent mismatch")
            os.lseek(fd, 0, os.SEEK_SET)
            yield fd, registry.check
            registry.check()
        finally:
            if checkpoint is not None and checkpoint in registry.checkpoints:
                registry.checkpoints.remove(checkpoint)
            try:
                if leased:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            finally:
                os.close(fd)


def space(path, remaining=0):
    if shutil.disk_usage(Path(path).parent).free < RESERVE + remaining:
        raise RuntimeError("17 GiB retained free space plus the remaining preparation budget is required")


def copy_fd(fd, checkpoint, destination, expected, size, maximum=DISK_BYTES, *, prefer_reflink=False, record_identity=False):
    """Copy the same read-leased descriptor into a fresh independent file.

    Explicit COW preference falls back only on unsupported clone operations.
    Sparse fallback skips zero 4 KiB runs while hashing every logical byte.
    A failed copy remains private and unaccepted; original inputs are unchanged.
    """
    destination, expected = safe_path(destination), pin_format(expected)
    method, fallback_errno = "streaming-sparse-zero-runs", None
    source_identity = stable(os.fstat(fd))
    if source_identity[2] != size or not 0 < size <= maximum:
        raise ValueError("leased copy extent mismatch")
    with destination.open("xb") as stream:
        checkpoint()
        cloned = False
        if prefer_reflink:
            space(destination, 1 << 20)
            try:
                fcntl.ioctl(stream.fileno(), 0x40049409, fd)  # Linux FICLONE.
                checkpoint()
                method, cloned = "leased-FICLONE-COW", True
            except OSError as error:
                if error.errno not in (errno.EXDEV, errno.EOPNOTSUPP, errno.ENOTTY, errno.ENOSYS, errno.EINVAL):
                    raise
                fallback_errno = error.errno
                checkpoint()
                # Failed unsupported clone never justifies a dense fallback.
                # Reserve the measured extent before sparse copying starts.
                space(destination, min(size, os.fstat(fd).st_blocks * 512))
                stream.truncate(0)
        if not cloned:
            os.lseek(fd, 0, os.SEEK_SET)
            digest, written = hashlib.sha256(), 0
            zero = bytes(1 << 20)
            while block := os.read(fd, 1 << 20):
                checkpoint()  # After read and before any owned data write.
                if written + len(block) > size:
                    raise ValueError("leased copy exceeds its bounded extent")
                digest.update(block)
                if block != zero[:len(block)]:
                    for at in range(0, len(block), 4096):
                        run = block[at:at + 4096]
                        if run != zero[:len(run)]:
                            space(destination, len(run))
                            stream.seek(written + at)
                            if stream.write(run) != len(run):
                                raise OSError("partial owned sparse write")
                written += len(block)
            if written != size or digest.hexdigest() != expected:
                raise ValueError("owned copy SHA/extent mismatch")
            stream.truncate(size)
        stream.flush()
        os.fsync(stream.fileno())
        checkpoint()
        owned = os.fstat(stream.fileno())
        if (owned.st_dev, owned.st_ino) == source_identity[:2] or stable(os.fstat(fd)) != source_identity:
            raise RuntimeError("copy inode independence or leased source identity failed")
        allocation = owned.st_blocks * 512
    checkpoint()
    pinned_hash(destination, expected, size, maximum=maximum)
    space(destination)
    result = {"method": method, "bytes": size, "sha256": expected,
            "allocated_bytes": allocation, "allocation_includes_shared_extents": cloned,
            "reflink_fallback_errno": fallback_errno, "source_lease_preserved": True,
            "independent_inode": True, "target_readback_verified": True}
    if record_identity:
        result["identity"] = list(stable(owned))
    return result


def preparation_budget(inputs):
    """Conservative ESP extent + measured input allocation + build metadata.

    Reflinks may cost fewer physical blocks; this deliberately counts their
    source allocation anyway. Full ESP capacity remains budgeted because FAT
    copies write complete logical members, including zero-filled disk sectors.
    Per-operation retained-space checks remain active throughout preparation.
    """
    measured = sum(min(item["bytes"], item["path"].stat().st_blocks * 512)
                   for item in inputs.values())
    return (ESP_MIB << 20) + measured + (128 << 20)


def config_bytes():
    return struct.pack("<4I", *CONFIG)


def validate_config(data):
    if data != config_bytes():
        raise ValueError("WIN98CFG.BIN must be exact version 1 / 128 MiB / reserved-zero config")


def validate_contents(name, fd):
    """Inspect the same pinned, read-leased descriptor that supplies the copy.

    MBR/ROM checks identify a supported container, not an installed Windows OS.
    """
    os.lseek(fd, 0, os.SEEK_SET)
    if name == "WIN98CFG.BIN":
        validate_config(os.read(fd, 17))
    elif name == "SEABIOS.BIN":
        rom = os.read(fd, ROM_BYTES + 1)
        if len(rom) != ROM_BYTES or rom[-16] not in (0xEA, 0xE9) or b"SeaBIOS" not in rom:
            raise ValueError("the pinned ROM lacks the supported x86 reset jump or SeaBIOS identifier")
    elif name == "DISK.IMG":
        mbr = os.read(fd, 512)
        if len(mbr) != 512 or mbr[-2:] != b"\x55\xaa":
            raise ValueError("the owned disk lacks an MBR signature")
    os.lseek(fd, 0, os.SEEK_SET)


def source_files():
    files = {p for folder in ("shizukudos/supervisor", "shizukudos/abi", "shizukudos/uefi", "shizukudos/boot_profile")
             for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld", ".py")}
    files.update(ROOT / p for p in ("shizukudos/tools/shzlib.py", "shizukudos/kernel64/standalone/memholes.h",
                                  "shizukudos/kernel32/service_policy.h"))
    # The ordinary Supervisor payload links the existing CSMWrap glyph source.
    # Pin its implementation, interface and included font outside Supervisor/.
    files.update(ROOT / "shizukudos/csmwrap/video" / name
                 for name in ("cp437.c", "cp437.h", "font8x8_basic.h"))
    return sorted(files)


def command(argv, receipt, cwd=None, timeout=120, *, pass_fds=()):
    argv = list(map(str, argv))
    receipt["commands"].append(argv)
    subprocess.run(argv, cwd=cwd, check=True, timeout=timeout, stdout=subprocess.DEVNULL, pass_fds=pass_fds)


def verify_esp_member(esp, name, expected, size, receipt, timeout=120):
    """Read actual FAT member bytes through mtype into a bounded streaming hash.

    No full-size readback file is materialized. Nonzero exit, timeout, excess
    bytes or a digest/extent difference fails the private build.
    """
    argv = ["mtype", "-i", str(esp), "::/" + name]
    receipt["commands"].append(argv)
    digest, count = hashlib.sha256(), 0
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("ESP member streaming readback timed out")
                if not selector.select(remaining):
                    raise TimeoutError("ESP member streaming readback timed out")
                block = os.read(child.stdout.fileno(), 1 << 20)
                if not block:
                    break
                count += len(block)
                if count > size:
                    raise ValueError("ESP byte readback mismatch: " + name)
                digest.update(block)
        if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise RuntimeError("ESP member readback command failed: " + name)
        if count != size or digest.hexdigest() != pin_format(expected):
            raise ValueError("ESP byte readback mismatch: " + name)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()
    return {"bytes": count, "sha256": digest.hexdigest(), "method": "mtype-streaming-SHA256"}


def assemble(out, copies, loader, receipt, *, scratch=None):
    if scratch is None:
        return _assemble(out, copies, loader, receipt)
    guard_path = HERE / "ram_assembly.py"
    guard_size, guard_sha = guard_path.stat().st_size, file_sha(guard_path)
    # These artifact leases outlive the guard and placement cleanup.
    with contextlib.ExitStack() as artifacts, read_leased(guard_path, guard_sha, guard_size, maximum=1 << 20) as (guard_fd, checkpoint):
        namespace = {"__file__": str(guard_path), "__name__": "native_ram_assembly_guard"}
        exec(compile(os.pread(guard_fd, guard_size, 0), str(guard_path), "exec"), namespace)
        checkpoint()
        with namespace["Placement"].create(scratch, out) as placement:
            work = Path(placement.plan["scratch"]["path"])
            plan_path = work / "ram-placement.json"
            raw = (json.dumps(placement.plan, indent=2) + "\n").encode()
            placement.check(len(raw))
            fd = os.open("ram-placement.json", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=placement.fds["scratch"])
            try:
                if os.write(fd, raw) != len(raw):
                    raise OSError("short RAM placement write")
                os.fsync(fd)
                if os.pread(fd, len(raw)+1, 0) != raw:
                    raise ValueError("RAM placement readback differs")
            finally:
                os.close(fd)
            plan_sha = hashlib.sha256(raw).hexdigest()
            with read_leased(plan_path, plan_sha, len(raw), maximum=64 << 10):
                esp, identities = _assemble(out, copies, loader, receipt, placement=placement,
                    ram_guard=(guard_fd, guard_size, guard_sha, guard_path, plan_path, plan_sha))
                checkpoint(); placement.check()
                produced = receipt.get("disk_insertion", {}).get("result", {}).get("esp")
                if not produced or produced["path"] != str(esp) or list(stable(esp.stat())) != produced["identity"]:
                    raise ValueError("RAM ESP no longer matches the returned producer identity")
                size, pin = produced["bytes"], pin_format(produced["sha256"])
                final = out / "esp-win98.img"
                source_fd, source_check = artifacts.enter_context(read_leased(esp, pin, size, maximum=ESP_MIB << 20))
                if list(stable(os.fstat(source_fd))) != produced["identity"]:
                    raise ValueError("RAM ESP producer identity changed during lease admission")
                copied = copy_fd(source_fd, source_check, final, pin, size,
                                 maximum=ESP_MIB << 20, prefer_reflink=True, record_identity=True)
                final_fd, final_check = artifacts.enter_context(read_leased(final, pin, size, maximum=ESP_MIB << 20))
                if list(stable(os.fstat(final_fd))) != copied["identity"]:
                    raise ValueError("NAS ESP differs from its actual copied inode")
                os.fsync(placement.fds["sink"])
                source_check(); final_check(); checkpoint(); placement.check()
                if (final.stat().st_dev, final.stat().st_ino) == (esp.stat().st_dev, esp.stat().st_ino):
                    raise ValueError("RAM assembly and final NAS inode must differ")
                receipt["ram_assembly"] = {"placement": placement.plan, "guard_source_sha256": guard_sha,
                    "temporary_ESP": str(esp), "final_copy": copied, "final_identity": copied["identity"],
                    "final_directory_fsync_completed": True, "worker_deadline_seconds": 120,
                    "NAS_reserve_bytes": RESERVE, "independent_NAS_copy_full_SHA_verified": True}
            checkpoint(); placement.check()
        checkpoint()
    return final, identities


def _assemble(out, copies, loader, receipt, *, placement=None, ram_guard=None):
    space(out, ESP_MIB << 20)
    work = out if placement is None else Path(placement.plan["scratch"]["path"])
    def step(argv):
        if placement is not None:
            placement.check()
        command(argv, receipt)
        if placement is not None:
            placement.check()
    esp = work / "esp-win98.img"
    with esp.open("xb") as stream:
        stream.truncate(ESP_MIB << 20)
        owned_esp = stable(os.fstat(stream.fileno()))[:3]
    # Avoid mkfs.fat's default whole-track rounding at the 2304 MiB extent.
    # The strict inserter requires the FAT BPB to cover every owned sector.
    step(["mkfs.vfat", "-F", "32", "-g", "1/1", "-n", "SHZWIN98", "-i", "53485739", esp])
    step(["mmd", "-i", esp, "::/EFI", "::/EFI/BOOT", "::/EFI/SHIZUKU", "::/SHZDOS"])
    policy = out / "BOOT.INI"
    policy.write_bytes(b"mode=supervisor\r\nmenu_timeout=0\r\n")
    members = {"EFI/BOOT/BOOTX64.EFI": loader, "EFI/SHIZUKU/BOOT.INI": policy,
               **{"SHZDOS/" + name: source for name, source in copies.items()}}
    identities = {}
    # Keep every ordinary boot/member producer. The large disk is inserted
    # last, so no subsequent mtools writer changes its FAT/FSInfo metadata.
    for name, source in members.items():
        if name == "SHZDOS/DISK.IMG":
            continue
        size, pin = source.stat().st_size, file_sha(source)
        space(out, size)
        step(["mcopy", "-i", esp, source, "::/" + name])
        verify_esp_member(esp, name, pin, size, receipt)
        identities[name] = {"bytes": size, "sha256": pin}
        space(out)
    if "SHZDOS/DISK.IMG" in members:
        source = safe_path(members["SHZDOS/DISK.IMG"])
        size, pin = source.stat().st_size, file_sha(source)
        space(out, size)
        if stable(esp.stat())[:3] != owned_esp:
            raise ValueError("fresh owned ESP inode/extent changed before disk insertion")
        # Lazy worker execution: run_vm's frozen four-helper guards do not
        # require a sibling packer merely to import this module.
        helper = HERE / "sparse_fat32.py"
        helper_size, helper_sha = helper.stat().st_size, file_sha(helper)
        request_path, result_path = work / "disk-insertion-request.json", work / "disk-insertion.json"
        request = {"schema": "shizukuos.sparse-fat32-request.v1", "member": "SHZDOS/DISK.IMG",
                   "source": {"path": str(source), "bytes": size, "sha256": pin, "identity": list(stable(source.stat()))},
                   "esp": {"path": str(safe_path(esp)), "bytes": esp.stat().st_size, "identity": list(stable(esp.stat()))},
                   "producer": {"sha256": helper_sha, "bytes": helper_size}, "result": str(safe_path(result_path))}
        raw = (json.dumps(request, indent=2) + "\n").encode()
        with os.fdopen(os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), "wb") as stream:
            if stream.write(raw) != len(raw):
                raise OSError("short private insertion request write")
            stream.flush(); os.fsync(stream.fileno())
        request_sha = hashlib.sha256(raw).hexdigest()
        # Only this held, read-leased helper FD crosses exec. The worker opens
        # and owns source/ESP descriptions and leases independently.
        bootstrap = ("import hashlib,os,sys\n"
                     "fd,n,name,pin=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[4]\n"
                     "parts=[];at=0\n"
                     "while at<n:\n"
                     " b=os.pread(fd,n-at,at)\n"
                     " if not b:raise ValueError('held worker source EOF')\n"
                     " parts.append(b);at+=len(b)\n"
                     "body=b''.join(parts)\n"
                     "if hashlib.sha256(body).hexdigest()!=pin:raise ValueError('held worker SHA differs')\n"
                     "g={'__name__':'__main__','__file__':name,'_EXECUTED_SOURCE_SHA256':pin,'_EXECUTED_SOURCE_BYTES':n}\n"
                     "sys.argv=[name,*sys.argv[5:]]\n"
                     "exec(compile(body,name,'exec'),g)\n")
        return_read, return_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            if os.fpathconf(return_write, 'PC_PIPE_BUF') < 512:
                raise ValueError("512-byte atomic metadata return unavailable")
            with read_leased(helper, helper_sha, helper_size, maximum=1 << 20) as (helper_fd, checkpoint):
                checkpoint()
                deadline = time.monotonic() + 120
                ram_args, ram_fds = [], ()
                if ram_guard is not None:
                    guard_fd, guard_size, guard_sha, guard_path, plan_path, plan_sha = ram_guard
                    ram_args = ["--ram-placement", plan_path, "--ram-placement-sha256", plan_sha,
                                "--ram-guard-fd", str(guard_fd), "--ram-guard-size", str(guard_size),
                                "--ram-guard-sha256", guard_sha, "--ram-guard-path", guard_path]
                    ram_fds = (guard_fd,)
                try:
                    command([sys.executable, "-B", "-c", bootstrap, str(helper_fd), str(helper_size), str(helper), helper_sha,
                         "--request", request_path, "--request-sha256", request_sha, "--result", result_path, "--return-fd", str(return_write), *ram_args],
                            receipt, timeout=120, pass_fds=(helper_fd, return_write, *ram_fds))
                finally:
                    os.close(return_write); return_write = None
                packet = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(return_read, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise TimeoutError("producer return exceeded original child deadline")
                        part = os.read(return_read, 513-len(packet))
                        if not part:
                            break
                        packet.extend(part)
                        if len(packet) > 512:
                            raise ValueError("producer return exceeded 512 bytes")
                def unique_packet(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError("duplicate producer return field")
                        value[key] = item
                    return value
                returned = json.loads(bytes(packet), object_pairs_hook=unique_packet)
                if (type(returned) is not dict or set(returned) != {"schema", "bytes", "sha256"} or
                    returned["schema"] != "shizukuos.sparse-fat32-return.v1" or type(returned["bytes"]) is not int or
                    not 0 < returned["bytes"] <= 64 << 10 or type(returned["sha256"]) is not str or
                    returned["sha256"] != pin_format(returned["sha256"])):
                    raise ValueError("exact bounded producer return required")
                checkpoint()
                pinned_hash(request_path, request_sha, len(raw), maximum=64 << 10)
                result_size, result_sha = returned["bytes"], returned["sha256"]
                pinned_hash(result_path, result_sha, result_size, maximum=64 << 10)
                def unique_result_object(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError("duplicate insertion result field")
                        value[key] = item
                    return value
                with read_leased(result_path, result_sha, result_size, maximum=64 << 10) as (result_fd, result_checkpoint):
                    result = json.loads(os.pread(result_fd, result_size, 0), object_pairs_hook=unique_result_object)
                    if set(result) != {"schema", "status", "request_sha256", "producer_sha256", "producer_bytes", "source", "esp", "member", "fat", "result_inode", "Windows98_executed", "VM_executed", "Windows98_boot_verified"}:
                        raise ValueError("exact insertion result schema required")
                    if (result["schema"] != "shizukuos.sparse-fat32-result.v1" or
                        result["status"] != "PRIVATE_FAT32_MEMBER_INSERTED_NOT_RUN" or
                        result["request_sha256"] != request_sha or result["producer_sha256"] != helper_sha or result["producer_bytes"] != helper_size or
                        any(result[k] is not False for k in ("Windows98_executed", "VM_executed", "Windows98_boot_verified")) or
                        result["result_inode"] != list(stable(os.fstat(result_fd))[:2])):
                        raise ValueError("insertion result source/request/owned inode differs")
                    supplied = result["source"]
                    if (set(supplied) != {"path", "bytes", "sha256", "identity", "before_sha256", "streamed_sha256", "lease_finalized"} or
                        any(supplied[k] != request["source"][k] for k in ("path", "bytes", "sha256", "identity")) or
                        list(stable(source.stat())) != supplied["identity"] or
                        supplied["before_sha256"] != pin or supplied["streamed_sha256"] != pin or supplied["lease_finalized"] is not True):
                        raise ValueError("insertion source identity/hash differs")
                    target, member, fat = result["esp"], result["member"], result["fat"]
                    if (set(target) != {"path", "bytes", "identity", "sha256", "independent_inode", "fsync_completed"} or
                        target["path"] != request["esp"]["path"] or target["bytes"] != request["esp"]["bytes"] or
                        target["identity"] != list(stable(esp.stat())) or target["identity"][:3] != list(owned_esp) or
                        target["independent_inode"] is not True or target["fsync_completed"] is not True or
                        file_sha(esp) != pin_format(target["sha256"])):
                        raise ValueError("post-worker owned ESP identity/hash differs")
                    if (set(member) != {"path", "bytes", "sha256", "clusters", "cluster_bytes", "zero_bytes_omitted", "data_bytes_written", "padding_zero_bytes"} or
                        member["path"] != "SHZDOS/DISK.IMG" or member["bytes"] != size or member["sha256"] != pin or
                        any(type(member[k]) is not int or member[k] < 0 for k in ("clusters", "cluster_bytes", "zero_bytes_omitted", "data_bytes_written", "padding_zero_bytes")) or
                        member["zero_bytes_omitted"] + member["data_bytes_written"] != size or not member["cluster_bytes"] or
                        not 512 <= member["cluster_bytes"] <= 65536 or member["cluster_bytes"] & (member["cluster_bytes"]-1) or
                        member["clusters"] != (size+member["cluster_bytes"]-1)//member["cluster_bytes"] or
                        member["clusters"] * member["cluster_bytes"] != size + member["padding_zero_bytes"] or
                        set(fat) != {"copies", "free_clusters_before", "free_clusters_after", "next_free", "mirrors_verified", "FSInfo_copies"} or
                        fat["copies"] != 2 or fat["FSInfo_copies"] != 2 or fat["mirrors_verified"] is not True or
                        any(type(fat[k]) is not int or fat[k] < 0 for k in ("copies", "FSInfo_copies", "free_clusters_before", "free_clusters_after", "next_free")) or
                        fat["free_clusters_before"] - fat["free_clusters_after"] != member["clusters"]):
                        raise ValueError("insertion member/FAT accounting differs")
                    verify_esp_member(esp, "SHZDOS/DISK.IMG", pin, size, receipt)
                    for name, item in identities.items():
                        verify_esp_member(esp, name, item["sha256"], item["bytes"], receipt)
                    if list(stable(esp.stat())) != target["identity"] or list(stable(source.stat())) != supplied["identity"]:
                        raise ValueError("ESP changed during independent member readback")
                    result_checkpoint(); checkpoint()
                    receipt["disk_insertion"] = {"result": result, "result_sha256": result_sha, "request_sha256": request_sha,
                                                 "helper_sha256": helper_sha, "independent_mtype_verified": True}
                checkpoint()
        finally:
            if return_write is not None:
                os.close(return_write)
            os.close(return_read)
        identities["SHZDOS/DISK.IMG"] = {"bytes": size, "sha256": pin}
        space(out)
    return esp, identities


def main(argv=None, *, receipt_sink=None):
    if receipt_sink is not None and not callable(receipt_sink):
        raise TypeError("receipt_sink must be callable")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--make-config", type=Path, help="create a new public 16-byte opt-in config and print its SHA")
    for name in ("disk", "rom", "config", "kernel32", "kernel64", "win64-img"):
        parser.add_argument("--" + name, type=Path)
        parser.add_argument("--" + name + "-sha256")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--assembly-scratch", type=Path,
                        help="fresh owned tmpfs workspace; final ESP still uses --out and its 17GiB reserve")
    parser.add_argument("--validate-only", action="store_true", help="check all explicit inputs without output or compilation")
    args = parser.parse_args(argv)
    if args.make_config:
        if any(getattr(args, name) for name in ("disk", "rom", "config", "kernel32", "kernel64", "win64_img", "out")):
            parser.error("--make-config is separate from private build inputs")
        path = safe_path(args.make_config)
        with path.open("xb") as stream:
            stream.write(config_bytes())
        print(json.dumps({"config": str(path), "bytes": 16, "sha256": file_sha(path)}))
        return 0
    required = ("disk", "rom", "config", "kernel32", "kernel64")
    if any(not getattr(args, name) or not getattr(args, name + "_sha256") for name in required):
        parser.error("explicit disk, ROM, config, Kernel32, Kernel64 and each SHA-256 are required for the native Win98 foundation")
    if args.win64_img and not args.kernel64:
        parser.error("WIN64.IMG requires an explicit Kernel64 input")
    sizes = {"disk": DISK_BYTES, "rom": ROM_BYTES, "config": 16}
    targets = {"disk": "DISK.IMG", "rom": "SEABIOS.BIN", "config": "WIN98CFG.BIN",
               "kernel32": "KERNEL32.BIN", "kernel64": "KERNEL64.BIN", "win64_img": "WIN64.IMG"}
    # The current loader gives K64 64 MiB and puts its archive at 32 MiB.
    # Larger archives require an explicit RAM/layout change, not a success claim.
    maximum = {"kernel32": 8 << 20, "kernel64": 16 << 20, "win64_img": 32 << 20}
    selected = {}
    for name, target in targets.items():
        path, pin = getattr(args, name), getattr(args, name + "_sha256")
        if bool(path) != bool(pin):
            parser.error("each optional input requires its SHA-256 pair")
        if path:
            selected[target] = {"path": safe_path(path), "sha256": pin_format(pin),
                                "required_size": sizes.get(name), "maximum": maximum.get(name, DISK_BYTES)}
    out, receipt = None, None
    try:
        with contextlib.ExitStack() as artifact_stack, contextlib.ExitStack() as stack:
            # Artifact custody closes after every original input and its registry.
            artifact_registry = artifact_stack.enter_context(ReadLeaseRegistry())
            registry = stack.enter_context(ReadLeaseRegistry())
            inputs, descriptors = {}, {}
            for name, item in selected.items():
                fd, checkpoint = stack.enter_context(read_leased(item["path"], item["sha256"],
                                                                 item["required_size"], item["maximum"], registry=registry))
                inputs[name] = {"path": item["path"], "sha256": item["sha256"], "bytes": os.fstat(fd).st_size}
                descriptors[name] = fd
            for name, fd in descriptors.items():
                validate_contents(name, fd)
                registry.check()
            if not args.validate_only:
                if not args.out:
                    parser.error("a new --out private directory is required for building")
                out = fresh_output(args.out)
                budget = preparation_budget(inputs)
                space(out, budget)
                out.mkdir()
                receipt = {"status": "FAIL_BUILD_PRESERVED", "private": True, "commands": [],
                           "preparation_budget_bytes": budget, "retained_free_space_bytes": RESERVE, "copies": {},
                           "input_pins": {n: {**item, "path": str(item["path"])} for n, item in inputs.items()},
                           "Windows98_installation_identity_verified": False, "VM_executed": False,
                           "Windows98_boot_verified": False, "MS_DOS_replaced": False, "native_Win64_app_verified": False}
                copies = {}
                for name, item in inputs.items():
                    destination = out / name
                    registry.check()
                    receipt["copies"][name] = copy_fd(descriptors[name], registry.check, destination,
                                                      item["sha256"], item["bytes"], prefer_reflink=True)
                    registry.check()
                    copies[name] = destination
                files = source_files()
                pins = {str(p.relative_to(ROOT)): file_sha(p) for p in files}
                snapshot = out / "source"
                for source in files:
                    registry.check()
                    relative = source.relative_to(ROOT)
                    pinned_hash(source, pins[str(relative)], source.stat().st_size, 16 << 20)
                    destination = snapshot / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    if file_sha(destination) != pins[str(relative)]:
                        raise ValueError("source snapshot hash differs")
                    registry.check()
                components = out / "components"
                command([sys.executable, snapshot / "shizukudos/supervisor/native_win98/compile.py", "--out", components], receipt, timeout=300)
                registry.check()
                compiled = json.loads((components / "result.json").read_text())
                if compiled["status"] != "PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN":
                    raise ValueError("ordinary native component compilation did not complete")
                loader = components / "BOOTX64.EFI"
                if file_sha(loader) != compiled["artifacts"]["BOOTX64.EFI"]["sha256"]:
                    raise ValueError("new loader does not match its compilation receipt")
                registry.check()
                if args.assembly_scratch is None:
                    esp, members = assemble(out, copies, loader, receipt)
                else:
                    esp, members = assemble(out, copies, loader, receipt, scratch=args.assembly_scratch)
                    known = receipt["ram_assembly"]
                    final_fd, final_check = artifact_stack.enter_context(read_leased(esp, known["final_copy"]["sha256"],
                        known["final_copy"]["bytes"], maximum=ESP_MIB << 20, registry=artifact_registry))
                    if list(stable(os.fstat(final_fd))) != known["final_identity"]:
                        raise ValueError("final NAS ESP changed after assembly return")
                    final_check()
                registry.check()
                if pins != {str(p.relative_to(ROOT)): file_sha(p) for p in files}:
                    raise ValueError("public source changed during private preparation")
                if args.assembly_scratch is None:
                    artifact = {"path": esp.name, "bytes": esp.stat().st_size, "sha256": file_sha(esp)}
                else:
                    artifact = {"path": esp.name, "bytes": known["final_copy"]["bytes"],
                                "sha256": known["final_copy"]["sha256"]}
                registry.check()
                success = {"sources_sha256": pins, "members": members, "artifact": artifact,
                           "source_before_after_match": True, "originals_before_after_match": True,
                           "original_input_leases_held_through_artifact_finalization": True,
                           "boot_path": "UEFI Supervisor -> explicit Win98 VMCS -> SeaBIOS -> selected private disk; guest boot unverified",
                           "next_gate": "Actual isolated L1/VMX DOS and Windows boot, VMM channel, GUI, app and replacement verification"}
            registry.check()
        # Every mandatory lease unlock/FD close must succeed before PASS escapes.
        if args.validate_only:
            print(json.dumps({"status": "PASS_EXPLICIT_INPUT_VALIDATION_NO_BUILD_OR_VM", "input_files": len(inputs),
                              "Windows98_installation_identity_verified": False, "Windows98_executed": False}))
            return 0
        receipt.update(status="PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN", **success)
    except BaseException as error:
        if receipt is not None:
            receipt["status"] = "FAIL_BUILD_PRESERVED"
            receipt["error"] = str(error)
        raise
    finally:
        if receipt is not None:
            (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt_sink is not None:
        receipt_sink((json.dumps(receipt, indent=2) + "\n").encode())
    print(json.dumps({"status": receipt["status"], "private_ESP": str(esp), "sha256": receipt["artifact"]["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
