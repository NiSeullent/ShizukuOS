#!/usr/bin/env python3
"""Store a pinned private build artifact on the user-selected NAS over SSH.

This archive operation neither publishes media nor certifies Windows boot. The
existing SSH alias supplies authentication; no credentials or global settings
are written. Source read leases and remote exclusive creation prevent a changing
input or an existing archive from silently becoming the accepted artifact.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time

REMOTE_ROOT = "/volume2/homes/sharhene777/ShizukuOS-private"
MAX_BYTES = 8 << 30
# Only data is passed in argv. This exact reviewed helper is executed over the
# already configured SSH connection; it accepts no commands from receipt data.
REMOTE_HELPER = r'''
import hashlib,json,os,re,stat,sys,uuid
from pathlib import Path
root=Path(sys.argv[1]); name=sys.argv[2]; size=int(sys.argv[3]); expected=sys.argv[4]
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",name) or name in (".",".."):
    raise ValueError("invalid archive basename")
if not 0<size<=8<<30 or not re.fullmatch(r"[0-9a-f]{64}",expected):
    raise ValueError("invalid geometry/pin")
if not root.is_absolute() or any(p.is_symlink() for p in (root,*root.parents)):
    raise ValueError("canonical private root required")
st=root.stat()
if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:
    raise ValueError("private root must be owned and mode0700")
if os.statvfs(root).f_bavail*os.statvfs(root).f_frsize < size+(1<<30):
    raise ValueError("NAS capacity admission failed")
final=root/name
if final.exists() or final.is_symlink(): raise ValueError("archive already exists")
tmp=root/(".incoming-"+uuid.uuid4().hex)
fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    digest=hashlib.sha256(); count=0
    with os.fdopen(fd,"wb") as out:
        while True:
            block=sys.stdin.buffer.read(1<<20)
            if not block: break
            count+=len(block)
            if count>size: raise ValueError("stream exceeds pinned size")
            out.write(block); digest.update(block)
        out.flush(); os.fsync(out.fileno())
    if count!=size or digest.hexdigest()!=expected:
        raise ValueError("stream differs from pinned artifact")
    readback=hashlib.sha256()
    with tmp.open("rb") as source:
        for block in iter(lambda:source.read(1<<20),b""): readback.update(block)
    if readback.hexdigest()!=expected: raise ValueError("NAS readback differs")
    os.link(tmp,final,follow_symlinks=False)
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    print(json.dumps(dict(path=str(final),bytes=count,sha256=expected,
        readback_sha256=readback.hexdigest(),exclusive_creation=True,mode=oct(final.stat().st_mode&0o777))))
finally:
    tmp.unlink(missing_ok=True)
'''


def identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def validate_input(path, expected):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("source symlinks are refused")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("explicit exact source SHA256 required")
    return path


def store(path, expected, name, receipt_path, timeout=1800):
    path = validate_input(path, expected)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) or name in (".", ".."):
        raise ValueError("simple remote artifact basename required")
    if not 30 <= timeout <= 3600:
        raise ValueError("timeout must be30..3600 seconds")
    receipt_path = Path(receipt_path).absolute()
    if receipt_path.exists() or not receipt_path.parent.is_dir() or any(
            p.is_symlink() for p in (receipt_path, *receipt_path.parents)):
        raise ValueError("new receipt in an existing canonical directory required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    previous = signal.getsignal(signal.SIGIO)
    broken = [False]
    leased = False
    child = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError("bounded nonempty regular artifact required")
        signal.signal(signal.SIGIO, lambda *_: broken.__setitem__(0, True))
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        leased = True

        def checkpoint():
            if broken[0] or identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.stat()):
                raise ValueError("source lease/identity changed")

        digest = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            digest.update(block)
            checkpoint()
        if digest.hexdigest() != expected:
            raise ValueError("source differs from explicit artifact pin")
        os.lseek(fd, 0, os.SEEK_SET)
        remote = shlex.join(["python3", "-c", REMOTE_HELPER, REMOTE_ROOT, name, str(before.st_size), expected])
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "snowra-f-nas", remote]
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        os.set_blocking(child.stderr.fileno(), False)
        deadline = time.monotonic() + timeout
        pending = memoryview(b"")
        eof = False
        outputs = {"out": bytearray(), "err": bytearray()}
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdin, selectors.EVENT_WRITE, "in")
            poll.register(child.stdout, selectors.EVENT_READ, "out")
            poll.register(child.stderr, selectors.EVENT_READ, "err")
            while poll.get_map():
                checkpoint()
                if time.monotonic() >= deadline:
                    raise TimeoutError("bounded NAS transfer timed out")
                for key, _ in poll.select(min(1, max(0, deadline - time.monotonic()))):
                    if key.data == "in":
                        if not pending and not eof:
                            pending = memoryview(os.read(fd, 1 << 20))
                            eof = not pending
                        if eof:
                            poll.unregister(child.stdin)
                            child.stdin.close()
                        else:
                            try:
                                used = os.write(child.stdin.fileno(), pending)
                                pending = pending[used:]
                            except BlockingIOError:
                                pass
                    else:
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            poll.unregister(key.fileobj)
                        else:
                            outputs[key.data].extend(chunk)
                            if len(outputs[key.data]) > 16384:
                                raise ValueError("bounded NAS helper output exceeded")
        rc = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if rc:
            raise RuntimeError("NAS helper failed: " + outputs["err"].decode(errors="replace")[-2000:])
        checkpoint()
        remote_result = json.loads(outputs["out"])
        if (remote_result.get("path") != REMOTE_ROOT + "/" + name or remote_result.get("bytes") != before.st_size
                or remote_result.get("sha256") != expected or remote_result.get("readback_sha256") != expected
                or remote_result.get("exclusive_creation") is not True or remote_result.get("mode") != "0o600"):
            raise ValueError("remote readback receipt differs")
        receipt = {"schema": "shizukuos.nas-archive.v1", "status": "PASS_PRIVATE_NAS_ARCHIVE",
                   "source": {"path": str(path), "bytes": before.st_size, "sha256": expected},
                   "remote": remote_result, "SSH_alias": "snowra-f-nas", "source_lease_preserved": True,
                   "source_before_after_match": True, "NAS_helper_sha256": hashlib.sha256(REMOTE_HELPER.encode()).hexdigest(),
                   "VM_executed": False, "Windows98_boot_verified": False, "public_release": False}
        with receipt_path.open("x") as out:
            json.dump(receipt, out, indent=2)
            out.write("\n")
        return receipt
    finally:
        if child is not None:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            for pipe in (child.stdin, child.stdout, child.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        if leased:
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        signal.signal(signal.SIGIO, previous)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    result = store(args.source, args.sha256, args.name, args.receipt, args.timeout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
