#!/usr/bin/python3
"""Serialize this private wrapper; preserve QEMU argv and refuse a third lane.

External launchers do not take this lock and can race the final snapshot.
This is an additional conditional guard, not a global host concurrency cap.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ACTUAL_QEMU = '/usr/libexec/qemu-kvm'
ACTUAL_QEMU_SHA256 = 'ea9073d267ec64048e8078c5fc0cb0d091bacf11587bdd6b05cf3d46181ffe09'
LOCK_PATH = '/root/Win98-Modern-boot/build/native-boot-concurrency-guard-20261001T0650-v2/boot-lane.lock'


def snapshot():
    rows = []
    for directory in Path('/proc').glob('[0-9]*'):
        try:
            words = (directory / 'cmdline').read_bytes().split(b'\0')
            if not words or 'qemu' not in Path(words[0].decode(errors='replace')).name:
                continue
            argv = [word.decode(errors='replace') for word in words if word]
            if '-name' in argv:
                position = argv.index('-name') + 1
                if position == len(argv):
                    raise RuntimeError('unavailable QEMU process name')
                name = argv[position]
            else:
                name = ''
            owned_paths = [word for word in argv if 'windows-uefi.raw' in word and '/root/Win98-Modern' in word]
            if not owned_paths and not name.startswith('shz-disposable-win98'):
                continue
            status = (directory / 'stat').read_text().rpartition(') ')[2].split()
            if len(status) < 20:
                raise RuntimeError('unavailable Win98 process identity')
            start = status[19]
            fds = []
            for fd in (directory / 'fd').iterdir():
                try:
                    target = os.readlink(fd)
                    if ('windows-uefi.raw' in target or 'OVMF_VARS.fd' in target) and '/root/Win98-Modern' in target:
                        fds.append(target)
                except FileNotFoundError:
                    continue
            verify = (directory / 'stat').read_text().rpartition(') ')[2].split()
            if len(verify) < 20 or verify[19] != start:
                continue
            rows.append({'pid': int(directory.name), 'start_ticks': int(start), 'state': verify[0],
                         'name': name, 'image_arguments': owned_paths, 'open_backing_FDs': sorted(set(fds))})
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise RuntimeError('unable to inspect a repository Win98 boot lane') from error
    return rows


def verify_binary():
    digest = hashlib.sha256()
    with open(ACTUAL_QEMU, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != ACTUAL_QEMU_SHA256 or not os.access(ACTUAL_QEMU, os.X_OK):
        raise RuntimeError('original QEMU binary differs from the frozen pin')


def main(argv):
    if argv == ['--inspect']:
        print(json.dumps({'repository_Win98_boot_lanes': snapshot()}, indent=2))
        return 0
    if '-name' not in argv:
        print('OWNED_BOOT_GUARD_REJECTED: expected retained Win98 runner arguments', file=sys.stderr)
        return 78
    position = argv.index('-name') + 1
    if position == len(argv) or argv[position] != 'shz-disposable-win98-uefi':
        print('OWNED_BOOT_GUARD_REJECTED: expected retained Win98 runner arguments', file=sys.stderr)
        return 78
    lock_fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
            raise RuntimeError('task-private lock identity is invalid')
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('OWNED_BOOT_GUARD_REJECTED: another same-wrapper launch owns the private lock', file=sys.stderr)
            return 78
        os.set_inheritable(lock_fd, True)
        if not os.get_inheritable(lock_fd):
            raise RuntimeError('task-private lock cannot remain inherited through exec')
        verify_binary()
        rows = snapshot()
        if len(rows) >= 2:
            print('OWNED_BOOT_GUARD_REJECTED: two repository Win98 boot lanes already active ' + json.dumps(rows), file=sys.stderr)
            return 78
        print('OWNED_BOOT_GUARD_ACCEPTED: private-lock-fd=' + str(lock_fd) + ' existing lanes=' + json.dumps(rows), file=sys.stderr, flush=True)
        os.execv(ACTUAL_QEMU, [ACTUAL_QEMU] + argv)
        return 0
    finally:
        os.close(lock_fd)


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as error:
        print('OWNED_BOOT_GUARD_REJECTED: ' + str(error), file=sys.stderr)
        sys.exit(78)
