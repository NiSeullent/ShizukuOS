#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Explicit temporary RAM assembly; final storage retains its 17GiB reserve."""
import ctypes
import os
from pathlib import Path
import stat
import sys

RAM_FLOOR = (6 << 30) + (160 << 20)
RAM_CAP = 1 << 30
NAS_RESERVE = 17 << 30
FINAL_BUDGET = 2304 << 20


def need(value, message):
    if not value:
        raise ValueError(message)


def canonical(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path and
         not any(p.is_symlink() for p in (path, *path.parents)), 'canonical RAM/sink path required')
    return path


class _StatFS(ctypes.Structure):
    # Linux LP64 libc statfs; type is absent from POSIX statvfs.
    _fields_ = [('type', ctypes.c_long), ('bsize', ctypes.c_long),
                *[(name, ctypes.c_ulong) for name in ('blocks', 'bfree', 'bavail', 'files', 'ffree')],
                ('fsid', ctypes.c_int * 2), ('namelen', ctypes.c_long),
                ('frsize', ctypes.c_long), ('flags', ctypes.c_long), ('spare', ctypes.c_long * 4)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFS))
_libc.fstatfs.restype = ctypes.c_int


def tmpfs_fd(fd):
    """Query the held file's actual filesystem, never a textual mount guess."""
    need(sys.platform == 'linux' and ctypes.sizeof(ctypes.c_long) == 8 and
         ctypes.sizeof(ctypes.c_void_p) == 8, 'Linux LP64 fstatfs ABI required')
    info = _StatFS()
    if _libc.fstatfs(fd, ctypes.byref(info)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return info.type == 0x01021994  # Linux TMPFS_MAGIC.


def tmpfs(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return tmpfs_fd(fd)
    finally:
        os.close(fd)


class Placement:
    def __init__(self, plan):
        need(type(plan) is dict and set(plan) == {'schema', 'scratch', 'sink', 'RAM_cap_bytes',
             'RAM_floor_bytes', 'NAS_reserve_bytes', 'final_budget_bytes'}, 'exact RAM placement schema required')
        need(plan['schema'] == 'shizukuos.ram-assembly-placement.v1' and
             plan['RAM_cap_bytes'] == RAM_CAP and plan['RAM_floor_bytes'] == RAM_FLOOR and
             plan['NAS_reserve_bytes'] == NAS_RESERVE and plan['final_budget_bytes'] == FINAL_BUDGET,
             'fixed actual RAM and final-storage reserves required')
        self.plan, self.fds = plan, {}
        try:
            for name in ('scratch', 'sink'):
                row = plan[name]
                need(type(row) is dict and set(row) == {'path', 'dev', 'ino', 'fsid'}, 'exact directory binding required')
                path = canonical(row['path'])
                need(all(type(row[k]) is int and row[k] > 0 for k in ('dev', 'ino')) and
                     type(row['fsid']) is int, 'actual directory binding values required')
                self.fds[name] = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            need(plan['scratch']['dev'] != plan['sink']['dev'], 'RAM and final storage must be distinct filesystems')
            self.check()
        except BaseException:
            self.close()
            raise

    @classmethod
    def create(cls, scratch, sink):
        scratch, sink = canonical(scratch), canonical(sink)
        need(not scratch.exists() and tmpfs(scratch.parent), 'fresh scratch on actual tmpfs required')
        parent = scratch.parent.stat()
        need(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, 'owned private RAM parent required')
        need(os.statvfs(scratch.parent).f_bavail * os.statvfs(scratch.parent).f_frsize >= RAM_FLOOR + RAM_CAP,
             'actual tmpfs floor plus complete physical RAM budget required')
        need(os.statvfs(sink).f_bavail * os.statvfs(sink).f_frsize >= NAS_RESERVE + FINAL_BUDGET,
             'actual final storage 17GiB plus complete ESP budget required')
        scratch.mkdir(mode=0o700)
        rows = {}
        for name, path in (('scratch', scratch), ('sink', sink)):
            info = path.stat()
            rows[name] = {'path': str(path), 'dev': info.st_dev, 'ino': info.st_ino, 'fsid': os.statvfs(path).f_fsid}
        return cls({'schema': 'shizukuos.ram-assembly-placement.v1', **rows,
                    'RAM_cap_bytes': RAM_CAP, 'RAM_floor_bytes': RAM_FLOOR,
                    'NAS_reserve_bytes': NAS_RESERVE, 'final_budget_bytes': FINAL_BUDGET})

    def check(self, pending=0):
        need(type(pending) is int and pending >= 0, 'bounded pending physical bytes required')
        for name, fd in self.fds.items():
            row = self.plan[name]; path = Path(row['path'])
            # Admission already fixed the lexical canonical path. Recheck every
            # ancestor for aliases without resolving it and parsing all mounts
            # on each I/O; named/held inode checks still bind the directory.
            need(not any(p.is_symlink() for p in (path, *path.parents)), 'canonical RAM/sink path required')
            named = path.stat(); held = os.fstat(fd)
            need(stat.S_ISDIR(named.st_mode) and stat.S_ISDIR(held.st_mode) and
                 (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino) == (row['dev'], row['ino']) and
                 named.st_uid == held.st_uid == os.getuid() and
                 stat.S_IMODE(named.st_mode) == stat.S_IMODE(held.st_mode) == 0o700,
                 'held RAM/sink directory identity or privacy changed')
            volume = os.fstatvfs(fd)
            need(volume.f_fsid == row['fsid'] and not volume.f_flag & os.ST_RDONLY, 'actual write filesystem changed')
        root = Path(self.plan['scratch']['path'])
        need(tmpfs_fd(self.fds['scratch']), 'scratch must remain actual tmpfs')
        names = os.listdir(self.fds['scratch'])
        need(set(names) <= {'esp-win98.img', 'ram-placement.json', 'disk-insertion-request.json', 'disk-insertion.json'},
             'foreign RAM workspace entry refused')
        used = 0
        for name in names:
            info = os.stat(name, dir_fd=self.fds['scratch'], follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                 'owned single-link regular RAM entry required')
            used += info.st_blocks * 512
        unit = os.fstatvfs(self.fds['scratch']).f_frsize
        need(unit > 0 and used + ((pending + unit - 1) // unit) * unit <= RAM_CAP, 'RAM physical allocation cap exceeded')
        ram = os.fstatvfs(self.fds['scratch']); sink = os.fstatvfs(self.fds['sink'])
        need(ram.f_bavail * ram.f_frsize >= RAM_FLOOR + max(0, RAM_CAP - used),
             'actual RAM floor and remaining physical budget unavailable')
        need(sink.f_bavail * sink.f_frsize >= NAS_RESERVE + FINAL_BUDGET,
             'actual final storage reserve and full ESP budget unavailable')
        available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:'))) * 1024
        need(available >= RAM_FLOOR, 'actual host memory floor unavailable')
        return used

    def close(self):
        errors = []
        for name, fd in list(self.fds.items()):
            try:
                os.close(fd)
            except BaseException as error:
                errors.append(error)
            finally:
                del self.fds[name]
        if errors:
            raise errors[0]

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, kind, primary, tb):
        try:
            self.check()
        finally:
            self.close()
