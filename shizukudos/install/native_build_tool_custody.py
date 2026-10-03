# SPDX-License-Identifier: GPL-2.0-only
"""Exact compiler-driver leases borrowed by one native input Union.

Only independently reviewed public compiler roles can use their recorded hard
links. This never admits Windows payloads, producer inputs or runtime authority.
The existing Union remains the sole SIGIO owner through all compiler cleanup.
"""
import fcntl
import os
import stat

import native_release_policy as policy

ROLES = {'gcc': 3, 'private-efi-gcc': 2, 'private-efi-as': 2, 'private-efi-ld': 4}
MAX_TOOL = 64 << 20


class BuildToolLeases:
    def __init__(self, ingest, held):
        ingest.need(type(held) is ingest.Union, 'actual input Union required')
        self.ingest, self.held = ingest, held
        self.entries = {}
        self.closed = False
        self._guard = self.check
        held.guards.append(self._guard)

    def __enter__(self):
        return self

    def check(self):
        self.ingest.need(not self.closed and not self.held.broken,
                         'compiler tool custody closed or input read lease broken')
        for path, entry in self.entries.items():
            self.ingest.path(str(path))
            current, original = path.stat(), os.fstat(entry['fd'])
            self.ingest.need(stat.S_ISREG(current.st_mode) and
                             stat.S_ISREG(original.st_mode) and
                             current.st_nlink == original.st_nlink == entry['nlink'] and
                             self.ingest.identity(current) == entry['identity'] ==
                             self.ingest.identity(original) and
                             fcntl.fcntl(entry['fd'], fcntl.F_GETLEASE) == fcntl.F_RDLCK,
                             'compiler original path/inode/link identity or lease changed')

    def add_build_tool(self, role, row):
        self.held.check()
        path = self.ingest.pin(row)
        # Ordinary tools retain the unchanged payload boundary. The special
        # lane is never selected by a caller pin's nlink or approval field.
        if path.stat().st_nlink == 1:
            return self.held.add(row)
        approved = getattr(policy, 'NATIVE_COMPILER_TOOLS', None)
        self.ingest.need(type(approved) is dict and set(approved) == set(ROLES) and
                         role in ROLES, 'independent exact compiler driver anchors absent')
        anchor = approved[role]
        self.ingest.need(type(anchor) is dict and
                         set(anchor) == {'path', 'bytes', 'sha256', 'nlink'} and
                         anchor['nlink'] == ROLES[role] and
                         row == {name: anchor[name] for name in ('path', 'bytes', 'sha256')},
                         'independent compiler driver role/path/extent/SHA anchor differs')
        self.ingest.need(row['bytes'] <= MAX_TOOL, 'bounded compiler driver required')
        if path in self.entries:
            entry = self.entries[path]
            self.ingest.need(entry['pin'] == row and entry['role'] == role,
                             'conflicting compiler driver role pin')
            return entry
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        added = False
        try:
            state = os.fstat(fd)
            self.ingest.need(stat.S_ISREG(state.st_mode) and
                             state.st_size == row['bytes'] and state.st_nlink == ROLES[role],
                             'exact compiler driver regular extent/link count required')
            identity = self.ingest.identity(state)
            self.ingest.need(not any(identity[:2] == entry['identity'][:2]
                                    for entry in (*self.held.entries.values(), *self.entries.values())),
                             'compiler driver aliases an existing input inode')
            fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            entry = {'fd': fd, 'pin': dict(row), 'identity': identity,
                     'nlink': ROLES[role], 'role': role}
            self.entries[path] = entry
            added = True
            self.ingest.need(self.ingest.hash_fd(fd, row['bytes'], self.check) == row['sha256'],
                             'compiler original full SHA differs')
            self.held.check()
            return entry
        finally:
            if not added:
                os.close(fd)

    def pins(self):
        self.check()
        return [dict(self.entries[path]['pin']) for path in sorted(self.entries)]

    def __exit__(self, *exc):
        self.ingest.need(not self.closed, 'compiler tool custody already closed')
        errors = []
        try:
            try:
                self.check()
            except BaseException as error:
                errors.append(error)
            for entry in self.entries.values():
                try:
                    self.ingest.need(self.ingest.hash_fd(entry['fd'], entry['pin']['bytes'], self.check)
                                     == entry['pin']['sha256'], 'final compiler original full SHA differs')
                except BaseException as error:
                    errors.append(error)
            try:
                self.check()
            except BaseException as error:
                errors.append(error)
        finally:
            # Remove our guard before FD teardown; the borrowed Union still
            # checks its own SIGIO state and every ordinary input descriptor.
            try:
                self.held.guards.remove(self._guard)
            except BaseException as error:
                errors.append(error)
            for entry in reversed(list(self.entries.values())):
                try:
                    fcntl.fcntl(entry['fd'], fcntl.F_SETLEASE, fcntl.F_UNLCK)
                except BaseException as error:
                    errors.append(error)
                try:
                    os.close(entry['fd'])
                except BaseException as error:
                    errors.append(error)
            self.closed = True
        if errors:
            raise errors[0]
