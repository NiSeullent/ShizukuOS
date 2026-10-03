# SPDX-License-Identifier: GPL-2.0-only
"""Live original-source custody only; never genuine-Windows admission.

Owns a new independent delegated unit's child, not an attached PID/QMP socket.
A future private approved Windows observer/service must supply a separate,
versioned verifier. Exit0, source hashes and this primitive cannot supply it.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import threading
import time

FICLONE = 0x40049409
SOURCE_CUSTODY_ONLY = 'SOURCE_CUSTODY_ONLY'
_KEY = object()


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def canonical(value):
    p = Path(value)
    need(p.is_absolute() and p.resolve() == p and
         not any(x.is_symlink() for x in (p, *p.parents)), 'canonical nonsymlink path required')
    return p


class SourceCapability:
    """Process-local callback capability. No JSON/pickle approval interface."""
    __slots__ = ('_owner', '_nonce', '_key')
    def __init__(self, key, owner, nonce):
        need(key is _KEY, 'owner-created capability required')
        self._owner, self._nonce, self._key = owner, nonce, key

    def __reduce__(self):
        raise TypeError('live source custody cannot be serialized')

    def check(self):
        self._owner.check()
        need(self._key is _KEY and self._owner.phase == 'CALLBACK' and
             self._owner.nonce == self._nonce, 'stale callback capability')

    @property
    def grade(self):
        self.check()
        return SOURCE_CUSTODY_ONLY

    def match_held_source(self, entry):
        self.check()
        need(type(entry) is dict and set(('fd', 'pin', 'identity')) <= entry.keys(), 'actual held source descriptor required')
        need(identity(os.fstat(entry['fd'])) == self._owner.source_identity == entry['identity'] and
             fcntl.fcntl(entry['fd'], fcntl.F_GETLEASE) == fcntl.F_RDLCK and
             entry['pin'] == self._owner.pin, 'caller held original differs')
        self._owner.full_hash(entry['fd'], self._owner.pin['bytes'], self._owner.pin['sha256'])

    def verify_windows_identity(self):
        self.check()
        raise ValueError('SOURCE_CUSTODY_ONLY: actual private-approved nonce-bound cold Windows observer absent')


class BaselineSourceOwner:
    """Trusted source/tool custody owner; own unit must survive child cleanup.

    Trusted producer code owns this object. Caller-supplied pins are verified
    bytes, not approvals. The object's only grade is SOURCE_CUSTODY_ONLY.
    Production callers must communicate with an independent private service;
    this is not an in-process sandbox against arbitrary Python/privileged code.
    """
    def __init__(self, unit, pin):
        need(re.fullmatch(r'shz-baseline-[a-z0-9-]{1,64}\.service', unit), 'independent baseline unit required')
        raw = subprocess.check_output(['systemctl', 'show', unit, '-p', 'MainPID', '-p', 'ActiveState', '-p', 'Delegate', '-p', 'RuntimeMaxUSec'], text=True, timeout=5)
        observation = dict(line.split('=', 1) for line in raw.splitlines())
        need(observation == {'MainPID': str(os.getpid()), 'ActiveState': 'active', 'Delegate': 'yes', 'RuntimeMaxUSec': 'infinity'}, 'actual sole surviving delegated owner required')
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1].lstrip('/')
        self.owner_pidfd = os.pidfd_open(self.pid, 0)
        self.phase = 'NEW'; self.nonce = os.getrandom(32); self.rows = {}; self.broken = False; self.cancelled = False
        need(len(self.nonce) == 32 and any(self.nonce), 'fresh owner random required')
        self.process = None; self.child_pidfd = None; self.used = False
        self.previous = {}
        self.handler = self._break
        for number in (signal.SIGIO, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            self.previous[number] = signal.getsignal(number)
            signal.signal(number, self.handler)
        self.pin = dict(pin)
        try:
            need(not self.descendants(), 'owner unit contains an unrelated process')
            p = canonical(pin['path']); s = p.stat()
            need(stat.S_IMODE(s.st_mode) == 0o400 and s.st_uid == os.getuid() and s.st_nlink == 1 and
                 stat.S_ISREG(s.st_mode) and 0 < s.st_size <= 8 << 30, 'owned0400 independent original required')
            self.source_fd = self.add(pin)
            self.source_identity = identity(os.fstat(self.source_fd))
            self.phase = 'HELD'
        except BaseException:
            self.close()
            raise

    def _break(self, number, *_):
        if number == signal.SIGIO:
            self.broken = True
            if callable(self.previous[number]):
                self.previous[number](number, None)
        else:
            self.cancelled = True

    def descendants(self):
        need(os.getpid() == self.pid and threading.get_ident() == self.thread,
             'membership observation requires actual original owner')
        pids = set()
        for p in (self.group / 'cgroup.procs', *self.group.rglob('cgroup.procs')):
            need(not p.is_symlink(), 'owned cgroup path changed')
            pids.update(map(int, p.read_text().split()))
        need(self.pid in pids, 'owner left independent group')
        return pids - {self.pid}

    def check(self):
        need(os.getpid() == self.pid and threading.get_ident() == self.thread and
             self.phase != 'CLOSED' and not self.broken and not self.cancelled and
             all(signal.getsignal(n) is self.handler for n in self.previous), 'owner exit/thread/lease handler changed')
        need(not select.select([self.owner_pidfd], [], [], 0)[0], 'owner process exited')
        for p, row in self.rows.items():
            fd, saved, _ = row
            need(identity(os.fstat(fd)) == saved == identity(canonical(p).stat()) and
                 fcntl.fcntl(fd, fcntl.F_GETOWN) == self.pid and
                 fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'original path/identity/readlease changed')

    def full_hash(self, fd, size, expected):
        at = 0; digest = hashlib.sha256()
        while at < size:
            self.check(); b = os.pread(fd, min(1 << 20, size-at), at)
            need(b, 'short original source read'); at += len(b); digest.update(b)
        self.check()
        need(not os.pread(fd, 1, size) and digest.hexdigest() == expected, 'full original SHA/extent differs')

    def add(self, pin):
        p = canonical(pin['path'])
        need(type(pin.get('bytes')) is int and type(pin.get('sha256')) is str and
             re.fullmatch('[0-9a-f]{64}', pin['sha256']), 'exact source pin required')
        if p in self.rows:
            need(self.rows[p][2] == pin, 'conflicting original pin'); return self.rows[p][0]
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == pin['bytes'], 'exact independent regular original required')
            fcntl.fcntl(fd, fcntl.F_SETOWN, self.pid); fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            self.rows[p] = (fd, identity(s), dict(pin)); self.full_hash(fd, s.st_size, pin['sha256'])
            return fd
        except BaseException:
            self.rows.pop(p, None); os.close(fd); raise

    def clone(self, target):
        self.check(); need(self.phase == 'HELD', 'clone once before launch only')
        p = canonical(target); parent = p.parent.stat()
        need(not p.exists() and stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_uid == self.pid_uid(), 'fresh private owned clone parent required')
        directory = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fd = None
        try:
            need(identity(os.fstat(directory)) == identity(parent), 'clone parent changed')
            fd = os.open(p.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            fcntl.ioctl(fd, FICLONE, self.source_fd)
            os.fsync(fd); os.fsync(directory)
            self.full_hash(fd, self.pin['bytes'], self.pin['sha256'])
            self.clone_path, self.clone_identity = p, identity(os.fstat(fd))[:2]
            need(self.clone_identity != self.source_identity[:2], 'clone aliases original')
            self.phase = 'CLONED'; return p
        finally:
            if fd is not None: os.close(fd)
            os.close(directory)

    @staticmethod
    def pid_uid():
        return os.getuid()

    def launch_control(self, argv, executable_pin, timeout):
        self.check()
        need(self.phase == 'CLONED' and type(timeout) in (float, int) and not isinstance(timeout, bool) and
             0 < timeout <= 600 and type(argv) is list and argv and all(type(v) is str and '\0' not in v for v in argv), 'bounded owned launch required')
        executable = canonical(argv[0]); need(executable_pin['path'] == str(executable), 'actual executable pin required')
        self.add(executable_pin); self.check()
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
        self.child_pidfd = os.pidfd_open(self.process.pid, 0); self.phase = 'RUNNING'
        try:
            result = self.process.wait(timeout=timeout)
            need(select.select([self.child_pidfd], [], [], 0)[0], 'actual child exit not observed')
            self.quiesce(); self.check()
            need(result == 0, 'actual owned child failed')
            self.full_hash(self.source_fd, self.pin['bytes'], self.pin['sha256'])
            self.freeze_clone()
            self.phase = 'OBSERVED_SOURCE_ONLY'
        except BaseException:
            self.quiesce(); raise

    def freeze_clone(self):
        self.check()
        need(not self.descendants() and identity(self.clone_path.stat())[:2] == self.clone_identity,
             'owned clone replaced or writer remains')
        p = self.clone_path
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            saved = os.fstat(fd)
            need(stat.S_ISREG(saved.st_mode) and saved.st_nlink == 1 and
                 identity(saved)[:2] == self.clone_identity and 0 < saved.st_size <= 8 << 30,
                 'owned clone extent/identity changed')
            fcntl.fcntl(fd, fcntl.F_SETOWN, self.pid)
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            row = {'path': str(p), 'bytes': saved.st_size, 'sha256': '0'*64}
            self.rows[p] = (fd, identity(saved), row)
            at = 0; digest = hashlib.sha256()
            while at < saved.st_size:
                self.check(); raw = os.pread(fd, min(1 << 20, saved.st_size-at), at)
                need(raw, 'short owned clone readback'); digest.update(raw); at += len(raw)
            self.check(); need(not os.pread(fd, 1, saved.st_size), 'owned clone grew')
            row['sha256'] = digest.hexdigest(); self.clone_pin = dict(row)
            self.full_hash(fd, saved.st_size, row['sha256'])
        except BaseException:
            self.rows.pop(p, None); os.close(fd); raise

    def quiesce(self):
        need(os.getpid() == self.pid and threading.get_ident() == self.thread,
             'cleanup requires actual original owner')
        warned = False
        while True:
            try:
                self._quiesce_once()
                need(not self.descendants(), 'owned unit quiescence not observed')
                return
            except Exception:
                if not warned:
                    print('Source custody cleanup not observed; retain original leases.', flush=True)
                    warned = True
                time.sleep(.1)

    def _quiesce_once(self):
        # Never release original leases while any member of our sole unit lives.
        for signum, budget in ((signal.SIGTERM, 3), (signal.SIGKILL, 6)):
            for pid in self.descendants():
                try: fd = os.pidfd_open(pid, 0)
                except ProcessLookupError: continue
                try:
                    c = Path('/sys/fs/cgroup') / Path('/proc', str(pid), 'cgroup').read_text().strip().split('::',1)[1].lstrip('/')
                    need(c == self.group or self.group in c.parents, 'cleanup target outside own unit')
                    signal.pidfd_send_signal(fd, signum)
                except ProcessLookupError: pass
                finally: os.close(fd)
            stop = time.monotonic()+budget
            while self.descendants() and time.monotonic() < stop: time.sleep(.02)
            if not self.descendants(): break
        while self.descendants(): time.sleep(.1)
        if self.process is not None: self.process.wait()

    def callback(self, challenge, callback):
        self.check()
        need(type(challenge) is bytes and challenge == self.nonce and not self.used and
             self.phase == 'OBSERVED_SOURCE_ONLY' and not self.descendants(), 'fresh one-shot owner challenge required')
        self.used = True; self.phase = 'CALLBACK'; cap = SourceCapability(_KEY, self, challenge)
        try:
            result = callback(cap)
            leftover = bool(self.descendants())
            self.quiesce()
            need(not leftover, 'callback returned before owned descendants exited')
            self.check()
            for fd, saved, pin in self.rows.values(): self.full_hash(fd, saved[2], pin['sha256'])
            return result
        finally:
            self.phase = 'CONSUMED'

    def close(self):
        if self.phase == 'CLOSED': return
        self.quiesce()
        errors = []
        try:
            for fd, saved, pin in self.rows.values(): self.full_hash(fd, saved[2], pin['sha256'])
        except BaseException as e: errors.append(e)
        for fd, _, _ in self.rows.values():
            try: fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            except BaseException as e: errors.append(e)
            finally: os.close(fd)
        self.rows.clear()
        if self.child_pidfd is not None: os.close(self.child_pidfd)
        os.close(self.owner_pidfd); self.phase = 'CLOSED'
        for number, previous in self.previous.items():
            if signal.getsignal(number) is self.handler: signal.signal(number, previous)
        if errors: raise errors[0]

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
