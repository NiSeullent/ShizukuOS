"""Prospective owned host endpoint; existing guardian/controller wiring is absent.

Protocol syntax alone conveys no hardware authority. Borrowed descriptors and
the actual sole QMP/Popen context stay owned by the caller through exact reap.
"""
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import threading
import time
import types

POLICY_NAME = 'opt/shizuku/native-device-epoch'
MAX_QMP = 256 << 10
MAX_CALLS = 64
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def need(ok, message):
    if not ok: raise ValueError(message)


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'bounded exact integer required')
    return value


def digest(raw):
    return hashlib.sha256(raw).digest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def frame(kind, extent, count):
    return struct.pack('<IHHII', 0x31454457, 1, kind, extent, count)


# Local copy of the reviewed native_epoch_guard_pump.py checked_select function.
# Original source SHA256:
# 74a5fc3fad170e370dbd39e2b8fea23bd2fad5c8bc1bfa49dfd86975e6642c3a
# Keep this in the admitted epoch source; no unpinned helper import is required.
def checked_select(readers, writers, deadline_ns, guard):
    """Check the owner guard around one <=25ms select under an absolute deadline.

    Readiness is refused if the deadline expires during the wait or postguard.
    A select exception remains primary if postguard also fails; that later
    refusal is retained as its explicit cause. No wait is retried or renewed.
    """
    if type(deadline_ns) is not int:
        raise TypeError("an absolute integer monotonic deadline is required")
    if not callable(guard):
        raise TypeError("the actual owner guard is required")
    guard()
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise TimeoutError("the original wait deadline expired")
    timeout = min(25_000_000, remaining_ns) / 1_000_000_000
    try:
        ready = select.select(readers, writers, [], timeout)
    except BaseException as first_error:
        try:
            guard()
        except BaseException as guard_error:
            raise first_error from guard_error
        raise
    guard()
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError("the original wait deadline expired")
    return ready


@dataclass(frozen=True)
class Device:
    role: int
    bdf: int
    vendor: int
    device: int
    klass: int
    bars: tuple
    regions: tuple


class Expectations:
    """Immutable byte expectations, never a current process/resource grant."""
    def __init__(self, vga, rom, storage, raw_bars):
        need((vga is None) == (rom is None), 'VGA config/ROM pair required')
        need(type(raw_bars) is dict and all(type(role) is int for role in raw_bars) and set(raw_bars) == ({1} if vga is not None else set()) | ({2} if storage is not None else set()), 'exact selected roles required')
        need(vga is not None or storage is not None, 'optional device selection required')
        self.hashes = (digest(vga) if vga is not None else bytes(32), digest(storage) if storage is not None else bytes(32))
        self.rom_hash = digest(rom) if rom is not None else bytes(32)
        devices = []
        for role in sorted(raw_bars):
            bars = raw_bars[role]
            need(type(bars) is tuple and len(bars) == 6, 'six immutable BAR DWORDs required')
            for raw in bars: integer(raw, 0, 0xffffffff)
            if role == 1:
                need(type(vga) is bytes and len(vga) == 136 and type(rom) is bytes and len(rom) == 65536, 'exact VGA pair required')
                magic, version, size, flags, bdf, reserved, base, extent = struct.unpack_from('<6I2Q', vga)
                need((magic, version, size, flags, reserved, extent) == (0x41475657, 1, 136, 1, 0, 16 << 20), 'VGA shape differs')
                need(0 < base < 1 << 32 and base % (16 << 20) == 0 and base + extent <= 1 << 32 and vga[40:72] == self.rom_hash and any(vga[72:104]) and any(vga[104:136]), 'VGA full ROM/resource/source binding differs')
                need(bars[0] == base | 8, 'VGA raw BAR0 differs')
                devices.append(Device(1, integer(bdf, 0, 255), 0x1234, 0x1111, 0x030000, bars, ((0, base, extent, 'memory', False, True),)))
            else:
                need(type(storage) is bytes and len(storage) == 192, 'exact persistence config required')
                magic, version, bdf, vendor, dev, reserved, esp, member, volume, reserved32 = struct.unpack_from('<II4H2Q2I', storage)
                need((magic, version, vendor, reserved, esp, member, volume, reserved32) == (0x52503957, 1, 0x1af4, 0, 2304 << 20, 2 << 30, 0x53485739, 0) and dev in (0x1001, 0x1042) and not any(storage[184:]), 'persistence shape differs')
                regions = []
                occupied = set()
                for bar in range(6):
                    base, extent, kind, pad = struct.unpack_from('<QQII', storage, 40 + 24 * bar)
                    need(pad == 0, 'dirty persistence BAR padding')
                    if not kind:
                        need(base == extent == 0, 'unselected BAR has resources')
                        continue
                    need(bar not in occupied and kind in (1, 2, 3) and 0 < extent <= 128 << 20 and extent & (extent - 1) == 0 and base and base % extent == 0, 'persistence BAR shape differs')
                    need(base + extent <= (1 << 16 if kind == 3 else 1 << 32), 'persistence BAR address bound')
                    raw = (base | 1) if kind == 3 else (base | 4) if kind == 2 else base
                    need(bars[bar] == raw, 'persistence raw BAR differs')
                    occupied.add(bar)
                    if kind == 2:
                        need(bar < 5 and bars[bar + 1] == 0, 'bounded64-bit upper BAR differs')
                        occupied.add(bar + 1)
                    regions.append((bar, base, extent, 'io' if kind == 3 else 'memory', kind == 2, False))
                need(regions and all(bars[b] == 0 for b in range(6) if b not in occupied), 'hidden/unselected persistence BAR')
                devices.append(Device(2, integer(bdf, 0, 255), vendor, dev, 0x010000, bars, tuple(regions)))
        need(len({d.bdf for d in devices}) == len(devices), 'duplicate selected BDF')
        decoded = []
        for d in devices:
            for _, base, extent, kind, _, _ in d.regions:
                need(not any(kind == previous_kind and base < end and start < base + extent for start, end, previous_kind in decoded), 'overlapping selected configured BARs')
                decoded.append((base, base + extent, kind))
        self.devices = tuple(devices)
        self.roles = sum(d.role for d in devices)

    def policy(self, nonce, deadline_ns):
        need(type(nonce) is bytes and len(nonce) == 32 and any(nonce), 'fresh32-byte nonce required')
        integer(deadline_ns, 1, (1 << 64) - 1)
        raw = bytearray(256)
        struct.pack_into('<IHHI', raw, 0, 0x50454457, 1, 256, self.roles)
        raw[16:48] = nonce; raw[48:80] = self.hashes[0]; raw[80:112] = self.hashes[1]; raw[112:144] = self.rom_hash
        struct.pack_into('<QI H', raw, 144, deadline_ns, 10000, 0x2f8)
        for d in self.devices:
            struct.pack_into('<H', raw, 160 + (d.role - 1) * 2, d.bdf)
            struct.pack_into('<6I', raw, 168 + (d.role - 1) * 24, *d.bars)
        return bytes(raw)


def validate_ready(raw, nonce):
    need(type(raw) is bytes and raw == frame(4, 48, 0) + nonce, 'current exact READY required')


def validate_report(raw, expected, nonce):
    need(type(raw) is bytes and len(raw) == 256 and raw[:16] == frame(2, 256, len(expected.devices)), 'canonical report header required')
    need(raw[16:48] == nonce and raw[48:80] == expected.hashes[0] and raw[80:112] == expected.hashes[1] and raw[112:144] == expected.rom_hash, 'report input/nonce binding differs')
    need(struct.unpack_from('<Q', raw, 144)[0] > 0 and not any(raw[152 + len(expected.devices) * 48:]), 'local TSC deadline/zero unused report bytes required')
    result = []
    for i, d in enumerate(expected.devices):
        bdf, role, reserved, *words = struct.unpack_from('<HHI10I', raw, 152 + i * 48)
        need((bdf, role, reserved) == (d.bdf, d.role, 0) and words[0] == d.vendor | d.device << 16 and words[2] >> 8 == d.klass and not words[3] & 0x7f0000 and tuple(words[4:]) == d.bars, 'report PCI identity/header/raw BAR differs')
        need(d.role != 1 or words[1] & 3 == 3, 'VGA decodes not enabled')
        result.append({'bdf': bdf, 'role': role, 'words': tuple(words)})
    return tuple(result)


def grant(report):
    need(type(report) is bytes and len(report) == 256 and report[:12] == frame(2, 256, 0)[:12], 'exact report extent/header required')
    count = struct.unpack_from('<I', report, 12)[0]; integer(count, 1, 2)
    return frame(3, 272, count) + report


def parse_flatview(text):
    """Complete bounded system FlatView; ECAM is observed, never guessed."""
    need(type(text) is str and 0 < len(text.encode()) <= MAX_QMP, 'bounded FlatView required')
    text = text.replace('\r\n', '\n')
    need(text.endswith('\n\n') and '\r' not in text, 'complete bounded FlatView required')
    sections, current = [], None
    for line in text.splitlines():
        if re.fullmatch(r'FlatView #[0-9]+', line):
            current = {'spaces': [], 'root': None, 'rows': []}; sections.append(current)
            need(len(sections) <= 128, 'FlatView section cap')
        elif not line: continue
        elif current is None: need(False, 'FlatView header absent')
        elif line.startswith(' AS '):
            m = re.fullmatch(r' AS "([^"\n]{1,128})", root: ([^,\n]{1,128})(?:, alias [^\n]{1,128})?', line)
            need(m is not None and current['root'] is None, 'FlatView AS header malformed'); current['spaces'].append(m.groups())
        elif line.startswith(' Root memory region: '):
            need(current['root'] is None and current['spaces'], 'FlatView root malformed'); current['root'] = line[21:]
        else: current['rows'].append(line)
    selected = [x for x in sections if ('memory', 'system') in x['spaces']]
    need(len(selected) == 1 and selected[0]['spaces'].count(('memory', 'system')) == 1 and selected[0]['root'] == 'system', 'unique complete memory/system view required')
    rows = selected[0]['rows']; need(1 <= len(rows) <= 4096, 'FlatView row cap')
    entries, ram, ecam = [], [], []
    pattern = r'  ([0-9a-f]{16})-([0-9a-f]{16}) \(prio (-?[0-9]+), ((?:nv-)?(?:ram|rom|ramd|romd|i/o))\): (.{1,256}?)(?: @([0-9a-f]{16}))?((?: (?:kvm|tcg|KVM|TCG))*)'
    for line in rows:
        m = re.fullmatch(pattern, line); need(m is not None, 'unrecognized selected FlatView row')
        start, end = int(m[1], 16), int(m[2], 16) + 1
        need(start < end <= 1 << 64 and (not entries or start >= entries[-1][1]) and abs(int(m[3])) <= 1 << 31, 'unordered/overlapping FlatView range')
        kind, name = m[4], m[5]; entries.append((start, end, kind, name))
        if name == 'pc.ram': ram.append((start, end))
        if name in ('pcie-mmcfg', 'pcie-mmcfg-mmio') and kind == 'i/o': ecam.append((start, end))
    need(ram and len(ecam) == 1 and ecam[0][0] % (1 << 20) == 0 and 1 << 20 <= ecam[0][1] - ecam[0][0] <= 256 << 20, 'observed bounded ECAM and RAM required')
    return {'entries': tuple(entries), 'ram': tuple(ram), 'ecam': ecam[0]}


def parse_xp(text, address):
    need(type(text) is str and 0 < len(text) <= 4096 and text.endswith('\n'), 'bounded complete xp output required')
    words = []
    for line in text.splitlines():
        m = re.fullmatch(r'([0-9a-f]{8,16}):((?: 0x[0-9a-f]{8}){1,4})', line)
        need(m is not None and int(m[1], 16) == address + len(words) * 4, 'xp address/row differs')
        words.extend(int(x, 16) for x in m[2].split()); need(len(words) <= 10, 'xp extent exceeded')
    need(len(words) == 10, 'exact40-byte PCI snapshot required')
    return tuple(words)


class PinnedFD:
    """Borrowed caller read lease; never installs SIGIO handlers or closes it."""
    def __init__(self, fd, pin):
        integer(fd, 0, 1 << 30)
        need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'exact source pin required')
        self.fd, self.pin = fd, dict(pin)
        self.path = Path(pin['path']); need(self.path.is_absolute() and self.path.resolve() == self.path and not any(x.is_symlink() for x in (self.path, *self.path.parents)), 'canonical pinned source required')
        self.size = integer(pin['bytes'], 1, 64 << 20)
        need(type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None, 'full source SHA pin required')
        self.binding = identity(os.fstat(fd)); self.check()

    def check(self):
        s = os.fstat(self.fd)
        need(self.path.resolve() == self.path and not any(x.is_symlink() for x in (self.path, *self.path.parents)), 'pinned source canonical name changed')
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and not s.st_mode & 0o022 and identity(s) == self.binding == identity(self.path.stat()) and s.st_size == self.size, 'held source identity/extent/privacy differs')
        need(fcntl.fcntl(self.fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'actual caller source read lease required')
        raw = os.pread(self.fd, self.size + 1, 0)
        need(len(raw) == self.size and digest(raw).hex() == self.pin['sha256'] and identity(os.fstat(self.fd)) == self.binding, 'held source full readback differs')
        return raw


class Attempt:
    def __init__(self, vga, rom, storage, raw_bars, deadline_ns):
        integer(deadline_ns, 1, (1 << 64) - 1)
        self.sources = tuple(x for x in (vga, rom, storage) if x is not None)
        need(all(type(x) is PinnedFD for x in self.sources), 'held input descriptors required')
        self.expected = Expectations(vga.check() if vga else None, rom.check() if rom else None, storage.check() if storage else None, raw_bars)
        self.original_deadline_ns = self._deadline = deadline_ns
        self.last_now = time.monotonic_ns(); need(self.last_now < deadline_ns, 'original host deadline expired')
        self.nonce = os.getrandom(32); self.policy = self.expected.policy(self.nonce, deadline_ns)
        self.policy_fd = None; self.consumed = False; self.owner = None
        self.exchange_stop_ns = self.original_exchange_stop_ns = None
        try:
            self.policy_fd = os.memfd_create('shz-native-device-epoch', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.fchmod(self.policy_fd, 0o600); need(os.write(self.policy_fd, self.policy) == 256, 'complete policy write required')
            fcntl.fcntl(self.policy_fd, fcntl.F_ADD_SEALS, SEALS)
            self.policy_identity = identity(os.fstat(self.policy_fd)); self.check()
        except BaseException:
            if self.policy_fd is not None: os.close(self.policy_fd); self.policy_fd = None
            raise

    def check(self):
        now = time.monotonic_ns()
        need(self.original_deadline_ns == self._deadline and self.last_now <= now < self._deadline, 'original immutable deadline/progress required')
        self.last_now = now
        if self.exchange_stop_ns is not None:
            need(self.exchange_stop_ns == self.original_exchange_stop_ns and now < self.exchange_stop_ns, 'additional immutable exchange bound expired')
        for source in self.sources: source.check()
        need(self.expected.policy(self.nonce, self._deadline) == self.policy and self.policy_fd is not None and identity(os.fstat(self.policy_fd)) == self.policy_identity and os.pread(self.policy_fd, 257, 0) == self.policy and fcntl.fcntl(self.policy_fd, fcntl.F_GET_SEALS) == SEALS, 'immutable sealed policy/source binding differs')

    def close(self):
        if self.owner is not None: self.owner.assert_reaped()
        if self.policy_fd is not None:
            fd, self.policy_fd = self.policy_fd, None; os.close(fd)


class PrivateListener:
    def __init__(self, path):
        self.path = Path(path); self.fd = self.sock = None; self.accepted = False; self.socket_identity = None; self.owner = None
        need(self.path.is_absolute() and len(os.fsencode(self.path)) < 104 and self.path.parent.resolve() == self.path.parent and not any(x.is_symlink() for x in self.path.parents), 'short canonical private socket path required')
        self.fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.parent_identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino); self._parent()
            need(not self.path.exists() and not self.path.is_symlink(), 'fresh socket name required')
            # Bind beneath the exact held parent, then check its public name.
            # A replaced parent must never select a foreign mutation target.
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind('/proc/self/fd/%d/%s' % (self.fd, self.path.name))
            s = os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
            self.socket_identity = (s.st_dev, s.st_ino)
            os.chmod(self.path.name, 0o600, dir_fd=self.fd, follow_symlinks=False)
            self.sock.listen(1); self.sock.setblocking(False); self.check()
        except BaseException:
            self.close(); raise

    def _parent(self):
        need(self.path.parent.resolve() == self.path.parent and not any(x.is_symlink() for x in self.path.parents), 'listener parent canonical name changed')
        for s in (os.fstat(self.fd), self.path.parent.stat()):
            need((s.st_dev, s.st_ino) == self.parent_identity and stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, 'admitted socket parent changed')

    def check(self):
        self._parent(); s = self.path.lstat()
        need(stat.S_ISSOCK(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and (s.st_dev, s.st_ino) == self.socket_identity, 'owned listener name changed')

    def accept(self, pid, uid, deadline_ns, guard=None):
        need(not self.accepted, 'single-use connector consumed'); self.accepted = True
        need(callable(guard), 'actual outer owner guard required for connector')
        integer(pid, 1, 1 << 30); integer(uid, 0, 1 << 30)
        def checked():
            guard(); self.check()
        while True:
            if checked_select([self.sock], [], deadline_ns, checked)[0]:
                peer, _ = self.sock.accept()
                try:
                    observed = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    need(observed[:2] == (pid, uid), 'COM2 connecting peer differs from current owned child')
                    peer.setblocking(False); checked()
                    if time.monotonic_ns() >= deadline_ns:
                        raise TimeoutError('the original connector deadline expired')
                    return peer
                except BaseException: peer.close(); raise

    def close(self):
        if self.owner is not None: self.owner.assert_reaped()
        error = None
        try:
            if self.fd is not None and self.socket_identity is not None:
                self.check(); os.unlink(self.path.name, dir_fd=self.fd)
        except BaseException as exc: error = exc
        finally:
            if self.sock is not None: self.sock.close(); self.sock = None
            if self.fd is not None: os.close(self.fd); self.fd = None
        if error is not None: raise error


class ProcessBinding:
    """Linux process facts only; the caller separately approves QEMU/recipe."""
    def __init__(self, process, pidfd, executable, argv, cgroup):
        need(isinstance(process, subprocess.Popen) and process.pid > 0, 'caller actual Popen required')
        need(type(executable) is PinnedFD and type(argv) is tuple and argv and all(type(x) is str and '\0' not in x for x in argv), 'exact borrowed executable/argv required')
        self.process, self.pidfd, self.executable, self.argv, self.cgroup = process, pidfd, executable, argv, cgroup
        self.command = b''.join(os.fsencode(x) + b'\0' for x in argv)
        need(len(self.command) <= 65536 and type(cgroup) is str and cgroup.startswith('/'), 'bounded actual argv/cgroup required')
        self.starttime = None; self.reap_record = None
        self.original_pidfd, self.original_pid = pidfd, process.pid
        self.pidfd_identity = identity(os.fstat(pidfd)); self.check()

    def _pidfd(self, reaped=False):
        need(self.pidfd == self.original_pidfd and self.process.pid == self.original_pid and identity(os.fstat(self.pidfd)) == self.pidfd_identity and os.readlink('/proc/self/fd/%d' % self.pidfd) == 'anon_inode:[pidfd]', 'exact original pidfd/child required')
        info = Path('/proc/self/fdinfo/%d' % self.pidfd).read_text()
        need(len(info) <= 8192 and re.findall(r'^Pid:\s*(-?\d+)$', info, re.M) == [str(-1 if reaped else self.original_pid)], 'original pidfd PID differs')

    def check(self):
        self._pidfd()
        p = self.process.pid; poll = select.poll(); poll.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(not poll.poll(0), 'exact live owned pidfd required')
        proc = Path('/proc/%d' % p); raw = (proc / 'stat').read_bytes(); need(len(raw) <= 8192, 'bounded proc stat')
        fields = raw[raw.rfind(b')') + 2:].split()
        need(len(fields) >= 20 and fields[0] not in (b'Z', b'X') and int(fields[1]) == os.getpid() and proc.stat().st_uid == os.getuid(), 'current child/parent/live UID differs')
        start = int(fields[19])
        if self.starttime is None: self.starttime = start
        need(start == self.starttime and (proc / 'cmdline').read_bytes() == self.command and (proc / 'cgroup').read_text().strip() == '0::' + self.cgroup, 'owned starttime/argv/cgroup differs')
        self.executable.check(); s = (proc / 'exe').stat()
        need((s.st_dev, s.st_ino) == self.executable.binding[:2], 'actual executable differs from held source')
        return {'pid': p, 'starttime': start, 'argv_sha256': digest(self.command).hex(), 'executable_pin': dict(self.executable.pin), 'cgroup': self.cgroup}

    def reap_owned(self):
        """Only when the outer custodian explicitly delegates its one reaper.

        Never accept Popen.poll()/ECHILD's synthesized status. A guardian that
        retains its reaper must first use its concrete source-pinned native
        reaper admission before delegating to this API.
        """
        need(self.reap_record is None, 'actual child already reaped by this binding')
        # Verify the original kernel object before the destructive operation.
        # A foreign ready pidfd must never be consumed by this custodian.
        self._pidfd()
        observed = os.waitid(os.P_PIDFD, self.pidfd, os.WEXITED | os.WNOHANG)
        need(observed is not None and observed.si_pid == self.process.pid and observed.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED), 'strict actual pidfd exit record required')
        self.reap_record = {'pid': observed.si_pid, 'code': observed.si_code, 'status': observed.si_status}
        self.process.returncode = observed.si_status if observed.si_code == os.CLD_EXITED else -observed.si_status
        self.assert_reaped()
        return dict(self.reap_record)

    def assert_reaped(self):
        need(self.reap_record is not None and self.reap_record['pid'] == self.process.pid, 'exact delegated waitid reap required before owned resource release')
        self._pidfd(reaped=True)
        poll = select.poll(); poll.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(poll.poll(0), 'original pidfd must observe reaped child')


class SoleQMP:
    """Use the already admitted sole monitor's socket and parser state.

    This is no takeover of a guardian's duplicated stream. The owner must
    instantiate it in the single actual OwnedQMP/Popen context, with no second
    reader. Existing default guardian/controller do not supply that context.
    """
    def __init__(self, binding, monitor, attempt, monitor_source):
        need(type(binding) is ProcessBinding and type(attempt) is Attempt, 'actual borrowed process/policy context required')
        need(type(monitor_source) is PinnedFD and monitor_source.path.name == 'owned_capture.py', 'admitted frozen OwnedQMP source FD required')
        raw = monitor_source.check(); need(len(raw) <= 1 << 20, 'bounded OwnedQMP source')
        # Preserve the full module compiler's import/symbol context. Compiling
        # an extracted class AST changes CPython3.12 LOAD_ATTR instructions.
        # Inspect code constants; never evaluate the admitted module here.
        compiled = compile(raw, str(monitor_source.path), 'exec', dont_inherit=True)
        classes = [x for x in compiled.co_consts if type(x) is types.CodeType and x.co_name == 'OwnedQMP']
        need(len(classes) == 1, 'unique admitted OwnedQMP class')
        self.expected_methods = {x.co_name: x for x in classes[0].co_consts if type(x) is types.CodeType}
        self.monitor_source = monitor_source
        need(type(monitor).__name__ == 'OwnedQMP', 'actual admitted OwnedQMP class required')
        need(not hasattr(monitor, '_native_epoch_claim'), 'sole monitor already claimed')
        self.binding, self.monitor, self.attempt = binding, monitor, attempt
        self.original_monitor = monitor
        self.socket = monitor.socket; self.deadline = monitor.deadline
        need(type(self.deadline) in (int, float) and math.isfinite(self.deadline) and int(self.deadline * 1e9) == attempt.original_deadline_ns, 'QMP original absolute deadline differs')
        self.claim = object(); monitor._native_epoch_claim = self.claim
        self.thread = threading.get_ident(); self.calls = 0; self.total_bytes = 0; self.transcripts = []
        self.ecam_reads = frozenset()
        self.socket_identity = identity(os.fstat(self.socket.fileno())); self.check()

    def check(self):
        need(not getattr(self, 'retired', False) and self.monitor is self.original_monitor, 'epoch monitor adapter retired or original monitor replaced')
        self.attempt.check(); self.binding.check()
        self.monitor_source.check()
        for name in ('__init__', '_remaining', '_read', 'call', 'hmp', 'close'):
            actual = getattr(self.monitor, name); frozen = self.expected_methods.get(name)
            # marshal also records object sharing/interning, which can differ
            # after execution despite equal code. Compare code semantics and
            # the origin/debug fields which code equality intentionally omits.
            need(hasattr(actual, '__code__') and frozen is not None and actual.__code__ == frozen and
                 all(getattr(actual.__code__, field) == getattr(frozen, field) for field in
                     ('co_filename', 'co_firstlineno', 'co_qualname', 'co_linetable', 'co_exceptiontable')),
                 'actual monitor method differs from held frozen source')
        need(getattr(self.monitor.call, '__self__', None) is self.monitor, 'actual bound monitor method required')
        need(threading.get_ident() == self.thread and threading.active_count() == 1 and self.monitor._native_epoch_claim is self.claim and self.monitor.socket is self.socket and self.monitor.deadline == self.deadline, 'exclusive monitor/deadline context changed')
        need(self.socket.family == socket.AF_UNIX and self.socket.type & 15 == socket.SOCK_STREAM and identity(os.fstat(self.socket.fileno())) == self.socket_identity, 'exact Unix QMP stream required')
        need(struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[:2] == (self.binding.process.pid, os.getuid()), 'fresh QMP peer differs from owned child')
        need(type(self.monitor.buffer) is bytearray and len(self.monitor.buffer) <= MAX_QMP and type(self.monitor.request) is int, 'bounded existing QMP parser state required')

    def call(self, command, arguments=None):
        allowed = {'stop', 'query-status', 'query-pci', 'query-block', 'query-named-block-nodes', 'human-monitor-command'}
        need(command in allowed and (arguments is None if command != 'human-monitor-command' else type(arguments) is dict and set(arguments) == {'command-line'} and (arguments['command-line'] == 'info mtree -f' or re.fullmatch(r'xp /10wx 0x[0-9a-f]{1,16}', arguments['command-line']) is not None)), 'bounded readonly observation or pause command required')
        flat_request = command == 'human-monitor-command' and arguments['command-line'] == 'info mtree -f'
        if command == 'human-monitor-command':
            if flat_request: self.ecam_reads = frozenset()
            else: need(int(arguments['command-line'].split()[-1], 16) in self.ecam_reads, 'current selected ECAM read required')
        self.check(); need(self.calls < MAX_CALLS, 'finite QMP operation budget'); self.calls += 1
        if self.attempt.exchange_stop_ns is not None:
            need(time.monotonic_ns() + 5_000_000_000 < self.attempt.exchange_stop_ns, 'existing QMP5s request bound does not fit exchange reserve')
        # Reuse the actual sole monitor, including buffered events and IDs.
        result = self.monitor.call(command, arguments)
        self.check(); payload = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
        need(len(payload) <= MAX_QMP, 'bounded complete QMP result required')
        self.total_bytes += len(payload); need(self.total_bytes <= MAX_QMP, 'aggregate QMP transcript cap')
        if flat_request:
            flat = parse_flatview(result)
            addresses = tuple(flat['ecam'][0] + d.bdf * 4096 for d in self.attempt.expected.devices)
            need(all(address + 40 <= flat['ecam'][1] for address in addresses), 'selected current ECAM extent required')
            self.check(); self.ecam_reads = frozenset(addresses)
        self.transcripts.append({'command': command, 'arguments': arguments, 'bytes': len(payload), 'sha256': digest(payload).hex(), 'result': result})
        return result

    def paused(self):
        result = self.call('query-status')
        need(type(result) is dict and result.get('running') is False and result.get('status') == 'paused', 'actual stopped/paused status required')


def validate_pci(data, expected, flat):
    need(type(data) is list and 1 <= len(data) <= 32, 'bounded complete PCI bus output')
    found, seen, count, decoded, all_regions = {}, set(), 0, [], []
    def devices(rows, bus, depth):
        nonlocal count
        need(type(rows) is list and len(rows) <= 256 and depth <= 4, 'bounded PCI device/bridge output')
        for row in rows:
            count += 1; need(count <= 256 and type(row) is dict, 'PCI device count/schema')
            number = integer(row.get('bus'), 0, 255); slot = integer(row.get('slot'), 0, 31); function = integer(row.get('function'), 0, 7)
            bdf = number << 8 | slot << 3 | function; need(number == bus and bdf not in seen, 'duplicate/misplaced PCI BDF'); seen.add(bdf)
            ids, klass, regions = row.get('id'), row.get('class_info'), row.get('regions')
            need(type(ids) is dict and type(klass) is dict and type(regions) is list and len(regions) <= 7 and type(row.get('qdev_id')) is str, 'complete PCI identity/regions required')
            vendor = integer(ids.get('vendor'), 0, 65535); dev = integer(ids.get('device'), 0, 65535); code = integer(klass.get('class'), 0, 65535)
            parsed, indices = [], set()
            for r in regions:
                need(type(r) is dict, 'PCI region schema'); bar = integer(r.get('bar'), 0, 6)
                need(bar not in indices and r.get('type') in ('io', 'memory'), 'duplicate/unknown PCI region'); indices.add(bar)
                address = integer(r.get('address'), -1, (1 << 64) - 1); extent = integer(r.get('size'), 1, 128 << 20)
                if r['type'] == 'memory': need(type(r.get('prefetch')) is bool and type(r.get('mem_type_64')) is bool, 'memory BAR flags required')
                parsed.append((bar, address, extent, r['type'], r.get('mem_type_64', False), r.get('prefetch', False)))
                if address >= 0:
                    need(address + extent <= (1 << 16 if r['type'] == 'io' else 1 << 64), 'assigned PCI region overflow')
                    all_regions.append((bdf, bar, address, address + extent, r['type']))
            selected = [d for d in expected.devices if d.bdf == bdf]
            if selected:
                d = selected[0]; need((vendor, dev, code) == (d.vendor, d.device, d.klass >> 8), 'actual selected PCI identity differs')
                need(all(r in parsed for r in d.regions), 'actual configured BAR base/size/type differs')
                used = set()
                for bar, address, extent, kind, wide, prefetch in parsed:
                    need(address >= 0 and address + extent <= (1 << 16 if kind == 'io' else 1 << 32), 'bounded selected PCI region')
                    need(not any(kind == previous_kind and address < end and start < address + extent for start, end, previous_kind in decoded), 'overlapping current selected BARs')
                    decoded.append((address, address + extent, kind))
                    if bar < 6:
                        need(bar not in used, 'overlapping BAR slots'); raw = d.bars[bar]
                        base = raw & (~3 if kind == 'io' else ~15)
                        need(bool(raw & 1) == (kind == 'io') and base == address, 'raw BAR/current region differs')
                        need((not wide and not prefetch and raw & 3 == 1) if kind == 'io' else ((raw & 6) == (4 if wide else 0) and bool(raw & 8) == prefetch), 'raw BAR type/flags differ')
                        used.add(bar)
                        if wide: need(bar < 5 and d.bars[bar + 1] == 0, 'bounded upper BAR required'); used.add(bar + 1)
                    if kind == 'memory': need(not any(address < end and start < address + extent for start, end in (*flat['ram'], flat['ecam'])), 'selected BAR overlaps actual RAM/ECAM')
                need(all(raw == 0 or bar in used for bar, raw in enumerate(d.bars)), 'unobserved selected raw BAR')
                found[bdf] = tuple(sorted(parsed))
            bridge = row.get('pci_bridge')
            if bridge is not None:
                need(type(bridge) is dict and type(bridge.get('bus')) is dict, 'PCI bridge schema')
                secondary = integer(bridge['bus'].get('secondary'), 0, 255)
                devices(bridge.get('devices', []), secondary, depth + 1)
    buses = set()
    for row in data:
        need(type(row) is dict, 'PCI bus schema'); bus = integer(row.get('bus'), 0, 255)
        need(bus not in buses, 'duplicate PCI bus'); buses.add(bus); devices(row.get('devices'), bus, 0)
    need(set(found) == {d.bdf for d in expected.devices}, 'missing current selected PCI device')
    for bdf, regions in found.items():
        for bar, address, extent, kind, _, _ in regions:
            need(not any((other_bdf, other_bar) != (bdf, bar) and kind == other_kind and address < end and start < address + extent for other_bdf, other_bar, start, end, other_kind in all_regions), 'selected BAR overlaps reported foreign/current BAR')
    return found


def observe_open_backend(binding, fd, path):
    """Observe one exact private writable inode open in the owned process.

    This reads only bounded proc metadata. It does not read image content,
    acquire a read lease on a writable backend, or inspect QEMU internals.
    The separate current block graph/recipe and exclusive owner are required.
    """
    need(type(binding) is ProcessBinding, 'actual owned process required for backend observation')
    integer(fd, 0, 1 << 30); path = Path(path)
    def caller():
        need(path.is_absolute() and path.resolve() == path and not any(x.is_symlink() for x in (path, *path.parents)), 'canonical private backend name required')
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and identity(s) == identity(path.stat()), 'exact private caller backend inode required')
        need(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR, 'caller writable backend descriptor required')
        return identity(s)
    def snapshot():
        rows, matches, total = [], [], 0
        proc = Path('/proc/%d' % binding.original_pid)
        with os.scandir(proc / 'fd') as entries:
            numbers = []
            for entry in entries:
                need(re.fullmatch('[0-9]{1,10}', entry.name) is not None and len(numbers) < 256, 'complete bounded process FD inventory required')
                numbers.append(integer(int(entry.name), 0, 1 << 30))
        for number in sorted(numbers):
            name = proc / 'fd' / str(number); target = os.readlink(name)
            total += len(os.fsencode(target)); need(len(os.fsencode(target)) <= 4096 and total <= MAX_QMP, 'bounded process FD target inventory')
            s = name.stat(); rows.append((number, target, s.st_dev, s.st_ino, s.st_mode, s.st_size))
            need(target != str(path) + ' (deleted)', 'deleted same-name backend open refused')
            if target == str(path) or (s.st_dev, s.st_ino) == expected[:2]:
                need(target == str(path) and identity(s) == expected and stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1, 'foreign or aliased same-name backend open refused')
                info_fd = os.open(proc / 'fdinfo' / str(number), os.O_RDONLY | os.O_CLOEXEC)
                try: raw = os.read(info_fd, 8193)
                finally: os.close(info_fd)
                need(len(raw) <= 8192, 'bounded actual backend fdinfo required')
                info = raw.decode('ascii'); flags = re.findall(r'^flags:\s*([0-7]+)$', info, re.M)
                inode = re.findall(r'^ino:\s*([0-9]+)$', info, re.M); mount = re.findall(r'^mnt_id:\s*([0-9]+)$', info, re.M)
                need(len(flags) == len(mount) == 1 and inode == [str(s.st_ino)], 'complete actual backend fdinfo required')
                actual_flags = int(flags[0], 8)
                need(actual_flags & os.O_ACCMODE == os.O_RDWR and not actual_flags & (os.O_DIRECT | os.O_APPEND), 'actual writable nondirect backend flags required')
                matches.append((number, actual_flags, int(mount[0]), identity(s)))
        need(len(matches) == 1, 'one unambiguous actual owned backend open required')
        return tuple(rows), matches[0]
    binding.check(); expected = caller()
    first, opened = snapshot(); binding.check()
    need(caller() == expected, 'caller backend changed during observation')
    last, final_opened = snapshot(); binding.check()
    need(caller() == expected and first == last and opened == final_opened, 'complete owned process FD/backend epoch changed')
    return {'observed_owned_process_open_inode': True, 'process_pid': binding.original_pid,
            'process_starttime': binding.starttime, 'path': str(path), 'opened_fd': opened[0],
            'opened_identity': list(opened[3]), 'flags': opened[1], 'mount_id': opened[2],
            'access': 'read-write', 'direct': False, 'complete_process_fd_inventory_count': len(first),
            'content_immutability_verified': False, 'QEMU_internal_graph_to_fd_mapping_verified': False}


class OwnedESP:
    """Owned writable image identity only; no image hash/read or lease here."""
    def __init__(self, fd, path):
        self.fd, self.path = fd, Path(path)
        need(self.path.is_absolute() and self.path.resolve() == self.path and not any(x.is_symlink() for x in (self.path, *self.path.parents)), 'canonical owned ESP required')
        self.binding = identity(os.fstat(fd)); self.check()

    def check(self):
        s = os.fstat(self.fd)
        need(self.path.resolve() == self.path and not any(x.is_symlink() for x in (self.path, *self.path.parents)), 'owned ESP canonical name changed')
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and s.st_size == 2304 << 20 and identity(s) == self.binding == identity(self.path.stat()), 'owned pre-grant ESP identity/extent changed')

    def observe_backend(self, binding):
        self.check(); result = observe_open_backend(binding, self.fd, self.path); self.check()
        return result


def validate_blocks(blocks, nodes, esp):
    esp.check(); need(type(blocks) is list and len(blocks) <= 32 and type(nodes) is list and len(nodes) <= 64, 'bounded full block graph required')
    selected = [x for x in blocks if type(x) is dict and x.get('device') == 'esp']
    need(len(selected) == 1 and not selected[0].get('locked', False), 'sole owned ESP backend required')
    inserted = selected[0].get('inserted'); need(type(inserted) is dict, 'inserted ESP required')
    name = inserted.get('node-name'); need(type(name) is str and 0 < len(name) <= 128, 'current ESP node name required')
    selected_nodes = [x for x in nodes if type(x) is dict and x.get('node-name') == name]
    need(len(selected_nodes) == 1, 'sole current ESP graph node required')
    for row in (inserted, selected_nodes[0]):
        need(row.get('drv') == 'raw' and row.get('ro') is False and row.get('encrypted') is False and row.get('file') == str(esp.path), 'owned writable raw ESP differs')
        cache = row.get('cache')
        need(type(cache) is dict and all(type(x) is bool for x in cache.values()) and cache == {'writeback': True, 'direct': False, 'no-flush': False}, 'actual cache/FLUSH semantics differ')
        image = row.get('image'); need(type(image) is dict and image.get('filename') == str(esp.path) and image.get('format') == 'raw' and image.get('virtual-size') == 2304 << 20, 'current ESP image graph differs')
    # These are QMP graph strings and the caller's inode, not a kernel open
    # backend proof. HostGrant separately requires the actual FD observation.
    esp.check(); return {'node': name, 'file': str(esp.path), 'caller_inode': esp.binding[:2], 'cache': inserted['cache'], 'QMP_filename_establishes_open_inode': False}


class HostGrant:
    """One prospective owned exchange. Returns while QEMU is still paused.

    No existing caller wires this. Outer source/recipe/ESP/ROM lineage admission
    and actual custody through reap remain mandatory before real optional use.
    """
    def __init__(self, attempt, binding, monitor, listener, esp, monitor_source, guard=None):
        need(type(attempt) is Attempt and type(binding) is ProcessBinding and type(listener) is PrivateListener, 'concrete owned context required')
        need(attempt.owner is None and listener.owner is None, 'fresh unbound policy/channel ownership required')
        # Once associated with an already-created child, even constructor
        # refusal must preserve policy/channel custody until exact reap.
        attempt.owner = listener.owner = binding
        need(callable(guard), 'actual outer owner guard required for host exchange')
        self.guard = guard; guard()
        binding.check()
        need(type(esp) is OwnedESP, 'concrete owned ESP context required')
        need(binding.executable.path.name in ('qemu-kvm', 'qemu-system-x86_64'), 'approved QEMU executable role required')
        argv = binding.argv
        def pair(option, value): return sum(argv[i:i + 2] == (option, value) for i in range(len(argv) - 1)) == 1
        need(all(pair(option, value) for option, value in (('-machine', 'q35'), ('-accel', 'kvm'), ('-cpu', 'host,+vmx'), ('-m', '4096M'), ('-smp', '1'), ('-nic', 'none'), ('-display', 'none'))), 'exact scoped owned Q35 recipe required')
        need(argv.count('-nodefaults') == 1 and '-readconfig' not in argv and '-writeconfig' not in argv and '-incoming' not in argv, 'explicit scoped recipe required')
        need(pair('-fw_cfg', 'name=%s,file=/proc/self/fd/%d' % (POLICY_NAME, attempt.policy_fd)) and pair('-chardev', 'socket,id=shz-epoch,path=%s,server=off' % listener.path) and pair('-serial', 'chardev:shz-epoch'), 'exact sealed policy and connecting COM2 recipe required')
        need(tuple(argv[i + 1] for i, x in enumerate(argv[:-1]) if x == '-device') == ('VGA', 'virtio-blk-pci,drive=esp,bootindex=1'), 'only known Supervisor-owned selected device recipe required')
        self.attempt, self.binding, self.listener, self.esp = attempt, binding, listener, esp
        self.qmp = SoleQMP(binding, monitor, attempt, monitor_source); self.peer = None
        self.exchange_stop_ns = self.original_exchange_stop_ns = None
        self.transport_calls = 0; self.grant_bytes_written = 0

    def check(self):
        need(not getattr(self, '_monitor_handed_off', False) and not getattr(self, '_handoff_failed', False), 'host epoch monitor transferred or handoff failed')
        self.qmp.check(); self.listener.check(); self.esp.check()
        s = Path('/proc/%d/fd/%d' % (self.binding.process.pid, self.attempt.policy_fd)).stat()
        need((s.st_dev, s.st_ino, s.st_size) == self.attempt.policy_identity[:3], 'actual child inherited policy FD differs')
        if self.exchange_stop_ns is not None:
            need(self.exchange_stop_ns == self.original_exchange_stop_ns and time.monotonic_ns() < self.exchange_stop_ns, 'unchanged additional10s exchange bound expired')
        if self.peer is not None: need(struct.unpack('3i', self.peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[:2] == (self.binding.process.pid, os.getuid()), 'current COM2 peer changed')

    def _guarded_check(self):
        # The caller supplies actual bootstrap/union/group/resource/cancellation
        # checks. Local device context checks cannot substitute for that guard.
        need(callable(getattr(self, 'guard', None)), 'actual outer owner guard required for host exchange')
        self.guard(); self.check()

    def transfer(self, data, extent, send=False):
        result = bytearray()
        while len(result) < extent:
            self._guarded_check(); need(self.transport_calls < 4096, 'finite shared COM2 transfer budget'); self.transport_calls += 1
            deadline_ns = self.attempt.original_deadline_ns
            if getattr(self, 'exchange_stop_ns', None) is not None:
                deadline_ns = min(deadline_ns, self.exchange_stop_ns)
            ready = checked_select([] if send else [self.peer], [self.peer] if send else [], deadline_ns, self._guarded_check)
            if (ready[1] if send else ready[0]):
                if send:
                    n = self.peer.send(data[len(result):extent]); need(n > 0, 'COM2 closed during write'); result.extend(b'\0' * n)
                    if extent == 272: self.grant_bytes_written += n
                else:
                    raw = self.peer.recv(extent - len(result) + 1); need(raw and len(result) + len(raw) <= extent, 'COM2 closed/surplus frame'); result.extend(raw)
            self._guarded_check()
        return bytes(result)

    def observe(self, observations):
        self.qmp.paused(); flat_text = self.qmp.call('human-monitor-command', {'command-line': 'info mtree -f'})
        flat = parse_flatview(flat_text); pci = self.qmp.call('query-pci'); resources = validate_pci(pci, self.attempt.expected, flat)
        for observed in observations:
            address = flat['ecam'][0] + observed['bdf'] * 4096
            need(address + 40 <= flat['ecam'][1], 'selected ECAM bound')
            raw = self.qmp.call('human-monitor-command', {'command-line': 'xp /10wx 0x%x' % address})
            need(parse_xp(raw, address) == observed['words'], 'actual raw PCI changed/differs from report')
        blocks = self.qmp.call('query-block'); nodes = self.qmp.call('query-named-block-nodes')
        backing = validate_blocks(blocks, nodes, self.esp)
        backing['owned_process_open_backend'] = self.esp.observe_backend(self.binding)
        self.qmp.paused(); self.check()
        return {'FlatView': flat, 'PCI': resources, 'ESP': backing}

    def exchange(self):
        need(not getattr(self, '_handoff_attempted', False), 'monitor handoff attempt is terminal')
        need(not self.attempt.consumed, 'single-use host attempt consumed'); self.attempt.consumed = True
        try:
            self._guarded_check(); self.peer = self.listener.accept(self.binding.process.pid, os.getuid(), self.attempt.original_deadline_ns, guard=self._guarded_check)
            ready = self.transfer(None, 48); validate_ready(ready, self.attempt.nonce)
            self.exchange_stop_ns = self.original_exchange_stop_ns = min(self.attempt.original_deadline_ns, time.monotonic_ns() + 10_000_000_000)
            self.attempt.exchange_stop_ns = self.attempt.original_exchange_stop_ns = self.exchange_stop_ns
            self.transfer(frame(1, 48, 0) + self.attempt.nonce, 48, True)
            report = self.transfer(None, 256); observed = validate_report(report, self.attempt.expected, self.attempt.nonce)
            self._guarded_check(); self.qmp.call('stop'); self.qmp.paused()
            self._guarded_check(); first = self.observe(observed)
            self._guarded_check(); last = self.observe(observed)
            need(first == last, 'current paused PCI/RAM/ECAM/ESP/cache epoch changed')
            self._guarded_check(); self.transfer(grant(report), 272, True); self.qmp.paused(); self._guarded_check()
            receipt = {'schema': 'shizukuos.native-device-host-grant.v1', 'host_grant_transmitted': True,
                    'owned_process': self.binding.check(), 'original_host_deadline_ns': self.attempt.original_deadline_ns,
                    'policy': {'bytes': 256, 'sha256': digest(self.attempt.policy).hex(), 'inode': self.attempt.policy_identity[:2], 'sealed': True},
                    'nonce_sha256': digest(self.attempt.nonce).hex(), 'report_sha256': digest(report).hex(),
                    'grant_sha256': digest(grant(report)).hex(), 'observations': first, 'actual_QMP_transcripts': self.qmp.transcripts,
                    'QEMU_remains_paused': True, 'owner_must_resume_within_original_deadline': True,
                    'constructor_host_runtime_wiring_implemented': False, 'native_gate_admission_observed': False,
                    'physical_device_initialization_verified': False, 'VM_Windows_boot_verified': False, 'coldboot_persistence_verified': False}
            # Receipt construction itself may still refuse the current child.
            # Only a completely returned exchange may transfer its one reader.
            self._completed_qmp = self.qmp
            return receipt
        except BaseException:
            # A partial/full GRANT is observable even if final checks fail.
            # Retain channel and policy for the actual outer recovery/reap.
            self.failure_after_grant_bytes = self.grant_bytes_written
            raise

    def handoff_monitor(self):
        """Return the original sole monitor after one fully completed epoch.

        The caller owns postepoch source/process/cancellation checks and a
        finite budget within the ORIGINAL owner deadline. No deadline is
        renewed here. Policy, listener and COM2 custody persist until exact
        child reap. This transfers the reader; it never creates another one.
        """
        need(not getattr(self, '_handoff_attempted', False), 'single-use monitor handoff consumed')
        self._handoff_attempted = True
        try:
            qmp = self.qmp
            need(type(qmp) is SoleQMP and getattr(self, '_completed_qmp', None) is qmp and
                 self.grant_bytes_written == 272 and not hasattr(self, 'failure_after_grant_bytes'),
                 'fully successful returned GRANT exchange required')
            self._guarded_check(); qmp.paused()
            monitor = qmp.monitor
            buffer = monitor.buffer; buffered = bytes(buffer); request = monitor.request
            self._guarded_check()
            need(self.qmp is qmp and monitor is qmp.monitor and monitor.buffer is buffer and bytes(buffer) == buffered and
                 monitor.request == request, 'post-query parser state changed during final owner check')
            # Keep the permanent claim on the original monitor. Rewrapping it
            # would create an independently budgeted reader after this epoch.
            qmp.retired = True
            self._monitor_handed_off = True
            return monitor
        except BaseException:
            self._handoff_failed = True
            raise

    def close_after_reap(self):
        self.binding.assert_reaped()
        try:
            if self.peer is not None: self.peer.close(); self.peer = None
        finally:
            try: self.listener.close()
            finally: self.attempt.close()
