#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guard the frozen disposable native Win98 absent-Supervisor negative trial.

Validation is the default. --execute is a separate reviewed root action. The
wrapper never turns a healthy runner/guard into native or application PASS.
GUI requests require an explicitly reviewed actual screenshot and prior receipt.
Only retained pidfds for the verified owned runner and exact-disk QEMU are
signalled on failure. No process-group or numeric-PID kill fallback exists.
"""
import argparse
import ast
from contextlib import redirect_stderr
from dataclasses import asdict, dataclass
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BOOT = Path('/root/Win98-Modern-boot')
DEFAULT_PROPOSAL = ROOT / 'build/modern-apps/native-w64-preparer-v2-review/native-launch-proposal-v9.json'
DEFAULT_PROPOSAL_SHA = '5df4344c015cbfb2e0ad13ee6b5686fdc0e65503b3c86140f20ee9f079a4f788'
NONCE = 'cb43-w64-negative-v3-20261001T010720Z-cc732595'
RUN_NAME = 'run-win98-native-w64-negative-cb43-v9-20261001T0835Z-cc732595'
SOURCE_RUN = BOOT / 'build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807'
RUN = BOOT / 'build/shizukudos/csm' / RUN_NAME
MANIFEST = ROOT / 'build/modern-apps/native-w64-negative-cb43-20261001-v3-outer/guest-inputs.json'
MANIFEST_SHA = '9479c1944386c49894957c1274108dc6a5b0795d6b4b3704ede081daaf334109'
QEMU = Path('/usr/libexec/qemu-kvm')
CODE = Path('/usr/share/edk2/ovmf/OVMF_CODE.fd')
VARS = Path('/usr/share/edk2/ovmf/OVMF_VARS.fd')
FLOOR = 18253611008
BEFORE_FLOOR = 19038617600
MEM_FLOOR = 4294967296
WALL = 2400
POLL = 2
RUNNER_ORIGINAL = BOOT / 'shizukudos/csm/test_win98_uefi.py'
RUNNER_ORIGINAL_SHA = '5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857'
RUNNER_ADAPTER = ROOT / 'build/modern-apps/native-w64-runner-adapter-v9/runner.py'
RUNNER_ADAPTER_SHA = 'f4e9ee96f745513448117054510eb5c3705869c240fa25b7113bb1dafe948dbe'
EXPECTED_ARGV = ['python3', '-u', str(RUNNER_ADAPTER),
    '--archive', '/root/Win98-Modern/build/win98-lab/install-packed-z_kei9n1.qcow2.xz',
    '--checkpoint-record', '/root/Win98-Modern/build/win98-lab/install-packed-current.json',
    '--resume-owned-run', str(SOURCE_RUN), '--csm-dir', str(BOOT / 'build/shizukudos/csm-gop-anchor'),
    '--replace-csmwrap', '--firmware-gop', '--machine', 'q35', '--accel', 'kvm', '--smp', '2',
    '--memory', '128', '--timeout', '1500', '--capture-interval', '10', '--manual-gui',
    '--manual-purpose', 'diagnostic', '--guest-files-manifest', str(MANIFEST),
    '--guest-files-manifest-sha', MANIFEST_SHA, '--reserve-gib', '17', '--run-name', RUN_NAME]
EXPECTED_CONTROLS = [
    {'sequence': 1, 'name': 'dismiss-reviewed-missing-mshbios-boot-prompt', 'keys': [['ret']]},
    {'sequence': 2, 'name': 'open-native-negative-run', 'keys': [['meta_l', 'r']]},
    {'sequence': 3, 'name': 'launch-frozen-W64OUT', 'keys': [['ctrl', 'a']],
     'text': 'C:\\VXDLAB\\W64OUT.EXE', 'enter': True},
    {'sequence': 4, 'name': 'capture-after-bounded-observers', 'capture': True},
    {'sequence': 5, 'name': 'finish-owned-negative-trial', 'finish': True}]


class GuardError(RuntimeError):
    pass


def digest_file(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic_json(path, data, new=False):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if new:
            os.link(temporary, path)  # publish complete inbox request, preserving O_EXCL semantics
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_proposal(proposal):
    if (proposal.get('schema') != 'win98modern.native-w64-negative-disposable-profile-proposal.v1'
            or proposal.get('status') != 'PROPOSAL_NOT_EXECUTED'
            or proposal.get('native_executed') is not False or proposal.get('application_executed') is not False
            or proposal.get('nonce') != NONCE or proposal.get('run') != str(RUN)
            or proposal.get('argv_for_root_guarded_launcher') != EXPECTED_ARGV
            or proposal.get('gui_control_proposal') != EXPECTED_CONTROLS):
        raise GuardError('Proposal differs from the exact native negative fixture/argv scope')
    guards = proposal.get('guards', {})
    fixed = {'disk_floor_bytes': FLOOR, 'minimum_before_clone_bytes': BEFORE_FLOOR,
             'minimum_host_mem_available_bytes': MEM_FLOOR, 'actual_guest_memory_mib': 128,
             'wall_bound_seconds': WALL, 'poll_seconds': POLL, 'dirty_allowance_bytes': 536870912,
             'source_allocated_bytes': 248135680}
    if any(type(guards.get(k)) is not int or guards[k] != v for k, v in fixed.items()):
        raise GuardError('Resource/timing guards changed')
    pins = proposal.get('held_source_pins')
    if not isinstance(pins, dict) or not 20 <= len(pins) <= 64:
        raise GuardError('Frozen pin set is missing or unbounded')
    required = [str(SOURCE_RUN / 'windows-uefi.raw'), str(SOURCE_RUN / 'result.json'), str(MANIFEST),
                EXPECTED_ARGV[2], str(QEMU), str(CODE), str(VARS)]
    if any(p not in pins for p in required):
        raise GuardError('Required source/runner/firmware pin absent')
    if any(not Path(p).is_absolute() or not re.fullmatch(r'[0-9a-f]{64}', h) for p, h in pins.items()):
        raise GuardError('Invalid frozen pin path/hash')
    if pins.get(str(RUNNER_ORIGINAL)) != RUNNER_ORIGINAL_SHA or pins.get(str(RUNNER_ADAPTER)) != RUNNER_ADAPTER_SHA:
        raise GuardError('Exact original/adapter producer pins absent or changed')
    return proposal


def runner_adapter_bytes(original):
    """Derive only the bounded timeout and explicit original helper roots.

    __file__ source hashing/copying stays attached to the actual adapter. All
    capture, staging, child ownership, guest and result code remains identical.
    """
    changes = [
        ('str(Path(__file__).resolve().parents[1] / "tools")', 'str(Path("/root/Win98-Modern-boot/shizukudos/tools"))'),
        ('not 10 <= args.timeout <= 900:', 'not 10 <= args.timeout <= 1500:'),
        ('and 10..900 seconds', 'and 10..1500 seconds'),
        ('str(Path(__file__).resolve().parents[2] / "tools")', 'str(Path("/root/Win98-Modern-boot/tools"))'),
        ('Path(__file__).resolve().parents[2])', 'Path("/root/Win98-Modern-boot"))')]
    source = original.decode('utf-8')
    for before, after in changes:
        if source.count(before) != 1:
            raise GuardError('Original producer no longer matches bounded adapter derivation')
        source = source.replace(before, after)
    return source.encode('utf-8')


def runner_cli_capability(source, argv):
    """Run only the pinned producer's argparse prefix and numeric gate.

    No producer import, main invocation, staging or process launch occurs. The
    extracted prefix admits argument declarations and bounded pure defaults;
    the resource gate must have the exact known production shape. This checks
    the real producer contract rather than repeating a wrapper timeout limit.
    """
    try:
        tree = ast.parse(source)
        main = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main']
        if len(main) != 1 or not isinstance(main[0].body[0], ast.Global) or main[0].body[0].names != ['RESERVE']:
            raise GuardError('Producer main argument prefix changed')
        body = main[0].body[1:]
        expected_parser = ast.parse('parser = argparse.ArgumentParser(description=__doc__)').body[0]
        expected_parse = ast.parse('args = parser.parse_args()').body[0]
        if ast.dump(body[0]) != ast.dump(expected_parser):
            raise GuardError('Producer argument parser creation changed')
        index = next(i for i, n in enumerate(body) if ast.dump(n) == ast.dump(expected_parse))
        declarations = body[1:index]
        for n in declarations:
            if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                    and ast.dump(n.value.func) == ast.dump(ast.parse('parser.add_argument', mode='eval').body)):
                raise GuardError('Producer has effects before argument validation')
        allowed = {'argparse.ArgumentParser', 'parser.add_argument', 'parser.parse_args', 'Path', 'range', 'time.strftime', 'time.gmtime'}
        for n in ast.walk(ast.Module(body=body[:index + 1], type_ignores=[])):
            if isinstance(n, ast.Call) and ast.unparse(n.func) not in allowed:
                raise GuardError('Producer argument default has an unsupported call')
        for option in ('--smp', '--memory', '--timeout'):
            calls = [n.value for n in declarations if n.value.args and isinstance(n.value.args[0], ast.Constant) and n.value.args[0].value == option]
            if len(calls) != 1 or len([k for k in calls[0].keywords if k.arg == 'type' and isinstance(k.value, ast.Name) and k.value.id == 'int']) != 1:
                raise GuardError('Producer numeric argument type changed')
        minimum = ast.parse('minimum_cpus = 1 if args.native_bios_control else 2').body[0]
        if ast.dump(body[index + 1]) != ast.dump(minimum):
            raise GuardError('Producer minimum CPU gate changed')
        gate = body[index + 2]
        maximum = None
        for limit in (900, 1500):
            reference = ast.parse(f'if not minimum_cpus <= args.smp <= 8 or not 64 <= args.memory <= 512 or not 10 <= args.timeout <= {limit}:\n    raise SystemExit(f"Require {{minimum_cpus}}..8 CPUs, 64..512 MiB RAM, and 10..{limit} seconds")').body[0]
            if ast.dump(gate) == ast.dump(reference):
                maximum = limit
        if maximum is None:
            raise GuardError('Producer bounded resource gate changed')
        body[index].value.args = [ast.Name(id='_guard_argv', ctx=ast.Load())]
        prefix = ast.fix_missing_locations(ast.Module(body=body[:index + 3], type_ignores=[]))
        namespace = {'__builtins__': {}, '__doc__': ast.get_docstring(tree), 'argparse': argparse, 'Path': Path,
            'time': time, 'range': range, 'int': int, 'SystemExit': SystemExit, '_guard_argv': list(argv),
            'CSM': BOOT / 'build/shizukudos/csm', 'qemu': argparse.Namespace(DEFAULT_QEMU=str(QEMU),
                DEFAULT_OVMF_CODE=str(CODE), DEFAULT_OVMF_VARS=str(VARS))}
        with redirect_stderr(io.StringIO()):
            exec(compile(prefix, '<pinned-producer-cli-only>', 'exec'), namespace)
        args = namespace['args']
        return {'status': 'PINNED_PRODUCER_CLI_ACCEPTED_NOT_EXECUTED', 'smp': args.smp, 'memory_mib': args.memory,
            'timeout_seconds': args.timeout, 'minimum_cpus': namespace['minimum_cpus'], 'maximum_cpus': 8,
            'minimum_memory_mib': 64, 'maximum_memory_mib': 512, 'minimum_timeout_seconds': 10,
            'maximum_timeout_seconds': maximum, 'producer_main_executed': False, 'vm_executed': False}
    except GuardError:
        raise
    except SystemExit as error:
        raise GuardError('Pinned producer CLI rejected the requested profile: ' + str(error)) from error
    except Exception as error:
        raise GuardError('Pinned producer CLI validation failed: ' + str(error)) from error


def pinned_producer_bytes(pins, path, expected):
    held = pins.held.get(str(path))
    if held is None or held[1] != expected:
        raise GuardError('Producer source is not held under its exact immutable pin')
    fd, _, initial = held
    before = os.fstat(fd)
    if not 1 <= before.st_size <= 262144:
        raise GuardError('Producer source extent is unbounded')
    raw = os.pread(fd, before.st_size + 1, 0)
    after = os.fstat(fd)
    current = os.stat(path, follow_symlinks=False)
    if (len(raw) != before.st_size or not pins.same(initial, before) or not pins.same(before, after)
            or not pins.same(after, current) or hashlib.sha256(raw).hexdigest() != expected):
        raise GuardError('Held producer source changed during capability validation')
    return raw


def validate_runner_capability(proposal, pins):
    original = pinned_producer_bytes(pins, RUNNER_ORIGINAL, RUNNER_ORIGINAL_SHA)
    adapter = pinned_producer_bytes(pins, RUNNER_ADAPTER, RUNNER_ADAPTER_SHA)
    if adapter != runner_adapter_bytes(original):
        raise GuardError('Adapter differs from the exact original producer derivation')
    result = runner_cli_capability(adapter, proposal['argv_for_root_guarded_launcher'][3:])
    if result['maximum_timeout_seconds'] != 1500:
        raise GuardError('Adapter does not implement the reviewed 1500-second bound')
    result.update(original_source_sha256=RUNNER_ORIGINAL_SHA, actual_adapter_source_sha256=RUNNER_ADAPTER_SHA,
                  exact_derivation_verified=True)
    return result


@dataclass(frozen=True)
class Identity:
    pid: int
    start: int
    ppid: int
    session: int
    state: str
    argv: tuple
    exe_device: int
    exe_inode: int

    def matches(self, other):
        # PPID can become 1 after the verified parent exits. Ownership was
        # established at capture; pidfd plus start/executable/argv/session guard
        # every subsequent signal, including that legitimate orphan case.
        return other is not None and (self.pid, self.start, self.session, self.argv, self.exe_device, self.exe_inode) == (
            other.pid, other.start, other.session, other.argv, other.exe_device, other.exe_inode)


def identity(pid, proc=Path('/proc')):
    base = proc / str(pid)
    try:
        raw = (base / 'stat').read_text()
        close = raw.rfind(')')
        if close < 0 or int(raw[:raw.find(' ')]) != pid:
            raise GuardError('Invalid proc stat identity')
        fields = raw[close + 2:].split()
        exe = (base / 'exe').stat()
        argv = tuple(v.decode('utf-8', errors='surrogateescape') for v in (base / 'cmdline').read_bytes().split(b'\0') if v)
        return Identity(pid, int(fields[19]), int(fields[1]), int(fields[3]), fields[0], argv, exe.st_dev, exe.st_ino)
    except (FileNotFoundError, ProcessLookupError):
        return None


def descendant(pid, parent, read_identity=identity):
    current, seen = read_identity(pid), set()
    while current is not None and current.pid not in seen:
        if parent.matches(current):
            return True
        if current.start < parent.start or current.session != parent.session:
            return False
        seen.add(current.pid)
        current = read_identity(current.ppid)
    return False


def validate_qemu_argv(argv, run=RUN):
    if not argv or argv[0] != str(QEMU) or len(argv) != 33:
        raise GuardError('Actual QEMU executable/argument count differs')
    qmp = argv[31]
    if not re.fullmatch(r'unix:/tmp/shz-win98-uefi-[A-Za-z0-9_-]+/qmp\.sock,server=on,wait=off', qmp):
        raise GuardError('Unexpected actual private QMP socket')
    expected = [str(QEMU), '-name', 'shz-disposable-win98-uefi', '-machine', 'q35,hpet=off', '-accel', 'kvm',
        '-cpu', 'qemu64', '-smp', '2', '-m', '128', '-nodefaults', '-nic', 'none', '-display', 'none',
        '-device', 'VGA', '-drive', f'if=pflash,unit=0,format=raw,readonly=on,file={CODE}',
        '-drive', f'if=pflash,unit=1,format=raw,file={run / "OVMF_VARS.fd"}',
        '-drive', f'file={run / "windows-uefi.raw"},format=raw,if=none,id=win98',
        '-device', 'ide-hd,drive=win98,bus=ide.0,bootindex=1', '-serial', f'file:{run / "serial.log"}',
        '-qmp', qmp, '-no-reboot']
    if list(argv) != expected:
        raise GuardError('Actual QEMU hardware/disk/network/firmware argv differs')
    return True


def exact_owned_disk(argv, run=RUN):
    values = [argv[i + 1] for i, v in enumerate(argv[:-1]) if v == '-drive']
    return values.count(f'file={run / "windows-uefi.raw"},format=raw,if=none,id=win98') == 1


@dataclass
class OwnedProcess:
    who: Identity
    pidfd: int
    kind: str


def capture_process(pid, kind, read_identity=identity):
    before = read_identity(pid)
    if before is None or before.state == 'Z':
        return None
    try:
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None
    after = read_identity(pid)
    if after is None or after.state == 'Z':
        os.close(fd)
        return None                 # natural exit while opening/reading the retained pidfd
    if not before.matches(after):
        os.close(fd)
        raise GuardError('Process identity changed while opening pidfd')
    return OwnedProcess(before, fd, kind)


def capture_spawn_candidate(child, read_identity=identity):
    """Retain the actual Popen child across its bounded initial exec transition.

    This is provisional, never an identity eligible for signalling. Only its
    PID/start remain immutable during the handshake; executable/argv/session
    must subsequently become the exact expected post-exec identity.
    """
    try:
        fd = os.pidfd_open(child.pid, 0)
    except ProcessLookupError:
        return None
    who = read_identity(child.pid)
    if who is None or who.state == 'Z':
        os.close(fd)
        return None
    return OwnedProcess(who, fd, 'runner-candidate')


def expected_runner(who, candidate, wrapper, argv, executable):
    return (who is not None and who.state != 'Z' and who.pid == candidate.who.pid
            and who.start == candidate.who.start and who.ppid == wrapper.pid and who.session == who.pid
            and who.argv == tuple(argv) and (who.exe_device, who.exe_inode) == executable)


def await_spawn_identity(candidate, wrapper, argv, executable, samples, check,
                         read_identity=identity, clock=time.monotonic, pause=time.sleep, child_poll=lambda: None):
    deadline = clock() + 2
    previous = None
    while clock() <= deadline:
        who = read_identity(candidate.who.pid)
        samples.append(None if who is None else asdict(who))
        if who is None or who.state == 'Z' or child_poll() is not None:
            raise GuardError('Popen child exited during post-exec identity handshake')
        if who.pid != candidate.who.pid or who.start != candidate.who.start:
            raise GuardError('Popen child PID/start changed during post-exec identity handshake')
        exact = expected_runner(who, candidate, wrapper, argv, executable)
        # Source-holder inspection rechecks this exact current identity itself;
        # a verified Popen child may begin its readonly copy before sample two.
        check(who if exact else None)
        if exact:
            if previous is not None and previous.matches(who):
                return OwnedProcess(who, candidate.pidfd, 'runner')
            previous = who
        else:
            previous = None
        pause(0.05)
    raise GuardError('Exact post-exec Popen identity did not stabilize within two seconds')


def verified_spawn_for_stop(candidate, wrapper, argv, executable, read_identity=identity):
    """A failed handshake may still have left our now-correct child alive.

    Adopt it only after two current exact reads with the original pidfd and
    immutable start. This never signals an unverified pre-exec argv identity.
    """
    first, second = read_identity(candidate.who.pid), read_identity(candidate.who.pid)
    if (expected_runner(first, candidate, wrapper, argv, executable)
            and expected_runner(second, candidate, wrapper, argv, executable) and first.matches(second)):
        return OwnedProcess(second, candidate.pidfd, 'runner')
    return None


def signal_owned(process, sig, read_identity=identity, sender=signal.pidfd_send_signal):
    now = read_identity(process.who.pid)
    if now is None or now.state == 'Z':
        return 'already-gone'
    if not process.who.matches(now):
        raise GuardError('Refusing to signal changed/reused process identity')
    if process.kind == 'qemu' and not exact_owned_disk(now.argv):
        raise GuardError('Refusing QEMU signal without exact owned fresh disk')
    try:
        sender(process.pidfd, sig, None, 0)
        return 'sent'
    except ProcessLookupError:
        return 'already-gone'


class Pins:
    def __init__(self, values):
        self.values = values
        self.held = {}

    def open(self):
        errors = []
        for name, expected in self.values.items():
            fd = None
            try:
                fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise GuardError('Pinned source is not a regular file')
                self.held[name] = (fd, expected, info)
            except Exception as error:
                if fd is not None:
                    os.close(fd)
                errors.append({'path': name, 'error': str(error)})
        return errors

    def snapshot(self):
        result = {}
        for name, (fd, expected, initial) in self.held.items():
            try:
                before = os.fstat(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                while data := os.read(fd, 4 * 1024 * 1024):
                    digest.update(data)
                after = os.fstat(fd)
                path_info = os.stat(name, follow_symlinks=False)
                stable = self.same(before, after) and self.same(after, path_info) and self.same(initial, after)
                result[name] = {'sha256': digest.hexdigest(), 'expected': expected, 'matches': stable and digest.hexdigest() == expected,
                                'device': after.st_dev, 'inode': after.st_ino, 'bytes': after.st_size,
                                'mtime_ns': after.st_mtime_ns, 'stable_inode_metadata': stable}
            except Exception as error:
                result[name] = {'matches': False, 'error': str(error)}
        return result

    @staticmethod
    def same(a, b):
        return (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns) == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns)

    def unchanged_metadata(self):
        for name, (fd, _, initial) in self.held.items():
            if not self.same(initial, os.fstat(fd)) or not self.same(initial, os.stat(name, follow_symlinks=False)):
                raise GuardError('Held source metadata/inode changed: ' + name)

    def close(self):
        for fd, _, _ in self.held.values():
            os.close(fd)


def source_fd_observation(fd, fdinfo):
    """Read the actual open descriptor, never reopen its target as a proxy.

    Linux fdinfo flags describe that descriptor's access mode. Its ino must
    agree with the dereferenced descriptor inode. Missing, malformed, O_PATH,
    nonregular or access-mode 3 descriptors are not proven source readers.
    """
    opened = fd.stat()
    raw = fdinfo.read_text()
    flags = re.findall(r'^flags:\s*([0-7]+)\s*$', raw, re.MULTILINE)
    numbers = re.findall(r'^ino:\s*([0-9]+)\s*$', raw, re.MULTILINE)
    mounts = re.findall(r'^mnt_id:\s*([0-9]+)\s*$', raw, re.MULTILINE)
    if (not stat.S_ISREG(opened.st_mode) or len(flags) != 1 or len(numbers) != 1
            or len(mounts) != 1 or int(numbers[0]) != opened.st_ino):
        raise GuardError('Source descriptor fdinfo/inode is unclassifiable')
    value = int(flags[0], 8)
    return {'device': opened.st_dev, 'inode': opened.st_ino, 'bytes': opened.st_size,
            'mtime_ns': opened.st_mtime_ns, 'flags_octal': flags[0], 'flags': value,
            'mount_id': int(mounts[0]), 'read_only': (value & os.O_ACCMODE) == os.O_RDONLY
            and not (value & getattr(os, 'O_PATH', 0))}


def live_vm_identity(who):
    """Even a read-only QEMU base descriptor is a forbidden shared VM base."""
    name = Path(who.argv[0]).name.lower() if who.argv else ''
    if (name.startswith('qemu-') or name in ('qemu', 'kvm', 'vboxheadless', 'virtualboxvm', 'vmware-vmx')):
        return True
    actual = QEMU.stat()
    return (who.exe_device, who.exe_inode) == (actual.st_dev, actual.st_ino)


def source_foreign_holders(device, inode, own_wrapper, own_runner=None, proc=Path('/proc'), read_identity=identity, audit=None):
    holders = []
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        current = read_identity(pid)
        if current is None:
            continue
        try:
            fds = list((entry / 'fd').iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        for fd in fds:
            try:
                opened = fd.stat()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if (opened.st_dev, opened.st_ino) != (device, inode):
                continue
            record = {'pid': pid, 'start': current.start, 'fd': fd.name,
                      'executable': Path(current.argv[0]).name if current.argv else '',
                      'device': device, 'inode': inode, 'allowed': False}
            try:
                first = source_fd_observation(fd, entry / 'fdinfo' / fd.name)
                middle = read_identity(pid)
                second = source_fd_observation(fd, entry / 'fdinfo' / fd.name)
                after = read_identity(pid)
                if (not current.matches(middle) or not current.matches(after)
                        or first != second or (first['device'], first['inode']) != (device, inode)):
                    raise GuardError('Source holder descriptor/process identity changed between reads')
                record.update(first)
                record['stable_double_read'] = True
                record['live_vm'] = live_vm_identity(after)
                if record['live_vm']:
                    record['reason'] = 'live VM holds the immutable base inode'
                elif not first['read_only']:
                    record['reason'] = 'source descriptor is writable or O_PATH'
                elif own_wrapper.matches(after) or (own_runner is not None and descendant(pid, own_runner, read_identity)):
                    record['allowed'] = True
                    record['reason'] = 'verified owned source reader'
                elif first['read_only']:
                    record['allowed'] = True
                    record['reason'] = 'stable proven foreign O_RDONLY source reader'
            except (OSError, GuardError, ValueError) as error:
                record['reason'] = str(error)
            if audit is not None:
                audit.append(record)
            if not record['allowed']:
                holders.append(record)
    return holders


def mem_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise GuardError('Actual MemAvailable is unavailable')


def resource_guard(free, memory, before):
    if free < (BEFORE_FLOOR if before else FLOOR) or memory < MEM_FLOOR:
        raise GuardError('Disk or actual host available RAM crossed the frozen floor')


def capture_number(screenshot):
    match = re.fullmatch(r'screen-(\d{3,})\.(png|ppm)', Path(screenshot).name)
    if not match or f'{int(match[1]):03d}' != match[1]:
        raise GuardError('Capture name differs from the actual canonical producer number')
    return int(match[1])


def validate_control(sequence, proposal, prior, screenshot, launch_age):
    if type(sequence) is not int or sequence not in (1, 2, 3, 4, 5):
        raise GuardError('Control is outside the five fixed proposal actions')
    if sequence > 1 and (not prior or type(prior.get('sequence')) is not int
            or prior['sequence'] != sequence - 1 or not prior.get('status', '').startswith('sent;')):
        raise GuardError('Actual prior native GUI receipt is missing or failed')
    if sequence in (4, 5) and (launch_age is None or launch_age < 50):
        raise GuardError('Bounded observers require at least 50 seconds after actual launch receipt')
    number = capture_number(screenshot)
    if sequence > 1:
        previous = Path(prior.get('screenshot', ''))
        if sequence in (2, 3):
            # The immediate post-key frame may precede desktop/dialog readiness.
            # Later automatic frames belong to the same pinned producer and run.
            if previous.parent != screenshot.parent or number < capture_number(previous):
                raise GuardError('Reviewed capture predates or differs from the actual prior GUI receipt run')
        elif previous != screenshot:
            raise GuardError('Reviewed screenshot differs from the actual prior GUI receipt')
    request = dict(proposal['gui_control_proposal'][sequence - 1])
    if request.get('sequence') != sequence:
        raise GuardError('Proposal controls are not sequential')
    return request


def verified_screenshot(path, run=RUN):
    path = Path(path).absolute()
    canonical = path.resolve(strict=True)
    canonical_run = run.resolve(strict=True)
    if (path != canonical or not canonical.is_relative_to(canonical_run) or not canonical.is_file()
            or not 0 < canonical.stat().st_size <= 32 * 1024 * 1024):
        raise GuardError('Reviewed screenshot is aliased or outside the actual canonical owned run')
    return canonical


def capture_file_bytes(path, run, minimum, maximum):
    path = Path(path)
    canonical = path.resolve(strict=True)
    if path != canonical or not canonical.is_relative_to(run.resolve(strict=True)):
        raise GuardError('Capture provider input is aliased or outside the owned run')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not minimum <= before.st_size <= maximum:
            raise GuardError('Capture provider input has invalid type or extent')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        if not Pins.same(before, after) or not Pins.same(after, path.stat(follow_symlinks=False)) or len(raw) != before.st_size:
            raise GuardError('Capture provider input changed while consuming actual bytes')
        return raw
    finally:
        os.close(fd)


def verified_capture_evidence(screenshot, proposal, run=RUN):
    """Bind the real producer's owned source snapshot, image and sidecars.

    The pinned runner's live frames list is in memory until its final result;
    it does not publish a live capture JSON. Its capture() always publishes a
    screen-NNN image, 4000-byte VGA sample, text and actual CPU register dump.
    These bytes and the copied runner source are validated before forwarding.
    This proves capture provenance/decodability, never a scene's GUI meaning.
    """
    screenshot = verified_screenshot(screenshot, run)
    number = capture_number(screenshot)
    if screenshot.parent != run.resolve(strict=True):
        raise GuardError('Actual producer capture must be directly in its owned run')
    match = re.fullmatch(r'(screen-\d{3,})\.(png|ppm)', screenshot.name)
    if not match:
        raise GuardError('Capture must use the pinned actual producer screen-NNN image name')
    expected = proposal['held_source_pins'].get(EXPECTED_ARGV[2])
    source = capture_file_bytes(run / 'runner-source.py', run, 1, 2 * 1024 * 1024)
    if hashlib.sha256(source).hexdigest() != expected:
        raise GuardError('Actual capture runner source snapshot differs from pinned producer')
    raw = capture_file_bytes(screenshot, run, 1, 32 * 1024 * 1024)
    from PIL import Image
    with Image.open(io.BytesIO(raw)) as frame:
        image_format, dimensions = frame.format, frame.size
        if (image_format != ('PNG' if match[2] == 'png' else 'PPM') or not all(0 < n <= 8192 for n in dimensions)
                or dimensions[0] * dimensions[1] > 16 * 1024 * 1024):
            raise GuardError('Actual screenshot format/dimensions are invalid')
        frame.verify()
    with Image.open(io.BytesIO(raw)) as frame:
        frame.load()                   # verify actual compressed pixel data too
    sidecars = {}
    for suffix, minimum, maximum in (('-vga.bin', 4000, 4000), ('-text.txt', 1, 16384),
                                     ('-registers.txt', 1, 65536)):
        path = run / (match[1] + suffix)
        data = capture_file_bytes(path, run, minimum, maximum)
        if suffix == '-registers.txt' and not re.search(rb'\b(?:EIP|RIP)=[0-9a-fA-F]+\b', data):
            raise GuardError('Actual capture lacks a producer CPU instruction-pointer register dump')
        sidecars[str(path)] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    return {'screenshot': str(screenshot), 'screenshot_sha256': hashlib.sha256(raw).hexdigest(),
            'capture_number': number,
            'format': image_format, 'dimensions': dimensions, 'producer_source_sha256': expected,
            'actual_producer_sidecars': sidecars, 'visual_scene_verified_by_guard': False}


def actual_control_receipt(run=RUN):
    path = run / 'gui-control-receipt.json'
    if not path.exists() and not path.is_symlink():
        return None, None
    raw = capture_file_bytes(path, run, 1, 65536)
    receipt = json.loads(raw)
    if (not isinstance(receipt, dict) or type(receipt.get('sequence')) is not int
            or receipt['sequence'] not in (1, 2, 3, 4, 5)):
        raise GuardError('Actual GUI receipt has invalid object/sequence')
    return receipt, hashlib.sha256(raw).hexdigest()


def capture_sources(proposal, proposal_path, proposal_sha):
    values = dict(proposal['held_source_pins'])
    values[str(proposal_path)] = proposal_sha
    values[str(Path(__file__).resolve())] = digest_file(__file__)
    values[str(Path(sys.executable).resolve())] = digest_file(sys.executable)
    frozen = ROOT / 'build/modern-apps/native-w64-preparer-v2-review/frozen-source-receipt.json'
    data = json.loads(frozen.read_text())
    # Also preserve the original preparation/native scripts and the frozen v3
    # compiler inputs. These are source pins, not executable routing directives.
    for table in ('source_sha256', 'all_frozen_v3_files'):
        for name, sha in data.get(table, {}).items():
            if name in values and values[name] != sha:
                raise GuardError('Conflicting immutable source pin')
            values[name] = sha
    if len(values) > 96:
        raise GuardError('Expanded source pin set exceeds fixed bound')
    return values


class GuardedRun:
    def __init__(self, proposal, proposal_path, proposal_sha, output, execute):
        self.proposal, self.output, self.execute = proposal, output, execute
        self.pins = Pins(capture_sources(proposal, proposal_path, proposal_sha))
        self.runner = self.qemu = self.runner_candidate = None
        self.child = None
        self.runlock = None
        self.log = None
        self.wrapper = identity(os.getpid())
        if self.wrapper is None:
            raise GuardError('Wrapper identity unavailable')
        self.started = time.monotonic()
        self.last_sequence = 0
        self.launch_receipt_time = None
        self.sent_sequence = 0
        self.last_actual_receipt_sha = None
        self.last_reviewed_capture_number = -1
        self.record = {'schema': 'win98modern.native-w64-guarded-run.v1', 'status': 'VALIDATING',
            'proposal': str(proposal_path), 'proposal_sha256': proposal_sha, 'run': str(RUN),
            'wrapper': asdict(self.wrapper), 'native_executed': False, 'native_negative_verified': False,
            'native_win64_positive_verified': False, 'application_executed': False,
            'source_before': {}, 'source_after': {}, 'resources': [], 'controls': [], 'stop_results': []}

    def save(self):
        atomic_json(self.output / 'guard-receipt.json', self.record)

    def check(self, before=False, source_owner=None):
        free = shutil.disk_usage(RUN.parent).free
        memory = mem_available()
        self.record['resources'].append({'seconds': round(time.monotonic() - self.started, 3), 'free_bytes': free, 'mem_available_bytes': memory})
        resource_guard(free, memory, before)
        self.pins.unchanged_metadata()
        raw = self.pins.held[str(SOURCE_RUN / 'windows-uefi.raw')][2]
        audit = []
        foreign = source_foreign_holders(raw.st_dev, raw.st_ino, self.wrapper,
            self.runner.who if self.runner else source_owner, audit=audit)
        self.record['source_foreign_holders'] = foreign
        self.record['source_fd_observations'] = audit
        if foreign:
            raise GuardError('An unsafe or shared-VM source descriptor holds the exact frozen disk inode')

    def own_run_lock(self):
        # Only --execute creates this sentinel. The peer runner itself must
        # create the still-absent run directory without our reserving it first.
        sentinel = RUN.parent / ('.' + RUN_NAME + '.guard.lock')
        fd = os.open(sentinel, os.O_RDWR | os.O_CLOEXEC | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, (json.dumps({'wrapper': asdict(self.wrapper), 'proposal_sha256': self.record['proposal_sha256']}) + '\n').encode())
        os.fsync(fd)
        self.runlock = fd
        self.record['run_lock'] = str(sentinel)

    def discover_qemu(self):
        if self.runner is None:
            return
        expected = self.pins.held[str(QEMU)][2]
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():
                continue
            who = identity(int(entry.name))
            if who is None or who.state == 'Z' or (who.exe_device, who.exe_inode) != (expected.st_dev, expected.st_ino):
                continue
            if not descendant(who.pid, self.runner.who):
                continue
            if not exact_owned_disk(who.argv):
                raise GuardError('Owned runner spawned QEMU with a foreign/unexpected disk; not eligible for wrapper signalling')
            raw = RUN / 'windows-uefi.raw'
            actual = raw.stat(follow_symlinks=False)
            source = self.pins.held[str(SOURCE_RUN / 'windows-uefi.raw')][2]
            if (not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) == (source.st_dev, source.st_ino)
                    or not 0 < actual.st_size <= 2 * 1024 ** 3):
                raise GuardError('Actual QEMU fresh raw path is a symlink, hardlink to source or invalid extent')
            found = capture_process(who.pid, 'qemu')
            if found is None:
                continue
            if not who.matches(found.who):
                os.close(found.pidfd)
                raise GuardError('QEMU identity/ancestry changed during capture')
            if self.qemu is not None:
                os.close(found.pidfd)
                if not self.qemu.who.matches(who):
                    raise GuardError('More than one actual owned QEMU identity')
            else:
                self.qemu = found
                self.record['qemu'] = asdict(found.who)
                self.record['native_vm_spawned'] = True
                self.record['qemu_observed_at'] = time.monotonic()
            validate_qemu_argv(who.argv)
            opened = []
            for fd in (Path('/proc') / str(who.pid) / 'fd').iterdir():
                try:
                    info = fd.stat()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if (info.st_dev, info.st_ino) == (source.st_dev, source.st_ino):
                    raise GuardError('Actual QEMU holds the immutable source disk inode')
                if (info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino):
                    opened.append(fd.name)
            if not opened:
                if time.monotonic() - self.record['qemu_observed_at'] > 10:
                    raise GuardError('Actual QEMU never opened the current fresh raw disk inode')
                self.record['qemu_awaiting_owned_raw_fd'] = True
                return                 # startup window: no GUI forwarding before actual fd proof
            if actual.st_blocks * 512 > self.proposal['guards']['source_allocated_bytes'] + self.proposal['guards']['dirty_allowance_bytes']:
                raise GuardError('Fresh raw disk exceeded the frozen allocation allowance')
            self.record['actual_owned_raw'] = {'path': str(raw), 'device': actual.st_dev, 'inode': actual.st_ino,
                'bytes': actual.st_size, 'allocated_bytes': actual.st_blocks * 512, 'verified_qemu_fds': opened}
            self.record['qemu_awaiting_owned_raw_fd'] = False
            self.record['actual_qemu_argv_verified'] = True

    def controls(self):
        if self.qemu is None or not self.record.get('actual_qemu_argv_verified'):
            return
        who = identity(self.qemu.who.pid)
        if not self.qemu.who.matches(who) or who.state == 'Z':
            return
        validate_qemu_argv(who.argv)
        prior, prior_sha = actual_control_receipt(RUN)
        if prior and prior.get('sequence') == self.sent_sequence and self.sent_sequence > self.last_sequence:
            if not prior.get('status', '').startswith('sent;'):
                raise GuardError('Actual native GUI action failed')
            self.last_sequence = self.sent_sequence
            self.last_actual_receipt_sha = prior_sha
            if self.last_sequence == 3:
                self.launch_receipt_time = time.monotonic()
            self.record['controls'].append({'phase': 'actual-receipt', 'receipt': prior, 'receipt_sha256': prior_sha})
        sequence = self.last_sequence + 1
        request_path = self.output / 'requests' / f'{sequence:04d}.json'
        if sequence > 5 or self.sent_sequence != self.last_sequence or not request_path.exists():
            return
        incoming = json.loads(request_path.read_text())
        if (incoming.get('sequence') != sequence or incoming.get('visual_review_explicit') is not True
                or incoming.get('proposal_sha256') != self.record['proposal_sha256'] or incoming.get('wrapper_start') != self.wrapper.start):
            raise GuardError('GUI inbox request has foreign wrapper/proposal identity')
        if sequence > 1 and (prior_sha != self.last_actual_receipt_sha
                or incoming.get('prior_receipt_sequence') != sequence - 1
                or incoming.get('prior_receipt_sha256') != prior_sha):
            raise GuardError('GUI inbox request is not linked to the same actual prior receipt')
        screenshot = verified_screenshot(incoming['reviewed_screenshot'])
        evidence = verified_capture_evidence(screenshot, self.proposal)
        if evidence['screenshot_sha256'] != incoming.get('reviewed_screenshot_sha256'):
            raise GuardError('Reviewed screenshot changed')
        if evidence['capture_number'] <= self.last_reviewed_capture_number:
            raise GuardError('Reviewed capture is stale relative to the prior forwarded review')
        if sequence > 1:
            verified_capture_evidence(Path(prior.get('screenshot', '')), self.proposal)
        age = None if self.launch_receipt_time is None else time.monotonic() - self.launch_receipt_time
        request = validate_control(sequence, self.proposal, prior, screenshot, age)
        atomic_json(RUN / 'gui-control.json', request)
        self.sent_sequence = sequence
        self.last_reviewed_capture_number = evidence['capture_number']
        self.record['controls'].append({'phase': 'forwarded', 'request': request, 'visual_review': incoming,
                                        'actual_capture_evidence': evidence})

    def stop(self):
        # FAIL was persisted before entering this method. Do not kill groups,
        # helpers, unverified QEMU commands or numeric PIDs after an exit race.
        if self.runner is None and self.runner_candidate is not None:
            me = os.stat(sys.executable)
            self.runner = verified_spawn_for_stop(self.runner_candidate, self.wrapper, EXPECTED_ARGV,
                                                  (me.st_dev, me.st_ino))
            if self.runner:
                self.record['runner_verified_during_failure_cleanup'] = asdict(self.runner.who)
            else:
                self.record['stop_results'].append({'kind': 'runner-candidate',
                    'outcome': 'not-signalled: exact post-exec identity could not be verified'})
        for process in (self.qemu, self.runner):
            if process is None:
                continue
            try:
                outcome = signal_owned(process, signal.SIGTERM)
                self.record['stop_results'].append({'kind': process.kind, 'signal': 'TERM', 'outcome': outcome})
                if outcome == 'sent' and not select.select([process.pidfd], [], [], 5)[0]:
                    outcome = signal_owned(process, signal.SIGKILL)
                    self.record['stop_results'].append({'kind': process.kind, 'signal': 'KILL', 'outcome': outcome})
            except Exception as error:
                self.record['stop_results'].append({'kind': process.kind, 'error': str(error)})

    def run(self):
        try:
            errors = self.pins.open()
            self.record['pin_open_errors'] = errors
            self.record['source_before'] = self.pins.snapshot()
            self.save()
            if errors or len(self.pins.held) != len(self.pins.values) or not all(p['matches'] for p in self.record['source_before'].values()):
                raise GuardError('Immutable pinned source drift or lock failure')
            if RUN.exists() or RUN.is_symlink():
                raise GuardError('Selected fresh run already exists')
            self.check(before=True)
            self.record['runner_cli_capability'] = validate_runner_capability(self.proposal, self.pins)
            self.save()
            if not self.execute:
                self.record['status'] = 'VALIDATION_ONLY_NOT_EXECUTED'
                return 0
            self.own_run_lock()
            self.check(before=True)
            self.record['runner_cli_capability_before_exec'] = validate_runner_capability(self.proposal, self.pins)
            self.save()
            self.log = (self.output / 'runner-output.log').open('xb')
            environment = os.environ.copy()
            for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'):
                environment.pop(key, None)
            environment.update(PYTHONDONTWRITEBYTECODE='1', TMPDIR='/tmp')
            self.child = subprocess.Popen(EXPECTED_ARGV, executable=sys.executable, cwd=BOOT, env=environment,
                stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
            self.runner_candidate = capture_spawn_candidate(self.child)
            if self.runner_candidate is None:
                raise GuardError('Runner exited before provisional Popen/pidfd capture')
            self.record['runner_candidate'] = asdict(self.runner_candidate.who)
            self.record['runner_identity_samples'] = []
            self.save()
            me = os.stat(sys.executable)
            self.runner = await_spawn_identity(self.runner_candidate, self.wrapper, EXPECTED_ARGV,
                (me.st_dev, me.st_ino), self.record['runner_identity_samples'],
                lambda who: self.check(source_owner=who), child_poll=self.child.poll)
            self.record['runner'] = asdict(self.runner.who)
            self.record['status'] = 'RUNNING_REQUIRES_ROOT_VISUAL_CONTROL'
            self.save()
            while self.child.poll() is None:
                if time.monotonic() - self.started > WALL:
                    raise GuardError(f'Frozen {WALL}-second wall bound expired')
                self.check()
                if not self.runner.who.matches(identity(self.runner.who.pid)):
                    if self.child.poll() is not None:
                        break
                    raise GuardError('Owned runner identity changed')
                self.discover_qemu()
                self.controls()
                self.save()
                time.sleep(POLL)
            self.record['runner_exit_code'] = self.child.wait(timeout=5)
            if self.qemu is None:
                raise GuardError('No verified actual QEMU was observed')
            current = identity(self.qemu.who.pid)
            if current is not None and current.state != 'Z' and self.qemu.who.matches(current):
                raise GuardError('Runner returned while its verified QEMU is still live')
            result = json.loads((RUN / 'result.json').read_text())
            self.record['runner_result'] = {'path': str(RUN / 'result.json'), 'sha256': digest_file(RUN / 'result.json'),
                'status': result.get('status'), 'qemu_exit_code': result.get('qemu_exit_code')}
            if self.child.returncode != 0 or result.get('qemu_exit_code') != 0 or not result.get('originals_unchanged') or not result.get('prepared_source_unchanged') or not result.get('manual_finish_requested'):
                raise GuardError('Actual runner/QEMU finish or unchanged-source result failed')
            if result.get('command') != list(self.qemu.who.argv):
                raise GuardError('Actual result QEMU argv does not match captured process identity')
            if self.sent_sequence != 5:
                raise GuardError('Normal finish did not consume the five proposal GUI controls')
            self.record['status'] = 'GUARDED_RUN_COMPLETE_NATIVE_EVIDENCE_REVIEW_REQUIRED'
            self.record['native_executed'] = True
            self.record['owned_disk_sha256'] = digest_file(RUN / 'windows-uefi.raw')
            if result.get('owned_disk_sha256_after_run') != self.record['owned_disk_sha256']:
                raise GuardError('Stopped disk differs from actual runner after-run hash')
            files = result.get('guest_files', {})
            if (files.get('manifest_sha256') != MANIFEST_SHA or not files.get('immutable_sources_unchanged')
                    or files.get('output_baseline') != 'all absent before private injection'):
                raise GuardError('Actual runner did not establish frozen guest inputs and absent output baseline')
            readbacks = {entry.get('guest'): entry for entry in files.get('readback', [])}
            self.record['stopped_disk_log_readbacks'] = []
            for name in ('W64NEG.LOG', 'W64OBS.LOG', 'W64OUT.LOG'):
                path = RUN / ('guest-output-' + name)
                evidence = readbacks.get('C:\\VXDLAB\\' + name, {})
                if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 65536:
                    raise GuardError('Missing or unbounded actual stopped-disk log readback: ' + name)
                prefix = ('CASE ' + NONCE + ' 0x00000000\r\n').encode('ascii')
                with path.open('rb') as stream:
                    if stream.read(len(prefix)) != prefix:
                        raise GuardError('Actual stopped-disk log nonce differs: ' + name)
                hashed = digest_file(path)
                if (evidence.get('status') != 'captured' or evidence.get('freshness') != 'new-in-owned-run'
                        or evidence.get('path') != str(path) or evidence.get('sha256') != hashed
                        or evidence.get('bytes') != path.stat().st_size):
                    raise GuardError('Actual stopped-disk readback provenance differs: ' + name)
                self.record['stopped_disk_log_readbacks'].append({'path': str(path), 'sha256': digest_file(path),
                    'bytes': path.stat().st_size, 'fresh_nonce_prefix_verified': True,
                    'full_negative_semantics_verified': False})
            source_receipt = json.loads((SOURCE_RUN / 'result.json').read_text())
            partition = source_receipt['partition']
            with (RUN / 'windows-uefi.raw').open('rb') as stream:
                mbr = stream.read(512)
                stream.seek(partition['start_lba'] * 512)
                boot = stream.read(512)
            self.record['legacy_boot_sectors'] = {'mbr_sha256': hashlib.sha256(mbr).hexdigest(),
                'boot_sector_sha256': hashlib.sha256(boot).hexdigest()}
            if any(self.record['legacy_boot_sectors'][name] != partition[name] for name in ('mbr_sha256', 'boot_sector_sha256')):
                raise GuardError('Actual original legacy boot sectors changed')
            self.check()
            return 0
        except Exception as error:
            self.record['status'] = 'FAIL'
            self.record['error'] = str(error)
            self.save()                 # observable FAIL precedes every signal
            self.stop()
            return 1
        finally:
            self.record['source_after'] = self.pins.snapshot()
            if not all(p['matches'] for p in self.record['source_after'].values()) or len(self.pins.held) != len(self.pins.values):
                self.record['status'] = 'FAIL'
                self.record['after_pin_failure'] = True
            if RUN.is_dir():
                self.record['owned_disk_present'] = (RUN / 'windows-uefi.raw').is_file()
            self.save()
            self.pins.close()
            if self.log:
                self.log.close()
            closed = set()
            for process in (self.runner, self.qemu, self.runner_candidate):
                if process and process.pidfd not in closed:
                    os.close(process.pidfd)
                    closed.add(process.pidfd)
            if self.runlock is not None:
                os.close(self.runlock)
            if self.record['status'] == 'FAIL':
                return 1


def submit_control(output, sequence, screenshot):
    record = json.loads((output / 'guard-receipt.json').read_text())
    if record.get('status') != 'RUNNING_REQUIRES_ROOT_VISUAL_CONTROL' or not record.get('actual_qemu_argv_verified'):
        raise GuardError('Verified running owned QEMU is required before a control request')
    wrapper = Identity(**(record['wrapper'] | {'argv': tuple(record['wrapper']['argv'])}))
    if not wrapper.matches(identity(wrapper.pid)):
        raise GuardError('Guard wrapper is no longer the same live process')
    if sequence not in (1, 2, 3, 4, 5):
        raise GuardError('Invalid fixed control/reviewed screenshot')
    screenshot = verified_screenshot(screenshot)
    request = {'sequence': sequence, 'proposal_sha256': record['proposal_sha256'], 'wrapper_start': wrapper.start,
               'reviewed_screenshot': str(screenshot), 'reviewed_screenshot_sha256': digest_file(screenshot),
               'visual_review_explicit': True}
    if sequence > 1:
        prior, prior_sha = actual_control_receipt(RUN)
        if (not prior or type(prior.get('sequence')) is not int or prior['sequence'] != sequence - 1
                or not prior.get('status', '').startswith('sent;')):
            raise GuardError('An actual successful prior receipt is required before queuing this control')
        request.update(prior_receipt_sequence=prior['sequence'], prior_receipt_sha256=prior_sha)
    atomic_json(output / 'requests' / f'{sequence:04d}.json', request, new=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proposal', type=Path, default=DEFAULT_PROPOSAL)
    parser.add_argument('--proposal-sha', default=DEFAULT_PROPOSAL_SHA)
    parser.add_argument('--output', type=Path, required=True, help='fresh PRIVATE receipt directory, or active receipt directory for --control')
    parser.add_argument('--execute', action='store_true', help='reviewed root action: start the exact native disposable runner')
    parser.add_argument('--control', type=int, choices=(1, 2, 3, 4, 5))
    parser.add_argument('--reviewed-screenshot', type=Path)
    args = parser.parse_args()
    supplied = args.output.absolute()
    parent = supplied.parent.resolve(strict=True)
    output = parent / supplied.name
    if not parent.is_relative_to((ROOT / 'build/modern-apps').resolve(strict=True)) or output.is_symlink():
        parser.error('Receipt output must be below PRIVATE build/modern-apps')
    if args.control:
        if args.execute or args.reviewed_screenshot is None:
            parser.error('--control requires explicit --reviewed-screenshot and no --execute')
        submit_control(output, args.control, args.reviewed_screenshot.absolute())
        return 0
    output.mkdir(mode=0o700)       # refuse existing receipt directory, including old run records
    (output / 'requests').mkdir(mode=0o700)
    try:
        if not re.fullmatch(r'[0-9a-f]{64}', args.proposal_sha) or digest_file(args.proposal) != args.proposal_sha:
            raise GuardError('Proposal SHA differs from explicit reviewed pin')
        proposal = validate_proposal(json.loads(args.proposal.read_text()))
        return GuardedRun(proposal, args.proposal.absolute(), args.proposal_sha, output, args.execute).run()
    except Exception as error:
        atomic_json(output / 'guard-receipt.json', {'schema': 'win98modern.native-w64-guarded-run.v1', 'status': 'FAIL',
            'error': str(error), 'native_executed': False, 'application_executed': False, 'source_before': {}, 'source_after': {}})
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
