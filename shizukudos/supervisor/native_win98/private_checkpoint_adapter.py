# SPDX-License-Identifier: GPL-2.0-only
"""Already-owned runtime adapter; no VM launcher, cleanup, CLI or controller wiring."""
from dataclasses import dataclass
import contextlib
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import select
import socket
import stat
import struct
import subprocess
import tempfile
import time

MAX_PROOF_BYTES = 1 << 20
MAX_PROC_BYTES = 65536
ROLES = {'controller', 'qemu', 'owned_qmp', 'checkpoint_helper', 'checkpoint_adapter'}
STRUCTS = {'shz_info_t': 'Info', 'shz_blob_t': 'Blob',
           'shz_domain_info_t': 'DomainInfo', 'shz_vmcs_snapshot_t': 'Snapshot'}


def _bound(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('bounded exact integer required')
    return value


def _read_proc(path, maximum):
    with Path(path).open('rb') as stream: payload = stream.read(maximum + 1)
    if len(payload) > maximum: raise RuntimeError('owned process observation exceeds its byte bound')
    return payload


def parse_flatview(text, base_memory):
    """Parse complete QEMU 10.1 `info mtree -f`, with inclusive-end rows."""
    _bound(base_memory, 1 << 20, 1 << 40)
    if not isinstance(text, str) or not 0 < len(text.encode()) <= MAX_PROOF_BYTES:
        raise ValueError('bounded full FlatView response required')
    text = text.replace('\r\n', '\n')
    if '\r' in text or not text.endswith('\n\n') or len(text.splitlines()) > 8192:
        raise ValueError('truncated or noncanonical FlatView response')
    sections, section = [], None
    for line in text.splitlines():
        if re.fullmatch(r'FlatView #[0-9]+', line):
            section = {'spaces': [], 'root': None, 'rows': []}
            sections.append(section)
            if len(sections) > 128: raise ValueError('FlatView count exceeded')
        elif not line:
            continue
        elif section is None:
            raise ValueError('FlatView header required')
        elif line.startswith(' AS '):
            match = re.fullmatch(r' AS "([^"\n]{1,128})", root: ([^,\n]{1,128})(?:, alias [^\n]{1,128})?', line)
            if not match or section['root'] is not None:
                raise ValueError('FlatView address-space headers malformed')
            section['spaces'].append(match.groups())
        elif line.startswith(' Root memory region: '):
            if section['root'] is not None or not section['spaces']:
                raise ValueError('unique FlatView root required')
            section['root'] = line[len(' Root memory region: '):]
        else:
            section['rows'].append(line)
    selected = [item for item in sections if ('memory', 'system') in item['spaces']]
    if len(selected) != 1 or selected[0]['spaces'].count(('memory', 'system')) != 1 or selected[0]['root'] != 'system':
        raise ValueError('exact unique system memory FlatView required')
    rows = selected[0]['rows']
    if not 1 <= len(rows) <= 4096: raise ValueError('bounded complete system FlatView rows required')
    entries, ranges, backing = [], [], []
    row_pattern = (r'  ([0-9a-f]{16})-([0-9a-f]{16}) \(prio (-?[0-9]+), '
                   r'((?:nv-)?(?:ram|rom|ramd|romd|i/o))\): (.{1,256}?)'
                   r'(?: @([0-9a-f]{16}))?((?: (?:kvm|tcg))*)')
    for row in rows:
        match = re.fullmatch(row_pattern, row)
        if not match: raise ValueError('unrecognized selected FlatView row')
        start, inclusive, priority, kind, name, offset, accelerator = match.groups()
        start, end, priority, offset = int(start, 16), int(inclusive, 16) + 1, int(priority), int(offset or '0', 16)
        if end <= start or end > 1 << 64 or (entries and start < entries[-1]['end']) or abs(priority) > 1 << 31:
            raise ValueError('FlatView ranges overlap, overflow or are unordered')
        entries.append({'start': start, 'end': end, 'priority': priority, 'kind': kind,
                        'name': name, 'offset': offset, 'accelerators': accelerator.split()})
        if kind == 'ram' and name == 'pc.ram':
            if start % 4096 or end % 4096 or offset % 4096 or offset + end - start > base_memory:
                raise ValueError('main RAM physical/backing extent invalid')
            backing.append([offset, offset + end - start])
            if ranges and ranges[-1][1] == start: ranges[-1][1] = end
            else: ranges.append([start, end])
    backing.sort()
    if not ranges or len(ranges) > 128 or any(backing[index][0] < backing[index - 1][1] for index in range(1, len(backing))):
        raise ValueError('bounded nonaliased writable main RAM required')
    return {'ranges': ranges, 'entries': entries, 'main_backing_ranges': backing}


def _sources(checkpoint, sources):
    if not isinstance(sources, tuple) or not 1 <= len(sources) <= checkpoint.MAX_SOURCES:
        raise ValueError('bounded held source tuple required')
    result = {}
    for source in sources:
        if (not isinstance(source, checkpoint.ReadLease) or not isinstance(source.name, str) or
                not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', source.name) or source.name in result or
                not re.fullmatch(r'[0-9a-f]{64}', source.sha256) or
                checkpoint._canonical(source.path) != source.path):
            raise ValueError('unique canonical exact leased source references required')
        _bound(source.bytes, 1, checkpoint.MAX_SOURCE_BYTES)
        _bound(source.fd, 0, 1 << 31)
        checkpoint._lease_check(source)
        result[source.name] = source
    return result


def _hash_source(checkpoint, source, guard):
    checkpoint._lease_check(source)
    actual = checkpoint._hash_fd(source.fd, source.bytes, guard)
    if actual != source.sha256: raise RuntimeError('held source SHA differs')
    checkpoint._lease_check(source)
    return actual


def _json_source(checkpoint, source, guard):
    _bound(source.bytes, 1, MAX_PROOF_BYTES)
    _hash_source(checkpoint, source, guard)
    payload = os.pread(source.fd, source.bytes + 1, 0)
    if len(payload) != source.bytes or hashlib.sha256(payload).hexdigest() != source.sha256:
        raise RuntimeError('leased proof readback differs')

    def pairs(items):
        result = {}
        for name, value in items:
            if name in result: raise ValueError('duplicate proof key')
            result[name] = value
        return result

    result = json.loads(payload, object_pairs_hook=pairs)
    if not isinstance(result, dict): raise ValueError('proof object required')
    guard()
    return result


def _publish(checkpoint, path, record, guard):
    """Fresh private proof with exact-fd publication; caller leases the result."""
    path = checkpoint._canonical(path)
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o777 != 0o700:
        raise ValueError('owned private proof parent required')
    payload = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
    if len(payload) > MAX_PROOF_BYTES: raise ValueError('proof output bound exceeded')
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directory_identity = (parent.st_dev, parent.st_ino)
    partial, fd, identity, linked = '.' + path.name + '.partial', None, None, False
    owner_guard = guard

    def directory_check():
        current = os.stat(path.parent, follow_symlinks=False)
        held = os.fstat(directory)
        if ((current.st_dev, current.st_ino) != directory_identity or
                (held.st_dev, held.st_ino) != directory_identity or
                current.st_uid != os.getuid() or current.st_mode & 0o777 != 0o700):
            raise RuntimeError('private proof parent identity/privacy changed')

    def guard():
        directory_check(); owner_guard(); directory_check()

    def invalidate(current_directory):
        if not linked: return
        try:
            current = os.stat(path.name, dir_fd=current_directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == identity:
                os.unlink(path.name, dir_fd=current_directory); os.fsync(current_directory)
        except OSError: pass

    try:
        guard()
        fd = checkpoint._create(directory, partial)
        checkpoint._write_all(fd, payload); os.fsync(fd)
        written = checkpoint._stable(os.fstat(fd))
        if os.pread(fd, len(payload) + 1, 0) != payload: raise RuntimeError('proof readback differs')
        consumed, fd = fd, None; os.close(consumed)
        fd = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        checkpoint._pinned_file(fd, directory, partial, written)
        with checkpoint._read_lease(fd) as leased:
            guard(); leased(); checkpoint._pinned_file(fd, directory, partial, written)
            if os.pread(fd, len(payload) + 1, 0) != payload: raise RuntimeError('leased proof serialization differs')
            current = os.fstat(fd); identity = (current.st_dev, current.st_ino)
            checkpoint._link_fd(fd, directory, path.name); linked = True
            os.unlink(partial, dir_fd=directory)
            published = checkpoint._stable(os.fstat(fd))
            guard(); leased(); checkpoint._pinned_file(fd, directory, path.name, published)
            os.fsync(directory)
            guard(); leased(); checkpoint._pinned_file(fd, directory, path.name, published)
            if os.pread(fd, len(payload) + 1, 0) != payload: raise RuntimeError('canonical proof serialization differs')
        consumed, fd = fd, None; os.close(consumed)
    except BaseException:
        invalidate(directory)
        raise
    finally:
        failure = None
        for current in (fd, directory):
            if current is not None:
                try: os.close(current)
                except BaseException as error: failure = failure or error
        if failure is not None:
            cleanup = None
            try:
                cleanup = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                item = os.fstat(cleanup)
                if (item.st_dev, item.st_ino) == directory_identity: invalidate(cleanup)
            except OSError: pass
            finally:
                if cleanup is not None:
                    try: os.close(cleanup)
                    except OSError: pass
            raise failure
    return identity


def read_budget(checkpoint, source):
    record = _json_source(checkpoint, source, lambda: checkpoint._lease_check(source))
    names = {'schema', 'private', 'approved', 'scope', 'approved_lane', 'disk_bytes',
             'capture_bytes', 'total_bytes', 'retained_free_bytes', 'timeout_seconds'}
    if (set(record) != names or record['schema'] != 'shizuku.private-checkpoint-budget.v1' or
            record['private'] is not True or record['approved'] is not True or
            record['scope'] != 'private_ram_checkpoint_only'):
        raise ValueError('explicit owner-approved private checkpoint budget required')
    lane = record['approved_lane']
    if not isinstance(lane, str) or not lane.startswith('/') or '\x00' in lane:
        raise ValueError('absolute approved lane required')
    lane = Path(lane)
    # Syntax only: budget validation must not access NAS. Real producer rechecks it.
    if checkpoint.NAS_WORKSPACE not in lane.parents or '..' in lane.parts:
        raise ValueError('explicit private NAS lane required')
    minimum = checkpoint.CHUNK_BYTES + checkpoint.MAX_MAP_BYTES + checkpoint.MAX_RECEIPT_BYTES + 2 * checkpoint.INFO_BYTES
    _bound(record['disk_bytes'], checkpoint.DISK_BYTES, checkpoint.DISK_BYTES)
    _bound(record['capture_bytes'], minimum, checkpoint.MAX_CAPTURE_BYTES)
    _bound(record['total_bytes'], record['disk_bytes'] + record['capture_bytes'], record['disk_bytes'] + record['capture_bytes'])
    _bound(record['retained_free_bytes'], 17 << 30, 1 << 50)
    _bound(record['timeout_seconds'], 1, 900)
    return checkpoint.Reservation(lane, source.name, record['disk_bytes'], record['capture_bytes'],
                                  record['total_bytes'], record['retained_free_bytes'], record['timeout_seconds'])


def _layout(info):
    layouts = {}
    for c_name, python_name in STRUCTS.items():
        structure = getattr(info, python_name)
        if not isinstance(structure, type) or not issubclass(structure, ctypes.Structure):
            raise ValueError('actual SHZ ctypes structures required')
        fields = {}
        for name, kind in structure._fields_:
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) or name in fields:
                raise ValueError('exact bounded layout fields required')
            fields[name] = {'offset': getattr(structure, name).offset, 'bytes': ctypes.sizeof(kind)}
        if not 1 <= len(fields) <= 128: raise ValueError('bounded layout field count required')
        layouts[c_name] = {'size': ctypes.sizeof(structure), 'fields': fields}
    if ctypes.sizeof(info.Info) > 8192: raise ValueError('SHZ info exceeds actual capture')
    if (dict(info.Info._fields_)['domains']._type_ is not info.DomainInfo or
            dict(info.Info._fields_)['blobs']._type_ is not info.Blob or
            dict(info.Info._fields_)['first_exit'] is not info.Snapshot or
            dict(info.Info._fields_)['last_exit'] is not info.Snapshot):
        raise ValueError('nested SHZ structure and array stride types differ')
    return layouts


@dataclass(frozen=True)
class _ProofArtifact:
    path: Path
    fd: int
    payload: bytes
    sha256: str
    check: object


@contextlib.contextmanager
def _proof_artifact(checkpoint, path, expected=None, payload=None, mode=0o600):
    """Hold one exact private artifact snapshot against path/content substitution."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        item = os.fstat(fd)
        expected = checkpoint._stable(item) if expected is None else expected
        _bound(item.st_size, 0, MAX_PROOF_BYTES)
        with checkpoint._read_lease(fd) as leased:
            snapshot = os.pread(fd, item.st_size + 1, 0)
            if len(snapshot) != item.st_size or (payload is not None and snapshot != payload):
                raise RuntimeError('generated artifact snapshot differs')

            def check():
                leased()
                current, named = os.fstat(fd), os.stat(path, follow_symlinks=False)
                if (checkpoint._stable(current) != expected or checkpoint._stable(named) != expected or
                        not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or
                        current.st_mode & 0o777 != mode or current.st_nlink != 1 or
                        os.pread(fd, len(snapshot) + 1, 0) != snapshot):
                    raise RuntimeError('generated artifact inode/extent/content/privacy changed')
                leased()

            check()
            yield _ProofArtifact(path, fd, snapshot, hashlib.sha256(snapshot).hexdigest(), check)
            check()
    finally:
        os.close(fd)


def _wait_layout_child(child):
    try:
        return child.wait(timeout=10)
    except BaseException as original:
        failures = []
        try:
            try: os.killpg(child.pid, 9)
            except ProcessLookupError: pass
            except BaseException as error: failures.append(error)
        finally:
            try: child.wait(timeout=3)
            except BaseException as error: failures.append(error)
        for error in failures: original.add_note('owned layout child cleanup: %r' % error)
        raise


def _invalidate_proof(path, parent_identity, identity):
    if identity is None: return
    directory = None
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        item = os.fstat(directory)
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (item.st_dev, item.st_ino) == parent_identity and (named.st_dev, named.st_ino) == identity:
            os.unlink(path.name, dir_fd=directory); os.fsync(directory)
    except OSError: pass
    finally:
        if directory is not None:
            try: os.close(directory)
            except OSError: pass


def prove_layout(checkpoint, info, header, parser, compiler, out):
    sources = _sources(checkpoint, (header, parser, compiler))
    if Path(info.__file__).resolve() != parser.path: raise ValueError('loaded parser source differs')
    expected = _layout(info)

    artifacts = []
    def guard():
        for artifact in artifacts: artifact.check()
        for source in sources.values(): checkpoint._lease_check(source)
        for artifact in artifacts: artifact.check()

    before = {name: _hash_source(checkpoint, source, guard) for name, source in sources.items()}
    if any(character in str(header.path) for character in ('"', '\n', '\r')):
        raise ValueError('header path cannot be interpolated into C')
    program = ['#include <stddef.h>', '#include <stdio.h>', '#include "%s"' % header.path, 'int main(void){']
    for c_name, layout in expected.items():
        program.append('printf("size %s %%zu\\n",sizeof(%s));' % (c_name, c_name))
        for field in layout['fields']:
            program.append('printf("field %s %s %%zu %%zu\\n",offsetof(%s,%s),sizeof(((%s*)0)->%s));' %
                           (c_name, field, c_name, field, c_name, field))
    program.append('return 0;}')
    payload = ('\n'.join(program) + '\n').encode()
    output = checkpoint._canonical(out)
    parent = output.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o777 != 0o700:
        raise ValueError('owned private layout proof parent required')
    parent_identity = (parent.st_dev, parent.st_ino)
    source_guard = guard

    def parent_check():
        item = output.parent.stat()
        if (not stat.S_ISDIR(item.st_mode) or (item.st_dev, item.st_ino) != parent_identity or
                item.st_uid != os.getuid() or item.st_mode & 0o777 != 0o700):
            raise RuntimeError('layout proof parent identity/privacy changed')

    def guard():
        parent_check(); source_guard(); parent_check()

    commands, actual = [], {}

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_PROOF_BYTES, MAX_PROOF_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))

    published = None
    try:
        guard()
        with tempfile.TemporaryDirectory(prefix='layout-', dir=output.parent) as temporary, contextlib.ExitStack() as held:
            directory = Path(temporary); source_path, executable = directory / 'layout.c', directory / 'layout'
            with source_path.open('xb') as generated:
                source_path.chmod(0o600); generated.write(payload); generated.flush(); os.fsync(generated.fileno())
            generated = held.enter_context(_proof_artifact(checkpoint, source_path, payload=payload))
            artifacts.append(generated)
            environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TMPDIR': str(directory)}
            binary = None
            for label in ('compile', 'probe'):
                if label == 'compile':
                    command = [str(compiler.path), '-x', 'c', '/proc/self/fd/%d' % generated.fd, '-o', str(executable)]
                    passed, execution = (generated.fd,), None
                else:
                    command = [str(executable)]
                    passed, execution = (binary.fd,), '/proc/self/fd/%d' % binary.fd
                guard()
                stdout, stderr = directory / (label + '.stdout'), directory / (label + '.stderr')
                with stdout.open('x+b') as out_stream, stderr.open('x+b') as err_stream:
                    stdout.chmod(0o600); stderr.chmod(0o600)
                    child = subprocess.Popen(command, executable=execution, pass_fds=passed,
                                             stdin=subprocess.DEVNULL, stdout=out_stream, stderr=err_stream,
                                             env=environment, start_new_session=True, preexec_fn=limits)
                    code = _wait_layout_child(child)
                    snapshots = []
                    for stream in (out_stream, err_stream):
                        item = os.fstat(stream.fileno()); _bound(item.st_size, 0, MAX_PROOF_BYTES)
                        snapshots.append((checkpoint._stable(item), os.pread(stream.fileno(), item.st_size + 1, 0)))
                outputs = []
                for path, (identity, snapshot) in zip((stdout, stderr), snapshots):
                    artifact = held.enter_context(_proof_artifact(checkpoint, path, identity, snapshot))
                    artifacts.append(artifact); outputs.append(artifact)
                if code: raise RuntimeError('bounded actual C layout command failed')
                if label == 'compile':
                    executable.chmod(0o700)
                    binary = held.enter_context(_proof_artifact(checkpoint, executable, mode=0o700))
                    artifacts.append(binary)
                guard()
                commands.append({'argv': command, 'exit_code': code,
                                 'stdout_sha256': outputs[0].sha256, 'stderr_sha256': outputs[1].sha256})
                if label == 'probe':
                    for line in outputs[0].payload.decode('ascii').splitlines():
                        parts = line.split()
                        if len(parts) == 3 and parts[0] == 'size' and parts[1] in expected and parts[1] not in actual:
                            actual[parts[1]] = {'size': int(parts[2]), 'fields': {}}
                        elif len(parts) == 5 and parts[0] == 'field' and parts[1] in actual and parts[2] not in actual[parts[1]]['fields']:
                            actual[parts[1]]['fields'][parts[2]] = {'offset': int(parts[3]), 'bytes': int(parts[4])}
                        else: raise RuntimeError('C layout output malformed or duplicated')
            if actual != expected: raise RuntimeError('actual C/Python nested layout differs')
            after = {name: _hash_source(checkpoint, source, guard) for name, source in sources.items()}
            if before != after: raise RuntimeError('layout source before/after differs')
            record = {'schema': 'shizuku.checkpoint-layout.v1', 'status': 'PASS_ACTUAL_C_PYTHON_LAYOUT_ONLY',
                      'layouts': actual, 'info_bytes': 8192, 'header_sha256': header.sha256,
                      'parser_sha256': parser.sha256, 'compiler_sha256': compiler.sha256,
                      'compiler_source_ref': compiler.name, 'source_before_after_match': True,
                      'source_before': before, 'source_after': after, 'commands': commands,
                      'probe_source_sha256': generated.sha256, 'probe_binary_sha256': binary.sha256,
                      'complete_toolchain_closure_verified': False, 'Windows98_boot_verified': False}
            published = _publish(checkpoint, output, record, guard)
    except BaseException:
        _invalidate_proof(output, parent_identity, published)
        raise
    return record


def _layout_receipt(record, info, header, parser, sources):
    names = {'schema', 'status', 'layouts', 'info_bytes', 'header_sha256', 'parser_sha256',
             'compiler_sha256', 'compiler_source_ref', 'source_before_after_match', 'source_before',
             'source_after', 'commands', 'probe_source_sha256', 'probe_binary_sha256',
             'complete_toolchain_closure_verified', 'Windows98_boot_verified'}
    compiler = sources.get(record.get('compiler_source_ref'))
    if compiler is None: raise RuntimeError('held layout compiler reference required')
    expected_pins = {header.name: header.sha256, parser.name: parser.sha256, compiler.name: compiler.sha256}
    commands = record.get('commands')
    valid_commands = isinstance(commands, list) and len(commands) == 2
    if valid_commands:
        for command in commands:
            if (not isinstance(command, dict) or set(command) != {'argv', 'exit_code', 'stdout_sha256', 'stderr_sha256'} or
                    type(command.get('exit_code')) is not int or command['exit_code'] != 0 or
                    not isinstance(command.get('argv'), list) or
                    any(not isinstance(arg, str) or '\x00' in arg for arg in command['argv']) or
                    any(not isinstance(command.get(name), str) or not re.fullmatch(r'[0-9a-f]{64}', command[name])
                        for name in ('stdout_sha256', 'stderr_sha256'))):
                valid_commands = False; break
    if valid_commands:
        compile_argv, probe_argv = commands[0]['argv'], commands[1]['argv']
        valid_commands = (len(compile_argv) == 6 and len(probe_argv) == 1 and compile_argv[0] == str(compiler.path) and
                          compile_argv[1:3] == ['-x', 'c'] and re.fullmatch(r'/proc/self/fd/[0-9]+', compile_argv[3]) and
                          compile_argv[4] == '-o' and compile_argv[5] == probe_argv[0])
    if (set(record) != names or record.get('schema') != 'shizuku.checkpoint-layout.v1' or
            record.get('status') != 'PASS_ACTUAL_C_PYTHON_LAYOUT_ONLY' or record.get('layouts') != _layout(info) or
            record.get('info_bytes') != 8192 or record.get('header_sha256') != header.sha256 or
            record.get('parser_sha256') != parser.sha256 or record.get('compiler_sha256') != compiler.sha256 or
            record.get('source_before_after_match') is not True or record.get('source_before') != expected_pins or
            record.get('source_after') != expected_pins or not valid_commands or
            record.get('complete_toolchain_closure_verified') is not False or record.get('Windows98_boot_verified') is not False or
            any(not isinstance(record.get(name), str) or not re.fullmatch(r'[0-9a-f]{64}', record[name])
                for name in ('probe_source_sha256', 'probe_binary_sha256'))):
        raise RuntimeError('exact leased actual nested C/Python layout proof required')


@dataclass(frozen=True)
class Binding:
    adapter: object
    reservation: object
    proof: dict


class OwnedRuntime:
    def __init__(self, process, pidfd, monitor, checkpoint, owned, sources, roles):
        if type(process) is not subprocess.Popen or type(monitor) is not owned.OwnedQMP:
            raise ValueError('caller actual Popen and exact owned QMP instance required')
        self.process, self.pidfd, self.monitor, self.checkpoint = process, pidfd, monitor, checkpoint
        self.sources = _sources(checkpoint, sources)
        if set(roles) != ROLES or any(name not in self.sources for name in roles.values()):
            raise ValueError('pinned runtime/controller/adapter source roles required')
        self.roles = dict(roles)
        for role, module in (('owned_qmp', owned), ('checkpoint_helper', checkpoint)):
            if Path(module.__file__).resolve() != self.sources[roles[role]].path: raise ValueError('loaded runtime source differs')
        if self.sources[roles['checkpoint_adapter']].path != Path(__file__).resolve(): raise ValueError('loaded adapter source differs')
        args = process.args
        if not isinstance(args, (tuple, list)) or not args or any(not isinstance(arg, str) or '\x00' in arg for arg in args):
            raise ValueError('exact shell-free owned argv required')
        self.argv = tuple(args)
        machines = [args[index + 1].split(',')[0] for index, arg in enumerate(args[:-1]) if arg in ('-machine', '-M')]
        if len(machines) != 1 or not (machines[0] == 'q35' or machines[0].startswith('pc-q35-')):
            raise ValueError('owned explicit Q35 argv required')
        self.socket = monitor.socket
        self.deadline = monitor.deadline
        if not isinstance(self.socket, socket.socket): raise ValueError('actual connected Unix QMP socket required')
        _bound(pidfd, 0, 1 << 31)
        self.pidfd_identity = (os.fstat(pidfd).st_dev, os.fstat(pidfd).st_ino)
        self.socket_identity = (os.fstat(self.socket.fileno()).st_dev, os.fstat(self.socket.fileno()).st_ino)
        self.owner = self._identity()
        self.baseline = None
        self.reservation = None
        self.bound_sources = None
        self.capture_bytes_requested = 0
        for source in self.sources.values(): _hash_source(checkpoint, source, self.assert_owned)

    def _identity(self):
        if self.process.poll() is not None or tuple(self.process.args) != self.argv:
            raise RuntimeError('owned Popen exited or argv changed')
        if (self.monitor.deadline != self.deadline or not math.isfinite(self.deadline) or time.monotonic() >= self.deadline or
                self.monitor.socket is not self.socket or self.socket.fileno() < 0):
            raise RuntimeError('owned QMP lifetime/socket deadline changed')
        if (os.fstat(self.pidfd).st_dev, os.fstat(self.pidfd).st_ino) != self.pidfd_identity or os.readlink('/proc/self/fd/%d' % self.pidfd) != 'anon_inode:[pidfd]':
            raise RuntimeError('held pidfd identity differs')
        poller = select.poll(); poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0): raise RuntimeError('owned pidfd process exited')
        fdinfo = _read_proc('/proc/self/fdinfo/%d' % self.pidfd, 8192)
        pids = re.findall(rb'^Pid:\s*([0-9]+)$', fdinfo, re.MULTILINE)
        if pids != [str(self.process.pid).encode()]: raise RuntimeError('pidfd does not identify this Popen child')
        if (os.fstat(self.socket.fileno()).st_dev, os.fstat(self.socket.fileno()).st_ino) != self.socket_identity:
            raise RuntimeError('QMP socket descriptor identity differs')
        peer, uid, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer != self.process.pid or uid != os.getuid(): raise RuntimeError('current QMP peer differs from owned child')
        proc = Path('/proc/%d' % self.process.pid)
        status = _read_proc(proc / 'stat', MAX_PROC_BYTES)
        cmdline = _read_proc(proc / 'cmdline', MAX_PROC_BYTES)
        if len(status) > MAX_PROC_BYTES or len(cmdline) > MAX_PROC_BYTES or not cmdline:
            raise RuntimeError('bounded current process identity required')
        fields = status[status.rfind(b')') + 2:].split()
        if len(fields) < 20 or fields[0] in (b'Z', b'X') or proc.stat().st_uid != os.getuid():
            raise RuntimeError('owned process is not live')
        if cmdline != b''.join(os.fsencode(arg) + b'\0' for arg in self.argv):
            raise RuntimeError('kernel cmdline differs from owned Popen argv')
        qemu = self.sources[self.roles['qemu']]
        executable = (proc / 'exe').stat()
        held = os.fstat(qemu.fd)
        if Path(self.argv[0]).resolve() != qemu.path or (executable.st_dev, executable.st_ino) != (held.st_dev, held.st_ino):
            raise RuntimeError('actual child executable differs from leased QEMU binary')
        return {'pid': peer, 'starttime': int(fields[19]), 'cmdline_sha256': hashlib.sha256(cmdline).hexdigest(),
                'qmp_peer_pid': peer, 'qmp_peer_uid': uid}

    def assert_owned(self):
        current = self._identity()
        if current != self.owner: raise RuntimeError('owned current process identity drift')
        for source in (self.bound_sources or self.sources).values(): self.checkpoint._lease_check(source)
        return dict(current)

    def _request(self, command, arguments=None):
        self.assert_owned()
        answer = self.monitor.call(command, arguments)
        self.assert_owned()
        if len(json.dumps(answer).encode()) > MAX_PROOF_BYTES: raise RuntimeError('bounded owned response required')
        return answer

    def observation(self, allow_prelaunch=False):
        allowed = ('paused', 'prelaunch') if allow_prelaunch is True else ('paused',)

        def stopped():
            status = self._request('query-status')
            if not isinstance(status, dict) or status.get('running') is not False or status.get('status') not in allowed:
                raise RuntimeError('current exact paused state required for capture observation')
            return status

        status = stopped()
        version = self._request('query-version')
        if (not isinstance(version, dict) or set(version) != {'qemu', 'package'} or
                not isinstance(version['qemu'], dict) or set(version['qemu']) != {'major', 'minor', 'micro'} or
                not isinstance(version['package'], str) or len(version['package']) > 4096):
            raise ValueError('bounded exact QEMU version response required')
        for number in version['qemu'].values(): _bound(number, 0, 1024)
        summary = self._request('query-memory-size-summary')
        if not isinstance(summary, dict) or set(summary) != {'base-memory', 'plugged-memory'} or summary['plugged-memory'] != 0:
            raise ValueError('explicit non-hotplug memory summary required')
        _bound(summary['plugged-memory'], 0, 0)
        flat = self._request('human-monitor-command', {'command-line': 'info mtree -f'})
        parsed = parse_flatview(flat, summary['base-memory'])
        final = stopped()
        if final.get('status') != status.get('status'): raise RuntimeError('stopped observation state drift')
        return {'schema': 'shizuku.owned-flatview.v1',
                'scope': 'read_only_prelaunch_protocol_probe' if status['status'] == 'prelaunch' else 'owned_paused_capture_geometry',
                'owner': dict(self.owner), 'qemu_source_ref': self.roles['qemu'],
                'qemu_sha256': self.sources[self.roles['qemu']].sha256, 'QMP_version': version,
                'status': status, 'memory_summary': summary, 'hmp_command': 'info mtree -f',
                'flatview_transcript': flat, 'selected_system_view': parsed,
                'controller_wiring_integrated': False, 'Windows98_boot_verified': False}

    def write_observation(self, path, allow_prelaunch=False):
        record = self.observation(allow_prelaunch)
        _publish(self.checkpoint, path, record, self.assert_owned)
        return record

    def bind(self, info, sources, references):
        if self.baseline is not None: raise RuntimeError('one immutable checkpoint binding per owned runtime')
        final_sources = _sources(self.checkpoint, sources)
        for name, source in self.sources.items():
            if final_sources.get(name) != source: raise ValueError('original held source closure must be retained')
        if set(references) != self.checkpoint.REQUIRED_REFS or any(name not in final_sources for name in references.values()):
            raise ValueError('exact existing helper role references required')
        if references['qemu'] != self.roles['qemu'] or references['controller'] != self.roles['controller'] or references['checkpoint_helper'] != self.roles['checkpoint_helper']:
            raise ValueError('bound helper roles differ from actual owned runtime')
        self.bound_sources = final_sources
        for source in final_sources.values(): _hash_source(self.checkpoint, source, self.assert_owned)
        record = _json_source(self.checkpoint, final_sources[references['ram_observation']], self.assert_owned)
        observed = self.observation()
        if (record.get('schema') != 'shizuku.owned-flatview.v1' or record.get('scope') != 'owned_paused_capture_geometry' or
                record.get('owner') != self.owner or record.get('qemu_sha256') != observed['qemu_sha256'] or
                record.get('qemu_source_ref') != self.roles['qemu'] or record.get('hmp_command') != 'info mtree -f' or
                record.get('QMP_version') != observed['QMP_version'] or record.get('memory_summary') != observed['memory_summary'] or
                record.get('status', {}).get('status') != 'paused' or record.get('status', {}).get('running') is not False or
                parse_flatview(record['flatview_transcript'], record['memory_summary']['base-memory']) != observed['selected_system_view'] or
                record.get('selected_system_view') != observed['selected_system_view']):
            raise RuntimeError('leased observation differs from actual current owned runtime')
        parser = final_sources[references['info_parser']]
        header = final_sources[references['info_header']]
        if Path(info.__file__).resolve() != parser.path: raise ValueError('loaded bound parser differs')
        layout = _json_source(self.checkpoint, final_sources[references['layout_receipt']], self.assert_owned)
        _layout_receipt(layout, info, header, parser, final_sources)
        self.reservation = read_budget(self.checkpoint, final_sources[references['budget']])
        self.baseline = observed
        self.references = dict(references)
        adapter = self.checkpoint.ControllerAdapter(self.call, self.assert_owned, self.observe_ram, dict(self.owner),
                                                    sources, dict(references), info, ctypes.sizeof(info.Info))
        proof = {'schema': 'shizuku.checkpoint-runtime-binding.v1', 'owner': dict(self.owner),
                 'source_references': dict(references), 'additional_runtime_roles': dict(self.roles),
                 'observed_ranges': observed['selected_system_view']['ranges'],
                 'controller_wiring_integrated': False, 'Windows98_boot_verified': False,
                 'VM_verified': False, 'private_checkpoint_captured': False}
        self.assert_owned()
        return Binding(adapter, self.reservation, proof)

    def observe_ram(self):
        if self.baseline is None: raise RuntimeError('owned runtime is not bound to leased geometry')
        current = self.observation()
        if any(current[key] != self.baseline[key] for key in ('owner', 'QMP_version', 'memory_summary', 'selected_system_view')):
            raise RuntimeError('actual owned physical RAM geometry/version drift')
        return {'ranges': tuple(tuple(pair) for pair in current['selected_system_view']['ranges']),
                'source_ref': self.references['ram_observation'], 'qemu_ref': self.references['qemu']}

    def call(self, command, arguments=None):
        if self.baseline is None: raise RuntimeError('checkpoint runtime is not bound')
        if command not in ('stop', 'query-status', 'pmemsave'): raise ValueError('checkpoint-only owned commands required')
        if command in ('stop', 'query-status'):
            if arguments is not None: raise ValueError('unexpected checkpoint command arguments')
        else:
            if not isinstance(arguments, dict) or set(arguments) != {'val', 'size', 'filename'}:
                raise ValueError('exact bounded physical dump arguments required')
            _bound(arguments['val'], 0, (1 << 64) - 1)
            _bound(arguments['size'], 1, self.checkpoint.MAX_CAPTURE_BYTES)
            ranges = self.observe_ram()['ranges']
            if not any(start <= arguments['val'] and arguments['val'] + arguments['size'] <= end for start, end in ranges):
                raise ValueError('complete capture outside actual owned RAM')
            path = self.checkpoint._canonical(arguments['filename'])
            if self.reservation.approved_lane not in path.parents:
                raise ValueError('dump outside separately approved private output lane')
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                item, named = os.fstat(fd), path.stat(follow_symlinks=False)
                identity = (item.st_dev, item.st_ino)
                if (self.checkpoint._stable(item) != self.checkpoint._stable(named) or
                        not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or
                        item.st_mode & 0o777 != 0o600 or item.st_nlink != 1 or item.st_size):
                    raise ValueError('fresh private precreated physical dump required')
                if self.capture_bytes_requested + arguments['size'] > self.reservation.total_bytes:
                    raise RuntimeError('separately approved aggregate physical capture budget exhausted')
                self.capture_bytes_requested += arguments['size']  # Failed requests remain charged.
                request = dict(arguments)
                request['filename'] = '/proc/%d/fd/%d' % (os.getpid(), fd)
                answer = self._request(command, request)
                current, named = os.fstat(fd), path.stat(follow_symlinks=False)
                if ((current.st_dev, current.st_ino) != identity or (named.st_dev, named.st_ino) != identity or
                        self.checkpoint._stable(current) != self.checkpoint._stable(named) or
                        not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or
                        current.st_mode & 0o777 != 0o600 or current.st_nlink != 1 or current.st_size != arguments['size']):
                    raise RuntimeError('owned physical dump destination inode/extent/privacy changed')
                return answer
            finally:
                os.close(fd)
        return self._request(command, arguments)
