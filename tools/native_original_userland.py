#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe a pinned original Windows source; never copy, alter or boot it.

The profile is preparation metadata, not genuine-source authority. FAT parsing
uses the exact held prepare_replacement.py source; its constructor is never
called. All original inputs remain leased through observation and final SHA
readback. Public outputs and visible Git source directories are refused.
"""
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import types

ROOT = Path(__file__).absolute().parents[1]
TOOL = ROOT / 'tools/native_original_userland.py'
READER = ROOT / 'shizukudos/win98_boot/prepare_replacement.py'
DISK_BYTES = 2 << 30
MAX_JSON = 1 << 20
FLAGS = ('Windows98_boot_verified', 'MSDOS_replacement_under_Windows98',
         'native_apps_verified', 'VM_executed', 'public_artifact',
         'installed_Windows98_version_verified', 'drive_mapping_verified',
         'native_bootability_verified', 'persistence_verified',
         'ShizukuCore_userland_verified')


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def canonical(value):
    need(type(value) is str and value and
         not any(c in value for c in ('\0', '\r', '\n', '@', ':')),
         'canonical nonsymlink absolute path required')
    p = Path(value)
    need(p.is_absolute() and str(p) == value and p.resolve() == p and
         not any(q.is_symlink() for q in (p, *p.parents)),
         'canonical nonsymlink absolute path required')
    need(not any(p == q or q in p.parents for q in
                 map(Path, ('/dev', '/proc', '/sys', '/srv/m98'))),
         'device, virtual and public origin paths refused')
    return p


def pin(row, maximum=DISK_BYTES):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'},
         'exact path/bytes/SHA pin required')
    p = canonical(row['path'])
    need(type(row['bytes']) is int and 0 < row['bytes'] <= maximum and
         type(row['sha256']) is str and
         re.fullmatch('[0-9a-f]{64}', row['sha256']) and
         row['sha256'] != '0' * 64, 'bounded literal extent/nonzero SHA required')
    return p


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON field refused')
        result[key] = value
    return result


def object_bytes(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, 'bounded JSON required')
    result = json.loads(raw, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False, 'nonfinite JSON refused'))
    need(type(result) is dict, 'JSON request object required')
    return result


class HeldInputs:
    """Own only this producer's read leases; attempt every mandatory close."""
    def __init__(self):
        self.rows = {}
        self.broken = False
        self.pid = os.getpid()

    def __enter__(self):
        self.previous = signal.getsignal(signal.SIGIO)
        def broken(*args):
            self.broken = True
            if callable(self.previous):
                self.previous(*args)
        self.handler = broken
        signal.signal(signal.SIGIO, self.handler)
        return self

    def check(self):
        need(os.getpid() == self.pid and not self.broken and
             signal.getsignal(signal.SIGIO) is self.handler,
             'producer owner or read lease changed')
        # Paths were lexically/canonically admitted by add(). Recheck every
        # actual namespace ancestor once per sweep, as the guardian does;
        # never retain or cache namespace observations across checkpoints.
        ancestors = set()
        for p, entry in self.rows.items():
            ancestors.update((p, *p.parents))
            current, original = p.stat(), os.fstat(entry['fd'])
            need(stat.S_ISREG(current.st_mode) and original.st_nlink ==
                 current.st_nlink == 1 and identity(current) ==
                 entry['identity'] == identity(original) and
                 fcntl.fcntl(entry['fd'], fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY and
                 fcntl.fcntl(entry['fd'], fcntl.F_GETLEASE) == fcntl.F_RDLCK and
                 fcntl.fcntl(entry['fd'], fcntl.F_GETOWN) == self.pid,
                 'held input path/inode/link/lease differs')
        need(not any(p.is_symlink() for p in ancestors),
             'held input namespace ancestor became a symlink')

    def hash(self, entry):
        h = hashlib.sha256()
        size = entry['pin']['bytes']
        at = 0
        while at < size:
            self.check()
            raw = os.pread(entry['fd'], min(1 << 20, size - at), at)
            need(raw, 'unexpected original input EOF')
            h.update(raw)
            at += len(raw)
        need(not os.pread(entry['fd'], 1, size), 'original input extent grew')
        self.check()
        return h.hexdigest()

    def add(self, row):
        p = pin(row)
        if p in self.rows:
            need(self.rows[p]['pin'] == row, 'conflicting duplicate input pin')
            return self.rows[p]
        self.check()
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        added = False
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 info.st_size == row['bytes'], 'one-link regular exact input required')
            need(not any(identity(info)[:2] == e['identity'][:2]
                         for e in self.rows.values()), 'input inode alias refused')
            fcntl.fcntl(fd, fcntl.F_SETOWN, self.pid)
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            entry = {'fd': fd, 'pin': dict(row), 'identity': identity(info)}
            self.rows[p] = entry
            added = True
            need(self.hash(entry) == row['sha256'], 'held original full SHA differs')
            return entry
        finally:
            if not added:
                os.close(fd)

    def raw(self, row, maximum=MAX_JSON):
        pin(row, maximum)
        entry = self.add(row)
        self.check()
        raw = os.pread(entry['fd'], row['bytes'] + 1, 0)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
             'held metadata/source bytes differ')
        self.check()
        return raw

    def finish(self):
        self.check()
        for entry in self.rows.values():
            need(self.hash(entry) == entry['pin']['sha256'],
                 'final original input full SHA differs')
        self.check()

    def __exit__(self, kind, value, trace):
        errors = []
        try:
            self.check()
        except BaseException as error:
            errors.append(error)
        for entry in reversed(list(self.rows.values())):
            try:
                fcntl.fcntl(entry['fd'], fcntl.F_SETLEASE, fcntl.F_UNLCK)
            except BaseException as error:
                errors.append(error)
            try:
                os.close(entry['fd'])
            except BaseException as error:
                errors.append(error)
        self.rows.clear()
        if signal.getsignal(signal.SIGIO) is self.handler:
            signal.signal(signal.SIGIO, self.previous)
        else:
            errors.append(ValueError('producer SIGIO handler changed'))
        if errors:
            raise RuntimeError('mandatory producer custody cleanup failed') from errors[0]


def request_fields(request):
    need(type(request) is dict and set(request) ==
         {'schema', 'source_disk', 'windows_directory', 'boot_policy', 'producer_inputs'} and
         request['schema'] == 'shizukuos.original-userland-profile-request.v1',
         'exact original-userland request schema required')
    pin(request['source_disk'])
    need(request['source_disk']['bytes'] == DISK_BYTES, 'exact original 2 GiB disk required')
    directory = request['windows_directory']
    need(type(directory) is str and re.fullmatch('[A-Z0-9_-]{1,8}', directory) and
         directory not in {'CON', 'PRN', 'AUX', 'NUL',
                           *(prefix + str(n) for prefix in ('COM', 'LPT') for n in range(1, 10))},
         'uppercase nondevice short Windows directory required')
    need(request['boot_policy'] == 'shz.foundation=win98',
         'explicit Windows foundation policy required')
    rows = request['producer_inputs']
    need(type(rows) is list and len(rows) == 2, 'two ordered actual producer pins required')
    for row in rows:
        pin(row, MAX_JSON)
    need([row['path'] for row in rows] == [str(TOOL), str(READER)],
         'exact current producer/reader paths required')
    return 'C:\\' + directory


def installed_paths(raw, selected):
    # GPL-2.0-or-later contract from install/win98_source_profile.py. Keep the
    # observed path rule here so no third unpinned producer is executed.
    need(all(v in (9, 10, 13) or 32 <= v <= 126 for v in raw),
         'unsupported MSDOS boot text/control bytes')
    text = raw.decode('ascii')
    need('\r' not in text.replace('\r\n', ''), 'physical LF/CRLF boot lines required')
    values, section, seen = {}, '', set()
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        if line.startswith('['):
            need(re.fullmatch(r'\[[A-Za-z0-9_]+\]', line), 'ambiguous MSDOS section')
            section = line[1:-1].upper()
            need(section not in seen, 'duplicate MSDOS section')
            seen.add(section)
        elif section == 'PATHS':
            need(line.count('=') == 1, 'ambiguous MSDOS path record')
            key, value = map(str.strip, line.split('=', 1))
            key = key.upper()
            need(key not in values, 'duplicate MSDOS path key')
            values[key] = value.upper()
    need(values.get('WINDIR') == values.get('WINBOOTDIR') == selected and
         values.get('HOSTWINBOOTDRV') == 'C', 'observed MSDOS C: paths differ')


def private_output(out):
    need(not out.exists() and out.parent.is_dir(), 'fresh private output leaf required')
    parent = out.parent.stat()
    need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
         'owned mode0700 output parent required')
    for root in out.parents:
        if (root / '.git').exists():
            need(out.relative_to(root).parts[0] == 'build',
                 'private output outside visible Git source required')
            result = subprocess.run(['git', '-C', str(root), 'check-ignore',
                                     '--no-index', '--quiet', '--', str(out)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, timeout=10)
            need(result.returncode == 0, 'private build output must be ignored by Git')
            break
    return identity(parent)[:2]


def observe(fd, disk_bytes, windows_directory, constructor, check):
    """Read actual held disk bytes for a caller with source-admitted readers.

    No path is opened and no descriptor ownership transfers. The guardian
    supplies its retained read-only FD and lease guard, then compares these
    three observed fields against the private profile before task launch.
    Observation supplies no genuine Windows or runtime authority.
    """
    need(type(fd) is int and fd >= 0 and type(disk_bytes) is int and
         disk_bytes == DISK_BYTES and callable(check), 'actual bounded disk FD/guard required')
    need(type(windows_directory) is str and
         re.fullmatch('[A-Z0-9_-]{1,8}', windows_directory) and
         windows_directory not in {'CON', 'PRN', 'AUX', 'NUL',
             *(prefix + str(n) for prefix in ('COM', 'LPT') for n in range(1, 10))},
         'uppercase nondevice short Windows directory required')
    check()
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_size == disk_bytes and
         fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
         'actual held read-only original disk extent required')
    mbr = os.pread(fd, 512, 0)
    need(len(mbr) == 512, 'short original MBR')
    active = [mbr[446+i*16:462+i*16] for i in range(4) if mbr[446+i*16] == 0x80]
    need(len(active) == 1, 'one original active partition required')
    start = struct.unpack_from('<I', active[0], 8)[0]
    vbr = os.pread(fd, 512, start * 512)
    check()
    geometry = constructor.inspect_geometry(mbr, vbr, disk_bytes)
    files = constructor.inventory(fd, geometry, check)
    need(len(files) <= 30000 and len({name.upper() for name in files}) == len(files),
         'ambiguous or unbounded original FAT inventory')
    directory = windows_directory
    required = {'IO.SYS', 'MSDOS.SYS', 'COMMAND.COM',
                *(directory + '/' + name for name in
                  ('WIN.COM', 'SYSTEM.INI', 'SYSTEM/VMM32.VXD', 'IFSHLP.SYS'))}
    observed = {}
    for name in sorted(required):
        row = files.get(name)
        need(type(row) is dict and set(row) ==
             {'bytes', 'sha256', 'metadata_sha256', 'cluster'} and
             type(row['bytes']) is int and 0 < row['bytes'] <= disk_bytes,
             'required regular original member missing or empty')
        observed[name] = dict(row)
    need(files.get(directory, {}).get('directory') is True and
         files.get(directory + '/SYSTEM', {}).get('directory') is True,
         'original installed Windows directories required')
    msdos = observed['MSDOS.SYS']
    need(msdos['bytes'] <= 65536, 'bounded original MSDOS path member required')
    data = io.BytesIO()
    actual = constructor.Volume(fd, geometry, check).file(
        msdos['cluster'], msdos['bytes'], data)
    need(actual == msdos['sha256'], 'original MSDOS member changed')
    selected = 'C:\\' + directory
    installed_paths(data.getvalue(), selected)
    check()
    need(os.pread(fd, 512, 0) == mbr and os.pread(fd, 512, start * 512) == vbr,
         'original boot sectors changed')
    check()
    return {'observed_windows_path': selected, 'observed_members': observed,
            'boot_sectors': {'mbr': {'bytes': 512, 'sha256': sha(mbr)},
                             'vbr': {'bytes': 512, 'sha256': sha(vbr)}}}


def generate(request_path, request_sha, out):
    request_path = canonical(str(request_path))
    out = canonical(str(out))
    parent_identity = private_output(out)
    request_pin = {'path': str(request_path), 'bytes': request_path.stat().st_size,
                   'sha256': request_sha}
    pin(request_pin, MAX_JSON)
    directory_fd = None
    output_fd = None
    owned_directory = None
    written = None
    final = 'original-userland-profile.json'
    partial = '.original-userland-profile.part'
    def output_check():
        canonical(str(out))
        parent = out.parent.stat()
        need(identity(parent)[:2] == parent_identity and parent.st_uid == os.geteuid() and
             stat.S_IMODE(parent.st_mode) == 0o700, 'private output parent changed')
        if directory_fd is not None:
            info = os.fstat(directory_fd)
            need(identity(info)[:2] == owned_directory == identity(out.stat())[:2] and
                 info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                 'owned output directory changed')
    try:
        with HeldInputs() as held:
            request = object_bytes(held.raw(request_pin))
            request_fields(request)
            own_raw = held.raw(request['producer_inputs'][0])
            need(sha(own_raw) == sha(TOOL.read_bytes()), 'executed producer source changed')
            reader_raw = held.raw(request['producer_inputs'][1])
            reader = types.ModuleType('held_original_userland_fat_reader')
            reader.__file__ = str(READER)
            exec(compile(reader_raw, str(READER), 'exec', dont_inherit=True), reader.__dict__)
            source = held.add(request['source_disk'])
            observed = observe(source['fd'], DISK_BYTES, request['windows_directory'],
                               reader, held.check)
            profile = {'schema': 'shizukuos.private-original-userland-profile.v1',
                       'status': 'ORIGINAL_USERLAND_SOURCE_OBSERVED_NOT_BOOTED',
                       'phase': 'original-userland-legacy-adapter',
                       'source_disk': dict(request['source_disk']), 'request': request_pin,
                       'producer_inputs': request['producer_inputs'], 'boot_policy': request['boot_policy'],
                       **observed,
                       'source_before_after_match': True, **{name: False for name in FLAGS}}
            raw = (json.dumps(profile, indent=2, allow_nan=False) + '\n').encode()
            need(len(raw) <= MAX_JSON, 'bounded private observational profile required')
            # add() already hashed every complete original. Keep all leases
            # checked here; the mandatory second full SHA pass follows the
            # completed artifact fsync below, before any successful profile.
            held.check()
            output_check()
            out.mkdir(mode=0o700)
            owned_directory = identity(out.stat())[:2]
            directory_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            output_check()
            output_fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=directory_fd)
            at = 0
            while at < len(raw):
                held.check()
                output_check()
                count = os.write(output_fd, raw[at:])
                need(count > 0, 'zero private profile write')
                at += count
            os.fsync(output_fd)
            written = identity(os.fstat(output_fd))
            need(os.pread(output_fd, len(raw) + 1, 0) == raw and
                 written == identity((out / partial).stat()) and
                 os.fstat(output_fd).st_nlink == 1 and
                 stat.S_IMODE(os.fstat(output_fd).st_mode) == 0o600,
                 'completed private profile readback/identity differs')
            os.fsync(directory_fd)
            held.finish()
        # Original full readback and every unlock/close succeeded. A partial
        # file is never a successful profile if mandatory custody close failed.
        output_check()
        need(identity((out / partial).stat()) == written and not (out / final).exists(),
             'private profile inode changed before publication')
        os.rename(partial, final, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        output_check()
        published = identity(os.fstat(output_fd))
        need(published[:3] == written[:3] and
             published == identity((out / final).stat()) and
             os.pread(output_fd, len(raw) + 1, 0) == raw and
             identity(os.fstat(output_fd)) == published and
             identity((out / final).stat()) == published and
             os.fstat(output_fd).st_nlink == 1 and
             stat.S_IMODE(os.fstat(output_fd).st_mode) == 0o600,
             'published private profile readback/identity differs')
        # Mandatory output close must succeed before returning acceptance.
        completed_fd = output_fd
        output_fd = None
        os.close(completed_fd)
        completed_directory = directory_fd
        directory_fd = None
        os.close(completed_directory)
        return profile
    except BaseException:
        # Never delete unrelated source/output data. Invalidate only our exact
        # accepted profile inode; retain partial files for failure diagnosis.
        if owned_directory is not None:
            try:
                canonical(str(out))
                info = out.stat()
                need(identity(info)[:2] == owned_directory and
                     info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                     'owned failed output changed')
                published = out / final
                if written is not None and published.exists() and identity(published.stat())[:2] == written[:2]:
                    published.unlink()
            except (OSError, ValueError):
                pass
        raise
    finally:
        try:
            if output_fd is not None:
                os.close(output_fd)
        finally:
            if directory_fd is not None:
                os.close(directory_fd)


EPOCH_INTENT_SCHEMA = 'shizukuos.native-original-userland-epoch-intent.v1'
OWNED_INPUT_SCHEMA = 'shizukuos.w98-owned-input-option.v1'


def owned_input_option(spec):
    """Explicit opt-in -> the exact guardian `owned_input` object, or None for 'none'.

    Selects only; the guardian generates W98INPT.BIN from its live Attempt, so no
    nonce, hash or port is carried here and a VGA pair alone never implies input."""
    need(type(spec) is str and spec, 'explicit --owned-input keyboard,mouse|none required')
    if spec == 'none':
        return None
    parts = spec.split(',')
    need(all(part in ('keyboard', 'mouse') for part in parts) and len(set(parts)) == len(parts),
         'owned input devices must be unique keyboard and/or mouse')
    return {'schema': OWNED_INPUT_SCHEMA, 'machine': 'q35-i8042',
            'keyboard': 'keyboard' in parts, 'mouse': 'mouse' in parts}


def add_owned_input(intent_path, spec, out):
    """Copy an existing original-epoch intent adding only `owned_input` (none: verbatim bytes)."""
    option = owned_input_option(spec)
    source = Path(intent_path)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'regular intent file required')
        raw = os.read(fd, MAX_JSON + 1)
    finally:
        os.close(fd)
    intent = object_bytes(raw)
    need(intent.get('schema') == EPOCH_INTENT_SCHEMA, 'original-epoch intent schema required')
    need('owned_input' not in intent, 'intent already carries owned_input; refusing to overwrite')
    if option is not None:
        intent = {**intent, 'owned_input': option}
        raw = (json.dumps(intent, indent=2) + '\n').encode()
    out = Path(out)
    private_output(out)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), 'short intent write')
        os.fsync(fd)
    finally:
        os.close(fd)
    return option


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path)
    parser.add_argument('--request-sha256')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--owned-input', help='keyboard,mouse|none: add the explicit owned Q35 i8042 input option to --intent')
    parser.add_argument('--intent', type=Path, help='existing original-epoch intent (with --owned-input)')
    args = parser.parse_args(argv)
    if args.owned_input is not None:
        if args.request or args.request_sha256 or not args.intent:
            parser.error('--owned-input edits --intent only and takes no --request')
        add_owned_input(args.intent, args.owned_input, args.out)
        print('ORIGINAL_EPOCH_INTENT_OWNED_INPUT_OPTION_WRITTEN_NOT_BOOTED')
        return 0
    if args.intent or not args.request or not args.request_sha256:
        parser.error('--request and --request-sha256 are required (or --owned-input with --intent)')
    generate(args.request, args.request_sha256, args.out)
    print('ORIGINAL_USERLAND_SOURCE_OBSERVED_NOT_BOOTED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
