#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build an owned, private Win98/Supervisor reference candidate from Git blobs.

Validation is the default; --link builds fresh native kernels and Supervisor EFI;
--build also prepares a private ESP from explicit disk/ROM/runtime inputs. Never
starts a VM or creates a public ISO. This boots the disk's existing OS: it does
not certify ShizukuDOS replacement, Windows98 boot, VMM, GUI or modern apps.

Private runtime binding contract (captured during a fresh owned runtime build):
  builder receipt: source_commit (or clean git.revision), archive.sha256,
    archive.files, consumed_sources_sha256 = {project-source-path: SHA256}.
  source manifest: schema=1, source_commit, archive_sha256,
    builder_receipt_sha256, consumed_sources_sha256 (the exact same map).
  An owner may put schema=1/source_commit/consumed_sources_sha256 inside the
    actual receipt's source_binding object instead of its top-level pins.
    Capture those pins before/after the actual build; preserve the original
    receipt's Git metadata. An old receipt lacking consumed pins must be rebuilt;
    adding a current-source sidecar later does not supply build provenance.
  Include every consumed project input, resources, upstream manifests/patches
    and out-of-tree export/DDK headers. All pins must match the same Git commit.
  The physical archive entry list must match archive.files and fit the pinned
    Supervisor loader's 64 MiB WIN64.IMG limit. No runtime execution is claimed.

Example source-only link (all compiler paths are explicit)::
  python3 -B tools/build_win98_supervisor_candidate.py \
    --source-root /absolute/repository --source-commit <40-hex> \
    --out /absolute/fresh-output --link --gcc /usr/bin/gcc \
    --nasm /usr/bin/nasm --ld /usr/bin/ld --nm /usr/bin/nm \
    --objcopy /usr/bin/objcopy --objdump /usr/bin/objdump \
    --readelf /usr/bin/readelf --mingw /usr/bin/x86_64-w64-mingw32-gcc
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
FLOOR = 17 << 30
EXPORT = 'docs/shizukudos10/reports/checkpoint-20261001/native-win98-candidate'
MANIFEST_SHA = 'f715aa6b300ab405707a71922beb7aa0ee926dfde155a77cddd69cb1b7554618'
PATCH_SHA = '06bd5eb18cb699f42444df935bb6b6b06831307f9af850f6e1a7c378ac571aca'
PEER_PATCH_SHA = 'b0054c23dfed9af1468aa8ec4f12abb53f16bc41fa558a896eeb4c925382d393'
PEER_HEADER_SHA = 'a72e27e51de1e33eef755f6e3164e1a21e68714e52e1b00e6ed2f1dcf3fe6933'
# Reviewed preimages for the 466c441 epoch. A source change requires review and
# a new producer epoch; context matching must never silently bypass these pins.
PREIMAGES = {
    'shizukudos/supervisor/loader/loader.c': 'd548d31aa95a8af556ceabd21484ee0782768c3f5872c59761bf75820068c809',
    'shizukudos/supervisor/include/shz_info.h': '2a72dd9fa2bef5293130e6fbfa46d7df825e85e22fbc92a15196e98e8e5c3f36',
    'shizukudos/supervisor/src/main.c': '34a34cacd7d3c0b3a7f47c5bd1af51016483ccc0b54245a3e4a80be61143dfae',
    'shizukudos/supervisor/src/domain.h': 'e75cce56b11fe6c29b529272f94f8d46f9b79a0edad93ce196f6fcfb102e70d2',
    'shizukudos/supervisor/src/domain.c': '66fb39cdbda6a9e976e4a47813976c954de31f54ce56562f8c6ca6474b2703ba',
    'shizukudos/supervisor/src/kdom.c': '64f3ad6e631936668f05b6c0552e0b120a611f6b51f4f345f2601e183159bd0b',
    'shizukudos/supervisor/src/devices.c': '4f2c255781f89854c0f9d62a27f293477bf4474bd0040f03213b4da2abeb744f',
    'shizukudos/supervisor/src/devices.h': '05c32a05f76c98cc643b669653535c214732d6c82a38ab9a5f2a9fe04ec1ea3b',
    'shizukudos/kernel64/main.c': '80410c1a943418e024fdcd21dc47b11c6398d96e1968055641537faaac58f5de',
}
ABI_AND_BUILDERS = {
    'shizukudos/abi/shz_abi.h': '7d53ebf6c5be271cf8dae5ff18fe1b05d8ba87492fc71f0a447f544c76750682',
    'shizukudos/abi/shz_ipc.h': '892e00099aad4d1c05cac2555ce6db7f95710ab41e544380afadf17c6ce6202c',
    'shizukudos/supervisor/loader/bootini.h': '5d9f969fc05c91528b235ca3bba66974a14d20e519f1ae52c1071bb816c49b0a',
    'shizukudos/kbuild.py': '1b0ffd44dd73b2b0a6c656b91f054e002cd999006e121ed16bbd666530f25b22',
    'shizukudos/tools/shzlib.py': 'e83d3cabafceba812d11eedb0693090a2736259d3f7270be5c2fe32f79de94e1',
    'shizukudos/supervisor/build.py': '4ee9d7aad75223647991c1a9bf146073e93b2fd2fd67c20fe67410801809037c',
}
NATIVE_NAMES = ('README.md', 'ata_pio.c', 'ata_pio.h', 'build_candidate.py',
                'config.h', 'string_pio.c', 'string_pio.h', 'win98.c', 'win98.h')
PATCH_PATHS = set(PREIMAGES) - {'shizukudos/kernel64/main.c'}
PATCH_PATHS |= {'shizukudos/supervisor/native_win98/' + n for n in NATIVE_NAMES}
PREFIXES = ('shizukudos/kernel32/', 'shizukudos/kernel64/', 'shizukudos/kcommon/',
            'shizukudos/abi/', 'shizukudos/supervisor/', 'shizukudos/uefi/',
            'shizukudos/win64/include/', 'shizukufs/v1/libsfs/')
SUFFIXES = {'.c', '.h', '.asm', '.ld', '.py'}
EXACT = {'shizukudos/kbuild.py', 'shizukudos/tools/shzlib.py',
         'shizukudos/win64/pe_parse.c', 'shizukudos/win64/pe_parse.h'}
TOOLS = ('gcc', 'nasm', 'ld', 'nm', 'objcopy', 'objdump', 'readelf', 'mingw')
MEDIA_TOOLS = ('mkfs.vfat', 'mcopy', 'mmd', 'fsck.vfat')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or any(x in ('', '.', '..') for x in name.split('/')) or '\\' in name or '\x00' in name:
        raise ValueError('unsafe source path')
    return name


def native_sources_only(name):
    return name in EXACT or (name.startswith(PREFIXES) and Path(name).suffix in SUFFIXES)


def git_bytes(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], timeout=60)


def git_snapshot(root, commit):
    """Read committed blobs, including when other owners have dirty worktrees."""
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('exact lowercase 40-hex source commit required')
    if git_bytes(root, 'rev-parse', commit + '^{commit}').decode().strip() != commit:
        raise ValueError('source commit did not resolve exactly')
    entries = {}
    for record in git_bytes(root, 'ls-tree', '-rz', commit).split(b'\0'):
        if not record:
            continue
        info, raw = record.split(b'\t', 1)
        mode, kind, oid = info.decode().split()
        name = safe_name(raw.decode('utf-8'))
        if native_sources_only(name) or name.startswith(EXPORT + '/'):
            if mode not in ('100644', '100755') or kind != 'blob':
                raise ValueError('non-regular consumed Git source: ' + name)
            entries[name] = oid
    data = {}
    # One batch, no shell, no worktree file reads and no repository scripts.
    queries = ''.join(oid + '\n' for oid in entries.values()).encode()
    raw = subprocess.run(['git', '-C', str(root), 'cat-file', '--batch'], input=queries,
                         capture_output=True, check=True, timeout=60).stdout
    pos = 0
    for name, expected in entries.items():
        end = raw.index(b'\n', pos)
        oid, kind, size = raw[pos:end].decode().split()
        size = int(size)
        if oid != expected or kind != 'blob' or not 0 <= size <= 32 << 20:
            raise ValueError('unexpected source blob extent')
        start = end + 1
        data[name] = raw[start:start + size]
        if len(data[name]) != size or raw[start + size:start + size + 1] != b'\n':
            raise ValueError('truncated source blob')
        pos = start + size + 1
    if pos != len(raw):
        raise ValueError('trailing source blob data')
    return data


def strict_patch(files, raw, allowed):
    """Apply exact unified hunks: no fuzzy context, offsets, outside paths or deletes."""
    lines = raw.decode('utf-8').splitlines(keepends=True)
    result = dict(files)
    changed = []
    i = 0
    while i < len(lines):
        if not lines[i].startswith('--- '):
            raise ValueError('unexpected patch header')
        old = lines[i][4:].strip()
        i += 1
        if i >= len(lines) or not lines[i].startswith('+++ '):
            raise ValueError('missing new patch path')
        new = lines[i][4:].strip()
        i += 1
        if not new.startswith('b/'):
            raise ValueError('unexpected new patch prefix')
        name = safe_name(new[2:])
        if name not in allowed or name in changed or (old != '/dev/null' and old != 'a/' + name):
            raise ValueError('patch path not allowed or repeated: ' + name)
        if (old == '/dev/null') != (name not in result):
            raise ValueError('new/existing patch preimage mismatch: ' + name)
        source = result.get(name, b'').decode('utf-8').splitlines(keepends=True)
        output, cursor = [], 0
        while i < len(lines) and lines[i].startswith('@@ '):
            m = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?', lines[i])
            if not m:
                raise ValueError('invalid patch hunk')
            old_start, old_count, new_start, new_count = (int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1))
            at = old_start - 1 if old_count else old_start
            if at < cursor or at > len(source):
                raise ValueError('overlapping or out of bounds patch hunk')
            output += source[cursor:at]
            if len(output) != (new_start - 1 if new_count else new_start):
                raise ValueError('new hunk offset mismatch')
            cursor, consumed, emitted = at, 0, 0
            i += 1
            while i < len(lines) and not lines[i].startswith(('@@ ', '--- ')):
                line = lines[i]
                i += 1
                if not line or line[0] not in ' +-':
                    raise ValueError('invalid hunk line')
                if line[0] in ' -':
                    if cursor >= len(source) or source[cursor] != line[1:]:
                        raise ValueError('exact hunk preimage mismatch: ' + name)
                    cursor += 1
                    consumed += 1
                if line[0] in ' +':
                    output.append(line[1:])
                    emitted += 1
            if (consumed, emitted) != (old_count, new_count):
                raise ValueError('hunk extent mismatch')
        output += source[cursor:]
        result[name] = ''.join(output).encode()
        changed.append(name)
    if set(changed) != allowed:
        raise ValueError('patch path inventory incomplete')
    return result, changed


def replace_once(data, old, new):
    if data.count(old) != 1:
        raise ValueError('reviewed peer hunk preimage is not unique')
    return data.replace(old, new, 1)


def prepared_sources(blobs):
    for name, expected in {**PREIMAGES, **ABI_AND_BUILDERS}.items():
        if digest(blobs[name]) != expected:
            raise ValueError('changed ABI/builder/patch preimage needs a new review: ' + name)
    m = blobs[EXPORT + '/manifest.json']
    if digest(m) != MANIFEST_SHA:
        raise ValueError('reviewed candidate manifest changed')
    manifest = json.loads(m)
    for group in ('entries', 'patches', 'host_fixture_sources'):
        for entry in manifest[group]:
            actual = blobs[EXPORT + '/' + safe_name(entry['path'])]
            if digest(actual) != entry.get('export_sha256', entry.get('sha256')):
                raise ValueError('candidate export drift: ' + entry['path'])
    patch = blobs[EXPORT + '/win98-source.patch']
    if digest(patch) != PATCH_SHA or digest(blobs[EXPORT + '/peer-dispatch.patch']) != PEER_PATCH_SHA:
        raise ValueError('reviewed patches changed')
    selected = {n: b for n, b in blobs.items() if native_sources_only(n)}
    staged, changed = strict_patch(selected, patch, PATCH_PATHS)
    peer = 'shizukudos/kernel64/main.c'
    # Explicit rebased hunk preserves the merged standalone observation block.
    staged[peer] = replace_once(staged[peer], b'#include "fs.h"\n', b'#include "fs.h"\n#include "boot_channel_peer.h"\n')
    staged[peer] = replace_once(staged[peer], b'    arch_init();\n',
        b'    const int has_kernel32_peer = k64_boot_has_kernel32_peer(&bootinfo);\n'
        b'    if (has_kernel32_peer < 0)\n'
        b'        shz_exit(97); /* malformed peer handoff is a real failure */\n    arch_init();\n')
    staged[peer] = replace_once(staged[peer], b'    if (bootinfo.channel_count) {\n', b'    if (has_kernel32_peer) {\n')
    header = blobs[EXPORT + '/peer-dispatch-source/shizukudos/kernel64/boot_channel_peer.h']
    if digest(header) != PEER_HEADER_SHA:
        raise ValueError('reviewed peer header changed')
    staged['shizukudos/kernel64/boot_channel_peer.h'] = header
    # Includes and machine code determine this stage; no ABI file is rewritten.
    return staged, changed + [peer, 'shizukudos/kernel64/boot_channel_peer.h']


def identity(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def pinned_file(path, expected=None, size=None):
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('canonical input file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not before.st_size or (size is not None and before.st_size != size):
            raise ValueError('regular input extent mismatch')
        h = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            h.update(block)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.stat()):
            raise ValueError('input changed during hash')
        actual = h.hexdigest()
        if expected is not None and actual != expected:
            raise ValueError('input SHA mismatch')
        return actual, before.st_size
    finally:
        os.close(fd)


def pinned_bytes(path, expected, limit):
    """Return the bounded bytes whose descriptor, identity and hash were verified."""
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('canonical pinned byte input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('bounded input extent mismatch')
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(fd, min(1 << 20, remaining))
            if not block:
                raise ValueError('truncated pinned input')
            chunks.append(block)
            remaining -= len(block)
        raw = b''.join(chunks)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.stat()) or digest(raw) != expected:
            raise ValueError('pinned input identity/SHA drift')
        return raw
    finally:
        os.close(fd)


@contextlib.contextmanager
def owned_output(out, private=False):
    """Restrict private directories and files before the first licensed byte."""
    previous = os.umask(0o077) if private else None
    try:
        out.mkdir(mode=0o700 if private else 0o755)
        if private and stat.S_IMODE(out.stat().st_mode) != 0o700:
            raise ValueError('private output must be mode0700')
        yield
    finally:
        if previous is not None:
            os.umask(previous)


def require_floor(path, budget=0):
    if shutil.disk_usage(path).free < FLOOR + budget:
        raise RuntimeError('17 GiB floor plus bounded build budget required')


@contextlib.contextmanager
def read_lease(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    previous, broken, leased = signal.getsignal(signal.SIGIO), [False], False
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != 2 << 30:
            raise ValueError('installed cold disk must be exactly 2 GiB')
        signal.signal(signal.SIGIO, lambda *_: broken.__setitem__(0, True))
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        leased = True
        def checkpoint():
            if broken[0] or identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.stat()) or fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_RDLCK:
                raise RuntimeError('original disk read lease/identity changed')
        h = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            checkpoint()
            h.update(block)
        if h.hexdigest() != expected:
            raise ValueError('leased original disk SHA mismatch')
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd, checkpoint
        checkpoint()
    finally:
        if leased:
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        os.close(fd)
        signal.signal(signal.SIGIO, previous)


def copy_disk(fd, checkpoint, out, expected):
    h, total = hashlib.sha256(), 0
    target_fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(target_fd, 'wb') as stream:
        while block := os.read(fd, 1 << 20):
            checkpoint()
            require_floor(out.parent, len(block))
            stream.write(block)
            h.update(block)
            total += len(block)
        stream.flush()
        os.fsync(stream.fileno())
    checkpoint()
    if total != 2 << 30 or h.hexdigest() != expected:
        raise ValueError('owned disk copy mismatch')
    pinned_file(out, expected, 2 << 30)


def private_copy(source, destination, expected=None):
    """Copy a small private payload with mode0600 and live floor checks."""
    actual, size = pinned_file(source, expected)
    require_floor(destination.parent, size)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        h = hashlib.sha256()
        with os.fdopen(target, 'wb') as stream:
            while block := os.read(fd, 1 << 20):
                require_floor(destination.parent, len(block))
                stream.write(block)
                h.update(block)
            stream.flush()
            os.fsync(stream.fileno())
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(source.stat()) or h.hexdigest() != actual:
            raise ValueError('private copied source drift')
        pinned_file(destination, actual, size)
        require_floor(destination.parent)
    finally:
        os.close(fd)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pin_tool(alias):
    """Pin real executable bytes while retaining the caller's dispatch name."""
    if not alias.is_absolute():
        raise ValueError('absolute executable alias required')
    alias_before = identity(alias.lstat())
    target = alias.resolve(strict=True)
    if not target.is_file() or not os.access(target, os.X_OK):
        raise ValueError('actual executable target required')
    target_before = identity(target.stat())
    sha, _ = pinned_file(target)
    binding = {'alias': str(alias), 'target': str(target),
               'alias_identity': alias_before, 'target_identity': target_before}
    verify_tool_binding(binding, target)
    return target, binding, sha


def verify_tool_binding(binding, target):
    alias = Path(binding['alias'])
    if (str(target) != binding['target'] or alias.resolve(strict=True) != target or
            identity(alias.lstat()) != tuple(binding['alias_identity']) or
            identity(target.stat()) != tuple(binding['target_identity'])):
        raise ValueError('executable alias/target identity changed')
    return str(alias)


def compiler_run(tools, out, proof):
    def run(command, cwd=None, env=None, timeout=300, capture=False, check=True):
        command = [str(x) for x in command]
        if command[0] not in tools:
            raise ValueError('builder requested a non-allowlisted executable')
        name = command[0]
        binding = proof.get('tool_bindings', {}).get(name)
        if binding is None:
            raise ValueError('missing executable alias/target pin')
        alias = verify_tool_binding(binding, tools[name])
        budget = 0
        if command[0] == 'mcopy':
            image_argument = command.index('-i') + 1 if '-i' in command else -1
            for i, arg in enumerate(command[1:-1], 1):
                if i != image_argument and not arg.startswith(('-', '::')) and Path(arg).is_file():
                    budget += Path(arg).stat().st_size
        # mcopy and mmd share the same mtools binary. Their original argv[0]
        # selects the utility; resolving argv[0] changes command semantics.
        command[0] = alias
        proof['commands'].append(command)
        proof.setdefault('command_executables', []).append(str(tools[name]))
        require_floor(out, budget)
        # Keep compiler search paths while avoiding shell execution and network.
        result = subprocess.run(command, executable=str(tools[name]), cwd=cwd or out, env=env, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        verify_tool_binding(binding, tools[name])
        log = out / ('command-%04d.log' % len(proof['commands']))
        log.write_text(result.stdout)
        require_floor(out)
        if check and result.returncode:
            raise RuntimeError('build command failed; see ' + str(log))
        return result
    return run


def link_native(source, tools, out, proof):
    sys.path.insert(0, str(source / 'shizukudos/tools'))
    sys.modules.pop('shzlib', None)
    run = compiler_run(tools, out, proof)
    k = load_module(source / 'shizukudos/kbuild.py', 'fresh_win98_kbuild')
    k.run = run
    k32 = k.build_kernel('kernel32', 'kernel32', k.K32_FLAGS, 'elf32', 'elf_i386', 'KERNEL32.BIN')
    extra = [k.SHZ / 'win64/pe_parse.c', *sorted((source / 'shizukufs/v1/libsfs').glob('*.c'))]
    k64 = k.build_kernel('kernel64', 'kernel64', k.K64_FLAGS, 'elf64', 'elf_x86_64', 'KERNEL64.BIN', extra_c=extra)
    b = load_module(source / 'shizukudos/supervisor/build.py', 'fresh_win98_supervisor')
    b.run = run
    b.OUT.mkdir(parents=True, exist_ok=True)
    (b.OUT / 'native_win98').mkdir()
    b.PAYLOAD_C = b.PAYLOAD_C + ['../native_win98/ata_pio.c', '../native_win98/string_pio.c', '../native_win98/win98.c']
    b.build_vbios()
    payload, _ = b.build_payload()
    loader, _ = b.build_loader(payload)
    if any('-DSHZ_STANDALONE' in c for c in proof['commands']):
        raise ValueError('standalone build must not satisfy native link gate')
    proof['standalone_compiled'] = False
    return b, loader, [k32['bin'], k32['elf'], k64['bin'], k64['elf'], loader, b.OUT / 'payload.bin', b.OUT / 'payload.elf']


def host_fixtures(blobs, source, tools, out, proof):
    """Execute actual ATA/string/PIC C bodies; host-only evidence, never VMX."""
    fixtures = out / 'host-fixtures'
    fixtures.mkdir()
    run = compiler_run(tools, out, proof)
    native = source / 'shizukudos/supervisor/native_win98'
    specs = [('ata', [native / 'ata_pio.c']),
             ('string', [native / 'string_pio.c', native / 'ata_pio.c']),
             ('pic', [source / 'shizukudos/supervisor/src/devices.c'])]
    results = []
    for name, bodies in specs:
        content = blobs[EXPORT + '/host-fixtures/' + name + '_host.c']
        # The historical fixture's include prefix is rebound to this fresh
        # source stage; no historical snapshot or copied production body is used.
        content = content.replace(b'candidate/shizukudos/', b'shizukudos/')
        p, exe = fixtures / (name + '_host.c'), fixtures / name
        p.write_bytes(content)
        run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', source,
             str(p), *bodies, '-o', exe])
        result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60, check=True)
        (fixtures / (name + '.log')).write_text(result.stdout + result.stderr)
        match = re.fullmatch(r'PASS (\d+) [^\r\n]*checks[^\r\n]*\n?', result.stdout)
        if not match or int(match[1]) != {'ata': 1554, 'string': 1450, 'pic': 70}[name]:
            raise ValueError('host fixture did not publish bounded PASS checks')
        results.append({'name': name, 'checks': int(match[1]), 'stdout': result.stdout.strip(), 'VM_executed': False,
                        'fixture_sha256': digest(content), 'executable_sha256': pinned_file(exe)[0]})
    proof['host_fixtures'] = results


def validate_runtime(args, root, commit):
    # This limit comes from the reviewed loader's wanted[] WIN64.IMG entry,
    # whose complete preimage/patch hashes are checked in prepared_sources().
    raw_archive = pinned_bytes(args.runtime, args.runtime_sha256, 64 << 20)
    expected = digest(raw_archive)
    receipt_raw = pinned_bytes(args.runtime_receipt, args.runtime_receipt_sha256, 16 << 20)
    receipt = json.loads(receipt_raw)
    actual = receipt.get('archive', {}).get('sha256')
    if actual != expected:
        raise ValueError('runtime archive is not bound to actual builder receipt')
    source_receipt = json.loads(pinned_bytes(args.runtime_source_manifest, args.runtime_source_manifest_sha256, 16 << 20))
    if (source_receipt.get('schema') != 1 or source_receipt.get('source_commit') != commit or
            source_receipt.get('archive_sha256') != expected or
            source_receipt.get('builder_receipt_sha256') != digest(receipt_raw)):
        raise ValueError('runtime manifest must bind actual archive, exact builder receipt and source commit')
    git = receipt.get('git')
    versions = [receipt[k] for k in ('source_commit',) if k in receipt]
    if git is not None:
        if not isinstance(git, dict) or git.get('dirty') is not False:
            raise ValueError('runtime builder Git source must be clean and exact')
        versions.append(git.get('revision'))
    binding = receipt.get('source_binding')
    consumed = receipt.get('consumed_sources_sha256')
    if binding is not None:
        # A producer may wrap its owner receipt with this metadata while the
        # build runs. The verified receipt itself must anchor commit and pins;
        # an unrelated later source sidecar never supplies missing evidence.
        if not isinstance(binding, dict) or binding.get('schema') != 1:
            raise ValueError('invalid builder source-binding wrapper')
        versions.append(binding.get('source_commit'))
        nested = binding.get('consumed_sources_sha256')
        if consumed is not None and consumed != nested:
            raise ValueError('conflicting builder consumed-source maps')
        consumed = nested
    if not versions or any(version != commit for version in versions):
        raise ValueError('actual runtime builder receipt is from a different source commit')
    pins = source_receipt.get('consumed_sources_sha256')
    if not isinstance(pins, dict) or not pins or consumed != pins:
        raise ValueError('runtime builder and manifest must carry the same actual consumed-source pins')
    if 'sources_sha256' in source_receipt and source_receipt['sources_sha256'] != pins:
        raise ValueError('ambiguous source inventories')
    required = []
    paths = ('shizukudos/win64', 'shizukudos/abi', 'shizukudos/kcommon',
             'shizukudos/kernel64', 'shizukudos/tools/shzlib.py', 'shizukudos/upstream')
    for record in git_bytes(root, 'ls-tree', '-rz', commit, *paths).split(b'\0'):
        if not record:
            continue
        info, raw = record.split(b'\t', 1)
        name = safe_name(raw.decode())
        # Include runtime resources/patches and the export/DDK inputs consumed
        # outside win64/. Extra declared consumed inputs are checked below too.
        if (not name.startswith('shizukudos/kernel64/') or Path(name).suffix == '.h' or
                name == 'shizukudos/kernel64/ntdrv_prov.c'):
            if info.split()[0] not in (b'100644', b'100755'):
                raise ValueError('nonregular runtime source')
            required.append(name)
    mandatory = {'shizukudos/win64/build.py', 'shizukudos/kernel64/ntsys.h',
                 'shizukudos/kernel64/ntdrv_prov.c', 'shizukudos/tools/shzlib.py',
                 'shizukudos/upstream/manifest.json'}
    if not mandatory.issubset(required) or not set(required).issubset(pins):
        raise ValueError('runtime source inventory is incomplete')
    for name, expected_sha in pins.items():
        if not isinstance(expected_sha, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha):
            raise ValueError('invalid consumed-source SHA pin')
        try:
            actual_sha = digest(git_bytes(root, 'show', commit + ':' + safe_name(name)))
        except subprocess.CalledProcessError as exc:
            raise ValueError('consumed input is not a same-commit Git source: ' + name) from exc
        if actual_sha != expected_sha:
            raise ValueError('runtime corresponding-source drift: ' + name)
    archive_inventory(raw_archive, receipt.get('archive', {}).get('files'))
    return expected


def archive_inventory(raw, expected_files):
    """Compare physical archive entries to the actual builder's file inventory."""
    if len(raw) < 16 or raw[:8] != b'SHZARC01':
        raise ValueError('actual Win64 archive signature/header missing')
    count, reserved = struct.unpack_from('<II', raw, 8)
    end = 16 + 136 * count
    if not 1 <= count <= 4096 or reserved or end > len(raw):
        raise ValueError('invalid bounded runtime archive table')
    names, normalized, extents = [], set(), []
    for i in range(count):
        field, offset, size = struct.unpack_from('<120sQQ', raw, 16 + 136 * i)
        name_bytes, nul, tail = field.partition(b'\0')
        if not nul or any(tail):
            raise ValueError('invalid bounded archive path')
        name = name_bytes.decode('ascii')
        parts = name.split('\\')
        key = name.upper()
        if (not name.startswith('\\SHZ\\') or '/' in name or ':' in name or
                any(p in ('', '.', '..') for p in parts[1:]) or key in normalized):
            raise ValueError('unsafe or aliased runtime archive path')
        if not size or offset < end or offset % 16 or offset > len(raw) or size > len(raw) - offset:
            raise ValueError('runtime archive payload extent is invalid')
        normalized.add(key)
        names.append(name)
        extents.append((offset, offset + size))
    extents.sort()
    if any(previous[1] > current[0] for previous, current in zip(extents, extents[1:])):
        raise ValueError('overlapping runtime archive payloads')
    if not isinstance(expected_files, list) or names != expected_files:
        raise ValueError('physical runtime archive differs from builder entry inventory')
    minimum = {'\\SHZ\\SYS64\\NTDLL.DLL', '\\SHZ\\SYS64\\KERNEL32.DLL', '\\SHZ\\TESTS\\T_HELLO.EXE'}
    if not minimum.issubset(normalized):
        raise ValueError('native bridge runtime providers/fixture missing')
    return names


def build_private_esp(args, builder, loader, source, tools, out, proof):
    require_floor(out, 7 << 30)
    runtime_sha = validate_runtime(args, args.source_root, args.source_commit)
    pinned_file(args.seabios, args.seabios_sha256, 256 << 10)
    # This candidate's constructor uses an explicit 2 GiB installed-disk profile.
    with read_lease(args.win98_disk, args.win98_disk_sha256) as (fd, checkpoint):
        owned = out / 'win98-owned.img'
        copy_disk(fd, checkpoint, owned, args.win98_disk_sha256)
        runtime = out / 'esp-runtime'
        (runtime / 'kernel64').mkdir(parents=True)
        (runtime / 'win64').mkdir()
        compiled = source / 'build/shizukudos'
        private_copy(compiled / 'kernel64/KERNEL64.BIN', runtime / 'kernel64/KERNEL64.BIN')
        private_copy(args.runtime, runtime / 'win64/WIN64.IMG', runtime_sha)
        pinned_file(runtime / 'win64/WIN64.IMG', runtime_sha)
        if args.include_kernel32:
            (runtime / 'kernel32').mkdir()
            private_copy(compiled / 'kernel32/KERNEL32.BIN', runtime / 'kernel32/KERNEL32.BIN')
        builder.BUILD, builder.ESP_MIB = runtime, 2304
        require_floor(out, builder.ESP_MIB << 20)
        esp = builder.build_esp(loader, owned)
        if stat.S_IMODE(esp.stat().st_mode) != 0o600:
            raise ValueError('private ESP permissions must be0600 before use')
        run = builder.run
        env = {**os.environ, 'MTOOLS_SKIP_CHECK': '1'}
        run(['mmd', '-i', esp, '::/EFI/SHIZUKU'], env=env)
        policy, config, rom = out / 'BOOT.INI', out / 'WIN98CFG.BIN', out / 'SEABIOS.BIN'
        policy.write_bytes(b'mode=supervisor\n')
        config.write_bytes(struct.pack('<4I', 0x38395753, 1, 128, 0))
        private_copy(args.seabios, rom, args.seabios_sha256)
        installed = [('::/EFI/SHIZUKU/BOOT.INI', policy), ('::/SHZDOS/WIN98CFG.BIN', config), ('::/SHZDOS/SEABIOS.BIN', rom)]
        for destination, path in installed:
            run(['mcopy', '-i', esp, path, destination], env=env)
        run(['fsck.vfat', '-n', esp])
        installed += [('::/SHZDOS/DISK.IMG', owned), ('::/SHZDOS/KERNEL64.BIN', runtime / 'kernel64/KERNEL64.BIN'),
                      ('::/SHZDOS/WIN64.IMG', runtime / 'win64/WIN64.IMG'), ('::/EFI/BOOT/BOOTX64.EFI', loader)]
        if args.include_kernel32:
            installed.append(('::/SHZDOS/KERNEL32.BIN', runtime / 'kernel32/KERNEL32.BIN'))
        proof['readbacks'] = []
        for index, (destination, path) in enumerate(installed):
            checkpoint()
            require_floor(out, path.stat().st_size + (1 << 20))
            readback = out / ('readback-%02d.bin' % index)
            run(['mcopy', '-i', esp, destination, readback], env=env)
            expected, size = pinned_file(path)
            pinned_file(readback, expected, size)
            proof['readbacks'].append({'ESP_path': destination, 'sha256': expected, 'bytes': size, 'whole_bytes_verified': True})
            readback.unlink()  # owned temporary only; receipt retains exact proof
        checkpoint()
    pinned_file(args.win98_disk, args.win98_disk_sha256, 2 << 30)
    pinned_file(args.seabios, args.seabios_sha256, 256 << 10)
    validate_runtime(args, args.source_root, args.source_commit)
    proof.update(original_disk_unchanged=True, original_disk_read_lease=True,
                 include_kernel32=args.include_kernel32, private_media=True,
                 boot_dependency='Existing installed disk OS; Microsoft IO.SYS reference if present. ShizukuDOS replacement NOT verified.')
    return [esp, config, rom]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-root', type=Path, required=True)
    ap.add_argument('--source-commit', required=True)
    ap.add_argument('--out', type=Path, required=True)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--link', action='store_true')
    mode.add_argument('--host-only', action='store_true', help='fresh actual-C device fixtures, no native link or VM')
    mode.add_argument('--build', action='store_true')
    ap.add_argument('--include-kernel32', action='store_true', help='explicit additional native peer; default ESP carries Kernel64 only')
    for name in TOOLS:
        ap.add_argument('--' + name, type=Path)
    for name in MEDIA_TOOLS:
        ap.add_argument('--' + name.replace('.', '-'), dest=name, type=Path)
    for name in ('win98-disk', 'seabios', 'runtime', 'runtime-receipt', 'runtime-source-manifest'):
        ap.add_argument('--' + name, type=Path)
        ap.add_argument('--' + name + '-sha256')
    args = ap.parse_args(argv)
    root, out = args.source_root, args.out
    if not root.is_absolute() or root.resolve() != root or not (root / 'shizukudos').is_dir():
        ap.error('canonical source repository required')
    if not out.is_absolute() or out.resolve() != out or out.exists() or not out.parent.is_dir():
        ap.error('fresh canonical output with existing parent required')
    if ('.git' in out.parts or root.is_relative_to(out) or
            (out.is_relative_to(root) and not out.is_relative_to(root / 'build'))):
        ap.error('output must not overlap source files')
    blobs = git_snapshot(root, args.source_commit)
    sources, changed = prepared_sources(blobs)
    proof = {'schema': 1, 'status': 'VALIDATED_NO_BUILD_OR_VM',
             'producer_sha256': pinned_file(Path(__file__).resolve())[0], 'source_commit': args.source_commit,
             'source_origin': 'immutable Git blobs; dirty working files never consumed',
             'source_epoch': 'native-win98-candidate-rebase-466c441-v1',
             'original_sources_sha256': {n: digest(b) for n, b in blobs.items()},
             'sources_sha256': {n: digest(b) for n, b in sources.items()},
             'changed_allowlist': changed, 'candidate_manifest_sha256': MANIFEST_SHA,
             'peer_dispatch_rebased': 'Preserve standalone observer; dispatch K32 IPC only for an actual K32 peer.',
             'VM_executed': False, 'Windows98_boot_verified': False,
             'ShizukuDOS_replaces_MSDOS_verified': False, 'Win98_VMM_mapping_verified': False,
             'native_Win64_app_verified': False, 'Windows98_GUI_input_verified': False,
             'target_apps_verified': False, 'public_artifact': False, 'commands': []}
    tools = {}
    proof['tool_bindings'] = {}
    proof['tools_sha256'] = {}
    executable_mode = args.link or args.build or args.host_only
    if executable_mode:
        needed = ('gcc',) if args.host_only else TOOLS
        for name in (*needed, *(MEDIA_TOOLS if args.build else ())):
            supplied = getattr(args, name)
            if supplied is None or not supplied.is_absolute():
                ap.error('explicit --' + name.replace('.', '-') + ' executable required')
            try:
                resolved, binding, tool_sha = pin_tool(supplied)
            except (OSError, ValueError) as exc:
                ap.error('actual stable executable required for ' + name + ': ' + str(exc))
            key = 'x86_64-w64-mingw32-gcc' if name == 'mingw' else name
            tools[key] = resolved
            proof['tool_bindings'][key] = binding
            proof['tools_sha256'][key] = tool_sha
    if args.build:
        for name in ('win98_disk', 'seabios', 'runtime', 'runtime_receipt', 'runtime_source_manifest'):
            if getattr(args, name) is None or not re.fullmatch('[0-9a-f]{64}', getattr(args, name + '_sha256') or ''):
                ap.error('explicit private input path and SHA required: ' + name)
        require_floor(out.parent, 7 << 30)
        proof['private_inputs'] = {}
        for name, size in (('win98_disk', 2 << 30), ('seabios', 256 << 10)):
            path, expected = getattr(args, name), getattr(args, name + '_sha256')
            _, actual_size = pinned_file(path, expected, size)
            proof['private_inputs'][name] = {'path': str(path), 'sha256': expected, 'bytes': actual_size}
        validate_runtime(args, root, args.source_commit)
        for name in ('runtime', 'runtime_receipt', 'runtime_source_manifest'):
            path, expected = getattr(args, name), getattr(args, name + '_sha256')
            _, actual_size = pinned_file(path, expected)
            proof['private_inputs'][name] = {'path': str(path), 'sha256': expected, 'bytes': actual_size}
    else:
        require_floor(out.parent, 128 << 20)
    if not executable_mode:
        print(json.dumps({'status': proof['status'], 'source_commit': args.source_commit,
                          'source_files': len(sources), 'changed_allowlist': changed, 'VM_executed': False}))
        return 0
    with owned_output(out, private=args.build):
        try:
            source = out / 'source'
            for name, content in sources.items():
                p = source / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)
            host_fixtures(blobs, source, tools, out, proof)
            artifacts = []
            if not args.host_only:
                builder, loader, artifacts = link_native(source, tools, out, proof)
            if args.build:
                artifacts += build_private_esp(args, builder, loader, source, tools, out, proof)
            for name, expected in proof['sources_sha256'].items():
                if pinned_file(source / name)[0] != expected:
                    raise ValueError('owned consumed source changed during build')
            for name, path in tools.items():
                verify_tool_binding(proof['tool_bindings'][name], path)
                if pinned_file(path)[0] != proof['tools_sha256'][name]:
                    raise ValueError('tool binary changed during build')
            proof['artifacts'] = {str(p.relative_to(out)): {'sha256': pinned_file(p)[0], 'bytes': p.stat().st_size} for p in artifacts}
            proof['status'] = ('PASS_PRIVATE_REFERENCE_CANDIDATE_NOT_RUN' if args.build else
                               'PASS_FRESH_SOURCE_HOST_ONLY_NATIVE_LINK_PENDING' if args.host_only else
                               'PASS_FRESH_NATIVE_SOURCE_LINK_AND_HOST_NOT_RUN')
            proof['source_before_after_match'] = True
            require_floor(out)
        except BaseException as exc:
            proof.update(status='FAIL_PRESERVED', error=str(type(exc).__name__) + ': ' + str(exc))
            raise
        finally:
            (out / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'status': proof['status'], 'receipt': str(out / 'result.json'), 'VM_executed': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
