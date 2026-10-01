#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded image I/O for owned build staging; preserve logical bytes and boot formats.

Never use overlay_sparse_partial on original media or a live VM. It accepts only
an explicitly owned *.partial regular file; any failed overlay must be discarded.
ISO deduplication accepts a frozen builder payload manifest, not arbitrary source
or evidence trees. Source notices, paths and hashes are retained.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath

CHUNK = 1024 * 1024
BLOCK = 4096
ZERO = bytes(CHUNK)


def _fingerprint(fd):
    s = os.fstat(fd)
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def _regular(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('regular file required: ' + str(path))
    return fd


def _range(fd, offset, length):
    size = os.fstat(fd).st_size
    if length is None:
        length = size - offset if type(offset) is int else -1
    if type(offset) is not int or type(length) is not int or offset < 0 or length < 0 or offset + length > size:
        raise ValueError('image range is outside the regular file')
    return length


def _digest(fd, offset, length):
    h = hashlib.sha256()
    end = offset + length
    while offset < end:
        chunk = os.pread(fd, min(CHUNK, end - offset), offset)
        if not chunk:
            raise OSError('unexpected image EOF')
        h.update(chunk)
        offset += len(chunk)
    return h.hexdigest()


def _expected(expected):
    if expected is not None and (type(expected) is not str or not re.fullmatch('[a-f0-9]{64}', expected)):
        raise ValueError('expected SHA-256 must be 64 lowercase hexadecimal characters')


def _pin(fd, offset, length, expected):
    _expected(expected)
    identity = _fingerprint(fd)
    digest = _digest(fd, offset, length)
    if _fingerprint(fd) != identity:
        raise RuntimeError('source changed while hashing')
    if expected is not None and digest != expected:
        raise ValueError('source range does not match expected SHA-256')
    return identity, digest


def _write(fd, data, offset):
    view = memoryview(data)
    while view:
        count = os.pwrite(fd, view, offset)
        if count <= 0 or count > len(view):
            raise OSError('invalid/zero image write')
        view = view[count:]
        offset += count


def _runs(chunk):
    # Whole empty chunks avoid a per-block scan; nonempty chunks retain every
    # nonzero 4 KiB block and the unaligned final tail without rounding sizes.
    if chunk == ZERO[:len(chunk)]:
        yield 0, len(chunk), True
        return
    first = 0
    was_zero = chunk[:min(BLOCK, len(chunk))] == ZERO[:min(BLOCK, len(chunk))]
    for at in range(BLOCK, len(chunk), BLOCK):
        size = min(BLOCK, len(chunk) - at)
        is_zero = chunk[at:at + size] == ZERO[:size]
        if is_zero != was_zero:
            yield first, at, was_zero
            first, was_zero = at, is_zero
    if chunk:
        yield first, len(chunk), was_zero


def _copy(src, dst, source_offset, destination_offset, length, identity, digest):
    copied = written = 0
    h = hashlib.sha256()
    while copied < length:
        chunk = os.pread(src, min(CHUNK, length - copied), source_offset + copied)
        if not chunk:
            raise OSError('unexpected image EOF while copying')
        h.update(chunk)
        for first, end, zero in _runs(chunk):
            at = destination_offset + copied + first
            if zero:
                # A hole may be skipped only if the existing logical target
                # bytes are zero. Dirty partial targets must be zeroed.
                existing = os.pread(dst, end - first, at)
                if existing == ZERO[:end - first]:
                    continue
            _write(dst, memoryview(chunk)[first:end], at)
            written += end - first
        copied += len(chunk)
    if _fingerprint(src) != identity:
        raise RuntimeError('source changed during image copy')
    actual = h.hexdigest()
    if digest is not None and actual != digest:
        raise ValueError('copied source range does not match expected SHA-256')
    digest = actual
    os.fsync(dst)
    if _digest(dst, destination_offset, length) != digest:
        raise RuntimeError('target image range failed exact SHA-256 readback')
    return {'bytes': length, 'sha256': digest, 'written_bytes': written,
            'zero_bytes_not_written': length - written, 'chunk_bytes': CHUNK,
            'source_stable': True, 'target_readback_verified': True}


def copy_new_sparse(source, destination, *, source_offset=0, length=None, expected_sha256=None):
    """Publish a new sparse copy/range only after stable-source and exact readback.
    Never replace an existing destination, including dangling symlinks. No VM,
    ISO structure or source receipt is changed; the logical range is byte-exact.
    """
    destination = Path(destination)
    if os.path.lexists(destination):
        raise FileExistsError(str(destination))
    src = _regular(source, os.O_RDONLY)
    fd = None
    temporary = None
    published = False
    try:
        length = _range(src, source_offset, length)
        _expected(expected_sha256)
        identity, digest = _fingerprint(src), expected_sha256
        fd, name = tempfile.mkstemp(prefix='.' + destination.name + '.', suffix='.tmp', dir=destination.parent)
        temporary = Path(name)
        os.ftruncate(fd, length)
        os.fchmod(fd, stat.S_IMODE(os.fstat(src).st_mode) & 0o666)
        result = _copy(src, fd, source_offset, 0, length, identity, digest)
        result['allocated_bytes'] = os.fstat(fd).st_blocks * 512
        os.link(temporary, destination, follow_symlinks=False)
        published = True
        temporary.unlink()
        temporary = None
        return result
    except BaseException:
        if published and fd is not None:
            try:
                actual = destination.stat(follow_symlinks=False)
                ours = os.fstat(fd)
                if (actual.st_dev, actual.st_ino) == (ours.st_dev, ours.st_ino):
                    destination.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        os.close(src)


def overlay_sparse_partial(source, destination, *, source_offset=0, destination_offset=0,
                           length=None, expected_sha256=None):
    """Write one exact range of an explicitly owned *.partial image in bounded RAM.
    Preserves all bytes outside the range; stale nonzero target data is cleared.
    Failure leaves an unaccepted partial build that the caller must discard.
    """
    destination = Path(destination)
    if not destination.name.endswith('.partial'):
        raise ValueError('overlay target must be an owned *.partial build image')
    if type(destination_offset) is not int or destination_offset < 0:
        raise ValueError('invalid destination offset')
    src = _regular(source, os.O_RDONLY)
    dst = None
    try:
        length = _range(src, source_offset, length)
        identity, digest = _pin(src, source_offset, length, expected_sha256)
        dst = _regular(destination, os.O_RDWR)
        if _fingerprint(dst)[:2] == identity[:2]:
            raise ValueError('source and destination are the same file')
        if destination_offset + length > os.fstat(dst).st_size:
            raise ValueError('overlay extends beyond the partial image')
        return _copy(src, dst, source_offset, destination_offset, length, identity, digest)
    finally:
        if dst is not None:
            os.close(dst)
        os.close(src)


def _staged_path(root, name):
    if type(name) is not str or '\\' in name:
        raise ValueError('invalid staged relative path')
    relative = PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or '..' in relative.parts or str(relative) != name:
        raise ValueError('invalid staged relative path')
    current = root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise OSError('symlink in staged path')
    return current


def deduplicate_stage(root, manifest):
    """Preserve frozen payload paths/bytes while joining equal ISO-stage inodes.
    Pass the builder's exact path -> {bytes, sha256} map. Use mkisofs --hardlinks
    afterwards; never compress boot-readable files or remove source/notices.
    The root must be an owned disposable stage. Failed stages cannot be shipped.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('owned regular staging directory required')
    groups = {}
    paths = {}
    # Verify the entire manifest before replacing any alias.
    for name, record in sorted(manifest.items()):
        path = _staged_path(root, name)
        if type(record) is not dict or type(record.get('bytes')) is not int or record['bytes'] < 0:
            raise ValueError('invalid staged size record')
        fd = _regular(path, os.O_RDONLY)
        try:
            if os.fstat(fd).st_size != record['bytes']:
                raise ValueError('staged size differs from source manifest')
            identity, digest = _pin(fd, 0, record['bytes'], record.get('sha256'))
            if record.get('sha256') is None:
                raise ValueError('staged source SHA-256 is required')
            s = os.fstat(fd)
            key = (record['bytes'], digest, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_mtime_ns)
            groups.setdefault(key, []).append(name)
            paths[name] = (path, identity)
        finally:
            os.close(fd)
    aliases = saved = 0
    for key, names in groups.items():
        canonical, original = paths[names[0]]
        for name in names[1:]:
            target, identity = paths[name]
            before = target.stat(follow_symlinks=False)
            source = canonical.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino) == (source.st_dev, source.st_ino):
                continue
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != identity[:4]:
                raise RuntimeError('staged alias changed before replacement')
            if (source.st_dev, source.st_ino, source.st_size, source.st_mtime_ns) != original[:4]:
                raise RuntimeError('canonical staged file changed before replacement')
            fd, temporary = tempfile.mkstemp(prefix='.' + target.name + '.', suffix='.tmp', dir=target.parent)
            os.close(fd)
            temporary = Path(temporary)
            temporary.unlink()
            try:
                os.link(canonical, temporary, follow_symlinks=False)
                linked = temporary.stat(follow_symlinks=False)
                if (linked.st_dev, linked.st_ino) != original[:2]:
                    raise RuntimeError('canonical staged inode changed while linking')
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
            aliases += 1
            saved += key[0]
    for name, record in manifest.items():
        fd = _regular(_staged_path(root, name), os.O_RDONLY)
        try:
            _pin(fd, 0, record['bytes'], record['sha256'])
        finally:
            os.close(fd)
    return {'aliases': aliases, 'logical_duplicate_bytes_shared': saved,
            'all_paths_retained': True, 'manifest_readback_verified': True,
            'iso_builder_required_flag': '--hardlinks'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source-offset', type=int, default=0)
    parser.add_argument('--length', type=int)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    print(json.dumps(copy_new_sparse(args.source, args.destination, source_offset=args.source_offset,
                                    length=args.length, expected_sha256=args.expected_sha256), indent=2))


if __name__ == '__main__':
    main()
