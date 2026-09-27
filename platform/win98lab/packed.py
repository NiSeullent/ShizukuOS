#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original immutable XZ checkpoints for an exclusively owned, stopped lab.

The caller must hold the lab lock and establish that its guest has stopped.
This module never starts QEMU, modifies an existing raw disk or removes an old
checkpoint. The legacy storage backend remains independent.
"""
from contextlib import contextmanager
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

import storage as s

ROOT_RESERVE = s.ROOT_RESERVE
WRITE_MARGIN = s.WRITE_MARGIN
RAW_CAP = s.RAM_DISK_ALLOWANCE
ARCHIVE_CAP = RAW_CAP + WRITE_MARGIN
CODEC_ALLOWANCE = 256 * s.MIB
DECODER_MEMORY = 64 * s.MIB
CHUNK = s.MIB
CODEC = 'lzma2-preset3-crc64'
RAM_PREFIX = 'win98-modern-private-packed-'
TOKEN = re.compile(r'[A-Za-z0-9_-]{1,80}')
HASH = re.compile(r'[0-9a-f]{64}')
META_KEYS = ('raw_sha256', 'raw_bytes', 'archive_sha256', 'archive_bytes')
STATES = ('preparing', 'working_copy_active', 'persistence_started',
          'archive_verified', 'persisted', 'persistence_required')


def allocation_bound(size):
    if type(size) is not int or size < 0:
        raise RuntimeError('Invalid checkpoint allocation size')
    return (size + 4095) // 4096 * 4096


def available_memory():
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return int(values['MemAvailable'].split()[0]) * 1024


def check_headroom(available_ram, root_free, tmpfs_free):
    required = 6 * s.GIB + s.GUEST_ALLOWANCE + RAW_CAP + CODEC_ALLOWANCE
    if available_ram < required:
        raise RuntimeError('Less than 6 GiB RAM reserve after packed working copy and codec')
    if tmpfs_free < RAW_CAP:
        raise RuntimeError('Insufficient private RAM-disk capacity')
    if root_free < ROOT_RESERVE + WRITE_MARGIN:
        raise RuntimeError('Less than 20 GiB disk reserve and checkpoint margin')
    return {'required_memory_bytes': required,
            'required_disk_bytes': ROOT_RESERVE + WRITE_MARGIN,
            'codec_allowance_bytes': CODEC_ALLOWANCE}


def _codec_headroom():
    if available_memory() < 6 * s.GIB + CODEC_ALLOWANCE:
        raise RuntimeError('Less than 6 GiB RAM reserve while checkpoint codec runs')


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def _input(path, cap):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise RuntimeError('Checkpoint source exceeds its regular-file size bound')
        yield source
        after = os.fstat(source.fileno())
        current = path.lstat()
        if (_signature(before) != _signature(after) or
                _signature(after) != _signature(current)):
            raise RuntimeError('Checkpoint source changed during reading')


class _Output:
    def __init__(self, path, reserve=0, sparse=False):
        self.path = Path(path) if path is not None else None
        self.reserve, self.sparse, self.file = reserve, sparse, None
        self.created = None

    def __enter__(self):
        if self.path is not None:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.created = os.fstat(fd)
            self.file = os.fdopen(fd, 'wb', buffering=0)
        return self

    def write(self, data):
        if self.file is None or not data:
            return
        if self.sparse and data.count(0) == len(data):
            self.file.seek(len(data), 1)
            return
        pending = memoryview(data)
        while pending:
            position = self.file.tell()
            additional = allocation_bound(position + len(pending)) - allocation_bound(position)
            if (self.reserve and shutil.disk_usage(self.path.parent).free <
                    self.reserve + additional):
                raise RuntimeError('Host disk reserve would be crossed during packed persistence')
            written = self.file.write(pending)
            if written is None or written <= 0:
                raise RuntimeError('Checkpoint output made no progress')
            pending = pending[written:]

    def __exit__(self, kind, value, trace):
        failure = kind is not None
        try:
            if self.file is not None and not failure:
                self.file.truncate(self.file.tell())
                self.file.flush()
                os.fsync(self.file.fileno())
        except BaseException:
            failure = True
            raise
        finally:
            if self.file is not None:
                self.file.close()
            if failure and self.created is not None:
                try:
                    current = self.path.lstat()
                except FileNotFoundError:
                    current = None
                if current is not None and (current.st_dev, current.st_ino) == (
                        self.created.st_dev, self.created.st_ino):
                    self.path.unlink()


def _metadata(value):
    if not isinstance(value, dict):
        raise RuntimeError('Invalid checkpoint metadata')
    for name in ('raw_sha256', 'archive_sha256'):
        if not isinstance(value.get(name), str) or not HASH.fullmatch(value[name]):
            raise RuntimeError('Invalid checkpoint checksum metadata')
    for name, limit in (('raw_bytes', RAW_CAP), ('archive_bytes', ARCHIVE_CAP)):
        if type(value.get(name)) is not int or not 0 < value[name] <= limit:
            raise RuntimeError('Invalid checkpoint size metadata')
    return {name: value[name] for name in META_KEYS}


def encode(source, destination=None, reserve=0):
    """Count or exclusively create deterministic XZ bytes; never load a disk in RAM."""
    raw, archive = hashlib.sha256(), hashlib.sha256()
    raw_size = archive_size = 0
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ,
                                    check=lzma.CHECK_CRC64, preset=3)
    with _Output(destination, reserve) as output, _input(source, RAW_CAP) as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            raw_size += len(block)
            if raw_size > RAW_CAP:
                raise RuntimeError('Raw checkpoint grew beyond its size bound')
            raw.update(block)
            encoded = compressor.compress(block)
            archive_size += len(encoded)
            if archive_size > ARCHIVE_CAP:
                raise RuntimeError('Compressed checkpoint exceeds its size bound')
            archive.update(encoded)
            output.write(encoded)
        encoded = compressor.flush()
        archive_size += len(encoded)
        if archive_size > ARCHIVE_CAP:
            raise RuntimeError('Compressed checkpoint exceeds its size bound')
        archive.update(encoded)
        output.write(encoded)
        if not raw_size:
            raise RuntimeError('Empty raw checkpoint is unsupported')
    return {'raw_sha256': raw.hexdigest(), 'raw_bytes': raw_size,
            'archive_sha256': archive.hexdigest(), 'archive_bytes': archive_size}


def decode(source, destination=None, expected=None):
    """Verify one CRC64 XZ stream; optionally restore exact sparse qcow bytes."""
    wanted = _metadata(expected) if expected is not None else None
    raw, archive = hashlib.sha256(), hashlib.sha256()
    raw_size = archive_size = 0
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=DECODER_MEMORY)
    with _Output(destination, sparse=True) as output, _input(source, ARCHIVE_CAP) as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            archive_size += len(block)
            if archive_size > ARCHIVE_CAP or decoder.eof:
                raise RuntimeError('Trailing or oversized compressed checkpoint')
            archive.update(block)
            try:
                plain = decoder.decompress(block, max_length=CHUNK)
                while True:
                    raw_size += len(plain)
                    if raw_size > RAW_CAP or (wanted and raw_size > wanted['raw_bytes']):
                        raise RuntimeError('Decoded checkpoint exceeds its size bound')
                    raw.update(plain)
                    output.write(plain)
                    if decoder.check not in (lzma.CHECK_UNKNOWN, lzma.CHECK_CRC64):
                        raise RuntimeError('Checkpoint requires XZ CRC64 integrity')
                    if decoder.eof or decoder.needs_input:
                        break
                    plain = decoder.decompress(b'', max_length=CHUNK)
            except lzma.LZMAError as error:
                raise RuntimeError('Invalid or excessive-memory XZ checkpoint') from error
            if decoder.unused_data:
                raise RuntimeError('Trailing or concatenated XZ checkpoint')
        if not decoder.eof or not raw_size or decoder.check != lzma.CHECK_CRC64:
            raise RuntimeError('Incomplete or empty XZ checkpoint')
        result = {'raw_sha256': raw.hexdigest(), 'raw_bytes': raw_size,
                  'archive_sha256': archive.hexdigest(), 'archive_bytes': archive_size}
        if wanted is not None and result != wanted:
            raise RuntimeError('Checkpoint checksum or size mismatch')
    return result


def _raw(path):
    digest, length = hashlib.sha256(), 0
    with _input(path, RAW_CAP) as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            length += len(block)
            if length > RAW_CAP:
                raise RuntimeError('Raw checkpoint grew beyond its size bound')
            digest.update(block)
    if not length:
        raise RuntimeError('Empty raw checkpoint')
    return {'raw_sha256': digest.hexdigest(), 'raw_bytes': length}


def _json(path):
    with _input(path, s.MIB) as stream:
        data = stream.read(s.MIB + 1)
        if len(data) > s.MIB:
            raise RuntimeError('Checkpoint record exceeds its size bound')
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Invalid checkpoint record') from error
    if not isinstance(value, dict):
        raise RuntimeError('Checkpoint record must be an object')
    return value, hashlib.sha256(data).hexdigest()


def _original(path):
    path = Path(path)
    if not path.is_absolute() or path.name != 'install-disk.qcow2' or path.is_symlink():
        raise RuntimeError('Unknown original installation disk path')
    return path


def pointer_path(original):
    return _original(original).parent / 'install-packed-current.json'


def has_checkpoint(original):
    path = pointer_path(original)
    return path.exists() or path.is_symlink()


def _load_pointer(original):
    original = _original(original)
    if not has_checkpoint(original):
        return None, None
    value, checksum = _json(pointer_path(original))
    token = value.get('generation')
    parent = value.get('parent_pointer_sha256')
    if (type(value.get('version')) is not int or value['version'] != 1 or
            value.get('format') != 'xz' or value.get('codec') != CODEC or
            not isinstance(token, str) or not TOKEN.fullmatch(token) or
            value.get('original_disk') != str(original) or
            not isinstance(value.get('original_sha256'), str) or not HASH.fullmatch(value['original_sha256']) or
            (parent is not None and (not isinstance(parent, str) or not HASH.fullmatch(parent))) or
            value.get('archive') != str(original.parent / ('install-packed-' + token + '.qcow2.xz'))):
        raise RuntimeError('Foreign or malformed current packed checkpoint')
    _metadata(value)
    return value, checksum


def current(original, verify=True):
    value, _ = _load_pointer(original)
    if value is not None and verify:
        _codec_headroom()
        if _raw(original)['raw_sha256'] != value['original_sha256']:
            raise RuntimeError('Preserved original installation disk changed')
        decode(value['archive'], expected=value)
    return value


def locations(record):
    try:
        original = _original(record['original_disk'])
        directory, working = Path(record['directory']), Path(record['working_disk'])
    except (KeyError, TypeError) as error:
        raise RuntimeError('Missing packed working-copy paths') from error
    token = directory.name.removeprefix(RAM_PREFIX)
    if (type(record.get('version')) is not int or record['version'] != 1 or
            record.get('mode') != 'packed' or record.get('status') not in STATES or
            directory.parent != Path('/dev/shm') or not directory.name.startswith(RAM_PREFIX) or
            not TOKEN.fullmatch(token) or working != directory / 'install-disk.qcow2' or
            directory.is_symlink() or working.is_symlink()):
        raise RuntimeError('Unknown private packed working-copy paths')
    if directory.exists() and (not directory.is_dir() or directory.stat().st_mode & 0o077):
        raise RuntimeError('Packed working-copy directory is not private')
    if not isinstance(record.get('original_sha256'), str) or not HASH.fullmatch(record['original_sha256']):
        raise RuntimeError('Missing preserved original checksum')
    expected = record.get('source_pointer_sha256')
    if expected is not None and (not isinstance(expected, str) or not HASH.fullmatch(expected)):
        raise RuntimeError('Invalid parent checkpoint checksum')
    return (working, original, directory, original.parent / ('packed-copy-' + token + '.json'),
            original.parent / ('.install-packed-' + token + '.qcow2.xz.part'),
            original.parent / ('install-packed-' + token + '.qcow2.xz'))


def _target(record):
    _, original, directory, _, _, archive = locations(record)
    value = {'version': 1, 'format': 'xz', 'codec': CODEC,
             'generation': directory.name.removeprefix(RAM_PREFIX), 'archive': str(archive),
             'original_disk': str(original), 'original_sha256': record['original_sha256'],
             'parent_pointer_sha256': record['source_pointer_sha256']}
    value.update(_metadata(record['candidate']))
    return value


def _generation(record, target=None):
    _, original, _, _, _, _ = locations(record)
    if _raw(original)['raw_sha256'] != record['original_sha256']:
        raise RuntimeError('Preserved original disk changed; all versions retained')
    pointer, checksum = _load_pointer(original)
    if target is not None and pointer == target:
        return True
    if checksum != record['source_pointer_sha256']:
        raise RuntimeError('Stale or foreign packed checkpoint generation')
    return False


def _restore(record):
    working, original, directory, _, _, _ = locations(record)
    _generation(record)
    source = record.get('source', {})
    wanted = _metadata(source)
    if not directory.exists():
        directory.mkdir(mode=0o700)
    if record['source_pointer_sha256'] is None:
        if source.get('kind') != 'raw' or source.get('path') != str(original):
            raise RuntimeError('Unknown raw checkpoint source')
        s.sparse_copy(original, working)
    else:
        pointer, _ = _load_pointer(original)
        if (source.get('kind') != 'xz' or source.get('path') != pointer['archive'] or
                wanted != _metadata(pointer)):
            raise RuntimeError('Unknown compressed checkpoint source')
        decode(source['path'], working, wanted)
    if _raw(working) != {name: wanted[name] for name in ('raw_sha256', 'raw_bytes')}:
        raise RuntimeError('Restored working copy differs from its source')
    s.check_qcow(working)
    _generation(record)


def _disk_headroom(directory, archive_bytes):
    required = ROOT_RESERVE + WRITE_MARGIN + allocation_bound(archive_bytes)
    if shutil.disk_usage(directory).free < required:
        raise RuntimeError('Insufficient packed persistence headroom; all copies retained')
    return required


def prepare(original, checkpoint=lambda stage: None):
    original = _original(original)
    check_headroom(available_memory(), shutil.disk_usage(original.parent).free,
                   shutil.disk_usage('/dev/shm').free)
    s.check_qcow(original)
    raw = _raw(original)
    pointer, parent_hash = _load_pointer(original)
    if pointer is None:
        source = encode(original)
        if source['raw_sha256'] != raw['raw_sha256']:
            raise RuntimeError('Original changed while measuring packed checkpoint')
        source.update(kind='raw', path=str(original))
    else:
        if pointer['original_sha256'] != raw['raw_sha256']:
            raise RuntimeError('Preserved original disk differs from packed history')
        source = decode(pointer['archive'], expected=pointer)
        source.update(kind='xz', path=pointer['archive'])
    # Compression/verification can take time. Recheck immediately before the
    # full volatile working-copy reservation is made.
    check_headroom(available_memory(), shutil.disk_usage(original.parent).free,
                   shutil.disk_usage('/dev/shm').free)
    required = _disk_headroom(original.parent, source['archive_bytes'])
    directory = Path(tempfile.mkdtemp(prefix=RAM_PREFIX, dir='/dev/shm'))
    directory.chmod(0o700)
    record = {'version': 1, 'mode': 'packed', 'directory': str(directory),
              'working_disk': str(directory / 'install-disk.qcow2'),
              'original_disk': str(original), 'original_sha256': raw['raw_sha256'],
              'source_pointer_sha256': parent_hash, 'source': source, 'status': 'preparing',
              'initial_disk_required_bytes': required}
    _, _, _, journal, _, _ = locations(record)
    s.durable_json(journal, record)
    checkpoint('prepared_journal')
    _restore(record)
    record['status'] = 'working_copy_active'
    s.durable_json(journal, record)
    checkpoint('working_copy_active')
    return record


def pending_journals(directory):
    pending = []
    for path in Path(directory).glob('packed-copy-*.json'):
        record, _ = _json(path)
        _, _, ram_directory, expected, _, _ = locations(record)
        if path != expected:
            raise RuntimeError('Packed journal filename does not match its owned paths')
        if record.get('status') != 'persisted' or ram_directory.exists():
            pending.append(path)
    return pending


def persist(record, checkpoint=lambda stage: None):
    """Idempotently publish a stopped working copy, then release only its RAM file."""
    working, original, directory, journal, temporary, archive = locations(record)
    if journal.exists() or journal.is_symlink():
        saved, _ = _json(journal)
        locations(saved)
        for key in ('version', 'mode', 'directory', 'working_disk', 'original_disk',
                    'original_sha256', 'source_pointer_sha256', 'source'):
            if saved.get(key) != record.get(key):
                raise RuntimeError('Packed persistence journal does not match its owner')
        record.update(saved)
    else:
        raise RuntimeError('Packed persistence requires its durable allocation journal')
    _codec_headroom()
    if 'candidate' not in record:
        _generation(record)
        if record.get('status') == 'preparing' and not working.exists():
            check_headroom(available_memory(), shutil.disk_usage(original.parent).free,
                           shutil.disk_usage('/dev/shm').free)
            _restore(record)
        s.check_qcow(working)
        candidate = encode(working)
        if record.get('status') == 'preparing' and any(candidate[name] != record['source'][name]
                for name in ('raw_sha256', 'raw_bytes')):
            raise RuntimeError('Partial preparation retained; refusing to publish different data')
        record.update(candidate=candidate, status='persistence_started')
        s.durable_json(journal, record)
        checkpoint('persistence_started')
    wanted = _metadata(record['candidate'])
    target = _target(record)
    published = _generation(record, target)
    if not published:
        if _raw(working) != {name: wanted[name] for name in ('raw_sha256', 'raw_bytes')}:
            raise RuntimeError('RAM checkpoint changed since persistence started')
        s.check_qcow(working)
        if archive.exists() or archive.is_symlink():
            decode(archive, expected=wanted)
        else:
            if temporary.is_symlink():
                raise RuntimeError('Unexpected packed persistence temporary symlink')
            valid = False
            if temporary.exists():
                # A token-shaped name alone does not prove ownership of an
                # invalid file. Preserve partial/foreign data for review.
                decode(temporary, expected=wanted)
                valid = True
            if not valid:
                _codec_headroom()
                _disk_headroom(original.parent, wanted['archive_bytes'])
                measured = encode(working, temporary, ROOT_RESERVE + WRITE_MARGIN)
                if measured != wanted:
                    raise RuntimeError('Checkpoint changed during compressed persistence')
                decode(temporary, expected=wanted)
            record['status'] = 'archive_verified'
            s.durable_json(journal, record)
            checkpoint('archive_verified')
            _generation(record)
            os.link(temporary, archive)
            s.fsync_directory(original.parent)
            checkpoint('archive_published')
        _generation(record)
        s.durable_json(pointer_path(original), target)
        checkpoint('pointer_published')
    # A retry can reach here after its RAM directory has already disappeared.
    decode(archive, expected=wanted)
    if not _generation(record, target):
        raise RuntimeError('Published checkpoint pointer disappeared or changed')
    record['status'] = 'persisted'
    s.durable_json(journal, record)
    checkpoint('persisted_journal')
    if working.exists() or working.is_symlink():
        if _raw(working) != {name: wanted[name] for name in ('raw_sha256', 'raw_bytes')}:
            raise RuntimeError('Published checkpoint differs from RAM copy; RAM retained')
        working.unlink()
        checkpoint('ram_unlinked')
    if directory.exists():
        directory.rmdir()
    checkpoint('ram_removed')
    if temporary.exists() or temporary.is_symlink():
        decode(temporary, expected=wanted)
        temporary.unlink()
        s.fsync_directory(original.parent)
    return record
