#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Optional immutable XZ representation of the packed lab's original base.

All mutations require the caller's exclusive lab lock and stopped-guest proof.
This module supplies immutable base identity for packed.py; it neither starts
nor stops a guest. Packed identity checks use verify() when has_archive() is
true. The lab entry point refuses raw access whenever a base pointer is present
and recognizes an absent raw path with that pointer as an existing installation.

create() preserves the raw file. retire_raw() is a separate explicit operation;
it never removes an archive, old packed generation, journal, or unknown partial.
Both resume from one durable journal. Interrupted/foreign partials that cannot
be verified are retained. Existing packed XZ bounds and resource reserves are
reused unchanged. The module has no standalone CLI or automatic migration;
lab.py exposes the explicit, guarded archive-base command.
"""
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

import storage as s

RAM_ROOT = Path('/dev/shm')
RAM_PREFIX = 'win98-modern-private-base-verify-'
SCHEMA = 'ntw.lab.base-archive.v1'
JOURNAL_SCHEMA = 'ntw.lab.base-archive-journal.v1'
TOKEN = re.compile(r'[0-9a-f]{32}')
HASH = re.compile(r'[0-9a-f]{64}')
STATES = ('preparing', 'archive_verified', 'archive_published',
          'pointer_published', 'retiring', 'raw_retired')


def _codec():
    # A later packed backend can import this module without an import cycle.
    import packed
    return packed


def _original(value):
    path = Path(value)
    if (not path.is_absolute() or path.name != 'install-disk.qcow2' or
            path != path.resolve() or not path.parent.is_dir()):
        raise RuntimeError('Unknown or symlinked original base path')
    return path


def pointer_path(original):
    return _original(original).parent / 'install-base-archive.json'


def journal_path(original):
    return _original(original).parent / 'install-base-archive-journal.json'


def has_archive(original):
    """Presence, even corrupt/dangling-symlink presence, MUST refuse raw mode."""
    return os.path.lexists(pointer_path(original))


def _identity(st):
    return {key: getattr(st, 'st_'+key) for key in
            ('dev', 'ino', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


@contextmanager
def _input(path, cap, links=1):
    path = Path(path)
    if path != path.resolve():
        raise RuntimeError('Symlinked base archive input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != links or
                not 0 < before.st_size <= cap):
            raise RuntimeError('Base archive input must be bounded and have no foreign hardlinks')
        yield stream, _identity(before)
        after = os.fstat(stream.fileno())
        if _identity(before) != _identity(after) or _identity(after) != _identity(path.lstat()):
            raise RuntimeError('Base archive input identity changed during capture')


def _raw(path):
    sha, size = hashlib.sha256(), 0
    with _input(path, _codec().RAW_CAP) as (stream, identity):
        for block in iter(lambda: stream.read(s.MIB), b''):
            size += len(block)
            if size > _codec().RAW_CAP:
                raise RuntimeError('Base source grew beyond its size bound')
            sha.update(block)
    return {'raw_sha256': sha.hexdigest(), 'raw_bytes': size}, identity


def _json(path):
    with _input(path, s.MIB) as (stream, _):
        data = stream.read(s.MIB+1)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError('Duplicate base archive record key')
            value[key] = item
        return value
    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Invalid base archive record') from error
    if not isinstance(value, dict):
        raise RuntimeError('Base archive record must be an object')
    return value, hashlib.sha256(data).hexdigest()


def _metadata(value):
    return _codec()._metadata(value)


def _pointer(original, value):
    expected_keys = {'schema', 'version', 'format', 'codec', 'generation',
                     'original_disk', 'archive', *_codec().META_KEYS}
    token = value.get('generation')
    if (set(value) != expected_keys or value.get('schema') != SCHEMA or
            type(value.get('version')) is not int or value['version'] != 1 or
            value.get('format') != 'xz' or value.get('codec') != _codec().CODEC or
            not isinstance(token, str) or not TOKEN.fullmatch(token) or
            value.get('original_disk') != str(original) or
            value.get('archive') != str(original.parent / ('install-base-'+token+'.qcow2.xz'))):
        raise RuntimeError('Foreign or malformed immutable base pointer')
    _metadata(value)
    return value


def _load(original):
    return _pointer(original, _json(pointer_path(original))[0])


def _journal(original):
    record, digest = _json(journal_path(original))
    pointer = _pointer(original, record.get('pointer', {}))
    identity = record.get('source_identity', {})
    if (set(record) != {'schema', 'version', 'status', 'pointer', 'source_identity',
                       'packed_pointer_sha256', 'retirement_pointer_sha256'} or
            record.get('schema') != JOURNAL_SCHEMA or type(record.get('version')) is not int or
            record['version'] != 1 or record.get('status') not in STATES or
            set(identity) != {'dev','ino','mode','nlink','size','mtime_ns','ctime_ns'} or
            any(type(item) is not int or item < 0 for item in identity.values()) or
            not stat.S_ISREG(identity['mode']) or identity['nlink'] != 1 or
            identity['size'] != pointer['raw_bytes'] or
            not isinstance(record.get('packed_pointer_sha256'), str) or
            not HASH.fullmatch(record['packed_pointer_sha256'])):
        raise RuntimeError('Foreign or malformed immutable base journal')
    retired = record['retirement_pointer_sha256']
    if ((record['status'] in ('retiring', 'raw_retired') and
         (not isinstance(retired, str) or not HASH.fullmatch(retired))) or
            (record['status'] not in ('retiring', 'raw_retired') and retired is not None)):
        raise RuntimeError('Invalid base retirement generation')
    return record, digest


def _rename_new(source, destination):
    """Linux atomic no-replace rename; no hardlink-based crash window/fallback."""
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, 'renameat2', None)
    if rename is None:
        raise RuntimeError('Immutable base publication requires Linux renameat2')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def _publish_json(path, value):
    """Durable exclusive publication; an existing pointer is never replaced."""
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'.tmp-', dir=path.parent)
    temporary = Path(temporary)
    owned = os.fstat(fd)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        _rename_new(temporary, path)
        s.fsync_directory(path.parent)
    finally:
        if temporary.exists() and (temporary.lstat().st_dev,temporary.lstat().st_ino) == (owned.st_dev,owned.st_ino):
            temporary.unlink()
            s.fsync_directory(path.parent)


def _save(original, record, previous):
    if _json(journal_path(original))[1] != previous:
        raise RuntimeError('Base archive journal changed before publication')
    s.durable_json(journal_path(original), record)
    return _json(journal_path(original))[1]


def _source(record):
    raw, identity = _raw(record['pointer']['original_disk'])
    if (identity != record['source_identity'] or
            raw != {key: record['pointer'][key] for key in ('raw_sha256','raw_bytes')}):
        raise RuntimeError('Original base identity or bytes changed; all versions retained')
    return raw


def _history(original, raw_hash):
    """Require a real, verified packed generation bound to this exact original."""
    codec = _codec()
    value, checksum = codec._load_pointer(original)
    if value is None or value['original_sha256'] != raw_hash:
        raise RuntimeError('Base archival requires matching existing packed history')
    codec._codec_headroom()
    # _load_pointer validates exact original/archive paths; also reject aliases.
    with _input(value['archive'], codec.ARCHIVE_CAP):
        codec.decode(value['archive'], expected=value)
    if codec._load_pointer(original) != (value, checksum):
        raise RuntimeError('Packed history changed during base verification')
    return checksum


def _restore_check(archive, wanted, original):
    codec = _codec()
    codec.check_headroom(codec.available_memory(), codec.shutil.disk_usage(original.parent).free,
                         codec.shutil.disk_usage(RAM_ROOT).free)
    directory = Path(tempfile.mkdtemp(prefix=RAM_PREFIX, dir=RAM_ROOT))
    destination = directory / 'restored.qcow2'
    owned = None
    try:
        codec.decode(archive, destination, expected=wanted)
        owned = destination.lstat()
        restored, _ = _raw(destination)
        if restored != {key: wanted[key] for key in ('raw_sha256','raw_bytes')}:
            raise RuntimeError('Independent restored base bytes disagree')
        s.check_qcow(destination)
    finally:
        if owned is not None and os.path.lexists(destination):
            current = destination.lstat()
            if ((current.st_dev, current.st_ino, current.st_nlink) ==
                    (owned.st_dev, owned.st_ino, 1) and not destination.is_symlink()):
                destination.unlink()
        # Never recursively remove unexpected children or a replacement file.
        directory.rmdir()


def verify(original, expected_sha256=None):
    """Verify the archived identity; returns only exact original hash and length.

    A present raw base must agree too. This is intentionally distinct from
    packed.current(): the newer packed generation has different raw bytes.
    """
    original = _original(original)
    value = _load(original)
    if expected_sha256 is not None and value['raw_sha256'] != expected_sha256:
        raise RuntimeError('Archived base does not match expected original identity')
    codec = _codec()
    codec._codec_headroom()
    with _input(value['archive'], codec.ARCHIVE_CAP):
        codec.decode(value['archive'], expected=value)
    raw = {key: value[key] for key in ('raw_sha256','raw_bytes')}
    if os.path.lexists(original) and _raw(original)[0] != raw:
        raise RuntimeError('Present original base differs from its immutable archive')
    if _load(original) != value:
        raise RuntimeError('Base pointer changed during verification')
    return raw


def create(original, checkpoint=lambda stage: None):
    """Create/resume a verified base archive and pointer, preserving the raw base."""
    original = _original(original)
    codec = _codec()
    codec._codec_headroom()
    if not has_archive(original):
        codec.check_headroom(codec.available_memory(), codec.shutil.disk_usage(original.parent).free,
                             codec.shutil.disk_usage(RAM_ROOT).free)
    if os.path.lexists(journal_path(original)):
        record, journal_hash = _journal(original)
    else:
        if has_archive(original):
            raise RuntimeError('Existing base pointer lacks its allocation journal')
        raw, identity = _raw(original)
        s.check_qcow(original)
        history = _history(original, raw['raw_sha256'])
        metadata = codec.encode(original)
        if {key: metadata[key] for key in raw} != raw or _raw(original) != (raw, identity):
            raise RuntimeError('Original base changed while measuring its archive')
        token = uuid.uuid4().hex
        value = {'schema': SCHEMA, 'version': 1, 'format': 'xz', 'codec': codec.CODEC,
                 'generation': token, 'original_disk': str(original),
                 'archive': str(original.parent / ('install-base-'+token+'.qcow2.xz')), **metadata}
        record = {'schema': JOURNAL_SCHEMA, 'version': 1, 'status': 'preparing',
                  'pointer': value, 'source_identity': identity,
                  'packed_pointer_sha256': history, 'retirement_pointer_sha256': None}
        _publish_json(journal_path(original), record)
        journal_hash = _json(journal_path(original))[1]
        checkpoint('journal_created')
    value = record['pointer']
    if has_archive(original):
        if _load(original) != value:
            raise RuntimeError('Foreign base pointer retained')
        verify(original, value['raw_sha256'])
        if record['status'] in ('preparing','archive_verified','archive_published'):
            _source(record)
            if _history(original, value['raw_sha256']) != record['packed_pointer_sha256']:
                raise RuntimeError('Stale packed generation before base pointer publication')
            record['status'] = 'pointer_published'
            _save(original, record, journal_hash)
        return value
    if record['status'] in ('pointer_published','retiring','raw_retired'):
        raise RuntimeError('Previously published base pointer disappeared')
    _source(record)
    if _history(original, value['raw_sha256']) != record['packed_pointer_sha256']:
        raise RuntimeError('Stale packed generation before base archive publication')
    archive = Path(value['archive'])
    temporary = archive.with_name('.'+archive.name+'.part')
    if not os.path.lexists(archive):
        if os.path.lexists(temporary):
            with _input(temporary, codec.ARCHIVE_CAP):
                codec.decode(temporary, expected=value)
        else:
            codec.check_headroom(codec.available_memory(), codec.shutil.disk_usage(original.parent).free,
                                 codec.shutil.disk_usage(RAM_ROOT).free)
            codec._disk_headroom(original.parent, value['archive_bytes'])
            measured = codec.encode(original, temporary, codec.ROOT_RESERVE+codec.WRITE_MARGIN)
            if measured != _metadata(value):
                raise RuntimeError('Base changed during archive creation; partial retained')
        _source(record)
        _restore_check(temporary, value, original)
        record['status'] = 'archive_verified'
        journal_hash = _save(original, record, journal_hash)
        checkpoint('archive_verified')
        _source(record)
        if _history(original, value['raw_sha256']) != record['packed_pointer_sha256']:
            raise RuntimeError('Packed generation changed before base archive publication')
        os.link(temporary, archive)
        s.fsync_directory(original.parent)
    # The only accepted second link is the journal's verified staging name.
    if os.path.lexists(temporary):
        if (temporary.is_symlink() or archive.is_symlink() or
                temporary.lstat().st_ino != archive.lstat().st_ino or
                temporary.lstat().st_dev != archive.lstat().st_dev):
            raise RuntimeError('Unknown base archive partial retained')
        with _input(archive, codec.ARCHIVE_CAP, links=2):
            codec.decode(archive, expected=value)
        temporary.unlink()
        s.fsync_directory(original.parent)
    with _input(archive, codec.ARCHIVE_CAP):
        codec.decode(archive, expected=value)
    # Retrying a link publication may arrive without a recorded restore pass.
    _restore_check(archive, value, original)
    record['status'] = 'archive_published'
    journal_hash = _save(original, record, journal_hash)
    checkpoint('archive_published')
    _source(record)
    if _history(original, value['raw_sha256']) != record['packed_pointer_sha256']:
        raise RuntimeError('Packed generation changed before base pointer publication')
    if _json(journal_path(original))[1] != journal_hash:
        raise RuntimeError('Base archive journal changed before pointer publication')
    _publish_json(pointer_path(original), value)
    record['status'] = 'pointer_published'
    _save(original, record, journal_hash)
    checkpoint('pointer_published')
    verify(original, value['raw_sha256'])
    return value


def retire_raw(original, checkpoint=lambda stage: None):
    """Explicitly remove only the verified redundant raw base; never its history.

    The stopped caller must already have integrated archive-aware packed
    identity/startup and unconditional raw-mode refusal. There is no fallback.
    """
    original = _original(original)
    record, journal_hash = _journal(original)
    value = record['pointer']
    if _load(original) != value or record['status'] not in ('pointer_published','retiring','raw_retired'):
        raise RuntimeError('Base retirement requires its durably published matching pointer')
    verify(original, value['raw_sha256'])
    if s.pending_journals(original.parent):
        raise RuntimeError('Pending raw working-copy journal forbids base retirement')
    history = _history(original, value['raw_sha256'])
    if record['status'] == 'raw_retired':
        if os.path.lexists(original):
            raise RuntimeError('Raw base unexpectedly reappeared after retirement')
        return record
    if record['status'] == 'pointer_published':
        _source(record)
        record.update(status='retiring', retirement_pointer_sha256=history)
        journal_hash = _save(original, record, journal_hash)
        checkpoint('retirement_started')
    elif history != record['retirement_pointer_sha256']:
        raise RuntimeError('Packed generation changed during base retirement')
    # Recheck after interruption hooks; a matching checksum alone does not
    # authorize unlinking a same-path replacement or somebody else's hardlink.
    verify(original, value['raw_sha256'])
    if _history(original, value['raw_sha256']) != record['retirement_pointer_sha256']:
        raise RuntimeError('Packed generation changed before raw base retirement')
    if s.pending_journals(original.parent):
        raise RuntimeError('Pending raw working-copy journal forbids base retirement')
    if os.path.lexists(original):
        if record['status'] == 'raw_retired':
            raise RuntimeError('Raw base unexpectedly reappeared after retirement')
        _source(record)
        if _json(journal_path(original))[1] != journal_hash:
            raise RuntimeError('Base archive journal changed before raw retirement')
        original.unlink()
        s.fsync_directory(original.parent)
        checkpoint('raw_unlinked')
    record['status'] = 'raw_retired'
    _save(original, record, journal_hash)
    checkpoint('raw_retired')
    verify(original, value['raw_sha256'])
    return record
