#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private RAM working copies with journaled, retryable stopped-guest persistence."""
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile

GIB = 1024 ** 3
MIB = 1024 ** 2
ROOT_RESERVE = 20 * GIB
DISK_CAP = 2 * GIB
RAM_DISK_ALLOWANCE = DISK_CAP + 256 * MIB
GUEST_ALLOWANCE = 384 * MIB
WRITE_MARGIN = 128 * MIB


def limit_child_files():
    resource.setrlimit(resource.RLIMIT_FSIZE, (RAM_DISK_ALLOWANCE, RAM_DISK_ALLOWANCE))


def check_headroom(available_ram, root_free, tmpfs_free, ram_copy):
    ram_required = 6 * GIB + GUEST_ALLOWANCE
    if ram_copy:
        ram_required += RAM_DISK_ALLOWANCE
        if tmpfs_free < RAM_DISK_ALLOWANCE:
            raise RuntimeError('Insufficient private RAM-disk capacity')
    if available_ram < ram_required:
        raise RuntimeError('Less than 6 GiB host RAM reserve after full guest allocation')
    disk_required = ROOT_RESERVE + (WRITE_MARGIN if ram_copy else RAM_DISK_ALLOWANCE)
    if root_free < disk_required:
        raise RuntimeError('Less than 20 GiB host disk reserve after guest allocation')
    return {'required_memory_bytes': ram_required, 'required_disk_bytes': disk_required}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(MIB), b''):
            h.update(block)
    return h.hexdigest()


def check_extent(path):
    path = Path(path)
    st = path.stat()
    if path.is_symlink() or not path.is_file() or st.st_size > RAM_DISK_ALLOWANCE or st.st_blocks * 512 > RAM_DISK_ALLOWANCE:
        raise RuntimeError('Guest image file extent/allocation exceeds reserved capacity')


def sparse_copy(source, destination, reserve=0):
    source, destination = Path(source), Path(destination)
    check_extent(source)
    created = False
    try:
        with source.open('rb') as src, destination.open('xb') as out:
            created = True
            os.fchmod(out.fileno(), 0o600)
            for block in iter(lambda: src.read(MIB), b''):
                if src.tell() > RAM_DISK_ALLOWANCE:
                    raise RuntimeError('Source grew beyond reserved capacity during copy')
                if block.count(0) == len(block):
                    out.seek(len(block), 1)
                else:
                    if reserve and shutil.disk_usage(destination.parent).free < reserve + len(block):
                        raise RuntimeError('Host reserve would be crossed during persistence')
                    out.write(block)
            out.truncate(src.tell())
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def check_qcow(path):
    check_extent(path)
    info = json.loads(subprocess.check_output(
        ['qemu-img', 'info', '--output=json', str(path)], text=True, timeout=30))
    if info.get('format') != 'qcow2' or info.get('virtual-size') != DISK_CAP or info.get('backing-filename'):
        raise RuntimeError('Expected an independent 2-GiB qcow2 installation disk')
    subprocess.run(['qemu-img', 'check', '-q', str(path)], check=True,
                   capture_output=True, timeout=30)


def fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def locations(record):
    working, original = Path(record['working_disk']), Path(record['original_disk'])
    directory = Path(record['directory'])
    if (directory.parent != Path('/dev/shm') or
            not directory.name.startswith('win98-modern-private-install-') or
            working != directory / 'install-disk.qcow2' or directory.is_symlink() or
            working.is_symlink() or original.is_symlink()):
        raise RuntimeError('Unknown private RAM working-copy paths')
    if directory.exists() and directory.stat().st_mode & 0o077:
        raise RuntimeError('RAM working-copy directory is not private')
    token = directory.name.removeprefix('win98-modern-private-install-')
    return (working, original, directory,
            original.parent / ('ram-copy-' + token + '.json'),
            original.parent / ('.install-persist-' + token + '.qcow2'),
            original.parent / ('install-disk.before-ram-' + token + '.qcow2'))


def prepare(original):
    original = Path(original)
    check_qcow(original)
    original_hash = digest(original)
    directory = Path(tempfile.mkdtemp(prefix='win98-modern-private-install-', dir='/dev/shm'))
    directory.chmod(0o700)
    record = {'directory': str(directory), 'working_disk': str(directory / 'install-disk.qcow2'),
              'original_disk': str(original), 'original_sha256': original_hash, 'status': 'preparing'}
    working, _, _, journal, _, _ = locations(record)
    # Register the private allocation before copying; interrupted preparation is
    # discoverable even before the global supervisor state has been replaced.
    durable_json(journal, record)
    sparse_copy(original, working)
    if digest(working) != original_hash or digest(original) != original_hash:
        raise RuntimeError('Original disk changed while making RAM working copy')
    check_qcow(working)
    record['status'] = 'working_copy_active'
    durable_json(journal, record)
    return record


def pending_journals(directory):
    pending = []
    for path in Path(directory).glob('ram-copy-*.json'):
        record = json.loads(path.read_text())
        _, _, ram_directory, _, _, _ = locations(record)
        if record.get('status') != 'persisted' or ram_directory.exists():
            pending.append(path)
    return pending


def persist(record, checkpoint=lambda stage: None):
    """Caller holds exclusive lab lock and proves QEMU stopped before entry."""
    working, original, directory, journal, temporary, backup = locations(record)
    if journal.exists():
        saved = json.loads(journal.read_text())
        for key in ('directory', 'working_disk', 'original_disk', 'original_sha256'):
            if saved.get(key) != record.get(key):
                raise RuntimeError('Persistence journal does not match owned working copy')
        record.update(saved)
    wanted = record.get('persisted_sha256')
    if not wanted:
        check_qcow(working)
        wanted = digest(working)
        if record.get('status') == 'preparing' and wanted != record['original_sha256']:
            raise RuntimeError('Preparation was interrupted before a verified copy; original retained')
        record.update({'persisted_sha256': wanted, 'status': 'persistence_started'})
        durable_json(journal, record)
    original_hash = digest(original)
    backup_valid = backup.exists() and not backup.is_symlink() and digest(backup) == record['original_sha256']
    if backup.exists() and not backup_valid:
        raise RuntimeError('Existing backup disagrees with original hash; all copies retained')
    already_published = original_hash == wanted and backup_valid
    if not already_published:
        if original_hash != record['original_sha256']:
            raise RuntimeError('Original disk changed; all versions are preserved')
        check_qcow(working)
        if digest(working) != wanted:
            raise RuntimeError('RAM working copy changed since persistence started')
        # A partial owned temporary from an interrupted copy is replaceable;
        # an already verified copy is reused without allocating another one.
        if temporary.is_symlink():
            raise RuntimeError('Unexpected persistence temporary symlink')
        temporary_valid = temporary.exists() and digest(temporary) == wanted
        if not temporary_valid:
            temporary.unlink(missing_ok=True)
            with working.open('rb') as source:
                allocation = sum(MIB for block in iter(lambda: source.read(MIB), b'')
                                 if block.count(0) != len(block))
            if shutil.disk_usage(original.parent).free < ROOT_RESERVE + allocation + WRITE_MARGIN:
                raise RuntimeError('Insufficient persistence headroom; original and RAM copy retained')
            sparse_copy(working, temporary, ROOT_RESERVE + WRITE_MARGIN)
            record['copy_allocation_bound'] = allocation
        if digest(temporary) != wanted:
            raise RuntimeError('Persistence copy checksum mismatch')
        check_qcow(temporary)
        record['status'] = 'copy_verified'
        durable_json(journal, record)
        checkpoint('copy_verified')
        if digest(original) != record['original_sha256']:
            raise RuntimeError('Original changed before publication')
        if not backup_valid:
            os.link(original, backup)
            fsync_directory(original.parent)
            checkpoint('backup_linked')
        record['original_backup'] = str(backup)
        record['status'] = 'backup_verified'
        durable_json(journal, record)
        checkpoint('backup_verified')
        os.replace(temporary, original)
        checkpoint('replaced')
        fsync_directory(original.parent)
        checkpoint('published')
    if digest(original) != wanted:
        raise RuntimeError('Published disk checksum mismatch; original backup retained')
    check_qcow(original)
    record.update({'status': 'persisted', 'original_backup': str(backup)})
    durable_json(journal, record)
    checkpoint('persisted_journal')
    # Publication is durably recoverable before deleting any RAM data. A retry
    # can complete from the journal plus verified disk/backup with no RAM file.
    if working.exists():
        if digest(working) != wanted:
            raise RuntimeError('Published disk verified, but RAM copy differs; retained for review')
        working.unlink()
        checkpoint('ram_unlinked')
    if directory.exists():
        directory.rmdir()
    checkpoint('ram_removed')
    temporary.unlink(missing_ok=True)
    return record
