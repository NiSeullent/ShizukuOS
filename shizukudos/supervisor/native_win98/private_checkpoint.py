# SPDX-License-Identifier: GPL-2.0-only
"""Private RAM disk checkpoint API; no CLI or native controller integration.

The caller retains its existing QEMU ownership and source read leases. This
module never starts/stops cleanup, resumes a guest, or rewrites an input/ESP.
See PRIVATE_CHECKPOINT.md for the required, still-unintegrated adapter contract.
"""
from dataclasses import dataclass
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import time

DISK_BYTES = 2 << 30
CHUNK_BYTES = 8 << 20
NAS_WORKSPACE = Path('/mnt/shizukuos-native-workspace-fada-20261001')
INFO_BYTES = 8192
INFO_BASE = 0x04000000
MAX_MAP_BYTES = 1 << 20
MAX_RECEIPT_BYTES = 1 << 20
MAX_CAPTURE_BYTES = 16 << 20
MAX_SOURCE_BYTES = 4 << 30
MAX_SOURCES = 512
U64_END = 1 << 64
REQUIRED_REFS = {'controller', 'qemu', 'ram_observation', 'info_header',
                 'info_parser', 'layout_receipt', 'budget', 'checkpoint_helper'}


@dataclass(frozen=True)
class ReadLease:
    name: str
    path: Path
    fd: int
    sha256: str
    bytes: int
    checkpoint: object


@dataclass(frozen=True)
class ControllerAdapter:
    call: object
    assert_owned: object
    observe_ram: object
    owner: dict
    sources: tuple
    references: dict
    info_module: object
    layout_bytes: int


@dataclass(frozen=True)
class Reservation:
    approved_lane: Path
    source_ref: str
    disk_bytes: int
    capture_bytes: int
    total_bytes: int
    retained_free_bytes: int
    timeout_seconds: int = 120


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('bounded integer required')
    return value


def _ranges(values):
    if not isinstance(values, (tuple, list)) or not 1 <= len(values) <= 128:
        raise ValueError('observed physical RAM ranges required')
    result = []
    for pair in values:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError('physical RAM range must be start/end')
        start, end = pair
        _integer(start, 0, U64_END - 1)
        _integer(end, start + 1, U64_END)
        if start % 4096 or end % 4096 or (result and start < result[-1][1]):
            raise ValueError('RAM ranges must be ordered, disjoint and page aligned')
        result.append((start, end))
    return tuple(result)


def _span(base, size, ranges, alignment=4096):
    _integer(base, 0x100000, U64_END - 1)
    _integer(size, 1, U64_END - base)
    if base % alignment or not any(start <= base and base + size <= end for start, end in ranges):
        raise ValueError('complete physical span is outside observed RAM')
    return base, base + size


def validate_info(raw, info_module, layout_bytes, ram_ranges):
    ranges = _ranges(ram_ranges)
    if len(raw) != INFO_BYTES or layout_bytes != ctypes.sizeof(info_module.Info):
        raise ValueError('exact current C/Python SHZ layout and full info capture required')
    info = info_module.Info.parse(raw)
    if (info.magic != 0x3031505553485A53 or info.version != 3 or info.size != layout_bytes or
            info.loader_flags != 1 or info.boot_path != 1 or info.disk_size != DISK_BYTES or
            info.guest_ram_size != 128 << 20 or info.region_base != INFO_BASE or
            info.region_size != 16 << 20 or info.k32_ram_size != 32 << 20 or
            info.k64_ram_size != 64 << 20 or info.ipc_size != 4 << 20 or
            info.stage not in (5, 6) or not info.hv_instance_id or
            not (info.cap_bits & (1 << 16))):
        raise ValueError('SHZ info differs from explicit native Win98 geometry/state')
    domain = info.domains[5]
    if domain.kind != 3 or not domain.generation or domain.state not in (1, 2, 3):
        raise ValueError('genuine active/exited Win98 domain record required')
    if info.stage == 6 and domain.state != 3:
        raise ValueError('finished Supervisor must have exited Win98')
    _integer(info.memmap_desc_size, 40, 256)
    if (info.memmap_desc_size % 8 or not 0 < info.memmap_bytes <= MAX_MAP_BYTES or
            info.memmap_bytes % info.memmap_desc_size):
        raise ValueError('bounded exact UEFI descriptor geometry required')
    disk = _span(info.disk_base, info.disk_size, ranges)
    regions = [_span(base, size, ranges) for base, size in
               ((info.region_base, info.region_size), (info.guest_ram_base, info.guest_ram_size),
                (info.k32_ram_base, info.k32_ram_size), (info.k64_ram_base, info.k64_ram_size),
                (info.ipc_base, info.ipc_size))]
    regions.append(_span(info.memmap_base, info.memmap_bytes, ranges, 8))
    rom_found = False
    for blob in info.blobs:
        if not blob.size and not blob.base:
            continue
        regions.append(_span(blob.base, blob.size, ranges))
        if blob.name == b'SEABIOS.BIN' and blob.size == 256 << 10:
            if rom_found:
                raise ValueError('duplicate SeaBIOS blob')
            rom_found = True
    if not rom_found:
        raise ValueError('exact SeaBIOS blob required')
    all_regions = [disk] + regions
    for index, (start, end) in enumerate(all_regions):
        if any(start < other_end and other_start < end for other_start, other_end in all_regions[index + 1:]):
            raise ValueError('disk/loader regions overlap')
    return info


def validate_loader_map(raw, stride, base, size):
    _integer(stride, 40, 256)
    if stride % 8 or not raw or len(raw) > MAX_MAP_BYTES or len(raw) % stride:
        raise ValueError('complete bounded UEFI memory map required')
    _integer(base, 0, U64_END - 1)
    _integer(size, 1, U64_END - base)
    entries = []
    for offset in range(0, len(raw), stride):
        kind = struct.unpack_from('<I', raw, offset)[0]
        physical = struct.unpack_from('<Q', raw, offset + 8)[0]
        pages = struct.unpack_from('<Q', raw, offset + 24)[0]
        if not pages or physical % 4096 or pages > (U64_END - physical) // 4096:
            raise ValueError('invalid UEFI physical descriptor extent')
        entries.append((physical, physical + pages * 4096, kind))
    entries.sort()
    if any(entries[index][0] < entries[index - 1][1] for index in range(1, len(entries))):
        raise ValueError('overlapping UEFI descriptors')
    position = base
    for start, end, kind in entries:
        if end <= position or start >= base + size:
            continue
        if start > position or kind != 2:  # EFI_LOADER_DATA, not arbitrary RAM/MMIO.
            raise ValueError('disk is not completely owned loader-data memory')
        position = min(end, base + size)
    if position != base + size:
        raise ValueError('loader memory map does not cover entire disk')


def _canonical(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('absolute paths without symlink parents required')
    return path.resolve()


def _stable(item):
    return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns


def _lease_check(source):
    source.checkpoint()  # Includes the controller's SIGIO break-request check.
    fd_stat = os.fstat(source.fd)
    path_stat = os.stat(source.path, follow_symlinks=False)
    if (not stat.S_ISREG(fd_stat.st_mode) or fd_stat.st_size != source.bytes or
            _stable(fd_stat) != _stable(path_stat) or
            fcntl.fcntl(source.fd, fcntl.F_GETLEASE) != fcntl.F_RDLCK or
            fcntl.fcntl(source.fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
        raise RuntimeError('source read lease, path identity or extent changed')


def _hash_fd(fd, expected_size, checkpoint):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
        raise RuntimeError('independent readback extent differs')
    digest = hashlib.sha256()
    position = 0
    while position < expected_size:
        checkpoint()
        block = os.pread(fd, min(1 << 20, expected_size - position), position)
        if not block:
            raise RuntimeError('short independent readback')
        digest.update(block)
        position += len(block)
    checkpoint()
    if os.pread(fd, 1, expected_size) or _stable(before) != _stable(os.fstat(fd)):
        raise RuntimeError('independent readback changed during hashing')
    return digest.hexdigest()


def _write_all(fd, payload):
    view = memoryview(payload)
    while view:
        count = os.write(fd, view)
        if not count:
            raise OSError('short private checkpoint write')
        view = view[count:]


def _create(directory, name):
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextlib.contextmanager
def _read_lease(fd):
    """Hold output against writers while preserving the caller's SIGIO handling."""
    previous, broken, leased = signal.getsignal(signal.SIGIO), [False], False

    def notified(signum, frame):
        broken[0] = True
        if callable(previous):
            previous(signum, frame)

    try:
        signal.signal(signal.SIGIO, notified)
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        leased = True

        def check():
            if broken[0] or fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_RDLCK:
                raise RuntimeError('private output read lease was broken')

        check()
        yield check
        check()
    finally:
        try:
            if leased:
                fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        finally:
            signal.signal(signal.SIGIO, previous)


def _pinned_file(fd, directory, name, expected):
    current = os.fstat(fd)
    path = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (_stable(current) != expected or _stable(path) != expected or
            not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or
            current.st_mode & 0o777 != 0o600 or current.st_uid != os.getuid()):
        raise RuntimeError('private published file identity/extent/privacy changed')


def _link_fd(fd, directory, name):
    # Linux linkat follows this procfs descriptor reference to the held inode.
    # A removed/replaced partial pathname cannot supply a different inode.
    os.link('/proc/self/fd/%d' % fd, name, dst_dir_fd=directory, follow_symlinks=True)


def _invalidate_receipt(directory, identity):
    """Best-effort removal of only the receipt inode this producer published."""
    if identity is None:
        return
    try:
        current = os.stat('checkpoint.json', dir_fd=directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == identity:
            os.unlink('checkpoint.json', dir_fd=directory)
            os.fsync(directory)
    except OSError:
        pass


def _invalidate_closed_directory(out, directory_identity, receipt_identity):
    # Linux close errors may already have consumed the fd: reopen the same owned
    # directory, never retry close on a possibly reused descriptor.
    if receipt_identity is None:
        return
    cleanup = None
    try:
        cleanup = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        current = os.fstat(cleanup)
        if (current.st_dev, current.st_ino) == directory_identity:
            _invalidate_receipt(cleanup, receipt_identity)
    except OSError:
        pass
    finally:
        if cleanup is not None:
            try:
                os.close(cleanup)
            except OSError:
                pass


def _dump(adapter, out, directory, name, address, size, guard):
    if not 0 < size <= MAX_CAPTURE_BYTES:
        raise ValueError('one QMP capture exceeds unchanged 16 MiB bound')
    fd = _create(directory, name)
    try:
        identity = os.fstat(fd)
        guard()
        adapter.call('pmemsave', {'val': address, 'size': size, 'filename': str(out / name)})
        guard()
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if ((identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino) or
                not stat.S_ISREG(current.st_mode) or current.st_size != size or current.st_nlink != 1 or
                current.st_mode & 0o777 != 0o600 or current.st_uid != os.getuid()):
            raise RuntimeError('QMP capture path, extent or privacy changed')
        os.fsync(fd)
        data = os.pread(fd, size, 0)
        if len(data) != size:
            raise RuntimeError('short physical capture readback')
        if (_hash_fd(fd, size, guard) != hashlib.sha256(data).hexdigest() or
                _stable(current) != _stable(os.fstat(fd))):
            raise RuntimeError('physical capture independent readback changed')
        return data
    finally:
        os.close(fd)


def _publish_receipt(directory, record, guard):
    payload = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
    if len(payload) > MAX_RECEIPT_BYTES:
        raise RuntimeError('private checkpoint receipt exceeds reserved bound')
    fd = _create(directory, 'checkpoint.json.partial')
    try:
        _write_all(fd, payload)
        os.fsync(fd)
        if os.pread(fd, len(payload) + 1, 0) != payload:
            raise RuntimeError('receipt independent readback differs')
        written = _stable(os.fstat(fd))
    finally:
        os.close(fd)
    fd = os.open('checkpoint.json.partial', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory)
    linked_identity = None
    try:
        _pinned_file(fd, directory, 'checkpoint.json.partial', written)
        with _read_lease(fd) as leased:
            guard()
            leased()
            _pinned_file(fd, directory, 'checkpoint.json.partial', written)
            if os.pread(fd, len(payload) + 1, 0) != payload:
                raise RuntimeError('leased receipt serialization differs')
            verified_identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
            _link_fd(fd, directory, 'checkpoint.json')
            linked_identity = verified_identity
            os.unlink('checkpoint.json.partial', dir_fd=directory)
            published = _stable(os.fstat(fd))

            def check():
                leased()
                _pinned_file(fd, directory, 'checkpoint.json', published)
                if os.pread(fd, len(payload) + 1, 0) != payload:
                    raise RuntimeError('canonical receipt serialization differs')

            guard()
            check()
            os.fsync(directory)  # Success receipt is the last durable publication.
            guard()
            check()
        consumed, fd = fd, None
        os.close(consumed)
        return linked_identity
    except BaseException:
        _invalidate_receipt(directory, linked_identity)
        raise
    finally:
        if fd is not None:
            os.close(fd)


def capture_private_checkpoint(adapter, reservation, out):
    """Capture a fresh private 2 GiB raw disk; caller retains all VM/lease ownership.

    Every error raises and leaves partial private files unaccepted. No success
    receipt means no accepted checkpoint. This API never releases source leases.
    """
    lane, out = _canonical(reservation.approved_lane), _canonical(out)
    workspace = _canonical(NAS_WORKSPACE)
    if (workspace not in lane.parents or lane not in out.parents or out.exists() or
            not out.parent.is_dir() or not lane.is_dir()):
        raise ValueError('fresh output in the explicitly approved private NAS lane required')
    for directory in (lane, out.parent):
        item = directory.stat()
        if item.st_uid != os.getuid() or item.st_mode & 0o777 != 0o700:
            raise ValueError('approved lane/output parent must be owned mode 0700')
    _integer(reservation.timeout_seconds, 1, 900)
    minimum = CHUNK_BYTES + MAX_MAP_BYTES + MAX_RECEIPT_BYTES + 2 * INFO_BYTES
    if (reservation.disk_bytes != DISK_BYTES or
            not minimum <= reservation.capture_bytes <= MAX_CAPTURE_BYTES or
            reservation.total_bytes != reservation.disk_bytes + reservation.capture_bytes or
            reservation.retained_free_bytes < 17 << 30):
        raise ValueError('separate exact disk/capture reservation and unchanged 17 GiB floor required')
    if not isinstance(adapter.sources, tuple) or not 1 <= len(adapter.sources) <= MAX_SOURCES:
        raise ValueError('bounded held source references required')
    sources = {}
    for source in adapter.sources:
        _integer(source.fd, 0, 1 << 31)
        _integer(source.bytes, 1, MAX_SOURCE_BYTES)
        if (source.name in sources or not isinstance(source.name, str) or not source.name or
                not re.fullmatch('[0-9a-f]{64}', source.sha256)):
            raise ValueError('unique exact source identity pins required')
        if _canonical(source.path) != source.path:
            raise ValueError('canonical leased source path required')
        _lease_check(source)
        sources[source.name] = source
    if (set(adapter.references) != REQUIRED_REFS or
            any(name not in sources for name in adapter.references.values()) or
            reservation.source_ref != adapter.references['budget']):
        raise ValueError('explicit controller/QEMU/layout/RAM/budget/helper source references required')
    for reference, actual in (('info_parser', Path(adapter.info_module.__file__).resolve()),
                              ('checkpoint_helper', Path(__file__).resolve())):
        if sources[adapter.references[reference]].path != actual:
            raise ValueError('loaded parser/helper differs from its leased source reference')
    baseline = json.loads(json.dumps(adapter.owner))
    if set(baseline) != {'pid', 'starttime', 'cmdline_sha256', 'qmp_peer_pid', 'qmp_peer_uid'}:
        raise ValueError('exact owned process/socket identity required')
    _integer(baseline['pid'], 1, 1 << 31)
    _integer(baseline['starttime'], 1, U64_END - 1)
    if (baseline['qmp_peer_pid'] != baseline['pid'] or baseline['qmp_peer_uid'] != os.getuid() or
            not re.fullmatch('[0-9a-f]{64}', baseline['cmdline_sha256'])):
        raise ValueError('owned Popen process and current QMP peer must agree')
    deadline = time.monotonic() + reservation.timeout_seconds
    ram = adapter.observe_ram()
    if (set(ram) != {'ranges', 'source_ref', 'qemu_ref'} or
            ram['source_ref'] != adapter.references['ram_observation'] or
            ram['qemu_ref'] != adapter.references['qemu']):
        raise ValueError('physical RAM observation must reference this owned QEMU/source')
    ranges = _ranges(ram['ranges'])
    ram_baseline = {'ranges': ranges, 'source_ref': ram['source_ref'], 'qemu_ref': ram['qemu_ref']}
    directory = None
    raw_fd = None
    raw_read_fd = None
    raw_pin = None
    receipt_identity = None
    output_leases = contextlib.ExitStack()
    written = 0

    def guard():
        if time.monotonic() >= deadline:
            raise TimeoutError('bounded private checkpoint deadline exceeded')
        if adapter.assert_owned() != baseline:
            raise RuntimeError('owned process/socket identity drift')
        current_ram = adapter.observe_ram()
        current_ram = {**current_ram, 'ranges': _ranges(current_ram['ranges'])}
        if current_ram != ram_baseline:
            raise RuntimeError('owned physical RAM observation drift')
        for source in sources.values():
            _lease_check(source)
        if raw_pin is not None:
            fd, expected, leased = raw_pin
            leased()
            _pinned_file(fd, directory, 'checkpoint.raw', expected)
        capture_used = 0
        if directory is not None:
            item = os.fstat(directory)
            current = os.stat(out, follow_symlinks=False)
            if (item.st_dev, item.st_ino) != (current.st_dev, current.st_ino) or current.st_mode & 0o777 != 0o700:
                raise RuntimeError('private output directory identity/privacy changed')
            for name in os.listdir(directory):
                item = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(item.st_mode):
                    raise RuntimeError('unexpected non-regular private output')
                if name not in ('checkpoint.raw.partial', 'checkpoint.raw'):
                    if item.st_size > MAX_CAPTURE_BYTES:
                        raise RuntimeError('one helper capture exceeded its reserved extent')
                    capture_used += item.st_size
            if capture_used > reservation.capture_bytes:
                raise RuntimeError('separate helper capture reservation exceeded')
        remaining = DISK_BYTES - written + max(0, reservation.capture_bytes - capture_used)
        if shutil.disk_usage(lane).free < reservation.retained_free_bytes + remaining:
            raise RuntimeError('live retained reserve/remaining checkpoint budget unavailable')

    def source_hashes():
        result = {}
        for name, source in sources.items():
            result[name] = _hash_fd(source.fd, source.bytes, guard)
            if result[name] != source.sha256:
                raise RuntimeError('source SHA differs before/after checkpoint')
        return result

    guard()
    before = source_hashes()
    guard()
    out.mkdir(mode=0o700)
    directory = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directory_stat = os.fstat(directory)
    directory_identity = (directory_stat.st_dev, directory_stat.st_ino)
    try:
        guard()
        adapter.call('stop')
        guard()

        def paused():
            guard()
            status = adapter.call('query-status')
            if not isinstance(status, dict) or status.get('running') is not False or status.get('status') != 'paused':
                raise RuntimeError('stop must acknowledge and current QMP state must be paused')
            guard()

        paused()
        raw_info = _dump(adapter, out, directory, 'info-before.bin', INFO_BASE, INFO_BYTES, guard)
        info = validate_info(raw_info, adapter.info_module, adapter.layout_bytes, ranges)
        memory_map = _dump(adapter, out, directory, 'loader-map.bin', info.memmap_base, info.memmap_bytes, guard)
        validate_loader_map(memory_map, info.memmap_desc_size, info.disk_base, info.disk_size)
        raw_fd = _create(directory, 'checkpoint.raw.partial')
        digest = hashlib.sha256()
        chunks = []
        while written < DISK_BYTES:
            paused()
            size = min(CHUNK_BYTES, DISK_BYTES - written)
            name = 'chunk-%03d.bin' % len(chunks)
            data = _dump(adapter, out, directory, name, info.disk_base + written, size, guard)
            _write_all(raw_fd, data)
            digest.update(data)
            chunks.append({'offset': written, 'bytes': size, 'sha256': hashlib.sha256(data).hexdigest()})
            written += size
            os.unlink(name, dir_fd=directory)
            guard()
        os.fsync(raw_fd)
        expected_sha = digest.hexdigest()
        if _hash_fd(raw_fd, DISK_BYTES, guard) != expected_sha:
            raise RuntimeError('complete disk independent readback SHA differs')
        verified_raw_stat = os.fstat(raw_fd)
        paused()
        final_info = _dump(adapter, out, directory, 'info-after.bin', INFO_BASE, INFO_BYTES, guard)
        if final_info != raw_info:
            raise RuntimeError('paused current SHZ information changed during capture')
        after = source_hashes()
        guard()
        if after != before:
            raise RuntimeError('source before/after identity differs')
        raw_stat = os.fstat(raw_fd)
        raw_path_stat = os.stat('checkpoint.raw.partial', dir_fd=directory, follow_symlinks=False)
        if (_stable(verified_raw_stat) != _stable(raw_stat) or
                _stable(raw_stat) != _stable(raw_path_stat) or raw_stat.st_nlink != 1 or
                raw_stat.st_mode & 0o777 != 0o600 or raw_stat.st_size != DISK_BYTES):
            raise RuntimeError('complete checkpoint path/extent/privacy changed')
        consumed, raw_fd = raw_fd, None
        os.close(consumed)
        raw_read_fd = os.open('checkpoint.raw.partial', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=directory)
        _pinned_file(raw_read_fd, directory, 'checkpoint.raw.partial', _stable(raw_stat))
        raw_leased = output_leases.enter_context(_read_lease(raw_read_fd))
        if _hash_fd(raw_read_fd, DISK_BYTES, guard) != expected_sha:
            raise RuntimeError('leased complete disk independent SHA differs')
        raw_leased()
        _pinned_file(raw_read_fd, directory, 'checkpoint.raw.partial', _stable(raw_stat))
        _link_fd(raw_read_fd, directory, 'checkpoint.raw')
        os.unlink('checkpoint.raw.partial', dir_fd=directory)
        raw_pin = (raw_read_fd, _stable(os.fstat(raw_read_fd)), raw_leased)
        guard()
        os.fsync(directory)
        guard()
        record = {'schema': 'shizuku.private-ram-checkpoint.v1',
                  'status': 'PASS_PRIVATE_RAM_CHECKPOINT_HOST_PRODUCER_ONLY', 'private': True,
                  'controller_adapter_runtime_integration': False, 'VM_verified': False,
                  'Windows98_boot_verified': False, 'clean_shutdown_verified': False,
                  'cold_boot_persistence_verified': False, 'live_storage_flush_verified': False,
                  'scope': 'unintegrated owned-controller RAM checkpoint; no Windows/native acceptance',
                  'owner': baseline, 'physical_RAM_observation': {**ram_baseline, 'ranges': [list(pair) for pair in ranges]},
                  'source_references': dict(adapter.references),
                  'sources': {name: {'path': str(source.path), 'bytes': source.bytes, 'sha256': source.sha256}
                              for name, source in sources.items()},
                  'source_before_after_match': before == after, 'current_info_before_after_match': True,
                  'info_sha256': hashlib.sha256(raw_info).hexdigest(),
                  'loader_map_sha256': hashlib.sha256(memory_map).hexdigest(),
                  'hv_instance_id': info.hv_instance_id, 'WIN98_generation': info.domains[5].generation,
                  'disk': {'path': str(out / 'checkpoint.raw'), 'physical_base': info.disk_base,
                           'bytes': DISK_BYTES, 'sha256': expected_sha, 'independent_readback_verified': True,
                           'read_lease_through_receipt_publication': True},
                  'chunks': chunks, 'reservation': {'source_ref': reservation.source_ref,
                      'disk_bytes': reservation.disk_bytes, 'capture_bytes': reservation.capture_bytes,
                      'total_bytes': reservation.total_bytes, 'retained_free_bytes': reservation.retained_free_bytes,
                      'timeout_seconds': reservation.timeout_seconds}}
        receipt_identity = _publish_receipt(directory, record, guard)
        return record
    except BaseException:
        _invalidate_receipt(directory, receipt_identity)
        raise
    finally:
        failure = None
        try:
            if raw_pin is not None:
                fd, expected, leased = raw_pin
                leased()
                _pinned_file(fd, directory, 'checkpoint.raw', expected)
        except BaseException as error:
            failure = error
        try:
            output_leases.close()
        except BaseException as error:
            failure = failure or error
        for fd in (raw_fd, raw_read_fd, directory):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    failure = failure or error
        if failure is not None:
            _invalidate_closed_directory(out, directory_identity, receipt_identity)
            raise failure
