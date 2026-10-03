#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Prepare a private replacement-DOS disk; never execute or attest Windows boot."""
import argparse
import contextlib
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
import subprocess
import tempfile

FLOOR = 17 << 30
MAX_DISK = 8 << 30
LANE = Path('/root/_drive/0001/volume1/working_stuff_by_nyase/root6970/replacement')
KERNEL_COMMIT = '5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3'
FREECOM_COMMIT = '04fc21a9f6792abe9048598e8f2d048b4f6cd0e5'
SYS_SHA = 'b8737d520d9c35fdbefadbea213c3528800a18f2580a70afb7f620cba6c59f59'
BOOT_SOURCE_SHA = {'boot.asm': '5ac89704061cc0f27a9cb58706f05be37cc6515a9ea3d465f31850b0c400201c',
                   'boot32lb.asm': '7ca6b5e5b63ef5486acd77e3428d7d02ed11531774218a5ff16f43a9c8014fdc',
                   'magic.mac': '1bd189937f73fb87c239e54a89db57038f8d3a2cbd6b465b7f21327211ed9b9d'}


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(value):
    raw = Path(value)
    need(raw.is_absolute() and not any(c in str(raw) for c in ('@', ':', '\n', '\r', '\0')),
         'absolute path without mtools image syntax required')
    need(raw.resolve() == raw and not any(p.is_symlink() for p in (raw, *raw.parents)), 'canonical nonsymlink path required')
    need(not any(raw == p or p in raw.parents for p in map(Path, ('/dev', '/proc', '/sys', '/srv/m98'))),
         'device, virtual and public origin paths refused')
    return raw


def private_output(path):
    for root in path.parents:
        if not (root/'.git').exists():
            continue
        need(path.relative_to(root).parts[0] == 'build', 'private output outside visible Git source required')
        ignored = subprocess.run(['git','-C',str(root),'check-ignore','--no-index','--quiet','--',str(path)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, timeout=10)
        need(ignored.returncode == 0, 'private build output must be ignored by Git')
        return


def large_output_scope(out, disk_bytes, explicit_root=None):
    """Select a private work area without weakening copy/lease/capacity rules."""
    if explicit_root is not None:
        root = safe_path(explicit_root)
        private_output(root/'output-policy-probe')
        st = root.stat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
             stat.S_IMODE(st.st_mode) == 0o700,
             'explicit large-output root must be an existing owned mode-0700 directory')
        need(out != root and out.is_relative_to(root),
             'fresh output must be strictly below the explicit private root')
        return {'kind':'explicit-owned-private-root','path':str(root),
                'device':st.st_dev,'inode':st.st_ino}
    need(disk_bytes <= 64 << 20 or out.is_relative_to(LANE),
         'large private copies require the reserved NAS lane or an explicit owned private root')
    return {'kind':'small-control' if disk_bytes <= 64 << 20 else 'reserved-NAS-lane',
            'path':None if disk_bytes <= 64 << 20 else str(LANE)}


def check_output_scope(scope):
    if scope['kind'] != 'explicit-owned-private-root':
        return
    root = safe_path(scope['path']); st = root.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700 and
         (st.st_dev,st.st_ino) == (scope['device'],scope['inode']),
         'explicit private output root identity/permissions changed')


def pin_fields(row):
    need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'}, 'exact file pin required')
    path = safe_path(row['path'])
    need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_DISK, 'bounded literal input size required')
    need(isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']) and row['sha256'] != '0'*64,
         'literal nonzero SHA256 required')
    return path


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def hash_fd(fd, size, checkpoint=lambda: None):
    h, at = hashlib.sha256(), 0
    while at < size:
        block = os.pread(fd, min(1 << 20, size-at), at)
        need(block, 'short input read')
        checkpoint(); h.update(block); at += len(block)
    checkpoint()
    return h.hexdigest()


class LeaseRegistry(dict):
    """Entries remain pinned while further reviewed source inputs are admitted."""
    pass


@contextlib.contextmanager
def leased_inputs(rows):
    """One SIGIO handler protects all simultaneous actual Linux read leases."""
    previous, broken, entries = signal.getsignal(signal.SIGIO), [False], LeaseRegistry()
    signal.signal(signal.SIGIO, lambda *_: broken.__setitem__(0, True))
    def add_inputs(rows):
        for row in rows:
            path = pin_fields(row)
            if str(path) in entries:
                need(entries[str(path)]['pin'] == row, 'conflicting duplicate source pin')
                continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                before = os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and before.st_size == row['bytes'], 'pinned regular input extent required')
                fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
                fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            except BaseException:
                os.close(fd); raise
            def checkpoint(fd=fd, path=path, before=before):
                if broken[0] or fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_RDLCK or identity(os.fstat(fd)) != identity(before) or identity(path.stat()) != identity(before):
                    raise RuntimeError('source read lease or identity changed')
            entries[str(path)] = {'fd': fd, 'pin': dict(row), 'identity': identity(before), 'checkpoint': checkpoint}
            need(hash_fd(fd, row['bytes'], checkpoint) == row['sha256'], 'pinned source SHA mismatch')
    entries.add_inputs = add_inputs
    try:
        add_inputs(rows)
        yield entries
        for entry in entries.values(): entry['checkpoint']()
    finally:
        for entry in entries.values():
            try: fcntl.fcntl(entry['fd'], fcntl.F_SETLEASE, fcntl.F_UNLCK)
            finally: os.close(entry['fd'])
        signal.signal(signal.SIGIO, previous)


def u16(data, at): return struct.unpack_from('<H', data, at)[0]
def u32(data, at): return struct.unpack_from('<I', data, at)[0]


def inspect_geometry(mbr, vbr, disk_bytes):
    need(type(disk_bytes) is int and 1024 <= disk_bytes <= MAX_DISK and disk_bytes % 512 == 0, 'bounded whole-sector disk required')
    need(len(mbr) == len(vbr) == 512 and mbr[510:] == vbr[510:] == b'\x55\xaa', 'signed MBR and VBR required')
    entries = []
    for n in range(4):
        row = mbr[446+n*16:462+n*16]
        flag, kind, start, count = row[0], row[4], u32(row, 8), u32(row, 12)
        need(flag in (0, 0x80), 'invalid MBR active flag')
        if not kind:
            need(row == bytes(16), 'empty partition contains metadata'); continue
        need(kind not in (5, 0x0f, 0x85, 0xee) and start and count and start+count <= disk_bytes//512 and start+count <= 1 << 32,
             'unsupported or out-of-bounds primary partition')
        entries.append((flag, kind, start, count))
    for n, left in enumerate(entries):
        for right in entries[n+1:]:
            need(left[2]+left[3] <= right[2] or right[2]+right[3] <= left[2], 'overlapping partitions refused')
    active = [row for row in entries if row[0] == 0x80]
    need(len(active) == 1, 'exactly one active partition required')
    _, part_kind, start, count = active[0]
    spc, reserved, fats, roots = vbr[13], u16(vbr, 14), vbr[16], u16(vbr, 17)
    need(u16(vbr, 11) == 512 and 1 <= spc <= 128 and not spc & (spc-1), '512-byte sectors and power-of-two cluster size required')
    need(reserved and fats in (1, 2) and vbr[21] == 0xf8 and u32(vbr, 28) == start, 'invalid FAT geometry or hidden-sector origin')
    small_total, large_total = u16(vbr, 19), u32(vbr, 32)
    need(bool(small_total) != bool(large_total), 'one authoritative volume sector count required')
    total = small_total or large_total
    fat_sectors = u16(vbr, 22) or u32(vbr, 36)
    root_sectors = (roots*32+511)//512
    first_data = reserved + fats*fat_sectors + root_sectors
    need(fat_sectors and first_data < total <= count, 'volume or FAT extent exceeds partition')
    clusters = (total-first_data)//spc
    bits = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
    need(clusters > 0 and clusters+1 < (0xff0 if bits == 12 else 0xfff0 if bits == 16 else 0xffffff0), 'reserved cluster range refused')
    capacity = (clusters+2)*3//2 + (clusters+2)%2 if bits == 12 else (clusters+2)*(bits//8)
    need(capacity <= fat_sectors*512 and fat_sectors*512 <= 32 << 20, 'FAT capacity cannot address volume')
    backup, fsinfo, root_cluster = None, None, None
    if bits == 32:
        need(part_kind in (0x0b, 0x0c) and not roots and not u16(vbr, 22) and not small_total and u16(vbr, 42) == 0,
             'FAT32 partition/BPB type differs from cluster count')
        flags = u16(vbr, 40)
        need(flags in (0, 0x80), 'only mirrored FATs or first active FAT supported')
        backup, fsinfo, root_cluster = u16(vbr, 50), u16(vbr, 48), u32(vbr, 44)
        need(1 <= backup < reserved and 1 <= fsinfo < reserved and backup != fsinfo and 2 <= root_cluster <= clusters+1,
             'FAT32 backup/FSInfo/root bounds invalid')
    else:
        need(part_kind in ({1} if bits == 12 else {4, 6, 0x0e}) and roots and u16(vbr, 22), 'FAT12/16 partition/BPB type differs from cluster count')
    return {'fat_bits': bits, 'start_lba': start, 'partition_sectors': count, 'total_sectors': total,
            'spc': spc, 'reserved': reserved, 'fats': fats, 'fat_sectors': fat_sectors,
            'root_entries': roots, 'root_sectors': root_sectors, 'root_cluster': root_cluster,
            'clusters': clusters, 'first_data': start+first_data, 'backup_sector': backup, 'fsinfo_sector': fsinfo}


def compose_boot(vbr, template, kind, geometry):
    bits = geometry['fat_bits']
    need(kind == {12: 'fat12com', 16: 'fat16com', 32: 'fat32lba'}[bits], 'declared template kind differs from FAT geometry')
    need(len(template) == 512 and template[510:] == b'\x55\xaa', 'signed source-built template required')
    offset, drive, end = (0x78, 0x82, 90) if bits == 32 else (0x5c, 0x66, 62)
    need(u16(template, offset) == 0x60 and template[drive:drive+3] == bytes((0x88, 0x56, 0x40 if bits == 32 else 0x24)) and
         template[0x1f1:0x1fc] == b'KERNEL  SYS', 'ke2046 template load segment/drive/name magic differs')
    boot = bytearray(template)
    boot[11:end] = vbr[11:end]
    boot[3:11] = b'FRDOS5.1'
    boot[64 if bits == 32 else 36] = 0x80
    # Keep actual DL capture enabled, exactly as SYS with ignoreBIOS false.
    return bytes(boot)


def available_bytes(path): return shutil.disk_usage(path).free


def capacity(path, remaining, capture_budget):
    need(type(capture_budget) is int and 1 << 20 <= capture_budget <= 1 << 30, 'explicit bounded future capture budget required')
    if available_bytes(path) < FLOOR + capture_budget + remaining:
        raise RuntimeError('17 GiB floor plus capture and remaining copy budget unavailable')


def copy_disk(source, target, mode, copy_budget, capture_budget):
    target = safe_path(target)
    need(mode in ('full', 'reflink') and type(copy_budget) is int and copy_budget >= 0, 'explicit copy mode/budget required')
    size, check = source['pin']['bytes'], source['checkpoint']
    if target.exists(): raise FileExistsError(target)
    need(mode != 'full' or copy_budget >= size, 'explicit full-copy logical-byte budget too small')
    capacity(target.parent, size if mode == 'full' else 16 << 20, capture_budget)
    owned, copy_stats = False, {}
    try:
        fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        owned = True
        try:
            check()
            if mode == 'reflink':
                fcntl.ioctl(fd, 0x40049409, source['fd'])  # FICLONE; never fallback.
            else:
                at, zero_bytes, data_bytes = 0, 0, 0
                while at < size:
                    block = os.pread(source['fd'], min(1 << 20, size-at), at)
                    need(block, 'source ended during full copy'); check()
                    capacity(target.parent, size-at, capture_budget)
                    if block.count(0) == len(block):
                        # Read bytes, never filesystem hole/extent metadata, decide
                        # whether a whole chunk can remain unwritten in this new inode.
                        need(os.lseek(fd,len(block),os.SEEK_CUR) == at+len(block), 'destination zero-chunk seek differs')
                        zero_bytes += len(block)
                    else:
                        written = 0
                        while written < len(block):
                            n = os.write(fd, block[written:]); need(n > 0, 'zero destination write'); written += n
                        data_bytes += written
                    at += len(block); check()
                # A seek alone does not establish an all-zero or trailing-zero extent.
                os.ftruncate(fd,size)
                copy_stats = {'source_bytes_read':at, 'zero_bytes_omitted':zero_bytes, 'data_bytes_written':data_bytes}
            os.fsync(fd); check()
            need(os.fstat(fd).st_size == size and identity(os.fstat(fd))[:2] != source['identity'][:2], 'independent complete destination required')
            need(hash_fd(fd, size, check) == source['pin']['sha256'], 'destination readback SHA mismatch')
            allocated = os.fstat(fd).st_blocks*512
        finally: os.close(fd)
        capacity(target.parent, 0, capture_budget); check()
        return {'method': 'explicit-full-copy' if mode == 'full' else 'mandatory-FICLONE', 'bytes': size,
                'sha256': source['pin']['sha256'], 'allocated_bytes': allocated,
                'destination_readback_verified': True, 'source_lease_preserved': True, **copy_stats}
    except BaseException:
        if owned: target.unlink()
        raise


class Volume:
    """Bounded independent FAT12/16/32 reader for private logical-file readback."""
    def __init__(self, fd, geometry, checkpoint=lambda: None):
        self.fd, self.g, self.check = fd, geometry, checkpoint
        self.cluster_bytes = geometry['spc']*512
        at = (geometry['start_lba']+geometry['reserved'])*512
        self.fat = self.read(at, geometry['fat_sectors']*512)
        if geometry['fats'] == 2:
            flags = u16(self.read(geometry['start_lba']*512, 512), 40) if geometry['fat_bits'] == 32 else 0
            if not flags & 0x80:
                need(self.read(at+len(self.fat), len(self.fat)) == self.fat, 'mirrored FAT copies differ')
        need(self.fat[0] == 0xf8, 'FAT media byte differs from BPB')
        self.used = set()

    def read(self, at, count):
        self.check()
        need(0 <= at and 0 <= count and at+count <= (self.g['start_lba']+self.g['total_sectors'])*512, 'FAT read extent out of bounds')
        data = os.pread(self.fd, count, at)
        need(len(data) == count, 'short FAT extent read'); self.check()
        return data

    def chain(self, start):
        chain, bits = [], self.g['fat_bits']
        end = 0xff8 if bits == 12 else 0xfff8 if bits == 16 else 0xffffff8
        need(2 <= start <= self.g['clusters']+1, 'invalid FAT chain start cluster')
        current = start
        while current < end:
            need(2 <= current <= self.g['clusters']+1 and current not in self.used, 'cyclic, crosslinked or invalid FAT cluster chain')
            self.used.add(current); chain.append(current)
            if bits == 12:
                pair = u16(self.fat, current+current//2)
                current = pair >> 4 if current & 1 else pair & 0xfff
            elif bits == 16: current = u16(self.fat, current*2)
            else: current = u32(self.fat, current*4) & 0xfffffff
        return chain

    def cluster(self, number):
        return self.read((self.g['first_data']+(number-2)*self.g['spc'])*512, self.cluster_bytes)

    def file(self, cluster, size, destination=None):
        need(type(size) is int and 0 <= size <= MAX_DISK, 'bounded FAT member length required')
        chain = self.chain(cluster) if cluster else []
        need(len(chain)*self.cluster_bytes >= size, 'FAT chain shorter than member')
        h, remaining = hashlib.sha256(), size
        for number in chain:
            block = self.cluster(number)[:remaining]
            h.update(block)
            if destination is not None and block:
                need(destination.write(block) == len(block), 'short private member backup write')
            remaining -= len(block)
        return h.hexdigest()


def inventory(fd, geometry, checkpoint=lambda: None):
    volume, records = Volume(fd, geometry, checkpoint), {}
    def directory(path, cluster, depth):
        need(depth <= 32, 'FAT directory nesting exceeds bound')
        if cluster:
            chunks = (volume.cluster(n) for n in volume.chain(cluster))
        else:
            chunks = [volume.read((geometry['start_lba']+geometry['reserved']+geometry['fats']*geometry['fat_sectors'])*512,
                                  geometry['root_sectors']*512)]
        pending = bytearray()
        for block in chunks:
            for at in range(0, len(block), 32):
                row = block[at:at+32]
                if row[0] == 0: return
                if row[0] == 0xe5: pending.clear(); continue
                if row[11] == 15:
                    need(len(pending) < 20*32, 'unbounded LFN sequence'); pending.extend(row); continue
                if row[11] & 8 or row[:11] in (b'.          ', b'..         '): pending.clear(); continue
                base = row[:8].rstrip(b' ').decode('cp437')
                extension = row[8:11].rstrip(b' ').decode('cp437')
                name = path+base+('.'+extension if extension else '')
                need(name not in records and len(name) <= 1024 and len(records) < 30000, 'duplicate or unbounded FAT member paths')
                number = u16(row, 26) | ((u16(row, 20) << 16) if geometry['fat_bits'] == 32 else 0)
                meta = digest(bytes(pending)+row); pending.clear()
                if row[11] & 16:
                    need(number >= 2, 'invalid directory start cluster')
                    records[name] = {'directory': True, 'metadata_sha256': meta}
                    directory(name+'/', number, depth+1)
                else:
                    size = u32(row, 28)
                    records[name] = {'bytes': size, 'sha256': volume.file(number, size), 'metadata_sha256': meta,
                                     'cluster': number}
    directory('', geometry['root_cluster'] or 0, 0)
    return records


def json_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key refused'); result[key] = value
    return result


def bounded_json(entry):
    need(entry['pin']['bytes'] <= 1 << 20, 'bounded profile/build receipt required')
    entry['checkpoint']()
    data = os.pread(entry['fd'], entry['pin']['bytes'], 0)
    need(digest(data) == entry['pin']['sha256'], 'JSON input SHA changed')
    return json.loads(data, object_pairs_hook=json_pairs)


def local_pin(path, expected=None):
    path = safe_path(path)
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 << 20, 'bounded source regular file required')
    with path.open('rb') as handle: sha = hash_fd(handle.fileno(), before.st_size)
    need(identity(before) == identity(path.stat()), 'source changed while pinning')
    need(expected is None or sha == expected, 'recorded build/upstream source SHA differs')
    return {'path': str(path), 'bytes': before.st_size, 'sha256': sha}


def recorded_pin(path, sha):
    need(isinstance(sha,str) and re.fullmatch('[0-9a-f]{64}',sha) and sha != '0'*64,
         'recorded literal nonzero source SHA256 required')
    return local_pin(path, sha)


def source_name(name, root):
    need(isinstance(name, str) and name and '\\' not in name and '..' not in Path(name).parts and
         not Path(name).is_absolute() and str(Path(name)) == name, 'safe recorded source-relative path required')
    return root/name


def run_tool(name, args, commands, cwd=None):
    executable = shutil.which(name)
    need(executable, 'required tool unavailable: '+name)
    literal, binary = Path(executable).absolute(), Path(executable).resolve(strict=True)
    pin = local_pin(binary)
    argv = [str(literal), *map(str, args)]
    commands.append({'argv': argv, 'executable': pin})
    subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, check=True, timeout=120)
    need(literal.resolve(strict=True) == binary and local_pin(binary) == pin, 'tool executable identity changed')


def verify_template(upstream, kind, template, commands):
    filename = 'boot32lb.asm' if kind == 'fat32lba' else 'boot.asm'
    defines = ['-dISFAT12'] if kind == 'fat12com' else ['-dISFAT16'] if kind == 'fat16com' else []
    with tempfile.TemporaryDirectory(prefix='shz-boot-source-') as temp:
        target = Path(temp)/'boot.bin'
        run_tool('nasm', ['-f','bin','-DXCPU=386',*defines,'-o',target,upstream/'boot'/filename], commands, cwd=upstream/'boot')
        need(target.stat().st_size == 512 and target.read_bytes() == template, 'boot template differs from actual pinned source assembly')


def prepare(profile_path, profile_sha, out, mode, copy_budget, capture_budget, *, validate_only=False, large_output_root=None):
    profile_path, out = safe_path(profile_path), safe_path(out)
    private_output(out)
    if out.exists() or out.is_symlink(): raise FileExistsError(out)
    need(out.parent.is_dir(), 'fresh owned output parent required')
    need(mode in ('full','reflink') and type(copy_budget) is int and copy_budget >= 0, 'explicit copy mode and budget required')
    need(isinstance(profile_sha,str) and re.fullmatch('[0-9a-f]{64}',profile_sha) and profile_sha != '0'*64,
         'approved literal nonzero profile SHA256 required')
    first = local_pin(profile_path, profile_sha)
    commands = []
    with leased_inputs([first]) as original:
        profile = bounded_json(original[str(profile_path)])
        need(isinstance(profile, dict) and set(profile) == {'schema','disk','boot_template','freedos_source','build_receipt','build_source_root','payloads'} and
             profile['schema'] == 'shizukuos.private-replacement-profile.v1', 'exact private replacement profile required')
        need(isinstance(profile['boot_template'], dict) and set(profile['boot_template']) == {'kind','file'}, 'declared template kind/file required')
        kind = profile['boot_template']['kind']
        need(kind in ('fat12com','fat16com','fat32lba'), 'supported ke2046 standard boot template kind required')
        disk_pin, receipt_pin, boot_pin = profile['disk'], profile['build_receipt'], profile['boot_template']['file']
        for pin in (disk_pin, receipt_pin, boot_pin): pin_fields(pin)
        need(disk_pin['bytes'] % 512 == 0 and boot_pin['bytes'] == 512 and receipt_pin['bytes'] <= 1 << 20, 'disk/template/receipt extent invalid')
        need(mode != 'full' or copy_budget >= disk_pin['bytes'], 'explicit full-copy logical-byte budget too small')
        need(type(capture_budget) is int and 1 << 20 <= capture_budget <= 1 << 30, 'explicit bounded capture budget required')
        output_scope = large_output_scope(out,disk_pin['bytes'],large_output_root)
        root = safe_path(profile['build_source_root']); upstream = safe_path(profile['freedos_source'])
        need(root.is_dir() and upstream.is_dir(), 'actual build/upstream source roots required')
        payloads, names = profile['payloads'], set()
        need(isinstance(payloads,list) and 2 <= len(payloads) <= 32, 'bounded explicit root payloads required')
        rows = [first,disk_pin,receipt_pin,boot_pin]
        for member in payloads:
            need(isinstance(member,dict) and set(member) == {'guest','file'}, 'exact pinned payload fields required')
            name = member['guest']
            need(isinstance(name,str) and re.fullmatch(r'[A-Z0-9_-]{1,8}(\.[A-Z0-9_-]{1,3})?',name) and name not in names and
                 name not in {'IO.SYS','MSDOS.SYS','WIN.COM','SYSTEM.DAT','USER.DAT','SYSTEM.INI','WIN.INI'}, 'unique DOS root payloads; Windows binary overwrite refused')
            names.add(name); pin_fields(member['file'])
            need(member['file']['bytes'] <= (128 << 10 if name == 'KERNEL.SYS' else 2 << 20), 'boot payload exceeds supported bound')
            rows.append(member['file'])
        need({'KERNEL.SYS','COMMAND.COM'} <= names, 'source-built kernel and FreeCOM payloads required')
        source_file = 'boot32lb.asm' if kind == 'fat32lba' else 'boot.asm'
        rows += [local_pin(upstream/'sys/sys.c', SYS_SHA),
                 local_pin(upstream/'boot'/source_file, BOOT_SOURCE_SHA[source_file]),
                 local_pin(upstream/'boot/magic.mac', BOOT_SOURCE_SHA['magic.mac'])]
        original[str(profile_path)]['checkpoint']()
    # The profile is re-pinned together with every input. No nested SIGIO handlers.
    with leased_inputs(rows) as sources:
        receipt = bounded_json(sources[receipt_pin['path']])
        need(isinstance(receipt,dict) and receipt.get('profile') == 'dos16-freedos', 'actual dos16 build receipt required; generic PASS refused')
        for name, commit in (('freedos-kernel',KERNEL_COMMIT),('freedos-freecom',FREECOM_COMMIT)):
            need(receipt.get('upstream',{}).get(name,{}).get('commit') == commit, 'wrong source-built DOS upstream identity')
        for name in ('KERNEL.SYS','COMMAND.COM'):
            member = next(p for p in payloads if p['guest'] == name)
            artifact = receipt.get('artifacts',{}).get(name.lower(),{})
            need(artifact.get('sha256') == member['file']['sha256'] and artifact.get('bytes') == member['file']['bytes'], 'source-built artifact differs from actual build receipt')
        mapping = receipt.get('user_boot',{}).get('sources_sha256')
        need(isinstance(mapping,dict) and 1 <= len(mapping) <= 30000, 'recorded actual dos16 source map required')
        source_rows = [recorded_pin(source_name(name,root), sha) for name,sha in mapping.items()]
        patches = receipt.get('patches')
        need(isinstance(patches,list) and len(patches) <= 256, 'recorded DOS build patches required')
        for row in patches:
            need(isinstance(row,dict) and set(row) == {'patch','sha256'}, 'exact recorded patch identity required')
            source_rows.append(recorded_pin(source_name(row['patch'],root), row['sha256']))
        sources.add_inputs(source_rows)
        disk = dict(sources[disk_pin['path']]); source_check = disk['checkpoint']
        def check():
            check_output_scope(output_scope)
            source_check()
        disk['checkpoint'] = check
        mbr = os.pread(disk['fd'],512,0)
        need(len(mbr) == 512, 'short source MBR')
        active = [mbr[446+n*16:462+n*16] for n in range(4) if mbr[446+n*16] == 0x80]
        need(len(active) == 1, 'exactly one active partition required before VBR read')
        start = u32(active[0],8)
        need(0 < start < disk_pin['bytes']//512, 'active partition start exceeds disk')
        vbr = os.pread(disk['fd'],512,start*512)
        geometry = inspect_geometry(mbr,vbr,disk_pin['bytes'])
        template = os.pread(sources[boot_pin['path']]['fd'],512,0)
        boot = compose_boot(vbr,template,kind,geometry)
        verify_template(upstream,kind,template,commands)
        before = inventory(disk['fd'],geometry,check)
        need(all(before[name]['bytes'] <= 2 << 20 for name in names & before.keys() if not before[name].get('directory')),
             'overwritten original root member exceeds private backup budget')
        check()
        result = {'schema':'shizukuos.private-replacement-preparation.v1','status':'INPUTS_VALIDATED_REPLACEMENT_NOT_PREPARED',
                  'private_source_disk':True,'public_artifact':False,'Windows98_boot_verified':False,
                  'MSDOS_replacement_under_Windows98':False,'native_apps_verified':False,'VM_executed':False,
                  'source_disk':disk_pin,'profile_sha256':profile_sha,'geometry':geometry,
                  'template':{'kind':kind,'sha256':boot_pin['sha256'],'sys_source_sha256':SYS_SHA,
                              'kernel_name':'KERNEL.SYS','load_segment':96,'actual_BIOS_DL_capture':True},
                  'build_receipt_sha256':receipt_pin['sha256'],'build_source_pins':source_rows,
                  'output_scope':output_scope,
                  'upstream_commits':{'freedos-kernel':KERNEL_COMMIT,'freedos-freecom':FREECOM_COMMIT},
                  'commands':commands,'source_unchanged':True,'existing_members':len(before)}
        if validate_only:
            for row in source_rows: need(local_pin(row['path']) == row, 'late build source drift')
            check_output_scope(output_scope)
            return result
        payload_budget = sum(member['file']['bytes'] for member in payloads)
        backup_budget = sum(before[name]['bytes'] for name in names & before.keys() if not before[name].get('directory'))
        capacity(out.parent, (disk_pin['bytes'] if mode == 'full' else 16 << 20)+payload_budget+backup_budget+(256<<20),capture_budget)
        check_output_scope(output_scope)
        out.mkdir(mode=0o700)
        try:
            target = out/'replacement.img'
            result['copy'] = copy_disk(disk,target,mode,copy_budget,capture_budget)
            (out/'original-mbr.bin').write_bytes(mbr); (out/'original-vbr.bin').write_bytes(vbr)
            backup = geometry['backup_sector']
            if backup is not None:
                (out/'original-backup-vbr.bin').write_bytes(os.pread(disk['fd'],512,(start+backup)*512))
            originals = out/'original-files'; originals.mkdir(mode=0o700)
            stage = out/'payloads'; stage.mkdir(mode=0o700)
            for member in payloads:
                name = member['guest']
                if name in before:
                    need(not before[name].get('directory'), 'payload collides with original directory')
                    capacity(out,before[name]['bytes']+(1<<20),capture_budget)
                    with (originals/name).open('xb') as saved:
                        volume = Volume(disk['fd'],geometry,check)
                        need(volume.file(before[name]['cluster'],before[name]['bytes'],saved) == before[name]['sha256'], 'private original member backup SHA differs')
                entry = sources[member['file']['path']]
                data = os.pread(entry['fd'],entry['pin']['bytes'],0); entry['checkpoint']()
                need(digest(data) == entry['pin']['sha256'], 'staged payload SHA differs')
                capacity(out,len(data)+(64<<20),capture_budget)
                (stage/name).write_bytes(data)
                run_tool('mcopy',['-o','-i',str(target)+'@@'+str(start*512),stage/name,'::'+name],commands)
                check(); capacity(out,0,capture_budget)
            with target.open('r+b') as handle:
                need(os.fstat(handle.fileno()).st_size == disk_pin['bytes'], 'replacement disk extent differs after payload tools')
                for lba in (start, start+backup) if backup is not None else (start,):
                    handle.seek(lba*512); need(handle.write(boot) == 512,'short VBR write')
                handle.flush(); os.fsync(handle.fileno())
                need(os.pread(handle.fileno(),512,0) == mbr,'original MBR changed')
                for lba in (start,start+backup) if backup is not None else (start,):
                    need(os.pread(handle.fileno(),512,lba*512) == boot,'boot-sector readback differs')
                after = inventory(handle.fileno(),geometry)
                for name, row in before.items():
                    if name not in names: need(after.get(name) == row,'unrelated Windows/private member changed: '+name)
                for member in payloads:
                    actual = after.get(member['guest'],{})
                    need(actual.get('bytes') == member['file']['bytes'] and actual.get('sha256') == member['file']['sha256'],'installed payload readback differs')
                destination_identity = identity(os.fstat(handle.fileno()))
                need(destination_identity[2] == disk_pin['bytes'], 'replacement disk final extent differs')
                def destination_checkpoint():
                    check()
                    need(identity(os.fstat(handle.fileno())) == destination_identity and
                         identity(target.stat()) == destination_identity, 'replacement disk changed during final readback')
                destination_sha = hash_fd(handle.fileno(),destination_identity[2],destination_checkpoint)
                result['destination'] = {'path':str(target),'bytes':destination_identity[2],'sha256':destination_sha}
            need(hash_fd(disk['fd'],disk_pin['bytes'],check) == disk_pin['sha256'],'source disk changed after preparation')
            for entry in sources.values(): entry['checkpoint']()
            for row in source_rows: need(local_pin(row['path']) == row,'late recorded source drift')
            capacity(out,0,capture_budget)
            result.update(status='PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED',unchanged_original_members=len(before)-len(names & before.keys()),
                          original_vbr_sha256=digest(vbr),replacement_vbr_sha256=digest(boot),
                          original_inventory_sha256=digest(json.dumps(before,sort_keys=True).encode()))
            raw_inventory = (json.dumps(before,indent=2,ensure_ascii=False)+'\n').encode()
            need(len(raw_inventory) <= 128 << 20,'private inventory exceeds declared metadata budget')
            capacity(out,len(raw_inventory)+(1<<20),capture_budget)
            (out/'original-inventory.json').write_text(raw_inventory.decode())
        except BaseException:
            # Own partial private staging is preserved without a successful receipt.
            (out/'preparation.json').unlink(missing_ok=True)
            raise
    # The lease context's final checkpoints must pass before any canonical
    # prepared receipt is published. A late break can never leave a PASS file.
    raw = (json.dumps(result,indent=2,ensure_ascii=False)+'\n').encode()
    need(len(raw) <= 128 << 20,'private receipt exceeds declared metadata budget')
    capacity(out,len(raw)+(1<<20),capture_budget)
    check_output_scope(output_scope)
    temporary = out/'.preparation.json.part'
    try:
        with temporary.open('xb') as handle:
            need(handle.write(raw) == len(raw),'short private receipt write')
            handle.flush(); os.fsync(handle.fileno())
        need(temporary.read_bytes() == raw,'private receipt readback differs')
        check_output_scope(output_scope)
        os.link(temporary,out/'preparation.json')
    finally:
        temporary.unlink(missing_ok=True)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--profile',type=Path,required=True); ap.add_argument('--profile-sha256',required=True)
    ap.add_argument('--out',type=Path,required=True); ap.add_argument('--copy-mode',choices=('reflink','full'),required=True)
    ap.add_argument('--copy-budget-bytes',type=int,required=True); ap.add_argument('--capture-budget-bytes',type=int,required=True)
    ap.add_argument('--validate-only',action='store_true')
    ap.add_argument('--large-private-output-root',type=Path,
                    help='explicit existing owned mode-0700 work area; retains all copy/lease/space checks')
    args = ap.parse_args()
    result = prepare(args.profile,args.profile_sha256,args.out,args.copy_mode,args.copy_budget_bytes,args.capture_budget_bytes,validate_only=args.validate_only,large_output_root=args.large_private_output_root)
    print(json.dumps(result,indent=2,ensure_ascii=False)); return 0


if __name__ == '__main__': raise SystemExit(main())
