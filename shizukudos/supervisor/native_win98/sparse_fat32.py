#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Insert one private DISK.IMG into a newly owned superfloppy FAT32 ESP.

Only the assembler invokes this worker. It imports no project sibling and
cannot start a VM. A completed insertion is not Windows or boot acceptance.
"""
import argparse
from array import array
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import time

RESERVE = 17 << 30
MAX_ESP = 2304 << 20
MAX_SOURCE = 2 << 30
MAX_JSON = 64 << 10
TIMEOUT = 120
U32 = struct.Struct('<I')
identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    path = Path(value)
    need(path.is_absolute() and path.resolve() == path and
         not any(p.is_symlink() for p in (path, *path.parents)), 'canonical nonsymlink path required')
    need(not any(path == p or p in path.parents for p in map(Path, ('/dev', '/proc', '/sys'))),
         'device or virtual path refused')
    return path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    need(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'exact lowercase SHA256 required')
    return value


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, 'duplicate JSON field refused')
        result[name] = value
    return result


def u16(data, at):
    return struct.unpack_from('<H', data, at)[0]


def u32(data, at):
    return U32.unpack_from(data, at)[0]


def read_exact(fd, at, count, checkpoint):
    result = bytearray()
    while len(result) < count:
        checkpoint()
        data = os.pread(fd, count-len(result), at+len(result))
        need(data, 'unexpected source or ESP EOF')
        result.extend(data)
        checkpoint()
    return bytes(result)


def hash_fd(fd, size, checkpoint):
    digest = hashlib.sha256()
    for at in range(0, size, 1 << 20):
        digest.update(read_exact(fd, at, min(1 << 20, size-at), checkpoint))
    checkpoint()
    return digest.hexdigest()


@contextlib.contextmanager
def owned_leases(specifications, deadline):
    """One SIGIO registry; worker alone owns all data file descriptions."""
    previous, broken, entries = signal.getsignal(signal.SIGIO), [False], {}
    signal.signal(signal.SIGIO, lambda *_: broken.__setitem__(0, True))

    def check():
        if time.monotonic() >= deadline:
            raise TimeoutError('sparse FAT32 insertion deadline expired')
        need(not broken[0], 'source or owned ESP lease break requested')
        for entry in entries.values():
            fd, path, kind = entry['fd'], entry['path'], entry['lease']
            need(fcntl.fcntl(fd, fcntl.F_GETLEASE) == kind and
                 identity(os.fstat(fd)) == entry['identity'] and
                 identity(path.stat()) == entry['identity'], 'leased identity or path drift')

    def add(name, path, expected, writable):
        path = canonical(str(path))
        flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        fd = os.open(path, flags)
        try:
            value = os.fstat(fd)
            need(stat.S_ISREG(value.st_mode) and list(identity(value)) == expected,
                 'handed regular file identity differs')
            need(all(identity(value)[:2] != e['identity'][:2] for e in entries.values()), 'data/request inodes must be independent')
            kind = fcntl.F_WRLCK if writable else fcntl.F_RDLCK
            fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
            fcntl.fcntl(fd, fcntl.F_SETLEASE, kind)
        except BaseException:
            os.close(fd)
            raise
        entries[name] = {'fd': fd, 'path': path, 'lease': kind, 'identity': identity(value)}
        check()

    check.add = add
    try:
        for specification in specifications:
            add(*specification)
        yield entries, check
        check()
    finally:
        error = None
        # Every successful unlock/close is required before any result exists.
        for entry in list(entries.values()):
            try:
                check()
                fcntl.fcntl(entry['fd'], fcntl.F_SETLEASE, fcntl.F_UNLCK)
            except BaseException as caught:
                error = error or caught
            finally:
                entries.pop(next(key for key, value in entries.items() if value is entry))
                try:
                    os.close(entry['fd'])
                except BaseException as caught:
                    error = error or caught
        signal.signal(signal.SIGIO, previous)
        if error is not None:
            raise error
        need(not broken[0], 'late data lease break')


def geometry(fd, size, check):
    vbr = read_exact(fd, 0, 512, check)
    need(size <= MAX_ESP and size % 512 == 0 and vbr[510:] == b'\x55\xaa', 'bounded signed superfloppy ESP required')
    spc, reserved, fats = vbr[13], u16(vbr, 14), vbr[16]
    sectors, fat_sectors = u32(vbr, 32), u32(vbr, 36)
    need(u16(vbr, 11) == 512 and 1 <= spc <= 128 and not spc & (spc-1), '512B power-of-two FAT32 geometry required')
    need(reserved > 1 and fats == 2 and not u16(vbr, 17) and not u16(vbr, 19) and
         not u16(vbr, 22) and not u32(vbr, 28) and vbr[21] == 0xf8 and
         not u16(vbr, 40) and not u16(vbr, 42), 'mirrored FAT32 LBA0 BPB required')
    first = reserved + fats * fat_sectors
    need(fat_sectors and first < sectors == size//512, 'FAT/volume extent differs from owned ESP')
    clusters = (sectors-first)//spc
    need(65525 <= clusters and clusters+1 < 0xffffff0 and
         (clusters+2)*4 <= fat_sectors*512 <= 32 << 20, 'true FAT32 cluster count/capacity required')
    root, info, backup = u32(vbr, 44), u16(vbr, 48), u16(vbr, 50)
    need(2 <= root <= clusters+1 and 1 <= info < reserved and 1 <= backup < reserved and
         info != backup and backup+info < reserved and backup+info not in (info, backup), 'backup/FSInfo/root bounds invalid')
    need(read_exact(fd, backup*512, 512, check) == vbr, 'backup VBR differs')
    infos = []
    for sector in (info, backup+info):
        block = read_exact(fd, sector*512, 512, check)
        need(u32(block, 0) == 0x41615252 and u32(block, 484) == 0x61417272 and
             u32(block, 508) == 0xaa550000, 'primary or backup FSInfo signature differs')
        need(u32(block, 488) == 0xffffffff or u32(block, 488) <= clusters, 'FSInfo free count out of bounds')
        need(u32(block, 492) == 0xffffffff or 2 <= u32(block, 492) <= clusters+1, 'FSInfo next-free hint out of bounds')
        infos.append((sector*512, block))
    fat = read_exact(fd, reserved*512, fat_sectors*512, check)
    need(read_exact(fd, (reserved+fat_sectors)*512, len(fat), check) == fat, 'mirrored FAT copies differ')
    need((u32(fat, 0) & 0xfffffff) == 0xffffff8 and (u32(fat, 4) & 0xfffffff) >= 0xffffff8,
         'reserved FAT entries invalid')
    return {'spc': spc, 'cluster_bytes': spc*512, 'reserved': reserved, 'fat_sectors': fat_sectors,
            'first_data': first*512, 'clusters': clusters, 'root': root, 'infos': infos, 'fat': fat}


def directories(fd, g, check):
    fat, used, directory_blocks, files, terminators = g['fat'], set(), {}, {}, {}

    def chain(first):
        result, current = [], first
        while True:
            need(2 <= current <= g['clusters']+1 and current not in used, 'invalid cyclic/crosslinked FAT chain')
            used.add(current); result.append(current)
            value = u32(fat, current*4) & 0xfffffff
            if value >= 0xffffff8:
                return result
            need(2 <= value <= g['clusters']+1, 'free/reserved/bad cluster in live chain')
            current = value

    def offset(cluster):
        return g['first_data']+(cluster-2)*g['cluster_bytes']

    def directory(path, first, depth):
        need(depth <= 32 and len(directory_blocks) < 128, 'directory inventory exceeds bound')
        blocks = [(offset(c), read_exact(fd, offset(c), g['cluster_bytes'], check)) for c in chain(first)]
        directory_blocks[path] = blocks
        ended, seen = False, set()
        for at, block in blocks:
            for pos in range(0, len(block), 32):
                row = block[pos:pos+32]
                if ended:
                    continue
                if row[0] == 0:
                    terminators[path] = (at+pos, block[pos:pos+64])
                    ended = True
                    continue
                need(row[0] != 0xe5 and row[11] != 15, 'deleted/LFN entries outside fresh short-name profile')
                if row[:11] in (b'.          ', b'..         ') or row[11] & 8:
                    continue
                name = row[:11]
                need(name not in seen and len(files) < 30000, 'duplicate/unbounded short directory member')
                seen.add(name)
                number = u16(row, 26) | (u16(row, 20) << 16)
                target = path+(name,)
                files[target] = (at+pos, row)
                if row[11] & 16:
                    need(u32(row, 28) == 0, 'directory size must be zero')
                    directory(target, number, depth+1)
                else:
                    size = u32(row, 28)
                    member_chain = chain(number) if number else []
                    need(len(member_chain) == (size+g['cluster_bytes']-1)//g['cluster_bytes'], 'member chain/size mismatch')
        need(ended, 'directory lacks bounded terminator')
    directory((), g['root'], 0)
    target = (b'SHZDOS     ',)
    need(target in directory_blocks, 'unique existing SHZDOS directory required')
    need(target+(b'DISK    IMG',) not in files, 'DISK.IMG already exists')
    # No orphan allocation is admitted in the fresh mkfs/mmd/mcopy profile.
    for number in range(2, g['clusters']+2):
        check() if number % 4096 == 0 else None
        need(not (u32(fat, number*4) & 0xfffffff) or number in used, 'unreachable preexisting FAT allocation')
    slot, pair = terminators[target]
    need(pair == bytes(64), 'SHZDOS needs a spare zero entry and preserved terminator')
    return slot, directory_blocks, files


def spans(chain, g, size, check):
    """Map actual consecutive FAT clusters to bounded logical source ranges."""
    index, left = 0, size
    while left:
        check()
        count = 1
        limit = (1 << 20)//g['cluster_bytes']
        while index+count < len(chain) and count < limit and chain[index+count] == chain[index]+count:
            count += 1
        length = min(left, count*g['cluster_bytes'])
        yield g['first_data']+(chain[index]-2)*g['cluster_bytes'], length
        left -= length; index += count


def validate_request(request, result_path, executed_sha, executed_bytes):
    need(type(request) is dict and set(request) == {'schema', 'member', 'source', 'esp', 'producer', 'result'}, 'exact request schema required')
    need(request['schema'] == 'shizukuos.sparse-fat32-request.v1' and request['member'] == 'SHZDOS/DISK.IMG', 'fixed private disk member required')
    need(set(request['producer']) == {'sha256', 'bytes'} and request['producer'] == {'sha256': executed_sha, 'bytes': executed_bytes}, 'executed helper pin differs')
    pin(executed_sha)
    need(type(executed_bytes) is int and 0 < executed_bytes <= 1 << 20, 'bounded executed helper required')
    for name, fields, maximum in (('source', {'path','bytes','sha256','identity'}, MAX_SOURCE), ('esp', {'path','bytes','identity'}, MAX_ESP)):
        item = request[name]
        need(type(item) is dict and set(item) == fields and type(item['bytes']) is int and 0 < item['bytes'] <= maximum, 'exact data pin schema required')
        canonical(item['path'])
        need(type(item['identity']) is list and len(item['identity']) == 5 and all(type(n) is int and n >= 0 for n in item['identity']) and item['identity'][2] == item['bytes'], 'exact data identity required')
    pin(request['source']['sha256'])
    result = canonical(str(result_path))
    need(str(result) == request['result'] and result.parent == canonical(request['esp']['path']).parent and
         not result.exists() and not result.is_symlink(), 'fresh owned result beside ESP required')
    return result


def prepare(request_path, request_sha, result_path, executed_sha, executed_bytes):
    request_path = canonical(str(request_path)); pin(request_sha)
    value = request_path.stat()
    need(stat.S_ISREG(value.st_mode) and 0 < value.st_size <= MAX_JSON, 'bounded regular request required')
    deadline = time.monotonic()+TIMEOUT
    with owned_leases([('request', request_path, list(identity(value)), False)], deadline) as (held, request_check):
        raw = read_exact(held['request']['fd'], 0, value.st_size, request_check)
        need(sha(raw) == request_sha, 'exact request SHA differs')
        request = json.loads(raw, object_pairs_hook=unique_object)
        result_path = validate_request(request, result_path, executed_sha, executed_bytes)
        source, esp = request['source'], request['esp']
        # Request, source and owned ESP share one actual SIGIO registry.
        request_check.add('source', Path(source['path']), source['identity'], False)
        request_check.add('esp', Path(esp['path']), esp['identity'], True)
        data, data_check = held, request_check
        def check():
            request_check(); data_check()
            need(shutil.disk_usage(Path(esp['path']).parent).free >= RESERVE, '17GiB retained free space unavailable')
        check()
        need(data['source']['identity'][:2] != data['esp']['identity'][:2], 'source and ESP inodes must differ')
        before_sha = hash_fd(data['source']['fd'], source['bytes'], check)
        need(before_sha == source['sha256'], 'source SHA differs before any ESP write')
        g = geometry(data['esp']['fd'], esp['bytes'], check)
        slot, old_directories, old_files = directories(data['esp']['fd'], g, check)
        wanted = (source['bytes']+g['cluster_bytes']-1)//g['cluster_bytes']
        available = array('I', (n for n in range(2, g['clusters']+2) if not u32(g['fat'], n*4) & 0xfffffff))
        need(len(available) >= wanted, 'FAT32 free cluster capacity insufficient')
        allocated = available[:wanted]

        def write(at, block):
            need(0 <= at <= esp['bytes']-len(block), 'owned ESP write range out of bounds')
            done = 0
            while done < len(block):
                check()
                n = os.pwrite(data['esp']['fd'], block[done:], at+done)
                need(n > 0, 'zero owned ESP write')
                done += n
                data['esp']['identity'] = identity(os.fstat(data['esp']['fd']))
                check()

        digest, consumed, omitted, written = hashlib.sha256(), 0, 0, 0
        for base, count in spans(allocated, g, source['bytes'], check):
            block = read_exact(data['source']['fd'], consumed, count, check)
            digest.update(block)
            if not any(block):
                need(read_exact(data['esp']['fd'], base, count, check) == bytes(count), 'skipped destination region is not zero')
                omitted += count
            else:
                # Mixed source ranges retain small zero omission granularity;
                # whole-zero ranges need only one bounded source/dest read.
                for pos in range(0, count, 4096):
                    chunk = block[pos:pos+4096]
                    if not any(chunk):
                        need(read_exact(data['esp']['fd'], base+pos, len(chunk), check) == bytes(len(chunk)), 'skipped destination region is not zero')
                        omitted += len(chunk)
                    else:
                        write(base+pos, chunk); written += len(chunk)
            consumed += count
        padding = wanted*g['cluster_bytes']-source['bytes']
        if padding:
            tail = g['first_data']+(allocated[-1]-2)*g['cluster_bytes']+g['cluster_bytes']-padding
            need(read_exact(data['esp']['fd'], tail, padding, check) == bytes(padding), 'final cluster padding is not fresh zero')
        need(consumed == source['bytes'] and digest.hexdigest() == source['sha256'], 'complete streamed source hash/extent differs')
        fat = bytearray(g['fat'])
        for index, number in enumerate(allocated):
            successor = allocated[index+1] if index+1 < len(allocated) else 0xfffffff
            U32.pack_into(fat, number*4, (u32(fat, number*4) & 0xf0000000) | successor)
        for copy in range(2):
            write((g['reserved']+copy*g['fat_sectors'])*512, fat)
        remaining = len(available)-wanted
        next_free = available[wanted] if remaining else 0xffffffff
        for at, original in g['infos']:
            block = bytearray(original); U32.pack_into(block, 488, remaining); U32.pack_into(block, 492, next_free)
            write(at, block)
        row = bytearray(32); row[:11] = b'DISK    IMG'; row[11] = 0x20
        stamp = datetime.datetime.fromtimestamp(source['identity'][3]/1_000_000_000, datetime.timezone.utc)
        need(1980 <= stamp.year <= 2107, 'source timestamp outside DOS date range')
        date = ((stamp.year-1980) << 9) | (stamp.month << 5) | stamp.day
        clock = (stamp.hour << 11) | (stamp.minute << 5) | (stamp.second//2)
        struct.pack_into('<HH', row, 22, clock, date)
        struct.pack_into('<H', row, 20, allocated[0] >> 16)
        struct.pack_into('<H', row, 26, allocated[0] & 0xffff)
        U32.pack_into(row, 28, source['bytes'])
        # The member becomes visible only after data/FAT/FSInfo readback.
        for copy in range(2):
            need(read_exact(data['esp']['fd'], (g['reserved']+copy*g['fat_sectors'])*512, len(fat), check) == fat, 'written FAT readback differs')
        for at, original in g['infos']:
            block = read_exact(data['esp']['fd'], at, 512, check)
            need(u32(block, 488) == remaining and u32(block, 492) == next_free, 'written FSInfo readback differs')
        write(slot, row)
        os.fsync(data['esp']['fd']); check()
        need(read_exact(data['esp']['fd'], slot, 64, check) == row+bytes(32), 'directory entry/terminator readback differs')
        final = geometry(data['esp']['fd'], esp['bytes'], check)
        need(final['fat'] == fat, 'complete final mirrored FAT differs')
        for blocks in old_directories.values():
            for at, old in blocks:
                expected = bytearray(old)
                if at <= slot < at+len(old): expected[slot-at:slot-at+32] = row
                need(read_exact(data['esp']['fd'], at, len(old), check) == expected, 'preexisting directory metadata changed')
        # Independent positional member reread, still under owned lease.
        readback = hashlib.sha256()
        for at, count in spans(allocated, g, source['bytes'], check):
            readback.update(read_exact(data['esp']['fd'], at, count, check))
        need(readback.hexdigest() == source['sha256'], 'complete inserted member readback differs')
        esp_sha = hash_fd(data['esp']['fd'], esp['bytes'], check)
        check()
        final_identity = list(data['esp']['identity'])
        request_check()
    result = {'schema':'shizukuos.sparse-fat32-result.v1', 'status':'PRIVATE_FAT32_MEMBER_INSERTED_NOT_RUN',
              'request_sha256':request_sha, 'producer_sha256':executed_sha, 'producer_bytes':executed_bytes,
              'source':{'path':source['path'], 'bytes':source['bytes'], 'sha256':source['sha256'], 'identity':source['identity'],
                        'before_sha256':before_sha, 'streamed_sha256':digest.hexdigest(), 'lease_finalized':True},
              'esp':{'path':esp['path'], 'bytes':esp['bytes'], 'identity':final_identity, 'sha256':esp_sha, 'independent_inode':True, 'fsync_completed':True},
              'member':{'path':request['member'], 'bytes':consumed, 'sha256':readback.hexdigest(), 'clusters':wanted,
                        'cluster_bytes':g['cluster_bytes'], 'zero_bytes_omitted':omitted, 'data_bytes_written':written, 'padding_zero_bytes':padding},
              'fat':{'copies':2, 'free_clusters_before':len(available), 'free_clusters_after':remaining,
                     'next_free':next_free, 'mirrors_verified':True, 'FSInfo_copies':2},
              'Windows98_executed':False, 'VM_executed':False, 'Windows98_boot_verified':False}
    fd = os.open(result_path, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    try:
        result['result_inode'] = list(identity(os.fstat(fd))[:2])
        encoded = (json.dumps(result, indent=2)+'\n').encode(); need(len(encoded) <= MAX_JSON, 'bounded result required')
        at = 0
        while at < len(encoded):
            n = os.write(fd, encoded[at:]); need(n > 0, 'zero result write'); at += n
        os.fsync(fd)
        need(read_exact(fd, 0, len(encoded), lambda: None) == encoded, 'raw result readback differs')
    finally:
        os.close(fd)
    fd = os.open(result_path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--return-fd', type=int, required=True)
    args = parser.parse_args()
    need('_EXECUTED_SOURCE_SHA256' in globals() and '_EXECUTED_SOURCE_BYTES' in globals(), 'assembler-held executed source FD required')
    need(stat.S_ISFIFO(os.fstat(args.return_fd).st_mode) and
         fcntl.fcntl(args.return_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
         os.fpathconf(args.return_fd, 'PC_PIPE_BUF') >= 512, 'owned bounded metadata return pipe required')
    result = prepare(args.request, args.request_sha256, args.result, globals()['_EXECUTED_SOURCE_SHA256'], globals()['_EXECUTED_SOURCE_BYTES'])
    # These bytes come from the producer's unchanged in-memory saved record,
    # never from a post-return mutable result pathname.
    encoded = (json.dumps(result, indent=2)+'\n').encode()
    packet = (json.dumps({'schema':'shizukuos.sparse-fat32-return.v1', 'bytes':len(encoded), 'sha256':sha(encoded)}, separators=(',',':'))+'\n').encode()
    need(len(packet) <= 512 and os.write(args.return_fd, packet) == len(packet), 'complete atomic producer return required')
    os.close(args.return_fd)


if __name__ == '__main__':
    main()
