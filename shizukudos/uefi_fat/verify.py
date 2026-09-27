#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent bounded decoder for the original FAT32/AHCI physical evidence.

No C parser, firmware, disk-device access or VM execution. A decoded proof is
not by itself execution provenance. The harness separately binds immutable
sources, binaries, receipts and the independently stopped QEMU instance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

DISK_BYTES, OUTPUT_BYTES = 64 * 1024**2, 512 * 1024
# Whole-image commitment for this version of the original fixture, including
# unused sectors. Derived from generator output, then separately structure- and
# byte-checked below; no external media or partition tool supplied these bytes.
FIXTURE_SHA256 = '0d37c4e1f18f42847269dce1f08f0785df28855d2a29cf14aa70edee1b4dd04f'
PROOF_ADDRESS, OUTPUT_ADDRESS = 0x0200f100, 0x02100000
GUARD_BEFORE, GUARD_AFTER, GUARD_BYTES = 0x020ff000, 0x02180000, 4096
PROOF_NAMES = ('magic size version stage calibrated ticks_per_us clock_fault clock_stagnant '
               'start_tsc clock_last_tsc file_start_us file_end_us pci_bdf abar pci_original '
               'pci_restored open_result fat_result read_result close_result sectors_low sectors_high '
               'sector_bytes port dma_address dma_bytes allocations releases quarantine sector_reads '
               'last_lba_low last_lba_high destination capacity guard_before guard_after guard_bytes '
               'guards_pass read_refusals read_overruns').split()
INFO_NAMES = ('struct_size abi_version partition_index file_bytes partition_lba partition_sectors '
              'volume_sectors sectors_per_cluster cluster_count root_cluster first_cluster fat_sectors '
              'fat_count active_fat mirrored root_clusters file_clusters sector_reads reserved').split()
HANDOFF_NAMES = ('magic version size stage framebuffer framebuffer_bytes width height pitch_pixels pixel_format '
                 'memory_map map_bytes descriptor_bytes descriptor_version region_base region_bytes payload_bytes stack_top '
                 'cr0 cr4 efer cs ss esp core_pass graphics_pass mode_pass exit_attempted').split()


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def snapshot(value, size, name):
    require(isinstance(value, (bytes, bytearray)) and len(value) == size,
            'Invalid bounded ' + name)
    return bytes(value)


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit):
    """No symlink component, device, FIFO, unbounded allocation or changing file."""
    path = Path(path).absolute()
    require(type(limit) is int and limit >= 0, 'Invalid read bound')
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'Symlink is not captured evidence: ' + str(item))
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                'Evidence is not a bounded regular file: ' + str(path))
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size and
                all(getattr(before, key) == getattr(after, key) for key in fields),
                'Evidence changed during capture: ' + str(path))
    return data


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda name: (_ for _ in ()).throw(EvidenceError('Nonfinite JSON')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError('Invalid JSON evidence') from error
    require(isinstance(value, dict), 'JSON evidence must be an object')
    return value


def decode_disk(data):
    """Derive geometry, root and file chains from the synthetic on-disk bytes.

    Does not import fixture.py or use its sector generator/arithmetic. All
    traversed FATs are read from the disk; the independently computed byte
    oracle prevents a self-consistent but changed file from being accepted.
    """
    data = snapshot(data, DISK_BYTES, 'synthetic disk')
    mbr = data[:512]
    require(mbr[:446] == bytes(446) and mbr[510:] == b'\x55\xaa' and mbr[462:510] == bytes(48),
            'Unexpected MBR code, signature or extra partitions')
    bootable, _, kind, _, start, count = struct.unpack_from('<B3sB3sII', mbr, 446)
    require((bootable, kind, start, count) == (0, 12, 2048, 129024), 'Wrong synthetic partition')
    boot = data[start*512:(start+1)*512]
    require(boot[510:] == b'\x55\xaa', 'Missing FAT32 BPB signature')
    bps, spc, reserved, copies, roots, total16, media, fat16, _, _, hidden, total = struct.unpack_from('<HBHBHHBHHHII', boot, 11)
    fatsize, flags, version, root = struct.unpack_from('<IHHI', boot, 36)
    require((bps,spc,reserved,copies,roots,total16,media,fat16,hidden,total,fatsize,flags,version,root) ==
            (512,1,32,2,0,0,248,0,2048,129024,1024,0,0,9), 'Unexpected FAT32 geometry')
    first_data = start + reserved + copies * fatsize
    clusters = (total - reserved - copies*fatsize)//spc
    require(clusters == 126944 and clusters >= 65525 and (clusters+2)*4 <= fatsize*512,
            'Fixture is not a capacity-valid FAT32 volume')
    fat = data[(start+reserved)*512:(start+reserved+fatsize)*512]
    require(fat == data[(start+reserved+fatsize)*512:(start+reserved+2*fatsize)*512],
            'Mirrored FATs disagree')
    require(u32(fat,0) == 0x0ffffff8 and u32(fat,4) == 0x0fffffff, 'Invalid FAT reserved entries')
    def chain(first, maximum):
        result = []
        current = first
        while True:
            require(2 <= current <= clusters+1 and current not in result and len(result) < maximum,
                    'Invalid, repeated or overlong FAT chain')
            result.append(current)
            current = u32(fat,current*4) & 0x0fffffff
            if current >= 0x0ffffff8:
                return result
            require(current < 0x0ffffff0, 'Bad or reserved cluster')
    roots = chain(root,64)
    require(roots == [9,71,15], 'Root directory is not the fragmented original fixture')
    matches, ended = [], False
    for cluster in roots:
        lba = first_data + (cluster-2)*spc
        directory = data[lba*512:(lba+spc)*512]
        for pos in range(0,len(directory),32):
            entry = directory[pos:pos+32]
            if ended:
                continue
            if entry[0] == 0:
                ended = True
                continue
            if entry[0] == 0xe5 or entry[11] & 8:
                continue
            require(entry[:11] == b'NTWBOOT BIN' and entry[11] == 0x26,
                    'Unexpected live file or directory in synthetic fixture')
            first = int.from_bytes(entry[20:22],'little') << 16 | int.from_bytes(entry[26:28],'little')
            matches.append((cluster,pos,first,u32(entry,28)))
    require(matches == [(71,160,1000,131195)] and ended, 'Missing, misplaced or duplicate target SFN')
    files = chain(matches[0][2],1024)
    expected_chain = [1000 + (487*index - ((487*index)//10007)*10007) for index in range(257)]
    require(files == expected_chain and not set(files) & set(roots), 'Wrong fragmented file chain')
    # Whole FAT equality also excludes undisclosed allocated files/clusters.
    allocated = {0:0x0ffffff8,1:0x0fffffff}
    for sequence in (roots,files):
        allocated.update({value: sequence[index+1] if index+1 < len(sequence) else 0x0fffffff
                          for index,value in enumerate(sequence)})
    expected_fat = bytearray(len(fat))
    for cluster,value in allocated.items():
        struct.pack_into('<I',expected_fat,cluster*4,value)
    require(fat == expected_fat, 'Unexpected FAT allocation or reserved high bits')
    raw = b''.join(data[(first_data+cluster-2)*512:(first_data+cluster-1)*512] for cluster in files)
    length = matches[0][3]
    # Equivalent arithmetic to the writer expressed with quotient/remainder
    # separately, and driven by logical file offsets rather than disk LBAs.
    expected = bytearray(length)
    for index in range(length):
        group, _ = divmod(index,251)
        expected[index] = ((29*index+7*group+83) % 256) ^ ((index//256) % 256)
    require(raw[:length] == expected and raw[length:] == b'\xcc'*(len(raw)-length),
            'Original patterned file or final-sector padding changed')
    disk_digest = digest(data)
    require(disk_digest == FIXTURE_SHA256, 'Whole original fixture changed, including unused sectors')
    return {'file': bytes(expected), 'disk_sha256':disk_digest, 'file_sha256':digest(expected),
            'file_bytes':length, 'file_chain':files, 'root_chain':roots,
            'last_lba':first_data+files[-1]-2, 'last_sector':raw[-512:],
            'partition_lba':start,'partition_sectors':count,'cluster_count':clusters}


def decode_proof(data):
    data = snapshot(data,256,'FAT proof')
    proof = dict(zip(PROOF_NAMES,struct.unpack_from('<8I4Q28I',data)))
    proof['info'] = dict(zip(INFO_NAMES,struct.unpack_from('<4IQ14I',data,176)))
    return proof


def inspect_handoff(data, memory_map, registers, *, payload_bytes, payload_end):
    data = snapshot(data,112,'protected-mode handoff')
    b = dict(zip(HANDOFF_NAMES,struct.unpack('<28I',data)))
    require((b['magic'],b['version'],b['size'],b['stage']) == (0x32334453,1,112,5), 'Invalid handoff ABI/stage')
    require(b['core_pass'] == b['graphics_pass'] == b['mode_pass'] == b['exit_attempted'] == 1,
            'Core/graphics/protected-mode/firmware-exit proof incomplete')
    require((b['region_base'],b['region_bytes'],b['memory_map'],b['stack_top']) ==
            (0x02000000,0x00200000,0x02004000,0x02200000), 'Handoff ownership coordinates changed')
    require(type(payload_bytes) is int and 0 < payload_bytes <= 0xef000 and b['payload_bytes'] == payload_bytes and
            type(payload_end) is int and 0x02010000+payload_bytes <= payload_end <= GUARD_BEFORE,
            'Linked payload/file bounds disagree')
    require(b['cr0'] & 1 and not b['cr0'] & 0x80000000 and not b['cr4'] & 0x21020 and
            not b['efer'] & 0x500 and b['cs'] == 0x10 and b['ss'] == 0x18 and
            0x021f0000 <= b['esp'] < 0x02200000, 'Wrong execution mode or stack')
    require(b['width'] >= 640 and b['height'] >= 400 and b['width'] <= b['pitch_pixels'] and
            b['height']*b['pitch_pixels']*4 <= b['framebuffer_bytes'] and
            b['pixel_format'] in (0,1) and b['framebuffer'] >= 0x80000000 and
            b['framebuffer']+b['framebuffer_bytes'] <= 0x100000000, 'Invalid framebuffer')
    require(isinstance(memory_map,(bytes,bytearray)) and len(memory_map) == b['map_bytes'] and
            0 < len(memory_map) <= 32768 and 40 <= b['descriptor_bytes'] <= 256 and
            b['descriptor_bytes'] % 8 == 0 and len(memory_map) % b['descriptor_bytes'] == 0 and
            b['descriptor_version'] == 1, 'Invalid retained EFI map bounds')
    extents = []
    for offset in range(0,len(memory_map),b['descriptor_bytes']):
        kind, _, address, _, pages, attributes = struct.unpack_from('<IIQQQQ',memory_map,offset)
        require(kind <= 15 and address % 4096 == 0 and pages > 0 and address+pages*4096 <= 1<<64,
                'Invalid EFI memory extent')
        extents.append((address,address+pages*4096,kind,attributes))
    extents.sort()
    require(all(left[1] <= right[0] for left,right in zip(extents,extents[1:])), 'Overlapping EFI memory extents')
    cursor = 0x02000000
    for start,end,kind,attributes in extents:
        if end <= cursor or start >= 0x02200000:
            continue
        require(start <= cursor and kind == 1 and attributes & (1<<63) == 0,
                'Payload reservation not owned as non-runtime EfiLoaderCode')
        cursor = min(end,0x02200000)
    require(cursor == 0x02200000, 'EFI map does not cover the whole owned payload/output/stack')
    require(isinstance(registers,str) and len(registers) <= 65536 and
            all(token in registers for token in ('CS32','CPL=0','HLT=1')), 'Missing independent halted CPL0 register state')
    observed = {}
    for name in ('EIP','ESP','CR0','CR4','EFER'):
        values = re.findall(r'\b'+name+r'=([0-9a-fA-F]+)',registers)
        require(len(values) == 1, 'Ambiguous/missing independent register '+name)
        observed[name] = int(values[0],16)
    require(0x02010000 <= observed['EIP'] < payload_end and 0x021f0000 <= observed['ESP'] < 0x02200000 and
            all(observed[name] == b[name.lower()] for name in ('ESP','CR0','CR4','EFER')),
            'Independent CPU registers disagree with handoff')
    return {'handoff':b,'registers':observed,'memory_descriptors':len(extents),'owned_bytes':0x200000}


def verify_pci(inventory, proof):
    require(isinstance(inventory,list) and len(inventory) == 1 and inventory[0].get('bus') == 0,
            'Unexpected PCI bus topology')
    devices = inventory[0].get('devices')
    require(isinstance(devices,list) and 1 <= len(devices) <= 32, 'Invalid PCI inventory')
    controllers = [item for item in devices if item.get('id',{}).get('vendor') == 0x8086 and
                   item.get('id',{}).get('device') == 0x2922]
    require(len(controllers) == 1, 'Missing/duplicate declared QEMU AHCI controller')
    controller = controllers[0]
    require((controller.get('bus'),controller.get('slot'),controller.get('function')) == (0,31,2) and
            controller.get('class_info',{}).get('class') == 0x106 and proof['pci_bdf'] == 0xfa,
            'AHCI PCI identity does not match proof')
    bars = [bar for bar in controller.get('regions',[]) if bar.get('bar') == 5]
    require(len(bars) == 1 and bars[0].get('type') == 'memory' and bars[0].get('size') == 4096 and
            bars[0].get('mem_type_64') is False and bars[0].get('prefetch') is False and
            bars[0].get('address') == proof['abar'], 'AHCI BAR5 aperture does not match physical dump')
    return {'bdf':0xfa,'vendor':0x8086,'device':0x2922,'abar':proof['abar'],'bytes':4096}


def verify_evidence(proof_bytes, dma_bytes, output_bytes, before_bytes, after_bytes, mmio_bytes,
                    *, expected_dma_address, disk_bytes, handoff_bytes, memory_map_bytes,
                    registers_text, payload_bytes, payload_end):
    proof = decode_proof(proof_bytes)
    disk = decode_disk(disk_bytes)
    dma = snapshot(dma_bytes,4096,'AHCI DMA page')
    output = snapshot(output_bytes,OUTPUT_BYTES,'whole file destination')
    before = snapshot(before_bytes,GUARD_BYTES,'leading output guard')
    after = snapshot(after_bytes,GUARD_BYTES,'trailing output guard')
    mmio = snapshot(mmio_bytes,4096,'AHCI MMIO')
    require((proof['magic'],proof['size'],proof['version'],proof['stage']) == (0x54414653,256,1,3),
            'Not a completed FAT proof')
    require(proof['calibrated'] == 1 and 10 <= proof['ticks_per_us'] <= 100000 and
            proof['clock_fault'] == 0 and proof['clock_stagnant'] < 64 and
            0 < proof['start_tsc'] < proof['clock_last_tsc'] and
            0 <= proof['file_start_us'] < proof['file_end_us'] and
            proof['file_end_us']-proof['file_start_us'] < 5000000 and
            (proof['clock_last_tsc']-proof['start_tsc'])//proof['ticks_per_us'] >= proof['file_end_us'],
            'Invalid calibration, clock progress or FAT time budget')
    require(all(proof[name] == 0 for name in ('open_result','fat_result','read_result','close_result',
            'quarantine','read_refusals','read_overruns')), 'I/O failure, deadline violation or DMA quarantine')
    require(proof['pci_bdf'] == 0xfa and proof['pci_original'] == proof['pci_restored'] <= 0xffff and
            0x80000000 <= proof['abar'] <= 0xfffff000 and proof['abar'] % 4096 == 0,
            'PCI restoration or bounded BAR mismatch')
    require((proof['sectors_low'],proof['sectors_high'],proof['sector_bytes'],proof['port']) == (131072,0,512,0),
            'AHCI identity does not match synthetic disk')
    require(type(expected_dma_address) is int and expected_dma_address % 4096 == 0 and
            0x02010000 <= expected_dma_address <= payload_end-4096 and
            proof['dma_address'] == expected_dma_address and proof['dma_bytes'] == 4096 and
            proof['allocations'] == proof['releases'] == 1, 'DMA symbol/allocation lifetime mismatch')
    require((proof['destination'],proof['capacity'],proof['guard_before'],proof['guard_after'],proof['guard_bytes'],
             proof['guards_pass']) == (OUTPUT_ADDRESS,OUTPUT_BYTES,GUARD_BEFORE,GUARD_AFTER,4096,7),
            'Output ownership or guard proof mismatch')
    require(before == after == b'\xa5'*4096 and output[:disk['file_bytes']] == disk['file'] and
            output[disk['file_bytes']:] == b'\xa5'*(OUTPUT_BYTES-disk['file_bytes']),
            'Physical file, destination tail or guard bytes differ')
    expected = (80,1,0,131195,2048,129024,129024,1,126944,9,1000,1024,2,0,1,3,257)
    info = proof['info']
    require(tuple(info[key] for key in INFO_NAMES[:17]) == expected and info['reserved'] == 0 and
            info['sector_reads'] == proof['sector_reads'] and 264 <= info['sector_reads'] <= 8192,
            'FAT32 decoded metadata or read accounting disagrees with disk')
    final_lba = proof['last_lba_low'] | (proof['last_lba_high'] << 32)
    require(final_lba == disk['last_lba'], 'Final read does not identify final fragmented file sector')
    header = struct.pack('<8I',0x10005,512,expected_dma_address+1280,0,0,0,0,0)
    require(dma[:32] == header and dma[32:1024] == bytes(992), 'AHCI command header/PRDBC/unused slots differ')
    table = bytearray(256)
    table[0:3],table[7],table[12] = b'\x27\x80\x25',0x40,1
    table[4:7] = final_lba.to_bytes(6,'little')[:3]
    table[8:11] = final_lba.to_bytes(6,'little')[3:]
    struct.pack_into('<4I',table,128,expected_dma_address+2048,0,0,511)
    require(dma[1280:1536] == table and dma[1536:2048] == bytes(512) and
            dma[2048:2560] == disk['last_sector'] and dma[2560:] == bytes(1536),
            'AHCI READ DMA EXT command/PRDT/final sector evidence differs')
    require(dma[1088] == 0x34 and dma[1090] & 0xa9 == 0,
            'Final received D2H FIS reports failure or wrong type')
    require(u32(mmio,4) & 0x80000003 == 0x80000000 and u32(mmio,12) & 1 and
            u32(mmio,16) >= 0x10000, 'AHCI global state is invalid, resetting or interrupt-enabled')
    port = 0x100
    require(all(u32(mmio,port+offset) == 0 for offset in (0,4,8,12,20,52,56)) and
            u32(mmio,port+24) & 0xc011 == 0 and u32(mmio,port+16) & 0x7d800010 == 0 and
            u32(mmio,port+32) & 0xa9 == 0 and u32(mmio,port+36) == 0x101 and
            u32(mmio,port+40) & 0xf0f == 0x103 and u32(mmio,port+48) == 0,
            'AHCI engines/DMA bases/interrupts were not detached cleanly')
    mode = inspect_handoff(handoff_bytes,memory_map_bytes,registers_text,
                           payload_bytes=payload_bytes,payload_end=payload_end)
    return {'status':'PASS','claim':'original fragmented FAT32 file read through AHCI after ExitBootServices',
            'proof':proof,'file_sha256':disk['file_sha256'],'disk_sha256':disk['disk_sha256'],
            'file_bytes':disk['file_bytes'],'root_chain':disk['root_chain'],'file_clusters':len(disk['file_chain']),
            'last_lba':final_lba,'mode':mode,'windows_98_driver':'not_tested',
            'file_execution':False,'physical_hardware':'not_tested'}
