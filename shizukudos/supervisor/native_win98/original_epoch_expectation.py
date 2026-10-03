#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Encode VGACFG.BIN (136 B) and optional W98PERS.BIN (192 B) EXPECTATIONS.

Input is root's actual saved PAUSED QMP probe of the exact native recipe
(two complete sequential snapshots of query-status, `info mtree -f`,
query-pci and bounded `xp /10wx` ECAM reads of the selected functions) plus
the source-built StdVGA ROM and its producer receipt from
tools/build_stdvga_rom.py.  Offsets 40/72/104 of VGACFG bind the padded ROM
SHA256, the producer's frozen source-manifest SHA256 and its generated
SeaBIOS .config SHA256 (never a self-hash of VGACFG).

The output is an expectation only.  It grants nothing: the guardian's
prepare_original_intent() mints the native_epoch_host.Attempt (getrandom
nonce, sealed policy memfd), and HostGrant re-observes the live paused child
twice through the sole QMP reader before COM2 GRANT.  This encoder never
writes a BDF/BAR value that it did not read from the observation, refuses any
observation that does not describe exactly the owned StdVGA (and, only when
explicitly requested, the single Supervisor virtio-blk function), and runs
the same native_epoch_host/builder validators the live path runs, so an
inexpressible device is refused here instead of being emitted.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys

HERE = Path(__file__).resolve().parent
OBSERVATION_SCHEMA = 'shizukuos.native-original-epoch-paused-observation.v1'
EXPECTATION_SCHEMA = 'shizukuos.native-original-epoch-expectation.v1'
MAX_OBSERVATION = 4 << 20
LFB = 16 << 20
FALSE_FLAGS = ('device_epoch_authority', 'HostGrant_transmitted', 'VM_executed_by_encoder', 'persistence_verified',
               'install_or_persist_claim', 'Windows98_display_verified', 'release_approved', 'public_artifact')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def _load(name, filename):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, HERE / filename)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        sys.modules[name] = module
    return module


host = _load('native_epoch_host', 'native_epoch_host.py')
builder = _load('native_win98_build', 'build.py')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read_pinned(path, maximum):
    """Bounded read of one regular nonsymlink file; identity stable across the read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'bounded regular input: %s' % path)
        raw = os.pread(fd, before.st_size + 1, 0); after = os.fstat(fd)
        need(len(raw) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed while read: %s' % path)
        return raw, {'path': str(Path(path).resolve()), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(fd)


def pci_functions(data):
    """Flatten a complete query-pci result (bridges included) without authority."""
    need(type(data) is list and 1 <= len(data) <= 32, 'bounded complete query-pci result required')
    rows, seen = [], set()
    def walk(devices, bus, depth):
        need(type(devices) is list and len(devices) <= 256 and depth <= 4, 'bounded PCI device list')
        for row in devices:
            need(type(row) is dict and len(rows) < 256, 'PCI device schema/count')
            number = host.integer(row.get('bus'), 0, 255); slot = host.integer(row.get('slot'), 0, 31)
            function = host.integer(row.get('function'), 0, 7)
            bdf = number << 8 | slot << 3 | function
            need(number == bus and bdf not in seen, 'duplicate/misplaced PCI BDF'); seen.add(bdf)
            ids, klass, regions = row.get('id'), row.get('class_info'), row.get('regions')
            need(type(ids) is dict and type(klass) is dict and type(regions) is list and len(regions) <= 7 and
                 type(row.get('qdev_id')) is str, 'complete PCI identity/regions required')
            bars = {}
            for r in regions:
                need(type(r) is dict and r.get('type') in ('io', 'memory'), 'PCI region schema')
                bar = host.integer(r.get('bar'), 0, 6); need(bar not in bars, 'duplicate PCI region')
                if r['type'] == 'memory':
                    need(type(r.get('prefetch')) is bool and type(r.get('mem_type_64')) is bool, 'memory BAR flags required')
                bars[bar] = (r['type'], host.integer(r.get('address'), -1, (1 << 64) - 1), host.integer(r.get('size'), 1, 1 << 40),
                             r.get('mem_type_64', False), r.get('prefetch', False))
            rows.append({'bdf': bdf, 'bus': number, 'vendor': host.integer(ids.get('vendor'), 0, 65535),
                         'device': host.integer(ids.get('device'), 0, 65535),
                         'class': host.integer(klass.get('class'), 0, 65535), 'qdev_id': row['qdev_id'], 'bars': bars})
            bridge = row.get('pci_bridge')
            if bridge is not None:
                need(type(bridge) is dict and type(bridge.get('bus')) is dict, 'PCI bridge schema')
                walk(bridge.get('devices', []), host.integer(bridge['bus'].get('secondary'), 0, 255), depth + 1)
    buses = set()
    for bus in data:
        need(type(bus) is dict, 'PCI bus schema'); number = host.integer(bus.get('bus'), 0, 255)
        need(number not in buses, 'duplicate PCI bus'); buses.add(number); walk(bus.get('devices'), number, 0)
    return rows


def ecam_words(snapshot, flat, bdf):
    text = snapshot['xp'].get(str(bdf)); address = flat['ecam'][0] + bdf * 4096
    need(type(text) is str and address + 40 <= flat['ecam'][1], 'observed ECAM xp for selected function required')
    return host.parse_xp(text, address)


def select(snapshot, persistence):
    need(type(snapshot) is dict and set(snapshot) == {'query-status', 'info-mtree-f', 'query-pci', 'xp'} and
         type(snapshot['xp']) is dict, 'exact paused snapshot fields required')
    status = snapshot['query-status']
    need(type(status) is dict and status.get('running') is False and status.get('status') == 'paused',
         'actual stopped/paused query-status required')
    flat = host.parse_flatview(snapshot['info-mtree-f'])
    rows = pci_functions(snapshot['query-pci'])
    display = [r for r in rows if r['class'] >> 8 == 0x03]
    need(len(display) == 1, 'exactly one observed display function required')
    vga = display[0]
    need(vga['bus'] == 0 and (vga['vendor'], vga['device'], vga['class']) == (0x1234, 0x1111, 0x0300),
         'observed display is not the owned bus-zero QEMU StdVGA (1234:1111 class 0300)')
    region = vga['bars'].get(0)
    need(region is not None and region[0] == 'memory' and region[2] == LFB and region[3] is False and region[4] is True,
         'StdVGA BAR0 must be the 16MiB prefetchable 32-bit LFB')
    base = region[1]
    need(0x08000000 <= base <= 0xfec00000 - LFB and base % LFB == 0, 'observed StdVGA LFB not assigned/aligned in native window')
    selected = {1: {'row': vga, 'words': ecam_words(snapshot, flat, vga['bdf']), 'base': base}}
    if persistence:
        disks = [r for r in rows if r['vendor'] == 0x1af4 and r['device'] in (0x1001, 0x1042)]
        need(len(disks) == 1, 'exactly one observed virtio-blk function required for persistence')
        disk = disks[0]
        need(disk['bus'] == 0 and disk['class'] == 0x0100, 'persistence device must be the bus-zero virtio-blk SCSI-class function')
        for bar, (kind, address, extent, wide, prefetch) in disk['bars'].items():
            if bar < 6:
                need(address >= 0, 'unassigned persistence BAR')
                need(kind == 'io' or address + extent <= 1 << 32,
                     'observed persistence BAR%d is above 4 GiB; probe/launch with %s' % (bar, host.MMIO64_OFF))
                # Only the hardwired 64-bit prefetchable virtio-pci modern
                # capability BAR is admitted as prefetchable; W98PERS192 keeps
                # kind MEM64 and the sealed raw ECAM DWORD carries the bit.
                need(not prefetch or (kind == 'memory' and wide),
                     'observed prefetchable persistence BAR%d is not the 64-bit virtio-pci capability BAR shape' % bar)
        selected[2] = {'row': disk, 'words': ecam_words(snapshot, flat, disk['bdf'])}
    need(set(snapshot['xp']) == {str(s['row']['bdf']) for s in selected.values()}, 'xp reads only for the selected functions')
    for role, s in selected.items():
        row, words = s['row'], s['words']
        need(words[0] == row['vendor'] | row['device'] << 16 and words[2] >> 8 == row['class'] << 8 and
             not words[3] & 0x7f0000, 'raw ECAM identity/class/header differs from query-pci')
        need(role != 1 or words[1] & 3 == 3, 'StdVGA I/O+memory decode not enabled at probe')
    need(selected[1]['words'][4] == base | 8, 'raw StdVGA BAR0 differs from observed LFB')
    return flat, selected


def encode_vga(bdf, base, rom, receipt):
    source_sha, config_sha = receipt.get('source_tree_digest_sha256'), receipt.get('generated_configuration_sha256')
    need(all(type(x) is str and len(x) == 64 for x in (source_sha, config_sha)), 'producer source/config digests required')
    return (struct.pack('<6I2Q', 0x41475657, 1, 136, 1, bdf, 0, base, LFB) + hashlib.sha256(rom).digest() +
            bytes.fromhex(source_sha) + bytes.fromhex(config_sha))


def encode_persistence(row):
    raw = bytearray(192)
    struct.pack_into('<II4H2Q2I', raw, 0, 0x52503957, 1, row['bdf'], 0x1af4, row['device'], 0,
                     2304 << 20, 2 << 30, 0x53485739, 0)
    for bar, (kind, address, extent, wide, _) in sorted(row['bars'].items()):
        if bar < 6:
            code = 3 if kind == 'io' else 2 if wide else 1
            struct.pack_into('<QQII', raw, 40 + 24 * bar, address, extent, code, 0)
    return bytes(raw)


def encode(observation, rom, receipt, persistence=False):
    """Pure expectation encoder; returns (blobs, raw_bars, selected) or raises."""
    need(type(observation) is dict and set(observation) == {'schema', 'probe_recipe_argv', 'snapshots'} and
         observation['schema'] == OBSERVATION_SCHEMA, 'exact paused-observation schema required')
    argv = observation['probe_recipe_argv']
    need(type(argv) is list and 0 < len(argv) <= 512 and all(type(a) is str for a in argv) and
         any(argv[i:i + 2] == ['-device', 'VGA'] for i in range(len(argv))), 'probe recipe argv with -device VGA required')
    need(not persistence or any(a.startswith('virtio-blk-pci,') for a in argv), 'persistence requires the virtio-blk probe recipe')
    # HostGrant pins this firmware knob iff persistence is selected, so the
    # expectation must come from a probe of that same recipe (and vice versa).
    need(sum(argv[i:i + 2] == ['-fw_cfg', host.MMIO64_OFF] for i in range(len(argv))) == (1 if persistence else 0),
         'probe recipe 64-bit PCI aperture knob must match the persistence selection')
    snapshots = observation['snapshots']
    need(type(snapshots) is list and len(snapshots) == 2, 'exactly two complete paused snapshots required')
    derived = [select(s, persistence) for s in snapshots]
    summary = [{role: (s['row'], s['words']) for role, s in sel.items()} for _, sel in derived]
    need(summary[0] == summary[1] and snapshots[0]['query-pci'] == snapshots[1]['query-pci'],
         'the two paused snapshots differ; no stable expectation')
    need(type(receipt) is dict and type(receipt.get('padded_ROM')) is dict and
         receipt['padded_ROM'].get('sha256') == hashlib.sha256(rom).hexdigest(),
         'ROM bytes differ from the producer receipt padded_ROM')
    builder.validate_vga_rom(rom)
    selected = derived[0][1]
    blobs = {'VGACFG.BIN': encode_vga(selected[1]['row']['bdf'], selected[1]['base'], rom, receipt)}
    if persistence:
        blobs['W98PERS.BIN'] = encode_persistence(selected[2]['row'])
        builder.validate_persistence_config(blobs['W98PERS.BIN'])
    builder.validate_vga_config(blobs['VGACFG.BIN'])
    raw_bars = {role: tuple(s['words'][4:10]) for role, s in selected.items()}
    # The live authority's own expectation/PCI validators must accept this
    # probe; otherwise HostGrant would refuse it later, so refuse it now.
    expected = host.Expectations(blobs['VGACFG.BIN'], rom, blobs.get('W98PERS.BIN'), raw_bars)
    for (flat, _), snapshot in zip(derived, snapshots):
        host.validate_pci(snapshot['query-pci'], expected, flat)
    return blobs, {str(role): list(words) for role, words in raw_bars.items()}, selected


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--observation', type=Path, required=True)
    p.add_argument('--vga-rom', type=Path, required=True)
    p.add_argument('--vga-build-receipt', type=Path, required=True)
    p.add_argument('--with-persistence', action='store_true',
                   help='also emit W98PERS.BIN (omit for the console-first milestone)')
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args(argv)
    out = Path(os.path.abspath(a.out)); parent = out.parent
    st = os.lstat(parent)
    need(not os.path.lexists(out) and stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700, 'fresh output under an owned mode0700 parent required')
    obs_raw, obs_pin = read_pinned(a.observation, MAX_OBSERVATION)
    rom, rom_pin = read_pinned(a.vga_rom, 65536)
    receipt_raw, receipt_pin = read_pinned(a.vga_build_receipt, builder.VGA_RECEIPT_MAX)
    blobs, raw_bars, selected = encode(strict_json(obs_raw), rom, strict_json(receipt_raw), a.with_persistence)
    # Same builder admission the native builder/guardian rerun from leased
    # FDs, run on sealed in-memory copies BEFORE any output exists.
    fds = {}
    try:
        for name, raw in blobs.items():
            fd = fds[name] = os.memfd_create('shz-' + name, os.MFD_CLOEXEC)
            need(os.write(fd, raw) == len(raw), 'complete expectation copy')
        fds['VGAROM.BIN'] = os.open(a.vga_rom, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        receipt_fd = os.open(a.vga_build_receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            builder.validate_optional_native(fds, {'vga-build-receipt': receipt_fd})
        finally:
            os.close(receipt_fd)
    finally:
        for fd in fds.values():
            os.close(fd)
    need(read_pinned(a.observation, MAX_OBSERVATION)[1] == obs_pin and read_pinned(a.vga_rom, 65536)[1] == rom_pin and
         read_pinned(a.vga_build_receipt, builder.VGA_RECEIPT_MAX)[1] == receipt_pin, 'expectation inputs changed')
    os.umask(0o077); os.mkdir(out, 0o700)
    pins = {}
    for name, raw in blobs.items():
        fd = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            need(os.write(fd, raw) == len(raw), 'complete expectation write'); os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(out / name, 0o400)
        pins[name] = {'path': str(out / name), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    optional = {**pins, 'VGAROM.BIN': rom_pin}
    record = {'schema': EXPECTATION_SCHEMA, 'status': 'EXPECTATION_ONLY_NOT_AUTHORITY',
              'observation': obs_pin, 'probe_recipe_argv_sha256': hashlib.sha256(
                  json.dumps(strict_json(obs_raw)['probe_recipe_argv']).encode()).hexdigest(),
              'encoder_source': read_pinned(Path(__file__).resolve(), 1 << 20)[1],
              'selected': {str(role): {'bdf': s['row']['bdf'], 'qdev_id': s['row']['qdev_id'],
                                       'vendor': s['row']['vendor'], 'device': s['row']['device'], 'class': s['row']['class']}
                           for role, s in selected.items()},
              'intent_fragment': {'optional_native_inputs': optional,
                                  'optional_native_provenance': {'vga-build-receipt': receipt_pin},
                                  'raw_bars': raw_bars},
              **{flag: False for flag in FALSE_FLAGS}}
    fd = os.open(out / 'expectation.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, (json.dumps(record, indent=2, sort_keys=True) + '\n').encode()); os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'status': record['status'], 'out': str(out), 'outputs': pins, 'raw_bars': raw_bars}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
