# SPDX-License-Identifier: GPL-2.0-only
"""Admit source-bound public PCI observations as prospective data only.

The caller supplies independently admitted producer pins and a held-descriptor
reader. A JSON claim alone is insufficient. This adapter neither launches a VM
nor confers current device authority or verifies a Windows 98 desktop.
"""
import copy
import hashlib
import json
import os
import re

PRODUCER_PINS = frozenset(('firmware', 'firmware_sources', 'firmware_header',
    'firmware_build_receipt', 'observer_source', 'host_source', 'capture_source',
    'builder_source', 'r5_source', 'r5_baseline'))
ARTIFACT_MAXIMUM = 256 << 20


def need(ok, message):
    if not ok:
        raise ValueError(message)


def validate_pin(pin, maximum):
    need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'exact source/artifact pin required')
    path = pin['path']
    need(type(path) is str and path.startswith('/') and not path.startswith('//') and
         '\0' not in path and all(part not in ('', '.', '..') for part in path[1:].split('/')),
         'absolute normalized source/artifact path required')
    need(type(pin['bytes']) is int and 0 < pin['bytes'] <= maximum and
         type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None,
         'positive bounded size and exact SHA-256 required')


def held_bytes(pin, maximum, read_pinned):
    validate_pin(pin, maximum)
    # Give callbacks a separate pin: changing caller-owned evidence cannot alter
    # the comparisons performed against this call's admitted snapshot.
    raw = read_pinned(copy.deepcopy(pin), maximum)
    need(type(raw) is bytes and len(raw) == pin['bytes'] and
         hashlib.sha256(raw).hexdigest() == pin['sha256'], 'held source/artifact bytes differ')
    return raw


def parse_snapshot(text, address):
    need(type(text) is str and len(text) <= 4096, 'bounded raw PCI snapshot required')
    lines = text.splitlines()
    need(len(lines) == 3, 'three original ten-DWORD snapshot lines required')
    words = []
    for i, count in enumerate((4, 4, 2)):
        match = re.fullmatch(r'([0-9a-fA-F]{8,16}):((?: 0x[0-9a-fA-F]{8}){%d})' % count, lines[i])
        need(match is not None and int(match[1], 16) == address + 16 * i,
             'exact original snapshot offset/count required')
        words.extend(int(word, 16) for word in match[2].split())
    return tuple(words)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate producer receipt field')
        result[key] = value
    return result


def recipe_layout(argv):
    """Preserve every hardware option; abstract only named output/input paths."""
    need(type(argv) is list and argv and all(type(s) is str for s in argv), 'typed preparation recipe required')
    result = list(argv)
    for i in range(1, len(argv)):
        if argv[i-1] == '-name':
            result[i] = '<guest-name>'
        elif argv[i-1] == '-drive':
            parts = argv[i].split(',')
            need(sum(p.startswith('file=') for p in parts) == 1, 'one backing file per admitted drive required')
            result[i] = ','.join('file=<held-original>' if p.startswith('file=') else p for p in parts)
        elif argv[i-1] == '-serial':
            need(argv[i].startswith('file:'), 'original file serial sink required')
            result[i] = 'file:<owned-sink>'
        elif argv[i-1] == '-qmp':
            need(argv[i].startswith('unix:') and argv[i].endswith(',server=on,wait=off'), 'original bounded Unix QMP recipe required')
            result[i] = 'unix:<owned-socket>,server=on,wait=off'
    return result


def validate_target_recipe(observed, target_plan):
    need(type(observed) is dict, 'original observation required')
    need(type(target_plan) is dict and target_plan.get('status') == 'PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN' and
         target_plan.get('private') is True and target_plan.get('VM_executed') is False,
         'original unexecuted private target plan required')
    need(recipe_layout(observed.get('argv')) == recipe_layout(target_plan.get('qemu_argv')),
         'target hardware/device recipe differs from original preparation')
    original_pins, target_pins = observed.get('input_pins'), target_plan.get('input_pins')
    need(type(original_pins) is dict and type(target_pins) is dict, 'original and target artifact pins required')
    for name in ('qemu', 'firmware_code'):
        original, target = original_pins.get(name), target_pins.get(name)
        validate_pin(original, ARTIFACT_MAXIMUM)
        validate_pin(target, ARTIFACT_MAXIMUM)
        need(original['sha256'] == target['sha256'] and original['bytes'] == target['bytes'],
             'target QEMU/firmware source artifact differs')
    need(observed['argv'][0] == original_pins['qemu']['path'] and
         target_plan['qemu_argv'][0] == target_pins['qemu']['path'], 'recipe executable path differs from its pin')
    return hashlib.sha256(json.dumps(target_plan['qemu_argv'], separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def validate_observation(observed, expected_producer_pins, read_pinned, target_plan):
    """Return ordered role/BDF/raw BAR expectations from held producer inputs.

    expected_producer_pins must come from the caller's source admission, rather
    than being copied blindly from observed. read_pinned(pin, maximum) must read
    the corresponding original through retained custody, never reopen its path.
    Current target PROBE/REPORT/QMP-before-GRANT remains mandatory downstream.
    """
    need(type(observed) is dict and callable(read_pinned), 'observation and held reader required')
    observed, expected_producer_pins, target_plan = copy.deepcopy((observed, expected_producer_pins, target_plan))
    need(observed.get('status') == 'ACTUAL_NEW_PUBLIC_PREPARATION_OBSERVATION' and
         observed.get('VM_executed') is True and observed.get('Windows98_boot_verified') is False and
         observed.get('HostGrant_transmitted') is False, 'successful prospective public preparation only')
    need(observed.get('originals_after_match') is True and observed.get('shared_ROOT_lock_released') is True and
         type(observed.get('actual_parent_wait_status')) is int and observed.get('actual_parent_wait_status') == 0 and
         type(observed.get('actual_exit_code')) is int and observed.get('actual_exit_code') == 0,
         'completed original custody and actual parent cleanup required')
    need(type(expected_producer_pins) is dict and set(expected_producer_pins) == PRODUCER_PINS,
         'independently admitted complete producer source closure required')
    pins = observed.get('input_pins')
    need(type(pins) is dict, 'producer input pins required')
    validate_target_recipe(observed, target_plan)
    for name in ('qemu', 'firmware_code'):
        held_bytes(pins[name], ARTIFACT_MAXIMUM, read_pinned)
        if target_plan['input_pins'][name] != pins[name]:
            held_bytes(target_plan['input_pins'][name], ARTIFACT_MAXIMUM, read_pinned)
    source_bytes = {}
    for name, expected in expected_producer_pins.items():
        validate_pin(expected, 1 << 20)
        need(pins.get(name) == expected, 'held producer source pin differs')
        raw = held_bytes(expected, 1 << 20, read_pinned)
        source_bytes[name] = raw
    built = json.loads(source_bytes['firmware_build_receipt'], object_pairs_hook=unique_pairs)
    need(built.get('status') == 'ACTUAL_NEW_PUBLIC_PREPARATION_FIRMWARE_COMPILED_NOT_RUN' and
         built.get('source_unchanged') is True and built.get('VM_executed') is False and
         built.get('Windows98_boot_verified') is False and
         built.get('source_sha256') == {'prepare_pci.c': pins['firmware_sources']['sha256'],
                                      'efi.h': pins['firmware_header']['sha256']}, 'firmware source/build closure differs')
    artifact = built.get('artifact', {})
    need(artifact.get('bytes') == pins['firmware']['bytes'] and artifact.get('sha256') == pins['firmware']['sha256'] and
         artifact.get('machine') == 'AMD64' and artifact.get('subsystem') == 'EFI_APPLICATION' and
         artifact.get('imports') == [] and artifact.get('relocations') is True, 'source-built firmware artifact differs')
    argv = observed.get('argv')
    need(type(argv) is list and argv and all(type(arg) is str for arg in argv), 'exact captured argv required')
    raw_argv = b'\0'.join(os.fsencode(arg) for arg in argv) + b'\0'
    binding, owner = observed.get('argv_binding', {}), observed.get('owned_process', {})
    sha = hashlib.sha256(raw_argv).hexdigest()
    need(binding.get('matches') is True and binding.get('expected_argv') == binding.get('actual_argv') == argv and
         binding.get('expected_sha256') == binding.get('actual_sha256') == owner.get('argv_sha256') == sha and
         binding.get('expected_bytes') == binding.get('actual_bytes') == owner.get('argv_bytes') == len(raw_argv) and
         owner.get('argv') == argv and owner.get('argv_hex') == raw_argv.hex() and
         owner.get('argv_terminal_nul') is True and
         owner.get('executable_sha256') == pins['qemu']['sha256'], 'exact executed preparation argv/binary differs')
    devices = observed.get('devices')
    need(type(devices) is dict and set(devices) == {'1', '2'}, 'exact two original selected device observations required')
    ecam = set()
    flat = observed.get('flatview_text')
    need(type(flat) is str and len(flat) <= 1 << 20, 'bounded actual flatview required')
    for line in flat.splitlines():
        match = re.fullmatch(r'[ \t]*([0-9a-f]{16})-([0-9a-f]{16}) \(prio -?[0-9]+, i/o\): pcie-mmcfg-mmio[ \t]*', line)
        if match:
            lo, hi = int(match[1], 16), int(match[2], 16) + 1
            # One bus occupies 1 MiB; this adapter addresses bus-zero BDFs.
            need(0 < lo < hi <= (1 << 64) and lo % (1 << 20) == 0 and
                 (hi - lo) % (1 << 20) == 0 and 1 << 20 <= hi - lo <= 256 << 20,
                 'aligned bounded actual ECAM bus geometry required')
            ecam.add((lo, hi))
    need(len(ecam) == 1, 'one actual ECAM region required')
    lo, hi = next(iter(ecam))
    result = []
    for role in (1, 2):
        pair = devices[str(role)]
        need(type(pair) is dict and type(pair.get('role')) is int and pair['role'] == role and
             type(pair.get('bdf')) is int and 0 <= pair['bdf'] <= 255, 'typed original role/BDF required')
        reads, qmp = pair.get('reads'), pair.get('actual_preparation_QMP_reads')
        need(type(reads) is list and len(reads) == 2 and type(qmp) is list and len(qmp) == 2,
             'two firmware and two independent QMP reads required')
        words = None
        for row in reads:
            need(type(row) is dict and set(row) == {'offset', 'text', 'words'} and type(row['offset']) is int and row['offset'] == 0,
                 'original firmware read shape required')
            parsed = parse_snapshot(row['text'], 0)
            need(type(row['words']) is list and len(row['words']) == 10 and
                 all(type(w) is int and 0 <= w <= 0xffffffff for w in row['words']) and tuple(row['words']) == parsed,
                 'firmware original words/text differ')
            need(words is None or words == parsed, 'unstable firmware observation')
            words = parsed
        address = lo + pair['bdf'] * 4096
        need(address + 40 <= hi, 'scoped actual ECAM extent required')
        for row in qmp:
            need(type(row) is dict and set(row) == {'address', 'text'} and type(row['address']) is int and
                 row['address'] == address and parse_snapshot(row['text'], address) == words,
                 'independent actual QMP original differs')
        need(words[0] == 0x11111234 if role == 1 else words[0] in (0x10011af4, 0x10421af4), 'observed selected device ID differs')
        need(words[2] >> 8 == (0x030000 if role == 1 else 0x010000) and not words[3] & 0x7f0000,
             'observed selected PCI class/header differs')
        need(words[1] & 3 == 3, 'selected device I/O and memory decoding required')
        result.append({'role': role, 'bdf': pair['bdf'], 'raw_bars': list(words[4:10])})
    need(result[0]['bdf'] != result[1]['bdf'], 'selected device BDF collision')
    return result


def admit_selection(selection, target_plan, read_pinned):
    """Caller manifest selects independent pins; receipt JSON cannot select them."""
    need(type(selection) is dict and set(selection) == {'observation', 'producer_pins'},
         'explicit original observation and independent producer pins required')
    raw = held_bytes(selection['observation'], 4 << 20, read_pinned)
    observed = json.loads(raw, object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite observation')))
    return validate_observation(observed, selection['producer_pins'], read_pinned, target_plan)


def current_qmp_observation(expected, monitor, guard):
    """Prospective stopped-device comparison only; never send PROBE or GRANT.

    Production caller binds monitor to guardian-owned child with SO_PEERCRED and
    invokes the guardian's live pidfd/cgroup/source checks around every request.
    The existing native gate still requires its own fresh PROBE/REPORT/GRANT.
    """
    need(type(expected) is list and len(expected) == 2 and callable(guard), 'admitted pair and live owner guard required')
    expected=copy.deepcopy(expected)
    for role,row in enumerate(expected,1):
        need(type(row) is dict and set(row)=={'role','bdf','raw_bars'} and
             type(row['role']) is int and row['role']==role and type(row['bdf']) is int and 0<=row['bdf']<=255 and
             type(row['raw_bars']) is list and len(row['raw_bars'])==6 and
             all(type(word) is int and 0<=word<=0xffffffff for word in row['raw_bars']), 'exact immutable prospective selected device shape required')
    need(expected[0]['bdf']!=expected[1]['bdf'],'prospective selected BDF collision')
    transcripts = []
    def call(command, arguments=None):
        guard()
        result = monitor.call(command, arguments)
        raw = json.dumps(result, separators=(',', ':'), allow_nan=False).encode()
        need(len(raw) <= 1 << 20, 'bounded current QMP response required')
        guard()
        transcripts.append({'command': command, 'arguments': arguments, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
        return result
    def paused():
        status = call('query-status')
        need(type(status) is dict and status.get('running') is False and status.get('status') == 'paused', 'current QMP must be paused')
    paused()
    flat = call('human-monitor-command', {'command-line': 'info mtree -f'})
    need(type(flat) is str and flat.endswith('\n\n') and len(flat) <= 1 << 20, 'complete bounded current FlatView required')
    sections = flat.replace('\r\n', '\n').split('FlatView #')[1:]
    selected = [s for s in sections if re.search(r'^ AS "memory", root: system$', s, re.M)]
    need(len(selected) == 1 and re.search(r'^ Root memory region: system$', selected[0], re.M), 'sole current memory/system FlatView required')
    apertures = []
    for line in selected[0].splitlines():
        match = re.fullmatch(r'  ([0-9a-f]{16})-([0-9a-f]{16}) \(prio -?[0-9]+, i/o\): pcie-mmcfg-mmio', line)
        if match:
            lo, hi = int(match[1], 16), int(match[2], 16) + 1
            need(0 < lo < hi <= 1 << 64 and lo % (1 << 20) == 0 and (hi-lo) % (1 << 20) == 0 and 1 << 20 <= hi-lo <= 256 << 20, 'current ECAM geometry differs')
            apertures.append((lo, hi))
    need(len(apertures) == 1, 'sole exact current ECAM aperture required')
    lo, hi = apertures[0]
    pci = call('query-pci')
    need(type(pci) is list and 0 < len(pci) <= 32, 'bounded current PCI buses required')
    buses = [b for b in pci if type(b) is dict and type(b.get('bus')) is int and b['bus'] == 0]
    need(len(buses) == 1 and type(buses[0].get('devices')) is list and len(buses[0]['devices']) <= 256, 'one actual bus-zero device inventory required')
    for row in expected:
        bdf, role, bars = row['bdf'], row['role'], row['raw_bars']
        devices = [d for d in buses[0]['devices'] if type(d) is dict and
                   type(d.get('slot')) is int and type(d.get('function')) is int and
                   d['slot'] == bdf >> 3 and d['function'] == bdf & 7]
        need(len(devices) == 1, 'unambiguous current selected BDF required')
        address = lo + bdf * 4096
        need(address + 40 <= hi, 'current selected ECAM extent required')
        words = None
        for _ in range(2):
            text = call('human-monitor-command', {'command-line': 'xp /10wx 0x%x' % address})
            parsed = parse_snapshot(text, address)
            need(words is None or parsed == words, 'unstable current PCI DWORDs')
            words = parsed
        vendor, device = words[0] & 65535, words[0] >> 16
        need((vendor == 0x1234 and device == 0x1111) if role == 1 else
             (vendor == 0x1af4 and device in (0x1001, 0x1042)), 'current selected device ID differs')
        need(words[2] >> 8 == (0x030000 if role == 1 else 0x010000) and
             not words[3] & 0x7f0000 and words[1] & 3 == 3 and list(words[4:]) == bars,
             'current class/header/decode/raw BAR differs')
        ident, klass = devices[0].get('id'), devices[0].get('class_info')
        need(type(ident) is dict and type(klass) is dict and
             type(ident.get('vendor')) is int and ident['vendor'] == vendor and
             type(ident.get('device')) is int and ident['device'] == device and
             type(klass.get('class')) is int and klass['class'] == words[2] >> 16,
             'current QMP PCI inventory and ECAM identity differ')
    paused()
    return {'status': 'CURRENT_PAUSED_PCI_PREPARATION_MATCH_NOT_DEVICE_AUTHORITY',
            'HostGrant_transmitted': False, 'Windows98_boot_verified': False,
            'device_authority_admitted': False, 'transcripts': transcripts}
