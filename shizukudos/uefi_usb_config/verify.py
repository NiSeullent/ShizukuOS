#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original configuration evidence verifier; no C parser, VM or hardware calls.

Reuses the project's independently authored device/MMIO/context verifier and
extends its exact physical-ring history checks for four control requests.
Configuration wire records are decoded independently in Python from USB2
sections9.4.3/9.6 and serialized into the complete fixed C result ABI. This
verifier neither submits SET_CONFIGURATION nor claims a functioning HID device.
"""
import importlib.util
from pathlib import Path
import struct

_path = Path(__file__).resolve().parent.parent / 'uefi_usb/verify.py'
_spec = importlib.util.spec_from_file_location('usb_device_evidence_contract', _path)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
EvidenceError = base.EvidenceError
require, snapshot, words, u32, u64 = base.require, base.snapshot, base.words, base.u32, base.u64
inspect_mmio, inspect_descriptor = base.inspect_mmio, base.inspect_descriptor
PROOF_BYTES, CONTROLLER_BYTES, DEVICE_BYTES = 256, 4096, 12288
CONFIG_ADDRESS, CONFIG_BYTES, CONFIG_PAGE = 0x0200d000, 3848, 4096


def decode_proof(data):
    proof = base.decode_proof(data)
    proof['configuration_address'], proof['configuration_bytes'], proof['configuration_index'] = proof.pop('reserved')
    return proof


def decode_configuration(raw, speed):
    """Return a separately reconstructed 1688-byte ABI and bounded observations."""
    require(9 <= len(raw) <= 2048 and raw[:2] == bytes((9,2)), 'invalid configuration header')
    total = int.from_bytes(raw[2:4], 'little')
    count, value, string, attributes, power = raw[4:9]
    require(total == len(raw) and 1 <= count <= 16 and value != 0 and
            attributes & 0x80 and attributes & 0x1f == 0 and power <= 250,
            'invalid configuration total/interfaces/value/attributes/power')
    # Walk raw records first. All later ownership checks use these bounded
    # records, independently of the supplied C arrays/counters.
    records, cursor = [], 9
    while cursor < total:
        require(cursor+2 <= total, 'truncated configuration record header')
        length, kind = raw[cursor:cursor+2]
        require(length >= 2 and cursor+length <= total, 'truncated configuration record')
        records.append((cursor,kind,raw[cursor:cursor+length]))
        cursor += length
    alternates, endpoints, opaque, current, preceding = [], [], [], None, 0xffff
    pairs, seen, defaults, owners = set(), set(), set(), {}
    for offset, kind, record in records:
        if kind == 4:
            require(len(record) == 9 and len(alternates) < 32, 'invalid/too many interface records')
            number, alternate, declared, cls, subclass, protocol, label = record[2:9]
            require(number < count and declared <= 30 and cls != 0 and (number,alternate) not in pairs,
                    'invalid/duplicate interface alternate')
            pairs.add((number,alternate)); seen.add(number)
            if alternate == 0: defaults.add(number)
            current = {'offset':offset,'number':number,'alternate':alternate,'declared':declared,
                       'class':cls,'subclass':subclass,'protocol':protocol,'string':label,
                       'first_endpoint':len(endpoints),'endpoints':[]}
            alternates.append(current); preceding = 0xffff
        elif kind == 5:
            require(len(record) == 7 and current is not None and len(endpoints) < 64,
                    'invalid/too many endpoint records')
            address, attributes, interval = record[2], record[3], record[6]
            packet = int.from_bytes(record[4:6], 'little')
            kind = attributes & 3
            require(address & 15 and address & 0x70 == 0 and attributes & 0xfc == 0 and
                    packet & 0xf800 == 0, 'unsupported endpoint fields')
            if kind == 2:
                require((speed == 1 and packet in (8,16,32,64)) or (speed == 3 and packet == 512),
                        'invalid/unsupported bulk packet or speed')
            elif kind == 3:
                require(packet <= {1:64,2:8,3:1024}[speed] and interval > 0 and
                        (speed != 3 or (interval <= 16 and (current['alternate'] != 0 or packet <= 64))),
                        'invalid/unsupported interrupt packet or interval')
            else:
                raise EvidenceError('unsupported endpoint transfer type')
            require(address not in current['endpoints'] and
                    (address not in owners or owners[address] == current['number']),
                    'duplicate/cross-interface endpoint address')
            owners[address] = current['number']; current['endpoints'].append(address)
            preceding = len(endpoints)
            endpoints.append((offset,packet,len(alternates)-1,address,kind,interval,1,0))
        elif kind == 11 or (kind >= 0x20 and kind not in (0x30,0x31)):
            require(len(opaque) < 64, 'too many opaque descriptors')
            opaque.append((offset,len(record),kind,len(alternates)-1 if current is not None else 0xffff,preceding))
        else:
            raise EvidenceError('unsupported configuration descriptor type')
    require(seen == defaults == set(range(count)) and
            all(len(item['endpoints']) == item['declared'] for item in alternates),
            'configuration interface/alternate/endpoint counts disagree')
    if speed == 2:
        require(sum(max(len(item['endpoints']) for item in alternates if item['number'] == number)
                    for number in range(count)) <= 2, 'low-speed endpoint budget exceeded')
    expected = bytearray(1688)
    struct.pack_into('<IIHBBHHHHBBBB', expected, 0, 1688,1,total,value,count,len(alternates),
                     len(endpoints),len(opaque),power*2,raw[7],string,{1:2,2:1,3:3}[speed],0)
    for index, item in enumerate(alternates):
        struct.pack_into('<HH8B', expected, 24+index*12, item['offset'],item['first_endpoint'],
            item['number'],item['alternate'],item['declared'],len(item['endpoints']),
            item['class'],item['subclass'],item['protocol'],item['string'])
    for index, item in enumerate(endpoints):
        struct.pack_into('<HHH4BH', expected, 408+index*12, *item)
    for index, item in enumerate(opaque):
        struct.pack_into('<HBBHH', expected, 1176+index*8, *item)
    return bytes(expected), {'total_length':total,'configuration_value':value,
        'interfaces':count,'alternates':len(alternates),'endpoints':len(endpoints),
        'opaque_descriptors':len(opaque),'raw_hex':raw.hex()}


def inspect_configuration(proof_bytes, proof, device, page, topology):
    page = snapshot(page, CONFIG_PAGE, 'configuration result page')
    require(proof['configuration_address'] == CONFIG_ADDRESS and proof['configuration_bytes'] == CONFIG_BYTES and
            0 <= proof['configuration_index'] < proof['descriptor']['parsed']['configuration_count'],
            'configuration proof address/size/index disagrees with device')
    size, version, index, length = words(page,0)
    require(size == CONFIG_BYTES and version == 1 and index == proof['configuration_index'] and
            9 <= length <= 2048, 'invalid configuration result ABI/index/length')
    raw = device[9216:9216+length]
    header = device[8576:8585]
    require(header == raw[:9], 'GET9/full header identity changed')
    require(device[8585:8640] == bytes([0xa5])*55 and
            device[9216+length:11328] == bytes([0xa5])*(2112-length), 'configuration DMA guards changed')
    parsed, observation = decode_configuration(raw,topology['port_speed_id'])
    expected = bytearray(CONFIG_PAGE)
    struct.pack_into('<4I',expected,0,CONFIG_BYTES,1,index,length)
    expected[16:100] = bytes(proof_bytes)[160:244]
    expected[100:109] = header
    expected[112:112+length] = raw
    expected[2160:3848] = parsed
    require(page == expected, 'configuration C result/padding differs from independent DMA decode')
    observation['index'] = index
    return observation


def check_rings(proof, controller, device, ctrl_address, dev_address, topology, descriptor, configuration):
    count = 4 if descriptor['evaluate_context'] else 3
    require(proof['commands_completed'] == count and proof['command_index'] == count and
            proof['command_cycle'] == 1, 'unexpected command sequence/count/cycle')
    # Section 4.6.4 requires software to clear the disabled slot's DCBAA entry.
    # Former device ownership is evidenced by the preserved addressed context
    # and correlated Address/Disable commands, not a stale final DMA pointer.
    require(controller[:2048] == bytes(2048), 'DCBAA retains a pointer after Disable Slot')
    command_specs = [(9,0,topology['slot_type'] << 16), (11,dev_address+4096,1 << 24)]
    if descriptor['evaluate_context']:
        command_specs.append((13,dev_address+4096,1 << 24))
    command_specs.append((10,0,1 << 24))
    command_pointers = []
    for index, (kind, pointer, flags) in enumerate(command_specs):
        offset = 2048+index*16
        require(words(controller, offset) == (pointer,0,0,(kind << 10) | flags | 1),
                'command TRB differs from Enable/Address/Evaluate/Disable sequence')
        command_pointers.append(ctrl_address+offset)
    require(controller[2048+count*16:2304] == bytes(256-count*16), 'unexpected extra command/Link TRB')
    require(words(controller,3328) == (ctrl_address+2304,0,64,0) and
            controller[3344:] == bytes(CONTROLLER_BYTES-3344), 'invalid ERST or controller DMA padding')
    requests = ((1,0,8,8448),(1,0,18,8512),
                (2,configuration['index'],9,8576),
                (2,configuration['index'],configuration['total_length'],9216))
    for index, (kind, descriptor_index, length, buffer_offset) in enumerate(requests):
        offset = 8192+index*48
        expected = (((kind << 24) | (descriptor_index << 16) | 0x680,length << 16,8,(2 << 10) | (3 << 16) | (1 << 6) | 1),
                    (dev_address+buffer_offset,0,length,(3 << 10) | (1 << 16) | (1 << 2) | 1),
                    (0,0,0,(4 << 10) | (1 << 5) | 1))
        for stage, trb in enumerate(expected):
            require(words(device,offset+stage*16) == trb, 'GET_DESCRIPTOR Setup/Data/Status TRB mismatch')
    require(device[8384:8432] == bytes(48) and
            words(device,8432) == (dev_address+8192,0,0,(6 << 10) | 3),
            'unexpected extra EP0 TRB or invalid closing Link')
    require(proof['completion_low'] == command_pointers[-1] and proof['completion_high'] == 0 and
            proof['last_completion_code'] == 1, 'last completion does not identify Disable Slot')
    end = proof['event_index']
    require(proof['event_cycle'] == 1 and 0 < end < 64, 'wrapped or empty event history is outside fixture')
    # Transfer chronology is checked independently of proof command counters.
    expected_order = [('command',command_pointers[0]),('command',command_pointers[1]),
                      ('status',dev_address+8192+2*16)]
    if descriptor['evaluate_context']:
        expected_order.append(('command',command_pointers[2]))
    expected_order.extend((('status',dev_address+8192+5*16),
                           ('status',dev_address+8192+8*16),
                           ('status',dev_address+8192+11*16),
                           ('command',command_pointers[-1])))
    progress, ports, shorts, reset_event = 0, 0, set(), False
    observed = []
    for index in range(end):
        lo, hi, status, control = words(controller,2304+index*16)
        kind = (control >> 10) & 63
        pointer, code, residual = lo | (hi << 32), status >> 24, status & 0xffffff
        require(control & 1 == 1, 'event cycle does not establish controller ownership')
        if kind == 34:
            require(1 <= lo >> 24 <= topology['max_ports'] and lo & 0xffffff == 0 and hi == 0 and
                    status == 1 << 24 and control == (34 << 10) | 1, 'malformed port event')
            ports += 1
            if progress == 0 and lo >> 24 == topology['root_port']:
                reset_event = True
            continue
        require(progress < len(expected_order), 'unexpected extra completed operation')
        operation, expected_pointer = expected_order[progress]
        if kind == 33:
            require(control == (1 << 24) | (33 << 10) | 1 and status == 1 << 24 and
                    operation == 'command' and pointer == expected_pointer,
                    'command completion pointer/slot/status/order mismatch')
        elif kind == 32:
            require(control == (1 << 24) | (1 << 16) | (32 << 10) | 1 and operation == 'status',
                    'transfer event slot/EP0/flags/order mismatch')
            if code == 13:
                require(pointer == expected_pointer-16 and residual == 0 and pointer not in shorts,
                        'short transfer, duplicate or wrong Data-stage event')
                shorts.add(pointer)
                observed.append({'kind':'data_zero_residue_short','pointer':pointer})
                continue
            require(code == 1 and residual == 0 and pointer == expected_pointer,
                    'Status completion pointer/code/residual mismatch')
        else:
            raise EvidenceError('unsupported event type in completed history')
        observed.append({'kind':operation,'pointer':pointer})
        progress += 1
    require(progress == len(expected_order) and ports == proof['port_events'] and reset_event,
            'event history does not cover all four descriptor transfers and cleanup')
    require(controller[2304+end*16:3328] == bytes(1024-end*16), 'unconsumed event evidence is nonzero')
    return {'command_count':count, 'port_event_count':ports, 'zero_residue_short_events':len(shorts),
            'events':observed}


def verify_evidence(proof_bytes, controller_dma_bytes, device_dma_bytes,
                    expected_controller_address, expected_device_address, *, mmio_bytes, configuration_page,
                    expected_configuration_address=CONFIG_ADDRESS, fixture=None):
    """Return independent decoded observations only after every success invariant.

    Expected addresses come from the build's linked symbols, not the proof.
    Optional fixture keys are independent observations: root_port, context_bytes,
    port_speed_id, slot_type, max_ports, vendor_id, product_id, descriptor_hex.
    Never populate these from the same proof or raw descriptor being checked.
    A failure/quarantine record is useful diagnostics but cannot pass this API.
    """
    proof = decode_proof(proof_bytes)
    controller = snapshot(controller_dma_bytes, CONTROLLER_BYTES, 'controller DMA')
    device = snapshot(device_dma_bytes, DEVICE_BYTES, 'device DMA')
    for address, size in ((expected_controller_address,CONTROLLER_BYTES),(expected_device_address,DEVICE_BYTES)):
        require(type(address) is int and address % 4096 == 0 and
                0x02010000 <= address <= 0x02100000-size, 'DMA symbol is outside bounded payload region')
    require(expected_controller_address+CONTROLLER_BYTES <= expected_device_address or
            expected_device_address+DEVICE_BYTES <= expected_controller_address, 'DMA allocations overlap')
    require((proof['magic'],proof['size'],proof['version']) == (0x43425355,256,2), 'invalid proof ABI')
    require(proof['reserved0'] == proof['reserved1'] == 0,
            'proof reserved bytes changed')
    require(proof['stage'] == 3 and proof['calibrated'] == 1 and 10 <= proof['ticks_per_us'] <= 100000 and
            proof['start_tsc'] != 0, 'proof is not a calibrated completed success')
    require(all(proof[name] == 0 for name in ('open_result','probe_status','transport_error','parser_status',
            'parser_offset','close_result','controller_dma_owned','device_dma_owned','dma_in_use_mask')),
            'operation failure or DMA quarantine remains')
    require(proof['failed_stage'] == 11 and proof['descriptor_bytes'] == 84 and
            proof['allocations'] == proof['releases'] == 2, 'probe completion/lifetime counters disagree')
    require(proof['dma_address'] == expected_controller_address and proof['device_dma_address'] == expected_device_address,
            'proof DMA addresses disagree with linked symbols')
    require(proof['original_pci_command'] == proof['restored_pci_command'] <= 0xffff,
            'PCI command ownership was not restored')
    require(0x100 <= proof['pci_bdf'] <= 0xffff and proof['bridges'] >= 1 and
            0x80000000 <= proof['mmio'] <= 0xffffc000 and proof['mmio'] % 0x4000 == 0,
            'proof lacks bounded bridged PCI controller coordinates')
    require(proof['last_status'] & 0x1805 == 0, 'controller reported halted, fatal or not-ready status')
    require(type(expected_configuration_address) is int and expected_configuration_address == CONFIG_ADDRESS,
            'configuration address is outside the reserved result page')
    topology = inspect_mmio(mmio_bytes)
    descriptor = inspect_descriptor(proof, device, topology)
    configuration = inspect_configuration(proof_bytes, proof, device, configuration_page, topology)
    # These two extension ranges were fully checked against DMA bytes/guards
    # above. Clear only those ranges in a local view for the original context
    # verifier's unused-space checks; all other physical bytes remain intact.
    context_view = bytearray(device)
    context_view[8576:8640] = bytes(64)
    context_view[9216:11328] = bytes(2112)
    usb_address = base.check_contexts(bytes(context_view), expected_device_address, topology, descriptor)
    rings = check_rings(proof, controller, device, expected_controller_address, expected_device_address, topology, descriptor, configuration)
    if fixture is not None:
        require(isinstance(fixture, dict) and set(fixture).issubset({
            'root_port','context_bytes','port_speed_id','slot_type','max_ports','vendor_id','product_id','descriptor_hex','configuration_hex','configuration_value','configuration_index'}),
            'unsupported independent fixture metadata')
        observed = {**topology, **descriptor, 'descriptor_hex':descriptor['raw_device'],
                    'configuration_hex':configuration['raw_hex'],
                    'configuration_value':configuration['configuration_value'],
                    'configuration_index':configuration['index']}
        require(all(observed[name] == value for name,value in fixture.items()),
                'independent fixture identity/topology disagrees with DMA/MMIO')
    return {'status':'PASS', 'proof':proof, 'topology':topology, 'descriptor':descriptor,
            'usb_address':usb_address, 'rings':rings, 'configuration':configuration, 'native_windows':'not_tested',
            'claim':'four EP0 device/configuration descriptor reads with completed shutdown; no SET_CONFIGURATION or HID reports'}
