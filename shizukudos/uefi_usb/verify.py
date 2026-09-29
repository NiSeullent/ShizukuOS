#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original, side-effect-free verifier for the bounded USB EP0 guest fixture.

Inputs are independent physical-memory/MMIO dumps, not simulated USB replies.
This verifier does not launch a VM, read files, import the C implementation, or
assert native Windows compatibility. The caller separately binds source/build
hashes, PCI/QMP inventory, final CPU handoff, process shutdown, and file hashes.

Format facts: Intel xHCI 1.2b sections 6.1, 6.2, 6.4 and 7.2,
https://cdrdv2-public.intel.com/625472/625472_xHCI_Rev1_2b.pdf ;
USB2 chapter 9, https://www.usb.org/document-library/usb-20-specification .
No external implementation or pseudocode was copied. Fixed offsets, preserved
snapshots and the small no-wrap operation sequence are project fixture policy.
"""
import struct


PROOF_BYTES = 256
CONTROLLER_BYTES = 4096
DEVICE_BYTES = 12288
MMIO_BYTES = 0x4000
PROOF_FIELDS = ('stage pci_bdf mmio bridges open_result probe_status transport_error '
    'parser_status failed_stage parser_offset close_result controller_dma_owned device_dma_owned '
    'allocations releases commands_completed port_events last_status last_completion_code '
    'completion_low completion_high dma_in_use_mask original_pci_command restored_pci_command '
    'command_index command_cycle event_index event_cycle dma_address device_dma_address '
    'descriptor_bytes reserved1').split()


class EvidenceError(ValueError):
    """A snapshot is malformed, inconsistent, or outside this fixture contract."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def snapshot(data, size, label):
    require(isinstance(data, (bytes, bytearray, memoryview)), label+' must be bytes')
    require(len(data) == size, label+' has incorrect size')
    value = bytes(data)
    require(len(value) == size, label+' has incorrect byte size')
    return value


def words(data, offset, count=4):
    return struct.unpack_from('<'+'I'*count, data, offset)


def u32(data, offset):
    return words(data, offset, 1)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def decode_proof(data):
    """Decode the exact wire ABI for polling/diagnostics; this is not a pass."""
    data = snapshot(data, PROOF_BYTES, 'proof')
    names = ('magic','size','version','calibrated','ticks_per_us','reserved0','start_tsc')
    result = dict(zip(names, struct.unpack_from('<6IQ', data)))
    result.update(zip(PROOF_FIELDS, words(data, 32, 32)))
    descriptor = dict(zip(('struct_size','abi_version','root_port','slot_id',
        'context_bytes','port_speed_id','initial_ep0_packet','final_ep0_packet'),
        struct.unpack_from('<6I2H', data, 160)))
    descriptor['first_eight'] = data[188:196].hex()
    descriptor['raw_device'] = data[196:214].hex()
    descriptor['reserved'] = list(data[214:216])
    parsed = dict(zip(('struct_size','abi_version','usb_bcd','vendor_id','product_id','device_bcd',
        'device_class','subclass','protocol','control_packet_bytes','manufacturer_string',
        'product_string','serial_string','configuration_count','speed'),
        struct.unpack_from('<2I4H9B', data, 216)))
    parsed['reserved'] = list(data[241:244])
    descriptor['parsed'] = parsed
    result['descriptor'] = descriptor
    result['reserved'] = list(words(data, 244, 3))
    return result


def inspect_mmio(data):
    """Derive topology from final physical MMIO and prove detached DMA pointers."""
    data = snapshot(data, MMIO_BYTES, 'MMIO')
    first, hcs1, hcs2, hcc = (u32(data, n) for n in (0,4,8,16))
    op, version = first & 255, first >> 16
    ports, slots, interrupters = hcs1 >> 24, hcs1 & 255, (hcs1 >> 8) & 2047
    runtime, doorbell = u32(data, 24), u32(data, 20)
    require(version in (0x100,0x110,0x120) and 0x20 <= op and op % 4 == 0,
            'unsupported MMIO capability header')
    require(slots > 0 and ports > 0 and 1 <= interrupters <= 1024 and
            (((hcs2 >> 27) & 31) | ((hcs2 >> 16) & 0x3e0)) == 0,
            'unsupported slot/port/scratchpad capability')
    areas = ((op, 0x400+ports*16), (runtime, 32+interrupters*32), (doorbell, (slots+1)*4))
    require(runtime % 32 == 0 and doorbell % 4 == 0 and runtime >= op and doorbell >= op,
            'invalid MMIO register alignment')
    for index, (address, length) in enumerate(areas):
        require(address+length <= len(data), 'MMIO register area exceeds aperture')
        for other, other_length in areas[:index]:
            require(address+length <= other or other+other_length <= address, 'overlapping MMIO areas')
    require(u32(data, op+8) & 1, 'controller lacks 4-KiB DMA pages')
    require(u32(data, op) & 0xf == 0 and u32(data, op+4) & 0x1805 == 1,
            'controller is not cleanly halted after reset')
    require(u64(data, op+24) == 0 and u64(data, op+48) == 0 and
            u32(data, runtime+40) == 0 and u64(data, runtime+48) == 0 and
            u64(data, runtime+56) == 0, 'hardware retains DMA ring pointers')
    require(u32(data, op+56) & 255 == 0, 'hardware retains enabled slots after reset')
    protocols, occupied = {}, set()
    offset, visited = (hcc >> 16)*4, set()
    while offset:
        require(offset not in visited and len(visited) < 256 and 0x20 <= offset <= len(data)-4,
                'invalid extended capability chain')
        visited.add(offset)
        header = u32(data, offset)
        kind, next_bytes = header & 255, ((header >> 8) & 255)*4
        require(kind != 0, 'zero extended capability ID')
        size = 16 if kind == 2 else 8 if kind == 1 else 4
        require(offset+size <= len(data), 'truncated extended capability')
        for address, length in areas:
            require(offset+size <= address or address+length <= offset,
                    'extended capability overlaps active register area')
        if kind == 2:
            name, port_info, slot_info = words(data, offset+4, 3)
            first_port, count = port_info & 255, (port_info >> 8) & 255
            require(name == 0x20425355 and first_port > 0 and count > 0 and
                    first_port+count-1 <= ports, 'invalid Supported Protocol port range')
            require(port_info >> 28 == 0, 'explicit protocol speed IDs are unsupported')
            require(header >> 24 != 2 or (header >> 16) & 255 == 0,
                    'unsupported USB2 protocol minor revision')
            require(slot_info & ~31 == 0, 'reserved Supported Protocol slot bits')
            for port in range(first_port, first_port+count):
                require(port not in occupied, 'overlapping Supported Protocol port ranges')
                occupied.add(port)
                protocols[port] = (header >> 24, slot_info & 31)
        if not next_bytes:
            break
        require(next_bytes >= size, 'extended capability link overlaps its body')
        offset += next_bytes
    connected = []
    for port in range(1, ports+1):
        portsc = u32(data, op+0x400+(port-1)*16)
        if portsc & 1:
            connected.append((port, portsc))
    require(len(connected) == 1, 'fixture requires exactly one connected root device')
    port, portsc = connected[0]
    require(port in protocols and protocols[port][0] == 2, 'connected device lacks USB2 protocol coverage')
    speed = (portsc >> 10) & 15
    require(speed in (1,2,3) and portsc & (1 << 9) and not portsc & ((1 << 3) | (1 << 4)),
            'connected port has invalid speed, power, overcurrent or reset state')
    return {'context_bytes':64 if hcc & 4 else 32, 'max_ports':ports,
            'root_port':port, 'port_speed_id':speed, 'slot_type':protocols[port][1],
            'portsc':portsc, 'version':version}


def inspect_descriptor(proof, device, topology):
    desc = proof['descriptor']
    require(desc['struct_size'] == 84 and desc['abi_version'] == 1 and desc['slot_id'] == 1 and
            desc['reserved'] == [0,0], 'invalid descriptor result ABI')
    for name in ('root_port','context_bytes','port_speed_id'):
        require(desc[name] == topology[name], 'descriptor result disagrees with physical '+name)
    first, raw = device[8448:8456], device[8512:8530]
    require(first == raw[:8] and first.hex() == desc['first_eight'] and raw.hex() == desc['raw_device'],
            'independent GET8/GET18 DMA bytes disagree with proof')
    require(raw[0] == 18 and raw[1] == 1, 'DMA lacks an exact device descriptor')
    usb, vendor, product, release = (struct.unpack_from('<H', raw, n)[0] for n in (2,8,10,12))
    require(usb in (0x0100,0x0110,0x0200) and all(((release >> shift) & 15) < 10
            for shift in (0,4,8,12)), 'descriptor contains invalid USB/device version')
    speed = topology['port_speed_id']
    require(speed != 3 or usb == 0x0200, 'high-speed device is not USB2')
    require(raw[4] != 0 or (raw[5] == 0 and raw[6] == 0), 'unsupported class-zero descriptor triple')
    require(raw[17] > 0, 'descriptor reports no configurations')
    packet = raw[7]
    require(packet in ({1:(8,16,32,64), 2:(8,), 3:(64,)}[speed]), 'invalid EP0 packet size')
    initial = 64 if speed == 3 else 8
    require(desc['initial_ep0_packet'] == initial and desc['final_ep0_packet'] == packet,
            'descriptor EP0 packet history disagrees with speed/data')
    expected = struct.pack('<2I4H9B3x',28,1,usb,vendor,product,release,
        raw[4],raw[5],raw[6],packet,*raw[14:18],{1:2,2:1,3:3}[speed])
    # Re-encode the parsed result independently, including all ABI padding.
    parsed = desc['parsed']
    actual = struct.pack('<2I4H9B3B',*(parsed[name] for name in
        ('struct_size','abi_version','usb_bcd','vendor_id','product_id','device_bcd','device_class',
         'subclass','protocol','control_packet_bytes','manufacturer_string','product_string',
         'serial_string','configuration_count','speed')), *parsed['reserved'])
    require(actual == expected, 'C parser result disagrees with independent descriptor decode')
    require(device[8456:8512] == bytes([0xa5])*56 and device[8530:8576] == bytes([0xa5])*46,
            'descriptor DMA guard bytes were modified')
    return {'vendor_id':vendor, 'product_id':product, 'usb_bcd':usb, 'device_bcd':release,
            'raw_device':raw.hex(), 'first_eight':first.hex(), 'packet_bytes':packet,
            'initial_packet_bytes':initial, 'evaluate_context':packet != initial}


def check_contexts(device, address, topology, descriptor):
    stride = topology['context_bytes']
    initial, final = descriptor['initial_packet_bytes'], descriptor['packet_bytes']
    ring = address+8192
    # Original Address Device input, preserved before the live command.
    original = device[8832:8832+3*stride]
    expected = bytearray(3*stride)
    struct.pack_into('<I', expected, 4, 3)
    struct.pack_into('<4I', expected, stride, (1 << 27) | (topology['port_speed_id'] << 20),
                     topology['root_port'] << 16, 0, 0)
    struct.pack_into('<5I', expected, 2*stride, 0, (initial << 16) | (4 << 3) | (3 << 1),
                     ring | 1, 0, 8)
    require(original == bytes(expected), 'preserved Address input context is invalid')
    require(device[8832+3*stride:9024] == bytes(192-3*stride), 'input snapshot padding changed')
    live = device[4096:8192]
    if descriptor['evaluate_context']:
        expected = bytearray(4096)
        struct.pack_into('<I', expected, 4, 2)
        struct.pack_into('<I', expected, 2*stride+4, final << 16)
    else:
        expected.extend(bytes(4096-len(expected)))
    require(live == bytes(expected), 'live input context disagrees with final command')
    output = device[8704:8704+2*stride]
    slot, ep = words(output, 0), words(output, stride, 5)
    require(slot[0] == (1 << 27) | (topology['port_speed_id'] << 20) and
            slot[1] == topology['root_port'] << 16 and slot[2] == 0 and
            slot[3] & ~0xf80000ff == 0 and slot[3] >> 27 == 2 and 1 <= slot[3] & 255 <= 127,
            'preserved output slot is not an addressed root device')
    require(ep[0] == 1 and ep[1] == (final << 16) | (4 << 3) | (3 << 1) and ep[4] == 8,
            'preserved output EP0 context is inconsistent with completed GET18')
    # xHCI Table 6-8: output TR Dequeue is undefined in Running state. Transfer
    # advancement is established by the exact submitted TRBs and event history,
    # never by the controller's optional live dequeue writeback.
    require(device[8704+2*stride:8832] == bytes(128-2*stride), 'output snapshot padding changed')
    # Disable Slot may invalidate live fields, including USB Device Address
    # (Table 6-7). Only a still-Addressed live context can be compared. The
    # preserved pre-disable snapshot above establishes the operational state.
    live_slot, live_ep = words(device, 0), words(device, stride, 5)
    live_state = live_slot[3] >> 27
    require(live_state in (0,2), 'unexpected live slot state after terminal teardown')
    if live_state == 2:
        require(live_slot == slot, 'live output slot lost its addressed context')
        require(live_ep[0] in (0,1) and live_ep[1] == ep[1] and live_ep[4] == ep[4],
                'live EP0 context changed beyond disable state')
    require(device[2*stride:4096] == bytes(4096-2*stride), 'unused endpoint contexts are not zero')
    require(device[8576:8704] == bytes(128) and device[9024:] == bytes(DEVICE_BYTES-9024),
            'unused device DMA memory changed')
    return slot[3] & 255


def check_rings(proof, controller, device, ctrl_address, dev_address, topology, descriptor):
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
    for index, (length, buffer_offset) in enumerate(((8,8448),(18,8512))):
        offset = 8192+index*48
        expected = ((0x01000680,length << 16,8,(2 << 10) | (3 << 16) | (1 << 6) | 1),
                    (dev_address+buffer_offset,0,length,(3 << 10) | (1 << 16) | (1 << 2) | 1),
                    (0,0,0,(4 << 10) | (1 << 5) | 1))
        for stage, trb in enumerate(expected):
            require(words(device,offset+stage*16) == trb, 'GET_DESCRIPTOR Setup/Data/Status TRB mismatch')
    require(device[8288:8432] == bytes(144) and
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
    expected_order.extend((('status',dev_address+8192+5*16),('command',command_pointers[-1])))
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
            'event history does not cover both descriptor transfers and cleanup')
    require(controller[2304+end*16:3328] == bytes(1024-end*16), 'unconsumed event evidence is nonzero')
    return {'command_count':count, 'port_event_count':ports, 'zero_residue_short_events':len(shorts),
            'events':observed}


def verify_evidence(proof_bytes, controller_dma_bytes, device_dma_bytes,
                    expected_controller_address, expected_device_address, *, mmio_bytes, fixture=None):
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
    require((proof['magic'],proof['size'],proof['version']) == (0x30425355,256,1), 'invalid proof ABI')
    require(proof['reserved0'] == proof['reserved1'] == 0 and proof['reserved'] == [0,0,0],
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
    topology = inspect_mmio(mmio_bytes)
    descriptor = inspect_descriptor(proof, device, topology)
    usb_address = check_contexts(device, expected_device_address, topology, descriptor)
    rings = check_rings(proof, controller, device, expected_controller_address, expected_device_address, topology, descriptor)
    if fixture is not None:
        require(isinstance(fixture, dict) and set(fixture).issubset({
            'root_port','context_bytes','port_speed_id','slot_type','max_ports','vendor_id','product_id','descriptor_hex'}),
            'unsupported independent fixture metadata')
        observed = {**topology, **descriptor, 'descriptor_hex':descriptor['raw_device']}
        require(all(observed[name] == value for name,value in fixture.items()),
                'independent fixture identity/topology disagrees with DMA/MMIO')
    return {'status':'PASS', 'proof':proof, 'topology':topology, 'descriptor':descriptor,
            'usb_address':usb_address, 'rings':rings, 'native_windows':'not_tested',
            'claim':'two EP0 device-descriptor reads with completed shutdown; no device configuration or HID reports'}
