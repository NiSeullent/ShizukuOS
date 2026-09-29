# SPDX-License-Identifier: GPL-2.0-only
"""Hostile synthetic physical snapshots; never opens a VM or hardware device.

Fixtures are authored here from the wire contract, with invented VID/PID values.
They are not records of QEMU or Windows execution. The verifier implementation
is not used to construct expected contexts, descriptors, TRBs or events.
"""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest


spec = importlib.util.spec_from_file_location('independent_usb_evidence', Path(__file__).with_name('verify.py'))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

CTRL = 0x0202f000
DEV = 0x02030000
OFFSETS = {'stage':32, 'pci_bdf':36, 'mmio':40, 'bridges':44,
    'open_result':48, 'probe_status':52, 'transport_error':56, 'parser_status':60,
    'failed_stage':64, 'parser_offset':68, 'close_result':72, 'controller_dma_owned':76,
    'device_dma_owned':80, 'allocations':84, 'releases':88, 'commands_completed':92,
    'port_events':96, 'last_status':100, 'last_completion_code':104,
    'completion_low':108, 'completion_high':112, 'dma_in_use_mask':116,
    'original_pci_command':120, 'restored_pci_command':124, 'command_index':128,
    'command_cycle':132, 'event_index':136, 'event_cycle':140, 'dma_address':144,
    'device_dma_address':148, 'descriptor_bytes':152, 'reserved1':156}


def put(data, offset, *values):
    struct.pack_into('<'+'I'*len(values), data, offset, *values)


def fixture(*, stride=32, speed=3, packet=64, short=(), port_events=1, slot_type=0):
    proof, controller, device, mmio = (bytearray(n) for n in (256,4096,12288,16384))
    initial = 64 if speed == 3 else 8
    evaluate = packet != initial
    commands = 4 if evaluate else 3
    put(proof, 0, 0x30425355, 256, 1, 1, 3000, 0)
    struct.pack_into('<Q', proof, 24, 1000000)
    fields = dict.fromkeys(OFFSETS, 0)
    fields.update(stage=3, pci_bdf=0x100, mmio=0x81000000, bridges=1, failed_stage=11,
        allocations=2, releases=2, commands_completed=commands, port_events=port_events,
        last_status=8, last_completion_code=1, completion_low=CTRL+2048+(commands-1)*16,
        original_pci_command=7, restored_pci_command=7, command_index=commands,
        command_cycle=1, event_cycle=1, dma_address=CTRL, device_dma_address=DEV, descriptor_bytes=84)
    for name, value in fields.items():
        put(proof, OFFSETS[name], value)
    struct.pack_into('<6I2H', proof, 160, 84,1,1,1,stride,speed,initial,packet)
    raw = struct.pack('<BBH4BHHH4B',18,1,0x0200,0,0,0,packet,0x1234,0x5678,0x0100,1,2,3,1)
    proof[188:196] = raw[:8]
    proof[196:214] = raw
    struct.pack_into('<2I4H9B3x', proof, 216,28,1,0x0200,0x1234,0x5678,0x0100,
                     0,0,0,packet,1,2,3,1,{1:2,2:1,3:3}[speed])
    device[8448:8576] = bytes([0xa5])*128
    device[8448:8456] = raw[:8]
    device[8512:8530] = raw
    # Original Address input snapshot and the final live input page.
    original = bytearray(3*stride)
    put(original,4,3)
    put(original,stride, (1 << 27) | (speed << 20),1 << 16,0,0)
    put(original,2*stride,0,(initial << 16) | 38,DEV+8193,0,8)
    device[8832:8832+len(original)] = original
    if evaluate:
        put(device,4100,2)
        put(device,4096+2*stride+4,packet << 16)
    else:
        device[4096:4096+len(original)] = original
    # Preserved pre-disable hardware output: address7, EP0 consumed six TRBs.
    output = bytearray(2*stride)
    put(output,0,(1 << 27) | (speed << 20),1 << 16,0,(2 << 27) | 7)
    put(output,stride,1,(packet << 16) | 38,DEV+8192+97,0,8)
    device[:len(output)] = output
    device[8704:8704+len(output)] = output
    commands_to_emit = [(9,0,slot_type << 16),(11,DEV+4096,1 << 24)]
    if evaluate:
        commands_to_emit.append((13,DEV+4096,1 << 24))
    commands_to_emit.append((10,0,1 << 24))
    for index,(kind,address,flags) in enumerate(commands_to_emit):
        put(controller,2048+16*index,address,0,0,(kind << 10) | flags | 1)
    put(controller,3328,CTRL+2304,0,64,0)
    for index,(length,address) in enumerate(((8,DEV+8448),(18,DEV+8512))):
        offset = 8192+48*index
        put(device,offset,0x01000680,length << 16,8,0x30841)
        put(device,offset+16,address,0,length,0x10c05)
        put(device,offset+32,0,0,0,0x1021)
    put(device,8432,DEV+8192,0,0,0x1803)
    events = [(1 << 24,0,1 << 24,0x8801)]*port_events
    def command(index):
        events.append((CTRL+2048+index*16,0,1 << 24,0x01008401))
    def transfer(index):
        if index in short:
            events.append((DEV+8192+index*48+16,0,13 << 24,0x01018001))
        events.append((DEV+8192+index*48+32,0,1 << 24,0x01018001))
    command(0)
    command(1)
    transfer(0)
    if evaluate:
        command(2)
    transfer(1)
    command(commands-1)
    for index,event in enumerate(events):
        put(controller,2304+index*16,*event)
    put(proof,136,len(events))
    # Disjoint capability, operational, runtime, doorbell and extended regions.
    put(mmio,0,0x01000040,(8 << 24) | (1 << 8) | 8,0,0,
        (0x3000//4 << 16) | (4 if stride == 64 else 0) | 1,0x2000,0x1000)
    put(mmio,0x44,1,1)  # halted USBSTS, 4KiB PAGESIZE
    put(mmio,0x440,1 | (1 << 9) | (speed << 10))
    put(mmio,0x3000,0x02000402,0x20425355,0x00000401,slot_type)
    put(mmio,0x3010,0x03000002,0x20425355,0x00000405,0)
    return [proof,controller,device,mmio]


class EvidenceTests(unittest.TestCase):
    def call(self, evidence, **kwargs):
        proof,controller,device,mmio = evidence
        return verify.verify_evidence(proof,controller,device,CTRL,DEV,mmio_bytes=mmio,**kwargs)

    def rejects(self, evidence, message=None):
        with self.assertRaisesRegex(verify.EvidenceError,message or '.'):
            self.call(evidence)

    def test_supported_speed_packet_and_context_combinations(self):
        for stride in (32,64):
            for speed,packet in ((1,8),(1,16),(1,32),(1,64),(2,8),(3,64)):
                with self.subTest(stride=stride,speed=speed,packet=packet):
                    evidence = fixture(stride=stride,speed=speed,packet=packet)
                    before = copy.deepcopy(evidence)
                    result = self.call(evidence)
                    self.assertEqual(result['status'],'PASS')
                    self.assertEqual(result['descriptor']['vendor_id'],0x1234)
                    self.assertEqual(result['descriptor']['evaluate_context'],speed == 1 and packet != 8)
                    self.assertEqual(result['topology']['context_bytes'],stride)
                    self.assertEqual(result['native_windows'],'not_tested')
                    self.assertEqual(evidence,before)

    def test_zero_residue_short_events_require_both_status_events(self):
        for short in ((),(0,),(1,),(0,1)):
            with self.subTest(short=short):
                result = self.call(fixture(short=short))
                self.assertEqual(result['rings']['zero_residue_short_events'],len(short))
        evidence = fixture(short=(0,))
        put(evidence[1],2304+3*16+8,(13 << 24) | 1)
        self.rejects(evidence,'short transfer')

    def test_direct_wire_decoder_can_diagnose_a_failure_but_not_validate_it(self):
        evidence = fixture()
        put(evidence[0],32,4)
        put(evidence[0],52,0xffffff9c)
        parsed = verify.decode_proof(evidence[0])
        self.assertEqual(parsed['stage'],4)
        self.assertEqual(parsed['probe_status'],0xffffff9c)
        self.assertEqual(parsed['descriptor']['raw_device'],evidence[2][8512:8530].hex())
        self.rejects(evidence,'completed success')

    def test_exact_snapshot_sizes_and_expected_linked_addresses(self):
        base = fixture()
        for index in range(4):
            for amount in (-1,1):
                evidence = copy.deepcopy(base)
                evidence[index] = evidence[index][:-1] if amount < 0 else evidence[index]+b'\0'
                with self.subTest(index=index,amount=amount):
                    self.rejects(evidence,'size')
        for ctrl,dev in ((CTRL+1,DEV),(CTRL,CTRL),(0,DEV),(CTRL,0x020ff000),
                         (CTRL,0x100000000),(True,DEV)):
            with self.subTest(ctrl=ctrl,dev=dev), self.assertRaises(verify.EvidenceError):
                verify.verify_evidence(*base[:3],ctrl,dev,mmio_bytes=base[3])

    def test_proof_success_lifetime_and_abi_are_mandatory(self):
        changes = {0:0,4:255,8:2,12:0,16:9,20:1,24:0,28:0,244:1,
            OFFSETS['stage']:4,OFFSETS['allocations']:1,OFFSETS['releases']:1,
            OFFSETS['failed_stage']:10,OFFSETS['descriptor_bytes']:8,OFFSETS['dma_address']:CTRL+4096,
            OFFSETS['device_dma_address']:DEV+4096,OFFSETS['restored_pci_command']:6,
            OFFSETS['mmio']:0x81000001,OFFSETS['pci_bdf']:0,OFFSETS['bridges']:0,
            OFFSETS['last_status']:4,OFFSETS['reserved1']:1}
        for name in ('open_result','probe_status','transport_error','parser_status','parser_offset',
                     'close_result','controller_dma_owned','device_dma_owned','dma_in_use_mask'):
            changes[OFFSETS[name]] = 1
        # start_tsc occupies two DWORDs; zero both for this mutation.
        changes.pop(28)
        for offset,value in changes.items():
            evidence = fixture()
            put(evidence[0],offset,value)
            with self.subTest(offset=offset):
                self.rejects(evidence)

    def test_every_descriptor_result_field_and_padding_is_checked(self):
        for offset in range(160,244):
            evidence = fixture()
            evidence[0][offset] ^= 1
            with self.subTest(offset=offset):
                self.rejects(evidence)

    def test_dma_descriptor_and_guard_corruption(self):
        for offset in (*range(8448,8512),*range(8512,8576)):
            evidence = fixture()
            evidence[2][offset] ^= 1
            with self.subTest(offset=offset):
                self.rejects(evidence)

    def test_rebinding_proof_does_not_make_malformed_descriptor_valid(self):
        for offset,value in ((0,17),(1,2),(2,0x10),(3,3),(5,1),(6,1),(7,9),(12,0xfa),(17,0)):
            evidence = fixture()
            raw = bytearray(evidence[2][8512:8530])
            raw[offset] = value
            evidence[2][8512:8530] = raw
            evidence[2][8448:8456] = raw[:8]
            evidence[0][196:214] = raw
            evidence[0][188:196] = raw[:8]
            with self.subTest(offset=offset):
                self.rejects(evidence)

    def test_independent_fixture_metadata_cannot_echo_wrong_identity(self):
        result = self.call(fixture(),fixture={'vendor_id':0x1234,'product_id':0x5678,'root_port':1})
        self.assertEqual(result['usb_address'],7)
        for metadata in ({'vendor_id':0xffff},{'context_bytes':64},{'root_port':2},
                         {'descriptor_hex':'00'*18},{'skip_checks':True}):
            with self.subTest(metadata=metadata), self.assertRaises(verify.EvidenceError):
                self.call(fixture(),fixture=metadata)

    def test_contexts_linkage_semantics_and_snapshot_padding(self):
        for stride in (32,64):
            offsets = (0,4,8,12,stride,stride+4,stride+16,
                2*stride,4096,4100,4096+stride,4096+2*stride+4,8191,
                8704,8708,8712,8716,8704+stride,8704+stride+4,
                8832,8836,8832+stride,8832+2*stride+4,9023,12287)
            for offset in offsets:
                evidence = fixture(stride=stride)
                evidence[2][offset] ^= 0x10
                with self.subTest(stride=stride,offset=offset):
                    self.rejects(evidence)
        # Output RsvdO belongs to the controller and must not be falsely rejected.
        evidence = fixture()
        put(evidence[2],16,0xdeadbeef)
        put(evidence[2],8704+16,0x12345678)
        put(evidence[2],32+8,0xdeadbeef,0xfeedface)
        put(evidence[2],8704+32+8,0x01234567,0x89abcdef)
        self.assertEqual(self.call(evidence)['status'],'PASS')
        # Hardware may publish disabled output states during terminal teardown.
        put(evidence[2],12,7)
        put(evidence[2],32,0)
        self.assertEqual(self.call(evidence)['status'],'PASS')
        # Disabled output address/context fields are no longer valid evidence.
        evidence[2][:64] = bytes(64)
        self.assertEqual(self.call(evidence)['usb_address'],7)
        put(evidence[2],12,1 << 27)  # Default is not terminal Disabled/Addressed.
        self.rejects(evidence,'live slot state')

    def test_evaluate_context_is_required_only_for_changed_full_speed_packet(self):
        evidence = fixture(speed=1,packet=64)
        put(evidence[2],4100,3)
        self.rejects(evidence,'live input context')
        evidence = fixture(speed=1,packet=64)
        put(evidence[1],2048+2*16+12,(10 << 10) | (1 << 24) | 1)
        self.rejects(evidence,'command TRB')

    def test_every_submitted_trb_word_and_unused_ring_slot_is_checked(self):
        for block,offsets in ((1,range(2048,2096,4)),(2,range(8192,8288,4))):
            for offset in offsets:
                evidence = fixture()
                evidence[block][offset] ^= 1
                with self.subTest(block=block,offset=offset):
                    self.rejects(evidence)
        for block,offset in ((1,0),(1,8),(1,16),(1,2096),(1,2288),(1,3328),
                             (1,3336),(1,3344),(1,4095),(2,8288),(2,8432)):
            evidence = fixture()
            evidence[block][offset] ^= 1
            with self.subTest(block=block,offset=offset):
                self.rejects(evidence)

    def test_disable_completion_requires_cleared_dcbaa_slot(self):
        evidence = fixture()
        struct.pack_into('<Q',evidence[1],8,DEV)
        self.rejects(evidence,'DCBAA retains a pointer')

    def test_event_type_pointer_slot_endpoint_code_residue_and_cycle(self):
        for index in range(6):
            for word in range(4):
                for bit in (0,2,16,24,31):
                    evidence = fixture()
                    offset = 2304+index*16+word*4
                    old = struct.unpack_from('<I',evidence[1],offset)[0]
                    put(evidence[1],offset,old ^ (1 << bit))
                    with self.subTest(index=index,word=word,bit=bit):
                        self.rejects(evidence)

    def test_duplicate_missing_reordered_and_extra_events(self):
        for first,second in ((1,2),(2,3),(3,4),(4,5)):
            evidence = fixture()
            a,b = 2304+first*16,2304+second*16
            evidence[1][a:a+16],evidence[1][b:b+16] = evidence[1][b:b+16],evidence[1][a:a+16]
            with self.subTest(first=first,second=second):
                self.rejects(evidence)
        for field,value in (('event_index',5),('event_index',7),('event_index',64),('event_cycle',0),
                            ('command_index',2),('command_cycle',0),('commands_completed',2),
                            ('port_events',0),('completion_low',CTRL+2048),('last_completion_code',13)):
            evidence = fixture()
            put(evidence[0],OFFSETS[field],value)
            with self.subTest(field=field):
                self.rejects(evidence)
        evidence = fixture(short=(0,))
        evidence[1][2304+4*16:2304+5*16] = evidence[1][2304+3*16:2304+4*16]
        self.rejects(evidence,'duplicate')

    def test_selected_root_reset_event_must_precede_enable_slot(self):
        self.rejects(fixture(port_events=0),'event history')
        evidence = fixture()
        put(evidence[1],2304,2 << 24)
        self.rejects(evidence,'event history')
        evidence = fixture()
        evidence[1][2304:2336] = evidence[1][2320:2336]+evidence[1][2304:2320]
        self.rejects(evidence,'event history')

    def test_mmio_capability_protocol_topology_and_cleanup(self):
        changes = ((0,0x01000041),(4,0),(8,1 << 27),(20,0x2001),(24,0x1001),
            (24,0x440),(24,0x3ff0),(16,0),(0x40,1),(0x44,0),(0x44,5),(0x44,0x801),
            (0x48,0),(0x58,1),(0x70,1),(0x78,1),(0x1028,1),(0x1030,1),(0x1038,1),
            (0x440,0),(0x440,1 | (3 << 10)),(0x440,1 | 512 | (4 << 10)),
            (0x450,1 | 512 | (3 << 10)),(0x3000,0x02000102),(0x3004,0),
            (0x3008,0x00000400),(0x3008,0x10000401),(0x300c,32),
            (0x3018,0x00000401),(0x3000,0x03000402),(0x3000,0x02010402))
        for offset,value in changes:
            evidence = fixture()
            put(evidence[3],offset,value)
            with self.subTest(offset=offset,value=value):
                self.rejects(evidence)

    def test_no_usb_identity_is_assumed_from_qemu_product_name(self):
        evidence = fixture()
        for buffer in ((evidence[0],196),(evidence[2],8512)):
            struct.pack_into('<HH',buffer[0],buffer[1]+8,0xabcd,0xef01)
        struct.pack_into('<HH',evidence[0],216+10,0xabcd,0xef01)
        result = self.call(evidence)
        self.assertEqual(result['descriptor']['vendor_id'],0xabcd)
        self.assertEqual(result['descriptor']['product_id'],0xef01)


if __name__ == '__main__':
    unittest.main()
