# SPDX-License-Identifier: GPL-2.0-only
"""Independent synthetic configuration wire fixtures; no guest execution.

The previous device fixture supplies established device/context/MMIO bytes.
New expected configuration records and transfer events are authored here without
calling the verifier's decoder or the C parser to construct their expected ABI.
"""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

verify = load('configuration_evidence', HERE/'verify.py')
original = load('original_device_fixture', HERE.parent/'uefi_usb/test_verify.py')
CTRL, DEV = original.CTRL, original.DEV
put = original.put


def fixture(*, stride=32, speed=3, packet=64, index=0, value=7, length=34, short=()):
    proof, controller, device, mmio = original.fixture(stride=stride,speed=speed,packet=packet)
    page = bytearray(4096)
    put(proof,0,0x43425355,256,2)
    put(proof,244,0x0200d000,3848,index)
    proof[213] = device[8529] = proof[239] = index+1
    raw = bytearray((9,2,0,0,1,value,0,0x80,50,
        9,4,0,0,1,3,0,0,0,9,0x21,0x11,1,0,1,0x22,0x34,0,7,5,0x81,3,8,0,1 if speed==3 else 10))
    struct.pack_into('<H',raw,2,length)
    opaque = [(18,9,0x21,0,0xffff)]
    while len(raw)<length:
        remaining = length-len(raw)
        amount = 254 if remaining==256 else min(remaining,255)
        if amount<2: raise ValueError('Fixture cannot represent a one-byte descriptor')
        opaque.append((len(raw),amount,0x24,0,0))
        raw.extend(bytes((amount,0x24))+bytes(amount-2))
    device[8576:8640] = bytes([0xa5])*64
    device[8576:8585] = raw[:9]
    device[9216:11328] = bytes([0xa5])*2112
    device[9216:9216+length] = raw
    put(page,0,3848,1,index,length)
    page[16:100] = proof[160:244]
    page[100:109] = raw[:9]
    page[112:112+length] = raw
    parsed = bytearray(1688)
    struct.pack_into('<IIHBBHHHHBBBB',parsed,0,1688,1,length,value,1,1,1,len(opaque),100,
                     0x80,0,{1:2,2:1,3:3}[speed],0)
    struct.pack_into('<HH8B',parsed,24,9,0,0,0,1,1,3,0,0,0)
    struct.pack_into('<HHH4BH',parsed,408,27,8,0,0x81,3,raw[33],1,0)
    for number,record in enumerate(opaque):
        struct.pack_into('<HBBHH',parsed,1176+number*8,*record)
    page[2160:3848] = parsed
    for request,(amount,offset) in enumerate(((9,8576),(length,9216)),2):
        where = 8192+request*48
        put(device,where,0x02000680|(index<<16),amount<<16,8,0x30841)
        put(device,where+16,DEV+offset,0,amount,0x10c05)
        put(device,where+32,0,0,0,0x1021)
    # Rebuild the whole event history independently; no synthetic status count
    # from the proof is used to decide which transfers should be present.
    evaluate = speed==1 and packet!=8
    count = 4 if evaluate else 3
    events = [(1<<24,0,1<<24,0x8801)]
    def command(number): events.append((CTRL+2048+number*16,0,1<<24,0x01008401))
    def transfer(number):
        if number in short: events.append((DEV+8192+number*48+16,0,13<<24,0x01018001))
        events.append((DEV+8192+number*48+32,0,1<<24,0x01018001))
    command(0);command(1);transfer(0)
    if evaluate:command(2)
    transfer(1);transfer(2);transfer(3);command(count-1)
    controller[2304:3328] = bytes(1024)
    for number,event in enumerate(events):put(controller,2304+number*16,*event)
    put(proof,136,len(events))
    return [proof,controller,device,mmio,page]


class ConfigurationEvidenceTests(unittest.TestCase):
    def call(self, evidence, **options):
        proof,controller,device,mmio,page = evidence
        return verify.verify_evidence(proof,controller,device,CTRL,DEV,
            mmio_bytes=mmio,configuration_page=page,**options)

    def reject(self,evidence,pattern='.'):
        with self.assertRaisesRegex(verify.EvidenceError,pattern):self.call(evidence)

    def test_speed_stride_index_value_and_length_combinations(self):
        for stride in (32,64):
            for speed,packet in ((1,8),(1,16),(1,32),(1,64),(2,8),(3,64)):
                for length in (34,63,64,65,511,512,513,2047,2048):
                    evidence = fixture(stride=stride,speed=speed,packet=packet,index=2,value=7,length=length)
                    before = copy.deepcopy(evidence)
                    with self.subTest(stride=stride,speed=speed,packet=packet,length=length):
                        result=self.call(evidence)
                        self.assertEqual(result['status'],'PASS')
                        self.assertEqual(result['configuration']['index'],2)
                        self.assertEqual(result['configuration']['configuration_value'],7)
                        self.assertEqual(result['configuration']['total_length'],length)
                        self.assertEqual(evidence,before)

    def test_every_result_byte_and_page_padding_is_validated(self):
        base=fixture()
        for offset in range(4096):
            evidence=copy.deepcopy(base);evidence[4][offset]^=1
            with self.subTest(offset=offset):self.reject(evidence)

    def test_every_header_and_full_dma_byte_guard_is_checked(self):
        base=fixture()
        for offset in (*range(8576,8640),*range(9216,11328)):
            evidence=copy.deepcopy(base);evidence[2][offset]^=1
            with self.subTest(offset=offset):self.reject(evidence)

    def test_full_prefix_changes_even_when_result_copy_is_rebound(self):
        for offset in range(9):
            evidence=fixture();evidence[2][9216+offset]^=1
            evidence[4][112+offset]^=1
            with self.subTest(offset=offset):self.reject(evidence,'header identity')

    def test_malformed_configuration_cannot_be_rebound_into_success(self):
        for offset,value in ((0,8),(1,7),(2,33),(3,8),(4,0),(4,17),(5,0),(7,0),(7,0x81),(8,251),
                             (9,0),(9,10),(11,1),(13,0),(14,0),(18,1),(19,0x30),
                             (27,8),(29,0x80),(29,0x91),(30,0),(31,65),(33,0)):
            evidence=fixture();evidence[2][9216+offset]=value;evidence[4][112+offset]=value
            if offset<9:
                evidence[2][8576+offset]=value;evidence[4][100+offset]=value
            with self.subTest(offset=offset,value=value):self.reject(evidence)

    def test_parser_counts_arrays_and_zero_unused_slots_cannot_lie(self):
        for offset in (2160,2168,2170,2171,2172,2174,2176,2178,2180,2182,
                       2184,2186,2188,2189,2190,2191,2192,2193,2194,2195,
                       2568,2570,2572,2574,2575,2576,2577,2578,3336,3338,3339,3340,3342,3847):
            evidence=fixture();evidence[4][offset]^=1
            with self.subTest(offset=offset):self.reject(evidence)

    def test_all_four_transfer_events_and_current_request_pointers_are_required(self):
        for event in range(8):
            for word in range(4):
                for bit in (0,2,16,24,31):
                    evidence=fixture();offset=2304+event*16+word*4
                    put(evidence[1],offset,struct.unpack_from('<I',evidence[1],offset)[0]^(1<<bit))
                    with self.subTest(event=event,word=word,bit=bit):self.reject(evidence)
        for first,second in ((3,4),(4,5),(5,6),(6,7)):
            evidence=fixture();a,b=2304+first*16,2304+second*16
            evidence[1][a:a+16],evidence[1][b:b+16]=evidence[1][b:b+16],evidence[1][a:a+16]
            self.reject(evidence)

    def test_zero_residue_short_packets_still_require_status(self):
        for shorts in ((),(2,),(3,),(0,1,2,3)):
            result=self.call(fixture(short=shorts))
            self.assertEqual(result['rings']['zero_residue_short_events'],len(shorts))
        evidence=fixture(short=(3,))
        put(evidence[1],2304+6*16+8,(13<<24)|1)
        self.reject(evidence,'short transfer')
        evidence=fixture(short=(3,))
        evidence[1][2304+7*16:2304+8*16]=evidence[1][2304+6*16:2304+7*16]
        self.reject(evidence,'duplicate')

    def test_exact_setup_type_index_length_ring_and_guards(self):
        for offset in range(8192,8384,4):
            evidence=fixture();evidence[2][offset]^=1
            with self.subTest(offset=offset):self.reject(evidence)
        for offset in (8384,8416,8432,8640,8699,9024,9215,11328,12287):
            evidence=fixture();evidence[2][offset]^=1;self.reject(evidence)

    def test_result_address_extent_index_and_compact_proof_lifetime(self):
        for offset,value in ((0,0),(4,255),(8,1),(12,0),(16,9),(20,1),(32,4),(48,1),(52,1),
            (56,1),(60,1),(64,10),(68,1),(72,1),(76,1),(80,1),(84,1),(88,1),(92,2),(108,0),
            (116,1),(124,6),(136,6),(140,0),(144,0),(148,0),(152,3848),(156,1),
            (244,0x0200f100),(248,4096),(252,1)):
            evidence=fixture();put(evidence[0],offset,value)
            with self.subTest(offset=offset):self.reject(evidence)
        for address in (0,True,0x0200d001,0x02010000):
            with self.assertRaises(verify.EvidenceError):
                self.call(fixture(),expected_configuration_address=address)

    def test_snapshot_sizes_and_independent_fixture_identity(self):
        for index in range(5):
            evidence=fixture();evidence[index]=evidence[index][:-1];self.reject(evidence,'size')
        self.assertEqual(self.call(fixture(),fixture={'configuration_value':7,'configuration_index':0})['status'],'PASS')
        for fact in ({'configuration_value':1},{'configuration_index':1},{'configuration_hex':'00'}, {'skip':True}):
            with self.assertRaises(verify.EvidenceError):self.call(fixture(),fixture=fact)

    def test_configuration_does_not_relax_old_context_or_shutdown_checks(self):
        for block,offset in ((1,8),(2,8704),(2,8836),(3,0x40),(3,0x58),(3,0x70),(3,0x1038)):
            evidence=fixture();evidence[block][offset]^=1;self.reject(evidence)
        evidence=fixture();evidence[2][:64]=bytes(64)
        self.assertEqual(self.call(evidence)['usb_address'],7)

if __name__=='__main__':unittest.main()
