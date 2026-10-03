# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('live_stage',Path(__file__).with_name('prepare.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Request(unittest.TestCase):
    def setUp(self):
        self.pins={n:'a'*64 for n in ('DRV_SHA256','VXD_SHA256','INF_SHA256','SETUPX_SHA256')}
    def test_exact_guest_request_and_real_source_identity(self):
        raw=m.request_bytes('Enum\\PCI\\VEN_1234&DEV_1111\\0000','b'*64,self.pins)
        self.assertIn(b'LIVE_PROVIDER_SHA256='+b'b'*64+b'\r\n',raw)
        self.assertEqual(raw.count(b'[GOP]'),1);self.assertNotIn(b'/install',raw)
    def test_no_registry_or_ini_injection(self):
        for key in ('Enum\\PCI\\x\r\n[Other]','Enum\\PCI\\x=evil','Enum\\..\\x','System\\Other',
                    'Enum\\PCI\\x;comment','Enum\\PCI\\'+'a'*256):
            with self.assertRaises((ValueError,RuntimeError)):m.request_bytes(key,'b'*64,self.pins)
    def test_zero_malformed_or_boolean_identity_is_not_live_success(self):
        for identity in ('0'*64,'B'*64,True,'native-ready','b'*63):
            with self.assertRaises((ValueError,RuntimeError)):m.request_bytes('Enum\\PCI\\0000',identity,self.pins)
    def test_missing_actual_setupx_pin(self):
        self.pins.pop('SETUPX_SHA256')
        with self.assertRaises((ValueError,RuntimeError)):m.request_bytes('Enum\\PCI\\0000','b'*64,self.pins)
    def test_wrong_actual_source_sha(self):
        for sha in ('0'*64,'../source',False,'c'*65):
            self.pins['SETUPX_SHA256']=sha
            with self.assertRaises((ValueError,RuntimeError)):m.request_bytes('Enum\\PCI\\0000','b'*64,self.pins)
if __name__=='__main__':unittest.main()
