# SPDX-License-Identifier: GPL-2.0-only
"""Actual readonly observer C; Win32/registry operations are modeled only."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
class BaselineObserver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary=Path(cls.tmp.name)/'observer'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(HERE/'tests'),
                        HERE/'tests/observer_host.c','-o',cls.binary],check=True)
    def run_mode(self,mode):
        raw=subprocess.check_output([self.binary,str(mode)],text=True,timeout=5)
        first,second,output=raw.split('\n',2)
        return list(map(int,first.split())),{a:int(b) for a,b in (x.split('=') for x in second.split())},output.strip()
    def test_actual_version_enum_and_fresh_nonce_observation(self):
        row,state,raw=self.run_mode(0);self.assertEqual(row,[0,3,3,0,0,0,1]);report=json.loads(raw)
        self.assertEqual(report['nonce_hex'],bytes(range(1,33)).hex())
        self.assertEqual([report[n] for n in ('platform_id','major','minor','build_raw')],[1,4,10,2222])
        self.assertEqual(report['devices'],[{'enum_key':r'Enum\PCI\VEN_1234&DEV_1111\00','driver':r'Display\0000'}])
        self.assertTrue(report['observation_only']);self.assertFalse(report['source_approval']);self.assertFalse(report['Windows98_on_ShizukuDOS'])
        self.assertNotIn('PRIVATE_KEY',raw);self.assertEqual(state,{'nonce_reads':2,'nonce_closed':1,'report_created':1})
    def test_version_non_win98_and_failed_api_refuse_before_open(self):
        for mode in (1,21,22):
            with self.subTest(mode=mode):
                row,state,raw=self.run_mode(mode);self.assertEqual(row[0],2);self.assertEqual(row[1:3],[0,0]);self.assertFalse(raw);self.assertEqual(state['report_created'],0)
    def test_existing_report_is_never_deleted_or_overwritten(self):
        row,state,raw=self.run_mode(2);self.assertEqual(row,[4,1,1,0,0,0,0]);self.assertFalse(raw);self.assertEqual(state['nonce_closed'],1)
    def test_missing_wrong_size_highword_seek_short_zero_read_nonce_refuse(self):
        for mode in (11,12,13,14,15,16,23):
            with self.subTest(mode=mode):
                row,state,raw=self.run_mode(mode);self.assertEqual(row[0],7);self.assertEqual(row[1:3],[0,0]);self.assertFalse(raw);self.assertEqual(state['report_created'],0)
    def test_nonce_or_version_drift_and_close_errors_remove_owned_report(self):
        for mode in (17,18,19,20):
            with self.subTest(mode=mode):
                row,state,_=self.run_mode(mode);self.assertEqual(row[0],5);self.assertEqual(row[1],row[2]);self.assertEqual(row[3],1);self.assertEqual(state['nonce_reads'],1 if mode==20 else 2)
    def test_missing_driver_type_truncation_nul_no_display_write_timeout_refuse(self):
        for mode in (3,4,5,6,7,8,9):
            with self.subTest(mode=mode):
                row,_,_=self.run_mode(mode);self.assertEqual(row[0],5);self.assertEqual(row[1],row[2]);self.assertEqual(row[3],1);self.assertEqual(row[4:6],[0,0])
    def test_failed_partial_output_cleanup_not_success(self):
        row,_,_=self.run_mode(10);self.assertEqual(row[0],6);self.assertEqual(row[3],1)
if __name__=='__main__':unittest.main(verbosity=2)
