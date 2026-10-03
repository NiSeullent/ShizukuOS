# SPDX-License-Identifier: GPL-2.0-only
"""Actual observer C with modeled registry calls; no Windows/VM execution."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
class EnumObserver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'observer-host'
        subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(HERE/'tests'),
                        HERE/'tests/enum_observer_host.c','-o',cls.binary],check=True)
    def invoke(self,mode):
        raw=subprocess.check_output([self.binary,str(mode)],text=True);line,output=raw.split('\n',1)
        return list(map(int,line.split())),output.strip()
    def test_only_display_class_and_driver_are_observed(self):
        row,raw=self.invoke(0);self.assertEqual(row,[0,3,3,0,0,0,1]);result=json.loads(raw)
        self.assertEqual(result['devices'],[{'enum_key':r'Enum\PCI\VEN_1234&DEV_1111\00','driver':r'Display\0000'}])
        self.assertNotIn('PRIVATE_KEY',raw);self.assertFalse(result['default_GOP_registered'])
    def test_non_win98_refuses_before_any_registry_access(self):
        row,raw=self.invoke(1);self.assertEqual(row,[2,0,0,0,0,0,0]);self.assertFalse(raw)
    def test_existing_output_refuses_without_deleting_or_overwriting(self):
        row,raw=self.invoke(2);self.assertEqual(row,[4,1,1,0,0,0,0]);self.assertFalse(raw)
    def test_missing_driver_wrong_type_truncated_name_and_bad_nul_refuse(self):
        for mode in (3,4,5,6):
            with self.subTest(mode=mode):
                row,_=self.invoke(mode);self.assertEqual(row[0],5);self.assertEqual(row[1],row[2]);self.assertEqual(row[3],1);self.assertEqual(row[4:6],[0,0])
    def test_no_display_write_failure_timeout_refuse_and_remove_partial_output(self):
        for mode in (7,8,9):
            with self.subTest(mode=mode):
                row,_=self.invoke(mode);self.assertEqual(row[0],5);self.assertEqual(row[1],row[2]);self.assertEqual(row[3],1);self.assertEqual(row[4:6],[0,0])
    def test_failed_partial_output_deletion_reports_failure(self):
        row,_=self.invoke(10);self.assertEqual(row[0],6);self.assertEqual(row[3],1)
        self.assertEqual(row[1],row[2]);self.assertEqual(row[4:6],[0,0])

if __name__=='__main__':unittest.main()
