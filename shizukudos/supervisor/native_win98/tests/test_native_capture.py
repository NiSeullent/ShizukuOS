# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile

P=Path(__file__).resolve().parents[1]/'run_vm.py'
s=importlib.util.spec_from_file_location('native_capture_test',P)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class NativeEvidence(unittest.TestCase):
    def test_long_capture_timeout_has_exact_bounded_type_and_range(self):
        for value in (20,300,600,900):self.assertTrue(m.timeout_valid(value))
        for value in (-1,0,19,901,100000,True,False,300.0,'300',None):
            with self.subTest(value=value):self.assertFalse(m.timeout_valid(value))
    def test_actual_cli_rejects_timeout_before_input_access_or_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)
            for value in ('19','901'):
                result=subprocess.run([sys.executable,'-B',str(P),'--plan',str(out/'absent-plan.json'),'--plan-sha256','0'*64,'--repo',str(out),'--timeout',value,'--runtime-sources-sha256','0'*64],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,2)
                self.assertIn('timeout must be 20..900 seconds',result.stderr)
                self.assertEqual(list(out.iterdir()),[])
    def base(self):return {'loader_flags':1,'boot_path':1,'guest_ram_size':128<<20,'disk_size':2<<30,'stage':5,'domains':{'WIN98':{'state':1,'exits':10,'error':''}}}
    def test_actual_domain_failure_is_not_gui_or_dos_replacement(self):
        info=self.base();info['domains']['WIN98'].update(state=4,error='guest triple fault')
        result=m.evidence_status(info)
        self.assertEqual(result,'NATIVE_WINDOWS98_DOMAIN_FAILED')
        self.assertNotIn('PASS',result)
    def test_running_vmcs_is_still_only_boot_unverified(self):
        self.assertEqual(m.evidence_status(self.base()),'NATIVE_VMCS_RUNNING_WINDOWS_BOOT_UNVERIFIED')
        info=self.base();info['domains']['WIN98']['exits']=0
        self.assertEqual(m.evidence_status(info),'NATIVE_DOMAIN_CREATED_CPU_EXECUTION_UNVERIFIED')
    def test_no_memory_or_other_profile_cannot_attest_native_boot(self):
        self.assertEqual(m.evidence_status(None),'NATIVE_INFO_UNAVAILABLE')
        for key,value in [('loader_flags',0),('boot_path',2),('guest_ram_size',64<<20),('disk_size',32<<20)]:
            info=self.base();info[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.evidence_status(info)
    def test_write_counter_missing_duplicate_reset_or_budget_overrun_refused(self):
        self.assertEqual(m.esp_write_bytes([{'device':'esp','stats':{'wr_bytes':100}}],0),100)
        for r,last in [([],0),([{'device':'esp','stats':{'wr_bytes':True}}],0),([{'device':'esp','stats':{'wr_bytes':5}}],6),([{'device':'esp','stats':{'wr_bytes':m.WRITE_BUDGET+1}}],0),([{'device':'esp','stats':{'wr_bytes':0}}]*2,0)]:
            with self.subTest(result=r),self.assertRaises((ValueError,RuntimeError)):m.esp_write_bytes(r,last)
if __name__=='__main__':unittest.main()
