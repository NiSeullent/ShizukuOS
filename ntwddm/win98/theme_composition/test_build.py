"""Observed V13 metadata failure and stale static artifact refusal regression."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('composition_builder',Path(__file__).with_name('build.py'))
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)

class StaticReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.receipt={'schema':1,'status':'PASS','native_win98':'not_tested','native_visibility_verified':False,'artifacts':{}}
        for name in ['M98THEME.DLL','NTTHGUI.EXE','NTTHRUN.EXE']:
            path=Path(self.tmp.name)/name;data=('fixture '+name).encode();path.write_bytes(data)
            self.receipt['artifacts'][name]={'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'pe98_gate':{'status':'PASS','runtime_execution_verified':False}}
    def test_static_contract_uses_no_exit_or_guest_logs(self):
        builder.validate_static_receipt(self.receipt)
        self.assertNotIn('external_exit_code',self.receipt)
    def test_observed_uppercase_v13_metadata_is_refused(self):
        r=copy.deepcopy(self.receipt);r['native_win98']='NOT-TESTED'
        with self.assertRaisesRegex(RuntimeError,'static evidence only'):builder.validate_static_receipt(r)
    def test_execution_visibility_and_invalid_schema_refused(self):
        for key,value in [('native_win98','PASS'),('native_visibility_verified',True),('schema',True),('status','FAIL')]:
            r=copy.deepcopy(self.receipt);r[key]=value
            with self.assertRaises(RuntimeError):builder.validate_static_receipt(r)
    def test_missing_or_nonstatic_native_gate_refused(self):
        for change in ['missing','failed','runtime']:
            r=copy.deepcopy(self.receipt)
            if change=='missing':del r['artifacts']['NTTHRUN.EXE']
            else:r['artifacts']['NTTHRUN.EXE']['pe98_gate']['status' if change=='failed' else 'runtime_execution_verified']='FAIL' if change=='failed' else True
            with self.assertRaises(RuntimeError):builder.validate_static_receipt(r)
    def test_stale_artifact_bytes_digest_size_and_path_refused(self):
        for key,value in [('sha256','f'*64),('bytes',999),('path','relative.exe'),('bytes',True)]:
            r=copy.deepcopy(self.receipt);r['artifacts']['NTTHGUI.EXE'][key]=value
            with self.assertRaises(RuntimeError):builder.validate_static_receipt(r)
        Path(self.receipt['artifacts']['NTTHGUI.EXE']['path']).write_bytes(b'stale')
        with self.assertRaisesRegex(RuntimeError,'Frozen artifact bytes'):builder.validate_static_receipt(self.receipt)

if __name__=='__main__':unittest.main()
