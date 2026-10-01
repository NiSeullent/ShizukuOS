# SPDX-License-Identifier: GPL-2.0-or-later
import importlib.util
from pathlib import Path
import unittest

P=Path(__file__).resolve().parents[1]/'run_original_dos_control.py'
spec=importlib.util.spec_from_file_location('original_dos_control_test',P)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SHA='a'*64

class OwnedMonitor:
    def __init__(self): self.calls=[]
    def call(self,*args): self.calls.append(args); return {}

class ControlInput(unittest.TestCase):
    def request(self,**kwargs):
        r={'sequence':1,'key':'ret','purpose':'continue-known-optional-device-warning','basis_screenshot_sha256':SHA}
        r.update(kwargs)
        return r

    def test_only_explicit_enter_with_an_owned_screen_is_sent_once(self):
        monitor=OwnedMonitor()
        record={'captures':[{'screenshot_sha256':SHA}],'operator_inputs':[]}
        sequence=module.process_input(self.request(),0,monitor,record,42.25)
        self.assertEqual(sequence,1)
        self.assertEqual(monitor.calls,[('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100})])
        self.assertEqual(record['operator_inputs'][0]['seconds'],42.25)
        module.process_input(self.request(),sequence,monitor,record,43)
        self.assertEqual(len(monitor.calls),1)

    def test_unqualified_out_of_order_and_nonenter_inputs_are_rejected(self):
        bad=(self.request(sequence=True),self.request(sequence=2),self.request(sequence=0),self.request(sequence=9),
             self.request(key='esc'),self.request(key='ctrl-alt-delete'),self.request(purpose='automatic-success'),
             self.request(basis_screenshot_sha256='b'*64),self.request(extra='raw-monitor-command'),{})
        for r in bad:
            with self.subTest(request=r):
                monitor=OwnedMonitor()
                record={'captures':[{'screenshot_sha256':SHA}],'operator_inputs':[]}
                with self.assertRaises(ValueError): module.process_input(r,0,monitor,record,1)
                self.assertEqual(monitor.calls,[])
                self.assertEqual(record['operator_inputs'],[])

if __name__=='__main__':unittest.main()
