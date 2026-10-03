# SPDX-License-Identifier: GPL-2.0-only
"""run_vm epoch recipe forwarding: production expected_recipe + real prepare_vm.recipe; no launch."""
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parents[1]
def _load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
run_vm=_load('run_vm_recipe_fwd',HERE/'run_vm.py')
prep=_load('prepare_vm_recipe_fwd',HERE/'prepare_vm.py')
OUT=Path('/tmp/shz-rfwd-out');QEMU=Path('/usr/bin/qemu-system-x86_64')
def binding(low32=False):
    b={'policy_fd':7,'listener_path':str(OUT/'epoch.sock')}
    if low32:b['modern_persistence_low32']=True
    return b
def plan(b=None):
    p={'qemu_argv':prep.recipe(QEMU,OUT,b)}
    if b is not None:p['prospective_native_epoch_recipe']=b
    return p
CTX=object()
class T(unittest.TestCase):
    def call(self,p,epoch,ctx):return run_vm.expected_recipe(prep,p,QEMU,OUT,epoch,ctx)
    def test_plain_unchanged(self):
        p=plan();self.assertEqual(self.call(p,False,None),p['qemu_argv']);self.assertEqual(self.call(p,False,CTX),p['qemu_argv'])
    def test_guardian_epoch_matches_and_low32_knob(self):
        for low in (False,True):
            p=plan(binding(low));self.assertEqual(self.call(p,True,CTX),p['qemu_argv'])
            self.assertEqual('name=opt/ovmf/X-PciMmio64Mb,string=0' in p['qemu_argv'],low)
    def test_old_held_plan_without_binding_refused_in_epoch(self):
        with self.assertRaises(ValueError):self.call(plan(),True,CTX)
    def test_binding_without_guardian_refused(self):
        with self.assertRaises(ValueError):self.call(plan(binding()),False,CTX)
    def test_no_custody_context_refused(self):
        with self.assertRaises(ValueError):self.call(plan(binding()),True,None)
    def test_extra_key_refused(self):
        b=binding();b['x']=1;p={'qemu_argv':[],'prospective_native_epoch_recipe':b}
        with self.assertRaises(ValueError):self.call(p,True,CTX)
    def test_changed_argv_differs(self):
        p=plan(binding());p['qemu_argv']=p['qemu_argv']+['-S'];self.assertNotEqual(self.call(p,True,CTX),p['qemu_argv'])
    def test_plain_recipe_not_equal_epoch_recipe(self):
        self.assertNotEqual(plan()['qemu_argv'],plan(binding())['qemu_argv'])
if __name__=='__main__':unittest.main()
