# SPDX-License-Identifier: GPL-2.0-only
"""Original-userland input recipe intent: pinned example, controller load route, guardian lease identity.

Host controls only (fake QMP, temp files). No VM, no Win98 GUI claim.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parents[1]
def _load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
cap=_load('owned_capture_recipe_intent',HERE/'owned_capture.py')
run_vm=_load('run_vm_recipe_intent',HERE/'run_vm.py')

EXAMPLE=HERE/'tests'/'fixtures'/'t_gui_native_enter_close.input.json'
EXAMPLE_SHA256='d9844c0e6cf5b229c27ec780bfbb53219627df53a92a11de56402784e1ecf2a4'


class TGuiNativeModel:
    """Fake QMP peer modelling Win98 presenter focus + t_gui_native.c, written from the C sources, not from owned_capture.

    Presenter wndproc forwards WM_KEYDOWN (not WM_SYSKEYDOWN) to the K64 app; the app toggles READY/PRESSED per
    WM_KEYDOWN. Alt+F4 -> DefWindowProc SC_CLOSE -> presenter WM_CLOSE -> szwin_close_request -> app WM_CLOSE ->
    DestroyWindow -> PostQuitMessage(7).
    """
    def __init__(self):self.alt=False;self.text='READY';self.exit=None;self.calls=[]
    def _down(self,key):
        if self.exit is not None:raise AssertionError('input after the app exited')
        if key=='alt':self.alt=True
        elif self.alt and key=='f4':self.exit=7
        elif not self.alt:self.text='PRESSED' if self.text=='READY' else 'READY'
    def call(self,command,arguments=None):
        self.calls.append((command,arguments))
        if command=='send-key':
            names=[k['data'] for k in arguments['keys']]
            for name in names:self._down(name)
            if 'alt' in names:self.alt=False
        elif command=='input-send-event':
            for event in arguments['events']:
                if event['type']=='key':
                    name=event['data']['key']['data']
                    if event['data']['down']:self._down(name)
                    elif name=='alt':self.alt=False
        else:raise AssertionError('non-input command reached the fake monitor: %r'%command)
        return {}


def drive(script,monitor,until=400.0):
    scoped=cap.ScopedInput(script,monitor);t=0.0
    while t<until and not scoped.done:scoped.poll(t);t+=0.05
    return scoped


class FakeBorrowed:
    """Guardian borrow stand-in: returns bytes of the HELD descriptor, which may differ from the path."""
    def __init__(self,held):self.held=held;self.items=[]
    def read(self,item,maximum):
        self.items.append((dict(item),maximum));return Path(self.held).read_bytes()


class Base(unittest.TestCase):
    def setUp(self):
        self.dir=Path(tempfile.mkdtemp(prefix='gi9-'));self.addCleanup(shutil.rmtree,self.dir,True)
        self.raw=EXAMPLE.read_bytes();self.path=self.dir/'recipe.json';self.path.write_bytes(self.raw)


class ExampleRecipe(Base):
    def test_pinned_example_drives_ready_pressed_then_remote_close(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),EXAMPLE_SHA256)
        script,pin=run_vm.load_input_recipe(EXAMPLE,EXAMPLE_SHA256,None,cap)
        self.assertEqual(pin,{'path':str(EXAMPLE),'bytes':len(self.raw),'sha256':EXAMPLE_SHA256,'custody':'CONTROLLER_PINNED_NOFOLLOW_READ'})
        model=TGuiNativeModel();self.assertEqual(model.text,'READY')
        scoped=drive(script,model)
        self.assertTrue(scoped.done);self.assertEqual(model.text,'PRESSED');self.assertEqual(model.exit,7)
        self.assertLessEqual(script.event_total,8)
        # Every delivered command passed the connection-layer allow-list.
        for command,arguments in model.calls:self.assertTrue(cap.input_arguments_valid(command,arguments))


class RecipeRefusals(Base):
    def load(self,path=None,sha=None,borrowed=None):
        return run_vm.load_input_recipe(path or self.path,sha or EXAMPLE_SHA256,borrowed,cap)
    def test_tampered_bytes_and_hash_mismatch(self):
        self.path.write_bytes(self.raw.replace(b'"ret"',b'"spc"'))
        with self.assertRaisesRegex(ValueError,'pinned SHA'):self.load()
        self.path.write_bytes(self.raw)
        with self.assertRaisesRegex(ValueError,'pinned SHA'):self.load(sha='0'*63+'1')
        with self.assertRaisesRegex(ValueError,'lowercase hex'):self.load(sha=EXAMPLE_SHA256.upper())
    def test_symlink_swapped_path_refused_without_reading(self):
        os.unlink(self.path);os.symlink(EXAMPLE,self.path)
        with self.assertRaisesRegex(ValueError,'non-symlink'):self.load()
        borrowed=FakeBorrowed(EXAMPLE)
        with self.assertRaisesRegex(ValueError,'non-symlink'):self.load(borrowed=borrowed)
        self.assertEqual(borrowed.items,[])
    def test_guardian_route_reads_only_the_held_descriptor(self):
        other=self.dir/'held.json';other.write_bytes(self.raw.replace(b'150',b'151'))
        borrowed=FakeBorrowed(other)
        with self.assertRaisesRegex(ValueError,'pinned SHA'):self.load(borrowed=borrowed)
        self.assertEqual(borrowed.items,[({'path':str(self.path),'bytes':len(self.raw),'sha256':EXAMPLE_SHA256},cap.INPUT_RECIPE_MAX_BYTES)])
        script,pin=self.load(borrowed=FakeBorrowed(self.path))
        self.assertEqual(pin['custody'],'GUARDIAN_BORROWED_FULL_SHA_LEASED_FD');self.assertEqual(script.sha256,EXAMPLE_SHA256)
    def test_late_modified_file_does_not_change_compiled_script(self):
        script,_=self.load()
        self.path.write_bytes(self.raw.replace(b'"ret"',b'"esc"'))
        model=TGuiNativeModel();drive(script,model)
        self.assertEqual((model.text,model.exit),('PRESSED',7))
        self.assertEqual(model.calls[0][1]['keys'][0]['data'],'ret')
    def test_relative_and_oversize_paths(self):
        with self.assertRaisesRegex(ValueError,'absolute'):self.load(path=Path('recipe.json'))
        self.path.write_bytes(b' '*(cap.INPUT_RECIPE_MAX_BYTES+1))
        with self.assertRaisesRegex(ValueError,'bounded'):self.load()
    def compile(self,recipe):
        raw=recipe if type(recipe) is bytes else json.dumps(recipe).encode()
        return cap.InputScript(raw,hashlib.sha256(raw).hexdigest())
    def test_too_many_inputs_bad_keys_duplicates(self):
        with self.assertRaises(ValueError):self.compile({'start_after_s':0,'steps':[{'delay_ms':20,'tap':'a'}]*65})
        ev={'delay_ms':20,'abs':[1,1]}
        with self.assertRaises(ValueError):self.compile({'start_after_s':0,'steps':[ev]*64+[ev]})
        for key in ('f5','RET','enter','ret ','',None,1):
            with self.subTest(key=key),self.assertRaises(ValueError):self.compile({'start_after_s':0,'steps':[{'tap':key}]})
        with self.assertRaisesRegex(ValueError,'duplicate'):
            self.compile(b'{"start_after_s":0,"start_after_s":1,"steps":[{"tap":"ret"}]}')
        with self.assertRaisesRegex(ValueError,'duplicate'):
            self.compile(b'{"start_after_s":0,"steps":[{"tap":"ret","tap":"esc"}]}')
        with self.assertRaises(ValueError):self.compile(b'{"start_after_s":NaN,"steps":[{"tap":"ret"}]}')


class ArgvControls(unittest.TestCase):
    def run_main(self,argv):
        with mock.patch.object(sys,'argv',['run_vm.py',*argv]),mock.patch('sys.stderr'),self.assertRaises(SystemExit) as raised:
            run_vm.main()
        return raised.exception.code
    base=['--plan','/x/plan.json','--plan-sha256','a'*64,'--repo','/x','--runtime-sources-sha256','b'*64]
    def test_duplicate_extra_and_abbreviated_flags_refused_before_custody(self):
        r=['--input-recipe','/x/r.json','--input-recipe-sha256',EXAMPLE_SHA256]
        for extra in (r+['--input-recipe','/x/s.json'],r+['--input-recipe-sha256='+'c'*64],
                      ['--input-recipe=/x/r.json']+r,r[:2]+['--input-recipe-s',EXAMPLE_SHA256],r+['--input-recipe-bytes','171']):
            with self.subTest(extra=extra),mock.patch.object(run_vm,'get_custody',side_effect=AssertionError('reached custody')):
                self.assertEqual(self.run_main(self.base+extra),2)
        self.assertTrue(run_vm.recipe_flags_unique(self.base+r))


class GuardianLeaseIdentity(Base):
    """task_custody.LeaseUnion holds the recipe FD; path swaps/writes break custody (needs F_SETLEASE on own file)."""
    def setUp(self):
        super().setUp()
        self.tc=_load('task_custody_recipe_intent',HERE/'task_custody.py')
        self.union=self.tc.LeaseUnion();self.addCleanup(lambda:self.union.closed or self.union.close())
        self.row={'path':str(self.path.resolve()),'bytes':len(self.raw),'sha256':EXAMPLE_SHA256}
    def test_leased_then_replaced(self):
        entry=self.union.add(self.row);self.assertTrue(entry['full_SHA_admitted']);self.union.check()
        swap=self.dir/'swap.json';swap.write_bytes(self.raw);os.replace(swap,self.path)
        with self.assertRaisesRegex(ValueError,'identity changed'):self.union.check()
        with self.assertRaisesRegex(ValueError,'identity changed'):self.union.close()  # release-time closure also refuses
        self.assertTrue(self.union.closed)
    def test_late_writer_breaks_lease(self):
        self.union.add(self.row)
        with self.assertRaises(BlockingIOError):os.open(self.path,os.O_WRONLY|os.O_NONBLOCK)
        with self.assertRaisesRegex(ValueError,'lease break'):self.union.check()
        with self.assertRaisesRegex(ValueError,'lease break'):self.union.close()
    def test_wrong_pin_never_admitted(self):
        with self.assertRaisesRegex(ValueError,'SHA mismatch'):self.union.add(dict(self.row,sha256='1'*64))
        self.assertEqual(self.union.rows,{})


if __name__=='__main__':unittest.main()
