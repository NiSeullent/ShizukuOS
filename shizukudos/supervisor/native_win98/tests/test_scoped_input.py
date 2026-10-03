# SPDX-License-Identifier: GPL-2.0-only
"""Scoped owned-QMP scripted input controls; fake monitor, no VM."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('owned_capture_input_test',HERE/'owned_capture.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
Q='qcode'

def script(recipe):
    raw=json.dumps(recipe).encode();return m.InputScript(raw,hashlib.sha256(raw).hexdigest())

class FakeMonitor:
    def __init__(self):self.calls=[]
    def call(self,command,arguments=None):
        self.calls.append((command,arguments));return {}

def ev(kind,**data):return {'events':[{'type':kind,'data':data}]}
class ScopedInputTests(unittest.TestCase):
    def test_rejections(self):
        key=lambda k:{'type':'key','data':{'down':True,'key':{'type':Q,'data':k}}}
        bad=[('human-monitor-command',{'command-line':'info'}),('screendump',{'filename':'x'}),('input-send-event',None),
             ('input-send-event',{'events':[key('f5')]}),('input-send-event',{'events':[key('a')]*5}),('input-send-event',{'events':[]}),
             ('input-send-event',ev('rel',axis='x',value=128)),('input-send-event',ev('abs',axis='x',value=32768)),
             ('input-send-event',ev('abs',axis='z',value=1)),('input-send-event',ev('btn',down=True,button='side')),
             ('input-send-event',ev('abs',axis='x',value=True)),('input-send-event',{'events':[key('a')],'extra':1}),
             ('send-key',{'keys':[{'type':'number','data':1}]}),('send-key',{'keys':[{'type':Q,'data':'a'}],'hold-time':501})]
        for command,arguments in bad:
            with self.subTest(command=command,arguments=arguments):
                with self.assertRaises(ValueError):m.input_events_count(command,arguments)
                self.assertFalse(m.input_arguments_valid(command,arguments))
                if command in m.INPUT_COMMANDS:
                    with self.assertRaises(ValueError):m.OwnedQMP.__new__(m.OwnedQMP).call(command,arguments)
        self.assertTrue(m.input_arguments_valid('send-key',{'keys':[{'type':Q,'data':'ret'}],'hold-time':100}))
    def test_recipe_budgets_and_pin(self):
        step={'delay_ms':10,'tap':'a'}
        for recipe in ({'start_after_s':0,'steps':[step]*65},{'start_after_s':601,'steps':[step]},
                       {'start_after_s':0,'steps':[{'delay_ms':5001,'tap':'a'}]},
                       {'start_after_s':0,'steps':[{'delay_ms':5000,'rel':[0,0]}]*13},
                       {'start_after_s':0,'steps':[{'delay_ms':0,'tap':'a','rel':[1,1]}]},
                       {'start_after_s':0,'steps':[{'delay_ms':0,'rel':[1,1,1]}]},
                       {'start_after_s':0,'steps':[{'delay_ms':0,'key':'a'}]},
                       {'start_after_s':0,'steps':[{'delay_ms':0,'tap':'f9'}]},{'steps':[step]}):
            with self.subTest(recipe=recipe),self.assertRaises(ValueError):script(recipe)
        raw=json.dumps({'start_after_s':0,'steps':[step]}).encode()
        with self.assertRaises(ValueError):m.InputScript(raw,'0'*64)
        with self.assertRaises(ValueError):m.InputScript(b'x'*(m.INPUT_RECIPE_MAX_BYTES+1),'0'*64)
    def test_accepted_events_match_log(self):
        recipe={'start_after_s':2,'steps':[{'delay_ms':0,'abs':[100,200]},{'delay_ms':0,'btn':'left','down':True},
                {'delay_ms':50,'btn':'left','down':False},{'delay_ms':50,'key':'ret','down':True},{'delay_ms':0,'tap':'spc'}]}
        s=script(recipe);mon=FakeMonitor();run=m.ScopedInput(s,mon)
        run.poll(1.0);self.assertEqual(mon.calls,[]);self.assertEqual(run.next_due(1.0),1.0)
        run.poll(2.0);self.assertEqual(len(mon.calls),2)
        run.poll(2.2);self.assertTrue(run.done)
        self.assertEqual(mon.calls,[(e['command'],e['arguments']) for e in run.log])
        self.assertEqual(mon.calls[0],('input-send-event',{'events':[{'type':'abs','data':{'axis':'x','value':100}},{'type':'abs','data':{'axis':'y','value':200}}]}))
        self.assertEqual(mon.calls[-1][0],'send-key')
        ev_=run.evidence();self.assertEqual(ev_['events_sent'],2+1+1+1+1);self.assertTrue(ev_['complete']);self.assertEqual(ev_['recipe_sha256'],s.sha256)
        self.assertEqual([e['reply'] for e in run.log],[{}]*5)

if __name__=='__main__':unittest.main()
