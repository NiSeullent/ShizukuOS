# SPDX-License-Identifier: GPL-2.0-only
"""Caller refusal and guardian-bound QMP guard controls; no QEMU or guest."""
import importlib.util
import hashlib
import json
import tempfile
import os
from pathlib import Path
import socket
import types
import unittest
from unittest.mock import Mock

HERE=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location('pci_caller_'+name,HERE/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
G=load('task_custody');R=load('run_vm')

class CallerControls(unittest.TestCase):
 def test_optional_selection_refuses_unowned_controller_before_outputs(self):
  args=types.SimpleNamespace(pci_preparation_json='{}')
  with self.assertRaisesRegex(ValueError,'guardian-selected'):
   R.run_plan(args,None,None,None)
 def test_null_selection_refuses_before_any_guardian_read(self):
  args=types.SimpleNamespace(pci_preparation_json='null')
  with self.assertRaisesRegex(ValueError,'selection object'):
   R.run_plan(args,None,object(),None)
 def test_actual_unix_peer_check_requires_live_guard_and_admitted_monitor(self):
  left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
  self.addCleanup(left.close);self.addCleanup(right.close)
  owner=types.SimpleNamespace(assert_owned=Mock(),qmp=left,process=types.SimpleNamespace(pid=os.getpid()))
  server=object.__new__(G.Server);server.owner=owner;server.sequence=0
  answer,rights=server.dispatch({'id':1,'op':'live-check','params':{}},[])
  self.assertIs(answer,True);self.assertEqual(rights,[]);self.assertEqual(owner.assert_owned.call_count,2)
  owner.process.pid+=1
  with self.assertRaisesRegex(ValueError,'QMP peer differs'):
   server.dispatch({'id':2,'op':'live-check','params':{}},[])
  owner.qmp=None
  with self.assertRaisesRegex(ValueError,'admitted QMP'):
   server.dispatch({'id':3,'op':'live-check','params':{}},[])
  owner.assert_owned.side_effect=ValueError('owned pidfd failed')
  with self.assertRaisesRegex(ValueError,'pidfd failed'):
   server.dispatch({'id':4,'op':'live-check','params':{}},[])

 def test_guardian_retains_and_executes_actual_adapter_and_original_observation_bytes(self):
  spec=importlib.util.spec_from_file_location('pci_evidence_fixture',HERE.parents[2]/'tools/tests/test_native_pci_preparation.py')
  fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
  observed,pins,reader,plan=fixture.fixture()
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   def materialize(row):
    raw=reader(row,1<<20);path=root/Path(row['path']).name;path.write_bytes(raw);row['path']=str(path)
   for row in observed['input_pins'].values():materialize(row)
   argv=observed['argv'];argv[0]=observed['input_pins']['qemu']['path']
   raw=b'\0'.join(os.fsencode(arg) for arg in argv)+b'\0';sha=hashlib.sha256(raw).hexdigest()
   binding=observed['argv_binding'];binding.update(expected_sha256=sha,actual_sha256=sha,expected_bytes=len(raw),actual_bytes=len(raw))
   observed['owned_process'].update(argv_sha256=sha,argv_bytes=len(raw),argv_hex=raw.hex())
   record=root/'observation.json';record.write_text(json.dumps(observed))
   source=root/'native_pci_preparation.py';source.write_bytes((HERE.parents[2]/G.PCI_PREPARATION_SOURCE).read_bytes())
   def pin(path):return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
   manifest={'pci_preparation':{'observation':pin(record),'producer_pins':pins}}
   sources={G.PCI_PREPARATION_SOURCE:pin(source)}
   union=G.LeaseUnion()
   try:
    union.add(sources[G.PCI_PREPARATION_SOURCE])
    rows=G.admit_pci_preparation(manifest,plan,sources,union)
    self.assertEqual([x['bdf'] for x in rows],[8,16])
    self.assertIn(str(record),union.rows)
    self.assertTrue(all(x['full_SHA_admitted'] for x in union.rows.values()))
    with self.assertRaisesRegex(ValueError,'declared together'):
     G.admit_pci_preparation(manifest,plan,{},union)
   finally:union.close()

if __name__=='__main__':unittest.main()
