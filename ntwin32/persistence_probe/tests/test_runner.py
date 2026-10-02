#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual tiny Linux child controls; not Windows or cold-boot evidence."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

MODULE=Path(__file__).resolve().parents[1]/'test.py'
SPEC=importlib.util.spec_from_file_location('perschk_runner',MODULE)
runner=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)


class OwnedCommands(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='perschk-child-control-',dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.env=os.environ.copy(); self.env['TMPDIR']=str(self.root)

    def call(self,code,**limits):
        return runner.execute_owned([sys.executable,'-c',code],self.root,self.env,self.root/'raw.log',**limits)

    def test_stream_overflow_stops_child_before_followup_write_and_bounds_raw_log(self):
        marker=self.root/'after-flood'
        code="import os,pathlib; block=b'x'*65536; [(os.write(1,block)) for _ in range(160)]; pathlib.Path('after-flood').write_text('unaccepted')"
        with self.assertRaises(RuntimeError): self.call(code,output_limit=1024)
        self.assertFalse(marker.exists())
        self.assertLessEqual((self.root/'raw.log').stat().st_size,1024)

    def test_timeout_stops_descendant_before_followup_write(self):
        descendant="import time,pathlib; time.sleep(0.5); pathlib.Path('after-timeout').write_text('unaccepted')"
        code="import subprocess,sys,time,pathlib; child=subprocess.Popen([sys.executable,'-c',"+repr(descendant)+"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); pathlib.Path('child.pid').write_text(str(child.pid)); time.sleep(20)"
        pidfile=self.root/'child.pid'
        try:
            with self.assertRaises(subprocess.TimeoutExpired): self.call(code,timeout=0.25)
            self.assertTrue(pidfile.exists())
            time.sleep(0.6)
            self.assertFalse((self.root/'after-timeout').exists())
        finally:
            if pidfile.exists():
                try: os.kill(int(pidfile.read_text()),9)
                except ProcessLookupError: pass

    def test_file_size_limit_stops_unaccepted_large_temp_output(self):
        code="import pathlib; pathlib.Path('large.tmp').write_bytes(b'x'*65536); pathlib.Path('after-file').write_text('unaccepted')"
        result=self.call(code,file_limit=32768)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'after-file').exists())
        self.assertLessEqual((self.root/'large.tmp').stat().st_size,32768)

    def test_group_kill_failure_preserves_primary_error_and_reaps_and_closes(self):
        real_popen,real_killpg=subprocess.Popen,os.killpg; children=[]
        def owned_child(*args,**kwargs):
            child=real_popen(*args,**kwargs); children.append(child); return child
        error=None
        try:
            with patch.object(runner.subprocess,'Popen',owned_child), \
                 patch.object(runner.os,'killpg',side_effect=PermissionError('injected group kill denial')):
                try: self.call("import os,time; os.write(1,b'x'*2048); time.sleep(20)",output_limit=1024)
                except Exception as caught: error=caught
            self.assertIsInstance(error,RuntimeError)
            self.assertIn('bounded raw output',str(error))
            self.assertTrue(any('group kill' in note for note in getattr(error,'__notes__',())))
            self.assertIsNotNone(children[0].returncode)
            self.assertTrue(children[0].stdout.closed)
        finally:
            for child in children:
                if child.returncode is None:
                    try: real_killpg(child.pid,9)
                    except ProcessLookupError: pass
                    child.wait(timeout=5)
                child.stdout.close()


if __name__=='__main__': unittest.main()
