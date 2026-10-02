#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Receipt binding controls in private copies; no real source is mutated."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
class ReceiptControls(unittest.TestCase):
    def fixture(self,folder):
        root=Path(folder)
        for name in ('kernel32','kcommon','abi'):
            shutil.copytree(ROOT/'shizukudos'/name,root/'shizukudos'/name,
                            ignore=shutil.ignore_patterns('build','__pycache__'))
        driver=root/'shizukudos/tests/test_k32_ipc.py';driver.parent.mkdir(parents=True)
        shutil.copy2(ROOT/'shizukudos/tests/test_k32_ipc.py',driver)
        header=root/'shizukudos/kcommon/receipt_dependency.h'
        header.write_text('/* private nested compiler dependency */\n')
        k32=root/'shizukudos/kernel32/k32.h'
        k32.write_text('#include "../kcommon/receipt_dependency.h"\n'+k32.read_text())
        spec=importlib.util.spec_from_file_location('k32_receipt_fixture',driver)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return root,driver,header,module
    def test_compiler_closure_control_and_nested_header_drift(self):
        for phase in (None,"object","discovery"):
            mutate=phase is not None
            with self.subTest(phase=phase),tempfile.TemporaryDirectory(prefix='k32 receipt ') as folder:
                root,driver,header,module=self.fixture(folder)
                before=module.digest(header.read_bytes());real_run=subprocess.run;changed=False
                def run(command,**kwargs):
                    nonlocal changed
                    # Mutation occurs after initial binding and host tests, at
                    # the actual freestanding object compiler boundary.
                    if mutate and ('-MM' if phase=='discovery' else '-c') in command and not changed:
                        header.write_text(header.read_text()+'/* persistent mutation */\n');changed=True
                    return real_run(command,**kwargs)
                out=root/'evidence'
                with mock.patch.object(module.subprocess,'run',run),mock.patch.object(sys,'argv',[str(driver),'--out',str(out)]),contextlib.redirect_stdout(io.StringIO()):
                    status=module.main()
                result=json.loads((out/'result.json').read_text())
                evidence=os.environ.get('K32_RECEIPT_CONTROL_OUT')
                if evidence:
                    saved=Path(evidence);saved.mkdir(parents=True,exist_ok=True)
                    (saved/((phase or 'control')+'.json')).write_text(json.dumps(result,indent=2)+'\n')
                self.assertEqual(status,1 if mutate else 0,result)
                self.assertEqual(result['source_compiler_binary_before_after_match'],not mutate)
                self.assertEqual(result['sources_sha256'].get(str(header.relative_to(root))),before)
                label='host_gcc' if phase=='discovery' else 'i486'
                self.assertIn(str(header.relative_to(root)),result['project_dependencies'][label])
                self.assertEqual(changed,mutate)
                self.assertIn(str(header.relative_to(root)),result['changed_project_inputs'] if mutate
                              else result['sources_sha256'])

if __name__=='__main__':unittest.main()
