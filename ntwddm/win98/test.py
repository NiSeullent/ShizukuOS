#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test original DIB adapter callbacks and pixels; never loads Windows or a VM."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE/'build'
SOURCES = ('ntwddm/win98/adapter.h','ntwddm/win98/adapter.c','ntwddm/win98/selftest.c',
           'ntwddm/win98/test_adapter.c','ntwddm/win98/test.py',
           'ntwddm/include/ntwddm.h','ntwddm/src/ntwddm.c')
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD/'host-tests.json'; receipt.unlink(missing_ok=True)
    before = {name:sha(ROOT/name) for name in SOURCES}
    logs = []
    for name,flags in (('strict',[]),('asan_ubsan',['-fsanitize=address,undefined','-fno-sanitize-recover=all'])):
        binary = BUILD/('test-'+name)
        command = ['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wpedantic',
                   '-Wconversion','-Wsign-conversion','-I',str(HERE.parent/'include'),*flags,
                   str(HERE/'adapter.c'),str(HERE/'selftest.c'),str(HERE/'test_adapter.c'),
                   str(HERE.parent/'src/ntwddm.c'),'-o',str(binary)]
        subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
        result = subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=60,
            env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
        if not result.stdout.startswith('PASS: '): raise RuntimeError('Missing test success')
        logs.append(name+'\n'+result.stdout+result.stderr)
    if any(sha(ROOT/name)!=value for name,value in before.items()): raise RuntimeError('Test source changed')
    log = BUILD/'host-tests.log'; log.write_text('\n'.join(logs))
    receipt.write_text(json.dumps({'passed':True,'variants':['strict','asan_ubsan'],
        'sources_sha256':before,'log_sha256':sha(log),'native_gdi':'not_executed','guest':'not_run'},indent=2)+'\n')
    print(log.read_text(),end='')
if __name__=='__main__':main()
