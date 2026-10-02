#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run actual portable authority, complete kernel dispatcher and secret-entry controls."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=ROOT/'build/fd5c2-accounts');p.add_argument('--timeout',type=float,default=300);p.add_argument('--tests',nargs='+',choices=['test_accounts','test_auth_kernel','test_auth_secret'],default=['test_accounts','test_auth_kernel','test_auth_secret']);a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
 if not 1<=a.timeout<=600:p.error('--timeout must be between 1 and 600 seconds')
 files=list((ROOT/'shizukudos/accounts').glob('*.[ch]'))+[ROOT/'shizukudos/kernel64/sysk32_auth.c',ROOT/'shizukudos/kernel64/auth_policy.h',ROOT/'shizukudos/abi/shz_auth.h']
 files+=list((ROOT/'shizukudos/win64/apps/elevate').glob('*.[ch]'))+[Path(__file__).resolve()]+[ROOT/'shizukudos/tests'/(x+'.c') for x in a.tests]
 before={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files};results=[]
 for cc in ['gcc','clang']:
  flags=['-std=c11','-O2','-g','-Wall','-Wextra','-Werror']+(['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if cc=='clang' else [])
  for test in a.tests:
   exe=out/(cc+'-'+test);sources=[ROOT/'shizukudos/tests'/(test+'.c')]
   sources+=[ROOT/'shizukudos/win64/apps/elevate/secret.c'] if test=='test_auth_secret' else [ROOT/'shizukudos/accounts'/x for x in ['account.c','kdf.c','sha256.c']]
   cmd=[cc,*flags,*map(str,sources),'-o',str(exe)]
   try:
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=120);status=r.returncode;log=r.stdout+r.stderr
   except subprocess.TimeoutExpired as error:
    status=124;log=(error.stdout or b'').decode(errors='replace')+(error.stderr or b'').decode(errors='replace')+'\nCOMPILE TIMEOUT\n'
   (out/(cc+'-'+test+'-compile.log')).write_text(log)
   if status:
    results.append({'compiler':cc,'test':test,'exit':status,'phase':'compile'});print(cc,test,status,log,flush=True);continue
   started=time.monotonic()
   try:
    run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=a.timeout,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
    status=run.returncode;log=run.stdout+run.stderr
   except subprocess.TimeoutExpired as error:
    status=124;log=(error.stdout or b'').decode(errors='replace')+(error.stderr or b'').decode(errors='replace')+'\nTIMEOUT\n'
   (out/(cc+'-'+test+'-run.log')).write_text(log);print(cc,test,status,log.strip(),flush=True)
   results.append({'compiler':cc,'test':test,'exit':status,'elapsed_seconds':time.monotonic()-started,'timeout_seconds':a.timeout,'sha256':hashlib.sha256(exe.read_bytes()).hexdigest()})
 after={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files};receipt={'source_sha256':before,'source_stable':before==after,'results':results,'requested_tests':a.tests,'scope':'host production code plus declared hardware/loader adapters; no guest/native/installer claim'}
 (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 raise SystemExit(any(r['exit'] for r in results) or before!=after)
if __name__=='__main__':main()
