#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build only the account companion and audit its real PE import surface."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=ROOT/'build/fd5c2-elevate');a=parser.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
 sources=sorted(Path(__file__).parent.glob('*.c'))+[ROOT/'shizukudos/win64/crt/shzcrt.c']
 deps=sources+sorted(Path(__file__).parent.glob('*.h'))+[ROOT/'shizukudos/abi/shz_auth.h',ROOT/'shizukudos/accounts/account.h',ROOT/'shizukudos/win64/include/nt.h',ROOT/'shizukudos/kernel64/ntsys.h']
 before={str(p.relative_to(ROOT)):sha(p) for p in deps}
 definition=out/'shznt.def';definition.write_text('LIBRARY ntdll.dll\nEXPORTS\n NtShzToken\n NtShzEvidence\n NtShzDebugPrint\n')
 subprocess.run(['x86_64-w64-mingw32-dlltool','-d',str(definition),'-l',str(out/'libshznt.a')],check=True)
 exe=out/'ELEVATE.EXE'
 cmd=['x86_64-w64-mingw32-gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-nostdlib','-Wl,--entry,ShzStart','-Wl,--subsystem,console','-Wl,--kill-at','-I',str(ROOT/'shizukudos/win64/include'),'-I',str(ROOT/'shizukudos/win64/crt'),*map(str,sources),'-L',str(out),'-lshznt','-lkernel32','-lntdll','-luser32','-lgdi32','-lgcc','-o',str(exe)]
 r=subprocess.run(cmd,capture_output=True,text=True);(out/'compile.log').write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError(r.stderr)
 imports=subprocess.check_output(['x86_64-w64-mingw32-objdump','-p',str(exe)],text=True);(out/'imports.txt').write_text(imports)
 symbols=re.findall(r'^\s+[0-9a-f]+\s+<none>\s+[0-9a-f]+\s+(\w+)\s*$',imports,re.M)
 providers=list((ROOT/'shizukudos/win64/kernel32').glob('*.c'))+list((ROOT/'shizukudos/win64/dlls/user32').glob('*.c'))+list((ROOT/'shizukudos/win64/dlls/gdi32').glob('*.c'))+list((ROOT/'shizukudos/win64/ntdll').glob('*.c'))
 inventory=set()
 for p in providers:inventory.update(re.findall(r'^(?:K32API|DLLAPI)\s+[^;{}\n]*?\b(\w+)\s*\(',p.read_text(),re.M))
 inventory.update(['NtShzToken','NtShzEvidence'])
 for p in (ROOT/'shizukudos/win64/ntdll').glob('*.c'):
  inventory.update(re.findall(r'^(?:SHZ_EXPORT\s+)?[^;{}\n]+\bNTAPI\s+\**(\w+)\s*\(',p.read_text(),re.M))
 # kernel32 forwarders are explicit in the existing build configuration.
 config=(ROOT/'shizukudos/win64/build.py').read_text();inventory.update(re.findall(r'"(\w+) = [^"\n]+"',config))
 missing=sorted(set(symbols)-inventory)
 after={str(p.relative_to(ROOT)):sha(p) for p in deps}
 result={'source_sha256':before,'source_stable':before==after,'exe_sha256':sha(exe),'imports':symbols,'missing_import_providers':missing,'command':cmd,'scope':'real PE64 companion compile/import audit; GUI/native Windows98 not run'}
 (out/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
 if missing or before!=after:raise RuntimeError(str(missing) or 'sources moved')
 print(json.dumps({'exe':str(exe),'sha256':sha(exe),'imports':len(symbols),'missing':missing}))
if __name__=='__main__':main()
