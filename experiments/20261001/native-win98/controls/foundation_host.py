#!/usr/bin/env python3
import hashlib, importlib.util, json, os, struct, tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
script=HERE/'candidate/tools/build_native_supervisor_foundation.py'
spec=importlib.util.spec_from_file_location('foundation',script)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
checks=[]
def fail(label,call):
    try: call()
    except (ValueError,KeyError,OSError): checks.append(label)
    else: raise AssertionError(label+' was accepted')
raw=Path('/root/Win98-Modern-apps-cb43/build/modern-apps/app-runtime-v38-public-roots/WIN64.IMG').read_bytes()
tiny,n=m.tiny_runtime(raw)
assert n==156 and len(tiny)==3 and m.digest(dict(tiny)['\\SHZ\\TESTS\\T_HELLO.EXE'])==m.HELLO_SHA
checks.append('actual three-image AMD64 provider import/forwarder closure156')
fail('invalid archive magic',lambda:m.unpack(b'abcdefgh'+b'\0'*8))
fail('archive truncated table',lambda:m.unpack(b'SHZARC01'+struct.pack('<II',100,0)))
fail('archive reserved bits',lambda:m.unpack(raw[:12]+struct.pack('<I',1)+raw[16:]))
bad=bytearray(raw);bad[16:136]=b'x'*120
fail('unterminated archive path',lambda:m.unpack(bytes(bad)))
bad=bytearray(raw);bad[152:288]=bad[16:152]
fail('duplicate archive file',lambda:m.unpack(bytes(bad)))
bad=bytearray(raw);struct.pack_into('<Q',bad,136,1)
fail('archive file overlaps header',lambda:m.unpack(bytes(bad)))
files=m.unpack(raw);name='\\SHZ\\TESTS\\T_HELLO.EXE';changed=bytearray(raw)
pos=raw.find(files[name]);assert pos>=0;changed[pos+100]^=1
fail('actual hello byte mutation pin',lambda:m.tiny_runtime(bytes(changed)))
# A real import spelling absent from the two provider export tables must fail.
changed=bytearray(raw);pos=raw.find(files['\\SHZ\\SYS64\\kernel32.dll']);end=pos+len(files['\\SHZ\\SYS64\\kernel32.dll'])
idx=raw.find(b'NtShzDebugPrint\0',pos,end);assert idx>=0;changed[idx:idx+len(b'NtShzDebugPrint')]=b'XtShzDebugPrint'
fail('actual provider unresolved import',lambda:m.tiny_runtime(bytes(changed)))
with tempfile.TemporaryDirectory(prefix='foundation-host-') as folder:
    p=Path(folder)/'real';p.write_bytes(b'owned fixture')
    pin=m.digest(p.read_bytes());assert m.verified_input(p,pin)==b'owned fixture';checks.append('actual stable regular descriptor')
    fail('wrong input SHA',lambda:m.verified_input(p,'0'*64))
    fail('input size bound',lambda:m.verified_input(p,pin,2))
    s=Path(folder)/'alias';s.symlink_to(p);fail('symlink input',lambda:m.verified_input(s,pin))
    f=Path(folder)/'fifo';os.mkfifo(f);fail('nonblocking FIFO input',lambda:m.verified_input(f,pin))
    p.write_bytes(b'');fail('empty input',lambda:m.verified_input(p,m.digest(b'')))
build=m.ROOT/'build/modern-apps/native-foundation-current-build-v2'
receipt=json.loads((build/'foundation-build-receipt.json').read_text())
assert receipt['status']=='PASS_NATIVE_FOUNDATION_BUILD_NOT_RUN' and not receipt['standalone_compiled']
assert receipt['source_before_after_match'] and not receipt['VM_executed']
assert all(m.digest((build/'source'/p).read_bytes())==h for p,h in receipt['sources_sha256'].items())
assert all(m.digest((build/p).read_bytes())==h for p,h in receipt['artifacts'].items())
assert len(receipt['sources_sha256'])==221
checks.append('actual ordinary build221 immutable copied sources and six artifact pins')
assert receipt['producer_sha256']==m.digest(script.read_bytes())
checks.append('executed exact producer pin')
result={'status':'PASS','checks':checks,'count':len(checks),'producer_sha256':m.digest(script.read_bytes()),'VM_executed':False,'compiled_by_host_tests':False}
(HERE/'foundation-host-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
