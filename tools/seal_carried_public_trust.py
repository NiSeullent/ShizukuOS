#!/usr/bin/env python3
"""Verify already carried public trust and seal a copied immutable native runtime.

No trust bytes, helper, publisher package, or validation policy are changed.
This receipt permits the existing capture tool to verify the five exact inherited
payloads after an ordinary subset build; guest/application evidence stays separate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from capture_modern_app import public_root_bootstrap

ROOT = Path(__file__).resolve().parents[1]

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def unpack(raw):
    if len(raw)<16 or raw[:8]!=b'SHZARC01': raise ValueError('invalid archive')
    count=struct.unpack_from('<I',raw,8)[0]; header=16+count*136
    if header>len(raw): raise ValueError('truncated header')
    files={};spans=[]
    for i in range(count):
        name,off,size=struct.unpack_from('<120sQQ',raw,16+i*136)
        name=name.split(b'\0',1)[0].decode('ascii').casefold()
        if name in files or off<header or off+size>len(raw): raise ValueError('invalid entry')
        files[name]=raw[off:off+size];spans.append((off,off+size))
    spans.sort()
    if any(a[1]>b[0] for a,b in zip(spans,spans[1:])): raise ValueError('overlap')
    return files

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--base',type=Path,required=True)
    ap.add_argument('--verified-trust',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args();base=a.base.resolve(strict=True);trust=a.verified_trust.resolve(strict=True);out=a.out.resolve()
    if not out.is_relative_to(ROOT/'build') or out==ROOT/'build' or out.exists(): raise ValueError('fresh private output required')
    inputs=[Path(__file__).resolve(),ROOT/'tools/capture_modern_app.py',base/'receipt.json',base/'WIN64.IMG',trust/'receipt.json',trust/'WIN64.IMG']
    pins={str(p):digest(p) for p in inputs}
    bp=json.loads((base/'receipt.json').read_text())
    if bp.get('status')!='PASS' or bp.get('mode')!='ordinary-native-frozen-subset-build-and-immutable-runtime-merge': raise ValueError('ordinary build pass required')
    raw=(base/'WIN64.IMG').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=bp['archive_sha256']: raise ValueError('base archive mismatch')
    tp=public_root_bootstrap(trust);files=unpack(raw);old=unpack((trust/'WIN64.IMG').read_bytes())
    additions=tp['payload_sha256']
    for name,want in additions.items():
        if files.get(name)!=old[name] or hashlib.sha256(files.get(name,b'')).hexdigest()!=want: raise ValueError('carried trust or helper changed')
    if pins!={str(p):digest(p) for p in inputs}: raise ValueError('input changed')
    proof={'status':'NATIVE_BUILD_PASS_GUEST_PENDING','mode':'exact-inherited-trust-verification-no-payload-change',
        'inputs':pins,'archive_sha256':bp['archive_sha256'],'base_native_receipt_sha256':pins[str(base/'receipt.json')],
        'additions':additions,'public_anchor_count':tp['public_anchor_count'],'unchanged_payload_count':len(files),
        'all_base_payloads_identical':True,'host_trust_modified':False,'tls_verification_disabled':False,
        'guest_executed':False,'app_functionality_verified':False,'native_windows98_verified':False}
    out.mkdir();(out/'WIN64.IMG').write_bytes(raw);(out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    public_root_bootstrap(out)
    print('PASS: exact carried public trust/helper; all native-runtime bytes unchanged')

if __name__=='__main__': main()
