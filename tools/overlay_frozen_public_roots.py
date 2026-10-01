#!/usr/bin/env python3
"""Copy verified public trust into a frozen native runtime with its new helper."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import ssl
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_frozen_native_subset import unpack, load_builder
from capture_modern_app import public_root_bootstrap


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True)
    p.add_argument('--verified-trust',type=Path,required=True)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    base=a.base.resolve(strict=True);trust=a.verified_trust.resolve(strict=True)
    capture=a.capture.resolve(strict=True);out=a.out.resolve()
    assert out.is_relative_to(ROOT/'build') and out!=ROOT/'build' and not out.exists()
    trust_proof=public_root_bootstrap(trust)
    base_proof=json.loads((base/'receipt.json').read_text())
    assert base_proof['status']=='PASS' and 't_runtime_roots' in base_proof['commands']
    inputs=[Path(__file__).resolve(),Path(unpack.__code__.co_filename),ROOT/'tools/capture_modern_app.py',
            base/'receipt.json',base/'WIN64.IMG',base/'native/t_runtime_roots.exe',
            trust/'receipt.json',trust/'WIN64.IMG',capture/'receipt.json',
            capture/'host-public-ca-bundle.pem',capture/'host-chain-public.log',
            *(capture/f'server-{i}.der' for i in range(3)),ROOT/'shizukudos/win64/build.py']
    pins={str(f):digest(f) for f in inputs}
    raw=(base/'WIN64.IMG').read_bytes();assert hashlib.sha256(raw).hexdigest()==base_proof['archive_sha256']
    files=unpack(raw);old=unpack((trust/'WIN64.IMG').read_bytes())
    cap=json.loads((capture/'receipt.json').read_text());pem=(capture/'host-public-ca-bundle.pem').read_bytes()
    assert cap['returncode']==0 and hashlib.sha256(pem).hexdigest()==cap['bundle_sha256']
    blocks=re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',pem,re.S)
    certs=[ssl.PEM_cert_to_DER_cert(x.decode('ascii')) for x in blocks]
    identities=[{'index':i,'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)} for i,b in enumerate(certs)]
    assert identities==cap['anchors'] and len(certs)==trust_proof['public_anchor_count']
    bundle=b'SHZCA001'+struct.pack('<II',1,len(certs))+b''.join(struct.pack('<I',len(c))+c for c in certs)
    assert old['\\SHZ\\CERTS\\ROOTS.BIN']==bundle
    log=(capture/'host-chain-public.log').read_bytes()
    server_pems=re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',log,re.S)
    server=[ssl.PEM_cert_to_DER_cert(x.decode('ascii')) for x in server_pems]
    assert len(server)==3==cap['server_certificates']
    for i,b in enumerate(server):assert b==(capture/f'server-{i}.der').read_bytes()==old[f'\\SHZ\\CERTS\\SERVER{i}.CER']
    helper='\\SHZ\\TESTS\\T_RUNTIME_ROOTS.EXE'
    native=(base/'native/t_runtime_roots.exe').read_bytes()
    assert native==files[helper] and hashlib.sha256(native).hexdigest()==base_proof['replaced_or_added'][helper]
    # GCC may split local WCHAR array constants into reordered vector stores.
    # Bind the exact compiled source instead of mistaking raw literal absence
    # for a missing command. Actual child argv propagation remains a guest gate.
    helper_source=ROOT/'shizukudos/win64/tests/t_runtime_roots.c'
    assert digest(helper_source)==base_proof['sources'][str(helper_source)]
    assert '--no-sandbox -no-cef-sandbox' in helper_source.read_text()
    inputs.append(helper_source);pins[str(helper_source)]=digest(helper_source)
    additions={helper:native,'\\SHZ\\CERTS\\ROOTS.BIN':bundle,
               **{f'\\SHZ\\CERTS\\SERVER{i}.CER':b for i,b in enumerate(server)}}
    assert all(name==helper or name not in files for name in additions)
    files.update(additions);packed=load_builder().pack_archive(sorted(files.items()))
    assert pins=={str(f):digest(f) for f in inputs}
    out.mkdir();(out/'WIN64.IMG').write_bytes(packed)
    proof={'status':'NATIVE_BUILD_PASS_GUEST_PENDING','mode':'immutable-native-helper-and-verified-public-trust-overlay',
           'inputs':pins,'archive_sha256':hashlib.sha256(packed).hexdigest(),
           'base_native_receipt_sha256':pins[str(base/'receipt.json')],
           'unchanged_payload_count':len(unpack(raw)),'helper_already_present_and_unchanged_in_base':True,
           'additions':{name:hashlib.sha256(data).hexdigest() for name,data in additions.items()},
           'public_anchor_count':len(certs),'anchor_identities':identities,'host_capture_chain_matches_der':True,
           'native_windows98_verified':False,'app_functionality_verified':False,
           'tls_verification_disabled':False,'host_trust_modified':False,'steam_sandbox_switches_in_pinned_compiled_source':True,'actual_child_argv_propagation_verified':False}
    (out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    public_root_bootstrap(out)
    print('PASS public trust overlay:',len(certs),'real anchors; native Steam helper has both required sandbox switches')


if __name__=='__main__':main()
