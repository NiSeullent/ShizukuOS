#!/usr/bin/env python3
"""Add the frozen real service catalog to a copied native runtime archive."""
import argparse, hashlib, json
from pathlib import Path
from build_frozen_native_subset import unpack, load_builder
ROOT=Path(__file__).resolve().parents[1]
CATALOG_SHA='2d84c0e7fe5ee474f8dc0096ccce7a5b10286be3da82d276acc5e79e7b8e42c0'
GUEST='\\SHZ\\SYS64\\drivers\\etc\\services'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--base',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
 a=p.parse_args();base=a.base.resolve(strict=True);catalog=a.catalog.resolve(strict=True);out=a.out.resolve()
 assert out.is_relative_to(ROOT/'build') and not out.exists()
 pins={str(f):sha(f) for f in [Path(__file__).resolve(),Path(unpack.__code__.co_filename),base/'receipt.json',base/'WIN64.IMG',catalog,ROOT/'shizukudos/win64/build.py']}
 receipt=json.loads((base/'receipt.json').read_text());assert receipt['status']=='PASS'
 raw=(base/'WIN64.IMG').read_bytes();assert hashlib.sha256(raw).hexdigest()==receipt['archive_sha256']
 files=unpack(raw);old=dict(files);data=catalog.read_bytes();assert hashlib.sha256(data).hexdigest()==CATALOG_SHA and len(data)==701707
 assert GUEST not in files;files[GUEST]=data
 packed=load_builder().pack_archive(sorted(files.items()));new=unpack(packed)
 assert all(new[k]==v for k,v in old.items()) and len(new)==len(old)+1 and new[GUEST]==data
 assert all(sha(Path(k))==v for k,v in pins.items())
 out.mkdir();(out/'WIN64.IMG').write_bytes(packed)
 proof={'status':'FROZEN_CATALOG_OVERLAY_PASS_GUEST_PENDING','inputs':pins,'archive_sha256':hashlib.sha256(packed).hexdigest(),'catalog_sha256':CATALOG_SHA,'catalog_guest_path':GUEST,'unchanged_payloads':len(old),'added_payloads':1,'actual_guest_executed':False,'host_configuration_modified':False}
 (out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n');print('PASS frozen real catalog overlay')
if __name__=='__main__':main()
