#!/usr/bin/env python3
"""Carry the three exact genuine OS catalogs from the closed WS2 source receipt."""
import argparse,hashlib,json
from pathlib import Path
from build_frozen_native_subset import unpack,load_builder
ROOT=Path(__file__).resolve().parents[1]
RECEIPT=Path('/root/Win98-Modern-codex-20260930/build/app-inputs/productivity-01a0f3d0cb43/tools/ws2-legacy-v1/frozen-source-receipt-v1.json')
RECEIPT_SHA='9d60d3b1c47ee2dd3f32487cb68d4d9ed82ae37f5d4e7585a263f8742e0d01d9'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--base',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
 base=a.base.resolve(strict=True);out=a.out.resolve()
 if not out.is_relative_to(ROOT/'build/modern-apps') or out.exists():raise ValueError('fresh private output required')
 if sha(RECEIPT)!=RECEIPT_SHA:raise ValueError('closed catalog receipt drift')
 frozen=json.loads(RECEIPT.read_text());bp=json.loads((base/'receipt.json').read_text())
 if bp['status']!='PASS':raise ValueError('ordinary build pass required')
 raw=(base/'WIN64.IMG').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=bp['archive_sha256']:raise ValueError('base bytes drift')
 inputs=[Path(__file__).resolve(),Path(unpack.__code__.co_filename),ROOT/'shizukudos/win64/build.py',RECEIPT,base/'receipt.json',base/'WIN64.IMG',*(Path(v['path']) for v in frozen['catalogs'].values())];pins={str(p):sha(p) for p in inputs}
 files=unpack(raw);old=dict(files);added=0;reused=0;records={}
 for key,row in frozen['catalogs'].items():
  data=Path(row['path']).read_bytes();name=row['guest_archive_path']
  if hashlib.sha256(data).hexdigest()!=row['sha256'] or len(data)!=row['bytes']:raise ValueError('catalog drift')
  if name in files:
   if files[name]!=data:raise ValueError('existing catalog differs')
   reused+=1
  else:files[name]=data;added+=1
  records[name]={'sha256':row['sha256'],'bytes':len(data)}
 if added!=2 or reused!=1:raise ValueError('expected exact services inheritance and two new catalogs')
 packed=load_builder().pack_archive(sorted(files.items()));new=unpack(packed)
 if len(new)!=len(old)+added or any(new[k]!=v for k,v in old.items()):raise ValueError('old payload changed')
 if pins!={str(p):sha(p) for p in inputs}:raise ValueError('inputs drift')
 out.mkdir();(out/'WIN64.IMG').write_bytes(packed);(out/'receipt.json').write_text(json.dumps({'status':'FROZEN_CATALOG_OVERLAY_PASS_GUEST_PENDING','mode':'closed-real-catalog-copy','inputs':pins,'archive_sha256':hashlib.sha256(packed).hexdigest(),'catalogs':records,'unchanged_payloads':len(old),'new_catalogs':added,'identical_reused_catalogs':reused,'actual_guest_executed':False,'host_configuration_modified':False},indent=2)+'\n');print('PASS: all native payloads preserved, three exact catalogs carried')
if __name__=='__main__':main()
