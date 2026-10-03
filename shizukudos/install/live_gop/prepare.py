#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Add actual Win16 caller and its private request to an owned GOP clone profile.

This stages root files through the existing backup/readback constructor. It does
not author hives, register RunOnce, execute Windows, or install a display driver.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('gop_preinstall',HERE.parent/'gop_preinstall_profile.py')
gop=importlib.util.module_from_spec(spec);spec.loader.exec_module(gop)
r,need=gop.replacement,gop.need
spec=importlib.util.spec_from_file_location('gop_installer_build',HERE/'build.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)

def request_bytes(enumkey,provider,pins):
    need(type(enumkey) is str and enumkey.lower().startswith('enum\\') and
         re.fullmatch(r'[A-Za-z0-9_&\\-]{6,255}',enumkey) is not None and
         enumkey.count('\\')>=2, 'explicit observed safe Enum key required')
    need(type(provider) is str and re.fullmatch('[0-9a-f]{64}',provider) and provider!='0'*64,
         'literal actual producer implementation identity required')
    need(set(pins)=={'DRV_SHA256','VXD_SHA256','INF_SHA256','SETUPX_SHA256'} and
         all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) and v!='0'*64 for v in pins.values()),
         'exact source-bound driver/actual guest SetupX pins required')
    text='[GOP]\r\nEnumKey='+enumkey+'\r\n'
    for name,value in pins.items():text+=name+'='+value+'\r\n'
    return (text+'LIVE_PROVIDER_SHA256='+provider+'\r\n').encode('ascii')

def prepare(request_path,request_sha,out,budget):
    first=r.local_pin(request_path,request_sha);request=gop.startup.read_json(first)
    need(type(request) is dict and set(request)=={'schema','gop_profile','utility_build_receipt','setupx_dll','enum_key'} and
         request['schema']=='shizukuos.private-live-gop-stage-request.v1','exact private stage request required')
    out=r.safe_path(out);r.private_output(out)
    need(not out.exists() and out.parent.is_dir(),'fresh private output required')
    need(type(budget) is int and 1<<20<=budget<=1<<30,'bounded capture budget required')
    own=[r.local_pin(p) for p in (Path(__file__).resolve(),HERE.parent/'gop_preinstall_profile.py',
                                HERE.parent/'win98_source_profile.py',gop.startup.CONSTRUCTOR,HERE/'build.py')]
    initial=[first,request['gop_profile'],request['utility_build_receipt'],request['setupx_dll'],*own]
    # Invalidate constructor-visible outputs even on a late lease break.
    owned = None
    try:
        with r.leased_inputs(initial) as held:
            stage=r.bounded_json(held[request['gop_profile']['path']])
            build=r.bounded_json(held[request['utility_build_receipt']['path']])
            need(stage.get('schema')=='shizukuos.private-gop-preinstall-profile.v1' and
                 stage.get('status')=='PRIVATE_GOP_PAYLOADS_PREPARED_NOT_INSTALLED' and
                 all(stage.get(n) is False for n in ('public_artifact','VM_executed','default_GOP_registered',
                                                    'Windows98_boot_verified','native_apps_verified')),
                 'raw source-bound GOP staging producer required')
            need(build.get('schema')=='shizukuos.private-win16-gop-installer-build.v1' and
                 build.get('status')=='HOST_COMPILE_LINK_PASS_NOT_EXECUTED' and
                 all(build.get(n) is False for n in ('public_artifact','VM_executed','default_GOP_registered','GPU_active','cold_boot_verified')),
                 'raw actual Win16 caller build required')
            current_paths=(HERE/'gopinst.c',HERE/'native_gop_gate.c',HERE/'native_gop_gate.h',HERE/'build.py',
                 builder.REPO/'drivers/shizuku_gop/gop_contract.h',builder.REPO/'drivers/shizuku_gop/gop_live_contract.h',
                 builder.REPO/'shizukudos/accounts/sha256.c',builder.REPO/'shizukudos/accounts/sha256.h')
            current_pins=[r.local_pin(p) for p in current_paths];held.add_inputs(current_pins)
            expected_sources={str(p.relative_to(builder.REPO)):pin['sha256'] for p,pin in zip(current_paths,current_pins)}
            need(build.get('captured_public_sources')==expected_sources and
                 build.get('sdk_header_sha256')==builder.SDK and build.get('Watcom_snapshot_sha256')==builder.SNAPSHOT,
                 'exact reviewed Win16 source/SDK/tool snapshot closure required')
            required={'binl64/wcc','binl64/wlink','binl64/wlink.lnk','lib286/win/windows.lib','lib286/win/clibl.lib'}
            need(type(build.get('captured_compiler_closure')) is dict and
                 required<=set(build['captured_compiler_closure']), 'actual compiler/link library closure required')
            base=Path(request['utility_build_receipt']['path']).parent
            utility=build['artifact'];r.pin_fields(utility)
            need(utility['path']==str(base/'GOPINST.EXE'),'artifact must belong to actual private capture')
            rows=[stage['constructor_profile'],stage['gop_receipt'],stage['launch_profile'],utility,
                  *stage['producer_inputs'],*stage['recorded_lineage_pins'],*stage['staged_payloads'].values()]
            for key,folder in (('captured_public_sources','source'),('captured_compiler_closure','ow'),('sdk_header_sha256','sdk')):
                mapping=build.get(key)
                need(type(mapping) is dict and 0<len(mapping)<=3000,'bounded actual utility build closure required')
                for name,sha in mapping.items():rows.append(r.recorded_pin(r.source_name(name,base/folder),sha))
            held.add_inputs(rows)
            profile=r.bounded_json(held[stage['constructor_profile']['path']])
            need(profile.get('schema')=='shizukuos.private-replacement-profile.v1' and
                 type(profile.get('payloads')) is list and len(profile['payloads'])==8 and
                 {p['guest'] for p in profile['payloads']}==gop.BASE|set(gop.DRIVERS),
                 'original eight source-bound startup/GOP payloads required')
            held.add_inputs([p['file'] for p in profile['payloads']])
            for name in gop.DRIVERS:
                need(next(p['file'] for p in profile['payloads'] if p['guest']==name)==stage['staged_payloads'][name],
                     'GOP profile payload differs from staged source bytes')
            raw=gop.read_bytes(held,utility,2<<20)
            need(len(raw)>=64 and raw[:2]==b'MZ','actual Win16 executable required')
            offset=struct.unpack_from('<I',raw,60)[0]
            need(offset>=64 and offset+2<=len(raw) and raw[offset:offset+2]==b'NE','actual Win16 NE caller required')
            sdk=gop.read_bytes(held,request['setupx_dll'],4<<20)
            need(len(sdk)>=64 and sdk[:2]==b'MZ','actual private guest SetupX executable required')
            offset=struct.unpack_from('<I',sdk,60)[0]
            need(offset>=64 and offset+2<=len(sdk) and sdk[offset:offset+2]==b'NE','actual Win98 SetupX NE DLL required')
            pins={key:stage['staged_payloads'][name]['sha256'] for key,name in
                  (('DRV_SHA256','SHZGOP.DRV'),('VXD_SHA256','SHZGOP.VXD'),('INF_SHA256','SHZGOP.INF'))}
            pins['SETUPX_SHA256']=request['setupx_dll']['sha256']
            ini=request_bytes(request['enum_key'],stage['live_provider_identity_sha256'],pins)
            r.capacity(out.parent,len(raw)+len(ini)+(4<<20),budget);out.mkdir(mode=0o700)
            stat=out.stat(follow_symlinks=False);owned=(stat.st_dev,stat.st_ino)
            for name,data in (('GOPINST.EXE',raw),('GPREQ.INI',ini)):gop.startup.write_private(out/name,data)
            additions=[{'guest':n,'file':r.local_pin(out/n)} for n in ('GOPINST.EXE','GPREQ.INI')]
            held.add_inputs([p['file'] for p in additions]);profile=copy.deepcopy(profile);profile['payloads']+=additions
            raw=(json.dumps(profile,indent=2)+'\n').encode();profilepin={'path':str(out/'replacement-profile.json'),'bytes':len(raw),'sha256':r.digest(raw)}
            result={'schema':'shizukuos.private-live-gop-stage.v1','status':'PRIVATE_CALLER_REQUEST_STAGED_NOT_EXECUTED',
                    'constructor_profile':profilepin,'request':first,'producer_inputs':own,
                    'source_gop_profile':request['gop_profile'],'utility_build_receipt':request['utility_build_receipt'],
                    'utility_payloads':additions,'private_SetupX_source':request['setupx_dll'],
                    'live_provider_identity_sha256':stage['live_provider_identity_sha256'],
                    'VM_executed':False,'default_GOP_registered':False,'GPU_active':False,'Windows98_boot_verified':False,
                    'public_artifact':False,'native_ingester_compatible':False,'Supervisor_epoch_verified':False,
                    'required_live_operation':'Load actual native GOP provider in an independently admitted boot, then run Win16 GOPINST.EXE /install; supported live RunOnce may be registered by the guest operator, not this staging producer.'}
            gop.startup.publish(out/'stage-result.json',(json.dumps(result,indent=2)+'\n').encode())
            gop.startup.publish(out/'replacement-profile.json',raw)
            held.add_inputs([profilepin,r.local_pin(out/'stage-result.json')])
            for item in held.values():item['checkpoint']()
        return result
    except BaseException:
        if owned is not None:
            try:
                stat=out.stat(follow_symlinks=False)
                if (stat.st_dev,stat.st_ino)==owned:
                    for n in ('replacement-profile.json','stage-result.json'):(out/n).unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        raise
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True)
    p.add_argument('--request-sha256',required=True);p.add_argument('--private-out',type=Path,required=True)
    p.add_argument('--capture-budget-bytes',type=int,required=True);a=p.parse_args()
    result=prepare(a.request,a.request_sha256,a.private_out,a.capture_budget_bytes)
    print(json.dumps({'status':result['status'],'constructor_profile':result['constructor_profile'],'default_GOP_registered':False}))
