#!/usr/bin/env python3
"""Read composition diagnostics. Pixel samples never establish full scanout."""
import argparse
import hashlib
import json
from pathlib import Path
import re

REGIONS = ['CAPTION','NORMAL','HOT','PRESSED','DISABLED','CLASSIC_CONTROL','MODERN_CONTROL']
FIELDS = {'COMPOSE_API_STAGE','MEMORY_VALID','MEMORY_BACKGROUND_SAMPLES','MEMORY_BACKGROUND_MISMATCHES',
          'MEMORY_READS_INVALID','FULL_SCENE_TRANSFER','SCREEN_BPP','SCREEN_SAMPLES','SCREEN_MISMATCHES',
          'SCREEN_READS_INVALID','COMPOSE_CLEANUP_ISSUES','SCREEN_VERDICT'}
INK_FIELDS = {'REFERENCE_INK','ACTUAL_INK','TEXT_PIXEL_MISMATCHES'}

def require(value, message):
    if not value:
        raise ValueError(message)

def parse(data, nonce):
    require(re.fullmatch('[0-9a-f]{32}',nonce),'Nonce format')
    require(0<len(data)<=1024**2,'Diagnostic log bounds')
    text=data.decode('ascii')
    require(not any(ord(c)<32 and c not in '\r\n\t' for c in text),'Control characters')
    lines=text.splitlines()
    for key,value in [('COMPOSITION_LOG_VERSION','1'),('BEGIN_NONCE',nonce),('RUN_NONCE',nonce)]:
        require(lines.count(key+'='+value)==1,'Missing/duplicate fresh field '+key)
        require(sum(s.startswith(key+'=') for s in lines)==1,'Contradictory field '+key)
    events=[];event=None;region=None
    for line in lines:
        if '=' not in line:continue
        key,value=line.split('=',1)
        if key=='COMPOSE_STYLE':
            require(value in ('CLASSIC','MODERN'),'Style value')
            event={'style':value,'regions':{}};events.append(event);region=None
        elif key=='COMPOSE_REGION':
            require(event is not None and value in REGIONS,'Unexpected region')
            require(value not in event['regions'],'Duplicate region')
            region={};event['regions'][value]=region
        elif key in INK_FIELDS:
            require(region is not None and key not in region,'Duplicate/orphan ink field')
            require(re.fullmatch('[0-9]{1,10}',value),'Ink number')
            region[key]=int(value)
        elif key in FIELDS:
            require(event is not None and key not in event,'Duplicate/orphan event field')
            if key=='SCREEN_VERDICT':require(value=='DIAGNOSTIC-SAMPLES-ONLY','Screen scope');event[key]=value
            else:require(re.fullmatch('[0-9]{1,10}',value),'Event number');event[key]=int(value)
    require(events,'No actual composition event')
    for e in events:
        require(FIELDS<=e.keys(),'Incomplete event fields')
        require(list(e['regions'])==REGIONS,'Incomplete/ordered region list')
        for v in e['regions'].values():require(INK_FIELDS==v.keys(),'Incomplete ink fields')
        e['offscreen_pixels_verified']=(e['COMPOSE_API_STAGE']==0 and e['MEMORY_VALID']==1 and
            e['MEMORY_BACKGROUND_SAMPLES']==28 and e['MEMORY_BACKGROUND_MISMATCHES']==0 and
            e['MEMORY_READS_INVALID']==0 and e['COMPOSE_CLEANUP_ISSUES']==0 and
            all(v['REFERENCE_INK']>=12 and v['REFERENCE_INK']==v['ACTUAL_INK'] and
                v['TEXT_PIXEL_MISMATCHES']==0 for v in e['regions'].values()))
        require(e['SCREEN_MISMATCHES']+e['SCREEN_READS_INVALID']<=e['SCREEN_SAMPLES'],'Screen count contradiction')
        e['screen_sample_verdict']=('UNAVAILABLE' if e['SCREEN_READS_INVALID'] or not e['SCREEN_SAMPLES'] else
                                   'MISMATCH' if e['SCREEN_MISMATCHES'] else 'MATCHED-SAMPLES-ONLY')
        e['screen_quantization_possible']=e['SCREEN_BPP']<24
    both={e['style'] for e in events}=={'CLASSIC','MODERN'}
    passed=both and all(e['offscreen_pixels_verified'] and e['FULL_SCENE_TRANSFER']==1 for e in events)
    return {'schema':1,'status':'PASS-OFFSCREEN-PIXELS' if passed else 'INCOMPLETE-OR-OFFSCREEN-MISMATCH',
            'nonce':nonce,'both_styles_observed':both,'offscreen_pixels_verified':passed,'events':events,
            'complete_visible_scene_verified':False,'native_process_exit_verified':False,
            'scope':'Actual 32bpp DIB palette samples and complete native text reference masks; destination GetPixel samples and visible screenshot review are separate.'}

def main():
    p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument('--log',type=Path,required=True);p.add_argument('--nonce',required=True);a=p.parse_args()
    data=a.log.read_bytes();result=parse(data,a.nonce);result['log']={'path':str(a.log),'sha256':hashlib.sha256(data).hexdigest()}
    print(json.dumps(result,indent=2));return 0 if result['offscreen_pixels_verified'] else 1
if __name__=='__main__':raise SystemExit(main())
