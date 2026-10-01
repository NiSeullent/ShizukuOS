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
FOREGROUND_FIELDS = {'FOREGROUND_STYLE','FOREGROUND_SWITCH','FOREGROUND_OWNED','FOREGROUND_VISIBLE',
                     'FOREGROUND_REQUESTED','FOREGROUND_API_RETURN','FOREGROUND_MATCH','FOREGROUND_VERDICT'}

def require(value, message):
    if not value:
        raise ValueError(message)

def parse_foreground(lines):
    records=[];record=None
    headers=[line for line in lines if line.startswith('FOREGROUND_LOG_VERSION=')]
    if not headers:
        require(not any(line.startswith('FOREGROUND_') for line in lines),'Missing foreground version')
        return {'observed':False,'records':[],'complete_visible_scene_verified':False}
    require(headers==['FOREGROUND_LOG_VERSION=1'],'Foreground version')
    for line in lines:
        if '=' not in line:continue
        key,value=line.split('=',1)
        if key=='FOREGROUND_TRIGGER':
            require(value in ('STYLE-SWITCH','INITIAL-SHOWN'),'Foreground trigger')
            record={'trigger':value};records.append(record)
        elif key in FOREGROUND_FIELDS:
            require(record is not None and key not in record,'Duplicate/orphan foreground field')
            if key=='FOREGROUND_STYLE':require(value in ('CLASSIC','MODERN'),'Foreground style');record[key]=value
            elif key=='FOREGROUND_VERDICT':require(value=='DIAGNOSTIC-ONLY','Foreground scope');record[key]=value
            elif key=='FOREGROUND_SWITCH':require(re.fullmatch('[1-9][0-9]{0,9}',value),'Foreground switch');record[key]=int(value)
            else:require(value in ('0','1'),'Foreground Boolean');record[key]=int(value)
    require(records,'Missing foreground records')
    for record in records:
        require(FOREGROUND_FIELDS<=record.keys(),'Incomplete foreground fields')
        owned,visible,requested=(record[k] for k in ['FOREGROUND_OWNED','FOREGROUND_VISIBLE','FOREGROUND_REQUESTED'])
        require(not visible or owned,'Foreign visible handle')
        require(requested==int(bool(owned and visible)),'Foreground request ownership/visibility contradiction')
        require(requested or not (record['FOREGROUND_API_RETURN'] or record['FOREGROUND_MATCH']),'Unrequested foreground result')
    return {'observed':True,'records':records,'complete_visible_scene_verified':False,
            'scope':'Own visible-window requests and instantaneous foreground-handle equality; no complete scene or lasting focus proof.'}

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
            'foreground':parse_foreground(lines),
            'complete_visible_scene_verified':False,'native_process_exit_verified':False,
            'scope':'Actual 32bpp DIB palette samples and complete native text reference masks; destination GetPixel samples and visible screenshot review are separate.'}

def main():
    p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument('--log',type=Path,required=True);p.add_argument('--nonce',required=True);a=p.parse_args()
    data=a.log.read_bytes();result=parse(data,a.nonce);result['log']={'path':str(a.log),'sha256':hashlib.sha256(data).hexdigest()}
    print(json.dumps(result,indent=2));return 0 if result['offscreen_pixels_verified'] else 1
if __name__=='__main__':raise SystemExit(main())
