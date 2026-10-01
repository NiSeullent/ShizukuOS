#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate private DOS launch files from an observed installed FAT source."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re

CONSTRUCTOR = Path(__file__).resolve().parents[1]/'win98_boot/prepare_replacement.py'
_spec = importlib.util.spec_from_file_location('source_profile_replacement',CONSTRUCTOR)
replacement = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(replacement)
need = replacement.need
XMS_SHA = '5e0ed027a150ac1c198e994ca248245c07c1f44796bc0791448afbcf29789211'
XMS_COMMITS = {'HimemX':'bbaf6b8951cdac785f1f4e9b67c25439c5bf8e75',
               'JWasm':'7f6f32e78b79565d40bcce496756aadd1ff66900'}
MAKE_CONFIG = 'XNASM=nasm\nundefine XUPX\nALLCFLAGS=-DWIN31SUPPORT\nNASMFLAGS=-DWIN31SUPPORT\n'


def read_json(pin):
    replacement.pin_fields(pin)
    with replacement.leased_inputs([pin]) as held:
        return replacement.bounded_json(held[pin['path']])


def dos_lines(data):
    need(all(v in (9,10,13) or 32<=v<=126 for v in data),'unsupported DOS boot text/control bytes')
    text=data.decode('ascii')
    need('\r' not in text.replace('\r\n',''),'DOS physical LF/CRLF lines required')
    return text.split('\n')


def installed_paths(data, selected):
    """Only the observed ASCII Win98 boot-path section selects this epoch."""
    values, section, seen = {}, '', set()
    for raw in dos_lines(data):
        line = raw.strip()
        if not line or line.startswith(';'): continue
        if line.startswith('['):
            need(re.fullmatch(r'\[[A-Za-z0-9_]+\]',line),'ambiguous MSDOS section')
            section=line[1:-1].upper()
            need(section not in seen,'duplicate MSDOS section');seen.add(section)
        elif section=='PATHS':
            need(line.count('=')==1,'ambiguous MSDOS path record')
            key,value=map(str.strip,line.split('=',1));key=key.upper()
            need(key not in values,'duplicate MSDOS path key');values[key]=value.upper()
    need(values.get('WINDIR')==values.get('WINBOOTDIR')==selected and values.get('HOSTWINBOOTDRV')=='C',
         'observed MSDOS paths must match the selected C: Windows directory')
    return values


def member_bytes(fd, geometry, files, name, check, limit=65536):
    row=files.get(name)
    need(row is not None and not row.get('directory') and row['bytes']<=limit,'bounded source member required: '+name)
    result=io.BytesIO()
    sha=replacement.Volume(fd,geometry,check).file(row['cluster'],row['bytes'],result)
    need(sha==row['sha256'],'source member changed: '+name)
    return result.getvalue()


def require_file(files,name):
    row=files.get(name)
    need(row is not None and not row.get('directory') and row['bytes']>0,'observed installed member missing: '+name)
    return row


def locale_lines(config, auto, windows, files):
    country,nls=[],[]
    country_path='C:\\'+windows+'\\COUNTRY.SYS'
    nls_path='C:\\'+windows+'\\COMMAND\\NLSFUNC.EXE'
    config_physical,auto_physical=dos_lines(config),dos_lines(auto)
    for raw in config_physical:
        line=raw.strip()
        if re.match(r'COUNTRY\b',line,re.I):
            match=re.fullmatch(r'COUNTRY\s*=\s*([0-9]{1,3}),([0-9]{1,5}),([^\s]+)',line,re.I)
            need(match and 0<int(match[1])<1000 and 0<int(match[2])<65536 and match[3].upper()==country_path,
                 'unambiguous observed COUNTRY path/values required')
            require_file(files,windows+'/COUNTRY.SYS');country.append(line)
    for raw in auto_physical:
        line=raw.strip()
        if 'NLSFUNC' in line.upper() and not re.match(r'(?:REM\b|::)',line,re.I):
            match=re.fullmatch(r'(?:LOADHIGH\s+)?([^\s]+)\s+([^\s]+)',line,re.I)
            need(match and match[1].upper()==nls_path and match[2].upper()==country_path,
                 'unambiguous observed NLSFUNC invocation required')
            require_file(files,windows+'/COMMAND/NLSFUNC.EXE');require_file(files,windows+'/COUNTRY.SYS')
            nls.append(line)
    need(len(country)<=1 and len(nls)<=1 and (not country or len(nls)==1),
         'only one observed NLS invocation allowed; COUNTRY requires that invocation')
    if country or nls:
        # Pinned ke2046 config.c and FreeCOM include/command.h use 256-byte
        # readers. CONFIG overflow can expose a suffix as a fresh command.
        # Keep space for newline/terminators; comments count in both files.
        need(all(len(v)<=250 for v in config_physical),'observed CONFIG line exceeds supported FreeDOS physical-line bound')
        need(all(len(v)<=250 for v in auto_physical),'observed batch line exceeds supported FreeCOM physical-line bound')
        config_lines=[v.strip() for v in config_physical if v.strip() and not re.match(r'REM\b|;',v.strip(),re.I)]
        auto_lines=[v.strip().lstrip('@').lstrip() for v in auto_physical
                    if v.strip() and not re.match(r'(?:@?REM\b|::)',v.strip(),re.I)]
        need(not any(v.startswith('[') or re.match(r'(?:INCLUDE|MENUITEM|MENUDEFAULT|SUBMENU)\b',v,re.I) for v in config_lines),
             'conditional CONFIG locale selection is not supported')
        need(not any(v.startswith(':') or re.match(r'(?:IF|GOTO|CALL|FOR|SHIFT|EXIT|CHOICE)\b',v,re.I) or
                     any(c in v for c in '&|<>') for v in auto_lines),
             'conditional batch locale selection is not supported')
        before=auto_lines[:next(i for i,v in enumerate(auto_lines) if v.upper()==nls[0].upper())]
        for line in before:
            need('%' not in line and re.fullmatch(
                r'(?:ECHO\s+(?:ON|OFF)|SET\s+[A-Z_][A-Z0-9_]*=.*|[A-Z]:|(?:CD|CHDIR)\s+[^\s]+|PATH(?:\s*=\s*[^\r\n]*|\s+[^\r\n]*)?)',line,re.I),
                'unproven command or batch transfer before observed NLS invocation')
    return country,nls


def xms_sources(receipt, root, file_pin):
    need(receipt.get('schema')=='shizukudos-cb43-himemx-source-build-v1' and
         file_pin['bytes']==6100 and file_pin['sha256']==XMS_SHA,'known normal source-built HIMEMX required')
    matches=[r for r in receipt.get('artifacts',[]) if r.get('file')=='artifacts/HIMEMX.EXE']
    need(len(matches)==1 and matches[0].get('bytes')==file_pin['bytes'] and matches[0].get('sha256')==file_pin['sha256'],
         'XMS artifact differs from its producer receipt')
    need(receipt.get('source_inputs_frozen_before_build') is True and receipt.get('source_files_unchanged_after_build') is True and
         receipt.get('source_files_changed')==[],'actual XMS source freeze required')
    builds=[r for r in receipt.get('builds',[]) if r.get('name')=='HIMEMX']
    need(len(builds)==1 and type(builds[0].get('exit_code')) is int and builds[0]['exit_code']==0 and
         isinstance(builds[0].get('command'),list) and '-mz' in builds[0]['command'] and
         not any('ALTSTRAT' in str(v).upper() for v in builds[0]['command']),'normal HIMEMX build record required')
    rows=[]
    for name,commit in XMS_COMMITS.items():
        source=receipt.get('source_preimages',{}).get(name,{})
        need(source.get('commit')==receipt.get('acquisitions',{}).get(name,{}).get('commit')==commit,
             'wrong source-built XMS upstream identity')
        files=source.get('files')
        need(isinstance(files,list) and len(files)==source.get('file_count')==({'HimemX':5,'JWasm':268}[name]),
             'complete recorded XMS source list required')
        names=set()
        for row in files:
            need(isinstance(row,dict) and set(row)=={'file','bytes','sha256'} and row['file'] not in names,
                 'unique exact XMS source pin required');names.add(row['file'])
            path=replacement.source_name(row['file'],root/name)
            pin=replacement.recorded_pin(path,row['sha256'])
            need(pin['bytes']==row['bytes'],'recorded XMS source extent differs');rows.append(pin)
    return rows


def write_private(path, data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        at=0
        while at<len(data):
            written=os.write(fd,data[at:]);need(written>0,'short private output write');at+=written
        os.fsync(fd)
    finally:os.close(fd)
    need(path.read_bytes()==data,'private output readback differs')


def publish(path, data):
    temporary=path.with_name('.'+path.name+'.part')
    try:
        write_private(temporary,data);os.link(temporary,path)
    finally:temporary.unlink(missing_ok=True)


def generate(request_path, request_sha, out, capture_budget):
    request_path,out=replacement.safe_path(request_path),replacement.safe_path(out)
    replacement.private_output(out)
    if out.exists():raise FileExistsError(out)
    need(out.parent.is_dir(),'fresh private output parent required')
    replacement.capacity(out.parent,4<<20,capture_budget)
    request_pin=replacement.recorded_pin(request_path,request_sha)
    request=read_json(request_pin)
    need(isinstance(request,dict) and set(request)=={'schema','replacement_profile','drive','windows_directory','boot_policy','xms'} and
         request['schema']=='shizukuos.win98-source-profile-request.v1','exact installed-source request required')
    need(request['drive']=='C' and request['boot_policy']=='shz.foundation=win98','C: native Win98 foundation policy required')
    windows=request['windows_directory']
    need(isinstance(windows,str) and re.fullmatch('[A-Z0-9_-]{1,8}',windows),'one explicit uppercase Windows short directory required')
    need(windows not in {'CON','PRN','AUX','NUL',*[v+str(n) for v in ('COM','LPT') for n in range(1,10)]},
         'DOS device names cannot select a Windows directory')
    selected='C:\\'+windows
    base_pin=request['replacement_profile'];base=read_json(base_pin)
    payloads=base.get('payloads',[]) if isinstance(base,dict) else []
    need(len(payloads)==2 and {r.get('guest') for r in payloads}=={'KERNEL.SYS','COMMAND.COM'},'base profile must contain only kernel and shell')
    # Existing constructor validates source/artifact bindings and assembles the
    # pinned template. No disk/output is created. Its SIGIO context fully closes
    # before this producer admits the same pinned inputs into its own registry.
    validation=replacement.prepare(Path(base_pin['path']),base_pin['sha256'],out,'full',base['disk']['bytes'],capture_budget,validate_only=True)
    xms=request['xms']
    need(isinstance(xms,dict) and set(xms)=={'file','build_receipt','source_root'},'exact XMS producer inputs required')
    root=replacement.safe_path(xms['source_root']);need(root.is_dir(),'actual XMS source root required')
    source=replacement.safe_path(base['freedos_source'])
    kind=base['boot_template']['kind'];assembly='boot32lb.asm' if kind=='fat32lba' else 'boot.asm'
    producer_inputs=[replacement.local_pin(Path(__file__).resolve()),replacement.local_pin(CONSTRUCTOR)]
    rows=[request_pin,base_pin,base['disk'],base['build_receipt'],base['boot_template']['file'],
          *[r['file'] for r in payloads],xms['file'],xms['build_receipt'],
          *validation['build_source_pins'],replacement.local_pin(source/'config.mak'),
          replacement.local_pin(source/'sys/sys.c',replacement.SYS_SHA),
          replacement.local_pin(source/'boot'/assembly,replacement.BOOT_SOURCE_SHA[assembly]),
          replacement.local_pin(source/'boot/magic.mac',replacement.BOOT_SOURCE_SHA['magic.mac']),*producer_inputs]
    with replacement.leased_inputs(rows) as held:
        # Both manifests are re-leased and checked after the constructor phase.
        need(replacement.bounded_json(held[request_pin['path']])==request and replacement.bounded_json(held[base_pin['path']])==base,
             'selected request/profile changed')
        dos=replacement.bounded_json(held[base['build_receipt']['path']]);cfg=dos.get('kernel_make_config',{})
        cfg_pin=held[str(source/'config.mak')]['pin']
        need(cfg.get('text')==MAKE_CONFIG and cfg.get('sha256')==cfg_pin['sha256'] and
             cfg.get('c_defines')==cfg.get('nasm_defines')==['WIN31SUPPORT'] and
             os.pread(held[str(source/'config.mak')]['fd'],cfg_pin['bytes'],0)==MAKE_CONFIG.encode(),
             'recorded C and NASM WIN31SUPPORT configuration required')
        xreceipt=replacement.bounded_json(held[xms['build_receipt']['path']])
        xrows=xms_sources(xreceipt,root,xms['file']);held.add_inputs(xrows)
        disk=held[base['disk']['path']];fd,check=disk['fd'],disk['checkpoint'];geometry=validation['geometry']
        files=replacement.inventory(fd,geometry,check)
        need(len({name.upper() for name in files})==len(files),'case-ambiguous DOS short paths refused')
        observed={}
        for name in ('WIN.COM','SYSTEM.INI','SYSTEM/VMM32.VXD','IFSHLP.SYS'):
            observed[windows+'/'+name]=require_file(files,windows+'/'+name)
        need(files.get(windows+'/SYSTEM',{}).get('directory') is True,'observed Windows SYSTEM directory required')
        installed_paths(member_bytes(fd,geometry,files,'MSDOS.SYS',check),selected)
        original={name:member_bytes(fd,geometry,files,name,check) if name in files else None for name in ('CONFIG.SYS','AUTOEXEC.BAT')}
        country,nls=locale_lines(original['CONFIG.SYS'] or b'',original['AUTOEXEC.BAT'] or b'',windows,files)
        if country or nls:
            for name in ('COUNTRY.SYS','COMMAND/NLSFUNC.EXE'):
                observed[windows+'/'+name]=require_file(files,windows+'/'+name)
        config=('DEVICE=C:\\HIMEMX.EXE /VERBOSE\r\nDEVICE='+selected+'\\IFSHLP.SYS\r\nDOS=HIGH\r\n'
                'FILES=30\r\nBUFFERS=20\r\nSHELL=C:\\COMMAND.COM C:\\ /E:512 /P\r\n'+''.join(v+'\r\n' for v in country)).encode('ascii')
        auto=('@ECHO OFF\r\nSET COMSPEC=C:\\COMMAND.COM\r\nSET windir='+selected+'\r\n'
              'SET PATH='+selected+';'+selected+'\\COMMAND;C:\\\r\nC:\r\nCD \\'+windows+'\r\n'+
              ''.join(v+'\r\n' for v in nls)+selected+'\\WIN.COM\r\n').encode('ascii')
        replacement.capacity(out.parent,4<<20,capture_budget);out.mkdir(mode=0o700)
        backups=out/'original-config';backups.mkdir(mode=0o700)
        stage=out/'payloads';stage.mkdir(mode=0o700)
        backup_pins=[]
        for name,data in original.items():
            if data is not None:
                write_private(backups/name,data)
                # Empty original files remain exact readback-backed observations;
                # the constructor's nonempty input pin schema stays unchanged.
                need((backups/name).read_bytes()==data,'original configuration backup differs')
                if data:backup_pins.append({'path':str(backups/name),'bytes':len(data),'sha256':replacement.digest(data)})
        generated={'CONFIG.SYS':config,'AUTOEXEC.BAT':auto}
        for name,data in generated.items():write_private(stage/name,data)
        generated_pins={name:{'path':str(stage/name),'bytes':len(data),'sha256':replacement.digest(data)}
                        for name,data in generated.items()}
        # Hashes come from the selected launch text, never from whatever a writer
        # leaves at its output pathname. Keep actual leases through final exit.
        held.add_inputs([*backup_pins,*generated_pins.values()])
        profile=dict(base,payloads=[*payloads,{'guest':'HIMEMX.EXE','file':xms['file']},
                                  *[{'guest':name,'file':generated_pins[name]} for name in generated]])
        result={'schema':'shizukuos.private-win98-launch-profile.v1','status':'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED',
                'public_artifact':False,'Windows98_boot_verified':False,'installed_Windows98_version_verified':False,
                'MSDOS_replacement_under_Windows98':False,'native_apps_verified':False,'VM_executed':False,
                'drive_mapping_verified':False,'native_bootability_verified':False,
                'boot_policy':request['boot_policy'],'observed_windows_path':selected,
                'source_disk':base['disk'],'request':request_pin,'base_profile':base_pin,'producer_inputs':producer_inputs,
                'observed_members':observed,
                'MSDOS.SYS_observation':files['MSDOS.SYS'],
                'original_config':{name:{'present':data is not None,**({'bytes':len(data),'sha256':replacement.digest(data),
                    'source_metadata_sha256':files[name]['metadata_sha256']} if data is not None else {})} for name,data in original.items()},
                'locale':{'country':country,'nls':nls},'xms_receipt':xms['build_receipt'],'xms_sources':xrows,
                'constructor_input_validation':validation,
                'limitations':['Observed files/paths are not Windows version or native boot evidence.',
                               'Original driver/startup commands are retained as backups, not executed or replayed.',
                               'This producer does not install an ESP or configure Supervisor/K32/K64 workers.']}
        need(replacement.hash_fd(fd,base['disk']['bytes'],check)==base['disk']['sha256'],'original disk changed')
        for name,data in original.items():
            if data is not None:need((backups/name).read_bytes()==data,'late original configuration backup drift')
        for entry in held.values():entry['checkpoint']()
    # A lease break at final context exit cannot leave a usable profile.
    profile_path,receipt_path=out/'replacement-profile.json',out/'source-profile.json'
    profile_bytes=(json.dumps(profile,indent=2)+'\n').encode()
    profile_pin={'path':str(profile_path),'bytes':len(profile_bytes),'sha256':replacement.digest(profile_bytes)}
    result['constructor_profile']=profile_pin
    receipt_bytes=(json.dumps(result,indent=2)+'\n').encode()
    need(len(receipt_bytes)<=4<<20,'bounded producer receipt required')
    receipt_pin={'path':str(receipt_path),'bytes':len(receipt_bytes),'sha256':replacement.digest(receipt_bytes)}
    replacement.capacity(out,len(profile_bytes)+len(receipt_bytes)+(1<<20),capture_budget)
    try:
        # The usable constructor profile is last; each pin is derived from the
        # intended serialization. A failed publish/readback/lease removes both.
        publish(receipt_path,receipt_bytes);publish(profile_path,profile_bytes)
        with replacement.leased_inputs([receipt_pin,profile_pin]):pass
    except BaseException:
        profile_path.unlink(missing_ok=True);receipt_path.unlink(missing_ok=True)
        raise
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--request',type=Path,required=True);ap.add_argument('--request-sha256',required=True)
    ap.add_argument('--out',type=Path,required=True);ap.add_argument('--capture-budget-bytes',type=int,required=True)
    args=ap.parse_args();result=generate(args.request,args.request_sha256,args.out,args.capture_budget_bytes)
    print(json.dumps({'status':result['status'],'constructor_profile':result['constructor_profile'],'Windows98_boot_verified':False}))


if __name__=='__main__':main()
