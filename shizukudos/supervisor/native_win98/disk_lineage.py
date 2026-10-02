# SPDX-License-Identifier: GPL-2.0-only
"""Private preparation lineage; byte snapshots only, never runtime acceptance.

The caller must acquire/read/check its real input leases and independently check
the selected disk. This pure parser opens no path, runs no producer and supplies
no Windows, replacement-boot, version, drive-mapping or persistence acceptance.
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re

DISK_BYTES=2<<30
LIMITS=(1<<20,4<<20,16<<20)
RUNTIME_FLAGS=('Windows98_boot_verified','MSDOS_replacement_under_Windows98',
               'native_apps_verified','VM_executed')


def need(value,message):
    if not value:raise ValueError(message)


def sha(value):
    need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) and value!='0'*64,
         'literal nonzero lowercase SHA256 required')
    return value


def pin(value,maximum=DISK_BYTES):
    need(isinstance(value,dict) and set(value)=={'path','bytes','sha256'},'exact path/bytes/SHA input pin required')
    path=value['path']
    need(isinstance(path,str) and '\x00' not in path and '\n' not in path and '\r' not in path and
         path.startswith('/') and not path.startswith('//') and str(PurePosixPath(path))==path and '..' not in PurePosixPath(path).parts and
         not any(path==root or path.startswith(root+'/') for root in ('/dev','/proc','/sys')),
         'canonical absolute nonvirtual input pin path required')
    need(type(value['bytes']) is int and 0<value['bytes']<=maximum,'bounded positive regular-file byte extent required')
    sha(value['sha256'])
    return copy.deepcopy(value)


def pairs(rows):
    result={}
    for key,value in rows:
        need(key not in result,'duplicate JSON field refused');result[key]=value
    return result


def snapshot(raw,identity,maximum):
    need(type(raw) is bytes and 0<len(raw)<=maximum,'bounded immutable input byte snapshot required')
    identity=pin(identity,maximum)
    need(identity['bytes']==len(raw) and hashlib.sha256(raw).hexdigest()==identity['sha256'],
         'actual snapshot extent/SHA differs from approved pin')
    try:
        result=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON refused')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as failure:
        raise ValueError('bounded valid JSON object required') from failure
    need(isinstance(result,dict),'JSON receipt object required')
    return result,identity


def unverified(row,names):
    need(all(row.get(name) is False for name in names),'every runtime/publication assertion must be exactly false')


def admit(raw,pins,selected_disk,expected_producers):
    """Admit three explicitly pinned snapshots, returning preparation metadata.

    Order: generated constructor profile, source-profile receipt, constructor
    preparation receipt. Producer pins are the caller's independently approved
    source-profile and constructor source identities; no path is opened here.
    """
    need(isinstance(raw,(list,tuple)) and isinstance(pins,(list,tuple)) and len(raw)==len(pins)==3,
         'exactly three ordered profile/receipt snapshots required')
    loaded=[snapshot(data,identity,limit) for data,identity,limit in zip(raw,pins,LIMITS)]
    (profile,profile_pin),(launch,launch_pin),(prepared,prepared_pin)=loaded
    need(len({row['path'] for _,row in loaded})==3,'three distinct metadata paths required')
    disk=pin(selected_disk)
    need(disk['bytes']==DISK_BYTES,'exact native 2GiB selected disk required')
    need(set(profile)=={'schema','disk','boot_template','freedos_source','build_receipt','build_source_root','payloads'} and
         profile['schema']=='shizukuos.private-replacement-profile.v1','exact constructor profile schema required')
    original=pin(profile['disk'])
    need(original['bytes']==DISK_BYTES and original['path']!=disk['path'] and original['sha256']!=disk['sha256'],
         'replacement disk must differ from its original source identity and bytes')
    dos=pin(profile['build_receipt'],1<<20)
    payloads=profile['payloads']
    need(isinstance(payloads,list) and len(payloads)==5,'five unique launch payloads required')
    names=set()
    for member in payloads:
        need(isinstance(member,dict) and set(member)=={'guest','file'} and isinstance(member['guest'],str) and
             member['guest'] not in names,'exact unique guest payload record required')
        names.add(member['guest']);pin(member['file'],16<<20)
    need(names=={'KERNEL.SYS','COMMAND.COM','HIMEMX.EXE','CONFIG.SYS','AUTOEXEC.BAT'},
         'exact source-generated kernel/shell/XMS/launch payload set required')
    template=profile['boot_template']
    need(isinstance(template,dict) and set(template)=={'kind','file'} and template['kind'] in ('fat12','fat16','fat32lba'),
         'source-built supported boot template required')
    template_pin=pin(template['file'],512);need(template_pin['bytes']==512,'one 512-byte boot template required')
    need(launch.get('schema')=='shizukuos.private-win98-launch-profile.v1' and
         launch.get('status')=='PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED',
         'source-generated launch receipt required')
    unverified(launch,(*RUNTIME_FLAGS,'public_artifact','installed_Windows98_version_verified',
                       'drive_mapping_verified','native_bootability_verified'))
    need(launch.get('constructor_profile')==profile_pin and launch.get('source_disk')==original,
         'launch receipt must bind this exact generated profile and original disk')
    need(launch.get('boot_policy')=='shz.foundation=win98','explicit native Windows foundation policy required')
    windows=launch.get('observed_windows_path')
    need(isinstance(windows,str) and re.fullmatch(r'C:\\[A-Z0-9_-]{1,8}',windows),'explicit observed C: short Windows path required')
    directory=windows[3:]
    need(directory not in {'CON','PRN','AUX','NUL',*[name+str(n) for name in ('COM','LPT') for n in range(1,10)]},
         'DOS device cannot be a Windows path')
    members=launch.get('observed_members')
    required={directory+'/'+name for name in ('WIN.COM','SYSTEM.INI','SYSTEM/VMM32.VXD','IFSHLP.SYS')}
    need(isinstance(members,dict) and required<=set(members) and len(members)<=30000 and
         all(isinstance(name,str) and 0<len(name)<=1024 for name in members),
         'bounded observations containing the four installed Windows members required')
    for row in members.values():
        # The actual FAT producer omits "directory" for regular files; it
        # emits exactly these four fields, unlike its two-field directory row.
        need(isinstance(row,dict) and set(row)=={'bytes','sha256','metadata_sha256','cluster'} and
             type(row['bytes']) is int and 0<row['bytes']<=DISK_BYTES and
             type(row['cluster']) is int and 2<=row['cluster']<DISK_BYTES//512,
             'exact nonempty regular FAT member record required')
        sha(row['sha256']);sha(row['metadata_sha256'])
    need(isinstance(expected_producers,(list,tuple)) and len(expected_producers)==2,
         'two independently approved producer-source pins required')
    producers=[pin(row,1<<20) for row in expected_producers]
    need([PurePosixPath(row['path']).name for row in producers]==['win98_source_profile.py','prepare_replacement.py'] and
         launch.get('producer_inputs')==producers,'exact ordered approved producer source identities required')
    need(prepared.get('schema')=='shizukuos.private-replacement-preparation.v1' and
         prepared.get('status')=='PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED' and
         prepared.get('private_source_disk') is True and prepared.get('source_unchanged') is True,
         'completed private constructor preparation receipt required')
    unverified(prepared,(*RUNTIME_FLAGS,'public_artifact'))
    need(prepared.get('destination')==disk and prepared.get('source_disk')==original and
         prepared.get('profile_sha256')==profile_pin['sha256'] and prepared.get('build_receipt_sha256')==dos['sha256'],
         'constructor output/profile/DOS/original disk crosslinks differ')
    boot=prepared.get('template')
    need(isinstance(boot,dict) and boot.get('kind')==template['kind'] and boot.get('sha256')==template_pin['sha256'] and
         boot.get('kernel_name')=='KERNEL.SYS' and type(boot.get('load_segment')) is int and boot['load_segment']==96 and
         boot.get('actual_BIOS_DL_capture') is True,'source-built kernel boot-template contract required')
    copied=prepared.get('copy')
    need(isinstance(copied,dict) and copied.get('method') in ('explicit-full-copy','mandatory-FICLONE') and
         type(copied.get('bytes')) is int and copied['bytes']==DISK_BYTES and copied.get('sha256')==original['sha256'] and
         copied.get('destination_readback_verified') is True and copied.get('source_lease_preserved') is True,
         'independent complete original-disk copy/readback required')
    for name in ('original_vbr_sha256','replacement_vbr_sha256','original_inventory_sha256'):sha(prepared.get(name))
    need(prepared['original_vbr_sha256']!=prepared['replacement_vbr_sha256'],'replacement VBR must differ from original')
    count,unchanged=prepared.get('existing_members'),prepared.get('unchanged_original_members')
    need(type(count) is int and count>0 and type(unchanged) is int and 0<=unchanged<=count,
         'bounded original-member preservation counts required')
    return {'schema':'shizukuos.private-native-disk-lineage.v1',
            'disk_origin':'source-built-private-replacement-prepared-not-booted',
            'constructor_profile':profile_pin,'launch_receipt':launch_pin,'preparation_receipt':prepared_pin,
            'source_disk':original,'replacement_disk':disk,'producer_source_pins':producers,
            'boot_policy':launch['boot_policy'],'observed_windows_path':windows,
            **{name:False for name in (*RUNTIME_FLAGS,'public_artifact','installed_Windows98_version_verified',
                                      'drive_mapping_verified','native_bootability_verified','persistence_verified')},
            'scope':'Pinned preparation metadata only; caller must check real leases, disk bytes and runtime evidence.'}
