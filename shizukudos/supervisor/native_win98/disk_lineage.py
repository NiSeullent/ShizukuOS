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


ORIGINAL_FLAGS = (*RUNTIME_FLAGS, 'public_artifact', 'installed_Windows98_version_verified',
                  'drive_mapping_verified', 'native_bootability_verified', 'persistence_verified',
                  'ShizukuCore_userland_verified')
ORIGINAL_SCHEMA = 'shizukuos.private-original-userland-profile.v1'
ORIGINAL_REQUEST_SCHEMA = 'shizukuos.original-userland-profile-request.v1'


def admit_original(raw, pins, selected_disk, expected_producers, *, request_raw):
    """Check an explicitly selected original-userland observation phase.

    This is not DOS replacement or genuine Windows authentication. The caller
    retains and hashes the actual disk, request, profile and producer FDs; its
    unchanged task guardian owns the fresh mutable ESP and QEMU lifetime.
    """
    need(type(raw) in (list, tuple) and type(pins) in (list, tuple) and
         len(raw) == len(pins) == 1, 'one explicit original-userland observation required')
    profile, profile_pin = snapshot(raw[0], pins[0], 4 << 20)
    fields = {'schema', 'status', 'phase', 'source_disk', 'request', 'producer_inputs',
              'boot_policy', 'observed_windows_path', 'observed_members', 'boot_sectors',
              'source_before_after_match', *ORIGINAL_FLAGS}
    need(set(profile) == fields and profile['schema'] == ORIGINAL_SCHEMA and
         profile['status'] == 'ORIGINAL_USERLAND_SOURCE_OBSERVED_NOT_BOOTED' and
         profile['phase'] == 'original-userland-legacy-adapter',
         'exact original-userland phase schema required')
    unverified(profile, ORIGINAL_FLAGS)
    need(profile['source_before_after_match'] is True, 'observed immutable source required')
    disk = pin(selected_disk)
    need(disk['bytes'] == DISK_BYTES and pin(profile['source_disk']) == disk,
         'original phase must select the exact observed original 2GiB disk')
    need(type(expected_producers) in (list, tuple) and len(expected_producers) == 2,
         'two independently held original-phase producer pins required')
    producers = [pin(row, 1 << 20) for row in expected_producers]
    need([PurePosixPath(row['path']).name for row in producers] ==
         ['native_original_userland.py', 'prepare_replacement.py'] and
         profile['producer_inputs'] == producers,
         'original-phase observation producer closure differs')
    request, request_pin = snapshot(request_raw, profile['request'], 1 << 20)
    need(set(request) == {'schema', 'source_disk', 'windows_directory', 'boot_policy', 'producer_inputs'} and
         request['schema'] == ORIGINAL_REQUEST_SCHEMA and request['source_disk'] == disk and
         request['producer_inputs'] == producers and
         request['boot_policy'] == profile['boot_policy'] == 'shz.foundation=win98',
         'original-phase request/source/producer/policy crosslinks differ')
    directory = request['windows_directory']
    need(type(directory) is str and re.fullmatch('[A-Z0-9_-]{1,8}', directory) and
         directory not in {'CON', 'PRN', 'AUX', 'NUL',
                          *[name + str(n) for name in ('COM', 'LPT') for n in range(1, 10)]} and
         profile['observed_windows_path'] == 'C:\\' + directory,
         'explicit observed C: short Windows path required')
    members = profile['observed_members']
    required = {'IO.SYS', 'MSDOS.SYS', 'COMMAND.COM',
                *[directory + '/' + name for name in
                  ('WIN.COM', 'SYSTEM.INI', 'SYSTEM/VMM32.VXD', 'IFSHLP.SYS')]}
    need(type(members) is dict and set(members) == required,
         'exact original boot and Windows member observations required')
    for row in members.values():
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'metadata_sha256', 'cluster'} and
             type(row['bytes']) is int and 0 < row['bytes'] <= DISK_BYTES and
             type(row['cluster']) is int and 2 <= row['cluster'] < DISK_BYTES // 512,
             'exact nonempty regular FAT member observation required')
        sha(row['sha256']); sha(row['metadata_sha256'])
    sectors = profile['boot_sectors']
    need(type(sectors) is dict and set(sectors) == {'mbr', 'vbr'}, 'both original boot-sector observations required')
    for row in sectors.values():
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and
             type(row['bytes']) is int and row['bytes'] == 512,
             'one exact boot-sector observation required')
        sha(row['sha256'])
    paths = [disk['path'], profile_pin['path'], request_pin['path'], *[row['path'] for row in producers]]
    need(len(set(paths)) == len(paths), 'distinct original-phase source/metadata/producer paths required')
    return {'schema': 'shizukuos.private-native-original-userland-lineage.v1',
            'disk_origin': 'private-original-userland-observed-not-booted',
            'phase': profile['phase'], 'source_disk': disk, 'selected_disk': disk,
            'observation_profile': profile_pin, 'request': request_pin,
            'producer_source_pins': producers, 'boot_policy': profile['boot_policy'],
            'observed_windows_path': profile['observed_windows_path'],
            'boot_sectors': copy.deepcopy(sectors), **{name: False for name in ORIGINAL_FLAGS},
            'scope': 'Source observation only; no genuine Windows, boot, replacement, hybrid service or release acceptance.'}


BASE_PAYLOADS = frozenset(('KERNEL.SYS','COMMAND.COM','HIMEMX.EXE','CONFIG.SYS','AUTOEXEC.BAT'))
GOP_PAYLOADS = BASE_PAYLOADS | frozenset(('SHZGOP.DRV','SHZGOP.VXD','SHZGOP.INF'))
CALLER_PAYLOADS = GOP_PAYLOADS | frozenset(('GOPINST.EXE','GPREQ.INI'))
NONCE_PAYLOADS = CALLER_PAYLOADS | frozenset(('SHZGOP/SHZGUARD.VXD','SHZGOP/SHZGOP.VXD',
                                           'SHZGOP/GOPLOAD.EXE','SHZGOP/GPEPOCH.NON'))
COHORT_RECORDS = frozenset(('baseline_profile','gop_stage','gop_profile','caller_stage','caller_profile',
                           'nonce_stage','firstload_build'))


def cohort_payloads(profile, expected):
    need(type(profile) is dict and profile.get('schema') == 'shizukuos.private-replacement-profile.v1',
         'source-linked cohort constructor schema required')
    rows = profile.get('payloads');need(type(rows) is list and len(rows) == len(expected), 'exact cohort extent required')
    result = {}
    for row in rows:
        need(type(row) is dict and set(row) == {'guest','file'} and type(row['guest']) is str and
             row['guest'] in expected and row['guest'] not in result, 'exact unique cohort payload required')
        result[row['guest']] = pin(row['file'],2<<20)
    need(set(result) == expected, 'incomplete exact GOP cohort')
    return result


def derived_profile(before, after, old_names, new_names):
    need(set(before) == set(after) and {k:v for k,v in before.items() if k != 'payloads'} ==
         {k:v for k,v in after.items() if k != 'payloads'}, 'GOP staging changed original launch/source fields')
    original = cohort_payloads(before,old_names);new = cohort_payloads(after,new_names)
    need(all(new[n] == p for n,p in original.items()), 'GOP staging changed a preserved startup/driver payload')
    return new


def admit_cohort(context, final_profile, final_pin, launch_pin):
    """Strict5→8→10→14 metadata chain; current policy comes from live owner.

    This remains pure metadata. The caller must hold every descriptor/source
    and derive live_policy directly from its retained same-process Attempt.
    """
    need(type(context) is dict and set(context) == {'records','producer_pins','live_policy'}, 'exact explicit GOP cohort context')
    records = context['records'];need(type(records) is dict and set(records) == COHORT_RECORDS, 'complete7-record GOP lineage')
    loaded = {}
    for name,row in records.items():
        need(type(row) is dict and set(row) == {'raw','pin'}, 'original cohort snapshot/pin pair required')
        loaded[name] = snapshot(row['raw'],row['pin'],4<<20)
    need(len({p['path'] for _,p in loaded.values()} | {final_pin['path'],launch_pin['path']}) == 9,
         'distinct original cohort receipts/profiles required')
    (base,basepin),(gop,goppin),(gp,gppin),(caller,callerpin),(cp,cppin),(nonce,noncep),(first,firstpin) = (
        loaded[n] for n in ('baseline_profile','gop_stage','gop_profile','caller_stage','caller_profile','nonce_stage','firstload_build'))
    gp_payloads = derived_profile(base,gp,BASE_PAYLOADS,GOP_PAYLOADS)
    cp_payloads = derived_profile(gp,cp,GOP_PAYLOADS,CALLER_PAYLOADS)
    final = derived_profile(cp,final_profile,CALLER_PAYLOADS,NONCE_PAYLOADS)
    producer = context['producer_pins']
    need(type(producer) is dict and set(producer) == {'gop_stage','caller_stage','nonce_stage'}, 'exact3 independent staging producer closures')
    expected_names = {
        'gop_stage':('gop_preinstall_profile.py','win98_source_profile.py','prepare_replacement.py'),
        'caller_stage':('prepare.py','gop_preinstall_profile.py','win98_source_profile.py','prepare_replacement.py','build.py'),
        'nonce_stage':('gop_nonce_staging.py','native_epoch_host.py','prepare_replacement.py')}
    for name,row in (('gop_stage',gop),('caller_stage',caller),('nonce_stage',nonce)):
        pins = producer[name];need(type(pins) is list and len(pins) == len(expected_names[name]), 'exact reviewed producer closure extent')
        for p in pins:pin(p,1<<20)
        need(tuple(PurePosixPath(p['path']).name for p in pins) == expected_names[name] and row.get('producer_inputs') == pins,
             'staging producer differs from independently held source closure')
    need(gop.get('schema') == 'shizukuos.private-gop-preinstall-profile.v1' and
         gop.get('status') == 'PRIVATE_GOP_PAYLOADS_PREPARED_NOT_INSTALLED' and
         gop.get('constructor_profile') == gppin and gop.get('launch_profile') == launch_pin and
         gop.get('staged_payloads') == {n:gp_payloads[n] for n in ('SHZGOP.DRV','SHZGOP.VXD','SHZGOP.INF')},
         'exact source-bound8 GOP staging crosslinks required')
    need(caller.get('schema') == 'shizukuos.private-live-gop-stage.v1' and
         caller.get('status') == 'PRIVATE_CALLER_REQUEST_STAGED_NOT_EXECUTED' and caller.get('source_gop_profile') == goppin and
         caller.get('constructor_profile') == cppin and type(caller.get('utility_payloads')) is list and
         len(caller['utility_payloads']) == 2 and
         {p['guest']:p['file'] for p in caller['utility_payloads']} == {n:cp_payloads[n] for n in ('GOPINST.EXE','GPREQ.INI')},
         'exact source-bound10 caller staging crosslinks required')
    for row in (gop,caller):
        unverified(row,('public_artifact','VM_executed','default_GOP_registered','Windows98_boot_verified','Supervisor_epoch_verified'))
        need((row.get('guardian_epoch_query_opcode'),row.get('guardian_epoch_query_bytes'),row.get('guardian_epoch_HCALL')) ==
             ('0x4f11',160,14), 'actual HC14 epoch160B source cohort required')
    provider = sha(gop.get('live_provider_identity_sha256'))
    need(caller.get('live_provider_identity_sha256') == provider and first.get('gop_provider_identity_sha256') == provider and
         first.get('gop_vxd_sha256') == final['SHZGOP.VXD']['sha256'] and
         first.get('gop_receipt_sha256') == gop.get('gop_receipt',{}).get('sha256'), 'firstload/caller/display provider cohort differs')
    need(first.get('status') == 'PASS_SOURCE_BUILD_NOT_EXECUTED', 'readonly firstload build producer required')
    unverified(first,('guest_executed','default_changed','mode_changed','gpu_active_verified'))
    need(nonce.get('schema') == 'shizukuos.private-gop-nonce-stage.v1' and
         nonce.get('status') == 'PROSPECTIVE_CURRENT_ATTEMPT_STAGED_NOT_GRANTED' and nonce.get('same_process_staging') is True and
         nonce.get('source_live_stage') == callerpin and nonce.get('source_firstload_build') == firstpin and
         nonce.get('source_constructor_profile') == cppin and nonce.get('constructor_profile') == final_pin and
         nonce.get('nonce_payload') == final['SHZGOP/GPEPOCH.NON'] and final['SHZGOP/GPEPOCH.NON']['bytes'] == 32 and
         final['SHZGOP/SHZGOP.VXD'] == final['SHZGOP.VXD'], 'same prospective nonce14 profile crosslinks required')
    for name in ('SHZGUARD.VXD','GOPLOAD.EXE'):
        actual = final['SHZGOP/'+name]
        need(nonce.get('staged_firstload_payloads',{}).get(name) == actual and first.get('artifacts',{}).get(name) ==
             {'bytes':actual['bytes'],'sha256':actual['sha256']}, 'staged firstload artifact differs from exact source producer')
    unverified(nonce,('public_artifact','VM_executed','default_GOP_registered','Windows98_boot_verified','HostGrant_transmitted'))
    policy = context['live_policy']
    need(type(policy) is dict and set(policy) == {'policy_sha256','nonce_sha256','original_host_deadline_ns'}, 'actual retained owner policy binding required')
    sha(policy['policy_sha256']);sha(policy['nonce_sha256'])
    need(type(policy['original_host_deadline_ns']) is int and 0 < policy['original_host_deadline_ns'] < 1<<64 and
         all(nonce.get(k) == v for k,v in policy.items()) and policy['nonce_sha256'] == final['SHZGOP/GPEPOCH.NON']['sha256'],
         'staged disk belongs to another owner policy/nonce/deadline')
    return base,basepin,{'schema':'shizukuos.private-native-gop-cohort-lineage.v1',
        'record_pins':{n:p for n,(_,p) in loaded.items()},'producer_pins':copy.deepcopy(producer),
        'current_policy_binding':copy.deepcopy(policy),'HostGrant_transmitted':False,'Windows98_boot_verified':False,
        'default_GOP_registered':False,'scope':'Prospective preparation binding only; no runtime authority.'}


def admit(raw,pins,selected_disk,expected_producers,*,gop_cohort=None):
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
    baseline,baseline_pin,cohort_proof = (profile,profile_pin,None)
    if gop_cohort is not None:baseline,baseline_pin,cohort_proof = admit_cohort(gop_cohort,profile,profile_pin,launch_pin)
    payloads=baseline['payloads']
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
    need(launch.get('constructor_profile')==baseline_pin and launch.get('source_disk')==original,
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
    return {**({'gop_cohort':cohort_proof} if cohort_proof is not None else {}),'schema':'shizukuos.private-native-disk-lineage.v1',
            'disk_origin':'source-built-private-replacement-prepared-not-booted',
            'constructor_profile':profile_pin,'launch_receipt':launch_pin,'preparation_receipt':prepared_pin,
            'source_disk':original,'replacement_disk':disk,'producer_source_pins':producers,
            'boot_policy':launch['boot_policy'],'observed_windows_path':windows,
            **{name:False for name in (*RUNTIME_FLAGS,'public_artifact','installed_Windows98_version_verified',
                                      'drive_mapping_verified','native_bootability_verified','persistence_verified')},
            'scope':'Pinned preparation metadata only; caller must check real leases, disk bytes and runtime evidence.'}
