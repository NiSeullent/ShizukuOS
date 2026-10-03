# SPDX-License-Identifier: GPL-2.0-only
"""Pre-exec GOP cohort producer borrowing the guardian's original lease union.

No CLI accepts a saved nonce or grant receipt. The same source-admitted epoch
module and live Attempt must remain in the guardian until exact child reap.
This producer does not create a HostGrant or attest guest execution.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import types

BASE = frozenset(('KERNEL.SYS','COMMAND.COM','HIMEMX.EXE','CONFIG.SYS','AUTOEXEC.BAT',
                  'SHZGOP.DRV','SHZGOP.VXD','SHZGOP.INF','GOPINST.EXE','GPREQ.INI'))
FIRSTLOAD_SOURCES = frozenset('drivers/shizuku_gop/first_load/'+n for n in
    ('build.py','control.asm','contract.h','guard.c','loader.c','link.ld')) | frozenset((
    'drivers/shizuku_gop/gop_contract.h','ntwrapper/vxd/le.py','shizukudos/abi/shz_abi.h'))


def need(ok, message):
    if not ok:raise ValueError(message)


def read(held, pin, replacement, maximum=2<<20):
    replacement.pin_fields(pin)
    need(pin['bytes'] <= maximum, 'bounded original staged input required')
    entry = held[pin['path']];need(entry['pin'] == pin, 'exact borrowed original pin required')
    entry['checkpoint']();raw = os.pread(entry['fd'],pin['bytes']+1,0)
    need(len(raw) == pin['bytes'] and replacement.digest(raw) == pin['sha256'], 'borrowed original bytes differ')
    entry['checkpoint']();return raw


def metadata(held,pin,replacement):
    return json.loads(read(held,pin,replacement),object_pairs_hook=replacement.json_pairs)


def borrowed_registry(union, replacement, guard):
    """Adapt one source-admitted guardian union; never reopen or close inputs."""
    need(callable(guard), 'actual task guard required')
    entries = replacement.LeaseRegistry()
    def add(rows):
        guard()
        for pin in rows:
            source = union.add(pin)
            need(source['pin'] == pin and source.get('full_SHA_admitted') is True,
                 'original guardian full-SHA admission required')
            entries[pin['path']] = {**source,'checkpoint':guard}
        guard()
    entries.add_inputs = add
    return entries


def compose(profile, live, firstload, artifacts, nonce_pin, replacement):
    """Pure shape/binding checks only; this does not admit a saved nonce."""
    profile = copy.deepcopy(profile)
    need(type(profile) is dict and set(profile) == {'schema','disk','boot_template','freedos_source',
         'build_receipt','build_source_root','payloads'} and
         profile['schema'] == 'shizukuos.private-replacement-profile.v1', 'exact constructor profile required')
    need(type(profile['payloads']) is list and len(profile['payloads']) == 10 and
         all(type(p) is dict and set(p) == {'guest','file'} for p in profile['payloads']) and
         {p['guest'] for p in profile['payloads']} == BASE, 'exact source-bound10 caller/GOP profile required')
    replacement.payload_names(profile['payloads'])
    need(live.get('schema') == 'shizukuos.private-live-gop-stage.v1' and
         live.get('status') == 'PRIVATE_CALLER_REQUEST_STAGED_NOT_EXECUTED' and
         all(live.get(k) is False for k in ('public_artifact','VM_executed','default_GOP_registered','GPU_active',
             'Windows98_boot_verified','Supervisor_epoch_verified')), 'actual nonexecuted caller producer required')
    need((live.get('guardian_epoch_query_opcode'),live.get('guardian_epoch_query_bytes'),live.get('guardian_epoch_HCALL')) ==
         ('0x4f11',160,14), 'actual HC14 epoch160B caller required')
    need(firstload.get('status') == 'PASS_SOURCE_BUILD_NOT_EXECUTED' and
         all(firstload.get(k) is False for k in ('guest_executed','default_changed','mode_changed','gpu_active_verified')),
         'actual readonly firstload producer required')
    need(set(artifacts) == {'SHZGUARD.VXD','GOPLOAD.EXE'}, 'exact readonly firstload artifacts required')
    target = next(p['file'] for p in profile['payloads'] if p['guest'] == 'SHZGOP.VXD')
    need(firstload.get('gop_provider_identity_sha256') == live.get('live_provider_identity_sha256') and
         firstload.get('gop_vxd_sha256') == target['sha256'], 'firstload producer belongs to a different GOP cohort')
    for name,pin in artifacts.items():
        replacement.pin_fields(pin)
        need(firstload.get('artifacts',{}).get(name) == {'bytes':pin['bytes'],'sha256':pin['sha256']},
             'firstload artifact differs from actual producer')
    replacement.pin_fields(nonce_pin);need(nonce_pin['bytes'] == 32, 'exact nonce32B required')
    profile['payloads'] += [{'guest':'SHZGOP/'+name,'file':pin} for name,pin in artifacts.items()]
    profile['payloads'] += [{'guest':'SHZGOP/SHZGOP.VXD','file':target},
                           {'guest':'SHZGOP/GPEPOCH.NON','file':nonce_pin}]
    replacement.payload_names(profile['payloads']);return profile


def stage(attempt, epoch, replacement, held, live_pin, firstload_pin, repo, out, guard, capture_budget):
    """Borrow exact source modules/leases; no nested SIGIO handler or input reopen.

    The guardian admits epoch/replacement/this module from held source bytes
    before calling. `held.add_inputs` extends that single same-process union.
    Failure consumes staging and publishes no successful constructor profile.
    """
    need(type(attempt) is epoch.Attempt and callable(guard), 'actual admitted live Attempt and owner guard required')
    repo = replacement.safe_path(repo)
    expected_epoch = repo/'shizukudos/supervisor/native_win98/native_epoch_host.py'
    need(Path(epoch.__file__) == expected_epoch and
         Path(replacement.__file__) == repo/'shizukudos/win98_boot/prepare_replacement.py' and
         Path(__file__) == repo/'shizukudos/supervisor/native_win98/gop_nonce_staging.py',
         'actual guardian workspace module origins required')
    own = [replacement.local_pin(p) for p in (Path(__file__),expected_epoch,Path(replacement.__file__))]
    held.add_inputs(own);guard()
    compiled = compile(read(held,own[1],replacement),str(expected_epoch),'exec',dont_inherit=True)
    classes = [c for c in compiled.co_consts if type(c) is types.CodeType and c.co_name == 'Attempt']
    need(len(classes) == 1, 'unique held live Attempt class required')
    methods = {c.co_name:c for c in classes[0].co_consts if type(c) is types.CodeType}
    for name in ('__init__','check','reserve_staging','close'):
        actual = getattr(type(attempt),name)
        need(hasattr(actual,'__code__') and actual.__code__ == methods.get(name) and
             actual.__code__.co_filename == str(expected_epoch), 'live Attempt method differs from held source')
    guard();claim = attempt.reserve_staging();attempt.check()
    out = replacement.safe_path(out);replacement.private_output(out)
    need(not out.exists() and out.parent.is_dir(), 'fresh private nonce staging directory required')
    def check():
        guard();attempt.check()
        need(attempt.staging_claim is claim and attempt.owner is None and not attempt.consumed,
             'same prospective pre-exec Attempt must remain held')
    held.add_inputs([live_pin,firstload_pin]);check()
    live = metadata(held,live_pin,replacement);first = metadata(held,firstload_pin,replacement)
    profile_pin = live['constructor_profile'];held.add_inputs([profile_pin])
    profile = metadata(held,profile_pin,replacement)
    sources = first.get('sources_sha256')
    need(type(sources) is dict and set(sources) == FIRSTLOAD_SOURCES, 'exact firstload source closure required')
    source_rows = []
    base = Path(firstload_pin['path']).parent
    for name,sha in sources.items():
        source_rows += [replacement.recorded_pin(replacement.source_name(name,repo),sha),
                        replacement.recorded_pin(replacement.source_name(name,base/'source'),sha)]
    tools = first.get('tools')
    need(type(tools) is dict and set(tools) == {'nasm','clang','ld','i686-w64-mingw32-gcc'},
         'exact firstload tool closure required')
    for tool in tools.values():
        need(type(tool) is dict and set(tool) == {'path','sha256'}, 'literal original executable pin required')
        source_rows.append(replacement.recorded_pin(tool['path'],tool['sha256']))
    source_rows += live.get('producer_inputs',[])
    need(type(live.get('producer_inputs')) is list and len(live['producer_inputs']) == 5,
         'exact actual live staging producer closure required')
    artifacts = {n:{'path':str(base/n),**first['artifacts'][n]} for n in ('SHZGUARD.VXD','GOPLOAD.EXE')}
    rows = [*source_rows,*artifacts.values(),*[p['file'] for p in profile['payloads']],live['source_gop_profile']]
    held.add_inputs(rows);check()
    source_gop = metadata(held,live['source_gop_profile'],replacement)
    need(first.get('gop_receipt_sha256') == source_gop.get('gop_receipt',{}).get('sha256') and
         source_gop.get('live_provider_identity_sha256') == live.get('live_provider_identity_sha256'),
         'firstload compiled against a different original GOP receipt')
    identity = hashlib.sha256()
    for name in sorted(sources):
        source_pin = next(p for p in source_rows if p['path'] == str(repo/name))
        raw = read(held,source_pin,replacement)
        identity.update(name.encode()+b'\0'+len(raw).to_bytes(8,'little')+raw)
    provider = identity.digest()
    need(first.get('provider_identity_sha256') == provider.hex(), 'firstload provider differs from held source implementation')
    raw_artifacts = {}
    for name,pin in artifacts.items():
        raw = read(held,pin,replacement)
        need(len(raw)>=64 and raw[:2] == b'MZ', 'real firstload executable required')
        at = struct.unpack_from('<I',raw,60)[0]
        need(at >=64 and at+2 <=len(raw) and raw[at:at+2] == (b'LE' if name.endswith('.VXD') else b'PE'),
             'real Win9x firstload executable format required')
        raw_artifacts[name] = raw
    target_pin = next(p['file'] for p in profile['payloads'] if p['guest'] == 'SHZGOP.VXD')
    target_raw = read(held,target_pin,replacement)
    need(provider in raw_artifacts['SHZGUARD.VXD'] and provider in raw_artifacts['GOPLOAD.EXE'] and
         raw_artifacts['SHZGUARD.VXD'] in raw_artifacts['GOPLOAD.EXE'] and target_raw in raw_artifacts['GOPLOAD.EXE'],
         'actual loader lacks full source-bound guard/target byte arrays')
    # Pure validation BEFORE creating any file. Nonce bytes come only from this
    # live sealed Attempt; metadata digests never supply runtime authority.
    nonce_pin = {'path':str(out/'GPEPOCH.NON'),'bytes':32,'sha256':replacement.digest(attempt.nonce)}
    compose(profile,live,first,artifacts,nonce_pin,replacement)
    replacement.capacity(out.parent,sum(len(b) for b in raw_artifacts.values())+(4<<20),capture_budget)
    check();out.mkdir(mode=0o700);owned = out.stat();owned = (owned.st_dev,owned.st_ino)
    def write(name,raw):
        fd = os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            need(os.write(fd,raw) == len(raw), 'complete private payload write required');os.fsync(fd)
        finally:os.close(fd)
    try:
        write('GPEPOCH.NON',attempt.nonce)
        for name,raw in raw_artifacts.items():write(name,raw)
        staged = {n:replacement.local_pin(out/n) for n in raw_artifacts}
        held.add_inputs([nonce_pin,*staged.values()]);check()
        need(read(held,nonce_pin,replacement) == attempt.nonce, 'current live Attempt nonce readback differs')
        derived = compose(profile,live,first,staged,nonce_pin,replacement)
        raw = (json.dumps(derived,indent=2)+'\n').encode();pin = {'path':str(out/'replacement-profile.json'),
              'bytes':len(raw),'sha256':replacement.digest(raw)}
        result = {'schema':'shizukuos.private-gop-nonce-stage.v1','status':'PROSPECTIVE_CURRENT_ATTEMPT_STAGED_NOT_GRANTED',
            'source_live_stage':live_pin,'source_firstload_build':firstload_pin,'constructor_profile':pin,
            'source_constructor_profile':profile_pin,'nonce_payload':nonce_pin,'staged_firstload_payloads':staged,
            'producer_inputs':own,'recorded_source_pins':source_rows,'original_host_deadline_ns':attempt.original_deadline_ns,
            'policy_sha256':replacement.digest(attempt.policy),'nonce_sha256':nonce_pin['sha256'],
            'same_process_staging':True,'HostGrant_transmitted':False,'VM_executed':False,'default_GOP_registered':False,
            'Windows98_boot_verified':False,'public_artifact':False}
        check();write('stage-result.json',(json.dumps(result,indent=2)+'\n').encode());write('replacement-profile.json',raw)
        held.add_inputs([pin,replacement.local_pin(out/'stage-result.json')]);check()
        for entry in held.values():entry['checkpoint']()
        return result
    except BaseException:
        st = out.stat(follow_symlinks=False)
        if (st.st_dev,st.st_ino) == owned:
            for name in ('replacement-profile.json','stage-result.json'):(out/name).unlink(missing_ok=True)
        raise
