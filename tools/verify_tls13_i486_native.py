#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only actual Win98 acceptance of the corrected offline TLS DLL pair."""
import sys
sys.dont_write_bytecode=True
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

ROOT = Path(__file__).resolve().parents[1]
BOOT = Path('/root/Win98-Modern-boot')
RUNS = BOOT / 'build/shizukudos/csm'
STAGE = BOOT / 'build/tls13-i486-native-5abe-20261001-v1'
NONCE = 'tls13-i486-5abe-20261001-v1'
PREFIX = 'C:\\GOPLAB\\'
LIMIT = 16 << 20
LOG_LIMIT = 65536
RUN_NAME = r'run-win98-gop-tls13-i486-5abe-native-v[1-9][0-9]{0,3}'
MANIFEST_SHA = 'e0c7af02378c03edd1e6a21d00787964ee9b6b20cb8d28d2f646f7191fed9632'
AUTHORITY_SHA = 'ad368edb18594c5b9a12823655eb9d8ebd13a28c814519996af6e1b14687c852'
PROVENANCE_SHA = '3776c62a6bcb80548263e664508aa38df08eea1892a5f7c8dc7253e99557f634'
HARNESS_SHA = '5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857'
HELPER_SHA = 'ba9eb7542b099b81a43f75c474602a27a14d6ee9b2f14f9c526a8da2c6d1ef92'
ORIGINAL_SHA = 'a2a696ef416060eca4ee6a381dd5cf6ba38edce9183d0eef1ad99c1b89066226'
MEDIA = {
 '/root/Win98-Modern/build/win98-lab/install-packed-z_kei9n1.qcow2.xz': '0c15c1a7b266599eb1834c9c02f87ee9c1d007a6d2b52e4207b5b89df8ee00d8',
 '/root/Win98-Modern/build/win98-lab/install-packed-current.json': 'd3df8220cde1564ed466567ff28c46dec7e2c9b223c50f8898afd7a28bfd0fd5',
}
SOURCES = ('tools/verify_tls13_i486_native.py', 'tests/test_tls13_i486_native.py',
           'docs/TLS13_I486_NATIVE_EVIDENCE.md')
DEPENDENCIES = {
 ROOT / 'tools/tls13_i486_native_stage_evidence.py': HELPER_SHA,
 ROOT / 'tools/verify_tls13_guest_evidence.py': ORIGINAL_SHA,
 ROOT / 'tests/m98_tls13_guest_interop.c': '840f0c02780e45a44204bcf36051e7d7ca2697c06d10ac8ac40906a743fbc13e',
 ROOT / 'tests/m98_tls13_guest_runner.c': '9be9086ee1fd92a2aba97eefa8b92322aa3f3f4f9609ac9dc54629c83327a27f',
 BOOT / 'shizukudos/csm/test_win98_uefi.py': HARNESS_SHA,
}
CHECKS = (
 'WIN98_IDENTIFIED','LOAD_BOTH_DLLS_AND_9_13_EXPORTS','FIXTURES_LOADED',
 'NATIVE_CRYPTOAPI_CSPRNG','NATIVE_UTC_VALID','INDEPENDENT_SERVER_PSA_NATIVE_INIT',
 'ENTROPY_ZERO_REJECTED','ENTROPY_MINUS1_REJECTED','ENTROPY_TWO_REJECTED',
 'LATE_ENTROPY_FAILURE_DENIED','PAIR_CREATE','TLS13_HANDSHAKE_BOTH_DLLS',
 'AUTHENTICATED_BIDIRECTIONAL_PAYLOAD','BOUNDED_PARTIAL_IO_WANT_RETRIES',
 'AUTHENTICATED_CLOSE_NOTIFY','WRITE_AFTER_CLOSE_DENIED',
 'WRONG_HOST_REJECTED_WITHOUT_PLAINTEXT','UNTRUSTED_CA_REJECTED_WITHOUT_PLAINTEXT',
 'LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT','SERVER_RUNTIME_SHUTDOWN',
 'CRYPTOAPI_PROVIDER_RELEASED','SERVER_DLL_UNLOADED','CLIENT_DLL_UNLOADED','CRYPTOAPI_DLL_UNLOADED')
DIAGNOSTICS = ('POSITIVE_CLIENT_STATUS','POSITIVE_SERVER_STATUS','POSITIVE_CLIENT_ESTABLISHED',
 'POSITIVE_CLIENT_BACKEND_ERROR','POSITIVE_SERVER_BACKEND_ERROR','POSITIVE_CLIENT_VERIFY_FLAGS',
 'POSITIVE_SERVER_VERIFY_FLAGS','POSITIVE_SERVER_VERSION','CLIENT_CERTIFICATE_AUTHENTICATION')
NATIVE_ORDER = ('NONCE','CLIENT_SHA256','SERVER_SHA256','SCOPE',CHECKS[0],
 'CLIENT_PATH','SERVER_PATH',*CHECKS[1:4],'UNIX_TIME',*CHECKS[4:11],*DIAGNOSTICS,
 *CHECKS[11:],'CHECKS','FAILURES','FINAL','REQUESTED_EXIT')
OBSERVER_ORDER = ('scope','nonce','WIN98_IDENTIFIED','os.major','os.minor','os.build-low','os.platform',
 'child.path','child.stdout','child.created','child.create-error','child.pid','child.wait',
 'child.exit-query','child.exit-query-error','child.exit-code','child.stdout-flushed',
 'child.handles-closed','child.success','supervisor.requested-exit-code')
INPUTS = frozenset(('TLSDLL.EXE','T13RUN.EXE','M98TLS13.DLL','M98TLS.DLL','CA.PEM','SRV.PEM','SRV.KEY','BADCA.PEM'))
OUTPUTS = frozenset(('TLSDLL.LOG','T13RUN.LOG','TLSOUT.LOG'))
FALSE_SCOPE = dict(actual_supervisor_exit_verified=False, client_certificate_authentication_verified=False,
 guest_code_page_verified=False, native_paint_verified=False, physical_input_verified=False,
 system_tls_verified=False, winsock_verified=False, network_transport_verified=False,
 application_functionality_verified=False, full_browser_verified=False, full_html5_verified=False,
 full_javascript_verified=False, full_css_verified=False, modern_wasm_verified=False,
 webgpu_verified=False, webgl_verified=False, user_objective_complete=False,
 large_original_media_independently_rehashed=False, external_tool_and_header_complete_closure=False,
 vm_operations=False, network_operations=False, global_install=False)


def require(ok, message):
    if not ok: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def pin(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value), 'full SHA256 pin required')
    return value


def equal(a,b):
    if type(a) is not type(b): return False
    if isinstance(b,dict): return set(a)==set(b) and all(equal(a[k],v) for k,v in b.items())
    if isinstance(b,list): return len(a)==len(b) and all(equal(x,y) for x,y in zip(a,b))
    return a==b


def canonical(value):
    require(isinstance(value,(str,Path)), 'canonical path required')
    p=Path(value)
    require(p.is_absolute() and str(p)==str(value) and str(p)==os.path.normpath(str(p)) and
            p.resolve(strict=True)==p, 'canonical non-symlink path required')
    return p


def raw_file(value,limit=LIMIT):
    p=canonical(value);require(type(limit) is int and 0<=limit<=LIMIT,'bounded read required')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=limit,'bounded regular evidence required')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(limit+1)
        after=os.fstat(fd);now=p.stat(follow_symlinks=False)
        fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode')
        require(len(raw)==before.st_size and p.resolve(strict=True)==p and
                all(getattr(before,k)==getattr(after,k)==getattr(now,k) for k in fields),'file changed while reading')
        return raw,tuple(getattr(now,k) for k in fields)
    finally: os.close(fd)


def object_json(raw):
    def pairs(rows):
        out={}
        for k,v in rows:
            require(k not in out,'duplicate JSON key');out[k]=v
        return out
    def nonfinite(_): raise ValueError('nonfinite JSON')
    result=json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite)
    require(type(result) is dict,'JSON object required');return result


class Ledger:
    def __init__(self): self.files={}
    def take(self,path,expected=None,limit=LIMIT,group=1):
        path=canonical(path);raw,_=raw_file(path,limit);h=sha(raw)
        require(expected is None or h==pin(expected),'consumed file SHA mismatch: '+str(path))
        old=self.files.get(str(path))
        require(old is None or old['sha256']==h and old['bytes']==len(raw),'mixed consumed file generation')
        self.files[str(path)]=dict(sha256=h,bytes=len(raw),limit=min(limit,old['limit']) if old else limit,
                                  group=max(group,old['group']) if old else group)
        return raw
    def final_rehash(self):
        stamps={}
        # Bulk stage proof first; small native logs and the harness receipt last.
        for p,row in sorted(self.files.items(),key=lambda x:(x[1]['group'],x[0])):
            raw,stamp=raw_file(Path(p),row['limit'])
            require(sha(raw)==row['sha256'] and len(raw)==row['bytes'],'final consumed file drift: '+p)
            stamps[p]=stamp
        self.final_stamps(stamps)
        return stamps
    def final_stamps(self,stamps):
        require(set(stamps)==set(self.files),'complete final consumed snapshot required')
        fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode')
        for p,stamp in stamps.items():
            now=Path(p).stat(follow_symlinks=False)
            require(Path(p).resolve(strict=True)==Path(p) and tuple(getattr(now,k) for k in fields)==stamp,
                    'file drift during final ledger: '+p)


def records(rows,guests):
    require(type(rows) is list and len(rows)==len(guests),'exact bounded guest records required')
    out={}
    for row in rows:
        require(type(row) is dict and type(row.get('guest')) is str and row['guest'] not in out,'duplicate/bad guest record')
        out[row['guest']]=row
    require(set(out)==guests,'wrong guest record set');return out


def log_pairs(raw):
    require(type(raw) is bytes and 0<len(raw)<=LOG_LIMIT and raw.endswith(b'\r\n'),'bounded complete CRLF native log required')
    try: text=raw.decode('ascii')
    except UnicodeDecodeError as error: raise ValueError('ASCII native log required') from error
    out={}
    for line in text[:-2].split('\r\n'):
        require(0<len(line)<=512 and '\r' not in line and '\n' not in line and '=' in line,'malformed native line')
        key,value=line.split('=',1)
        require(re.fullmatch('[A-Za-z0-9_.-]+',key) and key not in out and
                all(32<=ord(c)<=126 for c in value),'duplicate/invalid native key/value')
        out[key]=value
    return out


def decimal(value,maximum=0xffffffff,minimum=0):
    require(type(value) is str and re.fullmatch('0|[1-9][0-9]{0,9}',value),'canonical unsigned decimal required')
    n=int(value);require(minimum<=n<=maximum,'native numeric bound');return n


def native_protocol(raw,nonce,client_sha,server_sha):
    got=log_pairs(raw);require(tuple(got)==NATIVE_ORDER,'exact original native protocol order/catalog required')
    expected={n:'PASS' for n in CHECKS}
    expected.update(NONCE=nonce,CLIENT_SHA256=pin(client_sha),SERVER_SHA256=pin(server_sha),
        SCOPE='Native DLL interoperability; offline queues; no OS networking',CLIENT_PATH=PREFIX+'M98TLS13.DLL',
        SERVER_PATH=PREFIX+'M98TLS.DLL',CHECKS='24',FAILURES='0',FINAL='PASS',REQUESTED_EXIT='0',
        POSITIVE_CLIENT_STATUS='0',POSITIVE_SERVER_STATUS='0',POSITIVE_CLIENT_ESTABLISHED='1',
        POSITIVE_CLIENT_BACKEND_ERROR='0',POSITIVE_SERVER_BACKEND_ERROR='0',POSITIVE_CLIENT_VERIFY_FLAGS='0',
        POSITIVE_SERVER_VERSION='TLSv1.3',CLIENT_CERTIFICATE_AUTHENTICATION='not-requested')
    require(all(got[k]==v for k,v in expected.items()),'failed native TLS/identity/rejection/cleanup evidence')
    utc=decimal(got['UNIX_TIME'],2051222399,1577836800)
    flags=decimal(got['POSITIVE_SERVER_VERIFY_FLAGS'])
    return dict(checks=24,unix_time=utc,tls_version='TLSv1.3',server_reported_peer_verify_flags=flags,
                checked_source_forward_payload_bytes=3072,checked_source_reverse_payload_bytes=1021)


def observer_protocol(raw,nonce):
    got=log_pairs(raw);require(tuple(got)==OBSERVER_ORDER,'exact original supervisor protocol order required')
    expected=dict(scope='actual-win98-tls-owned-child-supervisor',nonce=nonce,WIN98_IDENTIFIED='1')
    expected.update({'os.major':'4','os.minor':'10','os.build-low':'2222','os.platform':'1',
        'child.path':PREFIX+'TLSDLL.EXE','child.stdout':PREFIX+'TLSOUT.LOG','child.created':'1',
        'child.create-error':'0','child.wait':'0','child.exit-query':'1','child.exit-query-error':'0',
        'child.exit-code':'0','child.stdout-flushed':'1','child.handles-closed':'1','child.success':'1',
        'supervisor.requested-exit-code':'0'})
    require(all(got[k]==v for k,v in expected.items()),'failed actual Win98 child/exit/flush/cleanup evidence')
    return decimal(got['child.pid'],minimum=1)


def catalogue(ledger):
    raw=ledger.take(ROOT/'tools/verify_tls13_guest_evidence.py',ORIGINAL_SHA)
    rows=[n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign) and
          any(isinstance(t,ast.Name) and t.id=='CHECKS' for t in n.targets)]
    require(len(rows)==1 and ast.literal_eval(rows[0])==CHECKS,'untouched original24check catalogue differs')
    ledger.take(ROOT/'tests/m98_tls13_guest_interop.c',DEPENDENCIES[ROOT/'tests/m98_tls13_guest_interop.c'])
    ledger.take(ROOT/'tests/m98_tls13_guest_runner.c',DEPENDENCIES[ROOT/'tests/m98_tls13_guest_runner.c'])


def load_helper(ledger,approved_sha):
    require(pin(approved_sha)==HELPER_SHA,'wrong frozen stage-helper generation')
    path=ROOT/'tools/tls13_i486_native_stage_evidence.py';raw=ledger.take(path,approved_sha)
    # Execute only this previously reviewed own helper's approved bytes in
    # memory. Historical verifier/builder/scanner sources are never executed.
    module=types.ModuleType('approved_tls13_i486_stage');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def tested_authority(ledger,path,approved_sha):
    path=canonical(path)
    require(path.name=='result.json' and path.parent.parent==ROOT/'build' and
            re.fullmatch('tls13-i486-native-verifier-v[1-9][0-9]{0,3}',path.parent.name),'canonical host-control authority required')
    a=object_json(ledger.take(path,approved_sha,2<<20))
    require(type(a.get('schema')) is int and a['schema']==1 and a.get('kind')=='tls13-i486-native-verifier-host-controls' and
            a.get('passed') is True and a.get('synthetic_tests_only') is True and a.get('native_guest_verified') is False,
            'host controls must not be fabricated native acceptance')
    require(all(a.get(k) is False for k in FALSE_SCOPE),'host-control scope flags must remain false')
    sources=a.get('source_sha256');require(type(sources) is dict and set(sources)==set(SOURCES),'exact three tested source profile')
    for name,h in sources.items():
        current=ledger.take(ROOT/name,h);require(ledger.take(path.parent/'source'/name,h)==current,'current/frozen tested source drift')
    py=a.get('python_interpreter',{});actual=Path(sys.executable).resolve(strict=True)
    require(type(py) is dict and set(py)=={'path','sha256','frozen','bytes'} and py.get('path')==str(actual) and
            py['frozen']==str(path.parent/'python-interpreter.bin'),'actual tested interpreter identity')
    python_raw=ledger.take(actual,py.get('sha256'))
    require(type(py['bytes']) is int and py['bytes']==len(python_raw) and
            ledger.take(Path(py['frozen']),py['sha256'])==python_raw,'current/frozen interpreter byte closure')
    dependencies=a.get('inputs');require(type(dependencies) is list and len(dependencies)==len(DEPENDENCIES),'tested input closure')
    expected={str(p):h for p,h in DEPENDENCIES.items()};seen=set()
    for n,row in enumerate(dependencies):
        require(type(row) is dict and set(row)=={'source','frozen','sha256','bytes'} and
                row['source'] in expected and row['source'] not in seen and row['sha256']==expected[row['source']] and
                row['frozen']==str(path.parent/'inputs'/(str(n)+'.bin')),'exact tested dependency bindings')
        data=ledger.take(Path(row['source']),row['sha256']);require(type(row['bytes']) is int and row['bytes']==len(data),'tested dependency count')
        require(ledger.take(Path(row['frozen']),row['sha256'])==data,'tested dependency frozen byte drift');seen.add(row['source'])
    tests=ast.parse(ledger.take(ROOT/SOURCES[1],sources[SOURCES[1]]))
    count=sum(isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name.startswith('test_')
              for c in tests.body if isinstance(c,ast.ClassDef) for m in c.body)
    require(0<count<=256 and type(a.get('methods_each')) is int and a['methods_each']==count,'actual source test-method count')
    rows=a.get('steps');require(type(rows) is list and len(rows)==2,'normal and optimized control logs required')
    for mode,row in zip(('normal','optimized'),rows):
        command=[str(actual),'-B']+(['-O'] if mode=='optimized' else [])+['tests/test_tls13_i486_native.py']
        require(type(row) is dict and row.get('mode')==mode and row.get('command')==command and
                type(row.get('returncode')) is int and row['returncode']==0 and row.get('log')==str(path.parent/(mode+'.log')),
                'actual normal/optimized host-control command')
        data=ledger.take(Path(row['log']),row.get('sha256'),1<<20)
        require(re.search(rb'\nRan '+str(count).encode()+rb' tests in [0-9.]+s\n\nOK\n\Z',data),
                'complete host-control verdict/no skipped tests required')
    return sources


def run_frame(run,run_dir,manifest,manifest_sha,authority_sha,ledger):
    require(run.get('profile')=='actual-win98-uefi-csmwrap' and run.get('status')=='NEEDS-VISUAL-REVIEW' and
            not any(run.get(n) for n in ('error','runtime_failure','interaction_failure')),'actual harness failed/partial')
    require(run.get('originals_unchanged') is True and run.get('prepared_source_unchanged') is True and
            type(run.get('qemu_exit_code')) is int and run['qemu_exit_code']==0 and run.get('manual_finish_requested') is True and
            run.get('guest_status',{}).get('running') is True,'normally stopped preserved private run required')
    h=run.get('hardware',{});require(type(h) is dict,'actual hardware object')
    expected=dict(run_name=run_dir.name,network='none',machine='q35',accel='kvm',memory=128,smp=2,reserve_gib=20,
        timeout=600,capture_interval=5,manual_gui=True,manual_purpose='diagnostic',firmware_gop=True,replace_csmwrap=True,
        native_bios_control=False,diagnostic_boot=False,replace_installed_gop=False,large_chromium_inputs=False,
        application_manifest=None,native_trial_manifest=None,guest_files_manifest=str(STAGE/'guest-files.json'),
        guest_files_manifest_sha=manifest_sha)
    require(all(k in h and equal(h[k],v) for k,v in expected.items()) and run.get('firmware_gop_opt_in') is True,
            'exact cold GOP/offline128MiB2KVM20GiB profile required')
    require(equal(run.get('immutable_sources'),MEDIA) and h.get('archive')==next(iter(MEDIA)) and
            h.get('checkpoint_record')==list(MEDIA)[1],'exact original media authority records')
    ledger.take(Path(list(MEDIA)[1]),MEDIA[list(MEDIA)[1]],2<<20)
    p=run.get('prepared_reuse',{});require(type(p) is dict and p.get('method')==
        'verified private sparse post-run disk copy; cold hardware, new VARS, no CPU/RAM state' and
        p.get('source_run')==h.get('resume_owned_run') and p.get('requires_efi_replacement') is False,
        'cold private-copy provenance required')
    cold=canonical(p.get('source_run'));require(cold.parent==RUNS and cold!=run_dir,'owned separate cold source path')
    ledger.take(cold/'result.json',p.get('source_receipt_sha256'),2<<20)
    pin(p.get('source_disk_sha256'))
    require(type(p.get('source_allocated_bytes')) is int and p['source_allocated_bytes']>0,'actual sparse-source allocation')
    gop=('explicit GOP configuration parsed','firmware GOP retained through SeaVGABIOS',
         'reserved native framebuffer handover emitted','legacy VGA OpROM path absent')
    require(equal(run.get('firmware_gop_checks'),[dict(check=n,status='PASS') for n in gop]),'actual GOP firmware evidence')
    require(run.get('serial_log')==str(run_dir/'serial.log'),'direct owned serial collection')
    serial=ledger.take(run_dir/'serial.log',limit=1<<20,group=2)
    require(all(re.search(x,serial) for x in (rb'gop_only = true',
        rb'gop_only: forced firmware GOP \+ SeaVGABIOS; no VGA OpROM',rb'SHZGOP1 handover=')) and
        b'Video Initialisation Succeed with OpROM' not in serial,'actual serial GOP checks differ')
    ui=run.get('gui_interaction',{});require(type(ui) is dict and ui.get('all_actions_completed') is True and
        type(ui.get('actions')) is list and 1<=len(ui['actions'])<=64,'completed bounded manual action records')
    for n,row in enumerate(ui['actions'],1):
        require(type(row) is dict and type(row.get('sequence')) is int and row['sequence']==n and
                row.get('status')=='sent; application effect requires screenshot/readback verification','manual sequence incomplete')
    require(sum(row.get('typed')==PREFIX+'T13RUN.EXE' for row in ui['actions'])==1,'exact recorded supervisor launch')
    require(run.get('source_snapshot')==str(run_dir/'runner-source.py') and run.get('source_sha256')==HARNESS_SHA,
            'exact approved harness source snapshot')
    ledger.take(run_dir/'runner-source.py',HARNESS_SHA,group=2)
    stderr=ledger.take(run_dir/'qemu.stderr',limit=1<<20,group=2)
    require(not re.search(rb'emulation failure|KVM internal error|qemu: fatal|failed to initialize kvm',stderr,re.I),'fatal QEMU diagnostics')
    inputs=records(manifest['inputs'],{PREFIX+n for n in INPUTS});f=run.get('guest_files',{})
    immutable={str(STAGE/'guest-files.json'):manifest_sha,str(STAGE/'stage-authority.json'):authority_sha}
    immutable.update({r['source']:r['sha256'] for r in inputs.values()})
    require(type(f) is dict and f.get('manifest')==str(STAGE/'guest-files.json') and f.get('manifest_sha256')==manifest_sha and
            f.get('immutable_sources_unchanged') is True and equal(f.get('immutable_sources'),immutable) and
            f.get('output_baseline')=='all absent before private injection' and equal(f.get('outputs'),manifest['outputs']) and
            f.get('backups')==[] and f.get('installed_gop_replacement')==[] and f.get('system_driver_file_readback')==[],
            'exact fresh staging authority/input/output scope')
    plan=object_json(ledger.take(run_dir/'guest-files-plan.json',limit=2<<20,group=2))
    plan_keys={'manifest','manifest_sha256','inputs','outputs','backups','installed_gop_replacement',
               'immutable_sources','output_baseline','native_installed_and_rendered'}
    require(set(plan)==plan_keys and equal(plan,{k:f[k] for k in plan_keys}),
            'initial private preparation plan differs from final collection')
    copied=records(f.get('inputs'),set(inputs))
    for guest,row in copied.items():
        original=inputs[guest];require(equal(row,{**original,'private_copy_sha256':original['sha256']}),'prepared record mismatch')
        data=ledger.take(run_dir/('prepared-guest-'+guest[len(PREFIX):]),original['sha256'],1<<20,group=2)
        require(type(original['bytes']) is int and original['bytes']==len(data),'exact prepared bytes')
    logs={};rows=records(f.get('readback'),{PREFIX+n for n in OUTPUTS})
    for guest,row in rows.items():
        name=guest[len(PREFIX):];path=run_dir/('guest-output-'+name)
        require(set(row)=={'guest','status','freshness','path','sha256','bytes'} and row['path']==str(path) and
                row.get('status')=='captured' and row.get('freshness')=='new-in-owned-run','fresh direct private collection required')
        data=ledger.take(path,row.get('sha256'),LOG_LIMIT,group=2)
        require(type(row.get('bytes')) is int and row['bytes']==len(data),'captured byte count');logs[name]=data
    require(logs['TLSOUT.LOG']==b'','unexpected child diagnostic output')
    return inputs,logs


def stage_ledger(ledger,manifest_sha,authority_sha,provenance_sha):
    manifest=object_json(ledger.take(STAGE/'guest-files.json',manifest_sha,65536,group=0))
    authority=object_json(ledger.take(STAGE/'stage-authority.json',authority_sha,2<<20,group=0))
    prov=object_json(ledger.take(STAGE/'provenance.json',provenance_sha,4<<20,group=0))
    require(type(prov.get('stage_sha256')) is dict and len(prov['stage_sha256'])==7614,'complete prepared provenance members')
    for name,h in prov['stage_sha256'].items():
        p=Path(name);require(type(name) is str and not p.is_absolute() and str(p)==name and
                            all(x not in ('','.','..') for x in name.split('/')),'provenance member escape')
        ledger.take(STAGE/name,h,group=0)
    source=authority.get('source_sha256');require(type(source) is dict and len(source)==26,'current26source bindings')
    for name,h in source.items():
        require(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts,'stage source escape')
        ledger.take(ROOT/name,h)
    return manifest,authority,prov


def topology(prov):
    aliases=prov.get('original_aliases');dirs=prov.get('original_directories')
    require(type(aliases) is dict and len(aliases)==147 and type(dirs) is list and len(dirs)==584,'exact original archive topology')
    expected=set(prov['stage_sha256'])|{'guest-files.json','provenance.json'}|set(aliases)
    actual=set();physical=set()
    for parent,subdirs,files in os.walk(STAGE,followlinks=False):
        for n in list(subdirs):
            p=Path(parent)/n
            if p.is_symlink(): actual.add(str(p.relative_to(STAGE)));subdirs.remove(n)
            else: canonical(p);physical.add(str(p.relative_to(STAGE)))
        actual.update(str((Path(parent)/n).relative_to(STAGE)) for n in files)
    require(actual==expected,'late stage file/alias topology drift')
    wanted={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}|set(dirs)
    require(physical==wanted,'late stage directory topology drift')
    for name,row in aliases.items():
        p=STAGE/name;require(stat.S_ISLNK(p.lstat().st_mode) and os.readlink(p)==row['target'] and
             p.resolve(strict=True)==STAGE/row['normalized_target'],'late original alias drift')
        target=p.resolve(strict=True)
        require(type(row.get('directory')) is bool and
                (target.is_dir() if row['directory'] else target.is_file()),'late original alias target type drift')


def final_gate(ledger,initial,stage_check,prov):
    require(equal(stage_check(),initial),'stage generation drift during native acceptance')
    stamps=ledger.final_rehash()
    topology(prov)
    # The directory walk is metadata-only; re-read sources and critical native/
    # run evidence last, then check every consumed snapshot again.
    for p,row in ledger.files.items():
        if row['group']>=1:
            raw,_=raw_file(Path(p),row['limit'])
            require(sha(raw)==row['sha256'],'last source/native/run file drift: '+p)
    ledger.final_stamps(stamps)


def verify(run_path,run_sha,manifest_path,manifest_sha,authority_sha,provenance_sha,
           harness_sha,helper_sha,build_pins,verifier_authority,verifier_authority_sha):
    run_path=canonical(run_path);run_dir=run_path.parent
    require(run_path.name=='result.json' and run_dir.parent==RUNS and re.fullmatch(RUN_NAME,run_dir.name),'canonical corrected TLS owned run required')
    require(canonical(manifest_path)==STAGE/'guest-files.json' and pin(manifest_sha)==MANIFEST_SHA and
            pin(authority_sha)==AUTHORITY_SHA and pin(provenance_sha)==PROVENANCE_SHA and pin(harness_sha)==HARNESS_SHA,
            'exact caller-approved corrected stage/harness generation')
    ledger=Ledger();helper=load_helper(ledger,helper_sha);helper.approved_pins(build_pins)
    tested_sources=tested_authority(ledger,verifier_authority,verifier_authority_sha);catalogue(ledger)
    stage_check=lambda:helper.check_stage(STAGE/'guest-files.json',manifest_sha,authority_sha,provenance_sha,build_pins)
    initial=stage_check();require(initial.get('passed') is True,'fresh stopped stage check required')
    manifest,authority,prov=stage_ledger(ledger,manifest_sha,authority_sha,provenance_sha)
    run=object_json(ledger.take(run_path,run_sha,2<<20,group=3))
    inputs,logs=run_frame(run,run_dir,manifest,manifest_sha,authority_sha,ledger)
    pid=observer_protocol(logs['T13RUN.LOG'],NONCE)
    observed=native_protocol(logs['TLSDLL.LOG'],NONCE,inputs[PREFIX+'M98TLS13.DLL']['sha256'],inputs[PREFIX+'M98TLS.DLL']['sha256'])
    final_gate(ledger,initial,stage_check,prov)
    return dict(schema='win98modern.corrected-i486-native-offline-tls.v1',passed=True,
        scope='Actual native latest-client/LTS-server DLL TLS1.3 interoperability through offline memory queues',
        nonce=NONCE,native_dll_memory_interop_verified=True,native_checks=24,
        actual_owned_child=dict(pid=pid,exit_code=0,stdout_flushed=True,handles_closed=True),
        supervisor_requested_exit_code=0,os=dict(platform='Win32 Windows',major=4,minor=10,build_low=2222,acp=None),
        observations=observed,manifest_sha256=manifest_sha,stage_authority_sha256=authority_sha,
        stage_provenance_sha256=provenance_sha,harness_result_sha256=run_sha,harness_source_sha256=harness_sha,
        stage_helper_sha256=helper_sha,approved_build_sha256=build_pins,verifier_authority_sha256=verifier_authority_sha,
        tested_verifier_source_sha256=tested_sources,source_sha256=authority['source_sha256'],
        input_sha256={g[len(PREFIX):]:r['sha256'] for g,r in inputs.items()},
        log_sha256={n:sha(raw) for n,raw in logs.items()},
        checked_file_sha256={p:r['sha256'] for p,r in ledger.files.items()},**FALSE_SCOPE)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('run-result','manifest','verifier-authority'):
        p.add_argument('--'+n,required=True,type=Path);p.add_argument('--'+n+'-sha256',required=True)
    for n in ('stage-authority','stage-provenance','harness','stage-helper'):
        p.add_argument('--'+n+'-sha256',required=True)
    for n in ('tls','root-review','independent-review','client','server'):
        p.add_argument('--'+n+'-sha256',required=True)
    a=p.parse_args()
    pins={n:getattr(a,n+'_sha256') for n in ('tls','root_review','independent_review','client','server')}
    try:
        r=verify(a.run_result,a.run_result_sha256,a.manifest,a.manifest_sha256,a.stage_authority_sha256,
                 a.stage_provenance_sha256,a.harness_sha256,a.stage_helper_sha256,pins,a.verifier_authority,a.verifier_authority_sha256)
    except (ValueError,OSError,TypeError,KeyError,AttributeError,SyntaxError,RecursionError) as error:
        print(json.dumps(dict(passed=False,native_dll_memory_interop_verified=False,error=str(error),**FALSE_SCOPE)));return 1
    print(json.dumps(r,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
