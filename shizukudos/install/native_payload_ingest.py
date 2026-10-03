#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Export a pinned private native ESP as ESP.SIM; no installation or execution.

This is an input boundary. It does not rebase a superfloppy to a partition,
launch a guest, mount installer source volumes, or confer Windows acceptance.
"""
import argparse
import ast
import bisect
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import types

DISK_BYTES = 2 << 30
ESP_BYTES = 2304 << 20
MAX_JSON = 4 << 20
MAX_FILE = 4 << 30
BLOCK = 4096
FLOOR = 17 << 30
CONSTRUCTOR_SHA = '1275da21ea913689b37e93503d6ddcf5defdb35736ac4cf5740a0f2de28729cd'
FAT_READER_SHA = 'c5941f761598107cfb408c5508ee8080a7c81113a1e37f91f72d49868d3d8387'
PROFILE_PRODUCER_SHA = 'd2d1b7018248cff14a0e81475b1d36f1a8aa4e2d2a943b0f8bc738925d211f43'
XMS_SHA = '5e0ed027a150ac1c198e994ca248245c07c1f44796bc0791448afbcf29789211'
XMS_COMMITS = {'HimemX':'bbaf6b8951cdac785f1f4e9b67c25439c5bf8e75',
               'JWasm':'7f6f32e78b79565d40bcce496756aadd1ff66900'}
NATIVE_SOURCES = {'shizukudos/supervisor/native_win98/build.py',
                  'shizukudos/supervisor/native_win98/win98.c',
                  'shizukudos/supervisor/native_win98/win98.h',
                  'shizukudos/supervisor/loader/loader.c',
                  'shizukudos/supervisor/src/domain.c',
                  'shizukudos/boot_profile/win98_foundation.h'}
DOS_SOURCES = {'shizukudos/dos16/build.py',
               *('shizukudos/dos16/user/'+name for name in
                 ('ready.asm','CONFIG.SYS','AUTOEXEC.BAT','SHZSTART.BAT','RECOVER.BAT','README.TXT'))}
MAKE_CONFIG = 'XNASM=nasm\nundefine XUPX\nALLCFLAGS=-DWIN31SUPPORT\nNASMFLAGS=-DWIN31SUPPORT\n'
DOS_PATCHES = (
    ('0001-shizukudos-branding.patch', 'bdbcd8b1184d6ddaac40c3fa494e7ff2ddc0eb2b2d273fbce66fa2e4ef27ded1'),
    ('0002-reproducible-build-date.patch', 'daba8b7e6876a6e5a682de4a6cc6d885472fd75279c70206f1c09409d662d1c3'),
    ('0003-cb43-win98-dos-internals.patch', 'a68f2a6bec6b378f69727bd32b386c097ed926323a98c5e34fb109ccdda10ce0'),
    ('0003-dosmgr-honest-contract.patch', '9ea1d25225664d41d0ba5be40e34455804932272b2f2f6808767e1bf14fc078d'),
    ('0004-win-startup-chain.patch', '72c0dab2e288159523cf3c018abccf3cd895e41c0c4150c6c60678a6c5882eef'),
    ('0005-korean-cp949-nls.patch', '32de944d45cce7e6fbe9c2ef8345735a005d032dd2f6c5f7ecb808ee7fa72a71'),
    ('0006-win98-registry-path.patch', '62925e53a57b750a53c9c35c0fccd9a99ecba8cdd9f84caf96c8774b6807aad1'),
    ('0007-primary-shell-parameters.patch', '7e1a708d5ccb2295421de318ee788a41e02290cd1089dfad881bf6533634bc06'),
    ('freecom-0001-reproducible-build-stamp.patch', 'ff9d333927637beb775a3d33fb42181026d4847f5523fdaa069553f68db2d76e'),
)
SCHEMA = 'shizukuos.private-native-install-payload.v1'
FALSE_FLAGS = ('VM_executed', 'Windows98_boot_verified', 'installer_executed',
               'installer_target_written', 'coldboot_persistence_verified',
               'MSDOS_replacement_under_Windows98', 'native_apps_verified', 'SMP_acceptance', 'ISO_built')


def need(value, message):
    if not value: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def identity(s): return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def path(value):
    need(type(value) is str and value and not any(c in value for c in ('\0', '\r', '\n', '@', ':')), 'canonical absolute path required')
    p = Path(value)
    need(p.is_absolute() and p.resolve() == p and not any(q.is_symlink() for q in (p, *p.parents)), 'nonsymlink canonical path required')
    need(not any(p == q or q in p.parents for q in map(Path, ('/dev', '/proc', '/sys', '/srv/m98'))), 'device/virtual/public paths refused')
    return p


def pin(row):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact file pin required')
    p = path(row['path'])
    need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE, 'bounded nonzero extent required')
    need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) and row['sha256'] != '0'*64, 'literal nonzero SHA256 required')
    return p


def read_exact(fd, count, offset, checkpoint):
    data = bytearray()
    while len(data) < count:
        checkpoint(); block = os.pread(fd, min(1 << 20, count-len(data)), offset+len(data))
        need(block, 'unexpected input EOF'); data.extend(block)
    checkpoint(); return bytes(data)


def hash_fd(fd, size, checkpoint):
    h = hashlib.sha256()
    for at in range(0, size, 1 << 20): h.update(read_exact(fd, min(1 << 20, size-at), at, checkpoint))
    need(not os.pread(fd, 1, size), 'input extent grew'); checkpoint(); return h.hexdigest()


class Union:
    """One actual SIGIO/read-lease union; attempt every mandatory cleanup."""
    def __init__(self): self.entries = {}; self.broken = False; self.guards=[]
    def __enter__(self):
        self.previous = signal.getsignal(signal.SIGIO)
        def broken(*args):
            self.broken = True
            if callable(self.previous): self.previous(*args)
        signal.signal(signal.SIGIO, broken); return self
    def check(self):
        need(not self.broken, 'input read lease broken')
        for guard in self.guards:guard()
        for p, e in self.entries.items():
            path(str(p))
            need(identity(os.fstat(e['fd'])) == e['identity'] == identity(p.stat()) and
                 fcntl.fcntl(e['fd'], fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'input identity/lease changed')
    def io_check(self, e):
        # Each FAT-cluster read checks its actual data fd and the union SIGIO.
        # Every admitted file still gets full checks before/after each phase
        # and final full SHA checks, without unrelated O(N) stats per cluster.
        need(not self.broken,'input read lease broken')
        for guard in self.guards:
            checkpoint=getattr(guard,'io_check',None)
            if checkpoint is None:guard() # Existing callable guards remain immediate.
            else:checkpoint()
        need(not self.broken,'input read lease broken')
        p=path(e['pin']['path'])
        need(identity(os.fstat(e['fd']))==e['identity']==identity(p.stat()) and
             fcntl.fcntl(e['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK,'active input identity/lease changed')
    def add(self, row, *, written_identity=None):
        p = pin(row)
        if p in self.entries:
            need(self.entries[p]['pin'] == row, 'conflicting duplicate pin'); return self.entries[p]
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == row['bytes'], 'independent regular pinned input required')
            need(written_identity is None or identity(s)==written_identity==identity(p.stat()), 'completed owned writer identity changed before admission')
            fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid()); fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            e = {'fd':fd, 'pin':dict(row), 'identity':identity(s)}; self.entries[p] = e
            need(hash_fd(fd, s.st_size, lambda:self.io_check(e)) == row['sha256'], 'input full SHA differs')
            return e
        except BaseException:
            if p not in self.entries: os.close(fd)
            raise
    def json(self, row):
        e = self.add(row); need(row['bytes'] <= MAX_JSON, 'bounded JSON required')
        return json.loads(read_exact(e['fd'], row['bytes'], 0, lambda:self.io_check(e)), object_pairs_hook=unique)
    def bytes(self, row, maximum=MAX_JSON):
        need(row['bytes'] <= maximum, 'bounded content required')
        e = self.add(row); return read_exact(e['fd'], row['bytes'], 0, lambda:self.io_check(e))
    def finish(self):
        self.check()
        for e in self.entries.values():
            need(hash_fd(e['fd'],e['pin']['bytes'],lambda:self.io_check(e))==e['pin']['sha256'], 'final source full SHA differs')
        self.check()
    def __exit__(self, *exc):
        errors = []
        try: self.check()
        except BaseException as e: errors.append(e)
        for e in reversed(list(self.entries.values())):
            try: fcntl.fcntl(e['fd'], fcntl.F_SETLEASE, fcntl.F_UNLCK)
            except BaseException as error: errors.append(error)
            try: os.close(e['fd'])
            except BaseException as error: errors.append(error)
        signal.signal(signal.SIGIO, self.previous)
        if errors: raise errors[0]


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON field'); result[key] = value
    return result


def recorded(root, name, digest):
    need(type(name) is str and name and '\\' not in name and not name.startswith('/') and
         all(v not in ('', '.', '..') for v in name.split('/')), 'safe source-relative path required')
    p = path(str(root/name)); need(p.is_file(), 'recorded source missing')
    return {'path':str(p), 'bytes':p.stat().st_size, 'sha256':digest}


def unchanged_flags(obj, flags):
    need(all(obj.get(k) is False for k in flags), 'runtime/public evidence is not an input-preparation claim')


def member_equal(record, row):
    return type(record) is dict and record.get('bytes') == row['bytes'] and record.get('sha256') == row['sha256']


def held_module(held, row, expected, name):
    need(row['sha256'] == expected, 'reviewed FAT reader source epoch required')
    raw = held.bytes(row, 1 << 20); module = types.ModuleType(name); module.__file__ = row['path']
    held.check();exec(compile(raw, row['path'], 'exec'), module.__dict__);held.check();return module


def startup_policy(source, held):
    row=next(r for r in source['producer_inputs'] if Path(r['path']).name=='win98_source_profile.py')
    need(row['sha256']==PROFILE_PRODUCER_SHA,'exact source-profile policy epoch required')
    tree=ast.parse(held.bytes(row,1<<20),filename=row['path'])
    names={'dos_lines','installed_paths','require_file','locale_lines','biling_lines'}
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    need({n.name for n in functions}==names and len(functions)==len(names),'exact reviewed startup policy functions required')
    policy={'need':need,'re':re}
    held.check();exec(compile(ast.Module(body=functions,type_ignores=[]),row['path'],'exec'),policy);held.check()
    return policy


def startup_configuration(source, selected):
    """Reconstruct admitted startup bytes; configuration never grants authority."""
    registry = source.get('registry_path_configuration')
    registry_path = selected+'\\SYSTEM.DAT'
    need(type(registry) is dict and set(registry)=={'path','origin','runtime_verified'} and
         registry['path']==registry_path and registry['origin']=='validated_source' and
         registry['runtime_verified'] is False and len(registry_path)<=78,
         'exact observed Windows registry path configuration without runtime authority required')
    locale = source.get('locale', {})
    country, nls = locale.get('country'), locale.get('nls')
    need(type(country) is list and type(nls) is list and len(country)<=1 and len(nls)<=1 and
         (not country or nls), 'observed locale arrays required; COUNTRY-only startup refused')
    biling = source.get('observed_biling_driver', [])
    need(type(biling) is list and len(biling)<=1, 'bounded observed BILING selection required')
    for line in country+nls+biling:
        need(type(line) is str and len(line)<=250 and all(32<=ord(c)<=126 for c in line) and
             not any(c in line for c in '&|<>%'), 'bounded observed locale line required')
    for line in biling:
        match = re.fullmatch(r'(DEVICE|DEVICEHIGH)\s*=\s*([^\s]+)', line, re.I)
        need(match and match[2].upper()==selected+'\\BILING.SYS',
             'exact observed Windows BILING path without arguments required')
    initial = source.get('initial_locale_configuration')
    if initial is not None:
        need(type(initial) is dict and set(initial)=={'country','codepage','origin','runtime_verified','observed_query_authority'} and
             type(initial['country']) is int and type(initial['codepage']) is int and
             initial['country']==82 and initial['codepage']==949 and initial['origin']=='explicit_request' and
             initial['runtime_verified'] is False and initial['observed_query_authority'] is False,
             'explicit locale configuration cannot claim runtime or observed authority')
        need(not country, 'explicit initial locale cannot override observed COUNTRY')
    initial_country = 'COUNTRY=82,949\r\n' if initial is not None else ''
    windows = selected[3:]
    config = ('WINREG='+registry_path+'\r\n'+initial_country+'DEVICE=C:\\HIMEMX.EXE /VERBOSE\r\n'+''.join(v+'\r\n' for v in biling)+
              'DEVICE='+selected+'\\IFSHLP.SYS\r\nDOS=HIGH\r\nFILES=30\r\nBUFFERS=20\r\n'
              'SHELL=C:\\COMMAND.COM C:\\ /E:512 /P\r\n'+''.join(v+'\r\n' for v in country)).encode('ascii')
    auto = ('@ECHO OFF\r\nSET COMSPEC=C:\\COMMAND.COM\r\nSET windir='+selected+'\r\nSET PATH='+selected+
            ';'+selected+'\\COMMAND;C:\\\r\nC:\r\nCD \\'+windows+'\r\n'+''.join(v+'\r\n' for v in nls)+
            selected+'\\WIN.COM\r\n').encode('ascii')
    return config, auto, country, nls, biling


def xms_lineage(source, payload, held):
    receipt=held.json(source['xms_receipt'])
    need(receipt.get('schema')=='shizukudos-cb43-himemx-source-build-v1' and
         payload['bytes']==6100 and payload['sha256']==XMS_SHA, 'known source-built normal HIMEMX required')
    matches=[r for r in receipt.get('artifacts',[]) if r.get('file')=='artifacts/HIMEMX.EXE']
    need(len(matches)==1 and member_equal(matches[0],payload), 'XMS artifact differs from raw producer receipt')
    need(receipt.get('source_inputs_frozen_before_build') is True and
         receipt.get('source_files_unchanged_after_build') is True and receipt.get('source_files_changed')==[], 'actual XMS source freeze required')
    builds=[r for r in receipt.get('builds',[]) if r.get('name')=='HIMEMX']
    need(len(builds)==1 and type(builds[0].get('exit_code')) is int and builds[0]['exit_code']==0 and
         type(builds[0].get('command')) is list and '-mz' in builds[0]['command'] and
         not any('ALTSTRAT' in str(v).upper() for v in builds[0]['command']), 'normal XMS source build command required')
    recorded_rows={}
    for name,commit in XMS_COMMITS.items():
        preimage=receipt.get('source_preimages',{}).get(name,{})
        need(preimage.get('commit')==receipt.get('acquisitions',{}).get(name,{}).get('commit')==commit, 'XMS upstream source identity differs')
        files=preimage.get('files')
        need(type(files) is list and len(files)==preimage.get('file_count')=={'HimemX':5,'JWasm':268}[name], 'complete XMS source list required')
        for row in files:
            need(type(row) is dict and set(row)=={'file','bytes','sha256'} and
                 type(row['file']) is str and all(v not in ('','.','..') for v in row['file'].split('/')) and
                 '\\' not in row['file'] and (name,row['file']) not in recorded_rows,'unique safe XMS source row required')
            recorded_rows[name,row['file']]=row
    actual={}
    for row in source['xms_sources']:
        p=pin(row);matched=[]
        for (name,relative),record in recorded_rows.items():
            if str(p).endswith('/'+name+'/'+relative) and member_equal(record,row):matched.append((name,relative))
        need(len(matched)==1 and matched[0] not in actual, 'XMS source physical pin differs from raw receipt')
        actual[matched[0]]=row
    need(actual.keys()==recorded_rows.keys(), 'XMS source pin omitted')


def validate_lineage(request, held):
    required = {'schema', 'source_profile', 'constructor_profile', 'replacement_receipt', 'dos_build_receipt',
                'native_build_receipt', 'native_esp', 'native_source_root', 'readers'}
    need(type(request) is dict and set(request) == required and request['schema'] == 'shizukuos.native-payload-ingest-request.v1', 'exact ingestion request required')
    need(type(request['readers']) is dict and set(request['readers']) == {'constructor', 'fat32'}, 'two exact reviewed reader pins required')
    constructor = held_module(held, request['readers']['constructor'], CONSTRUCTOR_SHA, 'held_native_constructor_reader')
    fat = held_module(held, request['readers']['fat32'], FAT_READER_SHA, 'held_native_esp_reader')
    source = held.json(request['source_profile']); profile = held.json(request['constructor_profile'])
    replacement = held.json(request['replacement_receipt']); dos = held.json(request['dos_build_receipt'])
    native = held.json(request['native_build_receipt'])
    held.check()
    need(source.get('schema') == 'shizukuos.private-win98-launch-profile.v1' and
         source.get('status') == 'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED', 'actual private source-profile receipt required')
    unchanged_flags(source, ('public_artifact', 'Windows98_boot_verified', 'installed_Windows98_version_verified',
                            'MSDOS_replacement_under_Windows98', 'native_apps_verified', 'VM_executed', 'drive_mapping_verified', 'native_bootability_verified'))
    need(source.get('constructor_profile') == request['constructor_profile'] and source.get('boot_policy') == 'shz.foundation=win98', 'source-profile constructor/Windows foundation crosslink differs')
    selected = source.get('observed_windows_path')
    need(type(selected) is str and re.fullmatch(r'C:\\[A-Z0-9_-]{1,8}', selected) and
         selected[3:] not in {'CON','PRN','AUX','NUL',*(v+str(n) for v in ('COM','LPT') for n in range(1,10))}, 'observed C: Windows short directory required')
    need(type(profile) is dict and set(profile) == {'schema','disk','boot_template','freedos_source','build_receipt','build_source_root','payloads'} and
         profile['schema'] == 'shizukuos.private-replacement-profile.v1' and profile['disk'] == source.get('source_disk') and
         profile['build_receipt'] == request['dos_build_receipt'], 'actual constructor/source/DOS raw receipt crosslinks required')
    need(replacement.get('schema') == 'shizukuos.private-replacement-preparation.v1' and
         replacement.get('status') == 'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED' and replacement.get('private_source_disk') is True and
         replacement.get('source_unchanged') is True and replacement.get('source_disk') == profile['disk'] and
         replacement.get('profile_sha256') == request['constructor_profile']['sha256'] and
         replacement.get('build_receipt_sha256') == request['dos_build_receipt']['sha256'], 'actual prepared replacement crosslinks required')
    unchanged_flags(replacement, ('public_artifact','Windows98_boot_verified','MSDOS_replacement_under_Windows98','native_apps_verified','VM_executed'))
    need(dos.get('profile') == 'dos16-freedos' and
         dos.get('upstream',{}).get('freedos-kernel',{}).get('commit') == constructor.KERNEL_COMMIT and
         dos.get('upstream',{}).get('freedos-freecom',{}).get('commit') == constructor.FREECOM_COMMIT, 'actual ke2046/FreeCOM DOS receipt required')
    cfg = dos.get('kernel_make_config', {})
    need(cfg.get('text') == MAKE_CONFIG and cfg.get('sha256') == sha(MAKE_CONFIG.encode()) and
         cfg.get('c_defines') == cfg.get('nasm_defines') == ['WIN31SUPPORT'], 'C/NASM WIN31SUPPORT receipt required')
    root = path(profile['build_source_root']); upstream = path(profile['freedos_source'])
    cfgrow = {'path':str(upstream/'config.mak'), 'bytes':len(MAKE_CONFIG), 'sha256':sha(MAKE_CONFIG.encode())}
    need(held.bytes(cfgrow) == MAKE_CONFIG.encode(), 'actual DOS make configuration differs')
    tool = dos.get('toolchain',{}).get('open-watcom',{})
    need(tool.get('matches_manifest') is True and tool.get('snapshot_sha256') == tool.get('manifest_snapshot_sha256') and
         type(tool.get('snapshot_sha256')) is str and re.fullmatch('[0-9a-f]{64}',tool['snapshot_sha256']) and
         tool['snapshot_sha256'] != '0'*64, 'DOS compiler observation/manifest must match')
    patches = dos.get('patches')
    need(type(patches) is list and len(patches)==len(DOS_PATCHES) and
         [(Path(p.get('patch','')).name,p.get('sha256')) for p in patches] == list(DOS_PATCHES), 'exact ordered DOS3 combined patches required')
    need(len({p.get('patch') for p in patches}) == len(patches), 'duplicate DOS patch refused')
    required_source_pins = []
    for row in patches:
        need(type(row) is dict and set(row) == {'patch','sha256'}, 'exact DOS patch row required')
        actual=recorded(root, row['patch'], row['sha256']);held.add(actual);required_source_pins.append(actual)
    mapping = dos.get('user_boot',{}).get('sources_sha256')
    need(type(mapping) is dict and set(mapping)==DOS_SOURCES, 'complete selected DOS3 project source map required')
    for name, digest in mapping.items():
        actual=recorded(root,name,digest);held.add(actual);required_source_pins.append(actual)
    actual_pins=replacement.get('build_source_pins')
    need(type(actual_pins) is list and len(actual_pins)==len(required_source_pins) and
         {r['path']:r for r in actual_pins}=={r['path']:r for r in required_source_pins}, 'complete constructor DOS source/patch crosslinks required')
    for row in actual_pins: held.add(row)
    template=profile['boot_template'];need(type(template) is dict and set(template)=={'kind','file'} and
          template['kind'] in ('fat12com','fat16com','fat32lba') and template['file']['bytes']==512, 'source-specific template input required')
    held.add(template['file']);t=replacement.get('template',{})
    need(t.get('kind')==template['kind'] and t.get('sha256')==template['file']['sha256'] and
         t.get('sys_source_sha256')==constructor.SYS_SHA and t.get('kernel_name')=='KERNEL.SYS' and
         t.get('load_segment')==96 and t.get('actual_BIOS_DL_capture') is True, 'constructor template provenance differs')
    held.add(recorded(upstream,'sys/sys.c',constructor.SYS_SHA))
    asm='boot32lb.asm' if template['kind']=='fat32lba' else 'boot.asm'
    for name in (asm,'magic.mac'):held.add(recorded(upstream,'boot/'+name,constructor.BOOT_SOURCE_SHA[name]))
    producers=source.get('producer_inputs')
    need(type(producers) is list and len(producers)==2 and
         {Path(r['path']).name:r['sha256'] for r in producers}==
         {'win98_source_profile.py':PROFILE_PRODUCER_SHA,'prepare_replacement.py':CONSTRUCTOR_SHA}, 'exact reviewed source-profile producer inputs required')
    xrows=source.get('xms_sources');need(type(xrows) is list and 1<=len(xrows)<=30000, 'recorded XMS source pins required')
    for row in producers + xrows: held.add(row)
    held.add(source['xms_receipt'])
    validation=source.get('constructor_input_validation',{})
    need(validation.get('status')=='INPUTS_VALIDATED_REPLACEMENT_NOT_PREPARED' and
         validation.get('source_disk')==profile['disk'] and validation.get('build_receipt_sha256')==request['dos_build_receipt']['sha256'] and
         validation.get('build_source_pins')==actual_pins and validation.get('template')==t and
         validation.get('source_unchanged') is True, 'source-profile actual constructor validation crosslinks required')
    held.add(profile['disk']); destination = replacement['destination']; held.add(destination)
    need(profile['disk']['bytes'] == destination['bytes'] == DISK_BYTES, 'exact original and replacement native disk extents required')
    need(profile['disk']['path'] != destination['path'] and
         held.entries[path(profile['disk']['path'])]['identity'][:2] != held.entries[path(destination['path'])]['identity'][:2], 'replacement must be independent of original')
    payloads = profile['payloads']; need(type(payloads) is list and len(payloads)==5, 'exact baseline DOS/XMS/startup payloads required')
    rows = {}
    for row in payloads:
        need(type(row) is dict and set(row) == {'guest','file'} and type(row['guest']) is str and re.fullmatch('[A-Z0-9_]{1,8}\\.[A-Z0-9_]{1,3}',row['guest']) and row['guest'] not in rows, 'unique 8.3 DOS root payloads required')
        rows[row['guest']] = row['file']; held.add(row['file'])
    need({'KERNEL.SYS','COMMAND.COM','HIMEMX.EXE','CONFIG.SYS','AUTOEXEC.BAT'} == rows.keys(), 'source-built DOS/XMS and startup files required')
    xms_lineage(source,rows['HIMEMX.EXE'],held)
    for name in ('KERNEL.SYS','COMMAND.COM'):
        need(member_equal(dos.get('artifacts',{}).get(name.lower()),rows[name]), 'DOS payload artifact differs from raw DOS receipt')
    config, auto, country, nls, biling = startup_configuration(source, selected)
    windows = selected[3:]
    need(held.bytes(rows['CONFIG.SYS']) == config and held.bytes(rows['AUTOEXEC.BAT']) == auto, 'observed WIN.COM startup policy differs')
    original = held.entries[path(profile['disk']['path'])]; disk = held.entries[path(destination['path'])]
    mbr = read_exact(original['fd'],512,0,held.check); active=[mbr[446+i*16:462+i*16] for i in range(4) if mbr[446+i*16]==0x80]
    need(len(active)==1, 'unambiguous original active partition required')
    start=struct.unpack_from('<I',active[0],8)[0]
    geometry=constructor.inspect_geometry(mbr,read_exact(original['fd'],512,start*512,held.check),DISK_BYTES)
    need(geometry['fat_bits']==32 and template['kind']=='fat32lba' and
         geometry==replacement.get('geometry')==validation.get('geometry'), 'original geometry/template/receipt differs')
    vbr=read_exact(original['fd'],512,start*512,held.check)
    wanted=constructor.compose_boot(vbr,held.bytes(template['file'],512),template['kind'],geometry)
    need(read_exact(disk['fd'],512,start*512,held.check)==wanted and
         read_exact(disk['fd'],512,(start+geometry['backup_sector'])*512,held.check)==wanted, 'actual source-specific primary/backup replacement boot bytes differ')
    held.check()
    before=constructor.inventory(original['fd'],geometry,lambda:held.io_check(original))
    after=constructor.inventory(disk['fd'],geometry,lambda:held.io_check(disk));held.check()
    need(read_exact(disk['fd'],512,0,held.check)==mbr, 'original private partition table changed')
    need(len({k.upper() for k in before})==len(before) and before.get(windows+'/SYSTEM',{}).get('directory') is True and
         source.get('MSDOS.SYS_observation')==before.get('MSDOS.SYS') and before.get('MSDOS.SYS',{}).get('bytes',0)>0, 'unambiguous installed-source path observation required')
    originals=source.get('original_config');need(type(originals) is dict and set(originals)=={'CONFIG.SYS','AUTOEXEC.BAT'}, 'original startup observations required')
    for name,observation in originals.items():
        need(type(observation) is dict and observation.get('present') is (name in before), 'original configuration presence differs')
        if name in before:
            need(member_equal(before[name],observation) and observation.get('source_metadata_sha256')==before[name]['metadata_sha256'], 'original startup metadata/content observation differs')
    def original_bytes(name):
        if name not in before:return b''
        row=before[name];collector=BytesCollector(65536)
        actual=constructor.Volume(original['fd'],geometry,lambda:held.io_check(original)).file(row['cluster'],row['bytes'],collector)
        need(actual==row['sha256'],'original startup file differs');return bytes(collector.value)
    policy=startup_policy(source,held)
    policy['installed_paths'](original_bytes('MSDOS.SYS'),selected)
    need(policy['locale_lines'](original_bytes('CONFIG.SYS'),original_bytes('AUTOEXEC.BAT'),windows,before)==(country,nls),
         'locale/startup rows are not the observed original source policy')
    need(policy['biling_lines'](original_bytes('CONFIG.SYS'),windows,before)==biling,
         'BILING selection is not the observed original source policy')
    for name,row in before.items():
        if name not in rows: need(after.get(name)==row, 'unrelated original Windows/private member changed')
    observed_windows=source.get('observed_members')
    required_windows={windows+'/'+name for name in ('WIN.COM','SYSTEM.INI','SYSTEM/VMM32.VXD','IFSHLP.SYS','SYSTEM.DAT')}
    if country or nls:required_windows|={windows+'/COUNTRY.SYS',windows+'/COMMAND/NLSFUNC.EXE'}
    if biling:required_windows.add(windows+'/BILING.SYS')
    need(type(observed_windows) is dict and set(observed_windows)==required_windows, 'exact observed Windows/locale file inventory required')
    for key,record in observed_windows.items():
        need(type(record) is dict and record.get('bytes',0)>0 and before.get(key)==record and after.get(key)==record, 'required observed installed Windows member differs')
    for name,row in rows.items(): need(member_equal(after.get(name),row), 'replacement startup/DOS/XMS member differs')
    need(native.get('status') == 'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN' and native.get('private') is True and
         all(native.get(k) is True for k in ('source_before_after_match','originals_before_after_match','original_input_leases_held_through_artifact_finalization')), 'actual successful raw native ESP producer receipt required')
    unchanged_flags(native, ('Windows98_installation_identity_verified','VM_executed','Windows98_boot_verified','MS_DOS_replaced','native_Win64_app_verified'))
    inputs=native.get('input_pins');need(type(inputs) is dict and {'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN'}<=inputs.keys() and set(inputs)<={'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'}, 'baseline exact native input members required')
    need(not native.get('optional_native_inputs') and not native.get('optional_native_provenance'), 'optional device epochs require a separate reviewed importer')
    need(inputs['DISK.IMG']==destination, 'native disk is not the selected actual replacement')
    for row in inputs.values(): held.add(row)
    need(inputs['SEABIOS.BIN']['bytes']==256<<10 and held.bytes(inputs['WIN98CFG.BIN'])==struct.pack('<4I',0x38395753,1,128,0), 'real system SeaBIOS/exact native config required')
    need(native.get('artifact',{}).get('bytes')==request['native_esp']['bytes']==ESP_BYTES and member_equal(native['artifact'],request['native_esp']), 'native ESP artifact differs from raw receipt')
    need(path(request['native_esp']['path']).name==native['artifact']['path'], 'native ESP basename differs from original producer')
    nroot=path(request['native_source_root']);mapping=native.get('sources_sha256')
    need(type(mapping) is dict and NATIVE_SOURCES<=mapping.keys() and len(mapping)<=30000,'native producer source closure required')
    for name,digest in mapping.items():held.add(recorded(nroot,name,digest))
    esp=held.add(request['native_esp']);g=fat.geometry(esp['fd'],ESP_BYTES,lambda:held.io_check(esp))
    geom={'fat_bits':32,'start_lba':0,'total_sectors':ESP_BYTES//512,'spc':g['spc'],'reserved':g['reserved'],'fats':2,'fat_sectors':g['fat_sectors'],'root_cluster':g['root'],'root_sectors':0,'first_data':g['first_data']//512,'clusters':g['clusters']}
    observed=constructor.inventory(esp['fd'],geom,lambda:held.io_check(esp));held.check();members=native.get('members')
    need(type(members) is dict and all(k in observed and member_equal(observed[k],v) for k,v in members.items()), 'actual native ESP members differ from raw receipt')
    expected={'EFI/BOOT/BOOTX64.EFI','EFI/SHIZUKU/BOOT.INI',*('SHZDOS/'+n for n in inputs)}
    need(set(members)==expected and {k for k,v in observed.items() if not v.get('directory')}==expected,'unexpected/omitted native ESP file refused')
    for name,row in inputs.items():need(member_equal(members['SHZDOS/'+name],row),'native input/member crosslink differs')
    v=constructor.Volume(esp['fd'],geom,held.check);b=observed['EFI/SHIZUKU/BOOT.INI'];collector=BytesCollector(1024)
    v.file(b['cluster'],b['bytes'],collector)
    need(bytes(collector.value)==b'mode=supervisor\r\nmenu_timeout=0\r\n','native Supervisor boot policy required')
    return esp, {'source_profile':request['source_profile'],'constructor_profile':request['constructor_profile'],
                 'replacement_receipt':request['replacement_receipt'],'dos_build_receipt':request['dos_build_receipt'],
                 'native_build_receipt':request['native_build_receipt'],'original_source_disk':profile['disk'],
                 'replacement_disk':destination,'native_esp':request['native_esp'],'native_members':members,
                 'observed_windows_path':selected,'boot_policy':'shz.foundation=win98','DOS3_patch_pins':patches}


class BytesCollector:
    def __init__(self,limit):self.value=bytearray();self.limit=limit
    def write(self,raw):need(len(self.value)+len(raw)<=self.limit,'bounded file contents required');self.value.extend(raw);return len(raw)


def capacity(where, pending):
    need(shutil.disk_usage(where).free >= FLOOR+pending,'17GiB reserve plus declared export budget unavailable')


def write_all(fd, raw, checkpoint=lambda:None):
    at=0
    while at<len(raw):
        checkpoint()
        count=os.write(fd,raw[at:]);need(count>0,'zero/failed output write');at+=count
        checkpoint()


def export_sim(entry, held, target, budget):
    size=entry['pin']['bytes'];need(size%BLOCK==0,'ESP.SIM complete blocks required')
    active=lambda:held.io_check(entry)
    # All original inputs are admitted at phase boundaries. Each actual IO
    # checks its source fd, canonical ancestors, global SIGIO and owned guards.
    held.check();runs=[];h=hashlib.sha256()
    for at in range(0,size,1<<20):
        data=read_exact(entry['fd'],min(1<<20,size-at),at,active);h.update(data)
        for pos in range(0,len(data),BLOCK):
            if data[pos:pos+BLOCK].count(0)!=BLOCK:
                block=(at+pos)//BLOCK
                if runs and runs[-1][0]+runs[-1][1]==block:runs[-1]=(runs[-1][0],runs[-1][1]+1)
                else:runs.append((block,1))
        need(len(runs)<=1<<20,'bounded sparse chunk table required')
    held.check();need(h.hexdigest()==entry['pin']['sha256'],'export source SHA differs')
    table=b''.join(struct.pack('<QII',first,count,0) for first,count in runs)
    total=64+len(table)+sum(count*BLOCK for _,count in runs);need(total<=budget,'private export exceeds explicit budget')
    header=b'SHZSIMG1'+struct.pack('<IIIIQ',BLOCK,0,len(runs),0,size)+bytes.fromhex(entry['pin']['sha256'])
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        owned=identity(os.fstat(fd))[:2];owner=os.geteuid()
        def writer_check():
            active();path(str(target));s=os.fstat(fd)
            need(identity(s)==identity(target.stat()) and identity(s)[:2]==owned and
                 owned!=entry['identity'][:2] and stat.S_ISREG(s.st_mode) and
                 stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==owner and s.st_nlink==1 and
                 0<=s.st_size<=total and s.st_size==os.lseek(fd,0,os.SEEK_CUR),
                 'owned ESP.SIM writer fd/path/extent changed')
            capacity(target.parent,budget)
        write_all(fd,header,writer_check);write_all(fd,table,writer_check)
        for first,count in runs:
            for at in range(first*BLOCK,(first+count)*BLOCK,1<<20):
                writer_check()
                write_all(fd,read_exact(entry['fd'],min(1<<20,(first+count)*BLOCK-at),at,writer_check),writer_check)
        held.check();writer_check();need(os.fstat(fd).st_size==total,'ESP.SIM output extent differs')
        os.fsync(fd);writer_check();written=identity(os.fstat(fd))
    finally:os.close(fd)
    readback=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        def readback_check():
            active();path(str(target));s=os.fstat(readback)
            need(identity(s)==written==identity(target.stat()) and
                 stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and
                 s.st_uid==owner and s.st_nlink==1 and s.st_size==total and
                 written[:2]!=entry['identity'][:2],
                 'completed ESP.SIM writer identity changed during readback')
            capacity(target.parent,budget)
        readback_check();expected_sha=hash_fd(readback,total,readback_check)
        held.check();readback_check()
    finally:os.close(readback)
    held.check()
    return {'path':str(target),'bytes':total,'sha256':expected_sha},written


class SparseView:
    def __init__(self, raw=None, *, fd=None, size=None, check=lambda:None):
        if raw is not None:
            need(type(raw) is bytes,'sparse buffer bytes required')
            size=len(raw);self.get=lambda at,count:raw[at:at+count]
        else:
            need(type(fd) is int and type(size) is int,'owned sparse descriptor/extent required')
            self.get=lambda at,count:read_exact(fd,count,at,check)
        need(size>=64,'exact ESP.SIM header required')
        header=self.get(0,64);need(header[:8]==b'SHZSIMG1','exact ESP.SIM header required')
        block,reserved,count,reserved2,self.size=struct.unpack_from('<IIIIQ',header,8)
        need(block==BLOCK and reserved==reserved2==0 and 0<count<=1<<20 and
             0<self.size<=MAX_FILE and self.size%BLOCK==0,'bounded ESP.SIM geometry required')
        self.digest=header[32:64].hex();self.runs=[];at=64+count*16;last=0
        need(at<=size,'sparse table exceeds file');table=self.get(64,count*16)
        for i in range(count):
            first,number,zero=struct.unpack_from('<QII',table,i*16)
            need(zero==0 and number>0 and first>=last and first+number<=self.size//BLOCK and at+number*BLOCK<=size,'invalid sparse chunk extent/order')
            self.runs.append((first*BLOCK,(first+number)*BLOCK,at));at+=number*BLOCK;last=first+number
        need(at==size,'extra/missing sparse payload bytes');self.starts=[x[0] for x in self.runs]
    def read(self, at, count):
        need(0<=at and 0<=count and at+count<=self.size,'sparse read outside image')
        result=bytearray(count);end=at+count;i=max(0,bisect.bisect_right(self.starts,at)-1)
        while i<len(self.runs) and self.runs[i][0]<end:
            first,last,data=self.runs[i];left=max(at,first);right=min(end,last)
            if left<right:result[left-at:right-at]=self.get(data+left-first,right-left)
            i+=1
        return bytes(result)


def verify_sim(fd, size, expected, check):
    # Independent expansion reads the saved file, never the producer's chunks.
    view=SparseView(fd=fd,size=size,check=check);h=hashlib.sha256()
    need(view.size==expected['bytes'] and view.digest==expected['sha256'],'saved sparse header differs')
    for at in range(0,view.size,1<<20):check();h.update(view.read(at,min(1<<20,view.size-at)))
    need(h.hexdigest()==expected['sha256'],'independent expanded ESP SHA differs')


def ingest(request_path, request_sha, out, budget_bytes):
    request_path=path(str(request_path));out=path(str(out))
    need(type(budget_bytes) is int and 1<<20<=budget_bytes<=MAX_FILE,'explicit bounded export budget required')
    need(not out.exists() and out.parent.is_dir(),'fresh private output leaf required')
    need(not any((p/'.git').exists() for p in out.parents),'private ingestion output must be outside source checkouts')
    request_pin={'path':str(request_path),'bytes':request_path.stat().st_size,'sha256':request_sha}
    manifest_path=out/'manifest.json';owned=None;accepted=None;directory=None
    try:
        with Union() as artifacts:
            with Union() as inputs:
                request=inputs.json(request_pin);entry,lineage=validate_lineage(request,inputs)
                need(budget_bytes>=entry['pin']['bytes']+(4<<20),'full logical ESP plus metadata export budget required')
                capacity(out.parent,budget_bytes);out.mkdir(mode=0o700);owned=identity(out.stat())[:2]
                directory=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                def output_check():
                    path(str(out))
                    need(identity(os.fstat(directory))[:2]==identity(out.stat())[:2]==owned and
                         stat.S_IMODE(os.fstat(directory).st_mode)==0o700 and not out.is_symlink(), 'owned private output directory changed')
                inputs.guards.append(output_check);artifacts.guards.append(output_check)
                sim,sim_written=export_sim(entry,inputs,out/'ESP.SIM',budget_bytes-(4<<20))
                e=artifacts.add(sim,written_identity=sim_written)
                verify_sim(e['fd'],sim['bytes'],entry['pin'],artifacts.check)
                result={'schema':SCHEMA,'status':'PRIVATE_NATIVE_ESP_INPUT_EXPORTED_NOT_INSTALLED',
                        'private':True,'public_artifact':False,'redistribution':'PROHIBITED_PRIVATE_LICENSED_INPUT',
                        'boot_profile':'native-win98','source_request':request_pin,'lineage':lineage,'esp_sim':sim,
                        'ESP_geometry':'LBA0_SUPERFLOPPY_UNCHANGED_NOT_PARTITION_REBASED','first_lba':0,
                        'input_linux_read_leases':True,'inputs_before_after_full_SHA_match':True,
                        'independent_expanded_ESP_readback':True,'compiler_tool_closure_verified':False,
                        **{name:False for name in FALSE_FLAGS}}
                raw=(json.dumps(result,indent=2)+'\n').encode();need(len(raw)<=MAX_JSON,'bounded private manifest required')
                temporary=out/'.manifest.part';fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                try:
                    write_all(fd,raw);os.fsync(fd);manifest_written=identity(os.fstat(fd))
                finally:os.close(fd)
                mrow={'path':str(temporary),'bytes':len(raw),'sha256':sha(raw)}
                m=artifacts.add(mrow,written_identity=manifest_written)
                inputs.finish();artifacts.check();capacity(out,budget_bytes)
            # Mandatory original lease unlock/close has succeeded before admission.
            artifacts.check();need(read_exact(m['fd'],len(raw),0,artifacts.check)==raw,'final manifest bytes differ')
            os.link(temporary,manifest_path);accepted=identity(manifest_path.stat())[:2]
            os.unlink(temporary)
            # The held inode has one link again; no re-open through mutable path.
            artifacts.entries.pop(temporary)
            artifacts.entries[manifest_path]=dict(m,pin={'path':str(manifest_path),'bytes':len(raw),'sha256':sha(raw)},identity=identity(os.fstat(m['fd'])))
            os.fsync(directory)
            artifacts.check();capacity(out,budget_bytes)
        output_check();os.close(directory);directory=None
        return result
    except BaseException:
        # Retain partial data, invalidate only our accepted manifest inode.
        if accepted is not None and out.exists() and identity(out.stat())[:2]==owned and manifest_path.exists() and identity(manifest_path.stat())[:2]==accepted:
            manifest_path.unlink()
        if directory is not None:
            try:os.close(directory)
            except OSError:pass
        raise


def archive_entries(raw):
    need(type(raw) is bytes and 16<=len(raw)<=64<<20 and raw[:8]==b'SHZARC01','bounded installer SHZARC01 required')
    count,reserved=struct.unpack_from('<II',raw,8);need(reserved==0 and 0<count<=65536 and 16+count*136<=len(raw),'bounded installer archive table required')
    entries={};ranges=[];floor=16+count*136
    for i in range(count):
        row=raw[16+i*136:16+(i+1)*136];namebytes=row[:120];zero=namebytes.find(b'\0')
        need(zero>=1 and not any(namebytes[zero:]),'canonical terminated archive name required')
        name=namebytes[:zero].decode('ascii').replace('\\','/');parts=name.lstrip('/').split('/')
        need(all(v not in ('','.','..') and ':' not in v for v in parts),'archive traversal/stream refused')
        name='/'.join(parts).upper();offset,size=struct.unpack_from('<QQ',row,120)
        need(name not in entries and floor<=offset<=len(raw) and size<=len(raw)-offset,'duplicate/out-of-bounds installer entry')
        ranges.append((offset,offset+size));entries[name]=raw[offset:offset+size]
    ordered=sorted(ranges)
    need(all(left[1]<=right[0] for left,right in zip(ordered,ordered[1:])), 'overlapping installer entries')
    return entries


PRIVATE_MEMBERS=('WIN98','WINDOWS','WIN98CFG.BIN','W98PERS.BIN','VGACFG.BIN','VGAROM.BIN','W98INPT.BIN')


def _short_alias_of_private(part):
    """True for NAME~N[.EXT] where NAME is a 1..6 char prefix of a protected base and EXT matches.

    Conservative: refuses a possible DOS 8.3 alias; unrelated names (README~1.TXT) pass."""
    base,dot,ext=part.partition('.')
    if '.' in ext or '~' not in base:
        return False
    stem,tilde,num=base.rpartition('~')
    if not (stem and num.isdigit() and 1<=len(stem)<=6):
        return False
    for protected in PRIVATE_MEMBERS:
        pbase,pdot,pext=protected.partition('.')
        if pext==ext and pbase.startswith(stem) and (dot==pdot):
            return True
    return False


def private_member(name):
    """True when any path component names a private native/Windows member.

    Case, backslash separators, FAT trailing dot/space aliases, NTFS ':stream'/'::$DATA'
    suffixes and possible DOS 8.3 NAME~N aliases are folded/refused."""
    for part in str(name).replace('\\','/').split('/'):
        part=part.split(':',1)[0].rstrip(' .').upper()
        if part in PRIVATE_MEMBERS or _short_alias_of_private(part):
            return True
    return False


def reject_private(obj):
    if type(obj) is dict:
        need(('private' not in obj or obj['private'] is False) and ('public_artifact' not in obj or obj['public_artifact'] is True) and
             not str(obj.get('schema','')).startswith(('shizukuos.private-','shizukuos.native-payload-')) and
             obj.get('boot_profile') not in ('native-win98','win98-foundation') and
             'lineage' not in obj and 'original_source_disk' not in obj,'private/native payload cannot enter public media')
        for value in obj.values():reject_private(value)
    elif type(obj) is list:
        for value in obj:reject_private(value)


def public_sparse_members(view):
    """Inspect genuine FAT32 directory entries, including renamed ESP.SIM data.

    Public development images use this format. Unknown geometries are refused
    rather than interpreted as a private native image's public qualification.
    """
    b=view.read(0,512);need(b[510:]==b'\x55\xaa' and struct.unpack_from('<H',b,11)[0]==512,'signed public FAT32 ESP required')
    spc,reserved,fats=b[13],struct.unpack_from('<H',b,14)[0],b[16]
    total,sectors,root=struct.unpack_from('<I',b,32)[0],struct.unpack_from('<I',b,36)[0],struct.unpack_from('<I',b,44)[0]
    need(spc and not spc&(spc-1) and spc<=128 and reserved and fats in (1,2) and sectors and
         0<=view.size-total*512<64*512 and not struct.unpack_from('<H',b,17)[0] and not struct.unpack_from('<H',b,22)[0], 'public FAT32 geometry differs')
    if total*512<view.size:
        need(not any(view.read(total*512,view.size-total*512)),'public FAT32 trailing track padding differs')
    first=reserved+fats*sectors;clusters=(total-first)//spc
    need(65525<=clusters and (clusters+2)*4<=sectors*512 and sectors*512<=8<<20,'bounded public FAT32 cluster count required')
    fat=view.read(reserved*512,sectors*512);visited=set();names=[]
    def directory(prefix,cluster,depth):
        need(depth<=16,'public FAT directory depth exceeds bound')
        while cluster<0xffffff8:
            need(2<=cluster<clusters+2 and cluster not in visited and len(visited)<65536,'public FAT directory chain differs')
            visited.add(cluster);raw=view.read((first+(cluster-2)*spc)*512,spc*512)
            for at in range(0,len(raw),32):
                row=raw[at:at+32]
                if row[0]==0:return
                if row[0]==0xe5 or row[11]&8 or row[:11] in (b'.          ',b'..         '):continue
                name=row[:8].rstrip(b' ').decode('cp437');extension=row[8:11].rstrip(b' ').decode('cp437')
                name=(name+('.'+extension if extension else '')).upper();full=prefix+name;names.append(full)
                need(len(names)<=30000 and not private_member(name),'private native/Windows sparse ESP member refused')
                number=struct.unpack_from('<H',row,26)[0]|(struct.unpack_from('<H',row,20)[0]<<16)
                if row[11]&16:directory(full+'/',number,depth+1)
            cluster=struct.unpack_from('<I',fat,cluster*4)[0]&0xfffffff
    directory('',root,0);return names


def require_public_payload(manifest, receipt, install_bytes):
    """Admission helper; existing media caller wiring requires a separate ACK."""
    need(type(manifest) is dict and manifest.get('schema')=='shizukudos-install-manifest/1' and
         manifest.get('boot_profile') in ('desktop','self-test'),'public development installer kind required')
    reject_private(manifest);reject_private(receipt)
    entries=archive_entries(install_bytes);key='SHZ/SETUP/PAYLOAD/MANIFEST.JSON'
    need(key in entries,'embedded installer manifest required')
    embedded=json.loads(entries[key],object_pairs_hook=unique);reject_private(embedded)
    need(embedded==manifest,'embedded installer manifest differs from outer public manifest')
    work={'bytes':0,'members':0}
    def inspect(raw,depth):
        need(depth<=8,'nested public archive depth exceeds bound')
        work['bytes']+=len(raw);need(work['bytes']<=256<<20,'nested public archive byte work exceeds bound')
        children=archive_entries(raw)
        work['members']+=len(children);need(work['members']<=65536,'nested public archive member work exceeds bound')
        for name,data in children.items():
            need(not private_member(name),'private native/Windows installer member refused')
            if data.startswith(b'SHZARC01'):inspect(data,depth+1)
            elif data.startswith(b'SHZSIMG1'):
                view=SparseView(data);need(view.size<=512<<20,'native-size sparse ESP refused by development public profile')
                if name.endswith('/ESP.SIM'):
                    need(manifest.get('esp',{}).get('bytes')==view.size and manifest.get('esp',{}).get('sha256')==view.digest,'public sparse ESP differs from manifest')
                public_sparse_members(view)
            elif data.startswith(SZOU_MAGIC):
                need(False,'private original-userland SZOU stage refused from public media')
            elif name.endswith('.JSON'):
                need(len(data)<=MAX_JSON,'bounded embedded public metadata required')
                reject_private(json.loads(data,object_pairs_hook=unique))
    # Inspect recognized contents regardless of rename, including SYSTEM.ARC.
    inspect(install_bytes,0)
    return True


# ---------------------------------------------------------------------------
# Distinct explicit original-Windows-userland route (SZOU v1).
#
# The strict native ESP route above is unchanged and remains the CLI default.
# This route consumes only a private profile already produced by the existing
# original observer (tools/native_original_userland.py), re-runs that held
# observer over the same leased source disk, and stages the observed Windows
# directory into the SZOU manifest consumed by the guest native installer
# (shizukudos/win64/setup/native_install). It installs, boots and admits
# nothing; native_release_admission.py remains the separate release gate.
REPO = Path(__file__).resolve().parents[2]
ORIGINAL_REQUEST_SCHEMA = 'shizukuos.original-userland-stage-request.v1'
ORIGINAL_SCHEMA = 'shizukuos.private-original-userland-stage.v1'
ORIGINAL_PROFILE_SCHEMA = 'shizukuos.private-original-userland-profile.v1'
ORIGINAL_OBSERVER = REPO/'tools/native_original_userland.py'
ORIGINAL_READER = REPO/'shizukudos/win98_boot/prepare_replacement.py'
ORIGINAL_DISK_BYTES = 2 << 30
ORIGINAL_STAGE_NAME = 'ORIGUSER.SZO'
ORIGINAL_FALSE_FLAGS = FALSE_FLAGS + ('release_admitted', 'original_userland_booted')
# Agreed with guest-installer: .codex/handoff/original-userland-schema.md.
SZOU_MAGIC = b'SZOU'
SZOU_VERSION = 1
SZOU_HEADER = struct.Struct('<4sHHIIQ32s8s')   # 64 bytes
SZOU_ENTRY = struct.Struct('<260sIQQ32s8s')    # 320 bytes
SZOU_MAX_ENTRIES = 30000                       # observer inventory bound; guest bound is 65535
SZOU_ATTRIBUTES = 0x27                         # READONLY|HIDDEN|SYSTEM|ARCHIVE
SZOU_REFUSED = frozenset('<>:"/|?*')
# SZOU v2 = v1 bytes unchanged + append-only SZLN extension after the payload
# (header flag 1). SZLN carries the complete selected directory list and the
# original VFAT long names as validated UTF-16LE code units.
SZOU_VERSION_NAMES = 2
SZOU_FLAG_NAMES = 1
SZLN_MAGIC = b'SZLN'
SZLN_HEADER = struct.Struct('<4sHHII32s')      # 48 bytes
SZLN_RECORD = struct.Struct('<260sBBH512s8s')  # 784 bytes
SZLN_FILE, SZLN_DIRECTORY = 1, 2
LFN_REFUSED = frozenset('"*/:<>?\\|')
ORIGINAL_ROOT_DOS = frozenset({'IO.SYS', 'MSDOS.SYS', 'COMMAND.COM'})
assert SZOU_HEADER.size == 64 and SZOU_ENTRY.size == 320
assert SZLN_HEADER.size == 48 and SZLN_RECORD.size == 784


def szou_path(name):
    need(type(name) is str and 0<len(name)<=259 and all(c==' ' or '!'<=c<='~' for c in name),
         'SZOU v1 requires a bounded printable ASCII destination path')
    need(not SZOU_REFUSED.intersection(name) and
         all(v not in ('','.','..') and v[-1] not in ' .' for v in name.split('\\')),
         'unsafe SZOU destination path refused')
    return name


def szou_table(rows):
    """Return the canonical contiguous SZOU entry table and payload total."""
    need(type(rows) is list and 0<len(rows)<=SZOU_MAX_ENTRIES,'bounded nonempty SZOU entry table required')
    table=bytearray();seen=set();offset=0
    for row in rows:
        need(type(row) is dict and {'path','attributes','bytes','sha256'}<=set(row),'exact SZOU row required')
        name=szou_path(row['path']);folded=name.upper();attributes=row['attributes'];size=row['bytes']
        need(folded not in seen,'duplicate case-insensitive SZOU destination refused');seen.add(folded)
        need(type(attributes) is int and 0<=attributes and not attributes&~SZOU_ATTRIBUTES,'unsupported SZOU DOS attributes refused')
        need(type(size) is int and 0<=size<=MAX_FILE-offset,'SZOU payload extent overflow refused')
        need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'literal SZOU member SHA required')
        table+=SZOU_ENTRY.pack(name.encode('ascii'),attributes,size,offset,bytes.fromhex(row['sha256']),bytes(8))
        offset+=size
    ancestors={'\\'.join(p.split('\\')[:i]) for p in seen for i in range(1,p.count('\\')+1)}
    need(not seen&ancestors,'SZOU file path is also a directory prefix')
    return bytes(table),offset


def szou_header(table,count,total,version=SZOU_VERSION):
    need(version in (SZOU_VERSION,SZOU_VERSION_NAMES),'unknown SZOU version')
    flags=SZOU_FLAG_NAMES if version==SZOU_VERSION_NAMES else 0
    return SZOU_HEADER.pack(SZOU_MAGIC,version,SZOU_HEADER.size,count,flags,total,hashlib.sha256(table).digest(),bytes(8))


def lfn_units(name):
    """Validated Win98 VFAT long name -> UTF-16LE code units (lossless carry)."""
    need(type(name) is str and name not in ('.','..') and name[-1:] not in ('',' ','.') and
         all(c>=' ' and c not in LFN_REFUSED for c in name),'invalid Win98 long file name refused')
    try:units=name.encode('utf-16-le')
    except UnicodeEncodeError:raise ValueError('unpaired UTF-16 surrogate in long file name refused') from None
    need(2<=len(units)<=510,'long file name exceeds 255 UTF-16 units')
    return units


def lfn_checksum(short):
    total=0
    for b in short:total=(((total&1)<<7)+(total>>1)+b)&0xff
    return total


def lfn_name(pending,short):
    """Return the VFAT long name bound to a short entry, or None for none/orphan.

    Windows ignores LFN chains whose ordinal sequence or checksum does not
    bind to the following short entry; such orphans are counted, not used.
    A structurally bound name that violates the long-name policy is refused.
    """
    if not pending:return None
    count=len(pending)//32;parts=[pending[i*32:i*32+32] for i in range(count)]
    checksum=lfn_checksum(short[:11])
    if len(pending)%32 or not 1<=count<=20 or any(
            part[0]!=(count-i)|(0x40 if i==0 else 0) or part[11]!=15 or part[12]!=0 or
            part[13]!=checksum or part[26:28]!=b'\0\0' for i,part in enumerate(parts)):
        return False
    raw=b''.join(part[1:11]+part[14:26]+part[28:32] for part in reversed(parts))
    units=[raw[i:i+2] for i in range(0,len(raw),2)]
    if b'\0\0' in units:
        end=units.index(b'\0\0')
        if any(u!=b'\xff\xff' for u in units[end+1:]) or end<=13*(count-1):return False
        units=units[:end]
    try:name=b''.join(units).decode('utf-16-le')
    except UnicodeDecodeError:raise ValueError('unpaired UTF-16 surrogate in long file name refused') from None
    lfn_units(name);return name


def szou_names(rows,records):
    """Canonical SZLN records: complete directory list plus long names."""
    need(type(records) is list and 0<len(records)<=SZOU_MAX_ENTRIES,'bounded nonempty SZLN record list required')
    files={r['path'].upper():r['path'] for r in rows};raw=bytearray();kinds={};previous=None;siblings={}
    for record in records:
        need(type(record) is dict and set(record)=={'path','kind','attributes','long_name'},'exact SZLN record required')
        name=szou_path(record['path']);folded=name.upper();kind=record['kind'];attributes=record['attributes'];long=record['long_name']
        need(previous is None or previous<folded,'SZLN records must be uniquely sorted by folded path');previous=folded
        if kind==SZLN_FILE:need(files.get(folded)==name and attributes==0 and long is not None,'SZLN file record must name an SZOU entry')
        else:need(kind==SZLN_DIRECTORY and folded not in files and type(attributes) is int and 0<=attributes and
                  not attributes&~SZOU_ATTRIBUTES,'SZLN directory record invalid')
        kinds[folded]=kind;units=lfn_units(long) if long is not None else b''
        parent,_,leaf=folded.rpartition('\\')
        for alias in {leaf,*([long.upper()] if long is not None else [])}:
            need(siblings.setdefault((parent,alias),folded)==folded,'long/short sibling name collision refused')
        raw+=SZLN_RECORD.pack(name.encode('ascii'),kind,attributes,len(units)//2,units.ljust(512,b'\0'),bytes(8))
    for folded,name in files.items():
        parent,_,leaf=folded.rpartition('\\')
        need(siblings.setdefault((parent,leaf),folded)==folded,'long/short sibling name collision refused')
    every=set(files)|set(kinds)
    ancestors={'\\'.join(p.split('\\')[:i]) for p in every for i in range(1,p.count('\\')+1)}
    need(all(kinds.get(a)==SZLN_DIRECTORY for a in ancestors),'SZLN directory list incomplete')
    return bytes(raw)


def szou_image(rows,records=None):
    """Return (header+table, total, trailing SZLN bytes, version); v1 when records is None."""
    table,total=szou_table(rows)
    if records is None:return szou_header(table,len(rows),total)+table,total,b'',SZOU_VERSION
    ext=szou_names(rows,records)
    tail=SZLN_HEADER.pack(SZLN_MAGIC,1,SZLN_HEADER.size,len(records),0,hashlib.sha256(ext).digest())+ext
    return szou_header(table,len(rows),total,SZOU_VERSION_NAMES)+table,total,tail,SZOU_VERSION_NAMES


def szou_verify(fd,size,check,names_out=None):
    """Independently parse and fully hash a held SZOU stage; returns summary, rows.

    v2 SZLN records are appended to names_out when a list is supplied."""
    need(type(size) is int and SZOU_HEADER.size<=size<=MAX_FILE,'bounded SZOU stage required')
    magic,version,header,count,flags,total,table_sha,reserved=SZOU_HEADER.unpack(read_exact(fd,SZOU_HEADER.size,0,check))
    need(magic==SZOU_MAGIC and (version,flags) in ((SZOU_VERSION,0),(SZOU_VERSION_NAMES,SZOU_FLAG_NAMES)) and
         header==SZOU_HEADER.size and not any(reserved) and 0<count<=SZOU_MAX_ENTRIES,'exact SZOU v1/v2 header required')
    start=SZOU_HEADER.size+count*SZOU_ENTRY.size
    need(start+total<=size and (size-start==total if version==SZOU_VERSION else size-start-total>=SZLN_HEADER.size),
         'SZOU image length differs from header')
    table=read_exact(fd,count*SZOU_ENTRY.size,SZOU_HEADER.size,check)
    need(hashlib.sha256(table).digest()==table_sha,'SZOU entry table SHA differs')
    rows=[]
    for i in range(count):
        raw,attributes,length,offset,digest,tail=SZOU_ENTRY.unpack_from(table,i*SZOU_ENTRY.size)
        zero=raw.find(b'\0')
        need(zero>0 and not any(raw[zero:]) and not any(tail),'canonical SZOU entry required')
        rows.append({'path':raw[:zero].decode('ascii'),'attributes':attributes,'bytes':length,'sha256':digest.hex(),'offset':offset})
    # Rebuilding enforces paths, duplicates, attributes and contiguous offsets.
    need(szou_table(rows)==(table,total),'noncanonical SZOU entry table refused')
    for row in rows:
        h=hashlib.sha256()
        for at in range(0,row['bytes'],1<<20):
            h.update(read_exact(fd,min(1<<20,row['bytes']-at),start+row['offset']+at,check))
        need(h.hexdigest()==row['sha256'],'SZOU member payload SHA differs')
    summary={'entry_count':count,'total_payload_bytes':total,'entries_sha256':table_sha.hex()}
    if version==SZOU_VERSION_NAMES:
        at=start+total;magic,ext_version,ext_header,records,ext_flags,ext_sha=SZLN_HEADER.unpack(read_exact(fd,SZLN_HEADER.size,at,check))
        need(magic==SZLN_MAGIC and ext_version==1 and ext_header==SZLN_HEADER.size and ext_flags==0 and
             0<records<=SZOU_MAX_ENTRIES and size-at-SZLN_HEADER.size==records*SZLN_RECORD.size,'exact SZLN v1 extension required')
        ext=read_exact(fd,records*SZLN_RECORD.size,at+SZLN_HEADER.size,check)
        need(hashlib.sha256(ext).digest()==ext_sha,'SZLN record SHA differs')
        names=[]
        for i in range(records):
            raw,kind,attributes,units,long,tail=SZLN_RECORD.unpack_from(ext,i*SZLN_RECORD.size)
            zero=raw.find(b'\0')
            need(zero>0 and not any(raw[zero:]) and not any(tail) and units<=255 and not any(long[2*units:]),'canonical SZLN record required')
            try:name=long[:2*units].decode('utf-16-le') if units else None
            except UnicodeDecodeError:raise ValueError('unpaired UTF-16 surrogate in SZLN record') from None
            names.append({'path':raw[:zero].decode('ascii'),'kind':kind,'attributes':attributes,'long_name':name})
        need(szou_names([{'path':r['path']} for r in rows],names)==ext,'noncanonical SZLN extension refused')
        summary.update(names_records=records,names_sha256=ext_sha.hex(),
                       long_names=sum(r['long_name'] is not None for r in names),
                       directories=sum(r['kind']==SZLN_DIRECTORY for r in names))
        if names_out is not None:names_out.extend(names)
    need(not os.pread(fd,1,size),'SZOU stage extent grew')
    return summary,rows


def original_request(request):
    need(type(request) is dict and set(request)=={'schema','route','source_disk','windows_directory','boot_policy',
                                                  'producer_inputs','original_userland_profile'} and
         request['schema']==ORIGINAL_REQUEST_SCHEMA and request['route']=='original-userland',
         'exact original-userland stage request required')
    pin(request['source_disk']);pin(request['original_userland_profile'])
    need(request['source_disk']['bytes']==ORIGINAL_DISK_BYTES,'exact original 2 GiB disk required')
    need(request['original_userland_profile']['bytes']<=MAX_JSON,'bounded private observer profile required')
    need(request['boot_policy']=='shz.foundation=win98','explicit Windows foundation policy required')
    directory=request['windows_directory']
    need(type(directory) is str and re.fullmatch('[A-Z0-9_-]{1,8}',directory) and
         directory not in {'CON','PRN','AUX','NUL',*(p+str(n) for p in ('COM','LPT') for n in range(1,10))},
         'uppercase nondevice short Windows directory required')
    rows=request['producer_inputs']
    need(type(rows) is list and len(rows)==2 and all(type(r) is dict for r in rows) and
         [r.get('path') for r in rows]==[str(ORIGINAL_OBSERVER),str(ORIGINAL_READER)],
         'exact existing observer/reader producer pins required')
    for row in rows:
        pin(row);need(row['bytes']<=1<<20,'bounded producer source required')


def original_entries(reader,fd,geometry,check,files):
    """Bind each entry's DOS attribute byte and VFAT long name to the held inventory.

    Returns ({path: (attribute byte, long name or None)}, orphaned LFN chain count).
    The LFN bytes are already covered by the inventory metadata SHA.
    """
    volume=reader.Volume(fd,geometry,check);result={};orphans=[0]
    def directory(prefix,cluster,depth):
        need(depth<=32,'FAT directory nesting exceeds bound')
        if cluster:chunks=(volume.cluster(n) for n in volume.chain(cluster))
        else:chunks=[volume.read((geometry['start_lba']+geometry['reserved']+geometry['fats']*geometry['fat_sectors'])*512,
                                 geometry['root_sectors']*512)]
        pending=bytearray()
        for block in chunks:
            for at in range(0,len(block),32):
                row=block[at:at+32]
                if row[0]==0:
                    orphans[0]+=bool(pending);return
                if row[0]==0xe5:orphans[0]+=bool(pending);pending.clear();continue
                if row[11]==15:need(len(pending)<20*32,'unbounded LFN sequence');pending.extend(row);continue
                if row[11]&8 or row[:11] in (b'.          ',b'..         '):orphans[0]+=bool(pending);pending.clear();continue
                base=row[:8].rstrip(b' ').decode('cp437');extension=row[8:11].rstrip(b' ').decode('cp437')
                name=prefix+base+('.'+extension if extension else '');record=files.get(name)
                need(type(record) is dict and record.get('metadata_sha256')==reader.digest(bytes(pending)+row),
                     'original directory entry differs from held inventory')
                long=lfn_name(bytes(pending),row);pending.clear()
                if long is False:orphans[0]+=1;long=None
                result[name]=(row[11],long)
                if row[11]&16:
                    directory(name+'/',reader.u16(row,26)|((reader.u16(row,20)<<16) if geometry['fat_bits']==32 else 0),depth+1)
        orphans[0]+=bool(pending)
    directory('',geometry['root_cluster'] or 0,0)
    return result,orphans[0]


def ingest_original_userland(request_path, request_sha, out, budget_bytes):
    request_path=path(str(request_path));out=path(str(out))
    need(type(budget_bytes) is int and 1<<20<=budget_bytes<=MAX_FILE,'explicit bounded export budget required')
    need(not out.exists() and out.parent.is_dir(),'fresh private output leaf required')
    need(not any((p/'.git').exists() for p in out.parents),'private ingestion output must be outside source checkouts')
    request_pin={'path':str(request_path),'bytes':request_path.stat().st_size,'sha256':request_sha}
    manifest_path=out/'manifest.json';stage_path=out/ORIGINAL_STAGE_NAME;owned=None;accepted=None;directory=None
    try:
        with Union() as artifacts:
            with Union() as inputs:
                request=inputs.json(request_pin);original_request(request)
                # Execute the held reviewed bytes of the existing observer and
                # FAT reader; their current checkout epoch must match the pins.
                observer=held_module(inputs,request['producer_inputs'][0],sha(ORIGINAL_OBSERVER.read_bytes()),'held_original_userland_observer')
                reader=held_module(inputs,request['producer_inputs'][1],sha(ORIGINAL_READER.read_bytes()),'held_original_userland_fat_reader')
                need(observer.ROOT==REPO and observer.READER==ORIGINAL_READER,'held observer bound to another checkout')
                profile=inputs.json(request['original_userland_profile'])
                need(type(profile) is dict and set(profile)=={'schema','status','phase','source_disk','request','producer_inputs',
                     'boot_policy','observed_windows_path','observed_members','boot_sectors','source_before_after_match',
                     *observer.FLAGS} and profile.get('schema')==ORIGINAL_PROFILE_SCHEMA and
                     profile.get('status')=='ORIGINAL_USERLAND_SOURCE_OBSERVED_NOT_BOOTED' and
                     profile.get('phase')=='original-userland-legacy-adapter' and
                     profile.get('source_disk')==request['source_disk'] and
                     profile.get('producer_inputs')==request['producer_inputs'] and
                     profile.get('boot_policy')==request['boot_policy'] and
                     profile.get('source_before_after_match') is True and
                     all(profile.get(name) is False for name in observer.FLAGS) and
                     profile.get('observed_windows_path')=='C:\\'+request['windows_directory'],
                     'exact observed original-userland profile required')
                disk=inputs.add(request['source_disk'])
                def check():inputs.io_check(disk)
                observed=observer.observe(disk['fd'],ORIGINAL_DISK_BYTES,request['windows_directory'],reader,check)
                need(all(observed[k]==profile.get(k) for k in observed),'fresh original observation differs from private profile')
                # Exactly the seven members the existing observer requires: the
                # three root MS-DOS control members plus four Windows members.
                windows_members={request['windows_directory']+'/'+n for n in ('WIN.COM','SYSTEM.INI','SYSTEM/VMM32.VXD','IFSHLP.SYS')}
                need(set(observed['observed_members'])==ORIGINAL_ROOT_DOS|windows_members,'exact seven observed original members required')
                mbr=read_exact(disk['fd'],512,0,check)
                active=[mbr[446+i*16:462+i*16] for i in range(4) if mbr[446+i*16]==0x80]
                need(len(active)==1,'one original active partition required')
                vbr=read_exact(disk['fd'],512,struct.unpack_from('<I',active[0],8)[0]*512,check)
                need(sha(mbr)==observed['boot_sectors']['mbr']['sha256'] and sha(vbr)==observed['boot_sectors']['vbr']['sha256'],
                     'original boot sectors changed after observation')
                geometry=reader.inspect_geometry(mbr,vbr,ORIGINAL_DISK_BYTES)
                files=reader.inventory(disk['fd'],geometry,check)
                entries,orphans=original_entries(reader,disk['fd'],geometry,check,files)
                need(set(entries)==set(files),'original directory walk differs from held inventory')
                prefix=request['windows_directory']+'/'
                selected=sorted((n for n,r in files.items() if n.startswith(prefix) and r.get('directory') is not True),key=str.upper)
                folders=sorted((n for n,r in files.items() if (n==request['windows_directory'] or n.startswith(prefix)) and
                                r.get('directory') is True),key=str.upper)
                need(request['windows_directory'] in folders and windows_members<=set(selected),
                     'observed original Windows members absent from staged inventory')
                # ShizukuDOS replaces the DOS layer: root MS-DOS members stay a private control input.
                need(all(n.startswith(prefix) and n.upper() not in ORIGINAL_ROOT_DOS for n in selected),'root MS-DOS member in stage refused')
                for name in selected:
                    record=files[name]
                    need(set(record)=={'bytes','sha256','metadata_sha256','cluster'} and not entries[name][0]&16 and
                         record['sha256']==observed['observed_members'].get(name,record)['sha256'],
                         'staged original member differs from observation')
                rows=[{'path':n.replace('/','\\'),'attributes':entries[n][0],'bytes':files[n]['bytes'],
                       'sha256':files[n]['sha256']} for n in selected]
                records=sorted([{'path':n.replace('/','\\'),'kind':SZLN_DIRECTORY,'attributes':entries[n][0]&~16,'long_name':entries[n][1]}
                                for n in folders]+
                               [{'path':n.replace('/','\\'),'kind':SZLN_FILE,'attributes':0,'long_name':entries[n][1]}
                                for n in selected if entries[n][1] is not None],key=lambda r:r['path'].upper())
                implied={'\\'.join(r['path'].split('\\')[:i]) for r in rows for i in range(1,r['path'].count('\\')+1)}
                # v1 stays byte-identical when the tree needs no names/empty/attributed directories.
                plain=all(r['long_name'] is None and (r['kind']==SZLN_FILE or (not r['attributes'] and r['path'] in implied))
                          for r in records)
                head,total,tail,version=szou_image(rows,None if plain else records)
                stage_bytes=len(head)+total+len(tail)
                need(budget_bytes>=stage_bytes+(4<<20),'full SZOU stage plus metadata export budget required')
                capacity(out.parent,budget_bytes);out.mkdir(mode=0o700);owned=identity(out.stat())[:2]
                directory=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                def output_check():
                    path(str(out))
                    need(identity(os.fstat(directory))[:2]==identity(out.stat())[:2]==owned and
                         stat.S_IMODE(os.fstat(directory).st_mode)==0o700 and not out.is_symlink(),'owned private output directory changed')
                inputs.guards.append(output_check);artifacts.guards.append(output_check)
                fd=os.open(stage_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                try:
                    digest=hashlib.sha256();written=[0]
                    class Sink:
                        def write(self,raw):
                            need(written[0]+len(raw)<=stage_bytes,'SZOU stage exceeds declared extent')
                            write_all(fd,raw,check);digest.update(raw);written[0]+=len(raw);return len(raw)
                    sink=Sink();sink.write(head)
                    volume=reader.Volume(disk['fd'],geometry,check)
                    for name in selected:
                        # inventory() already refused crosslinks across the whole
                        # volume with one chain set; reset per member re-read.
                        volume.used=set();record=files[name]
                        need(volume.file(record['cluster'],record['bytes'],sink)==record['sha256'],'original member changed during staging')
                    sink.write(tail);need(written[0]==stage_bytes,'short SZOU stage write')
                    os.fsync(fd);stage_written=identity(os.fstat(fd))
                finally:os.close(fd)
                stage={'path':str(stage_path),'bytes':stage_bytes,'sha256':digest.hexdigest()}
                e=artifacts.add(stage,written_identity=stage_written)
                staged_names=[];summary,_=szou_verify(e['fd'],stage_bytes,lambda:artifacts.io_check(e),staged_names)
                need(version==SZOU_VERSION or staged_names==records,'SZLN readback differs from original names')
                result={'schema':ORIGINAL_SCHEMA,'status':'PRIVATE_ORIGINAL_USERLAND_STAGED_NOT_INSTALLED',
                        'route':'original-userland','private':True,'public_artifact':False,
                        'redistribution':'PROHIBITED_PRIVATE_LICENSED_INPUT','boot_profile':'win98-foundation',
                        'boot_policy':request['boot_policy'],'source_request':request_pin,
                        'original_userland_profile':request['original_userland_profile'],
                        'producer_inputs':request['producer_inputs'],'source_disk':request['source_disk'],
                        'observed_windows_path':observed['observed_windows_path'],'boot_sectors':observed['boot_sectors'],
                        'stage':dict(stage,format='SZOU',version=version,**summary),
                        'long_file_names':{'carried':'UTF-16LE' if version==SZOU_VERSION_NAMES else 'NONE_PRESENT',
                                           'orphaned_lfn_chains_ignored':orphans},
                        'excluded_root_dos_members':sorted(ORIGINAL_ROOT_DOS),
                        'input_linux_read_leases':True,'inputs_before_after_full_SHA_match':True,
                        'independent_SZOU_readback':True,'native_release_admission':'NOT_PERFORMED_SEPARATE_GATE',
                        **{name:False for name in ORIGINAL_FALSE_FLAGS}}
                raw=(json.dumps(result,indent=2)+'\n').encode();need(len(raw)<=MAX_JSON,'bounded private manifest required')
                temporary=out/'.manifest.part';fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                try:
                    write_all(fd,raw);os.fsync(fd);manifest_written=identity(os.fstat(fd))
                finally:os.close(fd)
                m=artifacts.add({'path':str(temporary),'bytes':len(raw),'sha256':sha(raw)},written_identity=manifest_written)
                inputs.finish();artifacts.check();capacity(out,budget_bytes)
            # Mandatory original lease unlock/close has succeeded before publication.
            artifacts.check();need(read_exact(m['fd'],len(raw),0,artifacts.check)==raw,'final manifest bytes differ')
            os.link(temporary,manifest_path);accepted=identity(manifest_path.stat())[:2]
            os.unlink(temporary);artifacts.entries.pop(temporary)
            artifacts.entries[manifest_path]=dict(m,pin={'path':str(manifest_path),'bytes':len(raw),'sha256':sha(raw)},identity=identity(os.fstat(m['fd'])))
            os.fsync(directory);artifacts.check();capacity(out,budget_bytes)
        output_check();os.close(directory);directory=None
        return result
    except BaseException:
        # Retain partial data for diagnosis; invalidate only our accepted manifest inode.
        if accepted is not None and out.exists() and identity(out.stat())[:2]==owned and manifest_path.exists() and identity(manifest_path.stat())[:2]==accepted:
            manifest_path.unlink()
        if directory is not None:
            try:os.close(directory)
            except OSError:pass
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True)
    p.add_argument('--request-sha256',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--budget-bytes',type=int,required=True)
    # The old strict DOS/native ESP schema stays the default route. The
    # original-userland route must be named explicitly; schemas never cross.
    p.add_argument('--route',choices=('native-esp','original-userland'),default='native-esp');a=p.parse_args()
    if a.route=='original-userland':
        result=ingest_original_userland(a.request,a.request_sha256,a.out,a.budget_bytes)
        print(json.dumps({'status':result['status'],'private_manifest':str(a.out/'manifest.json'),
                          'stage':str(a.out/ORIGINAL_STAGE_NAME),**{k:False for k in ORIGINAL_FALSE_FLAGS}}));return
    result=ingest(a.request,a.request_sha256,a.out,a.budget_bytes)
    print(json.dumps({'status':result['status'],'private_manifest':str(a.out/'manifest.json'),**{k:False for k in FALSE_FLAGS}}))


if __name__=='__main__':main()
