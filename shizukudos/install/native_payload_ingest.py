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
CONSTRUCTOR_SHA = 'ab17f400fb2678b4ae0432f644fa9c22b9445b2b673dc2e65db53ee828668277'
FAT_READER_SHA = 'c5941f761598107cfb408c5508ee8080a7c81113a1e37f91f72d49868d3d8387'
PROFILE_PRODUCER_SHA = '2261a9d290addc2611da19505c4867174ebb52fedea684d6f058c003d055f1e0'
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
        for guard in self.guards:guard()
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
    names={'dos_lines','installed_paths','require_file','locale_lines'}
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    need({n.name for n in functions}==names and len(functions)==len(names),'exact reviewed startup policy functions required')
    policy={'need':need,'re':re}
    held.check();exec(compile(ast.Module(body=functions,type_ignores=[]),row['path'],'exec'),policy);held.check()
    return policy


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
    locale = source.get('locale', {}); country,nls = locale.get('country'),locale.get('nls')
    need(type(country) is list and type(nls) is list and len(country)<=1 and len(nls)<=1 and
         (not country or nls), 'observed locale arrays required; COUNTRY-only startup refused')
    for line in country+nls:
        need(type(line) is str and len(line) <= 250 and all(32<=ord(c)<=126 for c in line) and not any(c in line for c in '&|<>%'), 'bounded observed locale line required')
    windows = selected[3:]
    config = ('DEVICE=C:\\HIMEMX.EXE /VERBOSE\r\nDEVICE='+selected+'\\IFSHLP.SYS\r\nDOS=HIGH\r\nFILES=30\r\nBUFFERS=20\r\nSHELL=C:\\COMMAND.COM C:\\ /E:512 /P\r\n'+''.join(v+'\r\n' for v in country)).encode('ascii')
    auto = ('@ECHO OFF\r\nSET COMSPEC=C:\\COMMAND.COM\r\nSET windir='+selected+'\r\nSET PATH='+selected+';'+selected+'\\COMMAND;C:\\\r\nC:\r\nCD \\'+windows+'\r\n'+''.join(v+'\r\n' for v in nls)+selected+'\\WIN.COM\r\n').encode('ascii')
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
    for name,row in before.items():
        if name not in rows: need(after.get(name)==row, 'unrelated original Windows/private member changed')
    observed_windows=source.get('observed_members')
    required_windows={windows+'/'+name for name in ('WIN.COM','SYSTEM.INI','SYSTEM/VMM32.VXD','IFSHLP.SYS')}
    if country or nls:required_windows|={windows+'/COUNTRY.SYS',windows+'/COMMAND/NLSFUNC.EXE'}
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
                need(len(names)<=30000 and name not in ('WINDOWS','WIN98','WIN98CFG.BIN','W98PERS.BIN','VGACFG.BIN','VGAROM.BIN'),'private native/Windows sparse ESP member refused')
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
            need(not any(part in ('WIN98','WINDOWS','WIN98CFG.BIN','W98PERS.BIN','VGACFG.BIN','VGAROM.BIN') for part in name.split('/')),'private native/Windows installer member refused')
            if data.startswith(b'SHZARC01'):inspect(data,depth+1)
            elif data.startswith(b'SHZSIMG1'):
                view=SparseView(data);need(view.size<=512<<20,'native-size sparse ESP refused by development public profile')
                if name.endswith('/ESP.SIM'):
                    need(manifest.get('esp',{}).get('bytes')==view.size and manifest.get('esp',{}).get('sha256')==view.digest,'public sparse ESP differs from manifest')
                public_sparse_members(view)
            elif name.endswith('.JSON'):
                need(len(data)<=MAX_JSON,'bounded embedded public metadata required')
                reject_private(json.loads(data,object_pairs_hook=unique))
    # Inspect recognized contents regardless of rename, including SYSTEM.ARC.
    inspect(install_bytes,0)
    return True


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True)
    p.add_argument('--request-sha256',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--budget-bytes',type=int,required=True);a=p.parse_args()
    result=ingest(a.request,a.request_sha256,a.out,a.budget_bytes)
    print(json.dumps({'status':result['status'],'private_manifest':str(a.out/'manifest.json'),**{k:False for k in FALSE_FLAGS}}))


if __name__=='__main__':main()
