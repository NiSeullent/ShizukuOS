#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original disposable QA working copies; no VM launch or checkpoint writeback.

All mutations require the caller's exclusive lab lock. record_stopped(), seal()
and discard() additionally require an explicit guard callback which must prove
that no owned process can access the RAM image and raise on uncertainty. The
callback runs again at publication/deletion boundaries. The supervisor owns PID,
command and running-state evidence; this module does not claim to observe them.

The verified baseline/current pointer is never written. Stopped RAM is retained
until bounded externally collected evidence is durably sealed and its exact
manifest hash is explicitly supplied to discard(). Unknown objects survive.
An absent/partial image interrupted during initial restore remains pending for
explicit recovery; no method treats it as a completed or discardable trial.
Stopped bytes may be an intentionally failed guest filesystem: only the initial
baseline receives qemu-img validation; sealing records the final bytes as found.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

import base_archive as b
import packed as p
import storage as s

RAM_ROOT=Path('/dev/shm')
RAM_PREFIX='win98-modern-private-qa-'
SCHEMA='ntw.lab.qa-trial.v1'
EVIDENCE_SCHEMA='ntw.lab.qa-evidence.v1'
EVIDENCE_CAP=16*s.MIB
EVIDENCE_FILES=32
RECORD_CAP=65536
NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
TOKEN=re.compile(r'[A-Za-z0-9_-]{1,80}')
HASH=re.compile(r'[0-9a-f]{64}')
STATES=('preparing','ready','stopped_awaiting_evidence','sealing','evidence_saved','discarding','discarded')
IMMUTABLE=('schema','version','mode','token','directory','working_disk','original_disk',
           'baseline_pointer','baseline_pointer_sha256','baseline_pointer_identity',
           'baseline_archive_identity','base_identity','base_sources','directory_identity','evidence_directory_identity',
           'changes_are_disposable')


def _path(value):
    path=Path(value)
    if (not path.is_absolute() or '..' in path.parts or
            any(part.is_symlink() for part in (path,*path.parents))):
        raise RuntimeError('Canonical paths without symlink components are required')
    return path


def _identity(info):
    return {'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'links':info.st_nlink,
            'bytes':info.st_size,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}


def _file(path,cap):
    path=_path(path)
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>cap:
        raise RuntimeError('Expected one bounded, unaliased regular file')
    digest=hashlib.sha256();count=0
    with p._input(path,cap) as stream:
        for block in iter(lambda:stream.read(s.MIB),b''):
            count+=len(block)
            if count>cap:raise RuntimeError('Input grew beyond its byte bound')
            digest.update(block)
    after=path.lstat()
    if _identity(before)!=_identity(after) or count!=before.st_size:
        raise RuntimeError('Input identity changed during reading')
    return {'bytes':count,'sha256':digest.hexdigest(),'identity':_identity(after)}


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise RuntimeError('Duplicate journal key')
        result[key]=value
    return result


def _json(path):
    observed=_file(path,RECORD_CAP)
    data=Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest()!=observed['sha256'] or _file(path,RECORD_CAP)!=observed:
        raise RuntimeError('Journal changed during reading')
    value=json.loads(data,object_pairs_hook=_pairs,
                     parse_constant=lambda x:(_ for _ in ()).throw(RuntimeError('Nonfinite journal value')))
    if not isinstance(value,dict):raise RuntimeError('Journal must be an object')
    return value,observed


def _directory_identity(path):
    value=path.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_mode&0o077 or value.st_uid!=os.getuid():
        raise RuntimeError('Expected a private owned directory')
    return {'device':value.st_dev,'inode':value.st_ino,'mode':value.st_mode,'uid':value.st_uid}


def _directory(path,expected,absent=False):
    if (not isinstance(expected,dict) or set(expected)!={'device','inode','mode','uid'} or
            any(type(value) is not int or value<0 for value in expected.values())):
        raise RuntimeError('Missing directory identity')
    if not os.path.lexists(path) and absent:return
    if _directory_identity(path)!=expected:raise RuntimeError('Owned directory was replaced')


def _encoded(value):
    data=(json.dumps(value,indent=2,allow_nan=False)+'\n').encode()
    if len(data)>RECORD_CAP:raise RuntimeError('QA JSON exceeds its exact serialized byte bound')
    return data


def _publish(path,value,previous=None):
    """Bounded guarded atomic JSON publication; initial records never overwrite."""
    path=_path(path);data=_encoded(value)
    reserve=s.ROOT_RESERVE+s.WRITE_MARGIN
    if p.shutil.disk_usage(path.parent).free<reserve+p.allocation_bound(len(data)):
        raise RuntimeError('Insufficient normal JSON publication headroom')
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.tmp-',dir=path.parent)
    temporary=Path(name);owned=os.fstat(fd)
    try:
        with os.fdopen(fd,'wb',buffering=0) as output:
            pending=memoryview(data);position=0
            while pending:
                extra=p.allocation_bound(position+len(pending))-p.allocation_bound(position)
                if p.shutil.disk_usage(path.parent).free<reserve+extra:
                    raise RuntimeError('Normal disk reserve would be crossed during JSON publication')
                count=output.write(pending)
                if count is None or count<=0:raise RuntimeError('JSON output made no progress')
                position+=count;pending=pending[count:]
            os.fsync(output.fileno())
        if previous is None:b._rename_new(temporary,path)
        else:
            if _file(path,RECORD_CAP)!=previous:raise RuntimeError('QA journal changed before transition')
            os.replace(temporary,path)
        s.fsync_directory(path.parent)
    finally:
        if os.path.lexists(temporary):
            now=temporary.lstat()
            if (now.st_dev,now.st_ino)==(owned.st_dev,owned.st_ino):
                temporary.unlink();s.fsync_directory(path.parent)
    return _file(path,RECORD_CAP)


def locations(record):
    try:
        original=b._original(record['original_disk'])
        directory=_path(record['directory']);working=_path(record['working_disk']);token=record['token']
    except (KeyError,TypeError,ValueError) as error:
        raise RuntimeError('Missing QA ownership paths') from error
    if (record.get('schema')!=SCHEMA or type(record.get('version')) is not int or record['version']!=1 or
            record.get('mode')!='qa-trial' or record.get('status') not in STATES or
            record.get('changes_are_disposable') is not True or
            not isinstance(token,str) or not TOKEN.fullmatch(token) or directory.parent!=RAM_ROOT or
            directory.name!=RAM_PREFIX+token or working!=directory/'install-disk.qcow2'):
        raise RuntimeError('Unknown QA journal ownership')
    _directory(directory,record.get('directory_identity'),absent=True)
    journal=original.parent/('qa-trial-'+token+'.json')
    evidence=original.parent/('qa-evidence-'+token)
    _path(journal);_path(evidence)
    _directory(evidence,record.get('evidence_directory_identity'))
    return working,original,directory,journal,evidence


def load_record(path):
    record,_=_json(path)
    if locations(record)[3]!=Path(path):raise RuntimeError('QA journal name disagrees with ownership')
    return record


def pending_journals(directory):
    pending=[]
    for path in Path(directory).glob('qa-trial-*.json'):
        record=load_record(path);working,_,ram,_,_=locations(record)
        if record['status']!='discarded' or os.path.lexists(working) or os.path.lexists(ram):pending.append(path)
    return pending


def _reload(record):
    journal=locations(record)[3]
    saved,observed=_json(journal);locations(saved)
    if any(record.get(key)!=saved.get(key) for key in IMMUTABLE):
        raise RuntimeError('QA journal differs from the requested owner')
    record.clear();record.update(saved)
    return observed


def _save(record,previous):
    journal=locations(record)[3]
    if _file(journal,RECORD_CAP)!=previous:raise RuntimeError('QA journal changed before transition')
    return _publish(journal,record,previous)


def _base_sources(original):
    # A full base decode is done at prepare. Every later boundary pins exactly
    # those verified compressed/raw bytes and their identities, without decoding
    # the unchanged archived base once per evidence file.
    result={'raw':_file(original,p.RAW_CAP) if os.path.lexists(original) else None,
            'pointer':None,'archive':None}
    if b.has_archive(original):
        pointer=b._load(original)
        result['pointer']=_file(b.pointer_path(original),RECORD_CAP)
        result['archive']=_file(pointer['archive'],p.ARCHIVE_CAP)
    elif result['raw'] is None:raise RuntimeError('Preserved original base is absent')
    return result


def _baseline(record):
    _,original,_,_,_=locations(record)
    pointer,checksum=p._load_pointer(original)
    if (checksum!=record['baseline_pointer_sha256'] or pointer!=record['baseline_pointer'] or
            _file(p.pointer_path(original),RECORD_CAP)['identity']!=record['baseline_pointer_identity']):
        raise RuntimeError('Reviewed baseline pointer changed')
    if _base_sources(original)!=record['base_sources']:
        raise RuntimeError('Preserved original base changed')
    actual=_file(pointer['archive'],p.ARCHIVE_CAP)
    if (actual['identity']!=record['baseline_archive_identity'] or
            actual['sha256']!=pointer['archive_sha256'] or actual['bytes']!=pointer['archive_bytes']):
        raise RuntimeError('Immutable baseline archive changed')


def _guard(record,guard):
    if not callable(guard):raise RuntimeError('Explicit stopped-process guard is required')
    if guard(copy.deepcopy(record)) is False:raise RuntimeError('Stopped-process guard refused operation')
    _baseline(record)


def prepare(original,expected_pointer_sha256,checkpoint=lambda stage:None):
    """Restore the reviewed packed baseline without reserving/writing a new archive."""
    original=b._original(original)
    if not isinstance(expected_pointer_sha256,str) or not HASH.fullmatch(expected_pointer_sha256):
        raise RuntimeError('Reviewed baseline pointer SHA-256 is required')
    if pending_journals(original.parent):raise RuntimeError('A retained QA trial requires recovery first')
    if s.pending_journals(original.parent) or p.pending_journals(original.parent):
        raise RuntimeError('Unfinished persistent working copy blocks QA preparation')
    p.check_headroom(p.available_memory(),p.shutil.disk_usage(original.parent).free,p.shutil.disk_usage(RAM_ROOT).free)
    pointer,checksum=p._load_pointer(original)
    if pointer is None or checksum!=expected_pointer_sha256:raise RuntimeError('Reviewed baseline pointer does not match')
    base_sources=_base_sources(original)
    identity=p.base_identity(original)
    if identity['raw_sha256']!=pointer['original_sha256']:raise RuntimeError('Baseline original identity disagrees')
    pointer_file=_file(p.pointer_path(original),RECORD_CAP)
    archive_file=_file(pointer['archive'],p.ARCHIVE_CAP)
    if archive_file['sha256']!=pointer['archive_sha256'] or archive_file['bytes']!=pointer['archive_bytes']:
        raise RuntimeError('Baseline archive differs from its pointer')
    if pointer_file['sha256']!=checksum:raise RuntimeError('Baseline pointer changed during capture')
    p.decode(pointer['archive'],expected=pointer)
    if (_file(p.pointer_path(original),RECORD_CAP)!=pointer_file or
            _file(pointer['archive'],p.ARCHIVE_CAP)!=archive_file or _base_sources(original)!=base_sources):
        raise RuntimeError('Baseline changed during preparation')
    p.check_headroom(p.available_memory(),p.shutil.disk_usage(original.parent).free,p.shutil.disk_usage(RAM_ROOT).free)
    directory=Path(tempfile.mkdtemp(prefix=RAM_PREFIX,dir=RAM_ROOT));directory.chmod(0o700)
    token=directory.name.removeprefix(RAM_PREFIX)
    evidence=original.parent/('qa-evidence-'+token)
    evidence.mkdir(mode=0o700);s.fsync_directory(evidence.parent)
    record={'schema':SCHEMA,'version':1,'mode':'qa-trial','status':'preparing','token':token,
            'directory':str(directory),'working_disk':str(directory/'install-disk.qcow2'),
            'original_disk':str(original),'baseline_pointer':pointer,'baseline_pointer_sha256':checksum,
            'baseline_pointer_identity':pointer_file['identity'],'baseline_archive_identity':archive_file['identity'],
            'base_identity':identity,'base_sources':base_sources,'changes_are_disposable':True,
            'directory_identity':_directory_identity(directory),
            'evidence_directory_identity':_directory_identity(evidence)}
    working,_,_,journal,_=locations(record)
    previous=_publish(journal,record)
    checkpoint('prepared_journal');_baseline(record)
    p.decode(pointer['archive'],working,expected=pointer);s.check_qcow(working)
    checkpoint('working_restored');_baseline(record)
    record['status']='ready';_save(record,previous)
    checkpoint('ready')
    return record


def record_stopped(record,*,guard,checkpoint=lambda stage:None):
    previous=_reload(record);_guard(record,guard)
    working=locations(record)[0]
    if record['status'] in ('sealing','evidence_saved','discarding','discarded'):
        raise RuntimeError('QA evidence/discard already started')
    if record['status']=='preparing':
        # A partial or absent initial image remains for explicit recovery. A
        # complete verified baseline is safe to record after a failed launch.
        raw=_file(working,p.RAW_CAP)
        if raw['sha256']!=record['baseline_pointer']['raw_sha256'] or raw['bytes']!=record['baseline_pointer']['raw_bytes']:
            raise RuntimeError('Incomplete initial QA restore retained')
    s.check_extent(working)
    stopped=_file(working,p.RAW_CAP)
    if record.get('stopped_image') and record['stopped_image']!=stopped:
        raise RuntimeError('Previously stopped QA image changed')
    checkpoint('stopped_image_hashed');_guard(record,guard)
    if _file(working,p.RAW_CAP)!=stopped:raise RuntimeError('QA image changed before stopped receipt')
    record.update(status='stopped_awaiting_evidence',stopped_image=stopped)
    _save(record,previous);checkpoint('stopped_recorded')
    return record


def _stopped(record):
    working=locations(record)[0]
    if not isinstance(record.get('stopped_image'),dict) or _file(working,p.RAW_CAP)!=record['stopped_image']:
        raise RuntimeError('Stopped QA image bytes or identity changed')


def _sources(record,evidence_paths):
    if not isinstance(evidence_paths,dict) or not 1<=len(evidence_paths)<=EVIDENCE_FILES:
        raise RuntimeError('One to32 bounded external evidence files are required')
    working,original,_,journal,directory=locations(record)
    entries={};total=0
    if any(not isinstance(name,str) for name in evidence_paths):raise RuntimeError('Invalid evidence filename')
    for name,value in sorted(evidence_paths.items()):
        if not isinstance(name,str) or not NAME.fullmatch(name) or name=='manifest.json':
            raise RuntimeError('Invalid evidence filename')
        path=_path(value)
        if (path in (working,original,journal,p.pointer_path(original)) or
                path==Path(record['baseline_pointer']['archive']) or directory==path or directory in path.parents):
            raise RuntimeError('Evidence must be external to trial/control objects')
        observed=_file(path,EVIDENCE_CAP);total+=observed['bytes']
        if total>EVIDENCE_CAP:raise RuntimeError('Collected evidence exceeds16MiB')
        entries[name]={'source':str(path),**observed}
    return entries


def _evidence(record):
    directory=locations(record)[4]
    spec=record.get('evidence_spec')
    if not isinstance(spec,dict) or not 1<=len(spec)<=EVIDENCE_FILES:raise RuntimeError('Missing sealed evidence specification')
    total=0
    for name,item in spec.items():
        if (not isinstance(name,str) or not NAME.fullmatch(name) or name=='manifest.json' or
                not isinstance(item,dict) or set(item)!={'source','bytes','sha256','identity'} or
                type(item['bytes']) is not int or not 0<=item['bytes']<=EVIDENCE_CAP or
                not isinstance(item['sha256'],str) or not HASH.fullmatch(item['sha256'])):
            raise RuntimeError('Malformed evidence specification')
        total+=item['bytes']
    if total>EVIDENCE_CAP:raise RuntimeError('Sealed evidence exceeds its aggregate byte bound')
    expected=set(spec)|{'manifest.json'}
    if {x.name for x in directory.iterdir()}!=expected:raise RuntimeError('Unknown/missing evidence objects retained')
    for name,wanted in spec.items():
        actual=_file(directory/name,EVIDENCE_CAP)
        if actual['sha256']!=wanted['sha256'] or actual['bytes']!=wanted['bytes']:
            raise RuntimeError('Sealed evidence changed')
    manifest,observed=_json(directory/'manifest.json')
    wanted={'schema':EVIDENCE_SCHEMA,'trial_token':record['token'],
            'baseline_pointer_sha256':record['baseline_pointer_sha256'],
            'stopped_image':record['stopped_image'],'files':spec}
    if manifest!=wanted or observed['sha256']!=record.get('evidence_sha256'):
        raise RuntimeError('Evidence manifest differs from the reviewed receipt')
    return observed['sha256']


def seal(record,evidence_paths,*,guard,checkpoint=lambda stage:None):
    previous=_reload(record);_guard(record,guard)
    if record['status'] in ('evidence_saved','discarding','discarded'):
        _evidence(record)
        return record
    if record['status'] not in ('stopped_awaiting_evidence','sealing'):raise RuntimeError('Record a stopped trial before sealing')
    _stopped(record);spec=_sources(record,evidence_paths)
    if record.get('evidence_spec') and record['evidence_spec']!=spec:raise RuntimeError('Collected evidence source changed during sealing')
    if record['status']!='sealing':
        record.update(status='sealing',evidence_spec=spec);previous=_save(record,previous)
        checkpoint('sealing_recorded')
    directory=locations(record)[4]
    expected=set(spec)|{'manifest.json'}
    if any(path.name not in expected for path in directory.iterdir()):raise RuntimeError('Unknown evidence object retained')
    total=sum(value['bytes'] for value in spec.values())
    if p.shutil.disk_usage(directory.parent).free<s.ROOT_RESERVE+s.WRITE_MARGIN+sum(p.allocation_bound(v['bytes']) for name,v in spec.items() if not os.path.lexists(directory/name))+RECORD_CAP:
        raise RuntimeError('Insufficient normal128MiB evidence publication headroom')
    if total>EVIDENCE_CAP:raise RuntimeError('Collected evidence exceeds16MiB')
    for name,wanted in spec.items():
        source=Path(wanted['source']);destination=directory/name
        if _file(source,EVIDENCE_CAP)!={key:wanted[key] for key in ('bytes','sha256','identity')}:
            raise RuntimeError('External evidence changed before copy')
        if os.path.lexists(destination):
            actual=_file(destination,EVIDENCE_CAP)
            if actual['bytes']!=wanted['bytes'] or actual['sha256']!=wanted['sha256']:
                raise RuntimeError('Unknown evidence partial retained')
        else:
            with p._input(source,EVIDENCE_CAP) as stream,p._Output(destination,s.ROOT_RESERVE+s.WRITE_MARGIN+RECORD_CAP) as output:
                for block in iter(lambda:stream.read(s.MIB),b''):output.write(block)
            actual=_file(destination,EVIDENCE_CAP)
            if actual['bytes']!=wanted['bytes'] or actual['sha256']!=wanted['sha256']:
                raise RuntimeError('Copied evidence differs')
            s.fsync_directory(directory)
        checkpoint('evidence_copied');_guard(record,guard);_stopped(record)
    if _sources(record,evidence_paths)!=spec:raise RuntimeError('Evidence sources changed before manifest publication')
    manifest={'schema':EVIDENCE_SCHEMA,'trial_token':record['token'],
              'baseline_pointer_sha256':record['baseline_pointer_sha256'],'stopped_image':record['stopped_image'],'files':spec}
    target=directory/'manifest.json'
    if target.exists():
        if _json(target)[0]!=manifest:raise RuntimeError('Unknown evidence manifest retained')
    else:_publish(target,manifest)
    checkpoint('evidence_manifest_published');_guard(record,guard);_stopped(record)
    record.update(status='evidence_saved',evidence_sha256=_file(target,RECORD_CAP)['sha256'])
    _evidence(record);_save(record,previous);checkpoint('evidence_saved')
    return record


def discard(record,reviewed_evidence_sha256,*,guard,checkpoint=lambda stage:None):
    previous=_reload(record);_guard(record,guard)
    if (not isinstance(reviewed_evidence_sha256,str) or not HASH.fullmatch(reviewed_evidence_sha256) or
            record.get('evidence_sha256')!=reviewed_evidence_sha256):
        raise RuntimeError('Exact reviewed evidence SHA-256 is required for discard')
    if record['status'] not in ('evidence_saved','discarding','discarded'):raise RuntimeError('Evidence is not durably sealed')
    _evidence(record)
    working,_,directory,_,_=locations(record)
    if record['status']=='discarded':
        if os.path.lexists(working) or os.path.lexists(directory):raise RuntimeError('Unexpected RAM object after discard retained')
        return record
    if record['status']=='evidence_saved':
        _stopped(record)
        record['status']='discarding';previous=_save(record,previous);checkpoint('discarding_recorded')
    _guard(record,guard);_evidence(record)
    if directory.exists() and {x.name for x in directory.iterdir()}-{'install-disk.qcow2'}:
        raise RuntimeError('Unknown RAM children retained')
    if os.path.lexists(working):
        _stopped(record);_guard(record,guard);_evidence(record);_stopped(record)
        if {x.name for x in directory.iterdir()}-{'install-disk.qcow2'}:
            raise RuntimeError('Unknown RAM children retained')
        if _file(locations(record)[3],RECORD_CAP)!=previous:raise RuntimeError('QA journal changed before discard')
        working.unlink();s.fsync_directory(directory);checkpoint('ram_unlinked')
    if directory.exists():
        _directory(directory,record['directory_identity'])
        directory.rmdir();s.fsync_directory(directory.parent)
    checkpoint('ram_removed');_guard(record,guard);_evidence(record)
    record['status']='discarded';_save(record,previous);checkpoint('discarded_recorded')
    return record
