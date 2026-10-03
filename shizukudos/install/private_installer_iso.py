#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private native ISO finalizer; live producer custody, never receipt approval."""
from contextlib import ExitStack, contextmanager
from argparse import Namespace
import gzip
import configparser
import fcntl
import resource
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

import native_release_admission as admission
import native_capacity_profile as capacity
import private_installer_package as package

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import shizuku_se_media as media
import build_shizuku_se_iso as iso
MIB=1<<20
RESERVE=17<<30
# Corresponding sources of the DOS/native target and known Win64 Wine cohort.
# Noto is shipped unmodified under OFL; the original licence is sufficient.
GIT_UPSTREAMS=('freedos-kernel','freedos-freecom','csmwrap','wine','freetype','noto-fonts')
SOURCE_ONLY_MAX=1<<30


def need(condition,message):
    if not condition:raise ValueError(message)


def _load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def _row(custody,path,expected=None):
    row=admission.file_pin(custody._ingest,Path(path))
    need(expected is None or row['sha256']==expected,'independent pinned public input differs')
    custody._held.add(row)
    return row


def _read(custody,row,maximum=SOURCE_ONLY_MAX):
    need(0<row['bytes']<=maximum,'bounded held media input required')
    entry=custody._held.entries[custody._ingest.path(row['path'])]
    output=bytearray()
    for offset in range(0,row['bytes'],MIB):
        output+=custody._ingest.read_exact(entry['fd'],min(MIB,row['bytes']-offset),offset,
                                          lambda:custody._held.io_check(entry))
    custody.check()
    return bytes(output)


def _retain(custody,path):
    path=Path(path);os.chmod(path,0o400)
    with path.open('rb') as stream:
        state=os.fstat(stream.fileno());sha=hashlib.file_digest(stream,'sha256').hexdigest()
    row={'path':str(path),'bytes':state.st_size,'sha256':sha}
    custody.retain_output(row,custody._ingest.identity(state))
    return row


def _directory(custody,path):
    path=Path(path)
    need(path.is_absolute() and path.resolve()==path and not path.exists() and
         path.parent.is_dir() and not any((p/'.git').exists() for p in path.parents),
         'fresh canonical private ISO directory outside Git required')
    path.mkdir(mode=0o700);owned=custody._ingest.identity(path.stat())[:2]
    def guard():
        state=path.stat()
        need(not path.is_symlink() and custody._ingest.identity(state)[:2]==owned and
             state.st_uid==os.getuid() and stat.S_IMODE(state.st_mode)==0o700,
             'private ISO directory custody changed')
    custody.guard(guard);guard()
    return path


def _git(tree,*args):
    return subprocess.check_output(['git','-C',str(tree),*args],stderr=subprocess.PIPE)


def _git_archive(tree,prefix,commit):
    need(_git(tree,'rev-parse','HEAD').decode().strip()==commit,'public upstream/source commit differs')
    raw=_git(tree,'archive','--format=tar','--prefix='+prefix+'/',commit)
    need(len(raw)<=SOURCE_ONLY_MAX,'public Git source archive exceeds bounded memory')
    return raw


def _gz(raw):
    output=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as handle:handle.write(raw)
    return output.getvalue()


def _deb_payload(custody,row):
    # Parse the fixed SHA-admitted package directly from its original held FD.
    raw=_read(custody,row,64*MIB)
    need(raw[:8]==b'!<arch>\n','Debian ar magic required')
    offset=8;members={}
    while offset<len(raw):
        header=raw[offset:offset+60]
        need(len(header)==60 and header[58:]==b'`\n','bounded Debian ar header required')
        name=header[:16].decode('ascii').strip().removesuffix('/')
        size_text=header[48:58].decode('ascii').strip()
        need(size_text.isdecimal() and name not in members,'unique decimal Debian ar extent required')
        size=int(size_text);offset+=60
        need(size<=len(raw)-offset,'complete Debian ar extent required')
        members[name]=raw[offset:offset+size];offset+=size
        if size&1:
            need(raw[offset:offset+1]==b'\n','Debian ar padding required');offset+=1
    need(members.get('debian-binary')==b'2.0\n','Debian package version required')
    names=[name for name in members if name=='data.tar' or name.startswith('data.tar.')]
    need(len(names)==1,'one Debian data archive required')
    name=names[0];payload=members[name]
    if name=='data.tar.zst':
        payload=subprocess.run(['zstd','-d','-q','-c','--memory=64MB'],input=payload,
                               capture_output=True,check=True,timeout=60).stdout
    need(len(payload)<=64*MIB,'bounded Debian payload required')
    return payload


def _syslinux(custody,cache,spec):
    """Read exact original packages and pinned sources; no extracted-cache trust."""
    downloads=Path(cache)/'syslinux/downloads'
    payload={};files={}
    required={path for path in spec['files'] if Path(path).name in
              {'isolinux.bin','isohdpfx.bin','ldlinux.c32','libcom32.c32','libutil.c32','mboot.c32'}}
    required|=set(spec['license_files'])
    for item in spec['packages'].values():
        row=_row(custody,downloads/item['file'],item['sha256'])
        raw_package=_deb_payload(custody,row)
        with tarfile.open(fileobj=io.BytesIO(raw_package),mode='r:*') as tar:
            for member in tar.getmembers():
                name=member.name.removeprefix('./')
                if name not in required:continue
                need(member.isfile() and 0<member.size<=8*MIB,'regular bounded pinned Syslinux member required')
                raw=tar.extractfile(member).read()
                if name in spec['files']:
                    need(hashlib.sha256(raw).hexdigest()==spec['files'][name],
                         'Syslinux binary differs from independent manifest')
                    files[Path(name).name]=raw
                else:payload['SOURCE/LICENSES/syslinux-'+name.replace('/','-')]=raw
        custody.check()
    need(set(files)=={'isolinux.bin','isohdpfx.bin','ldlinux.c32','libcom32.c32','libutil.c32','mboot.c32'} and
         len([name for name in payload if name.startswith('SOURCE/LICENSES/')])==len(spec['license_files']),
         'complete pinned Syslinux binary/license set required')
    for item in spec['source'].values():
        row=_row(custody,downloads/item['file'],item['sha256'])
        payload['SOURCE/syslinux/'+item['file']]=_read(custody,row,64*MIB)
    return files,payload


def _bios_sources(custody,receipt_path,manifest):
    anchor=getattr(admission.policy,'NATIVE_SYSTEM_BIOS_SOURCE',None)
    need(type(anchor) is dict and receipt_path is not None,
         'independent source-built native system BIOS closure absent')
    saved=custody._held.json(custody.pin('manifest'))
    request=custody._held.json(saved['source_request'])
    native=custody._held.json(request['native_build_receipt'])
    bios=native['input_pins']['SEABIOS.BIN']
    admission.anchored(bios,anchor.get('artifact'),'native system BIOS artifact')
    admission.anchored(_row(custody,bios['path'],bios['sha256']),anchor.get('artifact'),'actual held native system BIOS')
    row=_row(custody,receipt_path)
    admission.anchored(row,anchor.get('receipt'),'native system BIOS producer receipt')
    receipt=json.loads(_read(custody,row,4*MIB))
    need(receipt.get('schema')=='shizukuos.actual-source-built-system-bios.v1' and
         receipt.get('status')=='ACTUAL_SOURCE_BOUND_SYSTEM_BIOS_BUILT_NOT_RUN',
         'actual source-built native BIOS producer format required')
    commit=manifest['upstreams']['csmwrap']['submodules']['seabios']['commit']
    need(receipt.get('source_commit')==anchor.get('source_commit')==commit,
         'native BIOS source commit differs from actual pinned source')
    admission.anchored(receipt.get('artifact'),anchor.get('artifact'),'source-built native BIOS output')
    sources,tools=receipt.get('sources_sha256'),receipt.get('tools_sha256')
    need(type(sources) is dict and sources and type(tools) is dict and tools and
         admission.digest(admission.canonical(sources))==anchor.get('source_map_sha256') and
         admission.digest(admission.canonical(tools))==anchor.get('tool_map_sha256'),
         'independent native BIOS source/tool maps differ')
    source_root=Path(receipt.get('source_root',''))
    need(source_root.is_absolute() and source_root.resolve()==source_root,'canonical actual BIOS producer source root required')
    for path,sha in sources.items():
        source=Path(path)
        need('..' not in source.parts,'canonical BIOS source pin required')
        _row(custody,source if source.is_absolute() else source_root/source,sha)
    for item in tools.values():_row(custody,item['path'],item['sha256'])
    archive=receipt.get('source_archive')
    admission.anchored(archive,anchor.get('source_archive'),'native BIOS corresponding source archive')
    _row(custody,archive['path'],archive['sha256'])
    result={'SOURCE/native-system-bios/'+Path(archive['path']).name:_read(custody,archive),
            'SOURCE/native-system-bios/producer-receipt.json':_read(custody,row,4*MIB)}
    licences=receipt.get('license_files')
    need(type(licences) in (dict,list) and licences,'actual native BIOS original licence pins required')
    for item in (licences.values() if type(licences) is dict else licences):
        _row(custody,item['path'],item['sha256'])
        key='SOURCE/LICENSES/native-system-bios-'+Path(item['path']).name
        need(key not in result,'unique native BIOS licence name required')
        result[key]=_read(custody,item,MIB)
    custody.check()
    return result


def _tree_entries(tree,commit):
    blobs={};links={}
    for entry in _git(tree,'ls-tree','-r','-z',commit).split(b'\0'):
        if not entry:continue
        fields,raw=entry.split(b'\t',1);mode,kind,oid=fields.decode('ascii').split()
        name=os.fsdecode(raw);path=Path(name)
        need(not path.is_absolute() and '..' not in path.parts,'canonical committed source path required')
        if kind=='blob' and mode in ('100644','100755'):blobs[name]=oid
        elif kind=='commit' and mode=='160000':links[name]=oid
        else:raise ValueError('unsupported committed source type: '+mode+'/'+kind)
    return blobs,links


@contextmanager
def _fd_budget():
    # Bound the actual project tree plus the producer's bounded input families.
    # Only this build process and its children inherit the temporary soft limit.
    blobs,_=_tree_entries(ROOT,_git(ROOT,'rev-parse','HEAD').decode().strip())
    need(len(blobs)<=30000,'project source descriptor inventory exceeds bound')
    required=((len(blobs)+32768+512+1023)//1024)*1024
    need(required<=65536,'private source descriptor budget exceeds process bound')
    previous=resource.getrlimit(resource.RLIMIT_NOFILE)
    need(previous[1]==resource.RLIM_INFINITY or previous[1]>=required,
         'actual hard descriptor limit cannot retain all private source leases')
    changed=previous[0]<required
    if changed:resource.setrlimit(resource.RLIMIT_NOFILE,(required,previous[1]))
    try:yield {'required':required,'previous_soft':previous[0]}
    finally:
        if changed:resource.setrlimit(resource.RLIMIT_NOFILE,previous)


class _CommittedMetadataLeases:
    """Source-only empty Git blobs; never native import roles/capabilities."""
    def __init__(self,custody):
        self.custody=custody;self.entries=[];self.closed=False
        custody.guard(self.check)
    def __enter__(self):return self
    def check(self):
        for entry in self.entries:
            path=self.custody._ingest.path(str(entry['path']))
            state=path.stat()
            need(stat.S_ISREG(state.st_mode) and state.st_nlink==1 and state.st_size==0 and
                 self.custody._ingest.identity(state)==entry['identity'],
                 'committed empty metadata identity changed')
            if entry['fd'] is not None:
                need(self.custody._ingest.identity(os.fstat(entry['fd']))==entry['identity'] and
                     fcntl.fcntl(entry['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK and
                     os.pread(entry['fd'],1,0)==b'',
                     'committed empty metadata original read lease changed')
    def add(self,path,expected):
        need(not self.closed and expected==hashlib.sha256(b'').hexdigest(),
             'exact empty committed metadata role required')
        self.custody.check();path=self.custody._ingest.path(str(path))
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            state=os.fstat(fd)
            need(stat.S_ISREG(state.st_mode) and state.st_nlink==1 and state.st_size==0,
                 'independent empty committed regular metadata required')
            fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid());fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK)
            self.entries.append({'path':path,'fd':fd,'identity':self.custody._ingest.identity(state)})
            fd=None;self.check()
        finally:
            if fd is not None:os.close(fd)
    def __exit__(self,*exc):
        errors=[]
        try:self.check()
        except BaseException as error:errors.append(error)
        for entry in reversed(self.entries):
            fd=entry['fd']
            try:fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
            except BaseException as error:errors.append(error)
            try:os.close(fd)
            except BaseException as error:errors.append(error)
            entry['fd']=None
        self.closed=True
        if errors:raise errors[0]


def _project_sources(custody,gitlink_cache=None,empty_metadata=None):
    commit=_git(ROOT,'rev-parse','HEAD').decode().strip()
    need(not _git(ROOT,'status','--porcelain'),'clean current Git source is required')
    def guard():
        need(_git(ROOT,'rev-parse','HEAD').decode().strip()==commit and
             not _git(ROOT,'status','--porcelain'),'public project source changed during ISO build')
    custody.guard(guard)
    blobs,links=_tree_entries(ROOT,commit)
    required=len(custody._held.entries)+len(blobs)+512
    soft,_=resource.getrlimit(resource.RLIMIT_NOFILE)
    need(soft>=required,'source descriptor budget not established before admission')
    raw=_git_archive(ROOT,'Win98-Modern-'+commit[:12],commit)
    prefix='Win98-Modern-'+commit[:12]+'/'
    archived=set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
        for member in tar.getmembers():
            if member.isdir():continue
            need(member.isfile() and member.name.startswith(prefix),'regular committed project source required')
            name=member.name[len(prefix):]
            need(name in blobs and name not in archived,'exact committed project archive member required')
            archived.add(name)
            data=tar.extractfile(member).read();sha=hashlib.sha256(data).hexdigest()
            if not data:
                need(type(empty_metadata) is _CommittedMetadataLeases,'scoped committed metadata read lease required')
                empty_metadata.add(ROOT/name,sha)
            else:_row(custody,ROOT/name,sha)
    need(archived==set(blobs),'complete committed regular project archive required')
    result={'SOURCE/Win98-Modern-source.tar.gz':_gz(raw)}
    config=configparser.RawConfigParser()
    if links:
        need(gitlink_cache is not None,'pinned project gitlink source cache required')
        config.read_string(_git(ROOT,'show',commit+':.gitmodules').decode())
    metadata=[]
    for name,revision in links.items():
        entries=[config[section] for section in config.sections() if config[section].get('path')==name]
        need(len(entries)==1,'exact committed gitlink repository mapping required')
        url=entries[0].get('url');tree=Path(gitlink_cache)/name
        need(tree.is_dir() and _git(tree,'rev-parse','--show-toplevel').decode().strip()==str(tree.resolve()),
             'actual independent project gitlink checkout required')
        need(_git(tree,'config','--get','remote.origin.url').decode().strip()==url,
             'project gitlink repository URL differs')
        need(not _git(tree,'status','--porcelain'),'clean pinned project gitlink checkout required')
        child_blobs,child_links=_tree_entries(tree,revision)
        need(not child_links,'nested project gitlinks need independently pinned source closure')
        def child_guard(tree=tree,revision=revision):
            need(_git(tree,'rev-parse','HEAD').decode().strip()==revision and
                 not _git(tree,'status','--porcelain'),'project gitlink source changed')
        custody.guard(child_guard)
        child_raw=_git_archive(tree,'project-'+name.replace('/','-'),revision)
        # Preserve every actual checked-out regular source under original-FD
        # leases; hashes derive from the exact pinned Git blobs, never a flag.
        empty_names=[];child_archived={}
        child_prefix='project-'+name.replace('/','-')+'/'
        with tarfile.open(fileobj=io.BytesIO(child_raw),mode='r:') as tar:
            for member in tar.getmembers():
                if member.isdir():continue
                need(member.isfile() and member.name.startswith(child_prefix),
                     'regular pinned project gitlink archive required')
                path=member.name[len(child_prefix):]
                need(path in child_blobs and path not in child_archived,
                     'exact pinned project gitlink archive member required')
                data=tar.extractfile(member).read();child_archived[path]=data
                sha=hashlib.sha256(data).hexdigest()
                if not data:
                    need(type(empty_metadata) is _CommittedMetadataLeases,'scoped committed metadata read lease required')
                    empty_metadata.add(tree/path,sha);empty_names.append(path)
                else:_row(custody,tree/path,sha)
        need(set(child_archived)==set(child_blobs),'complete pinned project gitlink source archive required')
        label=name.replace('/','-')
        result['SOURCE/project-gitlinks/'+label+'-'+revision[:12]+'.tar.gz']=_gz(child_raw)
        licenses=[path for path in child_blobs if Path(path).name.lower() in ('license','license.txt','copying','copying.txt')]
        need(licenses,'pinned project gitlink licence required')
        for path in licenses:
            result['SOURCE/LICENSES/project-'+label+'-'+path.replace('/','-')]=child_archived[path]
        metadata.append({'path':name,'repository':url,'commit':revision,'regular_source_files':len(child_blobs),
                         'source_archived':True,'committed_empty_metadata_read_leases':empty_names,
                         'producer_build_or_Windows_approval':False})
    result['SOURCE/project-gitlinks.json']=(json.dumps(metadata,sort_keys=True,indent=2)+'\n').encode()
    guard();custody.check()
    return result


def _compliance(custody,cache,bios_receipt,gitlink_cache=None,empty_metadata=None):
    manifest_row=_row(custody,ROOT/'shizukudos/upstream/manifest.json')
    manifest=json.loads(_read(custody,manifest_row,4*MIB))
    payload=_bios_sources(custody,bios_receipt,manifest)
    files,sys_payload=_syslinux(custody,cache,manifest['upstreams']['syslinux'])
    payload.update(sys_payload)
    payload.update(_project_sources(custody,gitlink_cache,empty_metadata))
    payload['SOURCE/LICENSES/Shizuku-GPL-2.0.txt']=_read(custody,_row(custody,ROOT/'LICENSE'),MIB)
    for name in GIT_UPSTREAMS:
        spec=manifest['upstreams'][name];tree=Path(cache)/name
        revision=_git(tree,'rev-parse','HEAD').decode().strip()
        need(revision==spec['commit'],'pinned upstream Git revision differs: '+name)
        def guard(tree=tree,revision=revision):
            need(_git(tree,'rev-parse','HEAD').decode().strip()==revision,'upstream Git identity changed')
        custody.guard(guard)
        for pattern in spec['license_files']:
            # Expand against committed names, avoiding patched working files.
            import fnmatch
            names=[os.fsdecode(p) for p in _git(tree,'ls-tree','-r','--name-only','-z',revision).split(b'\0') if p]
            matches=[p for p in names if fnmatch.fnmatchcase(p,pattern)]
            if not matches and pattern.endswith('/*'):matches=[pattern[:-2]] if pattern[:-2] in names else []
            need(matches,'pinned upstream licence missing: '+name+'/'+pattern)
            for path in matches:
                payload['SOURCE/LICENSES/'+name+'-'+path.replace('/','-')]=_git(tree,'show',revision+':'+path)
        if name!='noto-fonts':
            raw=_git_archive(tree,name+'-'+revision[:12],revision)
            # Gitlinks do not include submodule source bytes. Append each
            # independently pinned submodule's original archive explicitly.
            payload['SOURCE/'+name+'-'+revision[:12]+'.tar.gz']=_gz(raw)
            for sub,info in spec.get('submodules',{}).items():
                sub_tree=tree/sub;sub_commit=info['commit']
                payload['SOURCE/'+name+'-'+sub.replace('/','-')+'.tar.gz']=_gz(
                    _git_archive(sub_tree,name+'/'+sub,sub_commit))
                sub_names=[os.fsdecode(p) for p in _git(sub_tree,'ls-tree','-r','--name-only','-z',sub_commit).split(b'\0') if p]
                for pattern in info.get('license_files',[]):
                    local=pattern.removeprefix(sub+'/')
                    matched=[p for p in sub_names if fnmatch.fnmatchcase(p,local)]
                    need(matched,'pinned submodule licence missing')
                    for path in matched:
                        key='SOURCE/LICENSES/'+name+'-'+sub.replace('/','-')+'-'+path.replace('/','-')
                        payload[key]=_git(sub_tree,'show',sub_commit+':'+path)
    payload['SOURCE/upstream-manifest.json']=_read(custody,manifest_row,4*MIB)
    custody.check()
    return files,payload


class _HeldInput:
    def __init__(self,custody,row):self.custody,self.row=custody,row
    @property
    def data(self):return _read(self.custody,self.row)


def _budget(profile,public_bytes,free_disk,free_ram):
    profile.check()
    # Account for bytes-oriented media dictionaries, FAT scratch/image, stage,
    # final ISO and extraction verification. No private expanded ESP is copied.
    media_bytes=2*profile._budget['archive_bytes']+public_bytes+16*MIB
    disk_needed=RESERVE+5*media_bytes+64*MIB
    ram_needed=6*media_bytes+256*MIB
    need(free_disk>=disk_needed,'private ISO would cross retained 17GiB disk reserve')
    need(free_ram>=ram_needed,'private ISO bounded bytes adapters exceed available host memory')
    return {'live_media_bytes_upper_bound':media_bytes,'disk_required_including_reserve':disk_needed,
            'RAM_required_bytes':ram_needed,'expanded_ESP_copied':False}


def _ram_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):return int(line.split()[1])*1024
    raise ValueError('actual available host memory observation absent')


def _assemble(custody,profile,package_result,loader_row,syslinux,compliance,out):
    need(type(custody) is admission.BuildCustody and type(profile) is capacity.CapacityProfile and
         profile._custody is custody,'same live generator-held ISO profile required')
    profile.check()
    budget=_budget(profile,sum(len(v) for v in compliance.values())+loader_row['bytes'],
                   shutil.disk_usage(Path(out).parent).free,_ram_available())
    out=_directory(custody,out);work=_directory(custody,out/'work')
    archive=package_result['archive'];need(archive==profile._archive_pin,'retained package/profile archive differs')
    setup={'SHZ/SETUP/INSTALL.IMG':_read(custody,archive)}
    kernel=package_result['installer_kernel_pin'];stub=package_result['installer_stub_pin']
    members=media.efi_members(_HeldInput(custody,loader_row),None,
                             {'KERNEL64S.BIN':_HeldInput(custody,kernel)},'install',setup,0,profile)
    efi_path=work/'efiboot.img'
    efi_mib=max(16,(sum(len(raw) for raw in members.values())+3*MIB+MIB-1)//MIB)
    media.make_fat(efi_path,members,efi_mib,16,'SHZESP','53485A45',work/'efi-fat')
    efi=efi_path.read_bytes()
    payload=dict(compliance)
    payload.update(setup)
    payload.update({'SHZ/K64/KERNEL64S.BIN':_read(custody,kernel),'SHZ/K64/BOOT.ELF':_read(custody,stub),
                    iso.EFI_IMAGE:efi,'ISOLINUX/isolinux.cfg':media.boot_menu('',setup=True,direct_install=True),
                    'README.TXT':b'PRIVATE native preinstall installer. Direct UEFI GUI. No public redistribution.\r\n'
                      b'BIOS native installation lacks independently observed backing and refuses.\r\n'})
    # Match the existing writer's actual path constants, not display casing.
    cfg=payload.pop('ISOLINUX/isolinux.cfg');payload[iso.ISOLINUX_DIR+'/isolinux.cfg']=cfg
    for name in ('isolinux.bin','ldlinux.c32','libcom32.c32','libutil.c32','mboot.c32'):
        payload[iso.ISOLINUX_DIR+'/'+name]=syslinux[name]
    stage=_directory(custody,out/'stage')
    for name,raw in payload.items():
        path=Path(name)
        need(not path.is_absolute() and '..' not in path.parts,'canonical private ISO member required')
        destination=stage/path;destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with destination.open('xb') as stream:stream.write(raw)
    prefix=work/'isohdpfx.bin';prefix.write_bytes(syslinux['isohdpfx.bin'])
    prefix_row=_retain(custody,prefix)
    output=out/'shizukuos-native-installer-private.iso'
    profile.check();iso.write_iso(stage,output,prefix,payload)
    # Preserve completed writer identities. Full ISO and embedded FAT compare
    # against original held inputs before any custody can close.
    iso_row=_retain(custody,output)
    boot=work/'isolinux.bin';boot.write_bytes(syslinux['isolinux.bin']);_retain(custody,boot)
    evidence=_directory(custody,out/'verification')
    report=iso.verify_iso(output,payload,members,{'isolinux.bin':boot,'isohdpfx.bin':prefix},evidence)
    custody.finish();profile.check()
    return {'schema':'PRIVATE_NATIVE_ISO_WRITTEN_AND_READBACK_NOT_BOOTED','private':True,'public_artifact':False,
            'ISO':iso_row,'ISO_generated':True,'Windows98_boot_verified':False,'VM_executed':False,
            'profile':profile.record(),'host_budget':budget,'ISO_members':len(payload),'EFI_members':len(members),
            'layout_report':str(evidence/'layout.txt'),'layout_sha256':hashlib.sha256(report.encode()).hexdigest(),
            'BIOS_native_storage_authority':False,'CSM_fallback_included':False}


def _finalizer(cache,bios_receipt,gitlink_cache=None):
    def finish(release,build,results):
        need(type(release) is dict and type(release.get('custody')) is admission.BuildCustody and
             type(release.get('profile')) is capacity.CapacityProfile,'actual live private release required')
        custody=release['custody'];profile=release['profile'];profile.check()
        with _CommittedMetadataLeases(custody) as empty_metadata:
            packaged=package.finalize(release,build,results)
            syslinux,compliance=_compliance(custody,cache,bios_receipt,gitlink_cache,empty_metadata)
            supervisor=_load('private_iso_supervisor',ROOT/'shizukudos/supervisor/build.py')
            supervisor.OUT=_directory(custody,Path(build)/'private-efi')
            _,vbios_command=supervisor.build_vbios()
            _,ap_command=supervisor.build_ap_trampoline()
            _row(custody,supervisor.OUT/'vbios_image.h')
            _row(custody,supervisor.OUT/'ap_trampoline_image.h')
            payload,commands=supervisor.build_payload()
            commands=[vbios_command,ap_command,*commands]
            loader,command=supervisor.build_loader(payload,profile)
            row=_row(custody,loader)
            compliance['SOURCE/private-installer/native_release_admitted.c']=_read(custody,release['record'],4*MIB)
            compliance['SOURCE/private-installer/measured-profile.json']=(json.dumps(profile.record(),sort_keys=True)+'\n').encode()
            compliance['SOURCE/private-installer/efi-commands.json']=(json.dumps([[str(v) for v in values] for values in commands]+[[str(v) for v in command]],indent=2)+'\n').encode()
            result=_assemble(custody,profile,packaged,row,syslinux,compliance,Path(build)/'private-iso')
            result['Supervisor_commands']=[[str(v) for v in values] for values in commands]
            result['EFI_command']=[str(v) for v in command]
            return result
    return finish


def build_private_iso(manifest,output,upstream_cache,native_bios_producer_receipt=None,project_gitlink_cache=None):
    need(admission.policy.NATIVE_SOURCE_MAP_SHA is not None and admission.policy.NATIVE_ARTIFACTS is not None,
         'independently approved native producer anchors absent; private ISO refused')
    need(type(getattr(admission.policy,'NATIVE_SYSTEM_BIOS_SOURCE',None)) is dict and native_bios_producer_receipt is not None,
         'independent source-built native system BIOS closure absent; ISO refused')
    kbuild=_load('private_iso_kbuild',ROOT/'shizukudos/kbuild.py')
    with _fd_budget():
        with ExitStack() as stack:
            kbuild.build_all(Namespace(out=Path(output),native_release_manifest=Path(manifest)),stack,
                             private_finalize=_finalizer(Path(upstream_cache),Path(native_bios_producer_receipt),project_gitlink_cache))


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-release-manifest',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--upstream-cache',type=Path,required=True,help='existing pinned public upstream cache; never downloads')
    parser.add_argument('--native-bios-producer-receipt',type=Path,help='discovery path; must match independent ROOT-owned source-built BIOS anchor')
    parser.add_argument('--project-gitlink-cache',type=Path,help='existing exact repository/path checkouts for committed project gitlinks')
    args=parser.parse_args();build_private_iso(args.native_release_manifest,args.out,args.upstream_cache,args.native_bios_producer_receipt,args.project_gitlink_cache)

if __name__=='__main__':main()
