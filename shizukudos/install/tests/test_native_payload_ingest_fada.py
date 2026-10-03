"""Synthetic producer receipts/tiny FAT32 media; no DOS, PE, EFI or VM runs.

Only geometry, HIMEMX artifact bytes and capacity are modeled. Repository
source bytes, read leases, Linux FD/inode/SHA, actual FAT members and exports
are real. Standalone writer-failure controls model prior lineage. Production budgets, producer/source pins and binary SHA stay fixed.
"""
import copy
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT/'shizukudos/install/native_payload_ingest.py'
UPSTREAM = Path('/root/Win98-Modern-main-integration-20261001/build/shizukudos/dos16/work/freedos-kernel')
DISK_SIZE = 40 << 20
ESP_SIZE = 64 << 20


def load(p, name):
    spec=importlib.util.spec_from_file_location(name,p)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def sha(raw):return hashlib.sha256(raw).hexdigest()


def observed(p):
    with p.open('rb') as f:
        h=hashlib.sha256()
        for raw in iter(lambda:f.read(1<<20),b''):h.update(raw)
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':h.hexdigest()}


def save(p, raw):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(raw);return observed(p)


def jsave(p, obj):return save(p,(json.dumps(obj,indent=2)+'\n').encode())


def name83(name):
    fields=name.split('.')
    return fields[0].encode().ljust(8,b' ')+(fields[1].encode() if len(fields)==2 else b'').ljust(3,b' ')


def fat32(target, size, files, *, start=0, template=None):
    """Actual sparse FAT32 fixture with mirrored FATs/backup/FSInfo."""
    total=size//512-start;reserved=32;fat_sectors=1
    while True:
        clusters=total-reserved-2*fat_sectors
        needed=((clusters+2)*4+511)//512
        if needed<=fat_sectors:break
        fat_sectors=needed
    first=start+reserved+2*fat_sectors;clusters=total-reserved-2*fat_sectors
    assert clusters>=65525
    directories={'':2};next_cluster=3
    for name in files:
        parts=name.split('/')[:-1]
        for n in range(1,len(parts)+1):
            directory='/'.join(parts[:n])
            if directory not in directories:directories[directory]=next_cluster;next_cluster+=1
    fat=bytearray(fat_sectors*512);struct.pack_into('<III',fat,0,0x0ffffff8,0x0fffffff,0x0fffffff)
    for number in directories.values():struct.pack_into('<I',fat,number*4,0x0fffffff)
    entries={name:[] for name in directories};data=[]
    for name,number in directories.items():
        if not name:continue
        parent,_,base=name.rpartition('/')
        row=bytearray(32);row[:11]=name83(base);row[11]=16
        struct.pack_into('<H',row,20,number>>16);struct.pack_into('<H',row,26,number&65535)
        entries[parent].append(row)
    for name,payload in files.items():
        length=payload.stat().st_size if isinstance(payload,Path) else len(payload)
        count=(length+511)//512;number=next_cluster;next_cluster+=count
        assert next_cluster<=clusters+2
        for i in range(count):struct.pack_into('<I',fat,(number+i)*4,number+i+1 if i+1<count else 0x0fffffff)
        parent,_,base=name.rpartition('/');row=bytearray(32);row[:11]=name83(base);row[11]=32
        struct.pack_into('<H',row,20,number>>16);struct.pack_into('<H',row,26,number&65535);struct.pack_into('<I',row,28,length)
        entries[parent].append(row);data.append((number,payload,length))
    b=bytearray(512);b[:3]=b'\xeb\x58\x90';b[3:11]=b'MODELED '
    struct.pack_into('<H',b,11,512);b[13]=1;struct.pack_into('<H',b,14,reserved);b[16]=2;b[21]=0xf8
    struct.pack_into('<II',b,28,start,total);struct.pack_into('<I',b,36,fat_sectors);struct.pack_into('<I',b,44,2)
    struct.pack_into('<HH',b,48,1,6);b[64]=128;b[66]=41;b[82:90]=b'FAT32   ';b[510:]=b'\x55\xaa'
    if template is not None:
        replacement=bytearray(template);replacement[11:90]=b[11:90];replacement[3:11]=b'FRDOS5.1';replacement[64]=128;b=replacement
    info=bytearray(512);struct.pack_into('<I',info,0,0x41615252);struct.pack_into('<I',info,484,0x61417272)
    struct.pack_into('<II',info,488,clusters-(next_cluster-2),next_cluster);struct.pack_into('<I',info,508,0xaa550000)
    with target.open('xb') as f:
        f.truncate(size)
        if start:
            mbr=bytearray(512);mbr[446]=128;mbr[450]=12;struct.pack_into('<II',mbr,454,start,total);mbr[510:]=b'\x55\xaa';f.seek(0);f.write(mbr)
        for sector,raw in ((start,b),(start+6,b),(start+1,info),(start+7,info),(start+reserved,fat),(start+reserved+fat_sectors,fat)):
            f.seek(sector*512);f.write(raw)
        for name,rows in entries.items():
            assert len(rows)<16
            f.seek((first+directories[name]-2)*512);f.write(b''.join(rows))
        for number,payload,length in data:
            at=(first+number-2)*512
            if isinstance(payload,Path):
                with payload.open('rb') as source:
                    for off in range(0,length,1<<20):
                        raw=source.read(min(1<<20,length-off))
                        assert len(raw)==min(1<<20,length-off)
                        if raw.count(0)!=len(raw):f.seek(at+off);f.write(raw)
            else:f.seek(at);f.write(payload)
    return observed(target)


class Fixture:
    def __init__(self, directory, m, *, biling=False, initial_locale=False):
        self.p=directory;self.m=m;self.constructor=load(ROOT/'shizukudos/win98_boot/prepare_replacement.py','fixture_constructor')
        self.kernel=b'MODELED_KERNEL_NOT_RUN';self.command=b'MODELED_FREECOM_NOT_RUN';self.xms=b'MODELED_HIMEMX_NOT_RUN'.ljust(6100,b'\0')
        self.config=b'DEVICE=C:\\HIMEMX.EXE /VERBOSE\r\nDEVICE=C:\\WINDOWS\\IFSHLP.SYS\r\nDOS=HIGH\r\nFILES=30\r\nBUFFERS=20\r\nSHELL=C:\\COMMAND.COM C:\\ /E:512 /P\r\n'
        biling_line='device=C:\\WINDOWS\\biling.sys'
        if biling:
            self.config=self.config.replace(b'DEVICE=C:\\WINDOWS\\IFSHLP.SYS',biling_line.encode()+b'\r\nDEVICE=C:\\WINDOWS\\IFSHLP.SYS')
        if initial_locale:self.config=b'COUNTRY=82,949\r\n'+self.config
        self.nls='loadhigh C:\\WINDOWS\\COMMAND\\nlsfunc.exe C:\\WINDOWS\\country.sys'
        self.auto=b'@ECHO OFF\r\nSET COMSPEC=C:\\COMMAND.COM\r\nSET windir=C:\\WINDOWS\r\nSET PATH=C:\\WINDOWS;C:\\WINDOWS\\COMMAND;C:\\\r\nC:\r\nCD \\WINDOWS\r\n'+self.nls.encode()+b'\r\nC:\\WINDOWS\\WIN.COM\r\n'
        self.windows={'WINDOWS/WIN.COM':b'MODELED_WIN.COM', 'WINDOWS/SYSTEM.INI':b'[boot]\r\n',
                      'WINDOWS/SYSTEM/VMM32.VXD':b'MODELED_VMM', 'WINDOWS/IFSHLP.SYS':b'MODELED_IFS',
                      'WINDOWS/COUNTRY.SYS':b'MODELED_COUNTRY', 'WINDOWS/COMMAND/NLSFUNC.EXE':b'MODELED_NLSFUNC',
                      'MSDOS.SYS':b'[Paths]\r\nWinDir=C:\\WINDOWS\r\nWinBootDir=C:\\WINDOWS\r\nHostWinBootDrv=C\r\n',
                      'CONFIG.SYS':b'REM original startup\r\n','AUTOEXEC.BAT':self.nls.encode()+b'\r\n'}
        if biling:
            self.windows['WINDOWS/BILING.SYS']=b'MODELED_BILING_NOT_EXECUTED'
            self.windows['CONFIG.SYS']+=biling_line.encode()+b'\r\n'
        template=bytearray(512);template[:3]=b'\xeb\x58\x90';struct.pack_into('<H',template,0x78,96)
        template[0x82:0x85]=b'\x88\x56\x40';template[0x1f1:0x1fc]=b'KERNEL  SYS';template[510:]=b'\x55\xaa'
        self.template=save(directory/'boot-template.bin',template)
        self.original=fat32(directory/'original.img',DISK_SIZE,self.windows,start=1)
        replacement_files={**self.windows,'CONFIG.SYS':self.config,'AUTOEXEC.BAT':self.auto,
                           'KERNEL.SYS':self.kernel,'COMMAND.COM':self.command,'HIMEMX.EXE':self.xms}
        self.replaced=fat32(directory/'replacement.img',DISK_SIZE,replacement_files,start=1,template=template)
        with open(self.original['path'],'rb') as f:
            b=f.read(512);f.seek(512);v=f.read(512);self.geometry=self.constructor.inspect_geometry(b,v,DISK_SIZE)
            inventory=self.constructor.inventory(f.fileno(),self.geometry)
        self.inputs={'DISK.IMG':self.replaced,'SEABIOS.BIN':save(directory/'seabios.bin',b'MODELED_SYSTEM_ROM'.ljust(256<<10,b'\0')),
                     'WIN98CFG.BIN':save(directory/'win98cfg.bin',struct.pack('<4I',0x38395753,1,128,0)),
                     'KERNEL32.BIN':save(directory/'k32.bin',b'MODELED_K32'),'KERNEL64.BIN':save(directory/'k64.bin',b'MODELED_K64')}
        self.native_files={'EFI/BOOT/BOOTX64.EFI':b'MODELED_SUPERVISOR_EFI',
                           'EFI/SHIZUKU/BOOT.INI':b'mode=supervisor\r\nmenu_timeout=0\r\n',
                           **{'SHZDOS/'+name:Path(row['path']) for name,row in self.inputs.items()}}
        self.esp=fat32(directory/'esp-win98.img',ESP_SIZE,self.native_files)
        self.upstream=directory/'upstream';self.droot=directory/'dos-source'
        save(self.upstream/'config.mak',m.MAKE_CONFIG.encode())
        for name in ('sys/sys.c','boot/boot32lb.asm','boot/magic.mac'):save(self.upstream/name,(UPSTREAM/name).read_bytes())
        self.patchrows=[]
        for name,digest in m.DOS_PATCHES:
            relative='shizukudos/dos16/patches/'+name;p=self.droot/relative
            row=save(p,(ROOT/relative).read_bytes());assert row['sha256']==digest
            self.patchrows.append({'patch':relative,'sha256':digest})
        sources={name:save(self.droot/name,b'modeled DOS source; never executed\n') for name in m.DOS_SOURCES}
        self.dos={'profile':'dos16-freedos','upstream':{'freedos-kernel':{'commit':self.constructor.KERNEL_COMMIT},'freedos-freecom':{'commit':self.constructor.FREECOM_COMMIT}},
                  'kernel_make_config':{'text':m.MAKE_CONFIG,'sha256':sha(m.MAKE_CONFIG.encode()),'c_defines':['WIN31SUPPORT'],'nasm_defines':['WIN31SUPPORT']},
                  'toolchain':{'open-watcom':{'snapshot_sha256':'1'*64,'manifest_snapshot_sha256':'1'*64,'matches_manifest':True}},
                  'patches':self.patchrows,'user_boot':{'sources_sha256':{name:row['sha256'] for name,row in sources.items()}},
                  'artifacts':{'kernel.sys':{'bytes':len(self.kernel),'sha256':sha(self.kernel)},'command.com':{'bytes':len(self.command),'sha256':sha(self.command)}}}
        self.dos_pin=jsave(directory/'dos-result.json',self.dos)
        self.payloads={name:save(directory/'payloads'/name,raw) for name,raw in
                       [('KERNEL.SYS',self.kernel),('COMMAND.COM',self.command),('HIMEMX.EXE',self.xms),('CONFIG.SYS',self.config),('AUTOEXEC.BAT',self.auto)]}
        self.profile={'schema':'shizukuos.private-replacement-profile.v1','disk':self.original,'boot_template':{'kind':'fat32lba','file':self.template},
                      'freedos_source':str(self.upstream),'build_receipt':self.dos_pin,'build_source_root':str(self.droot),
                      'payloads':[{'guest':name,'file':row} for name,row in self.payloads.items()]}
        self.profile_pin=jsave(directory/'replacement-profile.json',self.profile)
        pins=[observed(self.droot/r['patch']) for r in self.patchrows]+list(sources.values())
        t={'kind':'fat32lba','sha256':self.template['sha256'],'sys_source_sha256':self.constructor.SYS_SHA,'kernel_name':'KERNEL.SYS','load_segment':96,'actual_BIOS_DL_capture':True}
        self.replacement={'schema':'shizukuos.private-replacement-preparation.v1','status':'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED',
                          'private_source_disk':True,'source_unchanged':True,'source_disk':self.original,'profile_sha256':self.profile_pin['sha256'],
                          'build_receipt_sha256':self.dos_pin['sha256'],'build_source_pins':pins,'template':t,'geometry':self.geometry,'destination':self.replaced,
                          **{k:False for k in ('public_artifact','Windows98_boot_verified','MSDOS_replacement_under_Windows98','native_apps_verified','VM_executed')}}
        self.replacement_pin=jsave(directory/'preparation.json',self.replacement)
        xrows=[];preimages={}
        for name,count in [('HimemX',5),('JWasm',268)]:
            files=[]
            for n in range(count):
                row=save(directory/'xms-source'/name/('file'+str(n)+'.c'),b'modeled xms source '+str(n).encode())
                xrows.append(row);files.append({'file':Path(row['path']).name,'bytes':row['bytes'],'sha256':row['sha256']})
            preimages[name]={'commit':m.XMS_COMMITS[name],'files':files,'file_count':count}
        self.xreceipt={'schema':'shizukudos-cb43-himemx-source-build-v1','artifacts':[{'file':'artifacts/HIMEMX.EXE','bytes':6100,'sha256':sha(self.xms)}],
                       'source_inputs_frozen_before_build':True,'source_files_unchanged_after_build':True,'source_files_changed':[],
                       'builds':[{'name':'HIMEMX','command':['modeled-jwasm','-mz'],'exit_code':0}], 'source_preimages':preimages,
                       'acquisitions':{name:{'commit':commit} for name,commit in m.XMS_COMMITS.items()}}
        self.source={'schema':'shizukuos.private-win98-launch-profile.v1','status':'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED',
                     **{k:False for k in ('public_artifact','Windows98_boot_verified','installed_Windows98_version_verified','MSDOS_replacement_under_Windows98','native_apps_verified','VM_executed','drive_mapping_verified','native_bootability_verified')},
                     'boot_policy':'shz.foundation=win98','observed_windows_path':'C:\\WINDOWS','constructor_profile':self.profile_pin,
                     'source_disk':self.original,'producer_inputs':[observed(ROOT/'shizukudos/install/win98_source_profile.py'),observed(ROOT/'shizukudos/win98_boot/prepare_replacement.py')],
                     'xms_sources':xrows,'xms_receipt':jsave(directory/'xms-result.json',self.xreceipt),'locale':{'country':[],'nls':[self.nls]},
                     'constructor_input_validation':{**self.replacement,'status':'INPUTS_VALIDATED_REPLACEMENT_NOT_PREPARED'},
                     'observed_members':{k:inventory[k] for k in ('WINDOWS/WIN.COM','WINDOWS/SYSTEM.INI','WINDOWS/SYSTEM/VMM32.VXD','WINDOWS/IFSHLP.SYS','WINDOWS/COUNTRY.SYS','WINDOWS/COMMAND/NLSFUNC.EXE')},
                     'MSDOS.SYS_observation':inventory['MSDOS.SYS'],'original_config':{name:{'present':True,'bytes':inventory[name]['bytes'],'sha256':inventory[name]['sha256'],'source_metadata_sha256':inventory[name]['metadata_sha256']} for name in ('CONFIG.SYS','AUTOEXEC.BAT')}}
        self.source['observed_biling_driver']=[biling_line] if biling else []
        self.source['initial_locale_configuration']=None if not initial_locale else {
            'country':82,'codepage':949,'origin':'explicit_request',
            'runtime_verified':False,'observed_query_authority':False}
        if biling:self.source['observed_members']['WINDOWS/BILING.SYS']=inventory['WINDOWS/BILING.SYS']
        self.source_pin=jsave(directory/'source-profile.json',self.source)
        reader=load(ROOT/'shizukudos/supervisor/native_win98/sparse_fat32.py','fixture_sparse_geometry')
        with open(self.esp['path'],'rb') as f:
            g=reader.geometry(f.fileno(),ESP_SIZE,lambda:None)
            geom={'fat_bits':32,'start_lba':0,'total_sectors':ESP_SIZE//512,'spc':g['spc'],'reserved':g['reserved'],'fats':2,'fat_sectors':g['fat_sectors'],'root_cluster':g['root'],'root_sectors':0,'first_data':g['first_data']//512,'clusters':g['clusters']}
            members=self.constructor.inventory(f.fileno(),geom)
        self.nroot=directory/'native-source'
        native_sources={name:save(self.nroot/name,b'modeled native source receipt; no compilation\n')['sha256'] for name in m.NATIVE_SOURCES}
        self.native={'status':'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN','private':True,'source_before_after_match':True,'originals_before_after_match':True,'original_input_leases_held_through_artifact_finalization':True,
                     **{k:False for k in ('Windows98_installation_identity_verified','VM_executed','Windows98_boot_verified','MS_DOS_replaced','native_Win64_app_verified')},
                     'input_pins':self.inputs,'artifact':{**self.esp,'path':'esp-win98.img'},'sources_sha256':native_sources,
                     'members':{k:{'bytes':r['bytes'],'sha256':r['sha256']} for k,r in members.items() if not r.get('directory')}}
        self.native_pin=jsave(directory/'native-result.json',self.native)
        self.request={'schema':'shizukuos.native-payload-ingest-request.v1','source_profile':self.source_pin,'constructor_profile':self.profile_pin,
                      'replacement_receipt':self.replacement_pin,'dos_build_receipt':self.dos_pin,'native_build_receipt':self.native_pin,
                      'native_esp':self.esp,'native_source_root':str(self.nroot),'readers':{'constructor':observed(ROOT/'shizukudos/win98_boot/prepare_replacement.py'),'fat32':observed(ROOT/'shizukudos/supervisor/native_win98/sparse_fat32.py')}}
        self.refresh()
    def refresh(self):self.request_pin=jsave(self.p/'request.json',self.request)
    def change(self, key, obj):
        old=self.request[key];row=jsave(Path(old['path']),obj);self.request[key]=row;self.refresh()
    def run(self, out=None, budget=None):
        with mock.patch.object(self.m,'DISK_BYTES',DISK_SIZE),mock.patch.object(self.m,'ESP_BYTES',ESP_SIZE),\
             mock.patch.object(self.m,'XMS_SHA',sha(self.xms)),mock.patch.object(self.m,'capacity',lambda *args:None):
            return self.m.ingest(Path(self.request_pin['path']),self.request_pin['sha256'],out or self.p/'private-output',budget or ESP_SIZE+(4<<20))


class IngestionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.m=load(PATH,'native_ingestion_controls')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir="/var/tmp");self.addCleanup(self.temp.cleanup)
        self.p=Path(self.temp.name);self.fixture=Fixture(self.p,self.m)
    def refuse(self, message=None):
        with self.assertRaises((ValueError,OSError),msg=message):self.fixture.run()
        self.assertFalse((self.p/'private-output/manifest.json').exists())
    def test_actual_missing_ingestion_seam_is_not_silently_accepted(self):
        self.assertTrue(PATH.is_file());self.assertTrue(callable(self.m.ingest))
        with self.assertRaises(ValueError):self.m.pin({'path':'relative','bytes':1,'sha256':'1'*64})
    def test_production_capacity_enforces_exact_floor_and_pending_budget(self):
        pending=5<<20
        usage=self.m.shutil.disk_usage(self.p)
        for free,accepted in ((self.m.FLOOR-1,False),
                              (self.m.FLOOR+pending-1,False),
                              (self.m.FLOOR+pending,True)):
            controlled=type(usage)(usage.total,usage.total-free,free)
            with self.subTest(free=free),mock.patch.object(self.m.shutil,'disk_usage',return_value=controlled):
                if accepted:self.m.capacity(self.p,pending)
                else:
                    with self.assertRaises(ValueError):self.m.capacity(self.p,pending)
    def test_real_fat_export_preserves_originals_and_retains_false_runtime_claims(self):
        before=[observed(Path(row['path'])) for row in (self.fixture.original,self.fixture.replaced,self.fixture.esp)]
        result=self.fixture.run();out=self.p/'private-output'
        self.assertEqual(result['schema'],self.m.SCHEMA);self.assertTrue(result['private']);self.assertEqual(result['first_lba'],0)
        self.assertTrue(all(result[k] is False for k in self.m.FALSE_FLAGS));self.assertFalse(result['compiler_tool_closure_verified'])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode),0o700)
        for name in ('ESP.SIM','manifest.json'):self.assertEqual(stat.S_IMODE((out/name).stat().st_mode),0o600)
        self.assertEqual(json.loads((out/'manifest.json').read_bytes()),result)
        self.assertEqual([observed(Path(row['path'])) for row in before],before)
        fd=os.open(out/'ESP.SIM',os.O_RDONLY)
        try:self.m.verify_sim(fd,(out/'ESP.SIM').stat().st_size,self.fixture.esp,lambda:None)
        finally:os.close(fd)
    def test_actual_fat_observed_biling_and_explicit_locale_reconstruct_without_runtime_claims(self):
        for index, selection in enumerate(((True,False),(False,True),(True,True))):
            parent=self.p/('locale-'+str(index));parent.mkdir()
            fixture=Fixture(parent,self.m,biling=selection[0],initial_locale=selection[1])
            result=fixture.run()
            self.assertTrue(all(result[k] is False for k in self.m.FALSE_FLAGS))
            config,_,_,_,biling=self.m.startup_configuration(fixture.source,'C:\\WINDOWS')
            self.assertEqual(config,fixture.config)
            self.assertEqual(bool(biling),selection[0])
    def test_explicit_locale_never_accepts_runtime_authority_or_extra_fields(self):
        source=copy.deepcopy(self.fixture.source)
        initial={'country':82,'codepage':949,'origin':'explicit_request','runtime_verified':False,'observed_query_authority':False}
        for field,value in (('country',True),('codepage',932),('origin','observed'),
                            ('runtime_verified',True),('observed_query_authority',True),('approval',True)):
            changed=copy.deepcopy(source);changed['initial_locale_configuration']={**initial,field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.m.startup_configuration(changed,'C:\\WINDOWS')
        changed=copy.deepcopy(source);changed['initial_locale_configuration']=initial
        changed['locale']['country']=['COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS']
        with self.assertRaises(ValueError):self.m.startup_configuration(changed,'C:\\WINDOWS')
    def test_biling_paths_arguments_duplicates_and_receipt_forgery_refused(self):
        for lines in (['DEVICE=C:\\OTHER\\BILING.SYS'],['DEVICE=C:\\WINDOWS\\BILING.SYS /OTHER'],
                      ['DEVICE=C:\\WINDOWS\\BILING.SYS & OTHER.COM'],['DEVICE=C:\\WINDOWS\\BILING.SYS']*2,
                      [True],{'approval':True}):
            source=copy.deepcopy(self.fixture.source);source['observed_biling_driver']=lines
            with self.subTest(lines=lines),self.assertRaises(ValueError):
                self.m.startup_configuration(source,'C:\\WINDOWS')
    def test_raw_native_failure_runtime_true_and_optional_epoch_refused(self):
        for field,value in [('status','FAIL_PRIVATE_WIN98_DOMAIN_ESP'),('VM_executed',True),('optional_native_inputs',{'VGACFG.BIN':{}})]:
            native=copy.deepcopy(self.fixture.native);native[field]=value;self.fixture.change('native_build_receipt',native);self.refuse(field)
    def test_missing_native_input_member_source_and_old_original_disk_refused(self):
        for kind in ('input','member','source','original'):
            native=copy.deepcopy(self.fixture.native)
            if kind=='input':del native['input_pins']['KERNEL32.BIN']
            if kind=='member':del native['members']['SHZDOS/WIN98CFG.BIN']
            if kind=='source':native['sources_sha256']={}
            if kind=='original':native['input_pins']['DISK.IMG']=self.fixture.original
            self.fixture.change('native_build_receipt',native);self.refuse(kind)
    def test_dos_patches_order_make_config_artifact_and_tool_identity_refused(self):
        for kind in ('patch','config','artifact','tool'):
            dos=copy.deepcopy(self.fixture.dos)
            if kind=='patch':dos['patches'].reverse()
            if kind=='config':dos['kernel_make_config']['nasm_defines']=[]
            if kind=='artifact':dos['artifacts']['kernel.sys']['sha256']='0'*64
            if kind=='tool':dos['toolchain']['open-watcom']['matches_manifest']=False
            self.fixture.change('dos_build_receipt',dos);self.refuse(kind)
    def test_fully_rebound_dos_receipt_wrong_patch_order_is_still_refused(self):
        dos=copy.deepcopy(self.fixture.dos);dos['patches'].reverse();self.fixture.change('dos_build_receipt',dos)
        profile=copy.deepcopy(self.fixture.profile);profile['build_receipt']=self.fixture.request['dos_build_receipt'];self.fixture.change('constructor_profile',profile)
        replacement=copy.deepcopy(self.fixture.replacement);replacement['profile_sha256']=self.fixture.request['constructor_profile']['sha256'];replacement['build_receipt_sha256']=self.fixture.request['dos_build_receipt']['sha256'];self.fixture.change('replacement_receipt',replacement)
        source=copy.deepcopy(self.fixture.source);source['constructor_profile']=self.fixture.request['constructor_profile'];self.fixture.change('source_profile',source);self.refuse()
    def test_windows_foundation_and_observed_file_content_required(self):
        for kind in ('desktop','cabinet','changed'):
            source=copy.deepcopy(self.fixture.source)
            if kind=='desktop':source['boot_policy']='shz.desktop=win98'
            if kind=='cabinet':del source['observed_members']['WINDOWS/WIN.COM']
            if kind=='changed':source['observed_members']['WINDOWS/SYSTEM.INI']['sha256']='2'*64
            self.fixture.change('source_profile',source);self.refuse(kind)
    def test_fully_rebound_second_WIN_COM_in_locale_cannot_be_replayed(self):
        f=self.fixture;auto=f.auto.replace(f.nls.encode()+b'\r\n',b'C:\\WINDOWS\\WIN.COM\r\n')
        f.payloads['AUTOEXEC.BAT']=save(Path(f.payloads['AUTOEXEC.BAT']['path']),auto)
        profile=copy.deepcopy(f.profile);profile['payloads']=[{'guest':name,'file':row} for name,row in f.payloads.items()]
        f.change('constructor_profile',profile)
        disk=fat32(self.p/'rebound.img',DISK_SIZE,{**f.windows,'CONFIG.SYS':f.config,'AUTOEXEC.BAT':auto,
                   'KERNEL.SYS':f.kernel,'COMMAND.COM':f.command,'HIMEMX.EXE':f.xms},start=1,template=Path(f.template['path']).read_bytes())
        replacement=copy.deepcopy(f.replacement);replacement['profile_sha256']=f.request['constructor_profile']['sha256'];replacement['destination']=disk;f.change('replacement_receipt',replacement)
        source=copy.deepcopy(f.source);source['constructor_profile']=f.request['constructor_profile'];source['locale']['nls']=['C:\\WINDOWS\\WIN.COM']
        with open(f.original['path'],'rb') as original:inventory=f.constructor.inventory(original.fileno(),f.geometry)
        for name in ('WINDOWS/COUNTRY.SYS','WINDOWS/COMMAND/NLSFUNC.EXE'):source['observed_members'][name]=inventory[name]
        f.change('source_profile',source)
        native=copy.deepcopy(f.native);native['input_pins']['DISK.IMG']=disk
        files={**f.native_files,'SHZDOS/DISK.IMG':Path(disk['path'])};parent=self.p/'rebound';parent.mkdir()
        esp=fat32(parent/'esp-win98.img',ESP_SIZE,files)
        native['artifact']={**esp,'path':'esp-win98.img'};native['members']['SHZDOS/DISK.IMG']={'bytes':disk['bytes'],'sha256':disk['sha256']}
        f.change('native_build_receipt',native);f.request['native_esp']=esp;f.refresh();self.refuse()
    def test_fresh_output_budget_symlink_and_hardlink_refused_without_acceptance(self):
        output=self.p/'private-output';output.mkdir()
        with self.assertRaises(ValueError):self.fixture.run()
        output.rmdir()
        with self.assertRaises(ValueError):self.fixture.run(budget=ESP_SIZE)
        self.assertFalse(output.exists())
        (self.p/'alias').symlink_to(self.p)
        with self.assertRaises(ValueError):self.fixture.run(out=self.p/'alias/output')
        os.link(self.fixture.original['path'],self.p/'original-hardlink');self.refuse()
    def test_stale_raw_receipt_duplicate_json_and_changed_actual_source_refused(self):
        old=Path(self.fixture.request['native_build_receipt']['path']);original=old.read_bytes();old.write_bytes(original+b' ');self.refuse()
        old.write_bytes(original)
        request=Path(self.fixture.request_pin['path']);raw=request.read_bytes();duplicate=raw.rstrip()[:-1]+b',"schema":"duplicate"}\n'
        request.write_bytes(duplicate);self.fixture.request_pin=observed(request);self.refuse()
    def test_export_full_short_read_short_write_and_saved_streaming_readback(self):
        original_pread=os.pread;original_write=os.write
        expected=save(self.p/'short-source.img',b'leading'.ljust(8192,b'\0')+bytes(8192)+b'trailing'.ljust(16384,b'\0'))
        with mock.patch.object(os,'pread',lambda f,n,at:original_pread(f,min(n,997),at)),\
             mock.patch.object(os,'write',lambda f,data:original_write(f,data[:313])):
            with self.m.Union() as u:
                entry=u.add(expected)
                with mock.patch.object(self.m,'capacity',lambda *args:None):row,created=self.m.export_sim(entry,u,self.p/'short.SIM',ESP_SIZE)
                out=os.open(row['path'],os.O_RDONLY)
                try:self.m.verify_sim(out,row['bytes'],expected,u.check)
                finally:os.close(out)
    def test_saved_sparse_mutation_wrong_extent_order_and_byte_rejected(self):
        with self.m.Union() as u:
            entry=u.add(self.fixture.esp)
            with mock.patch.object(self.m,'capacity',lambda *args:None):row,created=self.m.export_sim(entry,u,self.p/'saved.SIM',ESP_SIZE)
        p=Path(row['path']);raw=p.read_bytes()
        for mutated in (raw+b'\0',raw[:64],raw[:31]+b'\1'+raw[32:],raw[:-1]+bytes([raw[-1]^1])):
            save(self.p/'changed.SIM',mutated);fd=os.open(self.p/'changed.SIM',os.O_RDONLY)
            try:
                with self.assertRaises(ValueError):self.m.verify_sim(fd,len(mutated),self.fixture.esp,lambda:None)
            finally:os.close(fd)


class ExportIOOptimization(unittest.TestCase):
    """Synthetic sparse sources; actual 273-source Linux lease/IO guards."""
    @classmethod
    def setUpClass(cls):cls.m=load(PATH,'native_export_io_controls')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir="/var/tmp");self.addCleanup(self.temp.cleanup)
        self.p=Path(self.temp.name);self.target=self.p/'ESP.SIM'
    def source(self,size=2<<20):return save(self.p/'source.img',b'S'*size)
    def export(self,entry,held,target=None):
        with mock.patch.object(self.m,'capacity',lambda *args:None):
            return self.m.export_sim(entry,held,target or self.target,16<<20)
    def test_whole_union_check_cost_does_not_scale_with_ESP_MiB(self):
        rows=[save(self.p/'originals'/str(i),('actual original '+str(i)).encode()) for i in range(273)]
        small=save(self.p/'small.img',b'S'*(1<<20));large=save(self.p/'large.img',b'L'*(8<<20))
        results=[]
        with self.m.Union() as held:
            for row in rows:held.add(row)
            entries=[held.add(row) for row in (small,large)]
            self.assertTrue(all(fcntl.fcntl(e['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK for e in held.entries.values()))
            original=held.check
            for entry,label in zip(entries,('small','large')):
                calls=[]
                def count():calls.append(1);return original()
                start=time.monotonic()
                with mock.patch.object(held,'check',count):row,written=self.export(entry,held,self.p/(label+'.SIM'))
                elapsed=time.monotonic()-start
                fd=os.open(row['path'],os.O_RDONLY|os.O_NOFOLLOW)
                try:self.m.verify_sim(fd,row['bytes'],entry['pin'],held.check)
                finally:os.close(fd)
                results.append({'logical_bytes':entry['pin']['bytes'],'whole_union_checks':len(calls),'seconds':elapsed})
            held.finish()
        print('ACTUAL_273_SOURCE_EXPORT_SCALING '+json.dumps(results),flush=True)
        self.assertLessEqual(results[1]['whole_union_checks'],results[0]['whole_union_checks']+2,
                             'eightfold source extent repeated input-wide checks during IO')
        self.assertEqual([observed(Path(row['path'])) for row in rows],rows)
    def test_late_unrelated_same_byte_path_alias_refused_before_export_returns(self):
        source=self.source();unrelated=save(self.p/'inactive/source.dat',b'admitted unrelated original')
        original=os.pread;swapped=[];returned=[];zero_reads=[]
        with self.assertRaises(ValueError):
            with self.m.Union() as held:
                extra=held.add(unrelated);entry=held.add(source)
                def late(fd,count,offset):
                    raw=original(fd,count,offset)
                    if fd==entry['fd'] and offset==0:
                        zero_reads.append(1)
                        if len(zero_reads)==2:
                            p=Path(unrelated['path']);p.rename(p.with_suffix('.held'));save(p,b'admitted unrelated original')
                            self.assertEqual(observed(p),unrelated)
                            self.assertEqual(fcntl.fcntl(extra['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)
                            self.assertFalse(held.broken);swapped.append(True)
                    return raw
                with mock.patch.object(os,'pread',late):returned.append(self.export(entry,held))
        self.assertTrue(swapped);self.assertFalse(returned)
    def test_active_ESP_same_byte_path_drift_refused(self):
        source=self.source();original=os.pread;swapped=[];returned=[]
        with self.assertRaises(ValueError):
            with self.m.Union() as held:
                entry=held.add(source)
                def drift(fd,count,offset):
                    raw=original(fd,count,offset)
                    if fd==entry['fd'] and offset==0 and not swapped:
                        p=Path(source['path']);p.rename(p.with_suffix('.held'));save(p,original(fd,source['bytes'],0))
                        self.assertEqual(observed(p),source);self.assertFalse(held.broken);swapped.append(True)
                    return raw
                with mock.patch.object(os,'pread',drift):returned.append(self.export(entry,held))
        self.assertTrue(swapped);self.assertFalse(returned);self.assertFalse(self.target.exists())
    def test_same_byte_output_substitution_during_saved_readback_refused(self):
        source=self.source();original=os.pread;swapped=[];returned=[]
        with self.assertRaises(ValueError):
            with self.m.Union() as held:
                entry=held.add(source)
                def replace(fd,count,offset):
                    raw=original(fd,count,offset)
                    if fd!=entry['fd'] and offset==0 and self.target.exists() and not swapped:
                        saved=original(fd,os.fstat(fd).st_size,0);self.target.rename(self.target.with_suffix('.written'));save(self.target,saved)
                        self.assertEqual(sha(self.target.read_bytes()),sha(saved));swapped.append(True)
                    return raw
                with mock.patch.object(os,'pread',replace):returned.append(self.export(entry,held))
        self.assertTrue(swapped);self.assertFalse(returned)
    def test_same_inode_saved_output_timestamp_drift_refused(self):
        source=self.source();original=os.pread;changed=[];returned=[]
        with self.assertRaises(ValueError):
            with self.m.Union() as held:
                entry=held.add(source)
                def drift(fd,count,offset):
                    raw=original(fd,count,offset)
                    if fd!=entry['fd'] and offset==0 and self.target.exists() and not changed:
                        before=os.fstat(fd);os.utime(self.target,ns=(before.st_atime_ns,before.st_mtime_ns+1000000))
                        self.assertEqual(os.fstat(fd).st_ino,before.st_ino);changed.append(True)
                    return raw
                with mock.patch.object(os,'pread',drift):returned.append(self.export(entry,held))
        self.assertTrue(changed);self.assertFalse(returned)
    def test_partial_writer_substitution_stops_before_next_write(self):
        source=self.source();original=os.write;writes=[];returned=[]
        with self.assertRaises(ValueError):
            with self.m.Union() as held:
                entry=held.add(source)
                def replace(fd,raw):
                    number=original(fd,raw);writes.append(number)
                    if len(writes)==1:
                        self.target.rename(self.target.with_suffix('.written'));save(self.target,raw[:number])
                    return number
                with mock.patch.object(os,'write',replace):returned.append(self.export(entry,held))
        self.assertFalse(returned);self.assertEqual(writes,[64],'writer continued after its named inode was replaced')
    def test_actual_partial_reads_and_writes_preserve_exact_saved_content(self):
        source=self.source(16384);pread=os.pread;write=os.write
        with self.m.Union() as held:
            entry=held.add(source)
            with mock.patch.object(os,'pread',lambda fd,n,at:pread(fd,min(n,997),at)),\
                 mock.patch.object(os,'write',lambda fd,raw:write(fd,raw[:313])):
                row,written=self.export(entry,held)
                fd=os.open(row['path'],os.O_RDONLY|os.O_NOFOLLOW)
                try:self.m.verify_sim(fd,row['bytes'],source,held.check)
                finally:os.close(fd)
            held.finish()
    def test_actual_source_short_EOF_and_readback_EIO_refuse_export(self):
        source=self.source(16384);pread=os.pread
        for kind in ('source-EOF','readback-EIO'):
            returned=[];target=self.p/(kind+'.SIM')
            with self.assertRaises((ValueError,OSError)):
                with self.m.Union() as held:
                    entry=held.add(source)
                    def fail(fd,n,at):
                        if kind=='source-EOF' and fd==entry['fd']:return b'' if at>=4096 else pread(fd,min(n,997),at)
                        if kind=='readback-EIO' and fd!=entry['fd']:raise OSError(errno.EIO,'actual saved-readback failure')
                        return pread(fd,n,at)
                    with mock.patch.object(os,'pread',fail):returned.append(self.export(entry,held,target))
            self.assertFalse(returned)


class CustodyRegression(unittest.TestCase):
    """Modeled prior lineage; actual private writer/FD/lease/publication boundary."""
    @classmethod
    def setUpClass(cls):cls.m=load(PATH,'native_custody_regression')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir="/var/tmp");self.addCleanup(self.temp.cleanup)
        self.p=Path(self.temp.name);self.row=save(self.p/'inputs/source.img',b'original sparse fixture'.ljust(16384,b'\0'))
        self.request=jsave(self.p/'request.json',{'modeled_prior_lineage':True})
        self.parent=self.p/'output-parent';self.parent.mkdir(mode=0o700);self.out=self.parent/'private'
    def run_export(self):
        def lineage(request,held):return held.add(self.row),{'modeled_prior_lineage':True}
        with mock.patch.object(self.m,'validate_lineage',lineage),mock.patch.object(self.m,'capacity',lambda *args:None):
            return self.m.ingest(Path(self.request['path']),self.request['sha256'],self.out,5<<20)
    def test_same_bytes_replacement_before_first_ESP_lease_refused(self):
        original=self.m.Union.add;replaced=[]
        def add(union,row,*args,**kwargs):
            p=Path(row['path'])
            if p.name=='ESP.SIM' and not replaced:
                raw=p.read_bytes();p.rename(p.with_suffix('.written'));save(p,raw);replaced.append(True)
            return original(union,row,*args,**kwargs)
        with mock.patch.object(self.m.Union,'add',add):
            with self.assertRaises(ValueError):self.run_export()
        self.assertTrue(replaced);self.assertFalse((self.out/'manifest.json').exists())
    def test_same_bytes_replacement_before_first_manifest_lease_refused(self):
        original=self.m.Union.add;replaced=[]
        def add(union,row,*args,**kwargs):
            p=Path(row['path'])
            if p.name=='.manifest.part' and not replaced:
                raw=p.read_bytes();p.rename(p.with_suffix('.written'));save(p,raw);replaced.append(True)
            return original(union,row,*args,**kwargs)
        with mock.patch.object(self.m.Union,'add',add):
            with self.assertRaises(ValueError):self.run_export()
        self.assertTrue(replaced);self.assertFalse((self.out/'manifest.json').exists())
    def test_same_inode_input_ancestor_symlink_alias_refused(self):
        original=self.m.export_sim
        def swap(*args):
            (self.p/'inputs').rename(self.p/'moved-inputs');(self.p/'inputs').symlink_to(self.p/'moved-inputs',target_is_directory=True)
            return original(*args)
        with mock.patch.object(self.m,'export_sim',swap):
            with self.assertRaises(ValueError):self.run_export()
        self.assertFalse((self.out/'manifest.json').exists())
    def test_same_inode_output_ancestor_symlink_alias_refused(self):
        original=self.m.Union.finish
        def swap(union):
            original(union)
            self.parent.rename(self.p/'moved-output');self.parent.symlink_to(self.p/'moved-output',target_is_directory=True)
        with mock.patch.object(self.m.Union,'finish',swap):
            with self.assertRaises(ValueError):self.run_export()
        self.assertFalse((self.out/'manifest.json').exists())

    def test_output_eio_zero_write_and_fsync_failure_preserve_only_partial(self):
        original_write=os.write;original_fsync=os.fsync
        for kind in ('eio','zero','fsync'):
            self.out=self.parent/('failure-'+kind);output=self.out
            def writer(fd,raw):
                if kind=='eio':raise OSError(errno.EIO,'controlled EIO')
                if kind=='zero':return 0
                return original_write(fd,raw)
            def sync(fd):
                if kind=='fsync':raise OSError(errno.EIO,'controlled fsync')
                return original_fsync(fd)
            with mock.patch.object(os,'write',writer),mock.patch.object(os,'fsync',sync):
                with self.assertRaises((ValueError,OSError)):self.run_export()
            self.assertFalse((output/'manifest.json').exists())

    def test_lease_unlock_failure_prevents_canonical_manifest(self):
        real=fcntl.fcntl;failed=[False]
        def controlled(fd,operation,*args):
            if operation==fcntl.F_SETLEASE and args==(fcntl.F_UNLCK,) and not failed[0]:
                failed[0]=True;raise OSError(errno.EIO,'actual close follows controlled unlock failure')
            return real(fd,operation,*args)
        with mock.patch.object(fcntl,'fcntl',controlled):self.assertRaises(OSError,self.run_export)
        self.assertTrue(failed[0]);self.assertFalse((self.out/'manifest.json').exists())

    def test_real_conflicting_writer_break_refuses_manifest_in_isolated_child(self):
        pid=os.fork()
        if pid==0:
            try:
                original=self.m.export_sim
                def break_source(entry,held,*args):
                    try:writer=os.open(self.row['path'],os.O_WRONLY|os.O_NONBLOCK)
                    except BlockingIOError:pass
                    else:os.close(writer);raise AssertionError('leased original admitted a writer')
                    held.check();return original(entry,held,*args)
                with mock.patch.object(self.m,'export_sim',break_source):
                    try:self.run_export()
                    except ValueError:pass
                    else:raise AssertionError('lease break was accepted')
                assert not (self.out/'manifest.json').exists();os._exit(0)
            except BaseException:os._exit(1)
        waited,status=os.waitpid(pid,0);self.assertEqual(waited,pid);self.assertEqual(os.waitstatus_to_exitcode(status),0)


if __name__=='__main__':unittest.main()
