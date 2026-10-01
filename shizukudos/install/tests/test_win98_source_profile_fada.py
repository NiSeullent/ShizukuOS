# SPDX-License-Identifier: GPL-2.0-or-later
"""Real tiny FAT preparation controls; synthetic Windows files are never run."""
import hashlib
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT/'shizukudos/install/win98_source_profile.py'
spec = importlib.util.spec_from_file_location('source_profile_fada',TOOL) if TOOL.exists() else None
producer = importlib.util.module_from_spec(spec) if spec else None
if spec: spec.loader.exec_module(producer)
fixtures = importlib.util.spec_from_file_location('replacement_fixture_fada',ROOT/'shizukudos/win98_boot/tests/test_prepare_replacement.py')
fixture_module = importlib.util.module_from_spec(fixtures); fixtures.loader.exec_module(fixture_module)
XMS_STAGE = Path('/root/Win98-Modern-apps-cb43/build/modern-apps/xms-himemx-cb43-v1')


class InstalledSourceProfile(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(producer,'installed-source profile producer is missing')
        self.fixture=fixture_module.ReplacementPrepare('test_validate_only_has_no_owned_disk_or_acceptance_claim')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root,self.disk,self.pin=self.fixture.root,self.fixture.disk,self.fixture.pin
        self.upstream=self.root/'upstream';(self.upstream/'boot').mkdir(parents=True);(self.upstream/'sys').mkdir()
        for rel in ('sys/sys.c','boot/boot.asm','boot/magic.mac','boot/fat12com.bin'):
            shutil.copyfile(fixture_module.UPSTREAM/rel,self.upstream/rel)
        config='XNASM=nasm\nundefine XUPX\nALLCFLAGS=-DWIN31SUPPORT\nNASMFLAGS=-DWIN31SUPPORT\n'
        (self.upstream/'config.mak').write_text(config)
        receipt=json.loads(self.fixture.receipt.read_text())
        receipt['kernel_make_config']={'text':config,'sha256':self.pin(self.upstream/'config.mak')['sha256'],
            'c_defines':['WIN31SUPPORT'],'nasm_defines':['WIN31SUPPORT']}
        self.fixture.receipt.write_text(json.dumps(receipt))
        self.source_config=b'DEVICE=C:\\WINDOWS\\HIMEM.SYS\r\nDOS=LOW\r\nFILES=30\r\n'
        self.source_auto=b'@ECHO OFF\r\nC:\\WINDOWS\\WIN.COM /B\r\n'
        for name in ('WINDOWS','WINDOWS/SYSTEM','WINDOWS/COMMAND'):
            subprocess.run(['mmd','-i',str(self.disk)+'@@16384','::'+name],check=True,capture_output=True)
        for name,data in {'MSDOS.SYS':b'[Paths]\r\nWinDir=C:\\WINDOWS\r\nWinBootDir=C:\\WINDOWS\r\nHostWinBootDrv=C\r\n[Options]\r\nBootGUI=1\r\n',
                          'CONFIG.SYS':self.source_config,'AUTOEXEC.BAT':self.source_auto,
                          'WINDOWS/WIN.COM':b'MZ synthetic Windows launcher fixture',
                          'WINDOWS/SYSTEM.INI':b'[boot]\r\nshell=Explorer.exe\r\n',
                          'WINDOWS/SYSTEM/VMM32.VXD':b'MZ synthetic VMM fixture',
                          'WINDOWS/IFSHLP.SYS':b'MZ synthetic filesystem-helper fixture'}.items():self.write_member(name,data)
        base=dict(self.fixture.profile, disk=self.pin(self.disk), freedos_source=str(self.upstream),
                  boot_template={'kind':'fat12com','file':self.pin(self.upstream/'boot/fat12com.bin')},
                  build_receipt=self.pin(self.fixture.receipt))
        self.base=self.root/'replacement-base.json';self.base.write_text(json.dumps(base))
        self.request={'schema':'shizukuos.win98-source-profile-request.v1','replacement_profile':self.pin(self.base),
            'drive':'C','windows_directory':'WINDOWS','boot_policy':'shz.foundation=win98',
            'xms':{'file':self.pin(XMS_STAGE/'artifacts/HIMEMX.EXE'),
                   'build_receipt':self.pin(XMS_STAGE/'source-build-receipt.json'),'source_root':str(XMS_STAGE/'source')}}
        self.request_path=self.root/'request.json'

    def write_member(self,name,data):
        p=self.root/'member-input';p.write_bytes(data)
        subprocess.run(['mcopy','-o','-i',str(self.disk)+'@@16384',str(p),'::'+name],check=True,capture_output=True)

    def refresh_disk(self):
        base=json.loads(self.base.read_text());base['disk']=self.pin(self.disk)
        self.base.write_text(json.dumps(base));self.request['replacement_profile']=self.pin(self.base)

    def generate(self,out=None):
        self.request_path.write_text(json.dumps(self.request))
        with patch.object(producer.replacement,'available_bytes',return_value=1<<40):
            return producer.generate(self.request_path,self.pin(self.request_path)['sha256'],out or self.root/'profile',1<<20)

    def replace_xms_receipt(self,change):
        data=json.loads((XMS_STAGE/'source-build-receipt.json').read_text());change(data)
        path=self.root/'xms-receipt.json';path.write_text(json.dumps(data))
        self.request['xms']['build_receipt']=self.pin(path)

    def malformed_short_name(self,old,new):
        # mtools refuses reserved/case-duplicate names. Edit one actual aligned
        # directory entry to model the malformed media the reader must reject.
        data=bytearray(self.disk.read_bytes())
        offsets=[at for at in range(0,len(data),32) if data[at:at+11]==old]
        self.assertEqual(len(offsets),1);self.assertEqual(len(new),11)
        at=offsets[0];self.assertIn(data[at+11],(0x10,0x20))
        data[at:at+11]=new;self.disk.write_bytes(data)

    def test_actual_fat_source_generates_one_real_launch_and_constructor_preserves_windows_and_configs(self):
        before=self.disk.read_bytes();out=self.root/'profile'
        result=self.generate(out)
        self.assertEqual(result['status'],'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED')
        self.assertTrue(all(result[k] is False for k in ('Windows98_boot_verified','installed_Windows98_version_verified','native_apps_verified','VM_executed','public_artifact')))
        self.assertEqual((out/'original-config/CONFIG.SYS').read_bytes(),self.source_config)
        self.assertEqual((out/'original-config/AUTOEXEC.BAT').read_bytes(),self.source_auto)
        config=(out/'payloads/CONFIG.SYS').read_bytes();auto=(out/'payloads/AUTOEXEC.BAT').read_bytes()
        self.assertIn(b'DEVICE=C:\\HIMEMX.EXE /VERBOSE\r\n',config)
        self.assertIn(b'DEVICE=C:\\WINDOWS\\IFSHLP.SYS\r\n',config);self.assertIn(b'DOS=HIGH\r\n',config)
        self.assertEqual(auto.count(b'C:\\WINDOWS\\WIN.COM'),1)
        self.assertNotIn(b'SHZREADY',auto);self.assertNotIn(b'/B',auto)
        self.assertEqual(self.disk.read_bytes(),before)
        profile=out/'replacement-profile.json';owned=self.root/'constructed'
        with patch.object(producer.replacement,'available_bytes',return_value=1<<40):
            proof=producer.replacement.prepare(profile,self.pin(profile)['sha256'],owned,'full',len(before),1<<20)
        self.assertFalse(proof['Windows98_boot_verified'])
        self.assertEqual((owned/'original-files/CONFIG.SYS').read_bytes(),self.source_config)
        original=self.fixture.inventory(self.disk);after=self.fixture.inventory(owned/'replacement.img')
        for name,row in original.items():
            if name not in {'CONFIG.SYS','AUTOEXEC.BAT'}:self.assertEqual(row,after[name],name)

    def test_ambiguous_or_wrong_observed_windows_paths_refused_before_output(self):
        for data in (b'[Paths]\r\nWinDir=C:\\WINDOWS\r\nWinDir=C:\\OTHER\r\nWinBootDir=C:\\WINDOWS\r\nHostWinBootDrv=C\r\n',
                     b'[Paths]\r\nWinDir=D:\\WINDOWS\r\nWinBootDir=D:\\WINDOWS\r\nHostWinBootDrv=D\r\n'):
            self.write_member('MSDOS.SYS',data);self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_missing_installed_vmm_refused_instead_of_accepting_cabinet_media(self):
        subprocess.run(['mdel','-i',str(self.disk)+'@@16384','::WINDOWS/SYSTEM/VMM32.VXD'],check=True,capture_output=True)
        self.write_member('WINDOWS/BASE4.CAB',b'synthetic cabinet fixture');self.refresh_disk()
        with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile').exists())

    def test_diagnostic_policy_or_command_syntax_cannot_replace_observed_launch(self):
        for key,value in (('boot_policy','shz.desktop'),('windows_directory','WINDOWS&OTHER'),('drive','C:;'),('windows_directory','WINDOWS/SYSTEM')):
            saved=self.request[key];self.request[key]=value
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists());self.request[key]=saved

    def test_source_disk_drift_or_existing_writer_refused_before_output(self):
        writer=os.open(self.disk,os.O_WRONLY|os.O_NONBLOCK)
        try:
            with self.assertRaises(OSError):self.generate()
        finally:os.close(writer)
        self.write_member('CONFIG.SYS',b'changed source configuration')
        with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile').exists())

    def test_staged_launch_file_cannot_be_replaced_and_self_pinned_as_expected_output(self):
        write=producer.write_private
        def tamper(path,data):
            write(path,data)
            if path.name=='AUTOEXEC.BAT' and path.parent.name=='payloads':
                path.write_bytes(b'@ECHO OFF\r\nC:\\OTHER\\WIN.COM\r\n')
        with patch.object(producer,'write_private',tamper):
            with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile/replacement-profile.json').exists())

    def test_observed_country_and_nls_pair_is_preserved_without_diagnostic_commands(self):
        country=b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n'
        nls=b'LOADHIGH C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS\r\n'
        self.write_member('WINDOWS/COUNTRY.SYS',b'synthetic locale data')
        self.write_member('WINDOWS/COMMAND/NLSFUNC.EXE',b'MZ synthetic NLS fixture')
        self.write_member('CONFIG.SYS',self.source_config+country)
        self.write_member('AUTOEXEC.BAT',nls+b'C:\\UNPINNED.EXE\r\n'+self.source_auto);self.refresh_disk()
        result=self.generate()
        self.assertEqual(result['locale'],{'country':[country.decode().strip()],'nls':[nls.decode().strip()]})
        self.assertIn(country,(self.root/'profile/payloads/CONFIG.SYS').read_bytes())
        auto=(self.root/'profile/payloads/AUTOEXEC.BAT').read_bytes()
        self.assertIn(nls,auto);self.assertNotIn(b'UNPINNED',auto)
        self.assertEqual(result['observed_members']['WINDOWS/COUNTRY.SYS']['sha256'],hashlib.sha256(b'synthetic locale data').hexdigest())
        self.assertIn('WINDOWS/COMMAND/NLSFUNC.EXE',result['observed_members'])

    def test_ambiguous_locale_or_command_injection_is_refused_before_output(self):
        for config,auto in ((b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n',b''),
                            (b'COUNTRY=82,949,C:\\OTHER\\COUNTRY.SYS\r\n',b''),
                            (b'',b'C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS & C:\\OTHER.EXE\r\n')):
            self.write_member('CONFIG.SYS',config or b'REM config\r\n')
            self.write_member('AUTOEXEC.BAT',auto or b'REM startup\r\n');self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_missing_win31_compiler_flags_or_changed_recorded_config_is_refused(self):
        original=self.fixture.receipt.read_text()
        for mode in ('missing','physical-drift'):
            data=json.loads(original)
            if mode=='missing':data['kernel_make_config']['nasm_defines']=[]
            else:(self.upstream/'config.mak').write_text('XNASM=nasm\n')
            self.fixture.receipt.write_text(json.dumps(data));base=json.loads(self.base.read_text())
            base['build_receipt']=self.pin(self.fixture.receipt);self.base.write_text(json.dumps(base))
            self.request['replacement_profile']=self.pin(self.base)
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_xms_altstrat_generic_receipt_or_incomplete_sources_are_refused(self):
        changes=(lambda data:data.update(schema='PASS'),
                 lambda data:next(r for r in data['builds'] if r['name']=='HIMEMX')['command'].append('-DALTSTRAT=1'),
                 lambda data:data['source_preimages']['JWasm']['files'].pop())
        for change in changes:
            self.replace_xms_receipt(change)
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_request_changed_between_constructor_validation_and_releasing_inputs_is_refused(self):
        prepare=producer.replacement.prepare
        def change_request(*args,**kwargs):
            result=prepare(*args,**kwargs)
            self.request_path.write_text(self.request_path.read_text()+' ')
            return result
        with patch.object(producer.replacement,'prepare',change_request):
            with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile').exists())

    def test_actual_writer_break_during_staging_prevents_final_profile(self):
        write=producer.write_private
        def interrupt(path,data):
            write(path,data)
            if path.name=='AUTOEXEC.BAT' and path.parent.name=='payloads':
                with self.assertRaises(BlockingIOError):os.open(self.disk,os.O_WRONLY|os.O_NONBLOCK)
        with patch.object(producer,'write_private',interrupt):
            with self.assertRaises(RuntimeError):self.generate()
        self.assertFalse((self.root/'profile/replacement-profile.json').exists())

    def test_existing_output_and_real_production_capacity_floor_cannot_be_bypassed(self):
        self.request_path.write_text(json.dumps(self.request));sha=self.pin(self.request_path)['sha256']
        floor=producer.replacement.FLOOR
        with patch.object(producer.replacement,'available_bytes',return_value=floor+(1<<20)):
            with self.assertRaises(RuntimeError):producer.generate(self.request_path,sha,self.root/'profile',1<<20)
        self.assertFalse((self.root/'profile').exists())
        out=self.root/'profile';out.mkdir();(out/'retained').write_bytes(b'retained')
        with self.assertRaises(FileExistsError):self.generate(out)
        self.assertEqual((out/'retained').read_bytes(),b'retained')

    def test_canonical_profile_tamper_or_receipt_publication_failure_leaves_no_usable_profile(self):
        publish=producer.publish
        def tamper(path,data):
            publish(path,data)
            if path.name=='replacement-profile.json':path.write_bytes(b'{"schema":"forged"}')
        with patch.object(producer,'publish',tamper):
            with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile/replacement-profile.json').exists())
        def fail_receipt(path,data):
            if path.name=='source-profile.json':raise OSError('modeled output failure')
            return publish(path,data)
        out=self.root/'receipt-failure'
        with patch.object(producer,'publish',fail_receipt):
            with self.assertRaises(OSError):self.generate(out)
        self.assertFalse((out/'replacement-profile.json').exists())

    def test_country_in_menu_or_nls_behind_goto_cannot_be_made_unconditional(self):
        country=b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n'
        nls=b'LOADHIGH C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS\r\n'
        self.write_member('WINDOWS/COUNTRY.SYS',b'synthetic locale data')
        self.write_member('WINDOWS/COMMAND/NLSFUNC.EXE',b'MZ synthetic NLS fixture')
        for config,auto in ((b'[unused]\r\n'+country,nls),(country,b'GOTO end\r\n'+nls+b':end\r\n')):
            self.write_member('CONFIG.SYS',config);self.write_member('AUTOEXEC.BAT',auto);self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_reserved_dos_directory_with_real_matching_members_is_refused(self):
        self.write_member('MSDOS.SYS',b'[Paths]\r\nWinDir=C:\\CON\r\nWinBootDir=C:\\CON\r\nHostWinBootDrv=C\r\n')
        self.malformed_short_name(b'WINDOWS    ',b'CON        ')
        self.request['windows_directory']='CON';self.refresh_disk()
        with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile').exists())

    def test_case_duplicate_actual_fat_short_names_cannot_select_another_launcher(self):
        self.write_member('WINDOWS/OTHER.COM',b'MZ another launcher fixture')
        self.malformed_short_name(b'OTHER   COM',b'win     com');self.refresh_disk()
        with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile').exists())

    def test_empty_original_configs_are_preserved_and_backups_are_not_accepted_after_tamper(self):
        self.write_member('CONFIG.SYS',b'');self.refresh_disk()
        out=self.root/'empty-original';result=self.generate(out)
        self.assertEqual((out/'original-config/CONFIG.SYS').read_bytes(),b'')
        self.assertEqual(result['original_config']['CONFIG.SYS']['bytes'],0)
        write=producer.write_private
        def tamper(path,data):
            write(path,data)
            if path.name=='AUTOEXEC.BAT' and path.parent.name=='payloads':
                (path.parent.parent/'original-config/CONFIG.SYS').write_bytes(b'changed empty backup')
        with patch.object(producer,'write_private',tamper):
            with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile/replacement-profile.json').exists())

    def test_canonical_output_lease_break_at_context_exit_removes_final_profile(self):
        lease=producer.replacement.leased_inputs
        @contextlib.contextmanager
        def interrupted(rows):
            with lease(rows) as held:
                yield held
                profiles=[row['path'] for row in rows if Path(row['path']).name=='replacement-profile.json']
                if profiles:
                    with self.assertRaises(BlockingIOError):os.open(profiles[0],os.O_WRONLY|os.O_NONBLOCK)
        with patch.object(producer.replacement,'leased_inputs',interrupted):
            with self.assertRaises(RuntimeError):self.generate()
        self.assertFalse((self.root/'profile/replacement-profile.json').exists())
        self.assertFalse((self.root/'profile/source-profile.json').exists())

    def test_control_characters_cannot_turn_dos_comments_into_active_locale_lines(self):
        country=b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n'
        nls=b'LOADHIGH C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS\r\n'
        self.write_member('WINDOWS/COUNTRY.SYS',b'synthetic locale data')
        self.write_member('WINDOWS/COMMAND/NLSFUNC.EXE',b'MZ synthetic NLS fixture')
        for config,auto in ((country,b'REM ignored\x0b'+nls),(b'REM ignored\x0c'+country,nls)):
            self.write_member('CONFIG.SYS',config);self.write_member('AUTOEXEC.BAT',auto);self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_batch_chaining_before_nls_cannot_make_an_unreachable_locale_unconditional(self):
        self.write_member('WINDOWS/COUNTRY.SYS',b'synthetic locale data')
        self.write_member('WINDOWS/COMMAND/NLSFUNC.EXE',b'MZ synthetic NLS fixture')
        self.write_member('OTHER.BAT',b'REM replacement batch context\r\n')
        self.write_member('PATHX.BAT',b'REM command-prefix batch fixture\r\n')
        self.write_member('CONFIG.SYS',b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n')
        for command in (b'C:\\OTHER.BAT',b'C:\\OTHER',b'PATHX.BAT'):
            self.write_member('AUTOEXEC.BAT',command+b'\r\nLOADHIGH C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS\r\n')
            self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_overlong_physical_command_or_comment_cannot_promote_unreachable_nls(self):
        self.write_member('WINDOWS/COUNTRY.SYS',b'synthetic locale data')
        self.write_member('WINDOWS/COMMAND/NLSFUNC.EXE',b'MZ synthetic NLS fixture')
        self.write_member('CONFIG.SYS',b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n')
        for prefix in (b'SET A=',b'REM '):
            self.write_member('AUTOEXEC.BAT',prefix+b'x'*1024+b'\r\nLOADHIGH C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS\r\n')
            self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())

    def test_overlong_config_comment_or_command_cannot_hide_menu_control_suffix(self):
        self.write_member('WINDOWS/COUNTRY.SYS',b'synthetic locale data')
        self.write_member('WINDOWS/COMMAND/NLSFUNC.EXE',b'MZ synthetic NLS fixture')
        self.write_member('AUTOEXEC.BAT',b'LOADHIGH C:\\WINDOWS\\COMMAND\\NLSFUNC.EXE C:\\WINDOWS\\COUNTRY.SYS\r\n')
        for prefix in (b'REM '+b'x'*250,b'FILES='+b'0'*248):
            # ke2046 config.c stores 253 characters, consumes/discards byte253,
            # then reads the MENUDEFAULT suffix as the next command. Python
            # must reject the complete physical line before filtering REM.
            line=prefix+b'MENUDEFAULT=11\r\n';self.assertEqual(len(line),270)
            self.write_member('CONFIG.SYS',line+b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n')
            self.refresh_disk()
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'profile').exists())
        country=b'COUNTRY=82,949,C:\\WINDOWS\\COUNTRY.SYS\r\n'
        safe=b'REM '+b'x'*245+b'\r\n';self.assertEqual(len(safe.rstrip(b'\n')),250)
        self.write_member('CONFIG.SYS',safe+country);self.refresh_disk()
        result=self.generate(self.root/'config-at-supported-bound')
        self.assertEqual(result['locale']['country'],[country.decode().strip()])
        over=b'REM '+b'x'*246+b'\r\n';self.assertEqual(len(over.rstrip(b'\n')),251)
        self.write_member('CONFIG.SYS',over+country);self.refresh_disk()
        with self.assertRaises(ValueError):self.generate()
        self.assertFalse((self.root/'profile').exists())


if __name__=='__main__':unittest.main()
