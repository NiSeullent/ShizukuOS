#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual file/PE replay and synthetic transaction controls; no guest/network."""
import copy
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import tls13_i486_native_stage_evidence as e
import stage_tls13_i486_native as s


class FileControls(unittest.TestCase):
    def test_duplicate_nonfinite_json(self):
        for raw in (b'{"schema":1,"schema":1}', b'{"n":{"a":0,"a":1}}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): e.json_data(raw)

    def test_typed_equality_rejects_boolean_integer_aliases(self):
        for a,b in ((True,1),(False,0),({'schema':True},{'schema':1}),
                    ({'native_execution':0},{'native_execution':False}),([True],[1])):
            with self.subTest(a=a): self.assertFalse(e.same(a,b))

    def test_canonical_member_escape(self):
        for name in ('../escape','/absolute','x/../y','./x','x//y','x\\y',''):
            with self.subTest(name=name), self.assertRaises(ValueError): e.relative(name)

    def test_real_bound_alias_directory_and_fifo_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'original')
            self.assertEqual(e.read(p,8),b'original')
            with self.assertRaises(ValueError):e.read(p,7)
            q=Path(d)/'link';q.symlink_to(p)
            with self.assertRaises(ValueError):e.read(q)
            os.mkfifo(Path(d)/'pipe')
            with self.assertRaises(ValueError):e.read(Path(d)/'pipe')
            with self.assertRaises(ValueError):e.read(Path(d))

    def test_parent_alias_escape(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);(base/'actual').mkdir();(base/'actual/file').write_bytes(b'x');(base/'alias').symlink_to(base/'actual')
            with self.assertRaises(ValueError):e.read(base/'alias/file')

    def test_actual_late_file_change(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',Path(d)):
            p=Path(d)/'input';p.write_bytes(b'first');c=e.Closure();c.take(p,e.sha(b'first'));p.write_bytes(b'later')
            with self.assertRaisesRegex(ValueError,'late closure drift'):c.unchanged()

    def test_wrong_pinned_authority_before_read(self):
        for key in e.APPROVED:
            pins=dict(e.APPROVED);pins[key]='0'*64
            with self.subTest(key=key),patch.object(e,'read',side_effect=AssertionError('must not read')):
                with self.assertRaisesRegex(ValueError,'caller-approved'):e.collect(pins)

    def test_other_external_path_rejected(self):
        with self.assertRaisesRegex(ValueError,'undeclared external'):e.member_of(Path('/etc/passwd'))


class NativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table=e.policy(e.read(e.ROOT/'tools/i486_instruction_gate.py'))
        cls.installed=e.json_data(e.read(e.ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json'))['dlls']
        cls.binary=e.read(e.TLS/'latest-native/M98TLS13.dll',1<<20)
        cls.raw=e.read(e.TLS/'latest-native-full-byte-disassembly.log')

    def gate(self,binary=None,raw=None):
        return e.raw_gate(self.binary if binary is None else binary,self.raw if raw is None else raw,
                          self.table,e.CLIENT_EXPORTS,self.installed,e.IMAGE_CHARACTERISTICS['M98TLS13.DLL'])

    def test_real_frozen_linked_byte_proof(self):
        gate=self.gate();self.assertEqual(gate['instructions_decoded'],108405)
        self.assertEqual(gate['characteristics'],0x2106)

    def test_actual_classic_characteristics_tampering_rejected(self):
        import pefile
        pe=pefile.PE(data=self.binary);at=pe.FILE_HEADER.get_field_absolute_offset('Characteristics')
        for flags in (0x2306,0x2126,0x2146,0x0106,0x2107):
            data=bytearray(self.binary);data[at:at+2]=flags.to_bytes(2,'little')
            with self.subTest(flags=flags),self.assertRaisesRegex(ValueError,'classic PE characteristics'):self.gate(binary=bytes(data))
        pe.close()

    def test_missing_code_row_with_other_rows_intact(self):
        rows=self.raw.splitlines(keepends=True);n=next(i for i,x in enumerate(rows) if b':\t' in x);del rows[n]
        with self.assertRaisesRegex(ValueError,'byte/address gap'):self.gate(raw=b''.join(rows))

    def test_modern_opcode_is_not_swallowed(self):
        raw,n=re.subn(rb'([0-9a-f]+:[ \t]+(?:[0-9a-f]{2}[ \t]+)+)push[ \t]+',rb'\1mfence ',self.raw,count=1)
        self.assertEqual(n,1)
        with self.assertRaisesRegex(ValueError,'post-i486'):self.gate(raw=raw)

    def test_actual_executable_byte_change(self):
        import pefile
        pe=pefile.PE(data=self.binary);section=next(x for x in pe.sections if x.Characteristics&0x20000000)
        data=bytearray(self.binary);data[section.PointerToRawData]^=1;pe.close()
        with self.assertRaisesRegex(ValueError,'byte/address gap'):self.gate(binary=bytes(data))

    def test_both_relocation_fields_required(self):
        import pefile
        pe=pefile.PE(data=self.binary);directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        for field in ('VirtualAddress','Size'):
            data=bytearray(self.binary);at=directory.get_field_absolute_offset(field);data[at:at+4]=b'\0'*4
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'relocation fields'):self.gate(binary=bytes(data))
        pe.close()

    def test_zero_rva_nonzero_modern_directory_size_rejected(self):
        import pefile
        pe=pefile.PE(data=self.binary)
        for n in (9,10,13,14):
            data=bytearray(self.binary);at=pe.OPTIONAL_HEADER.DATA_DIRECTORY[n].get_field_absolute_offset('Size');data[at:at+4]=(1).to_bytes(4,'little')
            with self.subTest(directory=n),self.assertRaisesRegex(ValueError,'both modern'):self.gate(binary=bytes(data))
        pe.close()

    def test_unknown_policy_source_rejected(self):
        with self.assertRaisesRegex(ValueError,'unapproved'):e.policy(b'BASE={"mfence"}')


class AliasControls(unittest.TestCase):
    def tar(self,rows):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w:bz2') as t:
            for name,data,link in rows:
                x=tarfile.TarInfo(name)
                if link is not None:x.type=tarfile.SYMTYPE;x.linkname=link;t.addfile(x)
                else:x.size=len(data);t.addfile(x,io.BytesIO(data))
        return out.getvalue()

    def test_implied_directory_with_only_alias_children(self):
        base=Path('/original');raw=self.tar([('pkg/real',b'body',None),('pkg/links/one',b'', '../real'),
                                          ('pkg/links/two',b'', '../real'),('pkg/directory',b'', 'links')])
        a,d,r=e.archive_topology(raw,base,{'/original/pkg/real':e.sha(b'body')})
        self.assertIn('/original/pkg/links',d);self.assertEqual(a['/original/pkg/directory']['normalized_target'],'pkg/links')
        self.assertEqual(len(a),3);self.assertEqual(r,{'/original/pkg/real'})

    def test_escape_dangling_collision_and_alias_parent(self):
        cases=[ [('pkg/a',b'', '../../escape')], [('pkg/a',b'', 'missing')],
                [('pkg/a',b'', 'real'),('pkg/a/child',b'x',None)],
                [('pkg/a',b'x',None),('pkg/a',b'', 'real')] ]
        for rows in cases:
            rows=[('pkg/real',b'r',None)]+rows
            orig={str(Path('/original')/n):e.sha(b) for n,b,l in rows if l is None}
            with self.subTest(rows=rows),self.assertRaises(ValueError):e.archive_topology(self.tar(rows),Path('/original'),orig)

    def test_real_missing_or_changed_alias(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',Path(d)):
            base=Path(d);(base/'original').write_bytes(b'x');(base/'alias').symlink_to('original');c=e.Closure()
            c.aliases[str(base/'alias')]=dict(target='original',resolved_target=str(base/'original'),directory=False)
            e.verify_aliases(c);(base/'alias').unlink();(base/'alias').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError,'target/type drift'):e.verify_aliases(c)
            (base/'alias').unlink()
            with self.assertRaises(OSError):e.verify_aliases(c)


class StageControls(unittest.TestCase):
    def test_wrong_destination_and_existing_stage_before_collector(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'DESTINATION',Path(d)/'correct'),patch.object(e,'resource_guard'):
            with patch.object(e,'collect',side_effect=AssertionError('must not collect')):
                with self.assertRaises(ValueError):s.prepare(Path(d)/'wrong',e.APPROVED)
                (Path(d)/'correct').mkdir()
                with self.assertRaises(ValueError):s.prepare(Path(d)/'correct',e.APPROVED)

    def test_unapproved_provenance_and_authority_before_collect(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'DESTINATION',Path(d)):
            base=Path(d);(base/'provenance.json').write_bytes(b'{}');(base/'guest-files.json').write_bytes(b'{}')
            with patch.object(e,'collect',side_effect=AssertionError('must not collect')):
                with self.assertRaisesRegex(ValueError,'provenance SHA'):
                    e.check_stage(base/'guest-files.json',e.sha(b'{}'),'0'*64,'0'*64,e.APPROVED)

    @unittest.skipIf(sys.flags.optimize,'optimized preparation deliberately rejects before mutation')
    def test_failed_read_only_collect_never_creates_canonical_stage(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'DESTINATION',Path(d)/'stage'),patch.object(e,'resource_guard'):
            with patch.object(e,'collect',side_effect=ValueError('missing closure')):
                with self.assertRaisesRegex(ValueError,'missing closure'):s.prepare(Path(d)/'stage',e.APPROVED)
            self.assertFalse((Path(d)/'stage').exists())

    def test_actual_copy_detects_late_source_drift(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',Path(d)),patch.object(e,'resource_guard'):
            p=Path(d)/'original';p.write_bytes(b'first');c=e.Closure();c.take(p,e.sha(b'first'));p.write_bytes(b'later')
            out=Path(d)/'stage';out.mkdir()
            with self.assertRaisesRegex(ValueError,'drift immediately'):s.copy_inputs(out,c)
            self.assertEqual(list(out.iterdir()),[])

    def test_source_changes_during_copy_preserve_partial_evidence_and_reject(self):
        with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',Path(d)),patch.object(e,'resource_guard'):
            base=Path(d);p=base/'original';p.write_bytes(b'first');c=e.Closure();c.take(p,e.sha(b'first'))
            out=base/'stage';out.mkdir();real_write=s.write
            def drift(stage,name,data):
                result=real_write(stage,name,data);p.write_bytes(b'later');return result
            with patch.object(s,'write',side_effect=drift),self.assertRaisesRegex(ValueError,'late closure drift'):
                s.copy_inputs(out,c)
            self.assertEqual((out/'evidence/project/original').read_bytes(),b'first')

    def test_resource_floors_do_not_relax(self):
        with patch.object(e.os,'statvfs') as f:
            f.return_value.f_bavail=0;f.return_value.f_frsize=4096
            with self.assertRaisesRegex(ValueError,'disk reserve'):e.resource_guard()


class SyntheticTransactionControls(unittest.TestCase):
    """Exercise strict metadata/tree acceptance only; no synthetic CPU proof claim."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.original=self.base/'original';self.original.mkdir()
        self.stage=self.base/'stage';self.stage.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(e,'ROOT',self.original).start();patch.object(e,'DESTINATION',self.stage).start()
        self.c=e.Closure(self.stage);source=self.original/'source.c';data=b'only synthetic source'
        self.put(e.member_of(source),data);self.c.take(source,e.sha(data));self.c.sources={'source.c':e.sha(data)}
        for name in e.STAGE_SOURCES:
            source=self.original/name;source.parent.mkdir(parents=True,exist_ok=True);data=('synthetic validator '+name).encode()
            source.write_bytes(data);self.put(e.member_of(source),data);self.c.take(source,e.sha(data))
            self.c.sources[name]=e.sha(data);self.c.live_checked[str(source)]=e.sha(data)
        self.members={'guest-build/build-result.json':self.put('guest-build/build-result.json',b'{}')}
        for name in sorted(e.INPUTS):self.members[name]=self.put(name,('synthetic '+name).encode())
        self.authority=e.stage_authority(self.c,{}, {},self.members)
        self.authority_sha=self.put('stage-authority.json',s.json_bytes(self.authority))
        self.members['stage-authority.json']=self.authority_sha
        self.manifest=dict(schema=1,kind='isolated-guest-file-inputs',
            inputs=[dict(source=str(self.stage/n),guest=e.PREFIX+n,bytes=len(e.read(self.stage/n)),sha256=self.members[n]) for n in sorted(e.INPUTS)],
            outputs=[e.PREFIX+n for n in sorted(e.OUTPUTS)],backups=[],nonce=e.NONCE,command=e.PREFIX+'T13RUN.EXE',
            source_receipts=[dict(path=str(self.stage/'stage-authority.json'),sha256=self.authority_sha)],
            guest_execution='NOT-VERIFIED',network_required=False,
            scope='Corrected original latest/LTS DLL preparation only; no WinSock/OS/apps acceptance')
        self.manifest_sha=self.put('guest-files.json',s.json_bytes(self.manifest))
        self.provenance=e.provenance(self.manifest_sha,self.authority_sha,self.c,self.members)
        self.provenance_sha=self.put('provenance.json',s.json_bytes(self.provenance))
        self.collect=patch.object(e,'collect',return_value=({}, {},{}, {},self.c)).start()
        # This bypass is local to the metadata controls: real PE proof has its
        # separate actual frozen binary tests and the whole approved collector.
        patch.object(e,'generated',return_value=({}, {},dict(self.members))).start()

    def put(self,name,data):
        p=self.stage/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return e.sha(data)

    def check(self):
        return e.check_stage(self.stage/'guest-files.json',self.manifest_sha,self.authority_sha,self.provenance_sha,e.APPROVED)

    def test_nominal_synthetic_metadata_tree_and_false_scope(self):
        r=self.check();self.assertTrue(r['passed']);self.assertTrue(all(r[n] is False for n in e.SCOPE))

    def test_independent_three_pins_reject_changed_bytes(self):
        for name,reason in (('provenance.json','provenance SHA'),('guest-files.json','manifest SHA'),('stage-authority.json','stage authority SHA')):
            p=self.stage/name;old=p.read_bytes();p.write_bytes(old+b' ')
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,reason):self.check()
            p.write_bytes(old)

    def test_changed_authority_generation_even_with_new_metadata_pin(self):
        self.authority['guest_build_sha256']='0'*64
        self.authority_sha=self.put('stage-authority.json',s.json_bytes(self.authority))
        self.manifest['source_receipts'][0]['sha256']=self.authority_sha
        self.manifest_sha=self.put('guest-files.json',s.json_bytes(self.manifest))
        with self.assertRaisesRegex(ValueError,'authority source/CPU/scope drift'):self.check()

    def test_boolean_schema_or_numeric_false_cannot_alias_valid_authority(self):
        for key,value in (('schema',True),('native_execution',0)):
            original=self.authority[key];self.authority[key]=value
            self.authority_sha=self.put('stage-authority.json',s.json_bytes(self.authority))
            self.manifest['source_receipts'][0]['sha256']=self.authority_sha
            self.manifest_sha=self.put('guest-files.json',s.json_bytes(self.manifest))
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'authority source/CPU/scope drift'):self.check()
            self.authority[key]=original

    def test_changed_provenance_map_with_fresh_pin_rejected(self):
        self.provenance['stage_sha256']['CA.PEM']='0'*64
        self.provenance_sha=self.put('provenance.json',s.json_bytes(self.provenance))
        with self.assertRaisesRegex(ValueError,'provenance closure drift'):self.check()

    def test_missing_original_closure_rejected(self):
        (self.stage/'evidence/project/source.c').unlink()
        with self.assertRaises((ValueError,OSError)):self.check()

    def test_unexpected_file_or_physical_directory_rejected(self):
        (self.stage/'foreign').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'stage file/alias closure'):self.check()
        (self.stage/'foreign').unlink();(self.stage/'foreign-directory').mkdir()
        with self.assertRaisesRegex(ValueError,'stage directory topology'):self.check()

    def test_original_declared_directory_metadata_cannot_be_added(self):
        self.provenance['original_directories'].append('evidence/project/undeclared')
        self.provenance_sha=self.put('provenance.json',s.json_bytes(self.provenance))
        with self.assertRaisesRegex(ValueError,'provenance closure drift'):self.check()

    def test_declared_alias_metadata_cannot_be_added(self):
        self.provenance['original_aliases']['evidence/project/alias']=dict(target='source.c',normalized_target='evidence/project/source.c',directory=False)
        self.provenance_sha=self.put('provenance.json',s.json_bytes(self.provenance))
        with self.assertRaisesRegex(ValueError,'provenance closure drift'):self.check()

    def test_generated_file_symlink_escape_rejected(self):
        p=self.stage/'CA.PEM';p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'canonical path'):self.check()

    def test_late_generated_bytes_rejected_after_tree_validation(self):
        def change():
            (self.stage/'CA.PEM').write_bytes(b'late bytes');e.Closure.unchanged(self.c)
        with patch.object(self.c,'unchanged',side_effect=change),self.assertRaisesRegex(ValueError,'late generated'):self.check()

    def test_late_live_validator_change_after_frozen_closure_check_rejected(self):
        def change():
            e.Closure.unchanged(self.c)
            (self.original/e.STAGE_SOURCES[0]).write_bytes(b'late current source bytes')
        with patch.object(self.c,'unchanged',side_effect=change),self.assertRaisesRegex(ValueError,'late current validator/stager drift'):
            self.check()


if __name__=='__main__':unittest.main(verbosity=2)
