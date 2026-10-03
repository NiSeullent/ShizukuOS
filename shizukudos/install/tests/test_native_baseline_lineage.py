# SPDX-License-Identifier: GPL-2.0-only
"""Real Linux FD/lease/IPC controls; provenance fixtures are NOT Windows proof."""
import ast, importlib.util, json, os, pickle, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
m=load('lineage_controls',ROOT/'shizukudos/install/native_baseline_lineage.py')
ingest=load('lineage_actual_ingester',ROOT/'shizukudos/install/native_payload_ingest.py')

class LinuxControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/tmp',prefix='shz-root-lineage-controls-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.source=self.make('original',b'LINUX FIXTURE NOT WINDOWS');self.archive=self.make('archive',b'archive fixture')
        self.producers=[self.make('producer-'+str(i),('fixture producer'+str(i)).encode()) for i in range(3)]
        snapshot={'id':'7','name':'windows98-clean-installed'}
        self.fact={'schema':'shizukuos.independent-root-snapshot-rederivation.v1','scope':'ARCHIVE_SNAPSHOT7_ORIGINAL_DOS_CONTROL_SOURCE_EQUALITY',
                   'status':'PASS_ACTUAL_ARCHIVE_SNAPSHOT7_RAW_EQUALITY','snapshot':snapshot,
                   'original_inputs':dict(zip(('archive','original_raw','current_review_source','historical_export_source','qemu_img'),[self.archive,self.source,*self.producers])),
                   'actual_export':{'bytes':self.source['bytes'],'byte_compared':self.source['bytes'],'sha256':self.source['sha256'],'sealed':True,'persisted_raw':False},
                   'original_inputs_final_readback_passed':True,'all_original_fds_closed':True,'cleanup_errors':[]}
        for key in ('OEM_media_is_archive_ancestor','RAM_checkpoint_restored','SE_license_approval','VM_started','Windows98_on_ShizukuDOS','key_application_verified'):self.fact[key]=False
        self.record=self.make('record',json.dumps(self.fact).encode())
        self.values={'SCHEMA':'shizukuos.private-root-original-installed-lineage.v1','SCOPE':m.SCOPE,'ORIGINAL_SOURCE':self.source,
                     'ARCHIVE':self.archive,'SNAPSHOT':snapshot,'REDERIVATION':self.record,'PRODUCERS':self.producers}
        self.decision=self.make('root-decision.py',self.raw())
    def make(self,name,data):
        path=self.root/name;path.write_bytes(data);path.chmod(0o400);return m.replacement.local_pin(path)
    def raw(self):return ('\n'.join(k+' = '+repr(v) for k,v in self.values.items())+'\n').encode()
    def owner(self,union):
        union.add(m.replacement.local_pin(Path(m.__file__)))
        return m.RootLineageOwner.from_admitted_root(self.decision,union)
    def test_real_full_fd_leases_provenance_never_grade_and_final_release(self):
        with ingest.Union() as union:
            with self.owner(union) as owner:
                self.assertEqual(len(owner._entries),8);owner.check()
                with self.assertRaisesRegex(ValueError,'SOURCE_CUSTODY_ONLY'):owner.verify(self.source,union.entries[Path(self.source['path'])])
                with self.assertRaises(TypeError):pickle.dumps(owner)
            with self.assertRaises(ValueError):owner.check()
            union.finish()
        fd=os.open(self.source['path'],os.O_WRONLY|os.O_NONBLOCK);os.close(fd)
    def test_source_only_actual_exec_peer_cannot_be_promoted(self):
        with ingest.Union() as union:
            with self.owner(union) as owner:
                with m.provider.Client(self.source,self.root/'actual-service',borrowed_launcher=union) as client:
                    client.wait_ready();self.assertEqual(m.provider.peer_pid(client.peer),client.child.pid)
                    with self.assertRaisesRegex(ValueError,'fixed Windows'):owner.bind(client)
                    with self.assertRaisesRegex(ValueError,'SOURCE_CUSTODY_ONLY'):owner.verify(self.source,union.entries[Path(self.source['path'])])
                    client.finish()
            union.finish()
    def test_caller_object_and_saved_summary_refused(self):
        with ingest.Union() as union:
            with self.owner(union) as owner:
                for value in ({'grade':m.SCOPE},object()):
                    with self.assertRaises(ValueError):owner.bind(value)
                with self.assertRaises(ValueError):owner.verify(self.source,union.entries[Path(self.source['path'])])
    def test_actual_original_alias_refuses_live_owner(self):
        # Renaming back still changes ctime, so final Union check must refuse too.
        with self.assertRaises(ValueError):
            with ingest.Union() as union:
                owner=self.owner(union);Path(self.source['path']).rename(self.root/'moved-original')
                try:
                    with self.assertRaises((OSError,ValueError)):owner.check()
                    with self.assertRaises((OSError,ValueError)):owner.close()
                finally:(self.root/'moved-original').rename(self.source['path'])
    def test_any_actual_producer_conflicting_writer_revokes(self):
        # Any union SIGIO break is immediate, including a non-disk producer.
        with self.assertRaises(ValueError):
            with ingest.Union() as union:
                owner=self.owner(union)
                try:
                    row=subprocess.run(['/usr/bin/python3','-I','-c','import os,sys;os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)',self.producers[1]['path']],capture_output=True,timeout=5)
                    self.assertNotEqual(row.returncode,0)
                    with self.assertRaises(ValueError):owner.check()
                finally:owner.close()
    def test_cancel_and_expiry_revoke_and_close_pidfd(self):
        for action in ('cancel','expire'):
            with ingest.Union() as union:
                owner=self.owner(union);fd=owner._pidfd
                if action=='cancel':owner.cancel()
                else:owner._deadline=0
                with self.assertRaises(ValueError):owner.check()
                with self.assertRaises(ValueError):owner.close()
                with self.assertRaises(OSError):os.fstat(fd)
    def test_hook_literal_duplicate_scope_and_oem_expansion_refuse(self):
        for raw in (self.raw()+b'import os\n',self.raw()+b'SCOPE = "extra"\n',self.raw().replace(b'WINDOWS_ORIGINAL_DOS_INSTALLED_SOURCE',b'LICENSE_APPROVED')):
            with self.assertRaises(ValueError):m.literal_decision(raw)
        self.fact['OEM_media_is_archive_ancestor']=True
        path=Path(self.record['path']);path.chmod(0o600);path.write_bytes(json.dumps(self.fact).encode());path.chmod(0o400)
        self.values['REDERIVATION']=m.replacement.local_pin(path)
        path=Path(self.decision['path']);path.chmod(0o600);path.write_bytes(self.raw());path.chmod(0o400);self.decision=m.replacement.local_pin(path)
        with ingest.Union() as union:
            with self.assertRaisesRegex(ValueError,'original-DOS-only'):self.owner(union)
    def test_connector_not_independently_admitted_refuses(self):
        with ingest.Union() as union:
            with self.assertRaisesRegex(ValueError,'source-admitted connector'):
                m.RootLineageOwner.from_admitted_root(self.decision,union)
    def test_producer_order_is_not_authority_and_wrong_closure_refuses(self):
        # Root decision producer list is a set of exact pins, not positional roles.
        self.values['PRODUCERS']=list(reversed(self.producers))
        path=Path(self.decision['path']);path.chmod(0o600);path.write_bytes(self.raw());path.chmod(0o400)
        self.decision=m.replacement.local_pin(path)
        with ingest.Union() as union:
            with self.owner(union) as owner:
                owner.check()
                changed=json.loads(json.dumps(self.fact));changed['original_inputs']['qemu_img']=self.archive
                with self.assertRaisesRegex(ValueError,'producer closure'):owner._check_provenance(changed)
    def test_root_decision_wrong_mode_or_hardlink_or_caller_union_refuses(self):
        with self.assertRaises(ValueError):m.RootLineageOwner.from_admitted_root(self.decision,object())
        path=Path(self.decision['path']);path.chmod(0o600)
        with ingest.Union() as union:
            with self.assertRaisesRegex(ValueError,'root-private'):self.owner(union)
        path.chmod(0o400);os.link(path,self.root/'alias')
        with ingest.Union() as union:
            with self.assertRaisesRegex(ValueError,'root-private'):self.owner(union)

if __name__=='__main__':unittest.main()
