# SPDX-License-Identifier: GPL-2.0-only
"""Actual Linux service/IPC/FD controls; no QEMU or Windows execution."""
import importlib.util,json,os,pickle,signal,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
s=importlib.util.spec_from_file_location('baseline_provider_controls',ROOT/'shizukudos/install/native_baseline_provider.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/var/tmp',prefix='shz-baseline-service-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);os.chmod(self.root,0o700)
        self.source=self.root/'original';self.source.write_bytes(b'actual Linux offline fixture, NOT Windows\n');self.source.chmod(0o400);self.pin=m.replacement.local_pin(self.source)
    def client(self):return m.Client(self.pin,self.root/'service')
    def test_actual_postexec_peer_pid_source_fd_and_final_reap(self):
        with self.client() as client:
            row=client.wait_ready();self.assertEqual(row['grade'],'SOURCE_CUSTODY_ONLY');self.assertFalse(row['source_approval']);self.assertEqual(m.peer_pid(client.peer),client.child.pid)
            with m.replacement.leased_inputs([self.pin]) as held:self.assertTrue(client.match_held_source(held[self.pin['path']]))
            client.finish();self.assertEqual(client.child.returncode,0)
            with self.assertRaises(ValueError):client.query()
    def test_saved_response_and_serialization_cannot_authorize(self):
        with self.client() as client:
            client.wait_ready();saved=client.query();self.assertFalse(saved['summary']['source_approval'])
            with self.assertRaises(TypeError):pickle.dumps(client)
            with self.assertRaises(ValueError):client.query('WINDOWS_GRADE')
            client.finish()
        with self.assertRaises(ValueError):client.query()
    def test_actual_service_death_revokes_current_client(self):
        with self.client() as client:
            client.wait_ready();os.kill(client.child.pid,signal.SIGKILL);client.child.wait()
            with self.assertRaises(ValueError):client.query()
    def test_actual_alias_rename_revokes_owner(self):
        with self.client() as client:
            client.wait_ready();self.source.rename(self.root/'retained-original')
            with self.assertRaises((OSError,ValueError)):client.query()
            client.child.wait(timeout=5);self.assertNotEqual(client.child.returncode,0)
    def test_actual_conflicting_writer_break_revokes_owner(self):
        with self.client() as client:
            client.wait_ready()
            writer=subprocess.run(['/usr/bin/python3','-c','import os,sys;os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)',str(self.source)],capture_output=True,timeout=5)
            self.assertNotEqual(writer.returncode,0)
            with self.assertRaises((OSError,ValueError)):client.query()
            client.child.wait(timeout=5);self.assertNotEqual(client.child.returncode,0)
    def test_actual_replayed_sequence_refused(self):
        with self.client() as client:
            client.wait_ready();row=client.query()
            m.send(client.peer,{'operation':'CHECK','token':client.token,'sequence':row['sequence'],'challenge':row['challenge']})
            with self.assertRaises((OSError,ValueError)):m.receive(client.peer,client.deadline,client.owner_check)
            client.child.wait(timeout=5);self.assertNotEqual(client.child.returncode,0)
    def test_actual_wrong_current_token_refused(self):
        with self.client() as client:
            client.wait_ready();m.send(client.peer,{'operation':'CHECK','token':'00'*32,'sequence':1,'challenge':'01'*32})
            with self.assertRaises((OSError,ValueError)):m.receive(client.peer,client.deadline,client.owner_check)
            client.child.wait(timeout=5);self.assertNotEqual(client.child.returncode,0)
    def test_cancel_and_forked_caller_refused(self):
        with self.client() as client:
            client.wait_ready();pid=os.fork()
            if pid==0:
                try:client.owner_check()
                except ValueError:os._exit(0)
                os._exit(7)
            _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
            client.close()
            with self.assertRaises(ValueError):client.query()
    def test_actual_borrowed_ingester_union_no_nested_SIGIO(self):
        ingester=m.load(ROOT/'shizukudos/install/native_payload_ingest.py','provider_actual_ingester')
        with ingester.Union() as union:
            existing=signal.getsignal(signal.SIGIO)
            with m.Client(self.pin,self.root/'service',borrowed_launcher=union) as client:
                client.wait_ready();self.assertIs(signal.getsignal(signal.SIGIO),existing)
                union.guards.append(lambda:client.query())
                union.check() # Provider guard does not recurse into Union.check.
                union.guards.clear();client.finish()
            self.assertIs(signal.getsignal(signal.SIGIO),existing);union.finish()
    def test_actual_wrong_source_fd_cannot_match_claimed_pin(self):
        other=self.root/'other';other.write_bytes(self.source.read_bytes())
        with self.client() as client:
            client.wait_ready()
            with other.open('rb') as stream:
                with self.assertRaises(ValueError):client.match_held_source({'pin':self.pin,'fd':stream.fileno()})
            client.finish()
    def test_actual_reused_challenge_even_new_sequence_refused(self):
        with self.client() as client:
            client.wait_ready();previous=client.query()
            m.send(client.peer,{'operation':'CHECK','token':client.token,'sequence':2,'challenge':previous['challenge']})
            with self.assertRaises((OSError,ValueError)):m.receive(client.peer,client.deadline,client.owner_check)
            client.child.wait(timeout=5);self.assertNotEqual(client.child.returncode,0)
    def test_modeled_observation_hook_lifetime_never_source_approval(self):
        # Actual Linux FD/lease/reaped-child checks; Windows observation is MODELED.
        clone=self.root/'clone';clone.write_bytes(self.source.read_bytes());pin=m.replacement.local_pin(clone)
        child=subprocess.Popen(['/usr/bin/true']);pidfd=os.pidfd_open(child.pid);child.wait()
        with clone.open('rb') as f,m.replacement.leased_inputs([self.pin,pin]) as held:
            def guard(*_):
                for entry in held.values():entry['checkpoint']()
            record={'platform_id':1,'major':4,'minor':10,'build_raw':1,'display_count':1}
            observation=m.control.OwnedObservation(m.control._OBSERVATION_KEY,guard,held,self.pin,f.fileno(),pin,pidfd,child,record)
            self.assertFalse(observation.summary()['source_approval'])
            with self.assertRaises(TypeError):pickle.dumps(observation)
            copy=observation.summary();copy['observation']['major']=999
            self.assertEqual(observation.summary()['observation']['major'],4)
            observation.finish();observation._active=False
            with self.assertRaises(ValueError):observation.check()
        os.close(pidfd)
        with self.assertRaises(ValueError):m.control.OwnedObservation(object(),None,None,None,None,None,None,None,None)
    def test_source_mode_pin_and_output_collision_refused(self):
        self.source.chmod(0o600)
        with self.assertRaises((OSError,ValueError)):
            with self.client() as client:client.wait_ready()
        with self.assertRaises(ValueError):
            with self.client():pass
if __name__=='__main__':unittest.main()
