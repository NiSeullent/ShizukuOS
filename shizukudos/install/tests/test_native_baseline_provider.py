# SPDX-License-Identifier: GPL-2.0-only
"""Actual Linux service/IPC/FD controls; no QEMU or Windows execution."""
import importlib.util,json,os,pickle,signal,subprocess,tempfile,time,unittest
from unittest.mock import patch
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
    def test_finish_reads_queued_response_after_actual_clean_service_exit(self):
        # Actual source-only exec child and AF_UNIX response; only the parent's
        # receive timing is controlled. Its FINISH packet is queued before exit.
        with self.client() as client:
            client.wait_ready();receive=m.receive
            def after_exit(peer,deadline,guard):
                self.assertEqual(client.child.wait(timeout=5),0)
                return receive(peer,deadline,guard)
            with patch.object(m,'receive',side_effect=after_exit):client.finish()
            self.assertEqual(client.child.returncode,0)
            self.assertFalse(client.active)
            with self.assertRaises(ValueError):client.query()
    def test_finish_refuses_actual_nonzero_service_exit(self):
        # Corrupt only the outgoing FINISH token. The exact exec child actually
        # refuses it and exits nonzero before the parent reads the peer socket.
        with self.client() as client:
            client.wait_ready();send=m.send;receive=m.receive
            def bad_token(peer,row):send(peer,{**row,'token':'00'*32})
            def after_exit(peer,deadline,guard):
                self.assertNotEqual(client.child.wait(timeout=5),0)
                return receive(peer,deadline,guard)
            with patch.object(m,'send',side_effect=bad_token),patch.object(m,'receive',side_effect=after_exit):
                with self.assertRaisesRegex(ValueError,'actual owned service final cleanup failed'):client.finish()
            self.assertNotEqual(client.child.returncode,0)
    def test_finish_refuses_tampered_queued_response(self):
        # Read the actual source-only child's complete response after clean
        # exit, then model in-memory tampering of every bound response field.
        for field in ('token','sequence','challenge','state','summary'):
            message='actual source hold changed' if field in ('state','summary') else 'live challenge response differs'
            with self.subTest(field=field),m.Client(self.pin,self.root/('service-'+field)) as client:
                client.wait_ready();receive=m.receive
                def tampered(peer,deadline,guard):
                    self.assertEqual(client.child.wait(timeout=5),0)
                    row=receive(peer,deadline,guard)
                    if field in ('token','challenge'):row[field]='00'*32
                    elif field=='sequence':row[field]+=1
                    elif field=='state':row[field]='CHECK'
                    else:row[field]={**row[field],'source_approval':True}
                    return row
                with patch.object(m,'receive',side_effect=tampered):
                    with self.assertRaisesRegex(ValueError,message):client.finish()
                self.assertEqual(client.child.returncode,0)
                self.assertFalse(client.summary['source_approval'])
    def test_check_refuses_queued_response_after_actual_service_death(self):
        # An actual CHECK response is readable before killing/reaping the
        # service. Only FINISH may consume a response after clean keeper exit.
        with self.client() as client:
            client.wait_ready();receive=m.receive
            def after_death(peer,deadline,guard):
                self.assertTrue(m.select.select([peer],[],[],5)[0])
                os.kill(client.child.pid,signal.SIGKILL);client.child.wait(timeout=5)
                return receive(peer,deadline,guard)
            with patch.object(m,'receive',side_effect=after_death):
                with self.assertRaisesRegex(ValueError,'actual owned service exited'):client.query()
            self.assertEqual(client.child.returncode,-signal.SIGKILL)
    def test_finish_retains_launcher_lease_refusal_after_clean_service_exit(self):
        # Parent-owned configuration lease survives the actual keeper exit.
        # A real nonblocking conflicting writer revokes FINISH and must also
        # fail the mandatory parent lease teardown check.
        with self.assertRaisesRegex((ValueError,RuntimeError),'lease'):
            with self.client() as client:
                client.wait_ready();receive=m.receive
                def after_writer(peer,deadline,guard):
                    self.assertEqual(client.child.wait(timeout=5),0)
                    writer=subprocess.run(['/usr/bin/python3','-I','-c',
                        'import os,sys;os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)',
                        str(client.output/'configuration.json')],capture_output=True,timeout=5)
                    self.assertNotEqual(writer.returncode,0)
                    return receive(peer,deadline,guard)
                with patch.object(m,'receive',side_effect=after_writer):
                    with self.assertRaisesRegex((ValueError,RuntimeError),'lease'):client.finish()
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
    def test_compiler_hold_cannot_extend_expired_observation_or_repeat(self):
        # MODELED Windows record; actual source/clone leases and owned reaped Linux child.
        clone=self.root/'clone';clone.write_bytes(self.source.read_bytes());pin=m.replacement.local_pin(clone)
        child=subprocess.Popen(['/usr/bin/true']);pidfd=os.pidfd_open(child.pid);child.wait()
        try:
            with m.replacement.leased_inputs([self.pin,pin]) as held:
                guard=m.control.InputGuard(held,self.pin['path'],time.monotonic()+10,[False],lambda:None)
                observation=m.control.OwnedObservation(m.control._OBSERVATION_KEY,guard,held,self.pin,held[pin['path']]['fd'],pin,pidfd,child,{})
                hold=time.monotonic()+100;observation.begin_compiler_hold(hold);self.assertEqual(guard.deadline,hold)
                with self.assertRaises(ValueError):observation.begin_compiler_hold(time.monotonic()+100)
                guard.deadline=time.monotonic()-1
                with self.assertRaises(ValueError):observation.check()
                stale=m.control.OwnedObservation(m.control._OBSERVATION_KEY,guard,held,self.pin,held[pin['path']]['fd'],pin,pidfd,child,{})
                with self.assertRaises(ValueError):stale.begin_compiler_hold(time.monotonic()+100)
        finally:os.close(pidfd)
    def test_windows_route_requires_actual_delegated_owner_before_launch(self):
        with self.assertRaises(ValueError):
            with m.Client(self.pin,self.root/'service',control_request={'source':self.pin}):pass
        self.assertFalse((self.root/'service/service.stderr').exists())
    def test_source_mode_pin_and_output_collision_refused(self):
        self.source.chmod(0o600)
        with self.assertRaises((OSError,ValueError)):
            with self.client() as client:client.wait_ready()
        with self.assertRaises(ValueError):
            with self.client():pass
class DelegatedCleanup(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SHZ_PROVIDER_TEST_UNIT'),'requires independently owned delegated Linux test unit')
    def test_actual_member_exit_between_pidfd_and_proc_read(self):
        group=m.OwnedKeeperGroup(os.environ['SHZ_PROVIDER_TEST_UNIT'])
        child=subprocess.Popen(['/usr/bin/sleep','60'],preexec_fn=group.enter_child)
        pidfd=os.pidfd_open(child.pid);original=m.actual_group
        def exiting(pid='self'):
            if pid==child.pid:
                child.kill();child.wait(timeout=5)
            return original(pid)
        try:
            with patch.object(m,'actual_group',side_effect=exiting):
                group.signal_members(signal.SIGTERM,set())
            self.assertIsNotNone(child.returncode);self.assertFalse(group.members())
        finally:group.cleanup(child,pidfd);os.close(pidfd);group.remove()
    @unittest.skipUnless(os.environ.get('SHZ_PROVIDER_TEST_UNIT'),'requires independently owned delegated Linux test unit')
    def test_live_missing_proc_path_is_not_waived(self):
        group=m.OwnedKeeperGroup(os.environ['SHZ_PROVIDER_TEST_UNIT'])
        child=subprocess.Popen(['/usr/bin/sleep','60'],preexec_fn=group.enter_child)
        pidfd=os.pidfd_open(child.pid);original=m.actual_group
        def missing(pid='self'):
            if pid==child.pid:raise FileNotFoundError('modeled inaccessible live proc path')
            return original(pid)
        try:
            with patch.object(m,'actual_group',side_effect=missing):
                with self.assertRaisesRegex(ValueError,'live owned cleanup'):
                    group.signal_members(signal.SIGTERM,set())
            self.assertIsNone(child.poll())
        finally:group.cleanup(child,pidfd);os.close(pidfd);group.remove()
    @unittest.skipUnless(os.environ.get('SHZ_PROVIDER_TEST_UNIT'),'requires independently owned delegated Linux test unit')
    def test_actual_long_child_cleanup_before_observation_keeps_keeper_alive(self):
        # Actual Linux cgroup/Popen/pidfd with MODELED pre-OBSERVE keeper phase.
        # The keeper takes6s to reap its child; old3s SIGKILL would lose that reap.
        with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
            root=Path(temp);source=root/'source';source.write_bytes(b'protected during actual child cleanup');source.chmod(0o400)
            group=m.OwnedKeeperGroup(os.environ['SHZ_PROVIDER_TEST_UNIT'])
            program="import os,fcntl,signal,subprocess,sys,time,pathlib\nroot=pathlib.Path(sys.argv[1]);fd=os.open(root/'source',os.O_RDONLY);fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid());fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK)\nsignal.signal(signal.SIGIO,lambda *_:None);signal.signal(signal.SIGTERM,lambda *_:None)\nchild=subprocess.Popen(['/usr/bin/sleep','6']);(root/'ready').write_text(str(child.pid));child.wait();(root/'reaped').write_text('actual owned child reaped');time.sleep(60)\n"
            child=subprocess.Popen([str(Path('/usr/bin/python3').resolve()),'-I','-c',program,str(root)],preexec_fn=group.enter_child);pidfd=os.pidfd_open(child.pid)
            try:
                deadline=time.monotonic()+5
                while not (root/'ready').exists():self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                writer_program="import os,sys,time,pathlib\ntime.sleep(3.5);root=pathlib.Path(sys.argv[1])\ntry:fd=os.open(root/'source',os.O_WRONLY|os.O_NONBLOCK)\nexcept BlockingIOError:(root/'writer-blocked').write_text('RDLK kept through old3s kill boundary')\nelse:os.close(fd);(root/'writer-unexpectedly-opened').write_text('unsafe early lease release')\n"
                writer=subprocess.Popen([str(Path('/usr/bin/python3').resolve()),'-I','-c',writer_program,str(root)])
                start=time.monotonic();group.cleanup(child,pidfd);writer.wait(timeout=5)
                self.assertTrue((root/'writer-blocked').exists());self.assertFalse((root/'writer-unexpectedly-opened').exists())
                self.assertEqual(source.read_bytes(),b'protected during actual child cleanup')
                self.assertTrue((root/'reaped').exists());self.assertGreaterEqual(time.monotonic()-start,5.5)
                self.assertIsNotNone(child.returncode);self.assertFalse(group.members())
            finally:
                group.cleanup(child,pidfd);os.close(pidfd);group.remove()
    @unittest.skipUnless(os.environ.get('SHZ_PROVIDER_TEST_UNIT'),'requires independently owned delegated Linux test unit')
    def test_keeper_hardkill_waits_until_descendant_is_reaped(self):
        # Keeper TERM is ignored, actual child is forced down only after grace.
        with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
            root=Path(temp);group=m.OwnedKeeperGroup(os.environ['SHZ_PROVIDER_TEST_UNIT'])
            program="import signal,subprocess,sys,time,pathlib\nroot=pathlib.Path(sys.argv[1]);child=subprocess.Popen(['/usr/bin/sleep','60'])\nsignal.signal(signal.SIGTERM,lambda *_:None)\n(root/'ready').write_text(str(child.pid));child.wait();(root/'reaped').write_text('actual child wait completed');time.sleep(60)\n"
            child=subprocess.Popen([str(Path('/usr/bin/python3').resolve()),'-I','-c',program,str(root)],preexec_fn=group.enter_child);pidfd=os.pidfd_open(child.pid)
            try:
                deadline=time.monotonic()+5
                while not (root/'ready').exists():self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                group.cleanup(child,pidfd);self.assertTrue((root/'reaped').exists());self.assertFalse(group.members())
            finally:group.cleanup(child,pidfd);os.close(pidfd);group.remove()
if __name__=='__main__':unittest.main()
