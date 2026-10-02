# SPDX-License-Identifier: GPL-2.0-only
"""Actual host process/descriptor controls; never QEMU or Windows execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
old=module('old_main_controls',HERE/'tests/test_controller_main.py')
class DefaultTruth(unittest.TestCase):
    fixture=old.MainControls.fixture
    def test_successful_spawn_before_log_close_failure_is_recorded_executed(self):
        close=old.u.BoundedLogs.close_writers
        def fail(logs):
            close(logs);raise OSError('host control: writer close failed after successful spawn')
        with patch.object(old.m,'get_custody',return_value=None),patch.object(old.u.BoundedLogs,'close_writers',fail):
            result,error,record,state,out=self.fixture('normal')
        self.assertIsNone(error);self.assertIn('child',state)
        self.assertTrue(record['VM_executed'],'successful actual launch boundary must precede fallible log close')
        self.assertEqual(record['owned_pid'],state['child'].pid)
        self.assertFalse(record['collection_verified'])
class NewSeam(unittest.TestCase):
    def test_independent_task_custodian_exists(self):
        self.assertTrue((HERE/'task_custody.py').is_file(),'independent direct-parent custody is absent')


import array,errno,fcntl,hashlib,json,os,signal,socket,subprocess,sys,threading,time
r=module('host_custody_rpc',HERE/'custody_rpc.py')
g=module('host_task_custody',HERE/'task_custody.py')
def pinned(path):
    path=Path(path).resolve();return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
class RPCControls(unittest.TestCase):
    def pair(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);self.addCleanup(a.close);self.addCleanup(b.close)
        return r.Channel(a,os.getpid()),r.Channel(b,os.getpid())
    def test_actual_seqpacket_scm_rights_identity_and_credentials(self):
        a,b=self.pair();rd,wr=os.pipe();self.addCleanup(os.close,rd);self.addCleanup(os.close,wr)
        a.send({'value':'owned'},[wr]);row,fds=b.receive();self.assertEqual(row,{'value':'owned'});self.assertEqual(len(fds),1)
        try:self.assertEqual(os.fstat(fds[0]).st_ino,os.fstat(wr).st_ino);os.write(fds[0],b'x');self.assertEqual(os.read(rd,1),b'x')
        finally:os.close(fds[0])
    def test_wrong_actual_sender_and_duplicate_json_refused(self):
        a,b=self.pair();b.peer_pid+=100000;a.send({'x':1})
        with self.assertRaises(ValueError):b.receive()
        b.peer_pid=os.getpid();a.socket.send(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):b.receive()
    def test_surplus_rights_flood_and_eof_are_bounded(self):
        a,b=self.pair();fds=[os.open('/dev/null',os.O_RDONLY) for _ in range(4)]
        try:a.socket.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))])
        finally:
            for fd in fds:os.close(fd)
        with self.assertRaises(ValueError):b.receive()
        a.socket.send(b'x'*(r.MAX_PACKET+1))
        with self.assertRaises(ValueError):b.receive()
        a.socket.close()
        with self.assertRaises(EOFError):b.receive()
    def test_empty_socket_deadline(self):
        a,b=self.pair();start=time.monotonic()
        with self.assertRaises(socket.timeout):b.receive(.05)
        self.assertLess(time.monotonic()-start,.5)
class ActualOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
    def setup_owner(self,code='import time;time.sleep(30)'):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);out=Path(temporary.name)
        union=g.LeaseUnion();exe=pinned(sys.executable);union.add(exe)
        group=g.TaskGroup(self.parent,'custody-case-'+str(time.monotonic_ns()),{'memory.high':128<<20,'memory.max':160<<20,'pids.max':16,'cpu.max':'100000 100000'})
        args=[exe['path'],'-c',code,'-serial','file:/proc/self/fd/0','-debugcon','file:/proc/self/fd/1','-global','isa-debugcon.iobase=0xe9']
        owner=g.Owner(union,group,args,exe,20);owner.output=out
        pipes=[os.pipe() for _ in range(3)];rights=[p[1] for p in pipes]
        request={'argv':args,'pipes':[[os.fstat(fd).st_dev,os.fstat(fd).st_ino] for fd in rights]}
        def clean():
            if owner.process is not None:
                if owner.pidfd is not None:owner.signal(signal.SIGKILL)
                elif owner.process.poll() is None:owner.process.kill()
                try:owner.wait(3)
                except BaseException:
                    owner.process.wait(timeout=3)
            if not union.closed:
                try:owner.release()
                except BaseException:
                    if owner.process is None:union.close()
            if not getattr(group,'closed',False):group.close()
            for rd,wr in pipes:os.close(rd);os.close(wr)
        self.addCleanup(clean);return owner,request,rights,out
    def test_real_parent_pidfd_and_cgroup_precede_target(self):
        owner,request,rights,out=self.setup_owner("import pathlib,time;pathlib.Path('where').write_text(pathlib.Path('/proc/self/cgroup').read_text());time.sleep(30)")
        ack=owner.spawn(request,rights);self.assertEqual(ack['pid'],owner.process.pid);owner.assert_owned()
        stop=time.monotonic()+2
        while not (out/'where').exists() and time.monotonic()<stop:time.sleep(.01)
        self.assertEqual((out/'where').read_text().strip(),'0::/'+str(owner.group.path.relative_to('/sys/fs/cgroup')))
        self.assertNotEqual(owner.group.path,owner.group.guardian)
        self.assertIn('Pid:',Path('/proc/self/fdinfo/%d'%owner.pidfd).read_text())
    def test_pidfd_refusal_never_executes_target(self):
        owner,request,rights,out=self.setup_owner("import pathlib,time;pathlib.Path('executed').write_text('target');time.sleep(30)")
        with patch.object(g.os,'pidfd_open',side_effect=OSError(errno.EMFILE,'actual failure control')):
            with self.assertRaises(OSError):owner.spawn(request,rights)
        time.sleep(.1);self.assertFalse((out/'executed').exists(),'target must wait for actual pidfd admission')
    def test_live_child_and_false_echild_never_release_union(self):
        owner,request,rights,out=self.setup_owner();owner.spawn(request,rights)
        with self.assertRaises(ValueError):owner.release()
        self.assertFalse(owner.union.closed);self.assertEqual(fcntl.fcntl(next(iter(owner.union.rows.values()))['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)
        with patch.object(g.os,'waitid',side_effect=ChildProcessError(errno.ECHILD,'modeled wait refusal')):
            with self.assertRaises(ChildProcessError):owner.wait(.1)
        self.assertFalse(owner.confirm_reaped());self.assertFalse(owner.union.closed)
    def test_ack_loss_keeps_real_owner_and_actual_wait_recovers(self):
        owner,request,rights,out=self.setup_owner();a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        server=g.Server(r.Channel(a,os.getpid()),owner,{},out)
        b.close()
        try:
            result,returned=server.dispatch({'id':1,'op':'spawn','params':request},rights)
            with self.assertRaises(BrokenPipeError):server.channel.send({'id':1,'ok':True,'result':result})
            self.assertIsNotNone(owner.pidfd);self.assertFalse(owner.union.closed)
            self.assertTrue(owner.recover());self.assertTrue(owner.confirm_reaped());owner.release();self.assertTrue(owner.union.closed)
        finally:a.close()
    def test_one_shot_invalid_argv_and_duplicate_output_pipes(self):
        owner,request,rights,out=self.setup_owner();bad={**request,'argv':request['argv']+['-nic','user']}
        with self.assertRaises(ValueError):owner.spawn(bad,rights)
        with self.assertRaises(ValueError):owner.spawn(request,rights)
        self.assertIsNone(owner.process)
    def test_actual_lease_break_is_failed_custody_with_owned_child_retained(self):
        owner,request,rights,out=self.setup_owner();source=out/'immutable';source.write_bytes(b'owned source');entry=owner.union.add(pinned(source));owner.spawn(request,rights)
        writer=subprocess.run([str(Path(sys.executable).resolve()),'-c',"import os,sys;os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)",str(source)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
        self.assertNotEqual(writer.returncode,0);self.assertTrue(owner.union.broken)
        with self.assertRaises(ValueError):owner.union.check()
        self.assertEqual(source.read_bytes(),b'owned source');self.assertFalse(owner.union.closed);self.assertIsNotNone(owner.pidfd)
        owner.signal(signal.SIGKILL);owner.wait(3)
        with self.assertRaises(ValueError):owner.release()
        self.assertTrue(owner.union.closed)
    def test_pid_metadata_reuse_cannot_redirect_pidfd_signal(self):
        owner,request,rights,out=self.setup_owner();owner.spawn(request,rights);original=owner.process.pid
        owner.process.pid=os.getpid()
        try:
            with self.assertRaises(ValueError):owner.assert_owned()
            owner.signal(signal.SIGTERM)
        finally:owner.process.pid=original
        self.assertIsNotNone(owner.wait(3));self.assertTrue(owner.confirm_reaped())
    def test_cgroup_cap_drift_refuses_exec(self):
        owner,request,rights,out=self.setup_owner();(owner.group.path/'pids.max').write_text('15')
        with self.assertRaises(ValueError):owner.spawn(request,rights)
        self.assertIsNone(owner.process);(owner.group.path/'pids.max').write_text('16')
class FrozenSourceControls(unittest.TestCase):
    def test_held_frozen_bytes_execute_before_path_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);original=root/'original.py';original.write_text('VALUE="approved"\n')
            target=root/'runtime-source/example.py';target.parent.mkdir();target.write_bytes(original.read_bytes())
            union=g.LeaseUnion();self.addCleanup(lambda: union.close() if not union.closed else None)
            approved=pinned(original);union.add(approved)
            owner=type('NoSpawn',(),{'union':union})();a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            server=g.Server(r.Channel(a,os.getpid()),owner,{'example.py':approved},root);client=r.Client(b.detach(),os.getpid());self.addCleanup(client.close);self.addCleanup(a.close)
            errors=[]
            def call():
                try:client.admit_frozen(target,'example.py')
                except BaseException as error:errors.append(error)
            thread=threading.Thread(target=call);thread.start();server.once();thread.join(2);self.assertFalse(errors)
            saved=root/'saved.py';target.rename(saved);target.write_text('VALUE="unapproved"\n')
            self.assertEqual(client.load('frozen_execution',target).VALUE,'approved')
            with self.assertRaises(ValueError):client.load('not_admitted',root/'absent.py')
            with self.assertRaises(ValueError):union.check()
            with self.assertRaises(ValueError):union.close()
    def test_unadmitted_frozen_source_blocks_spawn(self):
        with tempfile.TemporaryDirectory() as td:
            union=g.LeaseUnion()
            try:
                owner=__import__('types').SimpleNamespace(union=union)
                server=g.Server(None,owner,{'build.py':{}},Path(td))
                with self.assertRaises(ValueError):server.dispatch({'id':1,'op':'spawn','params':{}},[])
            finally:union.close()


class AdditionalBoundaries(unittest.TestCase):
    def test_cli_without_custodian_refuses_before_plan_mutation(self):
        with self.assertRaises(ValueError):old.m.get_custody(None)
    def test_nonpositive_frozen_extent_is_refused_before_pread(self):
        client=object.__new__(r.Client)
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'x';source.write_bytes(b'x');fd=os.open(source,os.O_RDONLY)
            client.call=lambda *args,**kw:({'bytes':-1,'sha256':'a'*64},[fd])
            with patch.object(r.os,'pread',side_effect=AssertionError('must not read invalid size')):
                with self.assertRaises(ValueError):client.admit_frozen(source,'x')
            with self.assertRaises(OSError):os.fstat(fd)
    def test_actual_compiled_layout_uses_held_header_not_replaced_path(self):
        info=module('actual_layout_types',HERE.parents[1]/'tools/shzinfo.py')
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)/'shz_info.h';raw=(HERE.parent/'include/shz_info.h').read_bytes();target.write_bytes(raw);fd=os.open(target,os.O_RDONLY)
            try:
                client=object.__new__(r.Client);client.frozen_fds={str(target):(fd,raw)}
                target.rename(Path(td)/'saved.h');target.write_text('#error UNAPPROVED_HEADER\n')
                self.assertEqual(client.layout(info,target),5368)
            finally:os.close(fd)
    def test_source_manifest_missing_lineage_and_false_source_epoch_refused(self):
        union=g.LeaseUnion()
        try:
            with self.assertRaises(ValueError):g.admit_manifest({'schema':'shizukuos.native-custody-manifest.v1'},union)
        finally:union.close()
    def test_actual_eof_after_successful_spawn_keeps_pidfd_until_reap(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights)
            a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);server=g.Server(r.Channel(a,os.getpid()),owner,{},out);b.close()
            try:
                with self.assertRaises(EOFError):server.once(.1)
                self.assertFalse(owner.union.closed);self.assertFalse(owner.confirm_reaped());self.assertTrue(owner.recover())
            finally:a.close()
        finally:helper.doCleanups()
    def test_unreaped_wait_refusal_retains_full_union(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights)
            with patch.object(owner,'wait',return_value=None):
                self.assertFalse(owner.recover(.05));self.assertFalse(owner.confirm_reaped())
                with self.assertRaises(ValueError):owner.release()
                self.assertFalse(owner.union.closed)
            owner.wait(3)
        finally:helper.doCleanups()

class LegacyRegression(unittest.TestCase):
    pass
for name in dir(old.MainControls):
    if name.startswith('test_'):
        def legacy(self,name=name):
            control=old.MainControls(name)
            try:
                with patch.object(old.m,'get_custody',return_value=None):getattr(control,name)()
            finally:control.doCleanups()
        setattr(LegacyRegression,name,legacy)

class StrictWaitControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):ActualOwnership.setUpClass()
    def test_actual_controller_foreign_reap_never_returns_synthesized_zero(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        observer=g.ParentWait(child) if hasattr(g,'ParentWait') else child
        fd=os.pidfd_open(child.pid,0)
        try:
            if hasattr(observer,'pidfd'):observer.pidfd=fd
            signal.pidfd_send_signal(fd,signal.SIGKILL);os.waitpid(child.pid,0)
            with self.assertRaises(ChildProcessError):
                observer.observe() if hasattr(observer,'observe') else observer.poll()
            self.assertIsNone(child.returncode)
        finally:os.close(fd)
    def test_actual_controller_live_echild_refuses_then_real_wait_observes_signal(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);observer=g.ParentWait(child);observer.pidfd=os.pidfd_open(child.pid,0)
        try:
            with patch.object(g.os,'waitid',side_effect=ChildProcessError(errno.ECHILD,'modeled live status failure')):
                with self.assertRaises(ChildProcessError):observer.observe()
            self.assertFalse(observer.physically_dead);self.assertFalse(observer.safe_to_release());self.assertIsNone(child.returncode)
            observer.kill();stop=time.monotonic()+3
            while observer.observe() is None and time.monotonic()<stop:time.sleep(.01)
            self.assertEqual(child.returncode,-9);self.assertTrue(observer.reaped);self.assertTrue(observer.safe_to_release())
        finally:
            if not observer.safe_to_release():observer.kill();os.waitid(os.P_PIDFD,observer.pidfd,os.WEXITED)
            os.close(observer.pidfd)
    def test_other_empty_cgroup_cannot_release_live_original_descendant(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        descendant=None;original=None;foreign=None
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights)
            descendant=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],preexec_fn=owner.group.place_before_exec)
            owner.signal(signal.SIGKILL);owner.wait(3);self.assertTrue(owner.confirm_reaped())
            # This kernel refuses cgroup rename. Model a changed named-leaf
            # selection using two real delegated leaves and a real descendant.
            original=owner.group.path
            foreign=g.TaskGroup(helper.parent,'custody-other-'+str(time.monotonic_ns()),owner.group.limits)
            owner.group.path=foreign.path
            tick=getattr(g,'recovery_tick',lambda own,controller,group,stop:own.safe_to_release() and not (group.path/'cgroup.procs').read_text().split())
            self.assertFalse(tick(owner,None,owner.group,time.monotonic()-1),'foreign empty leaf must not authorize releasing original live descendant')
            self.assertFalse(owner.union.closed);self.assertIsNone(descendant.poll())
        finally:
            if original is not None:owner.group.path=original
            if foreign is not None:foreign.close()
            if descendant is not None:
                fd=os.pidfd_open(descendant.pid,0)
                try:signal.pidfd_send_signal(fd,signal.SIGKILL);descendant.wait(timeout=3)
                finally:os.close(fd)
            helper.doCleanups()
    def test_failed_cgroup_read_keeps_union_even_after_real_child_reap(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights);owner.signal(signal.SIGKILL);owner.wait(3)
            self.assertTrue(owner.confirm_reaped());self.assertFalse(owner.group.members())
            with patch.object(owner.group,'members',side_effect=OSError(errno.EIO,'modeled cgroup read failure')):
                self.assertFalse(g.recovery_tick(owner,None,owner.group,time.monotonic()))
            self.assertFalse(owner.union.closed);self.assertEqual(owner.record['custody_observation_failed'],'OSError')
            self.assertTrue(g.recovery_tick(owner,None,owner.group,time.monotonic()))
        finally:helper.doCleanups()
    def test_actual_nested_cgroup_descendant_prevents_release_and_recursive_kill_recovers(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        child=None;nested=None
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights);owner.signal(signal.SIGKILL);owner.wait(3)
            nested=owner.group.path/'nested-task';nested.mkdir()
            child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],preexec_fn=lambda:(nested/'cgroup.procs').write_text(str(os.getpid())))
            self.assertFalse(owner.group.members());self.assertIsNone(child.poll())
            self.assertFalse(g.recovery_tick(owner,None,owner.group,time.monotonic()-1),'recursive task population must veto empty direct membership')
            self.assertFalse(owner.union.closed);child.wait(timeout=3);self.assertEqual(child.returncode,-9)
            self.assertTrue(g.recovery_tick(owner,None,owner.group,time.monotonic()))
        finally:
            if child is not None and child.poll() is None:
                fd=os.pidfd_open(child.pid,0)
                try:signal.pidfd_send_signal(fd,signal.SIGKILL);child.wait(timeout=3)
                finally:os.close(fd)
            if nested is not None:nested.rmdir()
            helper.doCleanups()
    def test_real_target_reap_has_finite_controller_finalization_budget(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights);owner.signal(signal.SIGKILL);owner.wait(3)
            now=time.monotonic();stop=g.task_deadline(owner,now+20,None,20,now)
            self.assertEqual(stop,now+20)
            with self.assertRaises(TimeoutError):g.task_deadline(owner,now+20,stop,20,now+20.001)
            self.assertFalse(owner.union.closed)
        finally:helper.doCleanups()
    def test_empty_nested_group_cleanup_failure_still_persists_truthful_receipt(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        nested=None;a,b=socket.socketpair()
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights);owner.signal(signal.SIGKILL);owner.wait(3)
            nested=owner.group.path/'empty-owned-nested';nested.mkdir();self.assertFalse(owner.group.populated())
            if hasattr(g,'finish_task'):
                failure=g.finish_task(owner,None,owner.group,a,out,RuntimeError('host failed task'))
            else:
                # Actual old terminal order: a real ENOTEMPTY skips receipt.
                failure=RuntimeError('host failed task');owner.release()
                try:owner.group.close();g.persist(out/'custody-result.json',owner.record)
                except OSError:pass
            self.assertIsNotNone(failure)
            self.assertTrue((out/'custody-result.json').exists(),'physically safe cleanup failure must still persist failed receipt')
            row=json.loads((out/'custody-result.json').read_text());self.assertTrue(row['owned_child_reaped']);self.assertFalse(row['Windows98_boot_verified'])
            self.assertEqual(row['terminal_cleanup_errors']['cgroup'],'OSError');self.assertEqual(row['status'],'FAILED_CUSTODY_RELEASED_AFTER_ACTUAL_REAP')
        finally:
            if nested is not None:nested.rmdir()
            if getattr(owner.group,'closed',False):owner.group.path.rmdir()
            a.close();b.close();helper.doCleanups()
    def test_actual_foreign_reap_echild_never_fabricates_zero(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            owner,request,rights,out=helper.setup_owner();owner.spawn(request,rights)
            owner.signal(signal.SIGTERM);pid,status=os.waitpid(owner.process.pid,0);self.assertEqual(pid,owner.process.pid)
            with self.assertRaises(ChildProcessError):owner.poll()
            self.assertFalse(owner.record['exit_status_verified']);self.assertFalse(owner.confirm_reaped());self.assertTrue(owner.safe_to_release())
            self.assertIsNone(owner.process.returncode);owner.release();self.assertTrue(owner.union.closed)
        finally:helper.doCleanups()

class QMPAndProxyControls(unittest.TestCase):
    def test_actual_qmp_socket_peer_matches_owned_child_and_wrong_peer_refused(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            code="import socket,time;s=socket.socket(socket.AF_UNIX);s.bind('q');s.listen();a,_=s.accept();time.sleep(30)"
            owner,request,rights,out=helper.setup_owner(code);owner.spawn(request,rights)
            a,b=socket.socketpair()
            try:
                with self.assertRaises(ValueError):owner.admit_qmp(a.detach())
            finally:b.close()
            stop=time.monotonic()+2
            while not (out/'q').exists() and time.monotonic()<stop:time.sleep(.01)
            connection=socket.socket(socket.AF_UNIX);connection.connect(str(out/'q'));self.assertTrue(owner.admit_qmp(connection.detach()))
            self.assertTrue(owner.record['QMP_peer_admitted']);self.assertFalse(owner.confirm_reaped())
        finally:helper.doCleanups()
    def test_transported_three_pipe_numbers_are_rewritten_before_actual_exec(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        received=[]
        try:
            code="import os,sys,time;os.write(int(sys.argv[sys.argv.index('-serial')+1].rsplit('/',1)[1]),b'owned serial');time.sleep(30)"
            owner,request,rights,out=helper.setup_owner(code);a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            sender=r.Channel(a,os.getpid());receiver=r.Channel(b,os.getpid());sender.send(request,rights);request,received=receiver.receive()
            try:
                self.assertNotEqual(received,rights);ack=owner.spawn(request,received)
                self.assertEqual(ack['argv'][ack['argv'].index('-serial')+1],'file:/proc/self/fd/%d'%received[0])
                reader=Path('/proc/self/fd/%d'%rights[0]);inode=os.fstat(rights[0]).st_ino
                readfd=next(int(p.name) for p in Path('/proc/self/fd').iterdir() if p.name.isdigit() and int(p.name) not in rights+received and os.path.exists(p) and os.fstat(int(p.name)).st_ino==inode)
                ready=__import__('select').select([readfd],[],[],2)[0];self.assertTrue(ready);self.assertEqual(os.read(readfd,64),b'owned serial')
            finally:a.close();b.close()
        finally:
            for fd in received:os.close(fd)
            helper.doCleanups()
    def test_rpc_proxy_wait_is_actual_parent_observation(self):
        helper=ActualOwnership(methodName='runTest');helper.parent=ActualOwnership.parent
        try:
            owner,request,rights,out=helper.setup_owner();ack=owner.spawn(request,rights);a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            server=g.Server(r.Channel(a,os.getpid()),owner,{},out);client=r.Client(b.detach(),os.getpid());process=r.Process(client,ack['pid'],ack['argv'])
            result=[];errors=[]
            def call():
                try:process.terminate();result.append(process.wait(3))
                except BaseException as error:errors.append(error)
            thread=threading.Thread(target=call);thread.start()
            try:server.once();server.once();thread.join(4);self.assertFalse(errors);self.assertEqual(result,[-15]);self.assertTrue(owner.confirm_reaped());self.assertEqual(process.returncode,-15)
            finally:client.close();a.close()
        finally:helper.doCleanups()

class ResourceResult(unittest.TextTestResult):
    def startTest(self,test):
        import shutil
        base=Path(os.environ.get('TMPDIR','/tmp'))
        mem=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
        assert mem>=(6<<30)+(160<<20) and shutil.disk_usage(base).free>=(6<<30)+(160<<20)
        assert sum(p.stat().st_blocks*512 for p in base.rglob('*') if p.is_file())<=64<<20
        super().startTest(test)
if __name__=='__main__':unittest.main(testRunner=unittest.TextTestRunner(resultclass=ResourceResult,verbosity=2))
