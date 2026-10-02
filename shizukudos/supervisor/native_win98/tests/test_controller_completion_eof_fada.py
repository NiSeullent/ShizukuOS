# SPDX-License-Identifier: GPL-2.0-only
"""Actual controller exit/Unix EOF tests of the exact held production loop.

Only the guarded loop is extracted from held task_custody.main AST. ParentWait,
Unix seqpacket EOF, owned child exit and wall-clock deadlines are real Linux
facts. Source/cgroup/resource/owned-QEMU boundaries are explicit host fixtures;
this is neither native QEMU nor Windows acceptance.
"""
import ast
import copy
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
def held_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

g = held_module('held_completion_guardian', HERE / 'task_custody.py')
r = held_module('held_completion_rpc', HERE / 'custody_rpc.py')

CHILD = """import os,sys
endpoint,ready,release,code=map(int,sys.argv[1:])
os.close(endpoint)
os.write(ready,b'x');os.close(ready)
os.read(release,1);os.close(release)
sys.exit(code)
"""

class ControllerCompletionControls(unittest.TestCase):
    def fixture(self, exit_code=0, timeout=1.5, release_after=.22,
                bad_packet=False, owned_reaped=True, qmp_admitted=True,
                guard_failure=False, cancelled=False):
        raw = getattr(g, '__held_source_bytes__', None)
        self.assertIsInstance(raw, bytes, 'only independently held guardian bytes')
        tree = ast.parse(raw, filename=g.__file__)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        enclosing = next(node for node in main.body if isinstance(node, ast.Try)
                         and any(isinstance(row, ast.While) and ast.unparse(row.test) == 'controller_status.observe() is None'
                                 for row in node.body))
        start = next(i for i,row in enumerate(enclosing.body)
                     if isinstance(row, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'preparation_stop' for t in row.targets))
        loop_at = next(i for i,row in enumerate(enclosing.body)
                       if isinstance(row, ast.While) and ast.unparse(row.test) == 'controller_status.observe() is None')
        finish_at = next(i for i,row in enumerate(enclosing.body)
                         if i > loop_at and isinstance(row, ast.Expr)
                         and 'controller exit is not owned-child reap/QMP admission' in ast.unparse(row))
        args = 'controller_status controller server owner union group parent capture out manifest stopped check_bootstrap'.split()
        function = ast.FunctionDef(name='exact_production_loop',
            args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=x) for x in args],
                               kwonlyargs=[],kw_defaults=[],defaults=[]),
            body=copy.deepcopy(enclosing.body[start:finish_at+1]), decorator_list=[])
        code = ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[]))
        checks = []; after_eof = []
        def guard(*_):
            checks.append('resource')
            if guard_failure and len(checks) >= 2:
                raise ValueError('modeled retained ancestor guard refusal')
        namespace = dict(g.__dict__)
        namespace['resource_guard'] = guard
        exec(compile(code, g.__file__, 'exec'), namespace)
        call = namespace['exact_production_loop']
        left,right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        ready_rd,ready_wr = os.pipe(); release_rd,release_wr = os.pipe()
        child = None; observer = None; timer = None; cancel_timer = None
        fds = [ready_rd,ready_wr,release_rd,release_wr]
        try:
            if bad_packet:
                child = subprocess.Popen([sys.executable,'-B','-c',
                    'import os,socket,sys; s=socket.socket(fileno=int(sys.argv[1]));s.send(b"{bad-json}");os.write(int(sys.argv[2]),b"x");os.read(int(sys.argv[3]),1)',
                    str(right.fileno()),str(ready_wr),str(release_rd)],
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    pass_fds=(right.fileno(),ready_wr,release_rd))
            else:
                child = subprocess.Popen([sys.executable,'-B','-c',CHILD,
                    str(right.fileno()),str(ready_wr),str(release_rd),str(exit_code)],
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    pass_fds=(right.fileno(),ready_wr,release_rd))
            right.close();os.close(ready_wr);fds.remove(ready_wr)
            os.close(release_rd);fds.remove(release_rd)
            observer = g.ParentWait(child);observer.pidfd=os.pidfd_open(child.pid,0)
            self.assertEqual(os.read(ready_rd,1),b'x')
            self.assertIsNone(observer.observe(),'real controller must still be live after closing its endpoint')
            owner = types.SimpleNamespace(start=None,record={'QMP_peer_admitted':qmp_admitted},
                                          confirm_reaped=lambda:owned_reaped)
            source = types.SimpleNamespace(check=lambda:after_eof.append('source'))
            group = types.SimpleNamespace(check=lambda:after_eof.append('cgroup'))
            server = g.Server(r.Channel(left,child.pid),
                              types.SimpleNamespace(union=types.SimpleNamespace(rows={})),{},Path('.'))
            stopped=[False]
            if release_after is not None:
                timer=threading.Timer(release_after,lambda:os.write(release_wr,b'x'))
                timer.start()
            if cancelled:
                cancel_timer=threading.Timer(.04,lambda:stopped.__setitem__(0,True));cancel_timer.start()
            started=time.monotonic();error=None
            try:
                call(observer,child,server,owner,source,group,Path('/modeled-parent'),
                     None,Path('.'),{'limits':{},'timeout':timeout},stopped,
                     lambda:after_eof.append('bootstrap'))
            except BaseException as exc:error=exc
            elapsed=time.monotonic()-started
            return error,observer.reaped,child.returncode,checks,after_eof,elapsed,dict(owner.record)
        finally:
            for item in (timer,cancel_timer):
                if item is not None:item.cancel();item.join(2)
            if child is not None and observer is not None:
                if not observer.reaped:
                    if not observer.exited():signal.pidfd_send_signal(observer.pidfd,signal.SIGKILL)
                    stop=time.monotonic()+2
                    while observer.observe() is None and time.monotonic()<stop:time.sleep(.005)
                    self.assertTrue(observer.reaped,'only actual owned child reap permits test cleanup')
                if observer.pidfd is not None:os.close(observer.pidfd)
            left.close();right.close()
            for fd in fds:os.close(fd)

    def test_actual_EOF_before_exact_controller_zero_waits_and_keeps_guards(self):
        error,reaped,code,checks,retained,elapsed,record=self.fixture()
        self.assertIsNone(error,'normal EOF must await actual parent status rather than fail collection')
        self.assertTrue(reaped);self.assertEqual(code,0)
        self.assertGreaterEqual(elapsed,.18);self.assertGreaterEqual(len(checks),2)
        self.assertEqual(len(retained),len(checks)*3)
        self.assertTrue(record.get('controller_rpc_EOF_observed'))

    def test_actual_EOF_nonzero_controller_is_refused(self):
        error,reaped,code,*_=self.fixture(exit_code=7)
        self.assertIsInstance(error,ValueError);self.assertTrue(reaped);self.assertEqual(code,7)

    def test_actual_closed_channel_live_controller_keeps_original_deadline(self):
        error,reaped,code,checks,retained,elapsed,record=self.fixture(timeout=.14,release_after=None)
        self.assertIsInstance(error,TimeoutError);self.assertFalse(reaped);self.assertIsNone(code)
        self.assertLess(elapsed,.7);self.assertGreaterEqual(len(checks),2)

    def test_actual_EOF_does_not_skip_retained_resource_guard(self):
        error,_,_,checks,*_=self.fixture(guard_failure=True)
        self.assertIsInstance(error,ValueError);self.assertIn('ancestor guard refusal',str(error));self.assertEqual(len(checks),2)

    def test_actual_EOF_does_not_skip_guardian_cancellation(self):
        error,_,_,checks,*_=self.fixture(cancelled=True)
        self.assertIsInstance(error,ValueError);self.assertIn('guardian cancellation',str(error))

    def test_actual_bad_packet_is_not_normal_EOF(self):
        error,_,_,*_=self.fixture(bad_packet=True)
        self.assertIsInstance(error,ValueError)

    def test_controller_zero_without_owned_child_reap_is_refused(self):
        error,reaped,code,*_=self.fixture(owned_reaped=False)
        self.assertIsInstance(error,ValueError);self.assertTrue(reaped);self.assertEqual(code,0)

    def test_controller_zero_without_QMP_admission_is_refused(self):
        error,reaped,code,*_=self.fixture(qmp_admitted=False)
        self.assertIsInstance(error,ValueError);self.assertTrue(reaped);self.assertEqual(code,0)

    def test_actual_zero_completion_after_original_deadline_is_refused(self):
        error,reaped,code,checks,retained,elapsed,record=self.fixture(timeout=.14,release_after=.15)
        self.assertIsInstance(error,TimeoutError,'final parent zero must not bypass original deadline')
        self.assertTrue(reaped);self.assertEqual(code,0);self.assertLess(elapsed,.7)

    def test_actual_zero_completion_after_cancellation_is_refused(self):
        error,reaped,code,*_=self.fixture(cancelled=True,release_after=.05)
        self.assertIsInstance(error,ValueError);self.assertIn('guardian cancellation',str(error))
        self.assertTrue(reaped);self.assertEqual(code,0)

if __name__=='__main__':unittest.main()
