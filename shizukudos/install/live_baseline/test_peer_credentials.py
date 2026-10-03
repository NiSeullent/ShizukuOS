# SPDX-License-Identifier: GPL-2.0-only
"""Actual Linux credential/owned-process feasibility; NOT a custody service."""
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

WORKER = '''import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1]);s.sendall(sys.stdin.buffer.read(32))
s.recv(1)
'''

class PeerCredentials(unittest.TestCase):
    def connected(self, directory):
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(Path(directory)/'keeper.sock'));server.listen(2);server.settimeout(3)
        self.addCleanup(server.close)
        nonce=os.getrandom(32)
        child=subprocess.Popen([sys.executable,'-c',WORKER,str(Path(directory)/'keeper.sock')],stdin=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:child.kill()
            child.wait(timeout=3)
            if child.stdin:child.stdin.close()
        self.addCleanup(cleanup)
        child.stdin.write(nonce);child.stdin.flush()
        stream,_=server.accept();stream.settimeout(3);self.addCleanup(stream.close)
        pidfd=os.pidfd_open(child.pid,0);self.addCleanup(os.close,pidfd)
        credentials=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        raw=b''
        while len(raw)<32:
            block=stream.recv(32-len(raw))
            self.assertTrue(block);raw+=block
        return child,stream,pidfd,credentials,nonce,raw

    def test_exec_after_launch_peer_pid_nonce_and_live_pidfd(self):
        with tempfile.TemporaryDirectory(prefix='baseline-peer-',dir='/var/tmp') as d:
            os.chmod(d,0o700)
            child,stream,pidfd,credentials,nonce,raw=self.connected(d)
            self.assertEqual(credentials,(child.pid,os.getuid(),os.getgid()))
            self.assertEqual(raw,nonce)
            self.assertFalse(select.select([pidfd],[],[],0)[0])
            stream.sendall(b'1');child.wait(timeout=3)
            self.assertTrue(select.select([pidfd],[],[],0)[0])
            # Even this correct peer's saved response has no live-owner scope.
            self.assertEqual(credentials[0],child.pid)

    def test_same_uid_and_correct_nonce_do_not_identify_another_owner(self):
        with tempfile.TemporaryDirectory(prefix='baseline-peer-',dir='/var/tmp') as d:
            child,stream,_,credentials,nonce,raw=self.connected(d)
            self.assertEqual(raw,nonce);self.assertEqual(credentials[1],os.getuid())
            self.assertNotEqual(credentials[0],os.getpid())
            stream.sendall(b'1');child.wait(timeout=3)

    def test_preexec_socketpair_peer_credentials_are_creator_not_child(self):
        first,second=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            child=subprocess.Popen([sys.executable,'-c','import socket,sys;s=socket.socket(fileno=int(sys.argv[1]));s.sendall(b"x")',str(second.fileno())],pass_fds=(second.fileno(),))
            try:
                first.settimeout(3);self.assertEqual(first.recv(1),b'x')
                pid,uid,gid=struct.unpack('3i',first.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                self.assertEqual((pid,uid,gid),(os.getpid(),os.getuid(),os.getgid()))
                self.assertNotEqual(pid,child.pid)
            finally:
                if child.poll() is None:child.kill()
                child.wait(timeout=3)
        finally:first.close();second.close()

if __name__=='__main__':unittest.main(verbosity=2)
