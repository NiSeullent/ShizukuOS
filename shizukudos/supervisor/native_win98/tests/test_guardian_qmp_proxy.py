# SPDX-License-Identifier: GPL-2.0-only
"""Controller RPC refusal controls; no QEMU, HostGrant or Windows is executed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest

spec=importlib.util.spec_from_file_location('guardian_proxy_run',Path(__file__).resolve().parents[1]/'run_vm.py')
run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)

class Client:
    def __init__(self):self.calls=[];self.socket_rights=[];self.peer_rights=[];self.pid=os.getpid()
    def call(self,op,p,**kw):
        self.calls.append((op,p))
        if op=='epoch-monitor':return {'host_grant_transmitted':True,'original_deadline_ns':time.monotonic_ns()+int(20e9),'receipt_sha256':'a'*64},self.socket_rights
        if op=='epoch-peer-facts':return [self.pid,os.getuid(),os.getgid()],self.peer_rights
        raise AssertionError(op)

class ProxyControls(unittest.TestCase):
    def test_no_socket_descriptor_and_peer_facts_are_guardian_rpc(self):
        client=Client();proxy=run.GuardianQMP(client,os.getpid(),time.monotonic()+10,lambda:None)
        self.assertEqual([op for op,_ in client.calls],['epoch-monitor','epoch-peer-facts'])
        self.assertFalse(hasattr(proxy.socket,'peer'))
        self.assertEqual(run.struct.unpack('3i',proxy.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)),(os.getpid(),os.getuid(),os.getgid()))
        proxy.close()
        with self.assertRaises(ValueError):proxy.call('query-status')
    def test_socket_rights_are_refused_and_closed(self):
        client=Client();fd=os.open('/dev/null',os.O_RDONLY);client.socket_rights=[fd]
        with self.assertRaisesRegex(ValueError,'actual guardian'):run.GuardianQMP(client,os.getpid(),time.monotonic()+10,lambda:None)
        with self.assertRaises(OSError):os.fstat(fd)
    def test_peer_query_rights_are_refused_and_closed(self):
        client=Client();fd=os.open('/dev/null',os.O_RDONLY);client.peer_rights=[fd]
        with self.assertRaisesRegex(ValueError,'without descriptor'):run.GuardianQMP(client,os.getpid(),time.monotonic()+10,lambda:None)
        with self.assertRaises(OSError):os.fstat(fd)
    def test_wrong_actual_peer_refused(self):
        client=Client();client.pid+=1
        with self.assertRaisesRegex(ValueError,'peer differs'):run.GuardianQMP(client,os.getpid(),time.monotonic()+10,lambda:None)
    def test_original_result_fd_bytes_and_command_checked(self):
        client=Client();proxy=run.GuardianQMP(client,os.getpid(),time.monotonic()+10,lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'result.json';raw=json.dumps({'command':'query-status','result':{'running':False}}).encode();path.write_bytes(raw)
            pin={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            def reply(op,p,**kw):
                self.assertEqual(op,'epoch-monitor-call');return {'pin':pin,'command':'query-status'},[os.open(path,os.O_RDONLY)]
            client.call=reply
            self.assertEqual(proxy.call('query-status'),{'running':False})
            pin['sha256']='b'*64
            with self.assertRaisesRegex(ValueError,'snapshot differs'):proxy.call('query-status')
        proxy.close()

if __name__=='__main__':unittest.main()
