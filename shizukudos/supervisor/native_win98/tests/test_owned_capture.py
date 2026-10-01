# SPDX-License-Identifier: GPL-2.0-only
"""Actual owned Unix peer, pipe, descriptor and atomic-write controls; no VM."""
from contextlib import contextmanager
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('owned_capture_test',HERE/'owned_capture.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


@contextmanager
def server(mode):
    with tempfile.TemporaryDirectory(prefix='nq-') as temporary:
        base=Path(temporary);path=base/'q';ready_read,ready_write=os.pipe()
        pid=os.fork()
        if pid==0:
            os.close(ready_read)
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                    listener.bind(str(path));listener.listen(1);os.write(ready_write,b'R');os.close(ready_write)
                    conn,_=listener.accept()
                    with conn,conn.makefile('rb') as stream:
                        conn.sendall(b'{"QMP":{}}\n')
                        line=stream.readline();request=json.loads(line)
                        (base/'capabilities-seen').write_bytes(line)
                        conn.sendall((json.dumps({'id':request['id'],'return':{}})+'\n').encode())
                        request=json.loads(stream.readline());identifier=request['id']
                        if mode=='valid':response={'id':identifier,'return':{'running':True}}
                        elif mode=='wrong_id':response={'id':'other-owner','return':{}}
                        elif mode=='error':response={'id':identifier,'error':{'class':'GenericError'}}
                        elif mode=='invalid_object':response=[]
                        elif mode=='event_flood':
                            conn.sendall(b'{"event":"TEST"}\n'*140);time.sleep(.1);return_code=0
                            os._exit(return_code)
                        elif mode=='oversized':
                            conn.sendall(b'x'*((1<<20)+65536));os._exit(0)
                        elif mode=='deadline':
                            for _ in range(100):conn.sendall(b'{"event":"TEST"}\n');time.sleep(.02)
                            os._exit(0)
                        elif mode=='eof':os._exit(0)
                        conn.sendall((json.dumps(response)+'\n').encode())
            except (BrokenPipeError,ConnectionResetError,ValueError):pass
            finally:os._exit(0)
        os.close(ready_write)
        try:
            if os.read(ready_read,1)!=b'R':raise RuntimeError('owned test server did not start')
            yield path,pid,base
        finally:
            os.close(ready_read)
            try:os.kill(pid,signal.SIGTERM)
            except ProcessLookupError:pass
            os.waitpid(pid,0)


class OwnedQMPControls(unittest.TestCase):
    def test_real_peer_pid_and_exact_id_valid_request(self):
        with server('valid') as (path,pid,_):
            q=m.OwnedQMP(path,pid,time.monotonic()+2)
            try:self.assertEqual(q.call('query-status'),{'running':True})
            finally:q.close()

    def test_wrong_real_peer_rejected_before_capabilities(self):
        with server('valid') as (path,pid,base):
            with self.assertRaisesRegex(RuntimeError,'peer differs'):m.OwnedQMP(path,pid+1,time.monotonic()+2)
            time.sleep(.02);self.assertFalse((base/'capabilities-seen').exists())

    def test_wrong_id_error_shape_eof_events_and_bytes_fail_closed(self):
        for mode in ('wrong_id','error','invalid_object','eof','event_flood','oversized'):
            with self.subTest(mode=mode),server(mode) as (path,pid,_):
                q=m.OwnedQMP(path,pid,time.monotonic()+2)
                try:
                    with self.assertRaises((RuntimeError,ValueError)):q.call('query-status')
                finally:q.close()

    def test_continuous_events_obey_absolute_deadline(self):
        with server('deadline') as (path,pid,_):
            q=m.OwnedQMP(path,pid,time.monotonic()+2)
            start=time.monotonic();q.deadline=start+.25
            try:
                with self.assertRaises(TimeoutError):q.call('query-status')
                self.assertLess(time.monotonic()-start,1)
            finally:q.close()

    def test_pid_bool_negative_and_noninteger_refused(self):
        for value in (True,False,0,-1,1.0,'1',None):
            with self.subTest(value=value),self.assertRaises(ValueError):m.OwnedQMP('/unused',value,time.monotonic()+1)


class StorageControls(unittest.TestCase):
    def test_bounded_exact_host_memory_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=Path(temporary)/'meminfo';p.write_text('MemTotal: 99 kB\nMemAvailable: 123 kB\n')
            self.assertEqual(m.available_memory_bytes(p),123*1024)
            for text in ('MemAvailable: 1 B','MemAvailable: -1 kB','MemAvailable: true kB','MemTotal: 4 kB','MemAvailable: 1 kB\nMemAvailable: 2 kB','x'*32769):
                with self.subTest(text=text[:32]):
                    p.write_text(text)
                    with self.assertRaises(ValueError):m.available_memory_bytes(p)

    def test_real_pipe_overflow_keeps_exact_limit_and_closes_descriptors(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(m,'LOG_LIMIT',1024):
            out=Path(temporary);before=len(os.listdir('/proc/self/fd'));logs=m.BoundedLogs(out)
            os.write(logs.writers['serial.log'],b'a'*2048)
            with self.assertRaisesRegex(RuntimeError,'log exceeded'):logs.pump()
            self.assertEqual(logs.counts['serial.log'],1024);self.assertEqual(logs.dropped['serial.log'],1024)
            self.assertEqual((out/'serial.log').stat().st_size,1024)
            logs.close();self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_valid_pipe_drain_and_constructor_failure_reap_all_fds(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary);before=len(os.listdir('/proc/self/fd'));logs=m.BoundedLogs(out)
            os.write(logs.writers['e9.log'],b'actual pipe bytes');logs.close_writers();logs.pump();logs.close()
            self.assertEqual((out/'e9.log').read_bytes(),b'actual pipe bytes')
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
            with self.assertRaises(FileExistsError):m.BoundedLogs(out)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_atomic_json_success_and_partial_valid_json_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary);target=out/'native-result.json';before=len(os.listdir('/proc/self/fd'))
            m.atomic_json(target,{'collection_verified':True});self.assertEqual(json.loads(target.read_text()),{'collection_verified':True})
            target.unlink()
            actual_write=m.os.write
            def partial(fd,payload):
                actual_write(fd,payload[:-1]);raise OSError(errno.ENOSPC,'modeled disk full after valid JSON')
            with patch.object(m.os,'write',partial),self.assertRaises(OSError):m.atomic_json(target,{'collection_verified':True})
            self.assertFalse(target.exists());self.assertEqual(list(out.iterdir()),[])
            with patch.object(m.os,'fsync',side_effect=OSError(errno.EIO,'modeled flush failure')),self.assertRaises(OSError):m.atomic_json(target,{'collection_verified':True})
            self.assertFalse(target.exists());self.assertEqual(list(out.iterdir()),[])
            actual_close=m.os.close
            def close_error(fd):actual_close(fd);raise OSError(errno.EIO,'modeled final close failure')
            with patch.object(m.os,'close',close_error),self.assertRaises(OSError):m.atomic_json(target,{'collection_verified':True})
            self.assertFalse(target.exists());self.assertEqual(list(out.iterdir()),[])
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_atomic_replace_failure_preserves_existing_canonical(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary);target=out/'native-result.json';target.write_text('old owned receipt')
            with patch.object(m.os,'replace',side_effect=OSError(errno.EIO,'modeled rename failure')),self.assertRaises(OSError):m.atomic_json(target,{'collection_verified':True})
            self.assertEqual(target.read_text(),'old owned receipt');self.assertEqual(list(out.iterdir()),[target])

    def test_capture_geometry_regular_file_and_total_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary);p=out/'frame.png'
            def png(width,height):return b'\x89PNG\r\n\x1a\n'+struct.pack('>I',13)+b'IHDR'+struct.pack('>II',width,height)
            p.write_bytes(png(1024,768));self.assertEqual(m.check_png(p),[1024,768])
            for width,height in ((0,1),(1,0),(4097,1),(1,4097)):
                p.write_bytes(png(width,height))
                with self.assertRaises(ValueError):m.check_png(p)
            p.write_bytes(b'not png')
            with self.assertRaises(ValueError):m.check_png(p)
            p.unlink();p.symlink_to('/dev/null')
            with self.assertRaises(RuntimeError):m.capture_bytes(out)
            p.unlink();p.write_bytes(b'x'*100)
            with patch.object(m,'SINGLE_CAPTURE_LIMIT',99),self.assertRaises(RuntimeError):m.capture_bytes(out)
            with patch.object(m,'CAPTURE_LIMIT',99),self.assertRaises(RuntimeError):m.capture_bytes(out)

if __name__=='__main__':unittest.main()
