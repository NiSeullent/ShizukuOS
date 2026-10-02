#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded owned QMP, diagnostic pipes and atomic result persistence."""
import errno
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time
import uuid

LOG_LIMIT = 64 << 20
CAPTURE_LIMIT = 256 << 20
SINGLE_CAPTURE_LIMIT = 16 << 20
# 256 MiB sampled ESP requests + 3*64 MiB logs + 256 MiB captures,
# with 320 MiB for firmware, metadata and one trusted-QEMU capture in flight.
PREFLIGHT_BUDGET = 1 << 30
MEMORY_ADMISSION = 6 << 30
MEMORY_FLOOR = 2 << 30


def available_memory_bytes(path=Path('/proc/meminfo')):
    with path.open('r') as stream:text=stream.read(32769)
    if len(text)>32768:raise ValueError('host memory report exceeded its bound')
    entries=[line.split() for line in text.splitlines() if line.startswith('MemAvailable:')]
    if len(entries)!=1 or len(entries[0])!=3 or entries[0][2]!='kB' or not entries[0][1].isdigit():
        raise ValueError('one exact Linux MemAvailable report required')
    return int(entries[0][1])*1024


class OwnedQMP:
    """Linux peer PID checked before capabilities; every request has a deadline."""
    def __init__(self, path, pid, deadline, pump=lambda: None):
        if type(pid) is not int or pid <= 0:
            raise ValueError('an owned Popen PID is required')
        self.deadline = deadline
        self.pump = pump
        self.buffer = bytearray()
        self.request = 0
        self.socket = None
        stop = min(deadline, time.monotonic() + 20)
        try:
            while True:
                self._remaining(stop)
                peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                peer.settimeout(min(.2, self._remaining(stop)))
                try:
                    peer.connect(str(path))
                except OSError as error:
                    peer.close()
                    if error.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                        raise
                    self.pump();time.sleep(min(.05, self._remaining(stop)))
                    continue
                self.socket = peer
                credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                actual, uid, _ = struct.unpack('3i', credentials)
                if actual != pid or uid != os.getuid():
                    raise RuntimeError('QMP peer differs from the owned QEMU process')
                peer.setblocking(False)
                greeting = self._read(min(stop, time.monotonic() + 5))
                if not isinstance(greeting, dict) or not isinstance(greeting.get('QMP'), dict):
                    raise RuntimeError('missing QMP greeting')
                self.call('qmp_capabilities')
                return
        except BaseException:
            self.close();raise

    @staticmethod
    def _remaining(stop):
        remaining = stop - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('owned QMP absolute deadline exceeded')
        return remaining

    def _read(self, stop):
        while True:
            self.pump();self._remaining(stop)
            if b'\n' in self.buffer:
                line, _, tail = self.buffer.partition(b'\n')
                self.buffer = bytearray(tail)
                if len(line) > (1 << 20):
                    raise RuntimeError('QMP response exceeded its byte bound')
                return json.loads(line)
            if len(self.buffer) > (1 << 20):
                raise RuntimeError('QMP response exceeded its byte bound')
            ready, _, _ = select.select([self.socket], [], [], min(.05, self._remaining(stop)))
            if ready:
                chunk = self.socket.recv(65536)
                if not chunk:
                    raise RuntimeError('owned QMP closed before a response')
                self.buffer.extend(chunk)

    def call(self, command, arguments=None):
        stop = min(self.deadline, time.monotonic() + 5)
        self._remaining(stop);self.request += 1
        identifier = 'native-' + str(self.request)
        message = {'execute': command, 'id': identifier}
        if arguments is not None:message['arguments'] = arguments
        payload = memoryview((json.dumps(message) + '\n').encode())
        while payload:
            self.pump();self._remaining(stop)
            _, writable, _ = select.select([], [self.socket], [], min(.05, self._remaining(stop)))
            if writable:
                sent = self.socket.send(payload)
                if not sent:raise RuntimeError('owned QMP closed while sending')
                payload = payload[sent:]
        for _ in range(128):
            response = self._read(stop)
            if not isinstance(response, dict):raise RuntimeError('QMP response must be an object')
            if 'event' in response and 'id' not in response:
                continue
            if response.get('id') != identifier:
                raise RuntimeError('QMP response ID differs from the owned request')
            if 'error' in response:raise RuntimeError('owned QMP request failed: ' + command)
            if 'return' not in response:raise RuntimeError('QMP response has no result')
            return response['return']
        raise RuntimeError('QMP event count exceeded its bound')

    def hmp(self, command):
        return self.call('human-monitor-command', {'command-line': command})

    def close(self):
        if self.socket is not None:
            self.socket.close();self.socket = None


class BoundedLogs:
    """Three owned pipes drain without allowing QEMU to grow regular log files."""
    def __init__(self, out):
        self.readers = {};self.writers = {};self.files = {};self.counts = {};self.dropped = {}
        try:
            for name in ('serial.log', 'e9.log', 'native-qemu.stderr'):
                self.files[name] = (out / name).open('xb', buffering=0)
                read, write = os.pipe();os.set_blocking(read, False)
                self.readers[read] = name;self.writers[name] = write
                self.counts[name] = self.dropped[name] = 0
        except BaseException:
            self.close();raise

    def close_writers(self):
        pending=list(self.writers.values());self.writers.clear()
        failure=None
        for fd in pending:
            try:os.close(fd)
            except OSError as error:failure=error
        if failure is not None:raise failure

    def pump(self, timeout=0, check=True):
        if self.readers:
            ready, _, _ = select.select(list(self.readers), [], [], timeout)
            for fd in ready:
                name = self.readers[fd]
                for _ in range(4):
                    try:chunk = os.read(fd, 65536)
                    except BlockingIOError:break
                    if not chunk:
                        os.close(fd);del self.readers[fd];break
                    kept = min(len(chunk), LOG_LIMIT - self.counts[name])
                    if kept:
                        view = memoryview(chunk[:kept])
                        while view:
                            written = self.files[name].write(view)
                            if not written:raise OSError('short owned diagnostic write')
                            view = view[written:]
                        self.counts[name] += kept
                    self.dropped[name] += len(chunk) - kept
        elif timeout:
            time.sleep(timeout)
        if check and any(self.dropped.values()):
            raise RuntimeError('owned log exceeded its byte bound')

    def close(self):
        failure=None
        try:self.close_writers()
        except OSError as error:failure=error
        readers=list(self.readers);self.readers.clear()
        files=list(self.files.values());self.files.clear()
        for item in readers+files:
            try:
                if isinstance(item,int):os.close(item)
                else:item.close()
            except OSError as error:failure=error
        if failure is not None:raise failure


def capture_bytes(out):
    total = 0
    for path in out.iterdir():
        if path.suffix in ('.png', '.txt', '.bin', '.json'):
            item=path.lstat()
            if not stat.S_ISREG(item.st_mode):raise RuntimeError('one capture is not a regular owned file')
            size = item.st_size
            if size > SINGLE_CAPTURE_LIMIT:raise RuntimeError('one capture exceeded its byte bound')
            total += size
    if total > CAPTURE_LIMIT:raise RuntimeError('capture total exceeded its byte bound')
    return total


def check_png(path):
    if path.stat().st_size > SINGLE_CAPTURE_LIMIT:raise RuntimeError('PNG exceeded its byte bound')
    with path.open('rb') as stream:header = stream.read(24)
    if len(header) != 24 or header[:8] != b'\x89PNG\r\n\x1a\n' or header[8:12]!=b'\x00\x00\x00\x0d' or header[12:16] != b'IHDR':
        raise ValueError('capture is not a PNG with a bounded IHDR')
    width, height = struct.unpack('>II', header[16:24])
    if not 1 <= width <= 4096 or not 1 <= height <= 4096 or width * height > (1 << 24):
        raise ValueError('PNG dimensions exceed the diagnostic geometry')
    return [width, height]


def atomic_json(path, value):
    """A failed write/flush/close never leaves a partial canonical JSON result."""
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        payload = memoryview((json.dumps(value, indent=2) + '\n').encode())
        while payload:
            count = os.write(fd, payload)
            if not count:raise OSError('short atomic result write')
            payload = payload[count:]
        os.fsync(fd)
        closing=fd;fd=None
        os.close(closing)
        os.replace(temporary, path)
    finally:
        try:
            if fd is not None:os.close(fd)
        finally:temporary.unlink(missing_ok=True)
