#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded owned QMP, diagnostic pipes and atomic result persistence."""
import errno
import json
import os
from pathlib import Path
import selectors
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


def _poll_select(readers, writers, errors, timeout):
    """Poll original descriptors; never duplicate, consume or close them."""
    if errors:
        raise ValueError('exceptional readiness is not used by this transport')
    read_rows = [(item, item if isinstance(item, int) else item.fileno()) for item in readers]
    write_rows = [(item, item if isinstance(item, int) else item.fileno()) for item in writers]
    requests = {}
    for rows, event in ((read_rows, selectors.EVENT_READ), (write_rows, selectors.EVENT_WRITE)):
        for _, fd in rows:
            requests[fd] = requests.get(fd, 0) | event
    with selectors.PollSelector() as waiter:
        for fd, event in requests.items():
            # PollSelector maps POLLNVAL to readiness; retain select's EBADF refusal.
            os.fstat(fd)
            waiter.register(fd, event)
        events = waiter.select(timeout)
        for fd in requests:
            os.fstat(fd)
    ready = {key.fd: event for key, event in events}
    return ([item for item, fd in read_rows if ready.get(fd, 0) & selectors.EVENT_READ],
            [item for item, fd in write_rows if ready.get(fd, 0) & selectors.EVENT_WRITE], [])


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
            ready, _, _ = _poll_select([self.socket], [], [], min(.05, self._remaining(stop)))
            self.pump();self._remaining(stop)
            if ready:
                chunk = self.socket.recv(65536)
                if not chunk:
                    raise RuntimeError('owned QMP closed before a response')
                self.buffer.extend(chunk)

    def call(self, command, arguments=None):
        if command in INPUT_COMMANDS:input_events_count(command, arguments)
        stop = min(self.deadline, time.monotonic() + 5)
        self._remaining(stop);self.request += 1
        identifier = 'native-' + str(self.request)
        message = {'execute': command, 'id': identifier}
        if arguments is not None:message['arguments'] = arguments
        payload = memoryview((json.dumps(message) + '\n').encode())
        while payload:
            self.pump();self._remaining(stop)
            _, writable, _ = _poll_select([], [self.socket], [], min(.05, self._remaining(stop)))
            self.pump();self._remaining(stop)
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


# ---- Scoped scripted input (owned QMP only; tiny allow-list, bounded) ----
INPUT_COMMANDS = ('input-send-event', 'send-key')
INPUT_KEYS = frozenset(list('abcdefghijklmnopqrstuvwxyz0123456789') + ['ret', 'spc', 'esc', 'tab', 'up', 'down', 'left', 'right', 'shift', 'ctrl', 'alt', 'f4'])  # f4: Alt+F4 -> WM_CLOSE
INPUT_BUTTONS = frozenset(('left', 'right', 'middle'))
INPUT_MAX_STEPS = 64
INPUT_MAX_EVENTS = 128           # total input-send-event items over the whole script
INPUT_MAX_DELAY_MS = 5000
INPUT_MAX_TOTAL_MS = 60000
INPUT_MIN_GAP_S = 0.02           # rate bound between two sends
INPUT_MAX_START_S = 600
INPUT_RECIPE_MAX_BYTES = 16 << 10


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def input_events_count(command, arguments):
    """Validate one allow-listed input QMP command; return its event count."""
    if command not in INPUT_COMMANDS:
        raise ValueError('QMP command is not in the scoped input allow-list')
    if type(arguments) is not dict:
        raise ValueError('exact input arguments required')
    if command == 'send-key':
        if set(arguments) - {'keys', 'hold-time'} or 'keys' not in arguments:
            raise ValueError('exact send-key arguments required')
        keys = arguments['keys']
        if type(keys) is not list or not 1 <= len(keys) <= 3:
            raise ValueError('one to three send-key keys required')
        for key in keys:
            if type(key) is not dict or set(key) != {'type', 'data'} or key['type'] != 'qcode' or key['data'] not in INPUT_KEYS:
                raise ValueError('send-key key is outside the bounded qcode set')
        if 'hold-time' in arguments and not _int(arguments['hold-time'], 0, 500):
            raise ValueError('send-key hold-time out of range')
        return len(keys)
    if set(arguments) != {'events'} or type(arguments['events']) is not list or not 1 <= len(arguments['events']) <= 4:
        raise ValueError('one to four input events required')
    for event in arguments['events']:
        if type(event) is not dict or set(event) != {'type', 'data'} or type(event['data']) is not dict:
            raise ValueError('exact input event shape required')
        kind, data = event['type'], event['data']
        if kind == 'key':
            key = data.get('key')
            if set(data) != {'down', 'key'} or type(data['down']) is not bool or type(key) is not dict or set(key) != {'type', 'data'} \
                    or key['type'] != 'qcode' or key['data'] not in INPUT_KEYS:
                raise ValueError('key event is outside the bounded qcode set')
        elif kind == 'rel':
            if set(data) != {'axis', 'value'} or data['axis'] not in ('x', 'y') or not _int(data['value'], -127, 127):
                raise ValueError('relative pointer movement out of range')
        elif kind == 'abs':
            if set(data) != {'axis', 'value'} or data['axis'] not in ('x', 'y') or not _int(data['value'], 0, 32767):
                raise ValueError('absolute pointer coordinate out of range')
        elif kind == 'btn':
            if set(data) != {'down', 'button'} or type(data['down']) is not bool or data['button'] not in INPUT_BUTTONS:
                raise ValueError('pointer button outside the allow-list')
        else:
            raise ValueError('input event type is not allow-listed')
    return len(arguments['events'])


def input_arguments_valid(command, arguments):
    """Boolean wrapper for guardian-side enforcement."""
    try:
        input_events_count(command, arguments)
        return True
    except ValueError:
        return False


def _step_arguments(step):
    if type(step) is not dict or set(step) - {'delay_ms', 'key', 'down', 'rel', 'abs', 'btn', 'tap'} or not _int(step.get('delay_ms', 0), 0, INPUT_MAX_DELAY_MS):
        raise ValueError('recipe step shape or delay out of range')
    kinds = [name for name in ('key', 'rel', 'abs', 'btn', 'tap') if name in step]
    if len(kinds) != 1:
        raise ValueError('exactly one action per recipe step')
    kind = kinds[0]
    if kind == 'tap':  # press+release via send-key
        return 'send-key', {'keys': [{'type': 'qcode', 'data': step['tap']}], 'hold-time': 100}
    if kind == 'key':
        down = step.get('down')
        return 'input-send-event', {'events': [{'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': step['key']}}}]}
    if kind in ('rel', 'abs'):
        value = step[kind]
        if type(value) is not list or len(value) != 2:
            raise ValueError('pointer step needs [x, y]')
        return 'input-send-event', {'events': [{'type': kind, 'data': {'axis': axis, 'value': coordinate}} for axis, coordinate in zip('xy', value)]}
    return 'input-send-event', {'events': [{'type': 'btn', 'data': {'down': step.get('down'), 'button': step['btn']}}]}


class InputScript:
    """Hash-pinned recipe: {"start_after_s":n,"steps":[{"delay_ms":n,<one action>},...]}.

    Actions: {"tap":"ret"}, {"key":"a","down":true}, {"rel":[dx,dy]},
    {"abs":[x,y]}, {"btn":"left","down":true}. Compiled and fully validated
    before the VM starts; delivery re-validates every command.
    """
    def __init__(self, raw, sha256):
        import hashlib
        if type(raw) is not bytes or not 0 < len(raw) <= INPUT_RECIPE_MAX_BYTES:
            raise ValueError('bounded input recipe bytes required')
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise ValueError('input recipe differs from its pinned SHA-256')
        def unique(pairs):
            if len({key for key, _ in pairs}) != len(pairs):
                raise ValueError('duplicate input recipe field')
            return dict(pairs)
        recipe = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite input recipe value')))
        if type(recipe) is not dict or set(recipe) != {'start_after_s', 'steps'} or not _int(recipe['start_after_s'], 0, INPUT_MAX_START_S):
            raise ValueError('exact input recipe object required')
        steps = recipe['steps']
        if type(steps) is not list or not 1 <= len(steps) <= INPUT_MAX_STEPS:
            raise ValueError('input recipe step budget exceeded')
        self.sha256, self.bytes, self.start_after = sha256, len(raw), recipe['start_after_s']
        self.commands = []
        total_ms = events = 0
        for step in steps:
            command, arguments = _step_arguments(step)
            events += input_events_count(command, arguments)
            total_ms += step.get('delay_ms', 0)
            self.commands.append((total_ms, command, arguments))
        if events > INPUT_MAX_EVENTS or total_ms > INPUT_MAX_TOTAL_MS:
            raise ValueError('input recipe total event/time budget exceeded')
        self.event_total = events


class ScopedInput:
    """Sends a compiled InputScript through an already-admitted owned monitor."""
    def __init__(self, script, monitor):
        self.script, self.monitor, self.index, self.origin, self.last_send = script, monitor, 0, None, 0.0
        self.log = []
        self.sent_events = 0

    @property
    def done(self):
        return self.index >= len(self.script.commands)

    def next_due(self, elapsed):
        """Seconds until the next send (0 if due); None when finished."""
        if self.done:
            return None
        base = self.script.start_after if self.origin is None else self.origin + self.script.commands[self.index][0] / 1000.0
        return max(0.0, base - elapsed)

    def poll(self, elapsed):
        """Send due commands (rate-limited); `elapsed` is VM-relative seconds."""
        if self.origin is None and elapsed >= self.script.start_after:
            self.origin = elapsed
        while self.origin is not None and not self.done:
            due, command, arguments = self.script.commands[self.index]
            if elapsed < self.origin + due / 1000.0:
                return
            wait = self.last_send + INPUT_MIN_GAP_S - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            count = input_events_count(command, arguments)
            if self.sent_events + count > INPUT_MAX_EVENTS:
                raise RuntimeError('input event budget exceeded at delivery')
            self.last_send = time.monotonic()
            reply = self.monitor.call(command, arguments)
            self.sent_events += count
            self.log.append({'step': self.index, 'seconds': round(elapsed, 3), 'command': command, 'arguments': arguments, 'reply': reply})
            self.index += 1

    def evidence(self):
        return {'recipe_sha256': self.script.sha256, 'recipe_bytes': self.script.bytes, 'steps_total': len(self.script.commands),
                'steps_sent': self.index, 'events_sent': self.sent_events, 'complete': self.done, 'sent': self.log}


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
            ready, _, _ = _poll_select(list(self.readers), [], [], timeout)
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
