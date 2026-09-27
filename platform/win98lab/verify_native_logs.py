#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strictly parse original NTWRUN/probe success logs without executing anything.

This checks guest-reported statements only. Even complete_success=True means
that the four logs are consistent and the supplied runner exit code is zero;
it NEVER proves native execution, clean Win98 provenance, or visible rendering.
The caller must independently bind original media/build/source receipts, the
executed binaries, one guest session, stopped-guest evidence and a GDI screenshot.
No raw media, guest disk, product key, network or executable is accessed here.
"""
import argparse
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

LIMITS = {'NTWRUN.LOG': 4096, 'NTWPROBE.LOG': 256,
          'NTWQUERY.LOG': 4096, 'NTWGPROB.LOG': 4096}
LINE_COUNTS = {'NTWRUN.LOG': 31, 'NTWPROBE.LOG': 1,
               'NTWQUERY.LOG': 12, 'NTWGPROB.LOG': 15}
PROBES = ('NTWPROBE.EXE', 'NTWQUERY.EXE', 'NTWGPROB.EXE')
DWORD_MAX = 0xffffffff
DECIMAL = re.compile(r'(?:0|[1-9][0-9]{0,9})\Z', re.ASCII)


class NativeLogError(ValueError):
    """Rejected malformed, incomplete, inconsistent or non-success log input."""


class _Log:
    def __init__(self, name, data):
        self.name = name
        self.at = 0
        if type(data) is not bytes or not 0 < len(data) <= LIMITS[name]:
            raise NativeLogError(name + ': expected bounded nonempty bytes')
        if not data.endswith(b'\r\n'):
            raise NativeLogError(name + ': missing final CRLF')
        parts = data.split(b'\r\n')[:-1]
        if len(parts) != LINE_COUNTS[name]:
            raise NativeLogError(name + ': wrong line count')
        if any(not line or any(ch < 0x20 or ch > 0x7e for ch in line) for line in parts):
            raise NativeLogError(name + ': only printable ASCII and exact CRLF are allowed')
        self.lines = [line.decode('ascii') for line in parts]

    def next(self):
        if self.at >= len(self.lines):
            raise NativeLogError(self.name + ': missing required stage')
        value = self.lines[self.at]
        self.at += 1
        return value

    def exact(self, expected):
        if self.next() != expected:
            raise NativeLogError(self.name + ': unexpected stage at line ' + str(self.at))

    def number(self, name, minimum=0, maximum=DWORD_MAX):
        line = self.next()
        prefix = name + '='
        value = line[len(prefix):] if line.startswith(prefix) else ''
        if not DECIMAL.fullmatch(value):
            raise NativeLogError(self.name + ': invalid ' + name)
        number = int(value)
        if not minimum <= number <= maximum:
            raise NativeLogError(self.name + ': out-of-range ' + name)
        return number

    def done(self):
        if self.at != len(self.lines):
            raise NativeLogError(self.name + ': unexpected trailing stages')


def _runner(log):
    log.exact('NTWRUN_VERSION=1')
    log.exact('DIRECTORY=C:\\NTWLAB')
    log.exact('OS_PLATFORM=1')
    log.exact('OS_MAJOR=4')
    log.exact('OS_MINOR=10')
    raw = log.number('OS_BUILD_RAW')
    low = log.number('OS_BUILD_LOW', maximum=65535)
    if low != raw & 65535:
        raise NativeLogError(log.name + ': OS raw/low build mismatch')
    log.exact('WIN98_IDENTIFIED=1')
    log.exact('PREFLIGHT=PASS')
    for name in PROBES:
        for line in ('BEGIN=' + name, 'PROCESS_CREATED=1', 'WAIT_RESULT=0',
                     'EXIT_CODE=0', 'CLOSE_THREAD=PASS', 'CLOSE_PROCESS=PASS', 'END=' + name):
            log.exact(line)
    log.exact('RESULT=PASS')
    log.done()
    return {'platform': 1, 'major': 4, 'minor': 10, 'build_raw': raw, 'build_low': low}


def _dll(log):
    log.exact('PASS: NTWin32Wrapper9x static imports')
    log.done()


def _vxd(log):
    log.exact('START NTWrapper9x native VxD query ABI 0x00000001')
    for cycle in (1, 2):
        suffix = ' 0x0000000' + str(cycle)
        log.exact('BEGIN load cycle' + suffix)
        log.exact('PASS dynamic load/open' + suffix)
        log.exact('PASS version/core initialization/event selftest 0x00000001')
        log.exact('PASS unknown/short/input request errors 0x00000003')
        log.exact('PASS close/unload request' + suffix)
    log.exact('PASS: NTWrapper9x native VxD probe 0x00000000')
    log.done()


def _gdi(log, identity):
    log.exact('NTWDDMWrapper9x native GDI probe v1')
    log.exact('SCOPE=app-owned software DIB; no WDDM/D3D/GPU claim')
    log.exact('OS_PLATFORM=1')
    log.exact('OS_MAJOR=4')
    log.exact('OS_MINOR=10')
    if log.number('OS_BUILD') != identity['build_raw']:
        raise NativeLogError(log.name + ': runner/GDI OS build mismatch')
    log.exact('WIN98_IDENTIFIED=1')
    # These are diagnostic DWORDs, not an asserted list of supported modes.
    bits = log.number('DISPLAY_BITSPIXEL')
    planes = log.number('DISPLAY_PLANES')
    log.exact('PIXEL_CONTRACT_CHECKS=128014')
    log.exact('PIXEL_CONTRACTS=PASS')
    log.exact('FENCE_SCOPE=CPU copy only')
    paints = log.number('SUCCESSFUL_PAINTS', minimum=1)
    log.exact('CLEANUP=PASS')
    log.exact('RESULT=PASS')
    log.done()
    return {'pixel_contract_checks': 128014, 'successful_paints': paints,
            'display_bits_per_pixel': bits, 'display_planes': planes}


def verify_logs(logs, runner_exit_code=None):
    """Check four exact byte logs; raise NativeLogError on inconsistent claims.

    runner_exit_code is None or an explicitly captured unsigned DWORD. Missing
    or nonzero codes produce complete_success=False even if every log says PASS:
    NTWRUN can fail its final CloseHandle after flushing its final PASS line.
    The authenticity of the supplied exit code is the caller's responsibility.
    """
    if not isinstance(logs, Mapping) or set(logs) != set(LIMITS):
        raise NativeLogError('Expected exactly the four original native log names')
    if runner_exit_code is not None and (type(runner_exit_code) is not int
                                         or not 0 <= runner_exit_code <= DWORD_MAX):
        raise NativeLogError('runner_exit_code must be an explicit unsigned DWORD or None')
    # Snapshot values once: a mutable/custom mapping must not change the bytes
    # between parsing and the receipt hashes. Bytearray and text are rejected.
    captured = {name: logs[name] for name in LIMITS}
    parsed = {name: _Log(name, captured[name]) for name in LIMITS}
    identity = _runner(parsed['NTWRUN.LOG'])
    _dll(parsed['NTWPROBE.LOG'])
    _vxd(parsed['NTWQUERY.LOG'])
    gdi = _gdi(parsed['NTWGPROB.LOG'], identity)
    reason = ('Runner exit code was not captured; a final log-close failure remains possible.'
              if runner_exit_code is None else
              'Runner exited nonzero after the reported child results.' if runner_exit_code else None)
    return {'schema': 'ntw.native_logs.v1', 'assessment_scope': 'guest-reported log consistency only',
            'guest_reported_pass': True, 'complete_success': runner_exit_code == 0,
            'runner_exit_code': runner_exit_code, 'incomplete_reason': reason,
            'native_execution_verified': False, 'provenance_required': True,
            'os': identity, 'gdi': gdi,
            'child_exit_codes': {name: 0 for name in PROBES},
            'logs': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                     for name, data in captured.items()},
            'independent_evidence_required': [
                'original media/build/source and executed-binary hash binding',
                'same-session log/exit-code extraction and stopped-guest metadata',
                'clean Windows 98 identity and absence of compatibility replacements',
                'visible GDI window screenshot; byte checks alone do not prove scanout']}


def read_logs(directory):
    """Read only four bounded regular log files; refuse links and special files."""
    result = {}
    for name, limit in LIMITS.items():
        path = Path(directory) / name
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                    raise NativeLogError(name + ': expected bounded regular log file')
                data = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
                if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                        or len(data) != before.st_size):
                    raise NativeLogError(name + ': file changed during read')
                result[name] = data
        except OSError as failure:
            raise NativeLogError(name + ': unreadable log (errno ' + str(failure.errno) + ')') from failure
    return result


def _exit_argument(text):
    if not DECIMAL.fullmatch(text) or int(text) > DWORD_MAX:
        raise argparse.ArgumentTypeError('Use a canonical decimal DWORD, 0 through 4294967295')
    return int(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--runner-exit-code', type=_exit_argument)
    arguments = parser.parse_args(argv)
    try:
        result = verify_logs(read_logs(arguments.directory), arguments.runner_exit_code)
    except NativeLogError as failure:
        print('Native logs rejected: ' + str(failure), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    # Zero means consistent complete guest reports, NEVER verified native run.
    return 0 if result['complete_success'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
