#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Summarize bounded DOS/VMM register measurements; never assert boot success."""
import argparse
from collections import Counter
import hashlib
import json
import os
import re
import stat

PROFILES = ('windows98-original-control', 'shizukudos-win98-candidate')
MAX_BYTES = 1024 * 1024
MAX_CALLS = 4096
PATTERN = re.compile(rb'SHZVMM1 ([ER]) ' + rb' '.join([rb'([0-9A-F]{4})'] * 11) + rb'\r\n')
REGISTER_NAMES = ('AX','BX','CX','DX','DS','SI','ES','DI','BP','FLAGS')
WATCHED_AX = (0x1603,0x1605,0x1606,0x1607,0x4601,0x4602)


def parse(data, profile):
    if profile not in PROFILES:
        raise ValueError('an explicit control or candidate measurement profile is required')
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('the trace must be bytes, at most 1 MiB')
    active = []
    inputs = Counter()
    completed = 0
    last_id = 0
    records = 0
    for line in data.splitlines(keepends=True):
        if not line.startswith(b'SHZVMM'):
            continue
        match = PATTERN.fullmatch(line)
        if match is None:
            raise ValueError('malformed or incomplete SHZVMM record')
        phase = match.group(1)
        values = tuple(int(value,16) for value in match.groups()[1:])
        identifier, *registers = values
        records += 1
        if not 1 <= identifier <= MAX_CALLS:
            raise ValueError('call identifier is outside the bounded trace budget')
        if phase == b'E':
            if identifier != last_id + 1:
                raise ValueError('entry identifiers must be unique, contiguous and increasing')
            ax,bx,cx = registers[:3]
            if ax not in WATCHED_AX or (ax == 0x1607 and bx != 0x15):
                raise ValueError('entry is outside the DOS/VMM measurement filter')
            active.append(identifier)
            inputs['%04X:%04X:%04X' % (ax,bx,cx)] += 1
            last_id = identifier
        else:
            if not active or active.pop() != identifier:
                raise ValueError('return does not match the active call stack')
            completed += 1
    if active or not completed or records != completed * 2:
        raise ValueError('measurement has missing returns or no complete calls')
    return {
        'format': 'SHZVMM1-register-measurement',
        'status': 'COMPLETE_CALL_MEASUREMENT',
        'profile': profile,
        'trace_sha256': hashlib.sha256(data).hexdigest(),
        'trace_bytes': len(data),
        'completed_calls': completed,
        'trace_budget_reached': last_id == MAX_CALLS,
        'observed_input_calls': dict(sorted(inputs.items())),
        'native_Windows98_complete': False,
        'ShizukuDOS_replaces_MS_DOS_validated': False,
        'harness_guest_execution_validated': False,
        'note': 'Structural trace validation only; separate source-bound guest/control evidence is required.'
    }


def read_bounded(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('trace input must be a regular file')
        if before.st_size > MAX_BYTES:
            raise ValueError('trace exceeds 1 MiB')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        if any(getattr(before,name) != getattr(after,name) for name in fields) or len(data) != before.st_size:
            raise ValueError('finish and freeze the capture before parsing it')
        if len(data) > MAX_BYTES:
            raise ValueError('trace exceeds 1 MiB')
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace',help='private bounded E9 capture; raw paths/registers are not included in the summary')
    parser.add_argument('--profile',required=True,choices=PROFILES)
    args = parser.parse_args()
    try:
        result = parse(read_bounded(args.trace),args.profile)
    except ValueError as exc:
        parser.exit(2,'Measurement rejected: %s\n' % exc)
    except OSError:
        parser.exit(2,'Measurement rejected: an accessible regular trace file is required\n')
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
