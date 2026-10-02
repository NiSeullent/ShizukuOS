#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Separate hosted current MbedTLS3.6.7/SSPI build proof; never execute a PE.

The old bridge8MiB/256KiB profile is unchanged. This producer uses explicit
32MiB output and20GiB floor; separately admitted original upstream inputs,
normal captures256KiB and decoder streams16MiB each/four64MiB aggregate.
Sampling is not a quota, transient peak or complete tool-runtime attestation.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tarfile
import time
import types
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'ntwin32/secure_transport'
RESERVE = 20 * 1024**3
LIMIT = 32 * 1024**2
PREP_LIMIT = 1024**3
ARCHIVE_BYTES = 5473689
ARCHIVE_SHA = 'a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6'
ARCHIVE_URL = 'https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2'
PRODUCTION = {'ntwin32/secure_transport/build.py': (19667, 'a9f96b6a4501104b1929a669af4a0f4f6db9b7e68e56ad7241274783f44d787b'), 'ntwin32/secure_transport/i486_format.c': (6346, '3d5a6fd5895801d350ffeffe563e6bf858801fc24ac1139fec07e058d1346965'), 'ntwin32/secure_transport/i486_format.h': (663, '3f7a57cb7c545ba180a2dbb33fdfaf2f2c4bfa31f5cf02a01118cdbfd571a42d'), 'ntwin32/secure_transport/i486_gate.py': (8829, '85e976035c70478e9a2f021a37aa6925dd20ad85f089c7d06a18efadb7b9730f'), 'ntwin32/secure_transport/native.def': (302, '88c1d2cd388bc5d958d8473589fcf18d12d48e1c53da6fb3b2e396aba24b8c82'), 'ntwin32/secure_transport/native_crt.c': (1699, 'dff0e07803d0a6f708b597d6fc54225c6502c2293814e77fe2d95f821cae882f'), 'ntwin32/secure_transport/native_runtime.c': (1423, '268c5eae7b09145ea1ff971e24313b6a0b19cd7a8f85f8dcd44c886e6435cfa8'), 'ntwin32/secure_transport/native_runtime.h': (495, '6425fd3cad0c0a02a48851caf7337b55453ee6259bd35e79496d2de68769ea2e'), 'ntwin32/secure_transport/native_time.c': (2207, '8103149774591687c15554438925e303c99ba42fa1c6a9b4254a6ee6fae99031'), 'ntwin32/secure_transport/native_time_probe.c': (6364, '98c3d61a6cb585d9ce1822c5a233737c7d1d66fe29c16eb2968771814a4459da'), 'ntwin32/secure_transport/probe.c': (28767, '39fa6b3915de7aa2378173fc7ca3258267176e20cb2dd451ea795816d3b15585'), 'ntwin32/secure_transport/sspi_native.c': (35445, '32b6bbd23d7ed61c40d86e08711c631140dfeb3ee6e5e1a6427d9eebb2955672'), 'ntwin32/secure_transport/sspi_native.def': (769, 'd31e87e33f0b51bb175265e0f05a073749e1785d3d4d2cb34713ae7dd59566a7'), 'ntwin32/secure_transport/sspi_native.h': (1972, '172f12027a18b9d04a81936da4169f62793f25aa6d09d13edbc1da4bf81f280c'), 'ntwin32/secure_transport/sspi_native_host_test.py': (45452, 'a1ecceca9c7989d7559b610e6266285b00ba915c3a6f1880a13744d88424aea2'), 'ntwin32/secure_transport/sspi_stream.c': (16139, '873407d0cb80072957d6dacb1c2b4ba0c96eb9cd3b81ab93159c4668610c8ac1'), 'ntwin32/secure_transport/sspi_stream.h': (5600, '87c9038c2a5411a63b6e9cb942f1d6da04f7aaded296933357d5fdfad02b79e2'), 'ntwin32/secure_transport/transport.c': (13450, '353556e66a46c807480436015e1f85c0f80e93988d0d3e581cef4aa9d386b604'), 'ntwin32/secure_transport/transport.h': (3792, '7f3f364ab97fd58d94c03f80432a94b99c0ad28b71b48bc4d0ee4920e3191cda'), 'ntwin32/secure_transport/user_config.h': (1635, '578949f773d5189b149804013880786b2b258c1837fa32d4e9a117031ca31ab6')}
SUPPORT = {'benchmarks/win98se-ko-oem-native-exports-v1.json': (1866608, '3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d'), 'ntwin32/secure_transport/i486_gate_test.py': (5194, '6e90e48f6f690efd29d2db7035478589bca4f140f3c28f05960c9bd0b5a4af69'), 'ntwin32/legacy_provider_bridge/pe_link_script_6970.py': (26070, '9a98336d9c5a0bc417ed816454d3188e79dc4cf326a52bfabad73df8c903b55b'), 'ntwin32/legacy_provider_bridge/build_native_pe32_guarded_6970.py': (76927, 'b7d627c71076b6cbdb1e65d896ab798e4fe3688067ef7b0a1774243d2c3010d9'), 'ntwin32/legacy_provider_bridge/test_native_sspi_6970.py': (41247, '1b52856e537b298ea253d564754afefc35eb340bd7f7090fc1b30786bfa4f44e')}
NEW_HELPERS = ('native_tls_resources_6970.py', 'i486_stream_6970.py',
               'native_tls_quiescent_controls_6970.py')
FALSE_FLAGS = ('native_execution_verified', 'windows98_integration_verified',
               'network_execution_verified', 'credential_execution_verified',
               'os_tls_provider_verified', 'os_registration_verified',
               'kernel64_backend_verified', 'application_compatibility_verified',
               'default_ROOT_chain_validation_verified', 'final_ISO_verified')
TLS_FALSE_FLAGS=('TLS_execution_verified','TLS_negotiation_verified',
                 'real_tls_proven_by_this_test','native_guest_proven','native_ROOT_execution_proven')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def regular(path, maximum):
    """Exact held-inode source/preparation read; no repository helper executes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise ValueError('bounded singly-linked regular input required: ' + str(path))
        raw = bytearray()
        start = time.monotonic()
        while True:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            if len(raw) > maximum or time.monotonic() - start > 60:
                raise ValueError('input byte/time bound')
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat()):
            raise ValueError('input changed during held read')
        return bytes(raw), {'bytes': len(raw), 'sha256': digest(raw), 'identity': identity(before)}
    finally:
        os.close(fd)


def components(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('symlink component refused: ' + str(item))


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def load(path, expected, name, guard=None):
    raw, pin = regular(path, 2 * 1024**2)
    if expected is not None and (pin['bytes'], pin['sha256']) != tuple(expected):
        raise ValueError('frozen helper source mismatch: ' + str(path))
    if guard:
        guard.check()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.dont_write_bytecode = True
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    if regular(path, 2 * 1024**2)[1] != pin:
        raise ValueError('helper changed while loading verified bytes')
    module.__6970_bound_source_sha256__ = pin['sha256']
    module.__6970_bound_source_bytes__ = pin['bytes']
    if guard:
        guard.check()
    return module


def require_quiescent_controls(report, controls, guard, resources, source_pins, python_pin, offsets):
    """Bind actual closed child epochs without promoting expected FAIL commands."""
    def require(condition, message):
        if not condition:
            raise ValueError('quiescent controls: ' + message)

    def natural(value):
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    def payload(value):
        require(isinstance(value, str) and len(value) <= 8192
                and re.fullmatch(r'[0-9a-f]*', value) is not None and len(value) % 2 == 0,
                'bounded canonical payload hex required')
        return bytes.fromhex(value)

    require(isinstance(report, dict)
            and report.get('schema') == 'native-tls-quiescent-controls-6970.v1'
            and report.get('result') == 'PASS_QUIESCENT_GUARD_CONTROLS_ONLY'
            and type(report.get('completed')) is int and report['completed'] == 10
            and type(report.get('failures')) is int and report['failures'] == 0,
            'complete ten-case PASS required')
    cases = report.get('cases')
    require(isinstance(cases, list) and len(cases) == 10
            and tuple(row.get('name') for row in cases if isinstance(row, dict)) == controls.CONTROL_NAMES,
            'exact declared ordered case names required')
    for key in ('resource_source_before_after_equal', 'control_source_before_after_equal',
                'selected_python_before_after_equal', 'actual_controls_execution_verified',
                'fault_injection_is_not_unmanaged_writer_attestation'):
        require(report.get(key) is True, 'required observation absent: ' + key)
    for key in ('expected_negative_commands_added_to_parent', 'escaped_writers_excluded_verified',
                'continuous_group_stop_verified', 'filesystem_quota_verified',
                'native_execution_verified', 'windows98_integration_verified', 'tls_execution_verified'):
        require(report.get(key) is False, 'unsupported scope claim: ' + key)
    require(report.get('resource_source') == source_pins['ntwin32/secure_transport/native_tls_resources_6970.py']
            and report.get('control_source') == source_pins['ntwin32/secure_transport/native_tls_quiescent_controls_6970.py']
            and report.get('selected_python') == python_pin,
            'exact loaded source and selected Python pins required')
    require(len(guard.commands) == offsets['commands'], 'child commands entered production inventory')
    require(report.get('fixture_bytes_limit') == controls.FIXTURE_BYTES_LIMIT
            and report.get('case_timeout_seconds') == controls.CASE_SECONDS
            and report.get('total_timeout_seconds') == controls.TOTAL_SECONDS
            and isinstance(report.get('elapsed_seconds'), (int, float))
            and not isinstance(report['elapsed_seconds'], bool)
            and 0 <= report['elapsed_seconds'] <= controls.TOTAL_SECONDS, 'bounded actual control time required')
    records = report.get('proof_files')
    require(isinstance(records, list) and 0 < len(records) <= 320, 'explicit bounded proof files required')
    pins, inodes, total = {}, set(), 0
    for record in records:
        require(isinstance(record, dict) and set(record) == {'path', 'relative_path', 'bytes', 'sha256', 'identity'},
                'exact proof pin fields required')
        path = Path(record['path'])
        relative = Path(record['relative_path'])
        require(path.is_absolute() and str(path) == record['path'] and path.is_relative_to(guard.tmp)
                and not relative.is_absolute() and '..' not in relative.parts
                and guard.output / relative == path and str(path) not in pins,
                'duplicate or escaped control proof path')
        pin = guard.pin(path, maximum=controls.FIXTURE_BYTES_LIMIT)
        require(pin == {key: record[key] for key in ('bytes', 'sha256', 'identity')}, 'actual proof bytes changed')
        token = tuple(pin['identity'][:2])
        require(token not in inodes, 'duplicate control proof inode')
        inodes.add(token)
        pins[str(path)] = pin
        total += pin['bytes']
    require(total <= controls.FIXTURE_BYTES_LIMIT, 'actual control proof file sum exceeds 512 KiB')
    captured = decoded = embedded = 0
    for index, row in enumerate(cases):
        expected = controls.CONTROL_EXPECTATIONS[row['name']]
        require(row.get('result') == 'PASS' and row.get('executed') is True
                and row.get('expected_child_epoch') == expected['child_epoch']
                and row.get('child_epoch') == expected['child_epoch']
                and row.get('injected_fault') is expected['injected_fault']
                and row.get('expected_negative_reason') == expected['reason']
                and type(row.get('expected_command_count')) is int
                and row['expected_command_count'] == expected['command_count']
                and type(row.get('command_count')) is int and row['command_count'] == expected['command_count'],
                'actual child epoch/fault/command classification differs')
        require(isinstance(row.get('elapsed_seconds'), (int, float)) and not isinstance(row['elapsed_seconds'], bool)
                and 0 <= row['elapsed_seconds'] <= controls.CASE_SECONDS, 'case wall bound differs')
        for key in ('capture_pool_delta', 'decoder_pool_delta', 'capture_pool_offset', 'decoder_pool_offset'):
            require(natural(row.get(key)), 'actual pool counter required: ' + key)
        require(row['capture_pool_offset'] == offsets['capture'] + captured
                and row['decoder_pool_offset'] == offsets['decoder'] + decoded, 'inherited pool offset differs')
        captured += row['capture_pool_delta']
        decoded += row['decoder_pool_delta']
        reason = row.get('observed_error')
        require(reason is None if expected['reason'] is None else
                isinstance(reason, str) and expected['reason'] in reason, 'expected actual failure reason absent')
        observation = row.get('observation')
        require(isinstance(observation, dict), 'actual case observations required')
        if index < 8:
            require(natural(observation.get('early_continue_requests'))
                    and observation['early_continue_requests'] == 0, 'nested pause resumed early')
        if index < 4:
            require(natural(observation.get('paused_scans')) and observation['paused_scans'] > 0,
                    'positive case did not observe a paused traversal')
        if index == 1:
            require(observation.get('maximum_members', 0) >= 3 and observation.get('maximum_tasks', 0) >= 5,
                    'actual threads/late fork not observed')
        if index == 2:
            require(observation.get('zombie_leader_live_member') is True, 'zombie leader/live child not observed')
        if index == 3:
            require(observation.get('nested_checks') == 1 and observation.get('nested_pause_retained') is True,
                    'nested paused count not exercised')
        if index >= 4:
            require(natural(observation.get('fault_injections')) and observation['fault_injections'] > 0,
                    'named negative boundary not exercised')
        if index >= 8:
            require(observation.get('actual_rename_performed') is True
                    and observation.get('stat_boundary_calls', 0) >= 2, 'real inode substitution not exercised')
        child_path = row.get('child_receipt_path')
        expected_child_path = guard.tmp / ('quiescent-%02d' % index) / 'result.json'
        require(child_path == str(expected_child_path) and child_path in pins
                and row.get('child_receipt_sha256') == pins[child_path]['sha256'],
                'child closed receipt absent from exact proof set')
        raw, pin = regular(Path(child_path), controls.FIXTURE_BYTES_LIMIT)
        require(pin == pins[child_path], 'closed child receipt changed during read')
        child = json.loads(raw)
        require(child.get('schema') == 'native-tls-quiescent-control-child-6970.v1'
                and child.get('control') == row['name'] and child.get('result') == expected['child_epoch']
                and child.get('expected_negative') is expected['injected_fault']
                and child.get('receipt_accounting_verified') is True
                and child.get('command_count') == row['command_count'], 'actual child receipt classification differs')
        for key in ('native_execution_verified', 'windows98_integration_verified', 'tls_execution_verified'):
            require(child.get(key) is False, 'child unsupported scope claim: ' + key)
        actual_commands = child.get('commands')
        commands, capture_payloads = row.get('commands'), row.get('capture_payloads')
        require(isinstance(actual_commands, list) and isinstance(commands, list) and isinstance(capture_payloads, list)
                and len(actual_commands) == len(commands) == len(capture_payloads) == row['command_count'],
                'actual command/payload count differs')
        strings = child.get('command_argv_string_table')
        require(child.get('command_argv_encoding') == 'lossless-string-table-v1'
                and isinstance(strings, list) and len(strings) <= 8192
                and all(isinstance(value, str) for value in strings) and len(set(strings)) == len(strings)
                and sum(len(value.encode()) for value in strings) <= 256 * 1024, 'lossless actual argv table required')
        row_payload = 0
        consumer = payload(row.get('consumer_payload_hex', ''))
        for command, actual, capture in zip(commands, actual_commands, capture_payloads):
            require(isinstance(command, dict) and isinstance(actual, dict) and isinstance(capture, dict),
                    'actual command metadata required')
            require(command.get('label') == 'control', 'exact declared child command label required')
            refs = actual.get('argv_refs')
            require(isinstance(refs, list) and 0 < len(refs) <= 256
                    and all(natural(value) and value < len(strings) for value in refs), 'actual argv refs invalid')
            argv = [strings[value] for value in refs]
            require(command.get('argv_sha256') == digest(json.dumps(argv, separators=(',', ':')).encode())
                    and all(actual.get(key) == value for key, value in command.items() if key != 'argv_sha256'),
                    'compact command differs from closed actual command')
            require(command.get('reaped') is True and command.get('raw_stdout_stream') is (index == 7),
                    'actual cleanup/stream classification differs')
            quiescence = command.get('quiescence')
            require(isinstance(quiescence, dict), 'actual command stop observations absent')
            if index < 4:
                require(command.get('returncode') == 0 and command.get('aborted') is None
                        and command.get('nonreaping_leader_exit_observed') is True
                        and quiescence.get('verified_pauses', 0) > 0 and quiescence.get('continue_requests', 0) > 0
                        and (command.get('group_kill') == 'REQUESTED_BEFORE_REAP'
                             or command.get('group_kill') == 'NO_SUCH_GROUP_BEFORE_REAP'
                             and quiescence.get('stop_no_live_group_observations', 0) > 0),
                        'positive actual process/stop cleanup failed')
            else:
                require(command.get('returncode') == -9 and command.get('group_kill') == 'REQUESTED_BEFORE_REAP'
                        and isinstance(command.get('aborted'), str) and expected['reason'] in command['aborted']
                        and quiescence.get('failure_stop_retained_until_owned_kill') is True,
                        'negative actual command did not fail/kill at expected boundary')
            for key in ('escaped_writers_excluded_verified', 'continuous_group_stop_verified', 'filesystem_quota_verified'):
                require(quiescence.get(key) is False, 'command unsupported stop scope: ' + key)
            stdout, stderr = payload(capture.get('stdout_hex')), payload(capture.get('stderr_hex'))
            for stream, data in (('stdout', stdout), ('stderr', stderr)):
                capture_path = str(expected_child_path.parent / ('control.' + stream))
                require(capture_path in pins and pins[capture_path]['bytes'] == len(data)
                        and pins[capture_path]['sha256'] == digest(data),
                        'actual capture file absent or differs from embedded payload')
            require(command.get('captured_bytes') == len(stdout) + len(stderr)
                    and command.get('captured_sha256') == {'stdout': digest(stdout), 'stderr': digest(stderr)}
                    and command.get('full_stderr_bytes') == len(stderr)
                    and command.get('full_stderr_sha256') == digest(stderr), 'actual capture length/SHA differs')
            full_stdout = consumer if index == 7 else stdout
            require(command.get('full_stdout_bytes') == len(full_stdout)
                    and command.get('full_stdout_sha256') == digest(full_stdout), 'actual full stdout digest differs')
            if index == 7:
                require(bool(consumer) and not stdout and command.get('stdout_delivered_to_consumer_bytes') == 0
                        and row.get('stream_consumer_raised_before_delivery_commit') is True,
                        'raised consumer raw/delivery boundary differs')
            row_payload += len(stdout) + len(stderr)
        row_payload += len(consumer)
        require(row_payload == row['capture_pool_delta']
                and row['decoder_pool_delta'] == (len(consumer) if index == 7 else 0),
                'actual case payload differs from inherited charge')
        embedded += row_payload
    require(embedded == captured == report.get('capture_payload_bytes') == report.get('capture_bytes_charged_to_parent')
            and embedded <= controls.PAYLOAD_LIMIT
            and decoded == report.get('raw_bytes_charged_to_parent')
            and guard.capture_bytes == offsets['capture'] + captured <= resources.CAPTURE_LIMIT
            and guard.decoder_bytes == offsets['decoder'] + decoded <= resources.DECODER_LIMIT,
            'actual shared pool accounting differs')
    return pins


def prepare(prep):
    """Bounded fresh publisher inputs, distinct from proof32MiB output."""
    components(prep)
    if prep != prep.resolve(strict=True) or prep.parent != ROOT / 'build/native-tls-prep-6970':
        raise ValueError('exact hosted preparation lane required')
    prior_raw, prior_pin = regular(prep / 'result.json', 65536)
    prior = json.loads(prior_raw)
    if prior['result'] != 'PASS_HOSTED_PREREQUISITES_ONLY' or prior['reserve_bytes'] != RESERVE:
        raise ValueError('tool preparation failed or profile mismatch')
    initial = prior['available_before_bytes']
    minimum = prior['minimum_observed_free_bytes']
    def observe(pending=0):
        nonlocal minimum
        free = shutil.disk_usage(ROOT).free
        minimum = min(minimum, free)
        if free < RESERVE + pending or initial - free + pending > PREP_LIMIT:
            raise ValueError('separate preparation20GiB/1GiB observed budget crossed')
        return free
    observe(128 * 1024**2)
    lane = prep / 'upstream-original'
    if lane.exists() or lane.is_symlink():
        raise ValueError('preserve existing preparation; fresh lane required')
    lane.mkdir(mode=0o700)
    archive = lane / 'mbedtls-3.6.7.tar.bz2'
    hasher, count = hashlib.sha256(), 0
    started = time.monotonic()
    with urllib.request.urlopen(ARCHIVE_URL, timeout=20) as response, archive.open('xb') as target:
        if response.status != 200:
            raise ValueError('publisher download status')
        while True:
            observe(65536)
            block = response.read(65536)
            if not block:
                break
            count += len(block)
            if count > ARCHIVE_BYTES or time.monotonic() - started > 120:
                raise ValueError('publisher archive byte/time bound')
            hasher.update(block)
            target.write(block)
        target.flush()
        os.fsync(target.fileno())
    if count != ARCHIVE_BYTES or hasher.hexdigest() != ARCHIVE_SHA:
        raise ValueError('actual publisher archive differs from literal pin')
    archive.chmod(0o400)
    tree = lane / 'mbedtls-3.6.7'
    names, files, directories, total = set(), {}, set(), 0
    archive_before=regular(archive,8*1024**2)[1]
    archive_fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(archive_fd,'rb') as archive_input, tarfile.open(fileobj=archive_input, mode='r:bz2') as tar:
        if identity(os.fstat(archive_input.fileno()))!=archive_before['identity']:
            raise ValueError('actual archive changed before extraction')
        for member in tar:
            observe(member.size + 65536)
            name = member.name.rstrip('/')
            parts = name.split('/')
            if (not parts or parts[0] != tree.name or any(p in ('', '.', '..') for p in parts)
                    or name in names or len(names) >= 12000 or len(parts) > 16):
                raise ValueError('original archive unsafe/duplicate/unbounded membership')
            names.add(name)
            path = lane.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
                directories.add(str(path.relative_to(tree)) if path != tree else '.')
            elif member.isfile():
                if not 0 <= member.size <= 8 * 1024**2:
                    raise ValueError('original archive individual member cap')
                total += member.size
                if total > 64 * 1024**2:
                    raise ValueError('original upstream total logical cap')
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = tar.extractfile(member)
                raw = source.read(member.size + 1)
                if len(raw) != member.size:
                    raise ValueError('original upstream truncated member')
                with path.open('xb') as target:
                    target.write(raw)
                path.chmod(0o400)
                files[str(path.relative_to(tree))] = regular(path, 8 * 1024**2)[1]
            else:
                # No symlink, hardlink, device, sparse or unknown member is used.
                raise ValueError('unsupported original upstream member type: '+member.name[:240])
        if identity(os.fstat(archive_input.fileno()))!=archive_before['identity']:
            raise ValueError('actual held archive changed during extraction')
    if regular(archive,8*1024**2)[1]!=archive_before or archive_before['sha256']!=ARCHIVE_SHA:
        raise ValueError('actual pinned archive changed across extraction')
    actual_files = {str(p.relative_to(tree)) for p in tree.rglob('*') if p.is_file()}
    if actual_files != set(files):
        raise ValueError('original extraction exact file membership mismatch')
    for directory in sorted((p for p in tree.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        directory.chmod(0o500)
    tree.chmod(0o500)
    actual_dirs = sorted(str(p.relative_to(tree)) for p in tree.rglob('*') if p.is_dir())
    record = {'schema': 'native-tls-original-upstream-preparation-v1',
              'status': 'PASS_ORIGINAL_UPSTREAM_PREPARATION_ONLY',
              'publisher_url': ARCHIVE_URL, 'archive': {'path': str(archive), **regular(archive, 8 * 1024**2)[1]},
              'tree': str(tree), 'files': files, 'directories': actual_dirs,
              'regular_file_count': len(files), 'logical_bytes': total,
              'reserve_bytes': RESERVE, 'combined_tools_upstream_change_budget_bytes': PREP_LIMIT,
              'tool_prep_receipt': prior_pin, 'available_before_bytes': initial,
              'minimum_observed_free_bytes': minimum,
              'filesystem_quota_enforced': False, 'all_transient_peaks_measured': False,
              'native_execution_verified': False}
    destination = prep / 'upstream-preparation.json'
    observe(2 * 1024**2)
    for attempt in range(4):
        observe(2 * 1024**2 + LIMIT)
        record['minimum_observed_free_bytes'] = minimum
        raw = encode(record)
        if len(raw) > 2 * 1024**2:
            raise ValueError('original upstream preparation manifest bound')
        with destination.open('xb' if attempt == 0 else 'wb') as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        observe(LIMIT)
        if minimum == record['minimum_observed_free_bytes']:
            break
    else:
        raise ValueError('original upstream preparation minimum did not stabilize')
    print('Upstream preparation manifest SHA256:', digest(raw))
    print(json.dumps({'status': record['status'], 'files': len(files), 'logical_bytes': total,
                      'minimum_observed_free_bytes': minimum, 'manifest_bytes': len(raw)}))
    return {'path':str(destination),**regular(destination,2*1024**2)[1]}


def upstream_snapshot(prep,expected_sha):
    raw, pin = regular(prep / 'upstream-preparation.json', 2 * 1024**2)
    if not re.fullmatch('[0-9a-f]{64}',expected_sha) or pin['sha256']!=expected_sha:
        raise ValueError('actual newly prepared manifest digest binding mismatch')
    x = json.loads(raw)
    if x['status'] != 'PASS_ORIGINAL_UPSTREAM_PREPARATION_ONLY' or x['archive']['sha256'] != ARCHIVE_SHA:
        raise ValueError('current immutable upstream preparation required')
    tree = Path(x['tree'])
    components(tree)
    if tree != prep / 'upstream-original/mbedtls-3.6.7' or tree != tree.resolve(strict=True):
        raise ValueError('unexpected upstream source root')
    observed = regular(Path(x['archive']['path']), 8 * 1024**2)[1]
    if observed != {k:v for k,v in x['archive'].items() if k != 'path'}:
        raise ValueError('prepared archive changed')
    actual = {}
    dirs = []
    for path in sorted(tree.rglob('*')):
        if path.is_symlink():
            raise ValueError('upstream link introduced')
        if path.is_dir():
            dirs.append(str(path.relative_to(tree)))
        else:
            actual[str(path.relative_to(tree))] = regular(path, 8 * 1024**2)[1]
    if actual != x['files'] or sorted(dirs) != x['directories']:
        raise ValueError('prepared full upstream input content/membership changed')
    return tree, {'path': str(prep / 'upstream-preparation.json'), **pin,
                  'files': len(actual), 'logical_bytes': x['logical_bytes'],
                  'full_current_original_content_and_membership_verified': True}


def recipe_text(raw):
    candidates = [node.value for node in ast.walk(ast.parse(raw))
                  if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    project = [s for s in candidates if s.startswith('cmake_minimum_required(VERSION 3.16)')]
    toolchain = [s for s in candidates if s.startswith('set(CMAKE_SYSTEM_NAME Windows)')]
    if len(project) != 1 or len(toolchain) != 1:
        raise ValueError('frozen literal native recipe extraction ambiguous')
    return project[0], toolchain[0].replace('NATIVE_SUBSYSTEM', 'windows')


def dependencies(path, target, cwd, guard):
    raw, pin = regular(path, 65536)
    text = raw.decode('utf-8').replace('\\\n', '')
    if not text.startswith(target + ':'):
        raise ValueError('unexpected actual dependency target')
    names = shlex.split(text[len(target) + 1:])
    if not 0 < len(names) <= 1024:
        raise ValueError('actual dependency path bound')
    paths = sorted({(Path(n.replace('$$', '$')) if Path(n).is_absolute()
                     else cwd / n.replace('$$', '$')).resolve(strict=True) for n in names})
    guard.check()
    return paths, {'path': str(path), **pin}


def compile_recipe(row, cmake, cc):
    argv = shlex.split(row['command'])
    if (Path(argv[0]).resolve(strict=True) != Path(cc) or Path(row['directory']) != cmake
            or argv[-2] != '-c' or argv[-1] != row['file']):
        raise ValueError('unexpected actual CMake compiler recipe')
    if any(token.startswith('@') for token in argv):
        raise ValueError('unsupported compiler response-file recipe')
    if argv.count('-o') != 1 or argv.count('-c') != 1:
        raise ValueError('actual compiler output/source recipe ambiguous')
    at = argv.index('-o')
    output = argv[at + 1]
    if row.get('output', output) != output:
        raise ValueError('actual compile_commands output mismatch')
    common = argv[1:at] + argv[at + 2:-2]
    if any(token in ('-M', '-MM', '-MMD', '-MD', '-MF', '-MT', '-MQ') for token in common):
        raise ValueError('unexpected preexisting compiler dependency/output flags')
    obj = (cmake / output).absolute()
    components(obj)
    if not obj.is_relative_to(cmake) or '..' in Path(output).parts or obj.suffix != '.obj':
        raise ValueError('actual object escaped new CMake root')
    return common, Path(row['file']).resolve(strict=True), obj, output


def ninja_console_plan(build_raw, rules_raw, compile_targets, cmake_directory):
    """Fail-closed validation of this CMake graph, not a general Ninja evaluator.

    Only the two directly retained generated files are accepted. Selected
    writers must carry their own literal console binding; top-level variables,
    inherited pools and a configure option alone never establish that fact.
    Paths may use Ninja's literal space/colon/dollar escapes, but variable path
    expansion except the one exact CMake workdir prefix, additional
    includes/subninjas and dynamic dependencies fail.
    """
    if (not isinstance(compile_targets, list) or len(compile_targets) != 126
            or len(set(compile_targets)) != 126):
        raise ValueError('console graph requires exact 126 unique compiler outputs')

    context = {'stage':'generated-graph-framing', 'file':None, 'physical_line':None,
               'logical_line_bytes':0, 'logical_line_sha256':None}
    context_raw = b''

    def failure(message, fragment=None):
        raw = context_raw if fragment is None else fragment.encode()
        prefix = raw[:256].decode('utf-8', errors='ignore')
        error = ValueError(message)
        error.observation = {'schema':'native-tls-ninja-parser-failure-6970-v1', **context,
            'reason':message[:256], 'context_utf8':prefix, 'context_prefix_bytes':len(prefix.encode()),
            'context_total_bytes':len(raw), 'context_sha256':digest(raw),
            'context_kind':'logical-line-prefix' if fragment is None else 'offending-path-fragment',
            'native_execution_verified':False, 'tls_execution_verified':False}
        return error

    def canonical(name):
        # Ninja canonicalizes node names before producer lookup. Refuse every
        # alternate spelling here so ./hidden cannot conceal a real writer.
        # Absolute source leaves remain supported without filesystem resolution.
        if (not name or '\\' in name or '//' in name
                or any(part in ('.','..') for part in name.split('/'))
                or Path(name).as_posix() != name):
            raise failure('noncanonical decoded Ninja output/dependency refused',name)

    expected_directory = str(cmake_directory)
    canonical(expected_directory)
    if not Path(expected_directory).is_absolute():
        raise failure('absolute expected owned CMake directory required')
    expected_workdir = expected_directory + '/'
    workdir, workdir_binding = None, None

    def literal_workdir(value):
        decoded, at = [], 0
        while at < len(value):
            if value[at] == '$':
                at += 1
                if at >= len(value) or value[at] not in (' ', ':', '$'):
                    raise failure('workdir binding must be literal, not recursive',value)
            decoded.append(value[at]); at += 1
        return ''.join(decoded)

    def paths(text):
        tokens, token, at, expanded = [], [], 0, False
        def flush():
            nonlocal token, expanded
            if token:
                value = ''.join(token)
                if expanded and (not value.startswith(expected_workdir)
                        or not Path(value).is_relative_to(Path(expected_directory))):
                    raise failure('expanded workdir suffix escaped expected CMake directory',value)
                tokens.append(value); token = []
            expanded = False
        while at < len(text):
            char = text[at]
            if char == '$':
                if at + 1 < len(text) and text[at + 1] in (' ', ':', '$'):
                    at += 1; token.append(text[at])
                else:
                    braced, plain = '${cmake_ninja_workdir}', '$cmake_ninja_workdir'
                    width = len(braced) if text.startswith(braced,at) else 0
                    if not width and text.startswith(plain,at):
                        end = at + len(plain)
                        if end == len(text) or not re.match(r'[A-Za-z_0-9.+-]',text[end]):
                            width = len(plain)
                    if not width or token or workdir is None:
                        raise failure('unsupported/unbound Ninja variable/path escape',text[at:])
                    token.extend(workdir); expanded = True
                    at += width - 1
            elif char.isspace() or char in ':|':
                flush()
                if char == ':':
                    tokens.append(':')
                elif char == '|':
                    if at + 1 < len(text) and text[at + 1] in ('|', '@'):
                        at += 1; tokens.append('|' + text[at])
                    else:
                        tokens.append('|')
            else:
                token.append(char)
            at += 1
        flush()
        if len(tokens) > 8192:
            raise failure('Ninja edge token bound')
        return tokens

    edges, producers, rules, includes = [], {}, {}, []
    top_names = set()
    for filename, raw in (('build.ninja', build_raw), ('CMakeFiles/rules.ninja', rules_raw)):
        context_raw = b''
        context.update(stage='generated-graph-framing',file=filename,physical_line=None,
                       logical_line_bytes=0,logical_line_sha256=None)
        if (not isinstance(raw, bytes) or not raw or len(raw) > 2 * 1024**2
                or b'\r' in raw or b'\0' in raw or not raw.endswith(b'\n')):
            raise failure('bounded LF generated Ninja file required')
        try:
            text = raw.decode('utf-8', errors='strict')
        except UnicodeError as error:
            context_raw = raw
            raise failure('generated Ninja input is not UTF-8') from error
        physical = text.splitlines(keepends=True)
        if len(physical) > 32768 or any(len(line.encode()) > 65536 for line in physical):
            raise failure('generated Ninja line/count bound')
        records, current, index = [], None, 0
        while index < len(physical):
            begin = index
            line = physical[index].removesuffix('\n'); index += 1
            context_raw = line.encode()
            context.update(stage='generated-graph-continuation',file=filename,physical_line=begin+1,
                           logical_line_bytes=len(context_raw),logical_line_sha256=digest(context_raw))
            while line.endswith('$') and ((len(line) - len(line.rstrip('$'))) & 1):
                if index >= len(physical):
                    raise failure('truncated Ninja continuation')
                line = line[:-1] + physical[index].lstrip(' ').removesuffix('\n')
                index += 1
                if len(line.encode()) > 65536:
                    raise failure('generated Ninja logical line bound')
            context_raw = line.encode()
            context.update(stage='generated-graph-directive',file=filename,physical_line=begin+1,
                           logical_line_bytes=len(context_raw),logical_line_sha256=digest(context_raw))
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            if line.startswith((' ', '\t')):
                binding = re.fullmatch(r'  ([A-Za-z_][A-Za-z_0-9]*) = (.*)', line)
                if current is None or binding is None:
                    raise failure('unsupported generated Ninja binding context')
                name, value = binding.groups()
                if name in current['bindings']:
                    raise failure('duplicate generated Ninja block binding')
                current['bindings'][name] = value
                current['end'] = index
                continue
            current = None
            if line.startswith('build '):
                if filename != 'build.ninja':
                    raise failure('build edges outside retained build.ninja')
                tokens = paths(line[6:])
                if tokens.count(':') != 1:
                    raise failure('generated Ninja build delimiter ambiguous')
                colon = tokens.index(':'); out, tail = tokens[:colon], tokens[colon + 1:]
                if (not out or not tail or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9.+-]*', tail[0])
                        or out.count('|') > 1 or any(x in out for x in ('||', '|@'))):
                    raise failure('unsupported generated Ninja build edge')
                outputs = [x for x in out if x != '|']
                if len(outputs) != len(set(outputs)) or len(outputs) > 256:
                    raise failure('duplicate/unbounded generated Ninja edge outputs')
                for output in outputs:
                    canonical(output)
                dependencies, categories, category = [], {'explicit': [], 'implicit': [], 'order': [], 'validation': []}, 'explicit'
                seen = set()
                for token in tail[1:]:
                    if token in ('|', '||', '|@'):
                        if token in seen:
                            raise failure('duplicate Ninja dependency separator')
                        seen.add(token)
                        category = {'|':'implicit', '||':'order', '|@':'validation'}[token]
                    else:
                        canonical(token)
                        dependencies.append(token); categories[category].append(token)
                current = {'file':filename, 'begin':begin, 'end':index, 'outputs':outputs,
                           'rule':tail[0], 'dependencies':dependencies, 'categories':categories,
                           'bindings':{}}
                records.append(current); edges.append(current)
                for output in outputs:
                    if output in producers:
                        raise failure('duplicate generated Ninja producer: ' + output)
                    producers[output] = current
                if len(edges) > 8192 or len(producers) > 16384:
                    raise failure('generated Ninja graph bound')
            elif line.startswith('rule '):
                name = line[5:]
                if filename != 'CMakeFiles/rules.ninja' or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9.+-]*', name) or name in rules:
                    raise failure('duplicate/unsupported generated Ninja rule')
                current = {'file':filename, 'begin':begin, 'end':index, 'bindings':{}, 'rule':name}
                records.append(current); rules[name] = current
            elif line.startswith('include '):
                if filename != 'build.ninja' or paths(line[8:]) != ['CMakeFiles/rules.ninja']:
                    raise failure('unbound generated Ninja include')
                includes.append(line[8:])
            elif line.startswith(('subninja ', 'pool ')):
                raise failure('additional Ninja file or pool declaration refused')
            elif line.startswith('default '):
                if filename != 'build.ninja' or not paths(line[8:]):
                    raise failure('unsupported Ninja default context')
            else:
                binding = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9]*) = (.*)', line)
                if binding is None or binding[1] in ('pool', 'dyndep'):
                    raise failure('unsupported generated Ninja top-level directive')
                key = (filename, binding[1])
                if key in top_names:
                    raise failure('duplicate generated Ninja top-level variable')
                top_names.add(key)
                if binding[1] == 'cmake_ninja_workdir':
                    if filename != 'build.ninja' or workdir is not None:
                        raise failure('duplicate/foreign CMake workdir binding')
                    workdir = literal_workdir(binding[2])
                    if workdir != expected_workdir or len(workdir.encode()) > 4096:
                        raise failure('literal CMake workdir differs from expected owned directory',binding[2])
                    workdir_binding = {'literal':workdir,'physical_lines':[begin,index],
                                      'block_sha256':digest(''.join(physical[begin:index]).encode())}
        for record in records:
            record['block_sha256'] = digest(''.join(physical[record['begin']:record['end']]).encode())
    context_raw = b''
    context.update(stage='generated-graph-writer-closure',file='build.ninja',physical_line=None,
                   logical_line_bytes=0,logical_line_sha256=None)
    if includes != ['CMakeFiles/rules.ninja']:
        raise failure('exact single retained Ninja rule include required')
    if workdir_binding is None:
        raise failure('one literal MAIN CMake workdir binding required')

    def relative(name):
        path = Path(name)
        if path.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')) or '\\' in name:
            raise failure('selected Ninja output must be a safe relative path')

    def writer(name, kind):
        relative(name)
        edge = producers.get(name)
        if edge is None or not edge['rule'].startswith(kind + '__') or edge['rule'] not in rules:
            raise failure('selected Ninja writer rule/output mismatch: ' + name)
        rule = rules[edge['rule']]
        if (edge['bindings'].get('pool') != 'console' or 'dyndep' in edge['bindings']
                or 'pool' in rule['bindings'] or 'dyndep' in rule['bindings']
                or not rule['bindings'].get('command')):
            raise failure('selected Ninja writer lacks its own literal console pool: ' + name)
        return edge

    def alias(name, kind, basename):
        cursor, history, seen = name, [], set()
        for _ in range(4):
            if cursor in seen:
                raise failure('cycle in selected Ninja alias')
            seen.add(cursor); edge = producers.get(cursor)
            if edge is None:
                raise failure('selected Ninja alias/output missing: ' + cursor)
            if edge['rule'] != 'phony':
                if Path(cursor).name != basename:
                    raise failure('selected Ninja alias resolves unexpected artifact')
                return cursor, writer(cursor, kind), history
            relative(cursor)
            if (len(edge['outputs']) != 1 or len(edge['categories']['explicit']) != 1
                    or any(edge['categories'][key] for key in ('implicit','order','validation'))
                    or edge['bindings']):
                raise failure('selected Ninja phony alias must resolve one direct output')
            history.append({'alias':cursor, 'direct_output':edge['categories']['explicit'][0],
                            'block_sha256':edge['block_sha256'],
                            'physical_lines':[edge['begin'],edge['end']]})
            cursor = edge['categories']['explicit'][0]
        raise failure('selected Ninja alias depth bound')

    selected, identities, rows = [], set(), []
    def retain(target, output, edge, phase, aliases):
        if id(edge) in identities:
            raise failure('selected Ninja writer bound more than once')
        identities.add(id(edge)); selected.append(edge)
        rows.append({'target':target, 'output':output, 'outputs':edge['outputs'], 'rule':edge['rule'],
                     'phase':phase, 'pool':'console', 'edge_block_sha256':edge['block_sha256'],
                     'rule_block_sha256':rules[edge['rule']]['block_sha256'], 'aliases':aliases,
                     'edge_physical_lines':[edge['begin'],edge['end']],
                     'rule_physical_lines':[rules[edge['rule']]['begin'],rules[edge['rule']]['end']]})
    for target in compile_targets:
        retain(target, target, writer(target, 'C_COMPILER'), 'object', [])
    for target in ('everest','p256m','mbedcrypto','mbedx509','mbedtls','ntwst'):
        output, edge, history = alias(target, 'C_STATIC_LIBRARY_LINKER', 'lib' + target + '.a')
        retain(target, output, edge, 'archive', history)
    for target, suffix, kind in (('TLS13PROB','.exe','C_EXECUTABLE_LINKER'),
                                 ('TIMEPROB','.exe','C_EXECUTABLE_LINKER'),
                                 ('M98TLS','.dll','C_SHARED_LIBRARY_LINKER')):
        output, edge, history = alias(target, kind, target + suffix)
        retain(target, output, edge, 'PE-link', history)
    regenerate = producers.get('build.ninja')
    if (regenerate is None or regenerate['rule'] != 'RERUN_CMAKE'
            or regenerate['rule'] not in rules
            or regenerate['bindings'].get('pool') != 'console'
            or 'dyndep' in regenerate['bindings']
            or 'pool' in rules['RERUN_CMAKE']['bindings']
            or not rules['RERUN_CMAKE']['bindings'].get('command')):
        raise failure('manifest regeneration edge lacks literal console binding')
    # Any producer reached through a selected writer's complete dependency list
    # must be one of these frozen writers or a command-free phony edge. This
    # excludes hidden custom writers even if their own pool looks acceptable.
    visited, pending = set(), [name for edge in (*selected,regenerate) for name in edge['dependencies']]
    while pending:
        if len(visited) > 16384:
            raise failure('selected Ninja dependency reachability bound')
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name); edge = producers.get(name)
        if edge is None:
            continue
        if edge['rule'] != 'phony' and id(edge) not in identities and edge is not regenerate:
            raise failure('unbound writer reachable from selected Ninja targets: ' + name)
        if edge['rule'] == 'phony' and edge['bindings']:
            raise failure('reachable Ninja phony edge has bindings')
        pending.extend(edge['dependencies'])
    return {'schema':'native-tls-literal-console-graph-6970-v1',
            'status':'PASS_LITERAL_SELECTED_EDGES_ONLY', 'compile_count':126,
            'archive_count':6, 'PE_count':3, 'selected_writer_count':len(rows), 'edges':rows,
            'manifest_regeneration_edge':{'output':'build.ninja', 'rule':'RERUN_CMAKE', 'pool':'console',
                'edge_block_sha256':regenerate['block_sha256'],
                'rule_block_sha256':rules['RERUN_CMAKE']['block_sha256'],
                'physical_lines':[regenerate['begin'],regenerate['end']]},
            'reachable_dependency_names':len(visited), 'retained_files':['build.ninja','CMakeFiles/rules.ninja'],
            'cmake_ninja_workdir':workdir_binding,
            'configure_or_try_compile_group_containment_verified':False,
            'escaped_writers_excluded_verified':False, 'continuous_group_stop_verified':False}


def ninja_console_controls(baseline, rules, targets, actual_plan, cmake_directory):
    """Selective memory mutations of the actual admitted, retained graph bytes.

    No mutated graph is written or executed. Positive acceptance and rejected
    ambiguity/pool/writer cases use the same whole-buffer production parser.
    """
    started = time.monotonic()
    build_lines, rule_lines = baseline.splitlines(keepends=True), rules.splitlines(keepends=True)
    def block(lines, bounds, sha):
        value = b''.join(lines[bounds[0]:bounds[1]])
        if not value or digest(value) != sha:
            raise ValueError('actual control block source binding mismatch')
        return value
    def replace(raw, before, after):
        if raw.count(before) != 1 or before == after:
            raise ValueError('actual console control mutation must be unique')
        return raw.replace(before, after, 1)
    first = actual_plan['edges'][0]
    object_line = block(build_lines,first['edge_physical_lines'],first['edge_block_sha256'])
    first_rule = block(rule_lines,first['rule_physical_lines'],first['rule_block_sha256'])
    if object_line.count(b'  pool = console\n') != 1:
        raise ValueError('actual object console binding not uniquely mutable')
    unpooled = object_line.replace(b'  pool = console\n',b'',1)
    archive = next(row for row in actual_plan['edges'] if row['target'] == 'ntwst')
    archive_line = block(build_lines,archive['edge_physical_lines'],archive['edge_block_sha256'])
    history = archive['aliases'][0]
    alias_line = block(build_lines,history['physical_lines'],history['block_sha256'])
    if len(alias_line.splitlines()) != 1:
        raise ValueError('actual alias control requires one physical alias line')
    regeneration = actual_plan['manifest_regeneration_edge']
    regen_line = block(build_lines,regeneration['physical_lines'],regeneration['edge_block_sha256'])
    if regen_line.count(b'  pool = console\n') != 1:
        raise ValueError('actual regeneration binding not uniquely mutable')
    wrong_rule = next(row['rule'] for row in actual_plan['edges'] if row['phase'] == 'PE-link')
    archive_wrong = re.sub(rb': ' + re.escape(archive['rule'].encode()) + rb'(?=[ \n])',
                           b': ' + wrong_rule.encode(),archive_line,count=1)
    hidden = object_line.replace((': '+first['rule']+' ').encode(),
                                 (': '+first['rule']+' generated6970-control.h ').encode(),1)
    if b'generated6970-control.h' in baseline or b'UNBOUND_CONTROL_6970' in rules:
        raise ValueError('actual console control name collision')
    binding = actual_plan['cmake_ninja_workdir']
    binding_line = block(build_lines,binding['physical_lines'],binding['block_sha256'])
    if len(binding_line.splitlines()) != 1:
        raise ValueError('actual workdir control requires one physical literal binding')
    controls = [
        ('positive-literal-full-graph', True, baseline, rules),
        ('negative-missing-object-pool', False, replace(baseline,object_line,unpooled),rules),
        ('negative-inherited-rule-pool', False, replace(baseline,object_line,unpooled),
         replace(rules,first_rule,first_rule.replace(('rule '+first['rule']+'\n').encode(),
             ('rule '+first['rule']+'\n  pool = console\n').encode(),1))),
        ('negative-variable-pool', False, replace(baseline,object_line,object_line.replace(b'pool = console',b'pool = $selected_pool',1)),rules),
        ('negative-duplicate-producer', False, baseline+object_line,rules),
        ('negative-ambiguous-archive-alias', False, replace(baseline,alias_line,alias_line[:-1]+b' extra.a\n'),rules),
        ('negative-archive-wrong-rule-kind', False, replace(baseline,archive_line,archive_wrong),rules),
        ('negative-unbound-include', False, baseline+b'include other.ninja\n',rules),
        ('negative-reachable-hidden-writer', False,
         replace(baseline,object_line,hidden)+b'build generated6970-control.h: UNBOUND_CONTROL_6970\n  pool = console\n',
         rules+b'rule UNBOUND_CONTROL_6970\n  command = harmless-not-executed\n'),
        ('negative-noncanonical-hidden-writer', False,
         replace(baseline,object_line,hidden.replace(b' generated6970-control.h ',b' ./generated6970-control.h ',1))
         +b'build generated6970-control.h: UNBOUND_CONTROL_6970\n  pool = console\n',
         rules+b'rule UNBOUND_CONTROL_6970\n  command = harmless-not-executed\n'),
        ('negative-regeneration-hidden-writer', False,
         replace(baseline,regen_line,regen_line.replace(b': RERUN_CMAKE ',b': RERUN_CMAKE generated6970-control.h ',1))
         +b'build generated6970-control.h: UNBOUND_CONTROL_6970\n  pool = console\n',
         rules+b'rule UNBOUND_CONTROL_6970\n  command = harmless-not-executed\n'),
        ('negative-unpooled-regeneration', False, replace(baseline,regen_line,regen_line.replace(b'  pool = console\n',b'',1)),rules),
        ('negative-wrong-literal-workdir',False,replace(baseline,binding_line,
            b'cmake_ninja_workdir = /wrong-owned-directory-6970/\n'),rules),
        ('negative-unknown-path-variable',False,baseline+b'build ${unbound_6970_workdir}file: phony\n',rules),
    ]
    cases = []
    for name, expected, build_raw, rules_raw in controls:
        if time.monotonic() - started > 60 or len(build_raw) > 2 * 1024**2 or len(rules_raw) > 2 * 1024**2:
            raise ValueError('actual console control input/time bound')
        accepted, error = True, None
        try:
            report = ninja_console_plan(build_raw, rules_raw, targets, cmake_directory)
            if report['selected_writer_count'] != 135 or report['status'] != 'PASS_LITERAL_SELECTED_EDGES_ONLY':
                raise ValueError('positive console graph report differs')
        except ValueError as failure:
            accepted, error = False, str(failure)[:256]
        cases.append({'name':name, 'expected':'accept' if expected else 'reject',
                      'actual':'accept' if accepted else 'reject', 'result':'PASS' if accepted == expected else 'FAIL',
                      'build_sha256':digest(build_raw), 'rules_sha256':digest(rules_raw), 'error':error})
    failures = sum(case['result'] != 'PASS' for case in cases)
    return {'schema':'native-tls-console-parser-controls-6970-v1', 'completed':len(cases),
            'failures':failures, 'result':'PASS_PARSER_CONTROLS_ONLY' if not failures else 'FAIL', 'cases':cases,
            'basis_build_sha256':digest(baseline), 'basis_rules_sha256':digest(rules),
            'mutated_graphs_written_or_executed':False, 'elapsed_seconds':time.monotonic()-started,
            'process_execution_verified':False, 'native_execution_verified':False,
            'windows98_integration_verified':False, 'tls_execution_verified':False}


def compact_tu_headers(receipt):
    """The existing lossless header-index representation, for PASS and FAIL.

    Build both replacement arrays before changing the receipt. Repeated calls
    on the same header map preserve the already indexed arrays unchanged.
    """
    keys = [key for key in ('CMake_actual_TU_dependencies','SSPI_actual_TU_dependencies') if key in receipt]
    if not keys:
        return
    headers = receipt.get('headers_before')
    if not isinstance(headers,dict):
        raise ValueError('TU header compaction requires actual header pin map')
    names = sorted(headers)
    index = {name:at for at,name in enumerate(names)}
    replacements = {}
    for key in keys:
        rows = receipt[key]
        if not isinstance(rows,list):
            raise ValueError('TU header compaction requires actual unit rows')
        compact = []
        for unit in rows:
            if not isinstance(unit,dict):
                raise ValueError('TU header compaction requires unit dictionaries')
            if 'headers' in unit:
                if 'header_indices' in unit or not isinstance(unit['headers'],list):
                    raise ValueError('TU header representation is ambiguous')
                compact.append({**{k:v for k,v in unit.items() if k!='headers'},
                                'header_indices':[index[path] for path in unit['headers']]})
            else:
                values = unit.get('header_indices')
                if (receipt.get('TU_header_index_order')!='lexicographic_headers_before_path_keys'
                        or not isinstance(values,list)
                        or any(not isinstance(at,int) or isinstance(at,bool) or not 0<=at<len(names) for at in values)):
                    raise ValueError('existing TU header indices invalid')
                compact.append(unit)
        replacements[key] = compact
    receipt.update(replacements)
    receipt['TU_header_index_order']='lexicographic_headers_before_path_keys'


def build(output, prep, expected_preparation_sha):
    components(output)
    if output.parent != ROOT / 'build/native-tls-proof-6970':
        raise ValueError('new namespaced TLS proof root required')
    # This is the admission before loading the new resource helper's code.
    if shutil.disk_usage(ROOT).free < RESERVE + LIMIT:
        raise ValueError('BLOCKED local/hosted resource admission')
    source_pins, source_raw = {}, {}
    for relative, expected in {**PRODUCTION, **SUPPORT}.items():
        path = ROOT / relative
        raw, pin = regular(path, 2 * 1024**2)
        if (pin['bytes'], pin['sha256']) != tuple(expected):
            raise ValueError('literal production/support pin mismatch: ' + relative)
        source_pins[relative], source_raw[relative] = pin, raw
    for name in (*NEW_HELPERS, Path(__file__).name):
        relative = 'ntwin32/secure_transport/' + name
        raw, pin = regular(ROOT / relative, 200 * 1024)
        source_pins[relative], source_raw[relative] = pin, raw
    resources = load(HERE / NEW_HELPERS[0],
                     (source_pins['ntwin32/secure_transport/' + NEW_HELPERS[0]]['bytes'],
                      source_pins['ntwin32/secure_transport/' + NEW_HELPERS[0]]['sha256']),
                     'native_tls_resources_frozen')
    guard = resources.Guard(output, ROOT)
    receipt = {'schema': 'native-tls-sspi-guarded-build-6970-v1', 'result': 'FAIL',
               'profile': 'native-TLS32MiB-explicit-streaming-v1',
               'source_inputs_before': source_pins, 'commands': guard.commands,
               'source_inputs_after_equal': False, 'headers_before_after_equal': False,
               'tool_inputs_before_after_equal': False, 'upstream_before_after_equal': False,
               'scope': 'current native4PE compile/OEM/ISA proof only; no Windows/credential/TLS execution',
               'resource_observations_are_not_quota_or_unseen_peaks': True,
               'compiler_tool_dynamic_runtime_closure_verified': False,
               'Python_runtime_or_loaded_module_attestation_verified': False,
               **{flag: False for flag in (*FALSE_FLAGS,*TLS_FALSE_FLAGS)}}
    try:
        tree, upstream = upstream_snapshot(prep,expected_preparation_sha)
        receipt['upstream_before'] = upstream
        # Capture existing script helpers; no original build function executes.
        bridge_name = 'ntwin32/legacy_provider_bridge/build_native_pe32_guarded_6970.py'
        bridge = load(ROOT / bridge_name, SUPPORT[bridge_name], 'native_tls_existing_controls', guard)
        script_name = 'ntwin32/legacy_provider_bridge/pe_link_script_6970.py'
        script = load(ROOT / script_name, SUPPORT[script_name], 'native_tls_existing_link_script', guard)
        gate_name = 'ntwin32/secure_transport/i486_gate.py'
        gate = load(ROOT / gate_name, PRODUCTION[gate_name], 'native_tls_frozen_i486', guard)
        stream_name = 'ntwin32/secure_transport/i486_stream_6970.py'
        stream = load(ROOT / stream_name, (source_pins[stream_name]['bytes'], source_pins[stream_name]['sha256']),
                      'native_tls_stream_frozen', guard)
        quiescent_name = 'ntwin32/secure_transport/native_tls_quiescent_controls_6970.py'
        quiescent_controls = load(ROOT / quiescent_name,
            (source_pins[quiescent_name]['bytes'], source_pins[quiescent_name]['sha256']),
            'native_tls_quiescent_controls_frozen', guard)
        guard.check()
        receipt['stream_controls'] = stream.run_controls(gate)
        receipt['resource_control_plan']=resources.hosted_control_plan()
        if (receipt['stream_controls'].get('status') != 'PASS'
                or receipt['stream_controls'].get('completed') != 17
                or receipt['stream_controls'].get('failures') != 0
                or tuple(c['name'] for c in receipt['stream_controls']['cases']) != stream.CONTROL_NAMES
                or any(c['result'] != 'PASS' for c in receipt['stream_controls']['cases'])):
            raise ValueError('new bounded stream controls failed')
        receipt['script_controls'] = script.run_synthetic_controls()
        bridge.require_script_controls(receipt['script_controls'], 15)
        guard.check()
        tools = {}
        system_input_paths = set()
        def pin_tool(name):
            found = shutil.which(name, path='/usr/bin:/bin')
            if not found:
                raise ValueError('required hosted tool absent: ' + name)
            path = Path(found).resolve(strict=True)
            tools[str(path)] = guard.pin(path, maximum=256 * 1024**2,
                                        readonly_system_input=True)
            system_input_paths.add(str(path))
            return str(path)
        cc = pin_tool('i686-w64-mingw32-gcc-win32')
        objdump = pin_tool('i686-w64-mingw32-objdump')
        cmake_tool, ninja = pin_tool('cmake'), pin_tool('ninja')
        ar, ranlib, windres = (pin_tool('i686-w64-mingw32-' + n) for n in ('ar', 'ranlib', 'windres'))
        python = str(Path(sys.executable).resolve(strict=True))
        tools[python] = guard.pin(Path(python), maximum=256 * 1024**2,
                                  readonly_system_input=True)
        system_input_paths.add(python)
        parser = Path(gate.pefile.__file__).resolve(strict=True)
        if parser != prep / 'pydeps/pefile.py':
            raise ValueError('actual PE parser differs from prepared isolated source')
        tools[str(parser)] = guard.pin(parser, maximum=2 * 1024**2,
                                       readonly_system_input=False)
        versions = {}
        for name, tool in (('cc', cc), ('objdump', objdump), ('cmake', cmake_tool), ('ninja', ninja)):
            result = guard.run([tool, '--version'], 'version-' + name)
            if result.returncode or result.stderr or not result.stdout:
                raise ValueError('actual version query failed')
            versions[name] = result.stdout.decode('ascii').splitlines()[0]
        receipt['tool_versions'] = versions
        cmake_version = re.fullmatch(r'cmake version (\d+)\.(\d+)\.(\d+)(?:[-.].*)?', versions['cmake'])
        if not cmake_version:
            raise ValueError('actual CMake version shape')
        system_cmake = Path('/usr/share/cmake-' + '.'.join(cmake_version.groups()[:2]))
        components(system_cmake)
        system_cmake_inputs = {}
        for p in sorted(system_cmake.rglob('*')):
            if p.is_file():
                system_cmake_inputs[str(p)] = guard.pin(p, maximum=8 * 1024**2)
        if (not system_cmake_inputs or len(system_cmake_inputs)>8192
                or sum(p['bytes'] for p in system_cmake_inputs.values())>128*1024**2):
            raise ValueError('complete direct CMake module/template input bound')
        system_cmake_manifest = output/'system-cmake-inputs.json'
        system_cmake_manifest_raw = encode(system_cmake_inputs)
        if len(system_cmake_manifest_raw)>2*1024**2:
            raise ValueError('direct CMake inputs manifest output bound')
        guard.write(system_cmake_manifest,system_cmake_manifest_raw)
        receipt['direct_system_CMake_inputs']={'manifest':guard.pin(system_cmake_manifest,maximum=2*1024**2),
            'path':str(system_cmake_manifest),'files':len(system_cmake_inputs),
            'dynamic_tool_runtime_attestation_verified':False}
        def query(flag, name):
            r = guard.run([cc, flag + name], 'query-' + name.replace('.', '-'))
            text = r.stdout.decode('ascii')
            if r.returncode or r.stderr or not text.endswith('\n') or text.count('\n') != 1:
                raise ValueError('actual compiler tool/library query failed')
            value = text[:-1]
            path = Path(value)
            if not path.is_absolute():
                value = shutil.which(value, path='/usr/bin:/bin') if '/' not in value else None
                if not value:
                    return None
                path = Path(value)
            path = path.resolve(strict=True)
            tools[str(path)] = guard.pin(path, maximum=256 * 1024**2,
                                        readonly_system_input=True)
            system_input_paths.add(str(path))
            return path
        linker = None
        for name in ('cc1', 'collect2', 'as', 'ld'):
            selected = query('-print-prog-name=', name)
            if selected is None:
                raise ValueError('compiler-selected backend absent: ' + name)
            if name == 'ld':
                linker = selected
        system_libraries = set()
        for name in ('gcc', 'gcc_eh', 'mingw32', 'mingwex', 'moldname', 'msvcrt', 'kernel32',
                     'advapi32', 'crypt32', 'ws2_32', 'bcrypt', 'user32', 'gdi32', 'winspool',
                     'shell32', 'ole32', 'oleaut32', 'uuid', 'comdlg32', 'pthread', 'ssp'):
            selected = query('-print-file-name=', 'lib' + name + '.a')
            if selected is not None:
                system_libraries.add(selected)
        receipt['tool_inputs_before'] = tools.copy()
        receipt['readonly_system_input_paths'] = sorted(system_input_paths)
        control_offsets = {'commands':len(guard.commands), 'capture':guard.capture_bytes,
                           'decoder':guard.decoder_bytes}
        receipt['quiescent_controls'] = quiescent_controls.run_controls(guard, resources, python)
        quiescent_pins = require_quiescent_controls(receipt['quiescent_controls'], quiescent_controls,
            guard, resources, source_pins, tools[python], control_offsets)
        # Original in-memory ISA methods run through the existing exact-byte loader.
        r = guard.run([python, '-B', '-c', bridge.I486_CONTROL_CHILD,
                       str(HERE / 'i486_gate.py'), PRODUCTION[gate_name][1],
                       str(HERE / 'i486_gate_test.py'), SUPPORT['ntwin32/secure_transport/i486_gate_test.py'][1],
                       json.dumps(bridge.I486_CONTROL_METHODS)], 'original-i486-controls')
        if r.returncode or r.stderr or r.stdout != b'I486_PYTHON_CONTROLS: 4 original methods passed\n':
            raise ValueError('unchanged original ISA controls failed')
        receipt['original_i486_controls'] = {'completed':4, 'filesystem_method_deferred':True}
        scripts, script_pins = {}, {}
        for name, mode in (('dll', ['--dll']), ('exe', [])):
            r = guard.run([str(linker), '--verbose', '-m', 'i386pe', *mode], 'default-script-' + name)
            if r.returncode or r.stderr:
                raise ValueError('actual linker default discovery failed')
            default = script.extract_default_script(r.stdout)
            generated, info = script.relocate_lifecycle_lists(default)
            guard.write(output / (name + '-default.ld'), default)
            guard.write(output / (name + '-readonly.ld'), generated)
            for suffix,original in (('default',default),('readonly',generated)):
                path=output/(name+'-'+suffix+'.ld')
                pin=guard.pin(path,maximum=2*1024**2)
                if pin['bytes']!=len(original) or pin['sha256']!=digest(original):
                    raise ValueError('retained generated/default script differs from literal transformation')
                script_pins[str(path)]=pin
            scripts[name] = {'transformation': info, 'default_sha256':digest(default),
                             'generated_sha256':digest(generated)}
        receipt['link_scripts'] = scripts
        receipt['link_script_files_before']=script_pins
        def check_scripts():
            for path,pin in script_pins.items():
                if guard.pin(Path(path),maximum=2*1024**2)!=pin:
                    raise ValueError('generated/default linker script changed before/during link')
        project = output / 'project'
        project.mkdir(mode=0o700)
        source_copies={}
        for relative in PRODUCTION:
            guard.write(project / Path(relative).name, source_raw[relative])
            copied=project/Path(relative).name
            pin=guard.pin(copied,maximum=2*1024**2)
            if pin['sha256']!=source_pins[relative]['sha256'] or pin['bytes']!=source_pins[relative]['bytes']:
                raise ValueError('actual copied recipe/production input differs from frozen source')
            source_copies[str(copied)]=pin
        project_text, toolchain_text = recipe_text(source_raw['ntwin32/secure_transport/build.py'])
        # Exact production recipe plus explicit proof-retention linker script/trace.
        toolchain_text = toolchain_text.replace('set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)',
                                                'set(CMAKE_C_COMPILER ' + cc + ')')
        toolchain_text = toolchain_text.replace('set(CMAKE_RC_COMPILER i686-w64-mingw32-windres)',
                                                'set(CMAKE_RC_COMPILER ' + windres + ')')
        toolchain_text += '\nset(CMAKE_AR "' + ar + '")\nset(CMAKE_RANLIB "' + ranlib + '")\n'
        for flag, profile in (('CMAKE_EXE_LINKER_FLAGS_INIT','exe'), ('CMAKE_SHARED_LINKER_FLAGS_INIT','dll')):
            toolchain_text += 'string(APPEND ' + flag + ' " -Wl,-t -Xlinker -T -Xlinker ' + str(output / (profile+'-readonly.ld')) + '")\n'
        guard.write(project / 'CMakeLists.txt', project_text.encode())
        guard.write(project / 'toolchain.cmake', toolchain_text.encode())
        for name,original in (('CMakeLists.txt',project_text.encode()),('toolchain.cmake',toolchain_text.encode())):
            copied=project/name;pin=guard.pin(copied,maximum=2*1024**2)
            if pin['sha256']!=digest(original) or pin['bytes']!=len(original):
                raise ValueError('actual generated literal CMake recipe differs before configure')
            source_copies[str(copied)]=pin
        cmake = output / 'cmake'
        r = guard.run([cmake_tool, '-S', str(project), '-B', str(cmake), '-G', 'Ninja',
                       '-DCMAKE_TOOLCHAIN_FILE=' + str(project / 'toolchain.cmake'),
                       '-DUPSTREAM_SOURCE=' + str(tree), '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                       '-DCMAKE_MAKE_PROGRAM=' + ninja, '-DGEN_FILES=OFF',
                       '-DCMAKE_JOB_POOL_COMPILE=console', '-DCMAKE_JOB_POOL_LINK=console'],
                       'cmake-configure', timeout=120)
        if r.returncode:
            raise ValueError('actual CMake configure failed')
        receipt['CMake_identification_before_TU_header_freeze_verified'] = False
        receipt['CMake_configuration_diagnostics'] = bool(r.stderr)
        graph_raw, graph_pin = regular(cmake / 'compile_commands.json', 2 * 1024**2)
        graph = json.loads(graph_raw)
        if not isinstance(graph, list) or not 1 <= len(graph) <= 256:
            raise ValueError('actual compiler graph count bound')
        receipt['actual_CMake_TU_count'] = len(graph)
        receipt['compile_commands'] = graph_pin
        # Bind all configured generator files separately from actual C headers.
        generator_pins = {}
        for p in sorted(cmake.rglob('*')):
            if p.is_file() and p.suffix in ('.cmake', '.ninja', '.txt', '.json', '.c', '.h', '.in', '.rsp'):
                generator_pins[str(p)] = guard.pin(p, maximum=2 * 1024**2)
        receipt['configured_generator_inputs'] = generator_pins
        receipt['upstream_generated_files_explicitly_disabled'] = True
        console_raw, console_pins = {}, {}
        for name in ('build.ninja','CMakeFiles/rules.ninja'):
            path=cmake/name
            raw,pin=regular(path,2*1024**2)
            if pin!=generator_pins.get(str(path)) or guard.pin(path,maximum=2*1024**2)!=pin:
                raise ValueError('actual generated console graph differs from retained generator input')
            console_raw[name],console_pins[str(path)]=raw,pin
        compile_targets=[compile_recipe(row,cmake,cc)[3] for row in graph]
        try:
            console_plan=ninja_console_plan(console_raw['build.ninja'],console_raw['CMakeFiles/rules.ninja'],compile_targets,cmake)
        except ValueError as error:
            receipt['Ninja_console_parser_failure_observation']=getattr(error,'observation',None)
            raise
        console_plan['files']=console_pins
        receipt['Ninja_console_graph']=console_plan
        receipt['Ninja_console_graph_before_after_equal']=False
        guard.check()
        receipt['Ninja_console_parser_controls']=ninja_console_controls(
            console_raw['build.ninja'],console_raw['CMakeFiles/rules.ninja'],compile_targets,console_plan,cmake)
        guard.check()
        if (receipt['Ninja_console_parser_controls']['result']!='PASS_PARSER_CONTROLS_ONLY'
                or receipt['Ninja_console_parser_controls']['completed']!=14
                or receipt['Ninja_console_parser_controls']['failures']!=0
                or any(row['result']!='PASS' for row in receipt['Ninja_console_parser_controls']['cases'])):
            raise ValueError('actual generated graph parser controls failed')
        def check_console_graph():
            for path,pin in console_pins.items():
                if guard.pin(Path(path),maximum=2*1024**2)!=pin:
                    raise ValueError('actual console graph changed before/during selected production command')
        deps = output / 'dependencies'
        deps.mkdir(mode=0o700)
        units, headers, before_dep_total, objects = [], {}, 0, set()
        for index, row in enumerate(graph):
            common, source, obj, target = compile_recipe(row, cmake, cc)
            if obj in objects:
                raise ValueError('duplicate actual compiler object recipe')
            objects.add(obj)
            dep = deps / (str(index) + '.M')
            label = 'M-' + str(index)
            r = guard.run([cc, *common, '-M', '-MT', label, '-MF', str(dep), str(source)], label, cwd=cmake)
            if r.returncode or r.stdout or r.stderr:
                raise ValueError('actual-M failed/diagnosed')
            included, manifest = dependencies(dep, label, cmake, guard)
            if source not in included:
                raise ValueError('actual-M omits direct TU source')
            for path in included:
                key = str(path)
                pin = guard.pin(path, maximum=8 * 1024**2)
                if key in headers and headers[key] != pin:
                    raise ValueError('header changed between TU discoveries')
                headers[key] = pin
            if len(headers) > 4096 or sum(p['bytes'] for p in headers.values()) > 64 * 1024**2:
                raise ValueError('deduplicated actual header input closure bound')
            before_dep_total += manifest['bytes']
            units.append({'object':str(obj), 'source':str(source), 'target':target,
                          'before_M':manifest, 'headers':[str(p) for p in included]})
        receipt['headers_before'] = headers
        schedule = receipt['CMake_sequential_schedule'] = []
        receipt['CMake_schedule_parallel_jobs'] = 1
        for index, unit in enumerate(units):
            check_console_graph()
            label = 'cmake-object-' + str(index)
            schedule.append({'phase':'object','target':unit['target'],'label':label,
                             'command_index':len(guard.commands),'timeout_seconds':360})
            r = guard.run([ninja,'-C',str(cmake),'-j','1','-d','keepdepfile','-d','keeprsp',
                           unit['target']], label, timeout=360)
            if r.returncode:
                raise ValueError('actual CMake/Ninja compile failed: ' + unit['target'])
        md_total = 0
        for index, unit in enumerate(units):
            dep = Path(unit['object'] + '.d')
            included, manifest = dependencies(dep, unit['target'], cmake, guard)
            if [str(p) for p in included] != unit['headers']:
                raise ValueError('actual-M/-MD TU-specific closure differs')
            md_total += manifest['bytes']
            unit['actual_MD'] = manifest
            unit['object_pin'] = guard.pin(Path(unit['object']), maximum=8 * 1024**2)
        receipt['CMake_actual_TU_dependencies'] = units
        for target in ('everest','p256m','mbedcrypto','mbedx509','mbedtls','ntwst'):
            check_console_graph()
            label = 'cmake-archive-' + target
            schedule.append({'phase':'archive','target':target,'label':label,
                             'command_index':len(guard.commands),'timeout_seconds':120})
            r=guard.run([cmake_tool,'--build',str(cmake),'--parallel','1','--target',target,'--',
                         '-d','keepdepfile','-d','keeprsp'],label,timeout=120)
            if r.returncode:
                raise ValueError('production archive generation failed: ' + target)
        engine_link_inputs={unit['object']:unit['object_pin'] for unit in units}
        engine_link_inputs[str(project/'native.def')]=source_copies[str(project/'native.def')]
        for p in sorted(cmake.rglob('*.a')):
            engine_link_inputs[str(p)]=guard.pin(p,maximum=8*1024**2)
        for target in ('TLS13PROB','TIMEPROB','M98TLS'):
            check_console_graph()
            check_scripts()
            label = 'cmake-link-' + target
            schedule.append({'phase':'PE-link','target':target,'label':label,
                             'command_index':len(guard.commands),'timeout_seconds':120})
            r=guard.run([cmake_tool,'--build',str(cmake),'--parallel','1','--target',target,'--',
                         '-d','keepdepfile','-d','keeprsp'],label,timeout=120)
            if r.returncode:
                raise ValueError('actual engine final link failed: ' + target)
        for path,pin in engine_link_inputs.items():
            if guard.pin(Path(path),maximum=8*1024**2)!=pin:
                raise ValueError('pre-bound engine link object/archive changed')
        receipt['engine_link_inputs_before']=engine_link_inputs
        receipt['engine_link_inputs_before_after_equal']=True
        # Native adapter uses unchanged source/link order, split into two observed TUs.
        adapter = output / 'sspi'
        adapter.mkdir(mode=0o700)
        for name in ('sspi_native.c','sspi_native.h','sspi_native.def','sspi_stream.c','sspi_stream.h',
                     'transport.h','native_runtime.h','user_config.h','i486_format.h'):
            guard.write(adapter / name, regular(project / name, 2 * 1024**2)[0])
            copied=adapter/name;pin=guard.pin(copied,maximum=2*1024**2)
            if pin['sha256']!=source_copies[str(project/name)]['sha256']:
                raise ValueError('adapter copied input differs from original frozen project source')
            source_copies[str(copied)]=pin
        flags = ['-std=c11','-Os','-march=i486','-mtune=i486','-mno-sse','-mno-sse2','-mno-mmx','-mno-avx',
                 '-D__USE_MINGW_ANSI_STDIO=0','-Wall','-Wextra',
                 '-fno-isolate-erroneous-paths-dereference','-fno-isolate-erroneous-paths-attribute',
                 '-Werror','-Wpedantic','-ffunction-sections','-fdata-sections',
                 '-DWINVER=0x0410','-D_WIN32_WINDOWS=0x0410','-D_WIN32_WINNT=0x0400',
                 '-DMBEDTLS_USER_CONFIG_FILE="user_config.h"','-I'+str(adapter),'-I'+str(tree/'include')]
        adapter_objects, adapter_units = [], []
        for name in ('sspi_native','sspi_stream'):
            source, obj = adapter/(name+'.c'), adapter/(name+'.o')
            target = 'adapter-' + name
            m, md = deps/(name+'.M'), deps/(name+'.MD')
            r = guard.run([cc,*flags,'-M','-MT',target,'-MF',str(m),str(source)],target+'-M')
            if r.returncode or r.stdout or r.stderr:
                raise ValueError('adapter actual-M failed')
            included, before = dependencies(m,target,ROOT,guard)
            for path in included:
                pin = guard.pin(path,maximum=8*1024**2)
                if str(path) in headers and headers[str(path)] != pin:
                    raise ValueError('shared adapter header changed')
                headers[str(path)] = pin
            r = guard.run([cc,*flags,'-MD','-MT',target,'-MF',str(md),'-c',str(source),'-o',str(obj)],target+'-compile')
            if r.returncode or r.stdout or r.stderr:
                raise ValueError('adapter compile failed/diagnosed')
            after_included, after = dependencies(md,target,ROOT,guard)
            if included != after_included:
                raise ValueError('adapter actual-M/-MD closure differs')
            before_dep_total += before['bytes'];md_total += after['bytes']
            adapter_units.append({'source':str(source),'object':str(obj),'before_M':before,
                                  'actual_MD':after,'headers':[str(p) for p in included]})
            adapter_objects.append(obj)
        adapter_pre={str(p):guard.pin(p,maximum=8*1024**2) for p in adapter_objects}
        adapter_pre[str(adapter/'sspi_native.def')]=source_copies[str(adapter/'sspi_native.def')]
        if len(headers)>4096 or sum(p['bytes'] for p in headers.values())>64*1024**2:
            raise ValueError('combined adapter/engine header closure bound')
        if before_dep_total + md_total > 4 * 1024**2:
            raise ValueError('combined actual dependency manifest cap')
        retained = [cmake/'CMakeFiles/M98TLS.dir'/(n+'.c.obj')
                    for n in ('native_runtime','native_crt','native_time','i486_format')]
        retained += [cmake/'libntwst.a']
        retained += [cmake/'upstream/library'/('lib'+n+'.a') for n in ('mbedtls','mbedx509','mbedcrypto')]
        retained += [cmake/'upstream/3rdparty/everest/libeverest.a',cmake/'upstream/3rdparty/p256-m/libp256m.a']
        receipt['SSPI_retained_inputs_before'] = {str(p):guard.pin(p,maximum=8*1024**2) for p in retained}
        dll = adapter/'M98SSPI.dll'
        check_scripts()
        for path,pin in {**engine_link_inputs,**adapter_pre,**source_copies}.items():
            if guard.pin(Path(path),maximum=8*1024**2)!=pin:
                raise ValueError('source/definition/object/library changed before adapter link')
        r = guard.run([cc,*flags,'-shared','-nostartfiles','-static','-static-libgcc',
                       '-Wl,--gc-sections,--no-insert-timestamp,--subsystem,windows:4.10,'
                       '--major-os-version,4,--minor-os-version,10,--entry,_M98SspiDllMain@12',
                       '-Wl,-Map,'+str(adapter/'M98SSPI.map'),'-Wl,-t',
                       '-Xlinker','-T','-Xlinker',str(output/'dll-readonly.ld'),
                       *map(str,adapter_objects),*map(str,retained),str(adapter/'sspi_native.def'),
                       '-ladvapi32','-lcrypt32','-o',str(dll)],'SSPI-link',timeout=120)
        if r.returncode or r.stderr:
            raise ValueError('actual SSPI link failed/diagnosed')
        receipt['SSPI_actual_TU_dependencies'] = adapter_units
        receipt['actual_total_production_TU_compilations'] = len(graph)+2
        maps = [cmake/(n+'.map') for n in ('TLS13PROB','TIMEPROB','M98TLS')]+[adapter/'M98SSPI.map']
        map_total = 0
        linked = {}
        for p in maps:
            raw, pin = regular(p,2*1024**2);map_total +=len(raw)
            paths = []
            for line in raw.decode('utf-8').splitlines():
                if not line.startswith('LOAD '):
                    continue
                name = line[5:]
                if name == 'dll stuff':
                    continue  # GNU linker synthetic internal pseudo-input, not a file.
                candidate = Path(name)
                base = ROOT if p.parent == adapter else cmake
                candidate = (candidate if candidate.is_absolute() else base/candidate).resolve(strict=True)
                if not candidate.is_relative_to(output) and candidate not in system_libraries:
                    raise ValueError('actual map introduced unbound external linker input: '+str(candidate))
                prepin=engine_link_inputs.get(str(candidate),adapter_pre.get(str(candidate)))
                if candidate.suffix in ('.obj','.o','.a','.def') and candidate.is_relative_to(output):
                    if prepin is None or guard.pin(candidate,maximum=8*1024**2)!=prepin:
                        raise ValueError('actual LOAD object/archive absent from before-link pins')
                paths.append(str(candidate))
                linked[str(candidate)] = guard.pin(candidate,maximum=256*1024**2,
                    readonly_system_input=str(candidate) in system_input_paths)
            receipt.setdefault('maps',{})[str(p)]={**pin,'actual_LOAD_paths':paths}
        if map_total>8*1024**2:
            raise ValueError('combined map cap')
        receipt['actual_linked_input_pins']=linked
        baseline=json.loads(source_raw['benchmarks/win98se-ko-oem-native-exports-v1.json'])['dlls']
        expected_sspi=sorted(('AcquireCredentialsHandleA','FreeCredentialsHandle','InitializeSecurityContextA',
            'DeleteSecurityContext','QuerySecurityPackageInfoA','EnumerateSecurityPackagesA','FreeContextBuffer',
            'QueryContextAttributesA','EncryptMessage','DecryptMessage','ApplyControlToken','InitSecurityInterfaceA',
            'M98SspiEndInput','ExportSecurityContext','ImportSecurityContextA'))
        receipt['PEs']={}
        decode_total=0;gzip_total=0
        for p in (cmake/'TLS13PROB.exe',cmake/'TIMEPROB.exe',cmake/'M98TLS.dll',dll):
            raw,pe_pin=regular(p,8*1024**2)
            with gate.pefile.PE(data=raw) as pe:
                version=[pe.OPTIONAL_HEADER.MajorSubsystemVersion,pe.OPTIONAL_HEADER.MinorSubsystemVersion]
                imports={}
                for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',()):
                    name=e.dll.decode('ascii').upper()
                    if name in imports or not e.imports:
                        raise ValueError('duplicate/empty actual import descriptor')
                    imports[name]=[s.name.decode('ascii') if s.name else '#'+str(s.ordinal) for s in e.imports]
                missing=[[d,s] for d,names in imports.items() for s in names if s not in baseline.get(d,())]
                forbidden={str(i):[pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress,
                                   pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size] for i in (9,10,13,14)}
                symbols=list(getattr(pe,'DIRECTORY_ENTRY_EXPORT',types.SimpleNamespace(symbols=[])).symbols)
                if p.suffix=='.dll' and (not symbols or any(not s.name or s.forwarder for s in symbols)):
                    raise ValueError('unnamed/forwarded actual DLL export')
                exports=sorted(s.name.decode('ascii') for s in symbols if s.name)
                if len(exports)!=len(set(exports)):
                    raise ValueError('duplicate actual named exports')
                sections=bridge.executable_sections(raw,gate.pefile)
                entry=pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint
                highlow=sum(s.type==3 for row in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',()) for s in row.entries)
                os_version=[pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,pe.OPTIONAL_HEADER.MinorOperatingSystemVersion]
                if (pe.FILE_HEADER.Machine!=0x14c or pe.OPTIONAL_HEADER.Magic!=0x10b or version!=[4,10]
                        or pe.OPTIONAL_HEADER.Subsystem!=2 or pe.FILE_HEADER.TimeDateStamp!=0
                        or pe.is_dll()!=(p.suffix=='.dll') or os_version!=[4,10]
                        or not pe.OPTIONAL_HEADER.AddressOfEntryPoint
                        or not any(s['address']<=entry<s['address']+len(s['bytes']) for s in sections.values())
                        or (p.suffix=='.dll' and highlow==0)
                        or not imports or missing or any(v for row in forbidden.values() for v in row)
                        or (p==dll and exports!=expected_sspi)):
                    raise ValueError('actual current PE/OEM/version/export gate failed: '+p.name)
            layout=script.validate_empty_lifecycle_layout(raw,gate.pefile)
            decoder=stream.StreamDecoder(gate,sections)
            gzpath=output/(p.name+'.disassembly.txt.gz')
            with gzpath.open('xb') as stored:
                with gzip.GzipFile(filename='',fileobj=stored,mode='wb',mtime=0,compresslevel=9) as compressed:
                    def consume(block):
                        try:
                            decoder.feed(block)
                        except stream.DecodeError as error:
                            receipt['actual_decoder_failure_observation']=error.observation
                            raise
                        compressed.write(block)
                        compressed.flush()
                        if stored.tell()>2*1024**2:
                            raise ValueError('individual compressed decoder cap')
                        guard.check(1024*1024)
                    r=guard.run([objdump,'-d','-z','--show-raw-insn','--insn-width=16',str(p)],
                                'decode-'+p.name,cwd=ROOT,timeout=120,stdout_consumer=consume,raw_limit=16*1024**2)
                    if r.returncode or r.stderr:
                        raise ValueError('actual decoder failed/diagnosed')
                    try:
                        report=decoder.finish()
                    except stream.DecodeError as error:
                        receipt['actual_decoder_failure_observation']=error.observation
                        raise
                    if report['artifact_label']!=str(p):
                        raise ValueError('actual decoder preamble differs from exact artifact command')
            decode_total+=report['raw_bytes'];gzip_total+=gzpath.stat().st_size
            if decode_total>64*1024**2 or gzip_total>8*1024**2:
                raise ValueError('combined raw decoder input/compressed output cap')
            if regular(p,8*1024**2)[1]!=pe_pin:
                raise ValueError('PE changed during complete decode')
            receipt['PEs'][p.name]={'artifact':{'path':str(p),**pe_pin},'imports':imports,'exports':exports,
                'missing_OEM_imports':missing,'forbidden_directories':forbidden,'lifecycle':layout,
                'OS_version':os_version,'HIGHLOW_relocations':highlow,'entry_VA':entry,
                'i486_audit':report,'compressed_decode':{'path':str(gzpath),**guard.pin(gzpath,maximum=2*1024**2)}}
        receipt['decoder_input_bytes']=decode_total
        check_scripts()
        for item in receipt['PEs'].values():
            for key in ('artifact','compressed_decode'):
                record=item[key]
                if guard.pin(Path(record['path']),maximum=8*1024**2)!={k:v for k,v in record.items() if k!='path'}:
                    raise ValueError('selected PE/compressed proof changed before final closure')
        for unit in units+adapter_units:
            for key in ('before_M','actual_MD'):
                record=unit[key]
                if guard.pin(Path(record['path']),maximum=65536)!={k:v for k,v in record.items() if k!='path'}:
                    raise ValueError('actual dependency manifest changed before final closure')
        for path,record in receipt['maps'].items():
            if guard.pin(Path(path),maximum=2*1024**2)!={k:v for k,v in record.items() if k!='actual_LOAD_paths'}:
                raise ValueError('actual link map changed before final closure')
        receipt['selected_proof_files_before_after_equal']=True
        receipt['link_script_files_before_after_equal']=True
        for path,pin in source_copies.items():
            if guard.pin(Path(path),maximum=2*1024**2)!=pin:
                raise ValueError('actual frozen production/definition/generated recipe copy changed')
        receipt['source_copies_before']=source_copies
        receipt['source_copies_before_after_equal']=True
        # Close all actual includes/tools/production/upstream before success.
        for path,pin in headers.items():
            if guard.pin(Path(path),maximum=8*1024**2)!=pin:
                raise ValueError('actual header/source changed during compile/link')
        receipt['headers_before_after_equal']=True
        receipt['headers_before']=headers
        for path,pin in generator_pins.items():
            if guard.pin(Path(path),maximum=2*1024**2)!=pin:
                raise ValueError('configured generator input changed during build')
        check_console_graph()
        receipt['Ninja_console_graph_before_after_equal']=True
        receipt['configured_generator_inputs_before_after_equal']=True
        current_system_cmake={str(p):guard.pin(p,maximum=8*1024**2)
            for p in sorted(system_cmake.rglob('*')) if p.is_file()}
        if current_system_cmake!=system_cmake_inputs:
            raise ValueError('direct system CMake module/template closure changed')
        receipt['direct_system_CMake_inputs_before_after_equal']=True
        for path,pin in linked.items():
            if guard.pin(Path(path),maximum=256*1024**2,
                    readonly_system_input=path in system_input_paths)!=pin:
                raise ValueError('actual LOAD linked input changed after audit')
        for path,pin in {**engine_link_inputs,**adapter_pre}.items():
            if guard.pin(Path(path),maximum=8*1024**2)!=pin:
                raise ValueError('before-link object/archive changed before final proof closure')
        for path,pin in receipt['SSPI_retained_inputs_before'].items():
            if guard.pin(Path(path),maximum=8*1024**2)!=pin:
                raise ValueError('bound retained engine object/archive changed during SSPI link')
        for path,pin in tools.items():
            if guard.pin(Path(path),maximum=256*1024**2,
                    readonly_system_input=path in system_input_paths)!=pin:
                raise ValueError('actual selected tool/library/parser changed')
        receipt['tool_inputs_before_after_equal']=True
        for path,pin in quiescent_pins.items():
            if guard.pin(Path(path),maximum=quiescent_controls.FIXTURE_BYTES_LIMIT)!=pin:
                raise ValueError('actual closed quiescent control proof changed during build')
        if guard.capture_bytes>resources.CAPTURE_LIMIT or guard.decoder_bytes>resources.DECODER_LIMIT:
            raise ValueError('final actual parent capture/raw pools exceeded unchanged limits')
        receipt['quiescent_control_proof_files_before_after_equal']=True
        for relative,pin in source_pins.items():
            if regular(ROOT/relative,2*1024**2)[1]!=pin:
                raise ValueError('original source/helper changed')
        receipt['source_inputs_after_equal']=True
        if upstream_snapshot(prep,expected_preparation_sha)[1]!=upstream:
            raise ValueError('full prepared original source changed')
        receipt['upstream_before_after_equal']=True
        receipt['compiled_outputs']={str(p.relative_to(output)):guard.pin(p,maximum=8*1024**2)
            for p in sorted(output.rglob('*')) if p.is_file() and p.suffix in ('.a','.obj','.o','.map','.ld','.rsp')}
        receipt['recipe_changes']=['explicit gcc-win32 backend','separate original upstream input',
            'explicit selected windres/ar/ranlib paths',
            'exact literal CMake recipe copied without original helper execution','GEN_FILES explicitly OFF',
            'Ninja keepdepfile/keeprsp','SSPI TU object split with original flags/order',
            'Ninja objects/archives/final-links scheduled separately for before-link content pins',
            'sequential one graph object, dependency-ordered archive or PE target per command with jobs=1',
            'literal console compile/link pools verified on all135 actual selected Ninja writers plus manifest regeneration edge',
            'readonly lifecycle linker script and -t trace','bounded full-stream ISA framing']
        receipt['result']='PASS_CURRENT_NATIVE_TLS_SSPI_BUILD_ONLY'
    except BaseException as error:
        receipt['result']='FAIL'
        receipt['error']=str(error)[:2048]
        raise
    finally:
        try:
            try:
                compact_tu_headers(receipt)
            except (ValueError,KeyError,TypeError) as error:
                receipt['result']='FAIL'
                receipt['TU_header_compaction_error']=str(error)[:2048]
            closed=guard.close_receipt(receipt,output/'result.json')
            print('Current TLS build receipt SHA256:',closed['sha256'])
            print(json.dumps({k:closed[k] for k in ('result','bytes')}))
            if closed['result']!='PASS_CURRENT_NATIVE_TLS_SSPI_BUILD_ONLY':
                raise RuntimeError('counted TLS receipt is not a build PASS')
        finally:
            guard.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prep',type=Path,required=True)
    parser.add_argument('--prepare-upstream',action='store_true')
    parser.add_argument('--output-root',type=Path)
    parser.add_argument('--expected-preparation-sha256')
    args=parser.parse_args()
    if args.prepare_upstream:
        if args.output_root:
            parser.error('prep and counted build are separate phases')
        prepare(args.prep.absolute())
    else:
        if args.output_root is None:
            parser.error('new counted output root required')
        if not args.expected_preparation_sha256:
            parser.error('actual freshly prepared manifest SHA256 required')
        build(args.output_root.absolute(),args.prep.absolute(),args.expected_preparation_sha256)


if __name__=='__main__':
    main()
