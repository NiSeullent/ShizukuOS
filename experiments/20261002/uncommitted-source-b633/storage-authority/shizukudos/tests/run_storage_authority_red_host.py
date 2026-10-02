#!/usr/bin/env python3
"""Prepare/observe actual baseline blk/VFS behavioral REDs; never storage authority.

Execution requires ROOT checked entry plus an exact independent preparation
review. This source authoring epoch does not execute this driver or its helper.
"""
from pathlib import Path
import hashlib

_captured = globals().get('__captured_native_driver_bytes__')
if not isinstance(_captured, bytes) or Path(__file__).read_bytes() != _captured:
    raise RuntimeError('ROOT checked entry must inject the exact driver buffer')

import argparse
import ast
import ctypes
import json
import os
import re
import resource
import shlex
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_ROOT = Path('/dev/shm/Win98-Modern-native-storage-163f-20261002')
PREP = ROOT / 'build/prepare-native-storage-authority-red-host-163f'
FAMILY = Path('/dev/shm/native-storage-authority-red-host-163f-20261002')
BASE = 'f3153aa8fd98b582118503fa8eae18f83fe1e28c'
OWNER_SHA = 'adcf9a70767541d6fdeb47146bce72f3e3e349a05595d539091d2a7627e2fe4f'
DECISION = 'APPROVE_STORAGE_AUTHORITY_BASELINE_RED_HOST_PREPARATION'
CAP = 64 << 20
FLAGS = ['-std=gnu11', '-O1', '-g', '-fno-omit-frame-pointer', '-Wall', '-Wextra', '-Werror']
RED = {
    'red-sfs-busy': ['sfs-whole-raw-busy', 'sfs-part-raw-busy'],
    'red-mounted-reset': ['mounted-reset-refused', 'mounted-reset-backend-not-called'],
    'red-global-reset': ['global-reset-refused', 'global-reset-backend-not-called'],
}
CONTROL = ['legacy-unmounted', 'fat-internal', 'sfs-internal', 'readonly-range',
           'partition-forwarding', 'async-fallback', 'async-inline', 'async-deferred',
           'mount-rollback', 'vfs-shutdown', 'registry']
PROJECT = ['shizukudos/kernel64/' + name for name in
           ('blk.c', 'blk.h', 'blk_part.h', 'vfs_mounts.c', 'vfs_mounts.h', 'fs.h',
            'k64.h', 'proc_internal.h')]
FIXTURE = 'shizukudos/tests/test_storage_authority_red_host.c'
SELF = 'shizukudos/tests/run_storage_authority_red_host.py'
OWNER = 'shizukudos/tests/test_k32_memory_concurrency.py'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def read_pin(path, expected):
    data = Path(path).read_bytes()
    require(sha(data) == expected, 'input drift: ' + str(path))
    return data


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def owned_ok(raw, code=0):
    cleanup = raw['cleanup']
    return (raw['exit_code'] == raw['parent_exit_code'] == code and
            not raw['timed_out'] and raw['infrastructure_error'] is None and
            cleanup['passed'] and cleanup['direct_reaped'] and
            cleanup['group_empty'] and cleanup['drain_complete'])


def literal_chunks(blk, vfs):
    """Whole, byte-exact baseline intervals, not a replacement policy model."""
    records = []

    def take(data, origin, begin, end):
        require(data.count(begin) == data.count(end) == 1, 'ambiguous source boundary')
        first, last = data.index(begin), data.index(end)
        require(first < last, 'source boundary order')
        value = data[first:last]
        records.append({'origin': origin, 'offset': first, 'bytes': len(value),
                        'sha256': sha(value), 'end_excluded': end.decode('ascii')})
        return value

    registry = take(blk, PROJECT[0], b'static blk_dev_t *head, *tail;\n',
                    b'static blk_dev_t parts[BLK_MAX_DEVICES];')
    body = take(blk, PROJECT[0], b'int blk_register(blk_dev_t *d)\n',
                b'uint64_t blk_kva_to_pa(const void *kva)\n')
    partition = take(blk, PROJECT[0], b'static int part_read(',
                     b'static blk_dev_t *add_partition(')
    include = b'#include "vfs_mounts.h"\n'
    require(vfs.count(include) == 1, 'actual VFS include boundary')
    start = vfs.index(include) + len(include)
    tail = vfs[start:]
    records.append({'origin': PROJECT[3], 'offset': start, 'bytes': len(tail),
                    'sha256': sha(tail), 'end_excluded': 'EOF'})
    return registry + body + partition, tail, records


def main():
    require(ROOT == EXPECTED_ROOT, 'exact isolated source worktree required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--readiness', type=Path, required=True)
    parser.add_argument('--readiness-sha256', required=True)
    parser.add_argument('--cc', choices=['gcc', 'clang'], required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(args.manifest.resolve() == PREP / 'manifest.json', 'exact baseline manifest required')
    mb = read_pin(args.manifest, args.manifest_sha256)
    rb = read_pin(args.readiness, args.readiness_sha256)
    m, review = json.loads(mb), json.loads(rb)  # parse the SAME hashed buffers
    require(m['schema'] == 'STORAGE_AUTHORITY_BASELINE_RED_HOST_PREPARATION_V1' and
            m['state'] == 'SOURCE_PREPARATION_FOR_INDEPENDENT_REVIEW' and
            m['executed'] is False and m['future_authority_candidate'] is None,
            'baseline preparation only; no future provider substitution')
    require(m['source_head'] == BASE and m['driver_sha256'] == sha(_captured) and
            m['owner_sha256'] == OWNER_SHA and m['host_flags'] == FLAGS and
            m['red_assertions'] == RED and m['controls'] == CONTROL,
            'exact unchanged baseline/fixtures/flags required')
    require(m['ceiling_bytes'] == CAP and m['work_seconds'] == 30 and m['cleanup_seconds'] == 2,
            'finite unchanged process/output bounds required')
    require(review.get('decision') == DECISION and review.get('findings') == [] and
            review.get('manifest_sha256') == args.manifest_sha256 and
            review.get('driver_sha256') == sha(_captured) and
            review.get('fixture_sha256') == m['fixture_sha256'] and
            review.get('owner_sha256') == OWNER_SHA,
            'independent review must bind actual prepared buffers')
    mandatory = set(PROJECT + [FIXTURE, SELF, OWNER])
    require(set(m['source_sha256']) == mandatory, 'complete exact local source map required')
    require(all(not Path(rel).is_absolute() and '..' not in Path(rel).parts
                for rel in m['source_sha256']), 'bounded relative local sources')
    require(set(m['source_captures']) == mandatory and
            all(not Path(rel).is_absolute() and '..' not in Path(rel).parts
                for rel in m['source_captures'].values()), 'bounded exact capture map required')
    source_buffers = {rel: read_pin(ROOT / rel, pin) for rel, pin in m['source_sha256'].items()}
    require(sha(source_buffers[FIXTURE]) == m['fixture_sha256'] and
            source_buffers[SELF] == _captured and sha(source_buffers[OWNER]) == OWNER_SHA,
            'loaded fixture/helper/driver must match actual captured source')
    for rel, pin in m['source_sha256'].items():
        require(read_pin(PREP / m['source_captures'][rel], pin) == source_buffers[rel], 'capture differs from origin')
    require(m['compiler_dependency_text'].get('/usr/lib/clang/21/share/asan_ignorelist.txt') ==
            'f0180e94133315446c6e45287e1801e70ea94de1905a237c974627a732ebeadc',
            'actual Clang ASan dependency text must be presealed')
    for key, expected in m['compiler_environment'].items():
        require(os.environ.get(key) == expected, 'initial compiler environment drift: ' + key)
    origin_pins = {str(ROOT / rel): pin for rel, pin in m['source_sha256'].items()}
    origin_pins.update({str(PREP / m['source_captures'][rel]): pin for rel, pin in m['source_sha256'].items()})
    origin_pins.update({str(args.manifest.resolve()): sha(mb), str(args.readiness.resolve()): sha(rb)})
    external = {}
    for field in ('tools', 'python_runtime', 'external_runtime', 'system_headers', 'compiler_dependency_text'):
        require(m[field], 'empty external foundation: ' + field)
        for path, pin in m[field].items():
            require(Path(path).is_absolute() and re.fullmatch('[0-9a-f]{64}', pin), 'absolute pinned foundation required')
            require(path not in external or external[path] == pin, 'conflicting foundation pin')
            external[path] = pin
    require(str(Path(sys.executable).resolve()) in m['tools'] and
            m['git_path'] in m['tools'] and m['compilers'][args.cc] in m['tools'],
            'actual selected executables required')
    before = {**origin_pins, **external}
    require(all(file_sha(path) == pin for path, pin in before.items()), 'pre-helper input/tool/header drift')
    out = args.out.resolve()
    require(out.parent == FAMILY and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}', out.name) and
            not out.exists(), 'fresh direct RAM-family leaf required')
    require(not any(p.is_symlink() for p in (args.out, *args.out.parents)), 'no symlink output ancestry')
    require(sum(map(len, source_buffers.values())) + (16 << 20) < CAP, 'pre-output source admission budget')

    # Local output only; all original input/helper/tool bytes already captured.
    out.mkdir(parents=True)
    source = out / 'source'; source.mkdir()
    tmp = out / 'tmp'; tmp.mkdir()
    previous_tmp = os.environ.get('TMPDIR')
    os.environ['TMPDIR'] = str(tmp)  # own runner environment, never client-global
    commands, dependencies, scenarios = [], [], []
    result = {'status': 'FAIL', 'classification': 'ADMISSION_OR_INFRASTRUCTURE_FAILURE',
              'scope': 'actual unchanged blk/VFS C with typed memory-only dependencies',
              'source_head': BASE, 'compiler': args.cc, 'driver_sha256': sha(_captured),
              'manifest_sha256': sha(mb), 'readiness_sha256': sha(rb),
              'fixture_sha256': m['fixture_sha256'], 'owner_sha256': OWNER_SHA,
              'inputs_sha256_before': before, 'commands': commands, 'dependencies': dependencies,
              'scenarios': scenarios, 'error': None, 'ceiling_bytes': CAP,
              'work_seconds': 30, 'cleanup_seconds': 2, 'guest_executed': False,
              'physical_device_executed': False, 'authority_granted': False,
              'Windows98_verified': False, 'SMP_acceptance': False,
              'external_toolchain_fully_sealed': False,
              'project_buffers_captured_before_helper_execution': True}
    generated, consumer_dependencies = {}, {}

    def amount():
        return sum(p.stat().st_size for p in out.rglob('*') if p.is_file())

    def stable():
        require(amount() < CAP, 'observed aggregate64MiB output ceiling')
        pins = {**origin_pins, **m['tools'], **m['python_runtime'],
                **m['external_runtime'], **consumer_dependencies, **generated}
        require(all(file_sha(path) == pin for path, pin in pins.items()), 'input/generated/tool drift')
        for key, expected in m['compiler_environment'].items():
            require(os.environ.get(key) == (str(tmp) if key == 'TMPDIR' else expected), 'compiler environment drift: ' + key)

    def put(relative, data):
        dest = source / relative; dest.parent.mkdir(parents=True, exist_ok=True)
        require(amount() + len(data) + (1 << 20) < CAP, 'generated input ceiling')
        dest.write_bytes(data); generated[str(dest)] = sha(data)
        return dest

    try:
        for rel in PROJECT:
            put('project/' + rel, source_buffers[rel])
        fixture = put('fixture.c', source_buffers[FIXTURE])
        put('executed-owner.py', source_buffers[OWNER])
        put('executed-driver.py', _captured)
        put('manifest.json', mb)
        put('readiness.json', rb)
        blk, vfs, slices = literal_chunks(source_buffers[PROJECT[0]], source_buffers[PROJECT[3]])
        require(slices == m['literal_slices'], 'exact prospective production-slice record required')
        put('production_blk.inc', blk); put('production_vfs.inc', vfs)
        write_json(out / 'before-helper.json', {'project_captured_before_execution': True,
                   'original_sources_sha256': m['source_sha256'], 'generated_sha256': generated,
                   'literal_slices': slices, 'helper_sha256': OWNER_SHA})
        # Only these two actual adcf functions execute, from the SAME pinned buffer.
        tree = ast.parse(source_buffers[OWNER], filename=str(ROOT / OWNER))
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                 n.name in ('group_members', 'run_owned')]
        require({n.name for n in nodes} == {'group_members', 'run_owned'} and len(nodes) == 2,
                'actual owned-process helper extraction')
        owner = {'Path': Path, 'ctypes': ctypes, 'os': os, 'signal': signal,
                 'subprocess': subprocess, 'time': time, 'CLEANUP_SECONDS': 2.0}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ROOT / OWNER), 'exec'), owner)

        def run(argv, label):
            argv = list(map(str, argv)); executable = str(Path(argv[0]).resolve())
            require(executable in m['tools'] or executable in generated, 'unbound executable')
            stable(); remain = CAP - amount()
            require(remain > (2 << 20), 'per-command observed output admission')
            prior = resource.getrlimit(resource.RLIMIT_FSIZE)
            finite = [value for value in prior if value != resource.RLIM_INFINITY]
            resource.setrlimit(resource.RLIMIT_FSIZE, (min([remain - (1 << 20), *finite]), prior[1]))
            try:
                raw = owner['run_owned'](argv, timeout=30)
            finally:
                resource.setrlimit(resource.RLIMIT_FSIZE, prior)
            row = {'label': label, 'executed_file_sha256': file_sha(executable), **raw}
            commands.append(row); write_json(out / (label + '.owned.json'), row)
            stable()
            lifecycle = (not raw['timed_out'] and raw['infrastructure_error'] is None and
                         raw['cleanup']['passed'] and raw['cleanup']['group_empty'] and
                         raw['cleanup']['direct_reaped'] and raw['cleanup']['drain_complete'])
            if not lifecycle:
                result['classification'] = 'ADMISSION_OR_INFRASTRUCTURE_FAILURE'
            require(lifecycle, 'owned command lifecycle failure: ' + label)
            return raw

        identity = run([m['git_path'], '-C', ROOT, 'rev-parse', 'HEAD'], 'source-head')
        require(owned_ok(identity) and identity['stdout'].strip() == BASE, 'baseline HEAD changed')
        names = run([m['git_path'], '-C', ROOT, 'ls-files', '-z'], 'source-inventory')
        require(owned_ok(names) and set(names['stdout'].split('\0')) - {''} == set(m['tracked_paths']),
                'baseline tracked inventory changed')
        cc = m['compilers'][args.cc]
        flags = FLAGS + (['-fsanitize=address,undefined'] if args.cc == 'clang' else []) + ['-I', str(source)]
        executable = out / 'storage-red-host'
        consumer = [cc, *flags, str(fixture), '-o', str(executable)]
        depfile = out / 'host.d'
        dependency_argv = consumer[:-2] + ['-M', '-MF', str(depfile)]
        dr = run(dependency_argv, 'actual-dependencies')
        require(owned_ok(dr) and not dr['stderr'] and depfile.is_file(), 'actual-M admission failed')
        depbytes = depfile.read_bytes()
        values = shlex.split(depbytes.decode().replace('\\\n', ' ').partition(':')[2])
        require(values and len(values) == len(set(values)), 'actual-M nonempty unique closure')
        for name in values:
            path = str(Path(name).resolve())
            expected = generated.get(path, before.get(path))
            require(expected is not None and file_sha(path) == expected, 'unsealed actual compiler dependency: ' + path)
            consumer_dependencies[path] = expected
        generated[str(depfile)] = sha(depbytes)
        dependencies.append({'consumer_argv': consumer, 'dependency_argv': dependency_argv,
                             'dependency_sha256': sha(depbytes), 'inputs_sha256': dict(consumer_dependencies),
                             'captured_before_consumer': True, 'identical_flags_except_output_and_M': True})
        compiled = run(consumer, 'compile-host')
        require(owned_ok(compiled) and not compiled['stderr'] and executable.is_file(), 'host compile/link admission failed')
        generated[str(executable)] = file_sha(executable)
        result['classification'] = 'BEHAVIORAL_OBSERVATIONS'
        pattern = re.compile(r'^STORAGE_AUTHORITY_RED_HOST scenario=([^ ]+) checks=(\d+) failures=(\d+) reset0=(\d+) reset1=(\d+) mounts=(\d+) irq_depth=(\d+)$', re.M)
        for scenario in [*RED, *CONTROL]:
            raw = run([executable, scenario], 'run-' + scenario)
            rows = pattern.findall(raw['stdout'])
            require(len(rows) == 1 and rows[0][0] == scenario and int(rows[0][1]) >= 5 and rows[0][6] == '0',
                    'malformed/duplicate fixture summary: ' + scenario)
            labels = raw['stderr'].splitlines()
            if scenario in RED:
                expected = ['ASSERT ' + label for label in RED[scenario]]
                accepted = owned_ok(raw, 1) and labels == expected and int(rows[0][2]) == len(expected)
                observation = {'red-sfs-busy': ('0', '0', '1'),
                               'red-mounted-reset': ('1', '0', '0'),
                               'red-global-reset': ('0', '1', '0')}
                accepted = accepted and rows[0][3:6] == observation[scenario]
                classification = 'EXPECTED_ACTUAL_PRODUCTION_BEHAVIOR_RED'
            else:
                accepted = owned_ok(raw) and not labels and rows[0][2] == '0'
                classification = 'LEGACY_POSITIVE_CONTROL'
            scenarios.append({'scenario': scenario, 'classification': classification,
                              'accepted': accepted, 'summary': rows[0], 'failing_assertions': labels})
            require(accepted, 'unexpected production behavior or fixture failure: ' + scenario)
        stable()
        result['status'] = 'BASELINE_BEHAVIORAL_RED_CONFIRMED'
        result['classification'] = 'THREE_EXPECTED_BEHAVIOR_RED_AND_ELEVEN_LEGACY_CONTROLS'
    except BaseException as error:
        result['status'] = 'FAIL'; result['error'] = repr(error)
    finally:
        terminal, drift = {}, {}
        for path, expected in {**before, **generated, **consumer_dependencies}.items():
            try:
                actual = file_sha(path); terminal[path] = actual
                if actual != expected: drift[path] = 'SHA256 drift'
            except OSError as error:
                drift[path] = repr(error)
        result['inputs_sha256_after'] = {path: terminal.get(path) for path in before}
        result['input_maps_equal'] = result['inputs_sha256_after'] == before
        result['generated_inputs_sha256'] = generated
        result['terminal_pin_errors'] = drift
        if drift:
            result['status'] = 'FAIL'; result['error'] = 'terminal input/tool/dependency/generated drift'
        result['inventory_before_result'] = {str(p.relative_to(out)): {'sha256': file_sha(p), 'bytes': p.stat().st_size}
                                            for p in sorted(out.rglob('*')) if p.is_file()}
        result['observed_bytes_before_result'] = amount()
        data = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
        if amount() + len(data) + (1 << 20) >= CAP:
            result['status'] = 'FAIL'; result['error'] = 'terminal observed output ceiling exhausted'
            result['commands'] = [{'label': row['label'], 'argv': row['argv'], 'exit_code': row['exit_code'],
                                   'timed_out': row['timed_out'], 'cleanup': row['cleanup']} for row in commands]
        write_json(out / 'result.json', result)
        seal = {'result_sha256': file_sha(out / 'result.json'),
                'artifact_sha256': {str(p.relative_to(out)): file_sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
                'ceiling_bytes': CAP, 'scope': 'host baseline RED only; no native storage grant'}
        write_json(out / 'seal.json', seal)
        if previous_tmp is None: os.environ.pop('TMPDIR', None)
        else: os.environ['TMPDIR'] = previous_tmp
        require(amount() < CAP, 'actual terminal lane exceeds observed ceiling; no quota claimed')
    print(result['status'])
    return int(result['status'] != 'BASELINE_BEHAVIORAL_RED_CONFIRMED')


if __name__ == '__main__':
    raise SystemExit(main())
