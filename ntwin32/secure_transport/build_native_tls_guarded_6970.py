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
NEW_HELPERS = ('native_tls_resources_6970.py', 'i486_stream_6970.py')
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
    if guard:
        guard.check()
    return module


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
                       '-DCMAKE_MAKE_PROGRAM=' + ninja, '-DGEN_FILES=OFF'], 'cmake-configure', timeout=120)
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
        r = guard.run([ninja,'-C',str(cmake),'-j','2','-d','keepdepfile','-d','keeprsp',
                       *(unit['target'] for unit in units)], 'cmake-production-objects', timeout=360)
        if r.returncode:
            raise ValueError('actual CMake/Ninja compile failed')
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
        r=guard.run([cmake_tool,'--build',str(cmake),'--parallel','2','--target',
                     'ntwst','mbedtls','mbedx509','mbedcrypto','everest','p256m','--',
                     '-d','keepdepfile','-d','keeprsp'],'cmake-production-archives',timeout=120)
        if r.returncode:
            raise ValueError('production archive generation failed')
        engine_link_inputs={unit['object']:unit['object_pin'] for unit in units}
        engine_link_inputs[str(project/'native.def')]=source_copies[str(project/'native.def')]
        for p in sorted(cmake.rglob('*.a')):
            engine_link_inputs[str(p)]=guard.pin(p,maximum=8*1024**2)
        check_scripts()
        r=guard.run([cmake_tool,'--build',str(cmake),'--parallel','2','--',
                     '-d','keepdepfile','-d','keeprsp'],'cmake-final-links',timeout=120)
        if r.returncode:
            raise ValueError('actual engine final links failed')
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
        for relative,pin in source_pins.items():
            if regular(ROOT/relative,2*1024**2)[1]!=pin:
                raise ValueError('original source/helper changed')
        receipt['source_inputs_after_equal']=True
        if upstream_snapshot(prep,expected_preparation_sha)[1]!=upstream:
            raise ValueError('full prepared original source changed')
        receipt['upstream_before_after_equal']=True
        receipt['compiled_outputs']={str(p.relative_to(output)):guard.pin(p,maximum=8*1024**2)
            for p in sorted(output.rglob('*')) if p.is_file() and p.suffix in ('.a','.obj','.o','.map','.ld','.rsp')}
        # TU references use indices into lexical header keys, not repeated paths.
        # Actual -M/-MD files remain separately retained and hashed.
        header_index={path:i for i,path in enumerate(sorted(headers))}
        receipt['TU_header_index_order']='lexicographic_headers_before_path_keys'
        for key in ('CMake_actual_TU_dependencies','SSPI_actual_TU_dependencies'):
            receipt[key]=[{**{k:v for k,v in unit.items() if k!='headers'},
                           'header_indices':[header_index[path] for path in unit['headers']]}
                          for unit in receipt[key]]
        receipt['recipe_changes']=['explicit gcc-win32 backend','separate original upstream input',
            'explicit selected windres/ar/ranlib paths',
            'exact literal CMake recipe copied without original helper execution','GEN_FILES explicitly OFF',
            'Ninja keepdepfile/keeprsp','SSPI TU object split with original flags/order',
            'Ninja objects/archives/final-links scheduled separately for before-link content pins',
            'readonly lifecycle linker script and -t trace','bounded full-stream ISA framing']
        receipt['result']='PASS_CURRENT_NATIVE_TLS_SSPI_BUILD_ONLY'
    except BaseException as error:
        receipt['result']='FAIL'
        receipt['error']=str(error)[:2048]
        raise
    finally:
        try:
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
