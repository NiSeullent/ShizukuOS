#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict, read-only closure for one frozen numeric WAMR guest generation.

No build/scanner script is imported or executed. The saved complete objdump
listing is replayed against actual PE executable bytes and literal scanner data.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import pefile

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path('/root/Win98-Modern-boot/build')
PREFIX = 'C:\\GOPLAB\\'
PROFILE = dict(self=PREFIX + 'M98WARUN.EXE', supervisor_log=PREFIX + 'WARUN.LOG',
    child_stdout=PREFIX + 'WAOUT.LOG', child=PREFIX + 'WAS13PR.EXE',
    child_log=PREFIX + 'WA13.LOG', child_timeout_ms=60000, reap_timeout_ms=5000)
INPUTS = frozenset(('M98WASM.DLL', 'WAS13PR.EXE', 'M98WARUN.EXE'))
OUTPUTS = frozenset(('WA13.LOG', 'WARUN.LOG', 'WAOUT.LOG'))
RECEIPTS = frozenset(('runtime-build.json', 'probe-build.json', 'observer-build.json'))
APPROVED = {
    'runtime-build.json': '26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91',
    'probe-build.json': '8db17f7ec0db13f2b265617c66755621661b9c16ac3431d0d901b10783fe8629',
    'observer-build.json': 'c94de5b5458ab9f1945e4f8421c425c9d1422a62b9b9fb57e3200a2c9eae0c18',
}
BUILD_DIRS = {'runtime-build.json': 'wasm-runtime-v24',
    'probe-build.json': 'wasm-native-probe-v6', 'observer-build.json': 'wasm-native-observer-v3'}
SOURCE_DIR = 'build/wasm-runtime-sources-v3'
GATE_SHA = '6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973'
NONCE = 'wasm-numeric-5abe-20261001-v5'
MAX_MEMBER = 64 << 20
MAX_STAGE = 128 << 20
MAX_MEMBERS = 4096
STAGE_SOURCES = (
    'tools/wasm_native_stage_evidence.py', 'tools/stage_wasm_native.py',
    'tests/test_wasm_native_stage.py', 'docs/TRIDENT_WASM_NATIVE_STAGE.md',
    'tools/wasm_native_log.py', 'tools/verify_wasm_native.py',
    'tools/css_mshtml_native_log.py', 'tools/verify_trident_automation_native.py',
    'tests/test_wasm_native_log.py', 'tests/test_wasm_native_acceptance.py',
)
EXPORTS = sorted(('m98_wasm_' + name) for name in ('open', 'close', 'load', 'unload',
    'instantiate', 'instance_close', 'call', 'memory_size', 'memory_grow',
    'memory_read', 'memory_write', 'inspect'))
SOURCE_SETS = {
 'runtime-build.json': frozenset(('src/m98_wasm.h', 'src/m98_wasm.c',
    'src/m98_wasm_math.h', 'src/m98_wasm_math.c', 'src/m98_wasm_platform_internal.h',
    'src/m98_wasm_platform.c', 'tests/m98_wasm_host.c', 'tests/m98_wasm_native_gate.c',
    'tools/build_wasm_runtime.py', 'docs/TRIDENT_WASM_RUNTIME.md',
    'benchmarks/win98se-ko-oem-native-exports-v1.json', 'LICENSE',
    'tools/i486_instruction_gate.py', 'tests/test_i486_instruction_gate.py')),
 'probe-build.json': frozenset(('tests/m98_wasm_guest.c', 'tests/m98_wasm_guest_HANDOFF.md',
    'tools/build_wasm_guest.py', 'src/m98_wasm.h', 'tools/i486_instruction_gate.py',
    'tests/test_i486_instruction_gate.py', 'benchmarks/win98se-ko-oem-native-exports-v1.json')),
 'observer-build.json': frozenset(('tests/m98_wasm_guest_runner.c',
    'tests/m98_wasm_guest_runner_mock.c', 'tests/m98_tls13_guest_runner_mock.h',
    'tools/build_wasm_guest_runner.py', 'tools/i486_instruction_gate.py',
    'tests/test_i486_instruction_gate.py', 'docs/TRIDENT_WASM_NATIVE_OBSERVER.md',
    'benchmarks/win98se-ko-oem-native-exports-v1.json')),
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'SHA-256 pin required')
    return value


def relative(value):
    need(isinstance(value, str) and value and len(value) <= 1024 and '\\' not in value,
         'bounded POSIX relative member required')
    path = Path(value)
    need(not path.is_absolute() and str(path) == value and
         all(p not in ('', '.', '..') for p in value.split('/')), 'noncanonical relative member')
    return path


def canonical(path, exists=True):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)) and
         path.resolve(strict=exists) == path, 'canonical path without symlink required: ' + str(path))
    return path


def read(path, limit=MAX_MEMBER):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
             'bounded regular evidence required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        now = path.stat(follow_symlinks=False)
        attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(path.resolve(strict=True) == path and len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) ==
             getattr(now, k) for k in attributes), 'evidence changed while reading')
        return data
    finally:
        os.close(fd)


def json_data(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON number: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def receipt(path, expected, limit=16 << 20):
    data = read(path, limit)
    need(sha(data) == pin(expected), 'receipt hash differs')
    result = json_data(data)
    need(isinstance(result, dict), 'JSON object required')
    return result


class Closure:
    """Address the same original paths directly or through their frozen copies."""
    def __init__(self, stage=None):
        self.stage = stage
        self.copies = {}
        self.checked = {}
        self.current = {}
        self.total = 0

    def take(self, path, expected=None, size=None, limit=MAX_MEMBER):
        path = Path(path)
        need(path.is_absolute() and path.is_relative_to(ROOT) and
             str(path) == os.path.normpath(str(path)), 'owned canonical source required')
        member = 'evidence/' + str(relative(str(path.relative_to(ROOT))))
        actual = path if self.stage is None else self.stage / member
        data = read(actual, limit)
        digest = sha(data)
        need(expected is None or digest == pin(expected), 'closure input changed: ' + str(path))
        need(size is None or type(size) is int and size == len(data), 'closure input size differs')
        need(member not in self.copies or self.copies[member] == (path, digest),
             'conflicting evidence generation')
        if member not in self.copies:
            self.total += len(data)
        self.copies[member] = (path, digest)
        self.checked[str(actual)] = digest
        need(len(self.copies) <= MAX_MEMBERS and self.total <= MAX_STAGE,
             'complete stage closure exceeds bound')
        return data

    def alias(self, name, path, expected):
        relative(name)
        need(name not in self.copies, 'duplicate staged alias')
        data = self.take(path, expected)
        self.total += len(data)
        self.copies[name] = (path, expected)
        need(self.total <= MAX_STAGE, 'complete stage closure exceeds bound')
        if self.stage is not None:
            need(sha(read(self.stage / name)) == expected, 'frozen input/receipt alias differs')
            self.checked[str(self.stage / name)] = expected

    def unchanged(self):
        for path, expected in (self.checked | self.current).items():
            need(sha(read(Path(path))) == expected, 'late closure drift: ' + path)


def host_oracle(data):
    need(isinstance(data, bytes) and 0 < len(data) <= 65536 and data.endswith(b'\r\n'),
         'bounded complete host numeric log required')
    rows = data[:-2].decode('ascii').split('\r\n')
    need(rows[:2] == ['SCOPE=actual-host-engine-guest-oracles', 'NATIVE_EXECUTION=0'] and
         rows[-3:] == ['CHECKS=244', 'FAILURES=0', 'STATUS=PASS'] and len(rows) == 249,
         'exact actual 244-check host profile required')
    need(all(re.fullmatch('CHECK:[a-z0-9_]{1,96}=1', row) for row in rows[2:-3]),
         'host numeric failure/partial check')
    return data


def engine_configuration(runtime, logs):
    """Recheck each saved actual preprocessor result, not just its receipt label."""
    configured = runtime.get('effective_engine_config')
    need(isinstance(configured, dict) and set(configured) == {'host', 'sanitizer', 'native'},
         'all three real engine preprocessor profiles required')
    for label in ('host', 'sanitizer', 'native'):
        rows = re.findall(r'^#define (WASM_[A-Z0-9_]+)[ \t]+([^\r\n]+)$',
                          logs[('runtime-build.json', label + '-effective-engine-config')].decode('ascii'), re.M)
        actual = dict(rows)
        need(len(rows) == len(actual) == 114 and actual == configured[label] and
             all(actual.get(k) == str(v) for k, v in runtime['config'].items() if k.startswith('WASM_')),
             'actual engine feature macro/count drift')
    crt = runtime['native_crt_profile']
    required = {'__USE_MINGW_ANSI_STDIO': '0', 'PRId64': '"I64d"', 'PRIi64': '"I64i"',
                'PRIu64': '"I64u"', 'PRIx64': '"I64x"', 'PRIX64': '"I64X"'}
    output = logs[('runtime-build.json', 'native-original-crt-macros')].decode('ascii')
    for name, value in required.items():
        need(re.findall(r'^#define ' + name + r'[ \t]+([^\r\n]+)$', output, re.M) == [value],
             'actual original-CRT numeric macro differs')
    need(crt.get('compiler_derived_macros') == required and
         crt.get('dynamic_symbols') == {'MSVCRT.DLL': ['_vsnprintf']} and
         crt.get('system_path_check_implemented') is True and
         crt.get('native_dynamic_resolution_tested') is False, 'original-CRT scope/profile differs')


def policy(data):
    """Only literal sets/strings are interpreted; no imported foreign code."""
    need(sha(data) == GATE_SHA, 'unapproved i486 scanner policy')
    result = {}
    for node in ast.parse(data).body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and
                isinstance(node.targets[0], ast.Name)):
            continue
        name = node.targets[0].id
        if name not in ('BASE', 'X87', 'PREFIX', 'EXACT', 'SUFFIXABLE'):
            continue
        need(name not in result, 'duplicate literal policy')
        if isinstance(node.value, ast.Set):
            value = ast.literal_eval(node.value)
        else:
            strings = [n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant)
                       and isinstance(n.value, str)]
            need(len(strings) == 1, 'nonliteral policy string')
            value = set(strings[0].split())
        need(isinstance(value, set) and all(isinstance(v, str) for v in value), 'literal policy type')
        result[name] = value
    need(len(result) == 5, 'missing literal policy')
    return result


def raw_gate(binary, raw, item, table, expected_exports, stack_commit, installed):
    """Check saved decoder bytes against every actual executable VirtualSize."""
    need(0 < len(binary) <= 1 << 20 and isinstance(raw, bytes) and 0 < len(raw) <= MAX_MEMBER,
         'bounded actual PE/decode required')
    machine = item.get('i486_instructions', {})
    need(item.get('pe98_gate') == 'pass' and item.get('sha256') == sha(binary) and
         item.get('bytes', item.get('size')) == len(binary) and
         machine.get('artifact_sha256') == sha(binary) and machine.get('artifact_bytes') == len(binary)
         and machine.get('disassembly_sha256') == sha(raw), 'actual artifact/decode pin differs')
    try:
        pe = pefile.PE(data=binary)
    except pefile.PEFormatError as error:
        raise ValueError('malformed actual PE') from error
    try:
        h = pe.OPTIONAL_HEADER
        need(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and
             pe.is_dll() == bool(expected_exports) and h.AddressOfEntryPoint and
             pe.FILE_HEADER.TimeDateStamp == 0, 'actual deterministic x86 PE required')
        need((h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion,
              h.MajorSubsystemVersion, h.MinorSubsystemVersion, h.Subsystem) == (4, 10, 4, 10, 2),
             'Win98 4.10 loader/subsystem required')
        need((h.SizeOfStackReserve, h.SizeOfStackCommit) == (2097152, stack_commit) and
             not h.DllCharacteristics & (0x40 | 0x100 | 0x8000) and
             not pe.FILE_HEADER.Characteristics & 1 and h.DATA_DIRECTORY[5].VirtualAddress,
             'legacy stack/flags/relocations required')
        need(all(not h.DATA_DIRECTORY[n].VirtualAddress and not h.DATA_DIRECTORY[n].Size
                 for n in (9, 10, 13, 14)), 'modern PE directory forbidden')
        imports = {}
        for module in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            name = module.dll.decode('ascii').upper()
            need(name in ('KERNEL32.DLL', 'MSVCRT.DLL') and name not in imports and
                 all(s.name for s in module.imports), 'original named imports required')
            symbols = sorted(s.name.decode('ascii') for s in module.imports)
            need(len(symbols) == len(set(symbols)) and set(symbols) <= set(installed[name]),
                 'actual OEM import missing')
            imports[name] = symbols
        need(imports == item.get('imports') and imports, 'actual import table differs')
        actual_exports = []
        for symbol in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []):
            need(symbol.name and not symbol.forwarder, 'direct named exports required')
            actual_exports.append(symbol.name.decode('ascii'))
        need(sorted(actual_exports) == expected_exports, 'actual export surface differs')
        sections = {}
        for s in pe.sections:
            if not s.Characteristics & 0x20000000:
                continue
            name = s.Name.rstrip(b'\0').decode('ascii')
            need(name not in sections and 0 < s.Misc_VirtualSize <= s.SizeOfRawData <= 4 << 20,
                 'bounded executable section required')
            data = s.get_data()[:s.Misc_VirtualSize]
            need(len(data) == s.Misc_VirtualSize, 'truncated executable extent')
            sections[name] = dict(address=h.ImageBase + s.VirtualAddress, data=data)
    finally:
        pe.close()
    need(sections, 'real executable code required')
    allowed_forms = table['BASE'] | table['X87'] | table['EXACT']
    allowed_forms |= {base + suffix for base in table['SUFFIXABLE'] for suffix in ('b', 'w', 'l')}
    allowed_forms |= {base + suffix for base in table['X87'] for suffix in ('s', 'l', 't', 'll')}
    offsets, current, count = {}, None, 0
    for line in raw.decode('ascii').splitlines():
        need(len(line) <= 2048, 'decode line bound')
        header = re.fullmatch(r'Disassembly of section ([^ \t:]+):', line)
        if header:
            current = header[1]
            need(current in sections and current not in offsets, 'duplicate/unexpected decode section')
            offsets[current] = 0
            continue
        if not re.match(r'^[ \t]*[0-9a-f]+:[ \t]', line):
            continue
        match = re.fullmatch(r'[ \t]*([0-9a-f]+):[ \t]+((?:[0-9a-f]{2}[ \t]+)+)'
                             r'([^ \t]+)(?:[ \t]+(.*))?', line)
        need(match and current in sections, 'unknown instruction row')
        address, encoded, mnemonic, operands = match.groups()
        data, operands = bytes.fromhex(encoded), operands or ''
        for _ in range(15):
            if mnemonic not in table['PREFIX']:
                break
            parts = operands.split(None, 1)
            need(parts, 'prefix without instruction')
            mnemonic, operands = parts[0], parts[1] if len(parts) > 1 else ''
        need(mnemonic not in table['PREFIX'] and mnemonic in allowed_forms and
             not re.search(r'%(?:[xyz]mm\d+|mm[0-7])\b', operands) and
             all(n in ('0', '2', '3') for n in re.findall(r'%cr([0-9]+)\b', operands)),
             'unknown/post-i486 instruction or register')
        position, section = offsets[current], sections[current]
        need(1 <= len(data) <= 15 and int(address, 16) == section['address'] + position and
             section['data'][position:position + len(data)] == data, 'raw code byte/address gap')
        offsets[current] += len(data)
        count += 1
        need(count <= 1048576, 'decode instruction count bound')
    need(set(offsets) == set(sections) and all(offsets[n] == len(s['data'])
         for n, s in sections.items()), 'incomplete declared executable byte coverage')
    expected_sections = {n: dict(bytes=len(s['data']), sha256=sha(s['data']),
        address=s['address'], decoded_bytes=offsets[n]) for n, s in sections.items()}
    need(type(machine.get('instructions_decoded')) is int and machine['instructions_decoded'] == count
         and machine.get('executable_sections') == expected_sections and
         machine.get('parser') == 'horizontal-lines-explicit-i486-x87-allowlist-v1' and
         machine.get('post_i486_families') == 'absent', 'full native gate metadata differs')


def _collect(paths, pins, closure):
    need(isinstance(paths, dict) and set(paths) == RECEIPTS and
         isinstance(pins, dict) and pins == APPROVED, 'three exact approved source generations required')
    builds, merged, dirs = {}, {}, {}
    for role in sorted(RECEIPTS):
        directory = ROOT / 'build' / BUILD_DIRS[role]
        path = Path(paths[role])
        need(path == directory / 'result.json', 'exact canonical original build receipt required')
        build = json_data(closure.take(path, pins[role], limit=16 << 20))
        need(isinstance(build, dict) and type(build.get('schema')) is int and build['schema'] == 1 and
             build.get('passed') is True and build.get('native_execution') is False and
             build.get('vm_operations') is False, 'approved successful build-only receipt required')
        sources = build.get('source_sha256')
        need(isinstance(sources, dict) and set(sources) == SOURCE_SETS[role], 'exact source closure required')
        for name, digest in sources.items():
            relative(name)
            need(name not in merged or merged[name] == digest, 'mixed source generations')
            merged[name] = pin(digest)
            closure.take(ROOT / name, digest)
            closure.take(directory / 'source' / name, digest)
        builds[role], dirs[role] = build, directory
        closure.alias(role, path, pins[role])
    runtime, probe, observer = (builds[r] for r in
        ('runtime-build.json', 'probe-build.json', 'observer-build.json'))
    need(runtime.get('kind') == 'bounded-standalone-wamr-current-interpreter' and
         probe.get('kind') == 'actual-numeric-wamr-win98-probe-build' and
         observer.get('kind') == 'win98-wasm-owned-child-observer-build', 'wrong numeric WAMR build profile')
    need(probe.get('runtime_receipt_sha256') == pins['runtime-build.json'] and
         probe.get('nonce') == observer.get('nonce') == NONCE and
         probe.get('models') == {'host': 244, 'sanitizer': 244} and
         probe.get('actual_guest_output') == PROFILE['child_log'] and
         probe.get('independently_observed_actual_child_exit_required') is True and
         probe.get('source_archives_and_original_runtime_unchanged') is True,
         'probe dependency/nonce/real oracle profile differs')
    flags = {
        'runtime-build.json': ('browser_wasm', 'browser_js_api', 'full_modern_wasm',
            'mshtml_integration', 'full_browser', 'webgpu', 'webgl', 'modern_apps', 'foreign_script_execution'),
        'probe-build.json': ('browser_webassembly', 'full_modern_wasm', 'webgl', 'webgpu', 'modern_apps'),
        'observer-build.json': ('native_numeric_execution', 'native_paint', 'actual_child_exit',
            'full_modern_wasm', 'browser_webassembly', 'webgpu', 'webgl', 'full_web_standards'),
    }
    for role, keys in flags.items():
        need(all(builds[role].get(k) is False for k in keys), 'component scope downgrade/false support')
    expected_observer = 'PASS: 3022 supervisor API/lifecycle assertions across 18 injected scenarios'
    profile = observer.get('profiles', {}).get('wasm', {})
    need(set(observer.get('profiles', {})) == {'wasm'} and
         all(profile.get(k) == v for k, v in PROFILE.items()) and
         profile.get('host') == profile.get('sanitizer') == expected_observer,
         'exact owned observer path/deadline/fault profile required')
    logs = {}
    for role in sorted(RECEIPTS):
        build, directory = builds[role], dirs[role]
        steps = build.get('steps')
        need(isinstance(steps, list) and len(steps) == {'runtime-build.json': 28,
             'probe-build.json': 9, 'observer-build.json': 6}[role], 'exact build log closure required')
        names = set()
        for step in steps:
            name = step.get('name')
            need(isinstance(name, str) and name not in names, 'duplicate build log')
            names.add(name)
            path = Path(step['log'])
            need(path.parent == directory and type(step.get('returncode')) is int,
                 'canonical actual log/exit code required')
            expected_rc = 1 if role == 'runtime-build.json' and name in (
                'asan-control-test', 'ubsan-control-test') else 0
            need(step['returncode'] == expected_rc, 'unexpected actual build/control result')
            logs[(role, name)] = closure.take(path, step['sha256'], limit=8 << 20)
    host = host_oracle(logs[('probe-build.json', 'host-test')])
    need(logs[('probe-build.json', 'sanitizer-test')] == host, 'full ASan/UB numeric oracle differs')
    need(logs[('observer-build.json', 'wasm-host-test')] ==
         logs[('observer-build.json', 'wasm-sanitize-test')] == (expected_observer + '\n').encode(),
         'actual observer fault-model log differs')
    numeric_runtime = b'WAMR actual standalone tests: 1237 assertions; browser/native/full-Wasm false\n'
    need(logs[('runtime-build.json', 'host-tests')] ==
         logs[('runtime-build.json', 'sanitizer-tests')] == numeric_runtime, 'actual runtime totals differ')
    engine_configuration(runtime, logs)
    for role in ('probe-build.json',):
        for name, digest in builds[role]['generated_sha256'].items():
            need(relative(name).name == name, 'canonical generated probe member')
            closure.take(dirs[role] / name, digest)
    need(len(runtime.get('prepared_files', {})) == 392 and len(runtime.get('original_source_files', {})) == 2001
         and len(runtime.get('object_cache', [])) == 93 and len(runtime.get('original_fixtures', {})) == 17,
         'complete frozen runtime profile required')
    for name, row in runtime['prepared_files'].items():
        closure.take(dirs['runtime-build.json'] / 'prepared' / relative(name), row['sha256'], row['bytes'])
    original = ROOT / SOURCE_DIR
    archive = closure.take(original / 'wamr.tar.gz', runtime['upstream_archive_sha256'],
                           runtime['upstream_archive_bytes'])
    need(len(archive) == 6136546 and runtime['upstream_revision'] ==
         'f5f57c09aee623436f5fb87a90798fdd2cdf39fd', 'wrong upstream archive generation')
    upstream = json_data(closure.take(original / 'source-receipt.json', limit=16 << 20))
    need(upstream.get('revision') == runtime['upstream_revision'] and
         upstream.get('archive_sha256') == runtime['upstream_archive_sha256'] and
         upstream.get('files') == runtime['original_source_files'] and
         upstream.get('foreign_script_execution') is False, 'original source authority differs')
    for name, row in runtime['original_source_files'].items():
        closure.take(original / 'source' / relative(name), row['sha256'], row['bytes'])
    for name, row in runtime['patches'].items():
        need(row.get('original_sha256') == runtime['original_source_files'][name]['sha256'] and
             row.get('prepared_sha256') == runtime['prepared_files'][name]['sha256'], 'patch authority differs')
    fixtures = {}
    for name, row in runtime['original_fixtures'].items():
        need(re.fullmatch('[a-z_]{1,48}', name) and row.get('origin') == 'original-owned-binary-encoder',
             'original project-owned fixture required')
        fixtures[name] = closure.take(dirs['runtime-build.json'] / 'original-fixtures' / (name + '.wasm'),
                                     row['sha256'], row['bytes'])
    need(set(probe['original_fixture_sha256']) == {'arithmetic', 'memory', 'float', 'imports',
         'infinite', 'start_infinite', 'missing_import', 'bad_magic'} and all(
         h == runtime['original_fixtures'][n]['sha256'] for n, h in probe['original_fixture_sha256'].items()),
         'probe uses different numeric fixtures')
    header = '/* Original binary fixtures; not compiled official spec modules. */\n'
    header += ''.join('static const unsigned char wasm_' + name + '[]={' +
        ','.join(str(v) for v in data) + '};\n' for name, data in fixtures.items())
    closure.take(dirs['runtime-build.json'] / 'wasm_original_fixtures.h', sha(header.encode()))
    defs = ('LIBRARY M98WASM\nEXPORTS\n' + '\n'.join(' ' + n for n in EXPORTS) + '\n').encode()
    closure.take(dirs['runtime-build.json'] / 'M98WASM.def', sha(defs))
    cache = ROOT / 'build/wasm-runtime-object-cache'
    cache_hashes = set()
    cache_keys = set()
    for row in runtime['object_cache']:
        key = pin(row['key'])
        need(key not in cache_keys, 'duplicate actual cache object')
        cache_keys.add(key)
        metadata = json_data(closure.take(cache / (key + '.json'), row['provenance_sha256']))
        context = metadata.get('context')
        need(isinstance(context, dict) and sha(json.dumps(context, sort_keys=True).encode()) == key and
             metadata.get('object_sha256') == row['object_sha256'], 'cache context/object authority differs')
        closure.take(cache / (key + '.o'), row['object_sha256'])
        source = Path(row['source'])
        closure.take(source, context['source_sha256'])
        headers = context.get('headers')
        need(isinstance(headers, dict) and 1 <= len(headers) <= 392, 'bounded real cache header closure')
        for name, digest in headers.items():
            if name.startswith(('src/', 'tests/')):
                need(name in merged and merged[name] == digest, 'cache repository header differs')
            elif name == 'wasm_original_fixtures.h':
                need(digest == sha(header.encode()), 'cache fixture header differs')
            else:
                need(name in runtime['prepared_files'] and runtime['prepared_files'][name]['sha256'] == digest,
                     'cache prepared header differs')
        cache_hashes.add(row['object_sha256'])
    checked = probe.get('checked_evidence_sha256')
    need(isinstance(checked, dict) and len(checked) == 707, 'exact 707 actual probe inputs required')
    for name, digest in checked.items():
        closure.take(Path(name), digest)
    for label in ('host', 'sanitizer'):
        link = [s for s in runtime['steps'] if s['name'] == label + '-build']
        need(len(link) == 1, 'unique actual engine link required')
        objects = [Path(p) for p in link[0]['command'] if p.endswith('.o')]
        need(len(objects) == 31 and objects[-1] == dirs['runtime-build.json'] / (label + '-30.o'),
             'actual reusable engine objects/test separation differs')
        for path in objects[:-1]:
            need(str(path) in checked and checked[str(path)] in cache_hashes, 'actual linked object is unpinned')
    for name, row in runtime['retained_binaries'].items():
        need(relative(name).name == name, 'canonical retained runtime binary')
        closure.take(dirs['runtime-build.json'] / name, row['sha256'], row['bytes'])
    for control in runtime['sanitizer_controls']:
        name = control['name']
        need(name in ('asan', 'ubsan') and control['actual_returncode'] == 1 and
             control['expected_diagnostic'].encode() in logs[('runtime-build.json', name + '-control-test')],
             'real sanitizer diagnostic control required')
        for suffix, key in (('.c', 'source_sha256'), ('.o', 'object_sha256'), ('', 'binary_sha256')):
            closure.take(dirs['runtime-build.json'] / (name + '-control' + suffix), control[key])
    installed = json_data(closure.take(ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json',
                                      merged['benchmarks/win98se-ko-oem-native-exports-v1.json']))['dlls']
    table = policy(closure.take(ROOT / 'tools/i486_instruction_gate.py', GATE_SHA))
    for role, name, raw_name, exports, commit in (
        ('runtime-build.json', 'M98WASM.DLL', 'native-disassembly-complete', EXPORTS, 524288),
        ('probe-build.json', 'WAS13PR.EXE', 'WAS13PR.EXE-disassembly', [], 65536),
        ('observer-build.json', 'M98WARUN.EXE', 'wasm-full-disassembly', [], 65536)):
        item = builds[role]['artifacts'][name]
        data = closure.take(dirs[role] / name, item['sha256'], item.get('bytes', item.get('size')), limit=1 << 20)
        raw_gate(data, logs[(role, raw_name)], item, table, exports, commit, installed)
        closure.alias(name, dirs[role] / name, item['sha256'])
    machine = probe['runtime_i486_recheck']
    item = dict(runtime['artifacts']['M98WASM.DLL'], i486_instructions=machine)
    raw_gate(closure.take(dirs['runtime-build.json'] / 'M98WASM.DLL', item['sha256']),
             logs[('probe-build.json', 'M98WASM.DLL-disassembly')], item, table, EXPORTS, 524288, installed)
    for name in STAGE_SOURCES:
        digest = sha(closure.take(ROOT / name))
        if closure.stage is not None:
            need(sha(read(ROOT / name)) == digest, 'running stage/verifier source differs from frozen copy')
            closure.current[str(ROOT / name)] = digest
        need(name not in merged or merged[name] == digest, 'stage/verifier source generation differs')
        merged[name] = digest
    return builds, merged, host


def collect(build_receipt_paths, build_pins):
    closure = Closure()
    builds, merged, _ = _collect(build_receipt_paths, build_pins, closure)
    closure.unchanged()
    return builds, closure.copies, merged


def provenance(manifest_sha, copies, merged):
    return dict(schema=1, kind='genuine-numeric-wamr-frozen-native-stage',
        manifest_sha256=pin(manifest_sha), source_sha256=merged,
        stage_sha256={n: h for n, (_, h) in copies.items()}, native_execution=False,
        native_numeric_execution=False, actual_child_exit=False, actual_supervisor_exit=False,
        browser_webassembly=False, full_modern_wasm=False, mshtml_integration=False,
        full_browser=False, webgl=False, webgpu=False, modern_apps=False, vm_operations=False,
        network_operations=False, global_install=False)


def check_stage(manifest_path, manifest_sha, build_pins, stage_provenance_sha256):
    need(isinstance(build_pins, dict) and build_pins == APPROVED,
         'three exact approved source generations required')
    manifest_path = canonical(Path(manifest_path))
    stage = manifest_path.parent
    need(manifest_path.name == 'guest-files.json' and stage.parent == BOOT_BUILD,
         'canonical direct boot stage required')
    before = read(stage / 'provenance.json', 2 << 20)
    need(sha(before) == pin(stage_provenance_sha256), 'unapproved stage provenance hash')
    manifest = receipt(manifest_path, manifest_sha, 65536)
    need(set(manifest) == {'schema', 'kind', 'inputs', 'outputs', 'command', 'nonce',
         'network_required', 'source_receipts'} and type(manifest.get('schema')) is int and manifest['schema'] == 1 and
         manifest.get('kind') == 'isolated-guest-file-inputs' and
         manifest.get('command') == PROFILE['self'] and manifest.get('nonce') == NONCE and
         manifest.get('network_required') is False and type(manifest.get('outputs')) is list and
         len(manifest['outputs']) == 3 and set(manifest['outputs']) == {PREFIX + n for n in OUTPUTS},
         'wrong offline numeric stage manifest')
    rows = manifest.get('source_receipts')
    need(isinstance(rows, list) and len(rows) == 3 and
         all(isinstance(r, dict) and set(r) == {'path', 'sha256'} for r in rows) and
         {r.get('path') for r in rows} == {str(stage / n) for n in RECEIPTS} and all(
         r.get('sha256') == build_pins.get(Path(r['path']).name) for r in rows),
         'exact explicitly approved frozen receipt list required')
    closure = Closure(stage)
    paths = {n: ROOT / 'build' / BUILD_DIRS[n] / 'result.json' for n in RECEIPTS}
    builds, merged, host = _collect(paths, build_pins, closure)
    prov = json_data(before)
    expected_provenance = provenance(manifest_sha, closure.copies, merged)
    need(isinstance(prov, dict) and type(prov.get('schema')) is int and
         all(prov.get(k) is False for k, value in expected_provenance.items() if value is False) and
         prov == expected_provenance, 'stage provenance scope/member drift')
    inputs = manifest.get('inputs')
    need(isinstance(inputs, list) and len(inputs) == 3 and
         all(isinstance(r, dict) and set(r) == {'source', 'guest', 'bytes', 'sha256'} for r in inputs) and
         {r.get('guest') for r in inputs} == {PREFIX + n for n in INPUTS}, 'exact numeric PE inputs required')
    by_name = {}
    for row in inputs:
        name = row['guest'][len(PREFIX):]
        data = read(stage / name, 1 << 20)
        need(row.get('source') == str(stage / name) and type(row.get('bytes')) is int and
             0 < row['bytes'] == len(data) <= 1 << 20 and row.get('sha256') == sha(data) ==
             closure.copies[name][1], 'manifest input/path/size/hash differs')
        by_name[name] = row
    closure.unchanged()
    need(read(stage / 'provenance.json', 2 << 20) == before and
         sha(read(manifest_path, 65536)) == manifest_sha, 'late provenance/manifest drift')
    closure.checked[str(stage / 'provenance.json')] = sha(before)
    closure.checked[str(manifest_path)] = manifest_sha
    return builds, by_name, host, merged, closure.checked
