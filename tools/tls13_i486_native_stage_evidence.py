#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Closed, read-only TLS i486 preparation evidence; never execute old builders.

Only the approved scanner's literal instruction sets are read. Saved actual
objdump bytes are replayed against complete PE executable VirtualSize extents.
The separate wrapper alone may invoke the unchanged own guest builder.
"""
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import stat
import tarfile

import pefile

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path('/root/Win98-Modern-boot/build')
DESTINATION = BOOT_BUILD / 'tls13-i486-native-5abe-20261001-v1'
TLS = ROOT / 'build/tls13-i486-v2'
LTS_EXTERNAL = Path('/root/Win98-Modern-tls13-7707/build/secure-transport')
NONCE = 'tls13-i486-5abe-20261001-v1'
PREFIX = 'C:\\GOPLAB\\'
INPUTS = frozenset(('M98TLS13.DLL', 'M98TLS.DLL', 'TLSDLL.EXE', 'T13RUN.EXE',
                    'CA.PEM', 'SRV.PEM', 'SRV.KEY', 'BADCA.PEM'))
OUTPUTS = frozenset(('TLSDLL.LOG', 'T13RUN.LOG', 'TLSOUT.LOG'))
IMAGE_CHARACTERISTICS = {'M98TLS13.DLL': 0x2106, 'M98TLS.DLL': 0x2106,
                         'TLSDLL.EXE': 0x0106, 'T13RUN.EXE': 0x0306}
MAX_MEMBER = 16 << 20
MAX_STAGE = 512 << 20
MAX_MEMBERS = 8192
PROVENANCE_LIMIT = 4 << 20
DISK_FLOOR = 22058516480
MEMORY_FLOOR = 6 << 30
APPROVED = {
 'tls': '98c526151545be95fe5f6cd58140ae2dfdc52d21038fe1de893387290dea1819',
 'root_review': 'd2eaf7896235fedb8246bb7197ac24297f4a265d6dda21295b7f76bcdb8892cf',
 'independent_review': '9ef72856e5dfddb357e9e89211dcf0f01d18babe437cec30649e52fe04ebb9e3',
 'client': '7e5d48151b4754adfcdf6cf5c9e5ef4747c3b61ed37a1e84eb1991847c1496f9',
 'server': '6ad287ce7b43ed45af43f2b8b62f4ea678f876ec2341a4bc87cb72c8a913ad97',
}
RECEIPTS = {
 'tls': TLS / 'result.json',
 'root_review': ROOT / 'build/tls13-i486-root-readback-v3/result.json',
 'independent_review': ROOT / 'build/tls13-i486-independent-review-v1/result.json',
 'client': TLS / 'client-build.json', 'server': TLS / 'server-build.json',
}
AUTHOR_SHA = '7762bc0950984b3f6d5a51704c351cb3dda0c6a5bea65f0ba9f5854cfd3f2ccc'
GATE_SHA = '6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973'
PROBE_AUTHORITY = BOOT_BUILD / 'tls13-native-5abe-20261001-v7/build-result.json'
PROBE_AUTHORITY_SHA = 'dbc1e147d18b033497dc0bb403522798d186acd54a255a01566f7c61432ca7ca'
PROBE_SOURCES = {
 'tests/m98_tls13_guest_interop.c': '840f0c02780e45a44204bcf36051e7d7ca2697c06d10ac8ac40906a743fbc13e',
 'tools/build_tls13_guest_interop.py': 'd3d7c523a18e0ec4384dc05742eb43441aa7902d5fc34cd98f172fcf4d7917a6',
 'tests/m98_tls13_interop_controller.c': '742ee0bbc121e89a59b48b30f1b9820da87620618b8be7a59be5ed37f727e4e6',
 'tests/m98_tls13_guest_runner.c': '9be9086ee1fd92a2aba97eefa8b92322aa3f3f4f9609ac9dc54629c83327a27f',
 'tests/m98_tls13_guest_runner_mock.c': '5c7fd1f4e8495ad5c680a7355ed7d265956d01af75b983244923b3347e3f1311',
 'tests/m98_tls13_guest_runner_mock.h': '8195a20d0c5dbbc576bd00ce314411cd03f107b1110612a2c425089c5aca8ebc',
 'src/m98_tls13.h': 'fa420d5dd9183956673814ae8f0393c758fd3b7bb5687dbaa24097bf633e7dbe',
 'benchmarks/win98se-ko-oem-native-exports-v1.json': '3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d',
}
STAGE_SOURCES = ('tools/stage_tls13_i486_native.py',
 'tools/tls13_i486_native_stage_evidence.py', 'tests/test_tls13_i486_native_stage.py',
 'docs/TLS13_I486_NATIVE_STAGE.md')
CLIENT_EXPORTS = sorted('m98_tls_create m98_tls_handshake m98_tls_write m98_tls_read '
 'm98_tls_shutdown m98_tls_backend_error m98_tls_verify_flags m98_tls_is_established m98_tls_free'.split())
SERVER_EXPORTS = sorted('ntwst_runtime_init ntwst_runtime_fini ntwst_native_runtime_init '
 'ntwst_native_runtime_fini ntwst_create ntwst_destroy ntwst_handshake ntwst_write '
 'ntwst_read ntwst_close_notify ntwst_version ntwst_verify_flags ntwst_engine_error'.split())
CONTROLLER = b'HOST CONTROLLER PASS: 15 assertions; no TLS/native Windows claim\n'
RUNNER = b'PASS: 2957 supervisor API/lifecycle assertions across 18 injected scenarios\n'
SCOPE = dict(native_execution=False, native_network=False, winsock=False,
 system_tls=False, modern_apps=False, full_browser=False, user_objective_complete=False,
 vm_operations=False, network_operations=False, global_install=False,
 external_compiler_subtool_system_header_complete_closure=False)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'SHA-256 pin required')
    return value


def relative(value):
    need(isinstance(value, str) and value and len(value) <= 2048 and '\\' not in value,
         'bounded POSIX relative member required')
    p = Path(value)
    need(not p.is_absolute() and str(p) == value and
         all(n not in ('', '.', '..') for n in value.split('/')), 'noncanonical relative member')
    return p


def canonical(path, exists=True):
    p = Path(path)
    need(p.is_absolute() and str(p) == os.path.normpath(str(p)) and
         p.resolve(strict=exists) == p, 'canonical path without symlink required: ' + str(p))
    return p


def read(path, limit=MAX_MEMBER):
    path = canonical(path)
    need(type(limit) is int and 0 <= limit <= MAX_MEMBER, 'bounded read limit required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'bounded regular evidence required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after, now = os.fstat(fd), path.stat(follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(path.resolve(strict=True) == path and len(data) == before.st_size and
             all(getattr(before, k) == getattr(after, k) == getattr(now, k) for k in fields),
             'evidence changed while reading')
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
    def nonfinite(value):
        raise ValueError('nonfinite JSON: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def same(actual, expected):
    """JSON value equality with exact types; bool never aliases integer 0/1."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(same(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same(a, b) for a, b in zip(actual, expected))
    return actual == expected


def resource_guard(extra=0):
    need(type(extra) is int and 0 <= extra <= MAX_STAGE, 'bounded resource allowance')
    v = os.statvfs(canonical(BOOT_BUILD))
    free = v.f_bavail * v.f_frsize
    rows = re.findall(r'^MemAvailable:[ \t]+([0-9]+)[ \t]+kB$',
                      Path('/proc/meminfo').read_text(), re.M)
    need(len(rows) == 1, 'actual memory availability required')
    available = int(rows[0]) * 1024
    need(free >= DISK_FLOOR + extra, 'disk reserve floor insufficient; no guard relaxation')
    need(available >= MEMORY_FLOOR, 'memory reserve floor insufficient')
    return dict(free_bytes=free, available_memory_bytes=available,
                disk_floor=DISK_FLOOR, memory_floor=MEMORY_FLOOR, additional_bytes=extra)


def member_of(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'canonical source spelling')
    if path.is_relative_to(ROOT):
        return 'evidence/project/' + str(relative(str(path.relative_to(ROOT))))
    allowed = {LTS_EXTERNAL / 'upstream/mbedtls-3.6.7.tar.bz2'} | {
        LTS_EXTERNAL / 'native-v3/project' / n for n in
        ('transport.c', 'transport.h', 'native_time.c', 'native_runtime.c',
         'native_runtime.h', 'native_crt.c', 'native.def', 'user_config.h')}
    if path in allowed:
        return 'evidence/external/lts/' + str(relative(str(path.relative_to(LTS_EXTERNAL))))
    need(path == PROBE_AUTHORITY, 'undeclared external source path')
    return 'evidence/original-probe-source-authority.json'


class Closure:
    def __init__(self, stage=None):
        self.stage, self.copies, self.checked, self.sources = stage, {}, {}, {}
        self.live_checked = {}
        self.aliases, self.directories = {}, set()
        self.total = 0

    def actual(self, path):
        return Path(path) if self.stage is None else self.stage / member_of(path)

    def take(self, path, expected=None, size=None, limit=MAX_MEMBER):
        path = Path(path)
        member = member_of(path)
        data = read(self.actual(path), limit)
        digest = sha(data)
        need(expected is None or digest == pin(expected), 'closure SHA differs: ' + str(path))
        need(size is None or type(size) is int and size == len(data), 'closure byte count differs')
        need(member not in self.copies or self.copies[member] == (path, digest), 'conflicting closure generation')
        if member not in self.copies:
            self.total += len(data)
        self.copies[member] = (path, digest)
        self.checked[str(self.actual(path))] = digest
        need(len(self.copies) <= MAX_MEMBERS and self.total <= MAX_STAGE, 'complete closure bound')
        return data

    def unchanged(self):
        for path, digest in self.checked.items():
            need(sha(read(Path(path))) == digest, 'late closure drift: ' + path)
        self.live_unchanged()
        verify_aliases(self)

    def live_unchanged(self):
        for path, digest in self.live_checked.items():
            need(sha(read(Path(path))) == digest, 'late current validator/stager drift: ' + path)


def policy(data):
    need(sha(data) == GATE_SHA, 'unapproved literal CPU policy')
    table = {}
    for node in ast.parse(data).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name not in ('BASE', 'X87', 'PREFIX', 'EXACT', 'SUFFIXABLE'):
            continue
        need(name not in table, 'duplicate CPU policy')
        value = node.value
        if isinstance(value, ast.Set):
            words = ast.literal_eval(value)
        else:
            need(isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'set' and
                 len(value.args) == 1 and not value.keywords, 'nonliteral CPU policy')
            call = value.args[0]
            need(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and
                 call.func.attr == 'split' and isinstance(call.func.value, ast.Constant) and
                 isinstance(call.func.value.value, str) and not call.args and not call.keywords,
                 'nonliteral CPU word string')
            words = set(call.func.value.value.split())
        need(isinstance(words, set) and words and all(isinstance(w, str) and re.fullmatch('[a-z][a-z0-9]*', w)
             for w in words), 'bounded literal instruction set')
        table[name] = words
    need(len(table) == 5, 'incomplete CPU policy')
    return table


def raw_gate(binary, raw, table, exports, installed, characteristics):
    """Replay actual saved output, including all executable bytes and loader pairs."""
    need(isinstance(binary, bytes) and 0 < len(binary) <= 1 << 20 and
         isinstance(raw, bytes) and 0 < len(raw) <= MAX_MEMBER, 'bounded native image/listing')
    try:
        pe = pefile.PE(data=binary)
    except pefile.PEFormatError as error:
        raise ValueError('malformed actual PE') from error
    try:
        h = pe.OPTIONAL_HEADER
        need(type(characteristics) is int and characteristics in set(IMAGE_CHARACTERISTICS.values()) and
             pe.FILE_HEADER.Characteristics == characteristics, 'exact original classic PE characteristics required')
        need(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and pe.is_dll() == bool(exports)
             and h.AddressOfEntryPoint and pe.FILE_HEADER.TimeDateStamp == 0, 'actual deterministic x86 image')
        need(h.NumberOfRvaAndSizes == 16 and len(h.DATA_DIRECTORY) == 16, 'complete original PE directory table')
        need((h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion,
              h.MajorSubsystemVersion, h.MinorSubsystemVersion, h.Subsystem) == (4, 10, 4, 10, 2),
             'actual Win98 loader/subsystem')
        need(h.DllCharacteristics == 0 and (h.SizeOfStackReserve, h.SizeOfStackCommit) == (2097152, 65536),
             'legacy loader flags and exact stack')
        need(not pe.FILE_HEADER.Characteristics & 1 and h.DATA_DIRECTORY[5].VirtualAddress > 0 and
             h.DATA_DIRECTORY[5].Size > 0, 'both real relocation fields required')
        need(all(h.DATA_DIRECTORY[n].VirtualAddress == h.DATA_DIRECTORY[n].Size == 0
                 for n in (9, 10, 13, 14)), 'both modern directory fields must be zero')
        modules = {'KERNEL32.DLL'} if not exports else {'KERNEL32.DLL', 'MSVCRT.DLL', 'ADVAPI32.DLL'}
        imports = {}
        for item in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', ()):
            module = item.dll.decode('ascii').upper()
            need(module in modules and module not in imports and all(s.name for s in item.imports),
                 'unique original named import module')
            names = sorted(s.name.decode('ascii') for s in item.imports)
            need(names and len(names) == len(set(names)) and set(names) <= set(installed.get(module, [])),
                 'actual original OEM import symbols')
            imports[module] = names
        need(imports, 'actual original imports required')
        sections = {}
        for s in pe.sections:
            if s.Characteristics & 0x20000000:
                name = s.Name.rstrip(b'\0').decode('ascii')
                need(name not in sections and 0 < s.Misc_VirtualSize <= s.SizeOfRawData <= 4 << 20,
                     'bounded executable VirtualSize')
                data = s.get_data()[:s.Misc_VirtualSize]
                need(len(data) == s.Misc_VirtualSize, 'complete native code extent')
                sections[name] = dict(address=h.ImageBase + s.VirtualAddress, data=data)
        need(sections and sum(len(s['data']) for s in sections.values()) <= 4 << 20,
             'complete executable section bound')
        def code_rva(value):
            return any(s['address'] - h.ImageBase <= value < s['address'] - h.ImageBase + len(s['data'])
                       for s in sections.values())
        need(code_rva(h.AddressOfEntryPoint), 'entrypoint outside actual code')
        actual_exports = []
        for s in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', ()):
            need(s.name and not s.forwarder and code_rva(s.address), 'direct named code export')
            actual_exports.append(s.name.decode('ascii'))
        need(sorted(actual_exports) == exports and len(actual_exports) == len(set(actual_exports)),
             'exact original export ABI')
        loader = dict(imports=imports, exports=exports, relocation_rva=h.DATA_DIRECTORY[5].VirtualAddress,
                      relocation_bytes=h.DATA_DIRECTORY[5].Size, stack_reserve=h.SizeOfStackReserve,
                      stack_commit=h.SizeOfStackCommit, dll_characteristics=h.DllCharacteristics,
                      characteristics=pe.FILE_HEADER.Characteristics)
    finally:
        pe.close()
    forms = table['BASE'] | table['X87'] | table['EXACT']
    forms |= {b + s for b in table['SUFFIXABLE'] for s in ('b', 'w', 'l')}
    forms |= {b + s for b in table['X87'] for s in ('s', 'l', 't', 'll')}
    offsets, current, count = {}, None, 0
    for line in raw.decode('ascii').splitlines():
        need(len(line) <= 2048, 'bounded raw listing line')
        header = re.fullmatch(r'Disassembly of section ([^ \t:]+):', line)
        if header:
            current = header[1]
            need(current in sections and current not in offsets, 'duplicate/unexpected executable decode')
            offsets[current] = 0
            continue
        if not re.match(r'^[ \t]*[0-9a-f]+:[ \t]', line):
            continue
        row = re.fullmatch(r'[ \t]*([0-9a-f]+):[ \t]+((?:[0-9a-f]{2}[ \t]+)+)'
                           r'([^ \t]+)(?:[ \t]+(.*))?', line)
        need(row and current in sections, 'unknown/truncated raw instruction row')
        address, encoded, mnemonic, operands = row.groups()
        data, operands = bytes.fromhex(encoded), operands or ''
        for _ in range(15):
            if mnemonic not in table['PREFIX']:
                break
            parts = operands.split(None, 1)
            need(parts, 'prefix without instruction')
            mnemonic, operands = parts[0], parts[1] if len(parts) > 1 else ''
        need(mnemonic not in table['PREFIX'] and mnemonic in forms and
             not re.search(r'%(?:[xyz]mm\d+|mm[0-7])\b', operands) and
             all(n in ('0', '2', '3') for n in re.findall(r'%cr([0-9]+)\b', operands)),
             'post-i486/unknown instruction or register')
        n, section = offsets[current], sections[current]
        need(1 <= len(data) <= 15 and int(address, 16) == section['address'] + n and
             section['data'][n:n + len(data)] == data, 'raw instruction byte/address gap')
        offsets[current] += len(data)
        count += 1
        need(count <= 1048576, 'bounded real instruction count')
    need(set(offsets) == set(sections) and all(offsets[n] == len(s['data']) for n, s in sections.items()),
         'complete executable byte coverage required')
    return dict(sha256=sha(binary), bytes=len(binary), disassembly_sha256=sha(raw), **loader,
                instructions_decoded=count, executable_sections={n: dict(bytes=len(s['data']),
                sha256=sha(s['data']), address=s['address'], decoded_bytes=offsets[n])
                for n, s in sections.items()}, parser='horizontal-lines-explicit-i486-x87-allowlist-v1',
                post_i486_families='absent')


def archive_topology(archive, base, originals):
    """Validate every original TAR byte and all declared members/ancestors."""
    names, roots, directories, aliases, regulars = set(), set(), set(), {}, set()
    allocation = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:bz2') as bundle:
        for item in bundle:
            p = PurePosixPath(item.name)
            need(p.parts and not p.is_absolute() and '..' not in p.parts and len(item.name) <= 1024,
                 'noncanonical archived member')
            name = str(p)
            need(item.name == name or item.isdir() and item.name == name + '/', 'canonical archived member spelling')
            need(name not in names, 'duplicate original archive member')
            names.add(name)
            roots.add(p.parts[0])
            need(len(names) <= 40000, 'archive member bound')
            directories.update(str(base / str(q)) for q in p.parents if str(q) != '.')
            if item.isdir():
                directories.add(str(base / name))
            elif item.issym():
                target = item.linkname
                need(target and len(target) <= 1024 and not PurePosixPath(target).is_absolute(),
                     'bounded original relative alias')
                normalized = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                need(PurePosixPath(normalized).parts[0] == p.parts[0] and
                     '..' not in PurePosixPath(normalized).parts, 'archive alias escape')
                aliases[str(base / name)] = dict(target=target, normalized_target=normalized)
            else:
                need(item.isfile() and 0 <= item.size <= MAX_MEMBER, 'original regular archive member')
                allocation += item.size
                need(allocation <= MAX_STAGE, 'original archive allocation bound')
                with bundle.extractfile(item) as stream:
                    data = stream.read(MAX_MEMBER + 1)
                path = str(base / name)
                need(len(data) == item.size and originals.get(path) == sha(data), 'original TAR/extraction byte mismatch')
                regulars.add(path)
    need(len(roots) == 1, 'single original archive root')
    declared = {str(base / n) for n in names} | directories
    for path, item in aliases.items():
        need(str(base / item['normalized_target']) in declared and
             path not in directories and not any(str(p) in aliases for p in Path(path).parents),
             'archive alias collision/parent/undeclared target')
    return aliases, directories, regulars


def verify_aliases(closure):
    for path in closure.directories:
        actual = closure.actual(path)
        need(canonical(actual).is_dir(), 'declared original directory missing')
    for path, item in closure.aliases.items():
        actual = closure.actual(path)
        need(canonical(actual.parent) == actual.parent, 'alias under noncanonical parent')
        before = actual.lstat()
        need(stat.S_ISLNK(before.st_mode), 'declared original alias missing')
        target = os.readlink(actual)
        expected = closure.actual(item['resolved_target'])
        need(target == item['target'] and actual.resolve(strict=True) == expected and
             (expected.is_dir() if item['directory'] else expected.is_file()),
             'original alias normalized target/type drift')
        after = actual.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(os.readlink(actual) == target and all(getattr(before, f) == getattr(after, f) for f in fields),
             'alias metadata changed during read')


def approved_pins(values):
    need(isinstance(values, dict) and values == APPROVED, 'exact caller-approved TLS generations required')
    return values


def _collect(pins, c):
    approved_pins(pins)
    builds = {n: json_data(c.take(p, pins[n], limit=(2 << 20) if n in ('client', 'server') else MAX_MEMBER))
              for n, p in RECEIPTS.items()}
    b, root, review = (builds[n] for n in ('tls', 'root_review', 'independent_review'))
    need(isinstance(b, dict) and type(b.get('schema')) is int and b['schema'] == 1 and
         b.get('kind') == 'original-latest-lts-i486-corrective-port' and b.get('passed') is True and
         all(b.get(k) is False for k in ('native_execution', 'native_network', 'system_tls',
                                      'modern_apps', 'original_stages_modified')), 'corrective build scope/schema')
    need(root.get('schema') == 'win98modern.root-tls13-i486-readback.v2' and root.get('passed') is True and
         root.get('source_receipt_sha256') == pins['tls'] and type(review.get('schema')) is int and
         review['schema'] == 1 and review.get('kind') == 'independent-read-only-tls13-i486-review' and
         review.get('passed') is True and review.get('approved_build_receipt_sha256') == pins['tls'] and
         review.get('approved_author_readback_sha256') == AUTHOR_SHA, 'two reviewed generation authorities')
    for authority, fields in ((root, ('native_windows', 'native_network', 'system_tls', 'modern_apps',
           'full_browser', 'user_objective_complete', 'external_compiler_subtool_system_header_complete_closure')),
          (review, ('source_mutation', 'tests_rerun', 'build_rerun', 'vm_action', 'native_execution',
                    'native_network', 'system_tls', 'modern_apps'))):
        need(all(authority.get(n) is False for n in fields), 'review scope flags differ')
    root_map, review_map = root.get('checked_sha256'), review.get('checked_sha256')
    sizes = review.get('checked_bytes')
    need(isinstance(root_map, dict) and len(root_map) == 7561 and isinstance(review_map, dict) and
         len(review_map) == 7568 and isinstance(sizes, dict) and set(sizes) == set(review_map) and
         all(review_map.get(p) == h for p, h in root_map.items()), 'complete two-review byte closure')
    for p, h in review_map.items():
        c.take(Path(p), h, sizes[p])
    sources = b.get('source_sha256')
    need(isinstance(sources, dict) and len(sources) == 16 and review.get('source_sha256') == sources,
         'exact reviewed corrective source closure')
    for name, digest in sources.items():
        relative(name)
        c.take(ROOT / name, digest)
        c.take(TLS / 'source' / name, digest)
        c.sources[name] = pin(digest)
    for name, digest in PROBE_SOURCES.items():
        need(name not in c.sources or c.sources[name] == digest, 'mixed probe/corrective source generation')
        c.take(ROOT / name, digest)
        c.sources[name] = digest
    source_authority = json_data(c.take(PROBE_AUTHORITY, PROBE_AUTHORITY_SHA, limit=2 << 20))
    need(source_authority.get('source_sha256') == PROBE_SOURCES, 'original eight probe source authority differs')
    for name in STAGE_SOURCES:
        digest = sha(c.take(ROOT / name))
        need(name not in c.sources, 'stage source overlaps frozen original')
        c.sources[name] = digest
        if c.stage is not None:
            need(sha(read(ROOT / name)) == digest, 'current validator/stager differs from approved frozen source')
            c.live_checked[str(ROOT / name)] = digest
    need(len(c.sources) == 26, 'exact combined current/frozen source profile')
    need(len(b.get('steps', [])) == 978 and len(b.get('generated_recipe_sha256', {})) == 28,
         'complete actual build command/recipe closure')
    logs = {}
    for row in b['steps']:
        name = row.get('name')
        need(isinstance(name, str) and name not in logs and type(row.get('returncode')) is int and
             row['returncode'] == 0 and 'timed_out' not in row and Path(row['log']).parent == TLS,
             'actual successful distinct build command required')
        logs[name] = c.take(Path(row['log']), row['sha256'])
    fmt = b'PASS bounded TLS i486 formatter: 18974 assertions; independent C99 integer/string oracle; no TLS/native claim\n'
    need(logs.get('formatter-normal-test') == logs.get('formatter-sanitize-test') == fmt,
         'actual full formatter oracles differ')
    need(b'Ran 10 tests' in logs['startup-controls'] and logs['startup-controls'].endswith(b'OK\n'),
         'actual ten-method startup control verdict')
    startup = b.get('owned_server_startup_controls', {})
    need(startup.get('passed') is True and type(startup.get('deadline_seconds')) is int and
         startup['deadline_seconds'] == 5 and type(startup.get('line_limit_bytes')) is int and
         startup['line_limit_bytes'] == 64 and startup.get('sha256') == sha(logs['startup-controls']),
         'bounded actual startup profile')
    objects = review.get('supplemental_actual_object_sha256')
    measured = root.get('actual_object_measurements')
    need(isinstance(objects, dict) and len(objects) == 471 and isinstance(measured, dict) and
         set(measured) == set(objects) and all(measured[p].get('sha256') == h for p, h in objects.items()),
         'both independent actual compiler object measurements')
    counts = {'latest-host': 119, 'latest-native': 117, 'lts-host': 117, 'lts-native': 118}
    need(set(b.get('profiles', {})) == set(counts), 'four exact real compiler profiles')
    actual_outputs = set()
    for name, count in counts.items():
        profile = b['profiles'][name]
        entries = json_data(c.take(TLS / name / 'compile_commands.json', profile['compiler_database_sha256']))
        units = profile.get('actual_translation_unit_macro_checks')
        need(type(profile.get('translation_units')) is int and profile['translation_units'] == count and
             isinstance(entries, list) and len(entries) == count and isinstance(units, list) and len(units) == count,
             'actual compiler TU/database count')
        for number, (entry, unit) in enumerate(zip(entries, units)):
            args = entry.get('arguments') or shlex.split(entry['command'])
            need(isinstance(args, list) and args.count('-o') == 1 and not any(a.startswith('@') for a in args),
                 'exact actual compiler output recipe')
            output = Path(entry['directory']) / args[args.index('-o') + 1]
            need(str(output) in objects and output.is_relative_to(TLS / name) and str(output) not in actual_outputs and
                 measured[str(output)].get('source') == entry['file'] and measured[str(output)].get('profile') == name,
                 'actual object/source/profile closure')
            c.take(output, objects[str(output)])
            actual_outputs.add(str(output))
            need(unit.get('translation_unit') == entry['file'] and Path(unit['actual_dump_log']) ==
                 TLS / (name + '-unit-macros-' + str(number) + '.log'), 'actual TU macro log binding')
            dump = logs[name + '-unit-macros-' + str(number)]
            macros = dict(re.findall(rb'^#define (\w+)[ \t]*(.*)$', dump, re.M))
            need(all(macros.get(k.encode(), b'!').strip() == value.encode()
                 for k, value in unit['exact_macro_values'].items()) and
                 not {x.encode() for x in unit['forbidden_absent']} & macros.keys(), 'actual TU macro values/forbidden features')
            if name.endswith('native'):
                need([x for x in args if x.startswith('-march=')] == ['-march=i486'] and
                     [x for x in args if x.startswith('-mtune=')] == ['-mtune=i486'] and
                     all(x in args for x in ('-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float',
                                            '-fno-isolate-erroneous-paths-dereference')) and
                     '-fisolate-erroneous-paths-dereference' not in args, 'every actual native CPU recipe')
    need(actual_outputs == set(objects), 'missing actual compiler object')
    originals = json_data(c.take(Path(b['original_source_pins']['path']), b['original_source_pins']['sha256']))
    aliases = json_data(c.take(Path(b['original_alias_metadata']['path']), b['original_alias_metadata']['sha256']))
    need(len(originals) == b['original_source_pins']['files'] == 5978 and
         len(aliases) == b['original_alias_metadata']['aliases'] == 147, 'exact upstream files/aliases')
    for p, digest in originals.items():
        c.take(Path(p), digest)
    dep = b['original_dependency_pins']
    archives = ((ROOT / 'build/tls13/upstream/mbedtls-4.2.0.tar.bz2', dep['latest_archive_sha256'], TLS / 'original/latest'),
                (LTS_EXTERNAL / 'upstream/mbedtls-3.6.7.tar.bz2', dep['lts_archive_sha256'], TLS / 'original/lts'))
    all_aliases, all_regulars = {}, set()
    for path, digest, base in archives:
        aa, dd, rr = archive_topology(c.take(path, digest), base, originals)
        all_aliases.update(aa)
        c.directories.update(dd)
        all_regulars.update(rr)
    need(all_aliases == aliases and len(all_regulars) == 5970 and
         set(originals) - all_regulars == {str(TLS / 'original/lts-adapter' / n)
                                         for n in b['lts_original_source_sha256']}, 'exact original archive byte/topology closure')
    directories = []
    for path, item in aliases.items():
        base = TLS / 'original/latest' if Path(path).is_relative_to(TLS / 'original/latest') else TLS / 'original/lts'
        resolved = base / item['normalized_target']
        directory = str(resolved) in c.directories
        need(directory or str(resolved) in originals, 'alias final target not original member')
        c.aliases[path] = dict(item, resolved_target=str(resolved), directory=directory)
        if directory:
            directories.append(str(resolved))
    need(len(directories) == 19 and len(set(directories)) == 5, 'actual original directory alias profile')
    verify_aliases(c)
    table = policy(c.take(ROOT / 'tools/i486_instruction_gate.py', GATE_SHA))
    installed = json_data(c.take(ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json',
                                 PROBE_SOURCES['benchmarks/win98se-ko-oem-native-exports-v1.json']))['dlls']
    cpu = {}
    for name, exports in (('latest-native', CLIENT_EXPORTS), ('lts-native', SERVER_EXPORTS)):
        p = b['profiles'][name]
        gate = raw_gate(c.take(Path(p['artifact']), p['sha256'], p['bytes'], limit=1 << 20),
                        c.take(Path(p['disassembly_log']), p['disassembly_sha256']), table, exports, installed,
                        IMAGE_CHARACTERISTICS['M98TLS13.DLL' if name == 'latest-native' else 'M98TLS.DLL'])
        old = p['i486']
        need(type(old.get('instructions_decoded')) is int and old['instructions_decoded'] == gate['instructions_decoded'] and
             old.get('executable_sections') == gate['executable_sections'] and old.get('artifact_sha256') == gate['sha256'] and
             old.get('disassembly_sha256') == gate['disassembly_sha256'] and old.get('post_i486_families') == 'absent',
             'complete real native CPU proof differs')
        cpu[name] = gate
    interop = b.get('host_latest_lts_interop', {})
    need(interop.get('passed') is True and interop.get('native_windows') is False and
         interop.get('system_tls') is False and isinstance(interop.get('cases'), list) and len(interop['cases']) == 12,
         'actual library interop scope/cases')
    modes = set()
    for item in interop['cases']:
        mode = item['mode']
        need(mode not in modes and type(item['actual_client_exit']) is int and item['actual_client_exit'] == 0 and
             type(item['actual_server_exit']) is int and item['client_result']['passed'] is True, 'actual endpoint results')
        modes.add(mode)
        need(json_data(c.take(Path(item['client_log']), item['client_log_sha256'])) == item['client_result'],
             'actual client endpoint log differs')
        server_log = c.take(Path(item['server_log']), item['server_log_sha256'])
        if mode in ('valid', 'retry'):
            need(item['actual_server_exit'] == 0 and item['client_result']['verify_flags'] == 0 and
                 item['client_result']['response_bytes'] == 60 and b'SERVER_VERSION=TLSv1.3' in server_log and
                 b'HOST_LTS_ENCRYPTED_HTTP=PASS' in server_log, 'actual encrypted complete response')
    need(modes == {'valid', 'retry', 'wrong-host', 'untrusted', 'corrupt-record', 'entropy',
        'entropy-negative', 'entropy-partial', 'entropy-late', 'entropy-late-negative', 'entropy-late-partial', 'clock'},
        'exact actual twelve-case host profile')
    c.unchanged()
    return builds, cpu, installed, table


def collect(pins, stage=None):
    c = Closure(stage)
    values = _collect(pins, c)
    return (*values, c)


def guest_command(stage):
    return ['python3', '-B', str(ROOT / 'tools/build_tls13_guest_interop.py'),
        '--output', str(stage / 'guest-build'), '--nonce', NONCE,
        '--client-dll', str(TLS / 'latest-native/M98TLS13.dll'),
        '--client-receipt', str(RECEIPTS['client']),
        '--server-dll', str(TLS / 'lts-native/M98TLS.dll'),
        '--server-receipt', str(RECEIPTS['server']),
        '--server-receipt-sha256', APPROVED['server'], '--fixtures-dir', str(TLS / 'fixtures')]


def generated(stage, c, table, installed):
    """Read all deterministic guest-build outputs and four complete CPU proofs."""
    result, members = {}, {}
    def take(name, expected=None, limit=MAX_MEMBER):
        relative(name)
        data = read(stage / name, limit)
        digest = sha(data)
        need(expected is None or digest == pin(expected), 'generated stage byte drift: ' + name)
        members[name] = digest
        return data
    build = json_data(take('guest-build/build-result.json', limit=2 << 20))
    need(build.get('schema') == 'win98modern.latest-tls-dll-interop.v1' and build.get('status') == 'PASS' and
         build.get('nonce') == NONCE and build.get('source_sha256') == PROBE_SOURCES and
         build.get('client_receipt_sha256') == APPROVED['client'] and build.get('server_receipt_sha256') == APPROVED['server'] and
         type(build.get('child_timeout_ms')) is int and build['child_timeout_ms'] == 120000 and
         type(build.get('reap_timeout_ms')) is int and build['reap_timeout_ms'] == 5000 and
         all(build.get(k) is False for k in ('native_guest_verified', 'system_tls_verified', 'application_functionality_verified')),
         'fixed original guest ABI/source/deadline profile')
    need(set(build.get('artifacts', {})) == INPUTS, 'exact eight original guest inputs')
    expected_frozen = {str(p): APPROVED[n] for n, p in RECEIPTS.items() if n in ('client', 'server')}
    tls = json_data(c.take(RECEIPTS['tls'], APPROVED['tls']))
    for profile in ('latest-native', 'lts-native'):
        p = tls['profiles'][profile]
        expected_frozen[p['artifact']] = p['sha256']
    for name in ('CA.PEM', 'SRV.PEM', 'SRV.KEY', 'BADCA.PEM'):
        data = c.take(TLS / 'fixtures' / name, limit=1 << 20)
        expected_frozen[str(TLS / 'fixtures' / name)] = sha(data)
    need(build.get('frozen_inputs') == expected_frozen, 'explicit corrected DLL/receipt/fixture inputs required')
    for name in ('client', 'server'):
        take('guest-build/' + name + '-build.json', APPROVED[name], 2 << 20)
    take('guest-build/build.log', build['build_log_sha256'])
    controller, runner = build.get('host_controller', {}), build.get('host_runner', {})
    need(controller.get('passed') is True and type(controller.get('assertions')) is int and controller['assertions'] == 15 and
         controller.get('result') == CONTROLLER.decode().strip() and runner.get('passed') is True and
         type(runner.get('scenarios')) is int and runner['scenarios'] == 18 and runner.get('result') == RUNNER.decode().strip(),
         'actual controller/supervisor doubles profile')
    need(take('guest-build/host-controller.log', controller['log_sha256']) == CONTROLLER and
         take('guest-build/host-runner.log', runner['log_sha256']) == RUNNER, 'actual original model log verdict')
    take('guest-build/host-controller-sanitize', controller['artifact_sha256'])
    take('guest-build/host-runner-sanitize', runner['artifact_sha256'])
    take('guest-build/runner-build.log')
    invocation = json_data(take('builder-invocation.json', limit=65536))
    need(type(invocation.get('schema')) is int and invocation['schema'] == 1 and
         invocation.get('command') == guest_command(stage) and type(invocation.get('returncode')) is int and
         invocation['returncode'] == 0 and invocation.get('timed_out') is False and
         invocation.get('deadline_seconds') == 420 and invocation.get('owned_process_group') is True,
         'actual approved own builder invocation required')
    stdout = take('builder-stdout.log', invocation['log_sha256'])
    notice = json_data(stdout)
    need(notice.get('status') == 'PASS' and notice.get('receipt') == str(stage / 'guest-build/build-result.json') and
         notice.get('receipt_sha256') == members['guest-build/build-result.json'] and notice.get('guest_verified') is False,
         'actual builder result notice')
    manifest = json_data(take('guest-build/guest-files.json', limit=65536))
    need(type(manifest.get('schema')) is int and manifest['schema'] == 1 and manifest.get('kind') == 'isolated-guest-file-inputs' and
         manifest.get('nonce') == NONCE and manifest.get('command') == PREFIX + 'T13RUN.EXE' and
         manifest.get('outputs') == [PREFIX + n for n in ('TLSDLL.LOG', 'T13RUN.LOG', 'TLSOUT.LOG')] and
         manifest.get('backups') == [] and manifest.get('guest_execution') == 'NOT-VERIFIED' and
         manifest.get('network_required') is False and manifest.get('source_receipts') == [dict(
         path=str(stage / 'guest-build/build-result.json'), sha256=members['guest-build/build-result.json'])],
         'original unmodified builder manifest')
    rows = manifest.get('inputs')
    need(isinstance(rows, list) and len(rows) == 8 and len({r.get('guest') for r in rows}) == 8,
         'distinct exact original manifest inputs')
    for name in sorted(INPUTS):
        expected = build['artifacts'][name]
        data = take('guest-build/' + name, expected['sha256'], 1 << 20)
        need(type(expected.get('bytes')) is int and expected['bytes'] == len(data), 'real guest input byte count')
        row = next((r for r in rows if r.get('guest') == PREFIX + name), None)
        need(row == dict(source=str(stage / 'guest-build' / name), guest=PREFIX + name,
                         bytes=len(data), sha256=sha(data)), 'exact original guest input metadata')
        take(name, sha(data), 1 << 20)
        if name in ('M98TLS13.DLL', 'M98TLS.DLL', 'TLSDLL.EXE', 'T13RUN.EXE'):
            exports = CLIENT_EXPORTS if name == 'M98TLS13.DLL' else SERVER_EXPORTS if name == 'M98TLS.DLL' else []
            raw = take('cpu/' + name + '.log')
            result[name] = raw_gate(data, raw, table, exports, installed, IMAGE_CHARACTERISTICS[name])
    need(result['M98TLS13.DLL']['sha256'] == tls['profiles']['latest-native']['sha256'] and
         result['M98TLS.DLL']['sha256'] == tls['profiles']['lts-native']['sha256'], 'only corrected DLL generation accepted')
    return build, result, members


def stage_authority(c, build, cpu, generated_members):
    return dict(schema=1, kind='tls13-i486-preparation-only', nonce=NONCE, approved=APPROVED,
        original_probe_source_authority_sha256=PROBE_AUTHORITY_SHA,
        guest_build_sha256=generated_members['guest-build/build-result.json'], source_sha256=c.sources,
        original_files=5978, original_aliases=147, actual_compiler_objects=471,
        original_successful_steps=978, previous_actual_host_cases=12, previous_endpoint_logs=24,
        current_controller_assertions=15, current_supervisor_assertions=2957, current_supervisor_scenarios=18,
        child_timeout_ms=120000, reap_timeout_ms=5000, cpu=cpu, **SCOPE)


def provenance(manifest_sha, authority_sha, c, generated_members):
    return dict(schema=1, kind='tls13-i486-closed-frozen-native-preparation', nonce=NONCE,
        manifest_sha256=pin(manifest_sha), stage_authority_sha256=pin(authority_sha), approved=APPROVED,
        source_sha256=c.sources, stage_sha256={**{n: h for n, (_, h) in c.copies.items()}, **generated_members},
        original_directories=sorted(member_of(Path(p)) for p in c.directories),
        original_aliases={member_of(Path(p)): dict(target=x['target'],
             normalized_target=member_of(Path(x['resolved_target'])), directory=x['directory'])
             for p, x in sorted(c.aliases.items())}, **SCOPE)


def check_stage(manifest_path, manifest_sha, stage_authority_sha, stage_provenance_sha, pins):
    approved_pins(pins)
    manifest_path = canonical(manifest_path)
    stage = manifest_path.parent
    need(stage == DESTINATION and manifest_path.name == 'guest-files.json', 'one exact canonical native preparation stage')
    prov_data = read(stage / 'provenance.json', PROVENANCE_LIMIT)
    need(sha(prov_data) == pin(stage_provenance_sha), 'unapproved independent provenance SHA')
    data = read(manifest_path, 65536)
    need(sha(data) == pin(manifest_sha), 'unapproved manifest SHA')
    manifest = json_data(data)
    need(isinstance(manifest, dict) and set(manifest) == {'schema', 'kind', 'inputs', 'outputs', 'backups',
         'nonce', 'command', 'source_receipts', 'guest_execution', 'network_required', 'scope'} and
         type(manifest.get('schema')) is int and manifest['schema'] == 1 and manifest.get('kind') == 'isolated-guest-file-inputs' and
         manifest.get('nonce') == NONCE and manifest.get('command') == PREFIX + 'T13RUN.EXE' and
         manifest.get('outputs') == [PREFIX + n for n in sorted(OUTPUTS)] and manifest.get('backups') == [] and
         manifest.get('guest_execution') == 'NOT-VERIFIED' and manifest.get('network_required') is False and
         manifest.get('scope') == 'Corrected original latest/LTS DLL preparation only; no WinSock/OS/apps acceptance',
         'exact original offline guest paths/nonce/scope')
    authority_data = read(stage / 'stage-authority.json', 2 << 20)
    need(sha(authority_data) == pin(stage_authority_sha), 'unapproved stage authority SHA')
    rows = manifest.get('source_receipts')
    need(rows == [dict(path=str(stage / 'stage-authority.json'), sha256=stage_authority_sha)],
         'independently approved preparation authority binding')
    builds, old_cpu, installed, table, c = collect(pins, stage)
    build, cpu, members = generated(stage, c, table, installed)
    need(same(json_data(authority_data), stage_authority(c, build, cpu, members)), 'stage authority source/CPU/scope drift')
    members['stage-authority.json'] = stage_authority_sha
    need(same(json_data(prov_data), provenance(manifest_sha, stage_authority_sha, c, members)),
         'complete independently approved provenance closure drift')
    rows = manifest.get('inputs')
    need(isinstance(rows, list) and len(rows) == 8 and
         all(isinstance(row, dict) and set(row) == {'source', 'guest', 'bytes', 'sha256'} for row in rows),
         'exact bounded final input list')
    expected = [dict(source=str(stage / name), guest=PREFIX + name,
                     bytes=len(read(stage / name, 1 << 20)), sha256=members[name]) for name in sorted(INPUTS)]
    need(rows == expected and all(type(row['bytes']) is int for row in rows), 'final actual input path/size/hash binding')
    expected_files = set(c.copies) | set(members) | {'guest-files.json', 'provenance.json'} | {
                     member_of(Path(p)) for p in c.aliases}
    actual_files = set()
    actual_dirs = set()
    for parent, dirs, files in os.walk(stage, followlinks=False):
        for name in list(dirs):
            p = Path(parent) / name
            if p.is_symlink():
                actual_files.add(str(p.relative_to(stage)))
                dirs.remove(name)
            else:
                need(canonical(p).is_dir(), 'noncanonical physical stage directory')
                actual_dirs.add(str(p.relative_to(stage)))
        actual_files.update(str((Path(parent) / n).relative_to(stage)) for n in files)
    need(actual_files == expected_files, 'unexpected or missing stage file/alias closure')
    expected_dirs = {str(p) for n in expected_files for p in Path(n).parents if str(p) != '.'} | {
                     member_of(Path(p)) for p in c.directories}
    need(actual_dirs == expected_dirs, 'unexpected or missing stage directory topology')
    total = sum(len(read(stage / n)) for n in expected_files - {member_of(Path(p)) for p in c.aliases})
    need(total <= MAX_STAGE, 'whole native preparation including metadata bound')
    c.unchanged()
    for name, digest in members.items():
        need(sha(read(stage / name)) == digest, 'late generated preparation drift')
    need(read(manifest_path, 65536) == data and read(stage / 'provenance.json', PROVENANCE_LIMIT) == prov_data and
         read(stage / 'stage-authority.json', 2 << 20) == authority_data, 'late manifest/provenance/authority drift')
    c.live_unchanged()
    return dict(passed=True, stage=str(stage), manifest_sha256=manifest_sha,
        stage_authority_sha256=stage_authority_sha, stage_provenance_sha256=stage_provenance_sha,
        regular_members=len(expected_files) - 147, aliases=147, bytes=total, source_files=len(c.sources),
        cpu={name: x['instructions_decoded'] for name, x in cpu.items()}, **SCOPE)
