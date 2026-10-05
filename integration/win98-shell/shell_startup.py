#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Offline Windows98 original-shell startup adapter; never boots or attests Windows.

Input is one explicit, pinned private FAT disk image holding an installed
Windows98 tree (the private source disk, or a `replacement.img` produced by
shizukudos/win98_boot/prepare_replacement.py on the default
`shz.foundation=win98` route), plus the pinned SHZTHEME.EXE built by
ntwddm/win98/theme_selector/build.py from selector_win98.c + selector_core.c.
Output is ONLY a fresh candidate directory with a new copy of that disk. The
adapter:

* requires SYSTEM.INI `[boot] shell=Explorer.exe` and never edits SYSTEM.INI;
* requires the installed original Explorer/USER/GDI/KERNEL userland members and
  refuses when any is absent (no SHZDESK or other substitute desktop);
* stages SHZTHEME.EXE at exactly C:\\SHIZUKU\\SHZTHEME.EXE so that the selector's
  own transactional HKCU Run registration (written only after an explicit user
  selection) is `"C:\\SHIZUKU\\SHZTHEME.EXE" /restore`;
* optionally stages the appearance app and its M98THEME.DLL provider with NO
  startup entry, so nothing pops up at logon;
* leaves WIN.INI, SYSTEM.INI, SYSTEM.DAT and USER.DAT byte-identical. WIN.INI
  `run=` is an argument-free program list on the project's verified route, so
  `C:\\SHIZUKU\\SHZTHEME.EXE /restore` cannot be carried there: the split first
  token would open the selector UI and `/restore` would be launched as a file.

No profile, Run value or palette is created. Every Windows/runtime/boot flag in
the receipt is false. File hashes and PE headers are identity/static
observations, not build, authenticity, version or execution evidence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT/rel)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


# Existing default-route helpers: leased pinned inputs, independent FAT reader,
# geometry, copy, mtools runner, MSDOS.SYS path selection and private writes.
replacement = _load('shell_startup_replacement', 'shizukudos/win98_boot/prepare_replacement.py')
source_profile = _load('shell_startup_source_profile', 'shizukudos/install/win98_source_profile.py')
need = replacement.need

MAX_INI = 64 << 10
MAX_RECEIPT = 1 << 20
COMPANION_DIR = 'SHIZUKU'
SELECTOR_GUEST = 'SHZTHEME.EXE'        # 8.3 already; the native Run value derives from this path.
SELECTOR_PATH = 'C:\\' + COMPANION_DIR + '\\' + SELECTOR_GUEST
STARTUP_COMMAND = SELECTOR_PATH + ' /restore'
# Exactly what shz_theme_startup_value() builds from GetModuleFileNameA().
SELECTOR_RUN_VALUE = '"' + SELECTOR_PATH + '" /restore'
RUN_KEY = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
RUN_NAME = 'ShizukuOSTheme'
PROFILE_VALUE = 'HKEY_CURRENT_USER\\Software\\ShizukuOS\\Theme\\Profile'
APPEARANCE_GUEST = 'SHZAPPR.EXE'      # SHZAPPEAR.EXE is not 8.3; keep a fixed short name.
THEME_GUEST = 'M98THEME.DLL'           # SHZAPPEAR loads this exact adjacent name.
# Names whose presence in WIN.INI load=/run= would mean a substitute desktop or
# an existing logon popup/duplicate companion start.
FORBIDDEN_STARTUP = (b'shzdesk', b'shzappr', b'shzappear', b'shztheme')
SELECTOR_SOURCES = ('ntwddm/win98/theme_selector/selector_core.h',
                    'ntwddm/win98/theme_selector/selector_core.c',
                    'ntwddm/win98/theme_selector/selector_win98.c',
                    'platform/freestanding/memory.c')
# Original Windows98 userland that must already be installed. Kind: PE (PE32
# i386), NE (Win16), MZ (DOS/VxD container), DATA (nonempty).
ORIGINAL_USERLAND = (
    ('EXPLORER.EXE', 'PE'), ('WIN.COM', 'DATA'), ('SYSTEM.INI', 'DATA'), ('WIN.INI', 'DATA'),
    ('SYSTEM.DAT', 'DATA'), ('USER.DAT', 'DATA'),
    ('SYSTEM/VMM32.VXD', 'MZ'), ('SYSTEM/KRNL386.EXE', 'NE'), ('SYSTEM/USER.EXE', 'NE'),
    ('SYSTEM/GDI.EXE', 'NE'), ('SYSTEM/KERNEL32.DLL', 'PE'), ('SYSTEM/USER32.DLL', 'PE'),
    ('SYSTEM/GDI32.DLL', 'PE'), ('SYSTEM/ADVAPI32.DLL', 'PE'), ('SYSTEM/SHELL32.DLL', 'PE'),
    ('SYSTEM/COMCTL32.DLL', 'PE'),
)


def ini_lines(data, label):
    """Bounded byte-preserving INI view; ANSI text is never re-encoded."""
    need(isinstance(data, bytes) and 0 < len(data) <= MAX_INI, label+' must be bounded nonempty bytes')
    need(b'\x00' not in data and b'\x1a' not in data and
         not data.startswith((b'\xff\xfe', b'\xfe\xff', b'\xef\xbb\xbf')), label+' encoding/EOF markers are ambiguous')
    need(not re.search(rb'\r(?!\n)', data), 'lone CR in '+label)
    section, offset, sections = None, 0, {}
    for line in data.splitlines(keepends=True):
        body = line.rstrip(b'\r\n'); stripped = body.strip(b' \t')
        if stripped and not stripped.startswith(b';'):
            if stripped.startswith(b'['):
                match = re.fullmatch(rb'\[([^\[\]]+)\]', stripped)
                need(match is not None, 'ambiguous section header in '+label)
                section = match[1].strip(b' \t').lower()
                sections[section] = sections.get(section, 0)+1
            elif section is not None:
                left, separator, right = body.partition(b'=')
                if separator:
                    yield section, left.strip(b' \t').lower(), right.strip(b' \t'), offset+len(left)+1, right
        offset += len(line)
    need(all(count == 1 for count in sections.values()), 'duplicate INI section in '+label)


def original_shell(system_ini, windows):
    """Require the original Explorer shell; any other shell is refused."""
    rows = list(ini_lines(system_ini, 'SYSTEM.INI'))
    shells = [value for section, key, value, *_ in rows if section == b'boot' and key == b'shell']
    need(len(shells) == 1, 'exactly one SYSTEM.INI [boot] shell= required')
    accepted = {b'explorer.exe', ('c:\\'+windows+'\\explorer.exe').lower().encode()}
    need(shells[0].lower() in accepted,
         'SYSTEM.INI shell is not the original Explorer.exe; substitute desktops are refused')
    # Win9x does not need these, but if present they must name the original modules.
    for key, default in ((b'user.exe', b'user.exe'), (b'gdi.exe', b'gdi.exe'), (b'krnl386.exe', b'krnl386.exe')):
        values = [v for s, k, v, *_ in rows if s == b'boot' and k == key]
        need(all(v.lower() == default for v in values), 'SYSTEM.INI replaces original '+key.decode())
    return shells[0].decode('ascii')


def win_ini_startup(win_ini):
    """Observe, never edit, WIN.INI [windows] load=/run=; refuse popups and substitutes."""
    rows = list(ini_lines(win_ini, 'WIN.INI'))
    observed = {}
    for key in (b'load', b'run'):
        values = [r[2] for r in rows if r[0] == b'windows' and r[1] == key]
        need(len(values) <= 1, 'duplicate WIN.INI [windows] '+key.decode()+'=')
        need(not any(name in v.lower() for v in values for name in FORBIDDEN_STARTUP),
             'WIN.INI '+key.decode()+'= already starts a substitute desktop or Shizuku companion')
        # Lengths only: the owner's other startup programs are private and kept byte-identical.
        observed[key.decode()] = {'present': bool(values), 'value_bytes': len(values[0]) if values else 0}
    return observed


def selector_command_mode(line):
    """Python transcription of selector_core.c shz_theme_command_mode().

    0 = no-argument UI, 1 = exact /restore, -1 = refused. Used only to check the
    adapter's own constants; it is not the native parser and not runtime proof.
    """
    raw = line.encode('latin-1') if isinstance(line, str) else bytes(line)
    space = (0x20, 0x09); restore = b'/restore'; n = len(raw); i = 0
    if not n or n >= 1024: return -1
    while i < n and raw[i] in space: i += 1
    if i == n: return -1
    if raw[i] == 0x22:
        i += 1; start = i
        while i < n and raw[i] != 0x22:
            if raw[i] < 32: return -1
            i += 1
        if i == start or i == n: return -1
        i += 1
        if i < n and raw[i] not in space: return -1
    else:
        start = i
        while i < n and raw[i] not in space:
            if raw[i] == 0x22 or raw[i] < 32: return -1
            i += 1
        if i == start: return -1
    while i < n and raw[i] in space: i += 1
    if i == n: return 0
    if n-i < len(restore) or raw[i:i+len(restore)] != restore: return -1
    i += len(restore)
    while i < n and raw[i] in space: i += 1
    return 1 if i == n else -1


def startup_plan():
    """Exact startup hook, its product registration path, and what is NOT done."""
    need(selector_command_mode(STARTUP_COMMAND) == 1, 'startup hook must be the exact /restore mode')
    need(selector_command_mode(SELECTOR_RUN_VALUE) == 1, 'selector Run value must be the exact /restore mode')
    # Space/comma-separated WIN.INI run= would launch the first token without
    # arguments: that is the selector UI, i.e. a logon popup. Never use it here.
    need(selector_command_mode(STARTUP_COMMAND.split(' ')[0]) == 0, 'split-token analysis changed')
    need(len(SELECTOR_PATH) <= 248 and len(SELECTOR_RUN_VALUE)+1 <= 260, 'Run command bound exceeded')
    return {
        'hook_command': STARTUP_COMMAND, 'command_mode': 'restore', 'auto_popup': False,
        'registered_in_candidate': False, 'win_ini_run_used': False,
        'win_ini_run_refusal': 'WIN.INI [windows] run= is used only as an argument-free executable list on the '
                               'verified project route (tools/theme_startup_trial.py, SHZGBOOT); splitting '
                               + STARTUP_COMMAND + ' would start the selector UI and try to run /restore',
        'product_registration': {'writer': 'SHZTHEME.EXE after an explicit user selection (transactional, readback, rollback)',
                                 'key': RUN_KEY, 'value': RUN_NAME, 'type': 'REG_SZ', 'data': SELECTOR_RUN_VALUE,
                                 'written_by_adapter': False},
        'root_offline_hook': {'key': RUN_KEY, 'value': RUN_NAME, 'type': 'REG_SZ', 'data': STARTUP_COMMAND,
                              'applied': False,
                              'requires': 'root-owned offline Windows98 USER.DAT writer with readback; none exists in this tree'},
        'missing_profile_behavior': 'shz_theme_restore() reads ' + PROFILE_VALUE + '; absent/invalid fails before any '
                                    'palette write, exits 1 with OutputDebugStringA and writes no registry value',
        'initial_selection': 'separate explicit action: run ' + SELECTOR_PATH + ' with no arguments',
    }


def image_kind(data):
    """Header observation only: returns PE/NE/MZ, PE requires i386."""
    if len(data) < 64 or data[:2] != b'MZ':
        return None
    lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    if 64 <= lfanew <= len(data)-24:
        if data[lfanew:lfanew+4] == b'PE\0\0':
            return 'PE' if struct.unpack_from('<H', data, lfanew+4)[0] == 0x14c else 'PE-other'
        if data[lfanew:lfanew+2] == b'NE':
            return 'NE'
    return 'MZ'


def member_prefix(fd, geometry, row, check, limit=8192):
    volume = replacement.Volume(fd, geometry, check)
    need(row['cluster'] >= 2, 'member has no data cluster')
    out = bytearray()
    for number in volume.chain(row['cluster']):
        out += volume.cluster(number)
        if len(out) >= min(limit, row['bytes']):
            break
    return bytes(out[:min(limit, row['bytes'])])


def companion_pe(data, label):
    need(image_kind(data) == 'PE', label+' must be an i386 PE32 image')
    lfanew = struct.unpack_from('<I', data, 0x3c)[0]; opt = lfanew+24
    need(len(data) >= opt+72 and struct.unpack_from('<H', data, opt)[0] == 0x10b, label+' must be PE32')
    os_ver = struct.unpack_from('<HH', data, opt+40); subsystem = struct.unpack_from('<H', data, opt+68)[0]
    need(os_ver == (4, 10), label+' must target Windows 98 4.10')
    dll = bool(struct.unpack_from('<H', data, lfanew+22)[0] & 0x2000)
    return {'os_version': '4.10', 'subsystem': subsystem, 'dll': dll}


def selector_build_receipt(data, pin):
    """Bind either production builder's static receipt to this executable.

    A receipt never supplies native execution or installed-system evidence.
    """
    need(len(data) <= MAX_RECEIPT, 'selector build receipt exceeds bound')
    report = json.loads(data, object_pairs_hook=replacement.json_pairs)
    need(isinstance(report, dict) and report.get('schema') == 1,
         'selector build receipt is not schema 1')
    need(report.get('installation_performed') is False and report.get('native_win98_execution') == 'not_tested',
         'selector build receipt makes an unsupported install/runtime claim')
    if report.get('status') == 'PASS_STATIC_GATES_ONLY':
        component = report.get('components', {}).get('selector')
        need(isinstance(component, dict) and component.get('status') == 'PASS_STATIC_GATES_ONLY'
             and component.get('returncode') == 0, 'selective selector build did not succeed')
        exe, hashes = component.get('artifact'), component.get('source_sha256')
        gates = component.get('gates', {})
        gate = gates.get('native_gate')
        need(isinstance(gates.get('i486_scan'), dict) and gates['i486_scan'].get('status') == 'PASS',
             'selective selector receipt lacks the i486 gate')
        builder = 'integration/win98-shell/build_components.py'
    else:
        need(report.get('status') == 'PASS', 'selector build receipt is not PASS')
        exe, hashes = report.get('executable'), report.get('source_hashes')
        gate = exe.get('native_gate') if isinstance(exe, dict) else None
        builder = 'ntwddm/win98/theme_selector/build.py'
    need(isinstance(exe, dict) and exe.get('sha256') == pin['sha256'] and exe.get('bytes') == pin['bytes'],
         'selector build receipt names different executable bytes')
    need(isinstance(gate, dict) and gate.get('status') == 'PASS' and gate.get('role') == 'selector'
         and gate.get('native_execution_verified') is False, 'selector build receipt lacks the selector native gate')
    need(isinstance(hashes, dict), 'selector build receipt lacks source hashes')
    current = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in SELECTOR_SOURCES}
    matches = {n: hashes.get(n) == v for n, v in current.items()}
    need(all(matches.values()), 'selector production sources differ from the build receipt')
    return {'status': 'PASS_STATIC_GATES_ONLY', 'builder': builder,
            'host_tests': [h.get('kind') for h in report.get('host_tests', []) if isinstance(h, dict)],
            'source_hashes_match_this_tree': matches, 'native_win98_execution': 'not_tested'}


def selector_static_gate(path):
    """Existing OEM-import/relocation gate from the selector build owner."""
    build = _load('shell_startup_selector_build', 'ntwddm/win98/theme_selector/build.py')
    return build.native_gate(path, 'selector')


def observe(fd, geometry, check, windows):
    files = replacement.inventory(fd, geometry, check)
    need(len({n.upper() for n in files}) == len(files), 'case-ambiguous DOS short paths refused')
    source_profile.installed_paths(source_profile.member_bytes(fd, geometry, files, 'MSDOS.SYS', check), 'C:\\'+windows)
    need(files.get(windows+'/SYSTEM', {}).get('directory') is True, 'observed Windows SYSTEM directory required')
    observed = {}
    for rel, kind in ORIGINAL_USERLAND:
        name = windows+'/'+rel
        row = source_profile.require_file(files, name)
        if kind != 'DATA':
            actual = image_kind(member_prefix(fd, geometry, row, check))
            need(actual == kind, 'original userland member has wrong image format: %s (%s)' % (name, actual))
        observed[name] = {'bytes': row['bytes'], 'sha256': row['sha256'], 'format': kind}
    need(COMPANION_DIR not in files and not any(n.startswith(COMPANION_DIR+'/') for n in files),
         'C:\\SHIZUKU already exists; refusing to overwrite')
    system_ini = source_profile.member_bytes(fd, geometry, files, windows+'/SYSTEM.INI', check, MAX_INI)
    win_ini = source_profile.member_bytes(fd, geometry, files, windows+'/WIN.INI', check, MAX_INI)
    return files, observed, system_ini, win_ini


def prepare(disk, selector, windows, out, mode, copy_budget, capture_budget, *, selector_receipt=None,
            appearance=None, theme_dll=None, large_output_root=None):
    out = replacement.safe_path(out)
    replacement.private_output(out)
    if out.exists() or out.is_symlink(): raise FileExistsError(out)
    need(out.parent.is_dir(), 'fresh candidate output parent required')
    need(isinstance(windows, str) and re.fullmatch('[A-Z0-9_-]{1,8}', windows), 'explicit uppercase Windows short directory required')
    need((appearance is None) == (theme_dll is None), 'appearance app and M98THEME.DLL are staged together or not at all')
    pins = [p for p in (disk, selector, selector_receipt, appearance, theme_dll) if p is not None]
    for pin in pins: replacement.pin_fields(pin)
    need(len({p['path'] for p in pins}) == len(pins), 'distinct inputs required')
    need(selector['bytes'] <= 2 << 20, 'SHZTHEME.EXE exceeds bound')
    need(appearance is None or (appearance['bytes'] <= 2 << 20 and theme_dll['bytes'] <= 8 << 20), 'companion exceeds bound')
    plan = startup_plan()
    scope = replacement.large_output_scope(out, disk['bytes'], large_output_root)
    commands = []
    with replacement.leased_inputs(pins) as held:
        source = held[disk['path']]; fd = source['fd']
        def check():
            replacement.check_output_scope(scope); source['checkpoint']()
        def read(pin):
            entry = held[pin['path']]
            data = os.pread(entry['fd'], pin['bytes'], 0); entry['checkpoint']()
            need(len(data) == pin['bytes'] and replacement.digest(data) == pin['sha256'], pin['path']+' changed')
            return data
        mbr = os.pread(fd, 512, 0)
        active = [mbr[446+n*16:462+n*16] for n in range(4) if len(mbr) == 512 and mbr[446+n*16] == 0x80]
        need(len(active) == 1, 'exactly one active partition required')
        start = replacement.u32(active[0], 8)
        need(0 < start < disk['bytes']//512, 'active partition start exceeds disk')
        vbr = os.pread(fd, 512, start*512)
        geometry = replacement.inspect_geometry(mbr, vbr, disk['bytes'])
        before, observed, system_ini, win_ini = observe(fd, geometry, check, windows)
        shell = original_shell(system_ini, windows.lower())
        win_startup = win_ini_startup(win_ini)
        staged = {}
        data = read(selector); meta = companion_pe(data, 'SHZTHEME.EXE')
        need(meta['subsystem'] == 2 and not meta['dll'], 'SHZTHEME.EXE must be a GUI executable')
        evidence = {'identity': 'sha256 of the pinned bytes; not build or runtime proof',
                    'host_build_receipt': None, 'static_native_gate': None, 'native_execution_verified': False}
        if selector_receipt is not None:
            evidence['host_build_receipt'] = {**selector_receipt, **selector_build_receipt(read(selector_receipt), selector)}
        staged[SELECTOR_GUEST] = (data, selector, {'source_label': 'SHZTHEME.EXE', **meta, 'evidence': evidence})
        if appearance is not None:
            app, dll = read(appearance), read(theme_dll)
            app_meta, dll_meta = companion_pe(app, 'SHZAPPEAR.EXE'), companion_pe(dll, 'M98THEME.DLL')
            need(app_meta['subsystem'] == 2 and not app_meta['dll'], 'SHZAPPEAR.EXE must be a GUI executable')
            need(dll_meta['dll'], 'M98THEME.DLL must be a DLL')
            staged[APPEARANCE_GUEST] = (app, appearance, {'source_label': 'SHZAPPEAR.EXE', **app_meta, 'startup_entry': None})
            staged[THEME_GUEST] = (dll, theme_dll, {'source_label': 'M98THEME.DLL', **dll_meta, 'startup_entry': None,
                                                    'scope': 'app-local provider; does not style Explorer'})
        replacement.capacity(out.parent, (disk['bytes'] if mode == 'full' else 16 << 20)+(16 << 20), capture_budget)
        replacement.check_output_scope(scope)
        out.mkdir(mode=0o700)
        target = out/'candidate.img'
        result = {'schema': 'shizukuos.win98-shell-startup-candidate.v2', 'status': 'FAIL',
                  'public_artifact': False, 'Windows98_boot_verified': False, 'Explorer_executed': False,
                  'original_userland_authenticity_verified': False, 'selector_executed': False,
                  'companion_executed': False, 'VM_executed': False, 'live_original_media_written': False,
                  'host_registry_written': False, 'registry_edited': False, 'system_ini_modified': False,
                  'win_ini_modified': False, 'theme_profile_created': False, 'run_value_written': False,
                  'system_palette_changed': False,
                  'shell': {'system_ini_boot_shell': shell, 'replaced': False},
                  'source_disk': disk, 'windows_directory': 'C:\\'+windows, 'geometry': geometry,
                  'observed_original_userland': observed, 'win_ini_startup_observed': win_startup,
                  'staged': {COMPANION_DIR+'/'+g: {**p, **m} for g, (_, p, m) in staged.items()},
                  'startup': plan}
        stage = out/'payloads'; stage.mkdir(mode=0o700)
        for guest, (data, _, _) in staged.items():
            source_profile.write_private(stage/guest, data)
        # The selector owner's own static OEM import/relocation gate, on the
        # private staged copy, before any disk copy; bytes are rechecked after.
        evidence['static_native_gate'] = selector_static_gate(stage/SELECTOR_GUEST)
        need(replacement.digest((stage/SELECTOR_GUEST).read_bytes()) == selector['sha256'], 'staged selector changed')
        result['copy'] = replacement.copy_disk(source, target, mode, copy_budget, capture_budget)
        image = str(target)+'@@'+str(start*512)
        replacement.run_tool('mmd', ['-i', image, '::'+COMPANION_DIR], commands); check()
        for guest in staged:
            replacement.run_tool('mcopy', ['-i', image, stage/guest, '::'+COMPANION_DIR+'/'+guest], commands); check()
        with target.open('rb') as handle:
            hfd = handle.fileno()
            need(os.fstat(hfd).st_size == disk['bytes'], 'candidate extent changed')
            need(os.pread(hfd, 512, 0) == mbr and os.pread(hfd, 512, start*512) == vbr, 'candidate MBR/VBR changed')
            after = replacement.inventory(hfd, geometry)
            new = {COMPANION_DIR, *(COMPANION_DIR+'/'+g for g in staged)}
            need(set(after)-set(before) == new, 'unexpected candidate members created')
            for name, row in before.items():
                need(after.get(name) == row, 'original member changed in candidate: '+name)
            need(after[COMPANION_DIR].get('directory') is True, 'companion directory absent')
            for guest, (_, pin, _) in staged.items():
                row = after[COMPANION_DIR+'/'+guest]
                need(row['bytes'] == pin['bytes'] and row['sha256'] == pin['sha256'], 'staged readback differs: '+guest)
            for name, original in (('SYSTEM.INI', system_ini), ('WIN.INI', win_ini)):
                again = source_profile.member_bytes(hfd, geometry, after, windows+'/'+name, lambda: None, MAX_INI)
                need(again == original, 'candidate '+name+' changed')
            need(original_shell(system_ini, windows.lower()) == shell, 'candidate shell changed')
            result['candidate'] = {'path': str(target), 'bytes': disk['bytes'],
                                   'sha256': replacement.hash_fd(hfd, disk['bytes'])}
        need(replacement.hash_fd(fd, disk['bytes'], check) == disk['sha256'], 'source disk changed')
        for entry in held.values(): entry['checkpoint']()
        result.update(status='PRIVATE_WIN98_SHELL_STARTUP_CANDIDATE_PREPARED_NOT_BOOTED', commands=commands,
                      unchanged_original_members=len(before))
    raw = (json.dumps(result, indent=2)+'\n').encode()
    source_profile.publish(out/'shell-startup.json', raw)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument('--disk', type=Path, required=True); ap.add_argument('--disk-sha256', required=True)
    ap.add_argument('--selector', type=Path, required=True, help='SHZTHEME.EXE from ntwddm/win98/theme_selector/build.py')
    ap.add_argument('--selector-sha256', required=True)
    ap.add_argument('--selector-build-receipt', type=Path, help='that build run\'s result.json')
    ap.add_argument('--selector-build-receipt-sha256')
    for name in ('appearance', 'theme-dll'):
        ap.add_argument('--'+name, type=Path); ap.add_argument('--'+name+'-sha256')
    ap.add_argument('--windows-directory', default='WINDOWS')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--copy-mode', choices=('reflink', 'full'), required=True)
    ap.add_argument('--copy-budget-bytes', type=int, required=True)
    ap.add_argument('--capture-budget-bytes', type=int, required=True)
    ap.add_argument('--large-private-output-root', type=Path)
    a = ap.parse_args()
    def optional(path, sha, label):
        need((path is None) == (sha is None), label+' path and SHA256 are given together')
        return None if path is None else replacement.recorded_pin(path, sha)
    # local_pin is bounded to 64 MiB; the disk pin is the literal size plus the
    # operator's SHA, which leased_inputs() rehashes under a read lease.
    disk = replacement.safe_path(a.disk)
    result = prepare({'path': str(disk), 'bytes': disk.stat().st_size, 'sha256': a.disk_sha256},
                     replacement.recorded_pin(a.selector, a.selector_sha256), a.windows_directory, a.out,
                     a.copy_mode, a.copy_budget_bytes, a.capture_budget_bytes,
                     selector_receipt=optional(a.selector_build_receipt, a.selector_build_receipt_sha256, 'selector build receipt'),
                     appearance=optional(a.appearance, a.appearance_sha256, 'appearance'),
                     theme_dll=optional(a.theme_dll, a.theme_dll_sha256, 'M98THEME.DLL'),
                     large_output_root=a.large_private_output_root)
    print(json.dumps({'status': result['status'], 'candidate': result['candidate'],
                      'startup_hook': STARTUP_COMMAND, 'startup_registered_in_candidate': False,
                      'Windows98_boot_verified': False}))


if __name__ == '__main__':
    main()
