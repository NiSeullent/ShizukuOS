#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guarded Windows 98 -> Shizuku64 connection handoff: stage a private guest disk, verify evidence.

This leaf never launches QEMU and never touches the shared runners. Root runs the
owned native VM through the ACTIVE producer chain (shizukudos/supervisor/native_win98/build.py ->
prepare_vm.py -> run_vm.py under task_custody.py; the frozen-preimage tools/build_win98_supervisor_candidate.py
is historical and NOT used). Subcommands:

  plan    print the exact root sequence and the evidence contract (no side effects)
  stage   copy a pinned private Win98 baseline, inject the pinned NTWRAP9X.VXD, NTW32.DLL,
          NTW64RUN.EXE, NTW64GUI.EXE plus a generated W64RUN.BAT into C:\\VXDLAB and register it
          through WIN.INI run= (executed by the real Win98 shell). Requires --i-own-this-vm.
  verify  after root's VM run, extract the guest disk from the owned esp.img and parse the
          evidence the guest itself produced (batch exit-code ladder, ver, /q, T_HELLO output)
          together with the Supervisor receipt. Success needs every required parsed line.
  combine require connected + no-bridge + revoked + foreign verdicts with distinct exit codes.

There is no skip flag, no pre-set pass and no pass derived from QEMU/exit status. Missing
evidence yields INCOMPLETE or FAIL. stderr text of NTW64RUN is not captured because Win98
command.com cannot redirect handle 2; the distinct exit codes 254/253/252 are the evidence.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUEST_DIR = 'VXDLAB'
GUEST_DIR_WIN = 'C:\\VXDLAB'
BAT = 'W64RUN.BAT'
HELLO_IMAGE = '\\SHZ\\TESTS\\T_HELLO.EXE'          # built into the Kernel64 initrd by shizukudos/win64/build.py
HELLO_LINE = 'hello from Win64 PE32+: argc=2 argv1=first'
HELLO_EXIT = 7
RUN_UNAVAILABLE, RUN_DENIED, RUN_REVOKED = 254, 253, 252   # ntwin32/win64/ntw64run.c
DISK_BYTES = 2 << 30
INPUTS = ('vxd', 'ntw32', 'ntw64run', 'ntw64gui')
GUEST_NAMES = {'vxd': 'NTWRAP9X.VXD', 'ntw32': 'NTW32.DLL', 'ntw64run': 'NTW64RUN.EXE', 'ntw64gui': 'NTW64GUI.EXE'}
PROFILES = {
    # profile: (K64 domain must exist, expected /q exit or None, expected HELLO exit)
    'connected': (True, 0, HELLO_EXIT),
    'no-bridge': (False, RUN_UNAVAILABLE, RUN_UNAVAILABLE),
    'revoked-channel': (True, None, RUN_REVOKED),
    'foreign-owner': (True, None, RUN_DENIED),
}
SUPERVISOR_FLAGS_NATIVE_WIN98 = 1      # SHZ_LOADER_NATIVE_WIN98; bit 2 (K64_DISPLAY) must NOT be set

NW = 'shizukudos/supervisor/native_win98'
ROOT_SEQUENCE = [
    '0. K32/K64/WIN64.IMG (supervised, one profile build; reuse a root fast-boot tree ONLY if every consumed source closure hash is unchanged -- '
    'the recorded KERNEL32.BIN 8e6d4769.../KERNEL64.BIN bb7e072a... in the private note are the OLD 48a-era build and must NOT be reused): '
    'python3 shizukudos/kbuild.py --out <fresh>/kbuild  (KERNEL32.BIN + supervisor KERNEL64.BIN, NOT KERNEL64S.BIN) and '
    'python3 shizukudos/win64/build.py  (WIN64.IMG with \\SHZ\\TESTS\\T_HELLO.EXE, <= 32 MiB). Record each sha256 yourself after the build. '
    'Root also holds the read lease on the private baseline externally for steps 1-8: `stage` takes NO lease (plain pinned reads).',
    '1. stage (this tool): python3 tools/run_w98w64_connection.py stage --i-own-this-vm --baseline-disk <private 0400 2 GiB raw> '
    '--baseline-sha256 H --vxd/--ntw32/--ntw64run/--ntw64gui PATH + --*-sha256 --out <fresh>/stage [--gui-image ...] '
    '-> win98-w64-injected.img (reflink/2 GiB copy, original untouched) + stage-receipt.json (injected_disk_sha256).',
    '2. original observer (tools/native_original_userland.py) OVER THE INJECTED DISK: request JSON schema shizukuos.original-userland-profile-request.v1 '
    'with source_disk = <stage>/win98-w64-injected.img (NOT the baseline: the guardian requires the intent/manifest DISK.IMG == profile source_disk), '
    'windows_directory WINDOWS, boot_policy shz.foundation=win98, producer_inputs = tools/native_original_userland.py + shizukudos/win98_boot/prepare_replacement.py '
    '(exact bytes/sha256); then python3 tools/native_original_userland.py --request <req.json> --request-sha256 H --out <0700 fresh parent>/profile '
    '(-> original-userland-profile.json). The injected disk MUST NOT change after the profile is made (no re-stage, no mount, no edit); re-stage means re-observe.',
    '3. config pin: python3 %s/build.py --make-config <fresh>/WIN98CFG.BIN  (prints bytes/sha256; 16-byte public opt-in, no authority).' % NW,
    'ROUTE SELECTION (task_custody.py main; two different manifests, never mix them):',
    '  3a CONSOLE-FIRST, no write-back: manifest schema shizukuos.native-original-userland-custody-manifest.v1 = the ORIGINAL custody manifest with NO '
    'original_device_epoch and NO gop_cohort (fields: schema, plan, repo, sources, lineage=[1 profile pin], producers=[2 pins], limits, timeout 20..900). '
    'Root hand-runs build.py and prepare_vm.py (steps 4-5). Because W98PERS/VGA inputs are not admitted here, guest ATA writes stay in RAM: verify returns '
    'INCOMPLETE_NO_GUEST_EVIDENCE by design (see 8).',
    '  3b WRITE-BACK: manifest schema shizukuos.native-original-userland-epoch-intent.v1 (the epoch INTENT). The guardian itself runs build.py and prepare_vm.py inside '
    'its private_root, so SKIP the hand-run steps 4-5; verify then reads <private_root>/native/result.json and <private_root>/vm. The intent REQUIRES the source-built '
    'StdVGA pair (VGACFG.BIN + VGAROM.BIN via tools/build_stdvga_rom.py) and its vga-build-receipt (prepare_original_intent: optional inputs must contain both VGA files); '
    'W98PERS.BIN is optional ONLY inside this route and never without the StdVGA pair; raw_bars = literal BAR DWORDs (role 1 VGA, role 2 persistence only with W98PERS) taken '
    'from the native-epoch lane encoder / paused-probe recipe (.codex/lanes/native-epoch-b7.md, shizukudos/supervisor/native_win98/NATIVE_EPOCH_HOST.md paused observation '
    'and ORIGINAL_USERLAND_PHASE.md); the Attempt is minted in-process by the guardian, no CLI/file supplies it and a saved manifest carrying original_device_epoch is refused. '
    'Do not invent bar values.',
    '4. (3a only) validate then build: python3 %s/build.py --disk <injected> --disk-sha256 <stage injected_disk_sha256> --rom <seabios 256 KiB> --rom-sha256 R '
    '--config <WIN98CFG.BIN> --config-sha256 C --kernel32 <KERNEL32.BIN> --kernel32-sha256 K32 --kernel64 <supervisor KERNEL64.BIN> --kernel64-sha256 K64 '
    '--win64-img <WIN64.IMG> --win64-img-sha256 W --validate-only; then the same with --out <fresh>/native (add --assembly-scratch <owned tmpfs> if the 17 GiB reserve is tight). '
    'Result: <native>/result.json status PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN, members{SHZDOS/DISK.IMG,...}, artifact{path,bytes,sha256}, ESP <native>/esp-win98.img.' % NW,
    '5. (3a only) prepare: python3 %s/prepare_vm.py --esp <native>/esp-win98.img --esp-sha256 A --build-receipt <native>/result.json --build-receipt-sha256 B '
    '--firmware-code OVMF_CODE.fd --firmware-code-sha256 .. --firmware-vars OVMF_VARS.fd --firmware-vars-sha256 .. --qemu /usr/libexec/qemu-kvm --qemu-sha256 Q '
    '--out <fresh short>/vm  (CODE+VARS exactly 4 MiB; QMP socket path < 104 bytes). Writes <vm>/{esp.img,OVMF_*.fd,vm-plan.json}; never runs QEMU.' % NW,
    '6. run (root only, VM custody): python3 %s/task_custody.py --manifest <manifest.json> --manifest-sha256 H --guardian-unit <delegated systemd unit>; the guardian spawns '
    'run_vm.py (never run run_vm.py directly; --guardian-epoch is internal). Outputs <vm>/native-result.json, custody-result.json, serial.log, native-NNN.png, native-NNN-info.json. '
    'This tool never launches it.' % NW,
    '7. verify: python3 tools/run_w98w64_connection.py verify --i-own-this-vm --stage-receipt <stage>/stage-receipt.json '
    '--build-receipt <native>/result.json --run-dir <vm> --profile connected --out <fresh>/verdict. verify REQUIRES <vm>/custody-result.json '
    '(custody_admitted, owned_child_reaped, VM_executed) so a run outside the guardian cannot pass. First goal: /q connected + T_HELLO stdout + remote exit 7 from Win98.',
    '8. guest evidence in route 3a: there is none on disk. The ESP copy of DISK.IMG is the only place a guest write could land and without W98PERS it stays in guest RAM, so '
    'extracting <vm>/esp.img ::/SHZDOS/DISK.IMG after the guardian reaps the child (mcopy -i <vm>/esp.img ::/SHZDOS/DISK.IMG, exactly what verify does) yields an unchanged disk. '
    'Console-first evidence is then the real serial.log / native-NNN.png / native-NNN-info.json collected by owned_capture.py through run_vm.py (collection_verified), '
    'reviewed by root as boot-progress evidence only, NOT as a connected PASS. A PASS needs route 3b.',
    '9. negative controls (separate ESPs, same steps): no-bridge needs a K64 variant that does NOT announce a channel (build.py requires a K64 member, so the ESP still carries '
    'KERNEL64.BIN; the profile is unreachable until Core supplies such a K64 -- and verify currently expects no KERNEL64 domain, which that variant must satisfy); expect 254. '
    'revoked-channel expect 252; foreign-owner expect 253. The 252/253 triggers need a Core/VxD fixture that does not exist yet.',
    '10. GUI only after step 7 passes: stage --gui-image, root drives owned QMP input, verify --gui-expected-exit N; combine --verdict ... for the four console profiles.']
BLOCKED_INPUTS = {
    'W98PERS.BIN (192 B) / VGACFG.BIN (136 B) / VGAROM.BIN (64 KiB) / vga-build-receipt': (
        'build.py accepts them (--persistence-config, --vga-config, --vga-rom, --vga-build-receipt, each with -sha256; VGA trio all-or-none) but they are NOT hand-writable: '
        'W98PERS binds the observed PCI BDF + six raw BAR dwords of the owned virtio-blk ESP device and VGACFG the std-VGA BDF/LFB. The producer is task_custody.py with the '
        'original epoch intent (schema shizukuos.native-original-userland-epoch-intent.v1; ORIGINAL_EPOCH_INTENT_SCHEMA, prepare_original_intent, admit_manifest, main): it requires the '
        'StdVGA pair + vga-build-receipt, W98PERS optional; the Attempt is minted in-process. VGAROM + receipt come from tools/build_stdvga_rom.py --source .. --private-out .. --unit ... '
        'raw_bars come from the native-epoch lane encoder/paused-probe recipe (.codex/lanes/native-epoch-b7.md). Do not fabricate these bytes or any permission boolean.'),
    'consequence': 'console-first (original custody manifest, no epoch) has no write-back: the guest ATA writes stay in guest RAM and verify returns INCOMPLETE_NO_GUEST_EVIDENCE (disk unchanged). '
                   'Serial/screendump/info.json from run_vm are real evidence of boot progress only.',
}


class Refuse(RuntimeError):
    pass


def need(cond, msg):
    if not cond:
        raise Refuse(msg)


def sha256_path(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'regular file required: %s' % path)
        h = hashlib.sha256()
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                return h.hexdigest()
            h.update(block)
    finally:
        os.close(fd)


def pinned(path, digest, label, maximum=None):
    need(path.is_absolute() and path.resolve() == path, '%s: canonical absolute path required' % label)
    need(re.fullmatch('[0-9a-f]{64}', digest or ''), '%s: 64-hex sha256 required' % label)
    size = path.stat().st_size
    need(0 < size and (maximum is None or size <= maximum), '%s: size out of bounds' % label)
    need(sha256_path(path) == digest, '%s: sha256 mismatch' % label)
    return size


def tool(name):
    found = shutil.which(name)
    need(found, 'required host tool missing: ' + name)
    return found


def mtools(args, **kw):
    env = {**os.environ, 'MTOOLS_SKIP_CHECK': '1'}
    return subprocess.run(args, env=env, check=True, capture_output=True, timeout=80, **kw)


def partition_offset(disk):
    """First FAT32 primary partition (0x0b/0x0c), active preferred; returns (byte_offset, boot_sector_sha)."""
    with open(disk, 'rb') as f:
        mbr = f.read(512)
        need(len(mbr) == 512 and mbr[510:512] == b'\x55\xaa', 'MBR signature missing')
        rows = []
        for i in range(4):
            e = mbr[446 + 16 * i: 462 + 16 * i]
            kind, start, count = e[4], struct.unpack('<I', e[8:12])[0], struct.unpack('<I', e[12:16])[0]
            if kind in (0x0b, 0x0c) and start and count:
                rows.append((e[0] == 0x80, start, count))
        need(rows, 'no FAT32 primary partition')
        _, start, count = max(rows)
        need((start + count) * 512 <= os.stat(disk).st_size, 'partition exceeds disk')
        f.seek(start * 512)
        boot = f.read(512)
    return start * 512, hashlib.sha256(mbr).hexdigest(), hashlib.sha256(boot).hexdigest()


def exact_ladder(label, command, codes):
    """Exact-code ladder: for each wanted code N, `if errorlevel N if not errorlevel N+1`."""
    wanted = sorted((set(codes) | {RUN_UNAVAILABLE, RUN_DENIED, RUN_REVOKED, 255}) - {0})
    lines = [command]
    for c in wanted:
        lines.append('if errorlevel %d if not errorlevel %d goto %s_%d' % (c, c + 1, label, c) if c < 255
                     else 'if errorlevel 255 goto %s_255' % label)
    lines.append('if errorlevel 1 goto %s_OTHER' % label)
    lines.append('echo RC_%s=0>>RESULT.LOG' % label)
    lines.append('goto %s_END' % label)
    for c in wanted:
        lines += [':%s_%d' % (label, c), 'echo RC_%s=%d>>RESULT.LOG' % (label, c), 'goto %s_END' % label]
    lines += [':%s_OTHER' % label, 'echo RC_%s=OTHER>>RESULT.LOG' % label, ':%s_END' % label]
    return lines


def batch_text(gui_image):
    lines = ['@echo off', 'cd \\VXDLAB',
             'ver>VER.LOG',                               # the real command.com prints the Windows 98 banner
             'echo SHELLUP>>RESULT.LOG']                  # reached only through the shell's WIN.INI run= entry
    lines += exact_ladder('Q', 'NTW64RUN.EXE /q>Q.LOG', [0, HELLO_EXIT])
    lines += exact_ladder('HELLO', 'NTW64RUN.EXE %s first>HELLO.LOG' % HELLO_IMAGE, [HELLO_EXIT])
    if gui_image:
        lines += exact_ladder('GUI', 'NTW64GUI.EXE %s' % gui_image, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    lines += ['echo DONE>>RESULT.LOG', 'exit']
    return ('\r\n'.join(lines) + '\r\n').encode('ascii')


def describe(a):
    return {
        'status': 'PLAN_ONLY_NOTHING_EXECUTED',
        'root_sequence': ROOT_SEQUENCE,
        'blocked_inputs': BLOCKED_INPUTS,
        'guest_files': {GUEST_DIR_WIN + '\\' + n: k for k, n in GUEST_NAMES.items()} | {GUEST_DIR_WIN + '\\' + BAT: 'generated'},
        'win_ini': 'run=%s\\%s added to [windows] (refused if a run= value already exists)' % (GUEST_DIR_WIN, BAT),
        'guest_logs_parsed': ['RESULT.LOG', 'VER.LOG', 'Q.LOG', 'HELLO.LOG'],
        'expected_exit_codes': {k: {'q': v[1], 'hello': v[2], 'kernel64_domain': v[0]} for k, v in PROFILES.items()},
        'supervisor_requirements': {'loader_flags': SUPERVISOR_FLAGS_NATIVE_WIN98, 'boot_path': 1,
                                    'guest_ram': 128 << 20, 'disk': DISK_BYTES, 'WIN98_domain_exits_gt0': True,
                                    'KERNEL64_domain': 'present and not failed (connected/revoked/foreign); absent (no-bridge)'},
        'batch_preview': batch_text(a.gui_image).decode().splitlines(),
        'never': ['launches QEMU', 'sets a pass without parsed guest lines', 'edits the original baseline'],
    }


def cmd_plan(a):
    print(json.dumps(describe(a), indent=2))
    return 0


def cmd_stage(a):
    plan = describe(a)
    if a.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    need(a.i_own_this_vm, '--i-own-this-vm is required to stage')
    need(a.out is not None and a.out.is_absolute() and not a.out.exists() and a.out.parent.is_dir(), 'fresh absolute --out with existing parent required')
    need(a.baseline_disk is not None and a.baseline_sha256, '--baseline-disk and --baseline-sha256 required')
    for name in ('mcopy', 'mdir', 'mmd'):
        tool(name)
    pins = {}
    pins['baseline'] = pinned(a.baseline_disk, a.baseline_sha256, 'baseline', DISK_BYTES)
    need(pins['baseline'] == DISK_BYTES, 'baseline must be exactly 2 GiB raw')
    sources = {}
    for k in INPUTS:
        p, h = getattr(a, k), getattr(a, k + '_sha256')
        need(p is not None, '--%s required' % k)
        pinned(p, h, k, 8 << 20)
        sources[k] = (p, h)
    need(shutil.disk_usage(a.out.parent).free > (DISK_BYTES + (4 << 30)), 'insufficient free space for the 2 GiB copy plus reserve')
    a.out.mkdir(mode=0o700)
    disk = a.out / 'win98-w64-injected.img'
    subprocess.run(['cp', '--reflink=auto', '--', str(a.baseline_disk), str(disk)], check=True, timeout=85)
    os.chmod(disk, 0o600)
    need(sha256_path(disk) == a.baseline_sha256, 'private copy differs from the pinned baseline')
    off, mbr_sha, boot_sha = partition_offset(disk)
    spec = '%s@@%d' % (disk, off)
    probe = mtools(['mdir', '-i', spec, '::/'], text=True).stdout
    if not re.search(r'^\s*VXDLAB\b', probe, re.M):
        mtools(['mmd', '-i', spec, '::/' + GUEST_DIR])
    for n in list(GUEST_NAMES.values()) + [BAT, 'RESULT.LOG', 'VER.LOG', 'Q.LOG', 'HELLO.LOG']:
        found = subprocess.run(['mdir', '-i', spec, '::/%s/%s' % (GUEST_DIR, n)], capture_output=True,
                               env={**os.environ, 'MTOOLS_SKIP_CHECK': '1'})
        need(found.returncode != 0, 'guest path already exists, fresh evidence would be false: ' + n)
    bat = a.out / BAT
    bat.write_bytes(batch_text(a.gui_image))
    files = {GUEST_NAMES[k]: (sources[k][0], sources[k][1]) for k in INPUTS}
    files[BAT] = (bat, sha256_path(bat))
    receipt_files = {}
    for name, (src, digest) in files.items():
        mtools(['mcopy', '-o', '-i', spec, str(src), '::/%s/%s' % (GUEST_DIR, name)])
        back = a.out / ('readback-' + name)
        mtools(['mcopy', '-i', spec, '::/%s/%s' % (GUEST_DIR, name), str(back)])
        need(sha256_path(back) == digest, 'guest readback mismatch: ' + name)
        back.unlink()
        receipt_files[GUEST_DIR_WIN + '\\' + name] = digest
    # WIN.INI run= entry so the real shell starts the batch; refuse when something already runs.
    ini = a.out / 'WIN.INI.before'
    mtools(['mcopy', '-i', spec, '::/WINDOWS/WIN.INI', str(ini)])
    raw = ini.read_bytes()
    need(len(raw) < (1 << 20), 'WIN.INI too large')
    text = raw.decode('latin-1')
    m = re.search(r'^\[windows\][ \t]*\r?\n', text, re.I | re.M)
    need(m, 'WIN.INI has no [windows] section')
    section_end = re.search(r'^\[', text[m.end():], re.M)
    section = text[m.end(): m.end() + (section_end.start() if section_end else len(text))]
    need(not re.search(r'^run[ \t]*=[ \t]*\S', section, re.I | re.M), 'WIN.INI already has a run= value; refusing to overwrite')
    section2 = re.sub(r'^run[ \t]*=[ \t]*\r?\n', '', section, flags=re.I | re.M)
    new = text[:m.end()] + 'run=%s\\%s\r\n' % (GUEST_DIR_WIN, BAT) + section2 + text[m.end() + len(section):]
    ini_new = a.out / 'WIN.INI.after'
    ini_new.write_bytes(new.encode('latin-1'))
    mtools(['mcopy', '-o', '-i', spec, str(ini_new), '::/WINDOWS/WIN.INI'])
    check = a.out / 'WIN.INI.readback'
    mtools(['mcopy', '-i', spec, '::/WINDOWS/WIN.INI', str(check)])
    need(sha256_path(check) == sha256_path(ini_new), 'WIN.INI readback mismatch')
    off2, mbr2, boot2 = partition_offset(disk)
    need((off2, mbr2, boot2) == (off, mbr_sha, boot_sha), 'injection changed MBR/boot sector')
    receipt = {'schema': 'shizukuos.w98w64-stage.v1', 'status': 'STAGED_NOT_RUN', 'VM_executed': False,
               'private': True, 'baseline_sha256': a.baseline_sha256, 'injected_disk': str(disk),
               'injected_disk_sha256': sha256_path(disk), 'injected_disk_bytes': DISK_BYTES,
               'partition_offset': off, 'mbr_sha256': mbr_sha, 'boot_sector_sha256': boot_sha,
               'guest_files': receipt_files, 'win_ini_before_sha256': sha256_path(ini),
               'win_ini_after_sha256': sha256_path(ini_new), 'gui_image': a.gui_image,
               'runner_sha256': sha256_path(Path(__file__).resolve()),
               'claims': 'No VM executed; no Windows 98 boot, bridge or Win64 application established by staging.'}
    (a.out / 'stage-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'receipt': str(a.out / 'stage-receipt.json'),
                      'injected_disk_sha256': receipt['injected_disk_sha256']}))
    return 0


def parse_guest(logs, profile, gui_expected):
    """Pure parser over guest-produced text; returns (checks, evidence). Every check is a parsed fact."""
    k64, q_exit, hello_exit = PROFILES[profile]
    checks = []

    def add(name, ok, detail=''):
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})

    result = logs.get('RESULT.LOG', '')
    rc = {}
    for line in result.splitlines():
        m = re.fullmatch(r'RC_([A-Z]+)=(\d+|OTHER)\s*', line)
        if m:
            need(m.group(1) not in rc, 'duplicate stage record: ' + m.group(1))
            rc[m.group(1)] = m.group(2)
    lines = [l.strip() for l in result.splitlines()]
    add('shell started WIN.INI run= batch (SHELLUP once)', lines.count('SHELLUP') == 1)
    add('batch completed (DONE once)', lines.count('DONE') == 1)
    add('real command.com reports Windows 98', re.search(r'Windows 98', logs.get('VER.LOG', '')) is not None, logs.get('VER.LOG', '').strip())
    if q_exit is not None:
        add('/q exit code %d' % q_exit, rc.get('Q') == str(q_exit), str(rc.get('Q')))
    if profile == 'connected':
        q = logs.get('Q.LOG', '')
        add('/q reports WIN64 subsystem ABI/channel', re.search(r'WIN64 subsystem: ABI \d+\.\d+, subsystem \d+\.\d+, capabilities 0x[0-9a-f]+', q) and
            re.search(r'channel \d+ generation \d+', q))
        hello_lines = [l.rstrip('\r') for l in logs.get('HELLO.LOG', '').splitlines()]
        add('T_HELLO stdout relayed to Win98 file', HELLO_LINE in hello_lines, repr(logs.get('HELLO.LOG', '')[:120]))
    else:
        add('no Win64 output on a failed bridge', HELLO_LINE not in logs.get('HELLO.LOG', ''))
    add('T_HELLO exit code %d' % hello_exit, rc.get('HELLO') == str(hello_exit), str(rc.get('HELLO')))
    if gui_expected is not None:
        add('GUI PE64 exited with the expected input-driven code %d' % gui_expected, rc.get('GUI') == str(gui_expected), str(rc.get('GUI')))
    return checks, rc


def supervisor_checks(rec, profile):
    k64 = PROFILES[profile][0]
    info = rec.get('last_info') or {}
    doms = info.get('domains', {})
    c = []

    def add(name, ok, detail=''):
        c.append({'name': name, 'ok': bool(ok), 'detail': detail})

    add('native Win98 loader flag exactly 1, UEFI boot_path 1', info.get('loader_flags') == SUPERVISOR_FLAGS_NATIVE_WIN98 and info.get('boot_path') == 1)
    add('128 MiB guest / 2 GiB disk geometry', info.get('guest_ram_size') == 128 << 20 and info.get('disk_size') == DISK_BYTES)
    add('Supervisor not in failure stage', info.get('stage') not in (None, 0xdead), str(info.get('stage_name')))
    w = doms.get('WIN98') or {}
    add('WIN98 domain executed and not failed', w.get('exits', 0) > 0 and w.get('state') != 4 and not w.get('error'), str(w))
    k = doms.get('KERNEL64')
    if k64:
        add('KERNEL64 domain present and not failed', k is not None and k.get('state') != 4 and not k.get('error'), str(k))
    else:
        add('no KERNEL64 channel peer in this profile', k is None, str(k))
    add('run_vm native-result: VM executed, collection verified, receipt persisted, leases intact',
        rec.get('VM_executed') is True and rec.get('collection_verified') is True and rec.get('receipt_persisted') is True and
        rec.get('lease_integrity_verified') is True and rec.get('status') != 'NATIVE_CAPTURE_HARNESS_FAILED', str(rec.get('status')))
    add('QEMU exit 0, no forced cleanup', rec.get('qemu_exit_code') == 0 and not rec.get('forced_cleanup') and not rec.get('cleanup_errors'))
    add('original disk input unchanged (ESP copy took the guest writes)', rec.get('original_disk_unchanged') is True)
    add('owned child reaped, no unresolved child', rec.get('owned_child_reaped') is True and rec.get('unresolved_owned_child') is False)
    return c


def cmd_verify(a):
    if a.dry_run:
        print(json.dumps({'status': 'PLAN_ONLY_NOTHING_EXECUTED', 'would_read': ['stage-receipt.json', 'custody-result.json (required)', 'build result.json', 'vm-plan.json', 'native-result.json', 'serial.log', 'esp.img::SHZDOS/DISK.IMG'],
                          'profile': a.profile, 'expected': PROFILES[a.profile]}, indent=2))
        return 0
    need(a.i_own_this_vm, '--i-own-this-vm is required to verify (extracts a 2 GiB disk)')
    need(a.out is not None and a.out.is_absolute() and not a.out.exists() and a.out.parent.is_dir(), 'fresh absolute --out required')
    need(a.stage_receipt is not None and a.run_dir is not None, '--stage-receipt and --run-dir required')
    stage = json.loads(a.stage_receipt.read_text())
    need(stage.get('schema') == 'shizukuos.w98w64-stage.v1' and stage.get('status') == 'STAGED_NOT_RUN', 'valid stage receipt required')
    run = a.run_dir
    need(run.is_absolute() and run.is_dir(), 'absolute --run-dir required')
    need(a.build_receipt is not None, '--build-receipt (native_win98/build.py result.json) required to bind the ESP member to the staged disk')
    custody_path = run / 'custody-result.json'
    need(custody_path.is_file(), 'custody-result.json missing from --run-dir: the run was not made under the task_custody.py guardian')
    custody = json.loads(custody_path.read_text())
    built = json.loads(a.build_receipt.read_text())
    plan = json.loads((run / 'vm-plan.json').read_text())
    rec = json.loads((run / 'native-result.json').read_text())
    a.out.mkdir(mode=0o700)
    verdict = {'schema': 'shizukuos.w98w64-verdict.v1', 'profile': a.profile, 'checks': [], 'status': 'FAIL',
               'QEMU_launched_by_this_tool': False}
    checks = supervisor_checks(rec, a.profile)
    checks.append({'name': 'guardian custody-result: admitted, VM executed, owned child reaped',
                   'ok': custody.get('schema') == 'shizukuos.native-custody.v1' and custody.get('custody_admitted') is True and
                   custody.get('VM_executed') is True and custody.get('owned_child_reaped') is True, 'detail': str(custody.get('status'))})
    members = built.get('members') or {}
    checks.append({'name': 'build.py receipt PASS, no VM, private', 'ok': built.get('status') == 'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN' and
                   built.get('private') is True and built.get('VM_executed') is False})
    checks.append({'name': 'ESP DISK.IMG member is exactly the staged injected disk',
                   'ok': (members.get('SHZDOS/DISK.IMG') or {}).get('sha256') == stage['injected_disk_sha256'] and
                   (members.get('SHZDOS/DISK.IMG') or {}).get('bytes') == DISK_BYTES})
    checks.append({'name': 'ESP carries supervised KERNEL32.BIN, KERNEL64.BIN and WIN64.IMG members',
                   'ok': all(('SHZDOS/' + n) in members for n in ('KERNEL32.BIN', 'KERNEL64.BIN', 'WIN64.IMG')) if a.profile != 'no-bridge' else 'SHZDOS/KERNEL32.BIN' in members})
    checks.append({'name': 'vm-plan.json is a fresh PASS plan bound to this build receipt ESP',
                   'ok': plan.get('status') == 'PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN' and plan.get('VM_executed') is False and
                   (plan.get('input_pins') or {}).get('esp', {}).get('sha256') == (built.get('artifact') or {}).get('sha256')})
    for n in ('mcopy', 'mdir'):
        tool(n)
    esp = run / 'esp.img'
    need(esp.is_file(), 'esp.img missing from run dir')
    need(shutil.disk_usage(a.out).free > DISK_BYTES + (2 << 30), 'insufficient free space for the 2 GiB extract')
    disk = a.out / 'DISK.IMG'
    mtools(['mcopy', '-i', str(esp), '::/SHZDOS/DISK.IMG', str(disk)])
    after = sha256_path(disk)
    verdict['extracted_disk_sha256'] = after
    persisted = after != stage['injected_disk_sha256']
    checks.append({'name': 'guest disk changed after run (write-back/persistence active)', 'ok': persisted, 'detail': after})
    logs = {}
    if persisted:
        spec = '%s@@%d' % (disk, stage['partition_offset'])
        for n in ('RESULT.LOG', 'VER.LOG', 'Q.LOG', 'HELLO.LOG'):
            dst = a.out / n
            r = subprocess.run(['mcopy', '-i', spec, '::/%s/%s' % (GUEST_DIR, n), str(dst)], capture_output=True,
                               env={**os.environ, 'MTOOLS_SKIP_CHECK': '1'}, timeout=80)
            if r.returncode == 0 and 0 < dst.stat().st_size <= 65536:
                logs[n] = dst.read_bytes().decode('latin-1')
    if 'RESULT.LOG' not in logs:
        verdict.update(status='INCOMPLETE_NO_GUEST_EVIDENCE', checks=checks)
    else:
        try:
            gui = None
            if stage.get('gui_image'):
                need(a.gui_expected_exit is not None, '--gui-expected-exit required for a staged GUI image')
                gui = a.gui_expected_exit
            more, rc = parse_guest(logs, a.profile, gui)
            checks += more
            verdict['stage_codes'] = rc
        except Refuse as e:
            checks.append({'name': 'guest records well formed', 'ok': False, 'detail': str(e)})
        if stage.get('gui_image'):
            shots = sorted(run.glob('*.png'))
            digests = {sha256_path(p) for p in shots}
            checks.append({'name': 'at least two distinct QMP screenshots', 'ok': len(digests) >= 2, 'detail': str(len(shots))})
        verdict['status'] = 'PASS_' + a.profile.upper().replace('-', '_') if all(c['ok'] for c in checks) else 'FAIL'
    verdict['checks'] = checks
    verdict['scope'] = ('Guest-produced exit-code ladder and file output plus Supervisor receipt. GUI input delivery and '
                        'window correctness additionally depend on the root-driven QMP input and the fixture exit code.')
    (a.out / 'verdict.json').write_text(json.dumps(verdict, indent=2) + '\n')
    print(json.dumps({'status': verdict['status'], 'verdict': str(a.out / 'verdict.json')}))
    return 0 if verdict['status'].startswith('PASS_') else 1


def cmd_combine(a):
    seen = {}
    for p in a.verdict:
        v = json.loads(p.read_text())
        need(v.get('schema') == 'shizukuos.w98w64-verdict.v1' and v.get('status', '').startswith('PASS_'), 'passing verdict required: %s' % p)
        need(v['profile'] not in seen, 'duplicate profile')
        seen[v['profile']] = v['stage_codes']['HELLO']
    need(set(seen) == set(PROFILES), 'all four profiles required: ' + ','.join(sorted(PROFILES)))
    need(len(set(seen.values())) == 4, 'exit codes must be distinct per case: %s' % seen)
    print(json.dumps({'status': 'PASS_ALL_FOUR_PROFILES_DISTINCT', 'hello_exit_codes': seen}))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('plan', 'stage', 'verify', 'combine'):
        p = sub.add_parser(name)
        p.add_argument('--dry-run', action='store_true', help='print plan only; nothing is read or written')
        if name in ('plan', 'stage'):
            p.add_argument('--gui-image', default=None, help='Kernel64 path of an interactive PE64 to run after the console cases')
        if name in ('stage', 'verify'):
            p.add_argument('--i-own-this-vm', action='store_true', help='root asserts the VM, private media and output are root-owned')
            p.add_argument('--out', type=Path)
        if name == 'stage':
            p.add_argument('--baseline-disk', type=Path)
            p.add_argument('--baseline-sha256')
            for k in INPUTS:
                p.add_argument('--' + k, type=Path)
                p.add_argument('--' + k + '-sha256')
        if name == 'verify':
            p.add_argument('--stage-receipt', type=Path, default=None)
            p.add_argument('--run-dir', type=Path, help='the prepare_vm --out directory that holds esp.img, vm-plan.json, native-result.json')
            p.add_argument('--build-receipt', type=Path, help='native_win98/build.py result.json used for this run')
            p.add_argument('--profile', choices=sorted(PROFILES), default='connected')
            p.add_argument('--gui-expected-exit', type=int)
        if name == 'combine':
            p.add_argument('--verdict', type=Path, nargs='+', required=True)
    a = ap.parse_args(argv)
    try:
        return {'plan': cmd_plan, 'stage': cmd_stage, 'verify': cmd_verify, 'combine': cmd_combine}[a.cmd](a)
    except (Refuse, subprocess.SubprocessError, OSError, ValueError) as exc:
        print(json.dumps({'status': 'REFUSED_OR_FAILED', 'error': '%s: %s' % (type(exc).__name__, exc)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
