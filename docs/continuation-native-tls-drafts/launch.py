#!/usr/bin/env python3
"""Owned corrected offline TLS DLL trial admission; do not touch other guests or original media."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

ROOT = Path('/root/Win98-Modern-theme-tls-5abe')
BOOT = Path('/root/Win98-Modern-boot')
STAGE = BOOT / 'build/tls13-i486-native-5abe-20261001-v1'
MANIFEST_SHA = 'e0c7af02378c03edd1e6a21d00787964ee9b6b20cb8d28d2f646f7191fed9632'
PROVENANCE_SHA = '3776c62a6bcb80548263e664508aa38df08eea1892a5f7c8dc7253e99557f634'
HARNESS = BOOT / 'shizukudos/csm/test_win98_uefi.py'
HARNESS_SHA = '5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857'
COLD = BOOT / 'build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807'
COLD_SHA = '518d18d5e286cb0eb63065d8d896d0d3ee743289f220fb62083f6176b5925db7'
SCOPE = ROOT / 'docs/NATIVE_QA_SCHEDULING_SCOPE.md'
SCOPE_SHA = '8f4567ff592a0ba9c192499c5b00753fdcc4cc6cd149a87b4e4520a0bd51d89e'
COPY_FLOOR = 22058516480
RUN_NAME = 'run-win98-gop-tls13-i486-5abe-native-v1'
AUTHORITY_SHA = 'ad368edb18594c5b9a12823655eb9d8ebd13a28c814519996af6e1b14687c852'
HELPER_SHA = 'ba9eb7542b099b81a43f75c474602a27a14d6ee9b2f14f9c526a8da2c6d1ef92'
VERIFIER_SHA = '0b660a00a9f88009038b6e46b2876d4b54411ab53296d04beaa0f92aeac100c8'
CONTROL_AUTHORITY = ROOT / 'build/tls13-i486-native-verifier-v1/result.json'
CONTROL_SHA = '35c84f712bc8593132768bbcee8f4bd6e88d06e4863918b8741cc21579fed380'
PINS = {
 'tls':'98c526151545be95fe5f6cd58140ae2dfdc52d21038fe1de893387290dea1819',
 'root_review':'d2eaf7896235fedb8246bb7197ac24297f4a265d6dda21295b7f76bcdb8892cf',
 'independent_review':'9ef72856e5dfddb357e9e89211dcf0f01d18babe437cec30649e52fe04ebb9e3',
 'client':'7e5d48151b4754adfcdf6cf5c9e5ef4747c3b61ed37a1e84eb1991847c1496f9',
 'server':'6ad287ce7b43ed45af43f2b8b62f4ea678f876ec2341a4bc87cb72c8a913ad97',
}


def digest(path):
    path = Path(path)
    if path.resolve(strict=True) != path:
        raise ValueError('Noncanonical input: ' + str(path))
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Input is not regular')
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
        after = os.fstat(stream.fileno())
        if any(getattr(before, k) != getattr(after, k) for k in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('Input changed during hashing')
        return result.hexdigest()


def guests():
    native, separate = [], []
    proof = Path('/root/Win98-Modern-apps-cb43/build/modern-apps/steam-baseline/result.json')
    if digest(proof) != '1d5e0722905c848b20ba042039a9f932f656285c554cdc3e478070a5004efeb9':
        raise ValueError('Steam Kernel64 classification evidence changed')
    known = json.loads(proof.read_text())
    if known.get('profile') != 'kernel64-standalone + steam Electron app on AHCI FAT32 (D:), autorun' or known.get('image') != '/root/Win98-Modern-apps-cb43/build/modern-apps/steam.img' or known.get('windows98_execution_verified') is not False:
        raise ValueError('Exact separate Steam domain proof required')
    classification_path = ROOT / 'build/kernel64-classification-5abe-v1/result.json'
    if digest(classification_path) != '65df20cc5680f2ae83d5049e043f51d708df2cfd6ba01afe5566f8ae42bd0524':
        raise ValueError('Caller-approved exact Kernel64 scenario classification changed')
    classified = json.loads(classification_path.read_text())
    if classified.get('schema') != 'win98modern.separate-kernel64-classification.v1' or classified.get('actual_pid') != 3215209 or classified.get('actual_open_image') != '/root/Win98-Modern-apps-cb43/build/modern-apps/chromium-gui-rev1708403.img' or classified.get('windows98_execution_verified') is not False or classified.get('direct_kernel_elf_magic_observed') is not True:
        raise ValueError('Exact caller-approved separate Kernel64 evidence required')
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            comm = (process / 'comm').read_text().strip()
            if not comm.startswith('qemu'):
                continue
            descriptors = list((process / 'fd').iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        images = set()
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if target.startswith('/root/Win98-Modern') and target.endswith(('.raw', '.qcow2', '.img')):
                images.add(target)
        if not images:
            continue
        row = dict(pid=int(process.name), comm=comm, images=sorted(images))
        # These exact application images have positive peer-session evidence
        # identifying standalone Kernel64 runners. All other project images
        # remain conservative native-slot blockers until independently known.
        known_kernel64 = {
            '/root/Win98-Modern-apps-cb43/build/modern-apps/steam.img',
            '/root/Win98-Modern-codex-20260930/build/app-inputs/productivity-01a0f3d0cb43/productivity-images/legcord.img',
            '/root/Win98-Modern-apps-cb43/build/modern-apps/chromium-latest-prep-01a0f3d0cb43/chromium-rev1708403.img'}
        exact_live_classified = False
        if images == {classified['actual_open_image']} and int(process.name) == classified['actual_pid']:
            try:
                fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
                exact_live_classified = int(fields[19]) == classified['process_start_ticks']
            except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
                pass
        (separate if images <= known_kernel64 or exact_live_classified else native).append(row)
    return native, separate


def resources():
    fs = os.statvfs(BOOT)
    available = next(int(row.split()[1]) * 1024 for row in
                     Path('/proc/meminfo').read_text().splitlines()
                     if row.startswith('MemAvailable:'))
    return dict(free_bytes=fs.f_bavail * fs.f_frsize,
                mem_available_bytes=available)


def write(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2, allow_nan=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt', required=True, type=Path)
    parser.add_argument('--independent-review', required=True, type=Path)
    parser.add_argument('--independent-review-sha256', required=True)
    args = parser.parse_args()
    out = args.attempt
    if out.parent != ROOT / 'build' or out.resolve() != out or out.exists():
        raise ValueError('Fresh owned direct build attempt required')
    out.mkdir()
    script = Path(__file__).resolve()
    r = dict(schema='win98modern.corrected-tls-native-admission.v1',
             observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
             controller_sha256=digest(script), queue_scope_addendum_sha256=SCOPE_SHA,
             exact_kernel64_classification_sha256='65df20cc5680f2ae83d5049e043f51d708df2cfd6ba01afe5566f8ae42bd0524',
             manifest_sha256=MANIFEST_SHA, provenance_sha256=PROVENANCE_SHA,
             harness_sha256=HARNESS_SHA, reserve_gib=20,
             copy_floor_with_reserve_bytes=COPY_FLOOR, root_owns_vm=False,
             qemu_launched=False, source_image_modified=False,
             native_execution_verified=False, user_objective_complete=False)
    lock = (BOOT / 'build/modern-app-native-guest.lock').open('a+')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r['cooperative_lock_acquired'] = True
        except BlockingIOError:
            r['cooperative_lock_acquired'] = False
        native, separate = guests()
        r.update(actual_native_win98_candidates=native, separate_known_kernel64_guests=separate,
                 **resources())
        if not r['cooperative_lock_acquired'] or native:
            r['status'] = 'QUEUED_BEFORE_RUN_CREATION'
            write(out / 'preflight.json', r)
            print(json.dumps({k: r[k] for k in ('status', 'actual_native_win98_candidates',
                                              'cooperative_lock_acquired', 'free_bytes')}), flush=True)
            return 0
        if r['free_bytes'] < COPY_FLOOR or r['mem_available_bytes'] < 6 * (1 << 30):
            raise ValueError('Measured staging/reserve or available-memory floor not met')
        for path, expected in ((STAGE / 'guest-files.json', MANIFEST_SHA),
                               (STAGE / 'provenance.json', PROVENANCE_SHA),
                               (HARNESS, HARNESS_SHA), (SCOPE, SCOPE_SHA)):
            if digest(path) != expected:
                raise ValueError('Frozen input changed: ' + str(path))
        # Only previously reviewed, exactly approved helper bytes execute in memory.
        verifier_path = ROOT / 'tools/verify_tls13_i486_native.py'
        verifier_raw = verifier_path.read_bytes()
        if hashlib.sha256(verifier_raw).hexdigest() != VERIFIER_SHA:
            raise ValueError('Approved strict verifier source changed')
        verifier = types.ModuleType('root_approved_tls_native_verifier')
        verifier.__file__ = str(verifier_path)
        exec(compile(verifier_raw, str(verifier_path), 'exec'), verifier.__dict__)
        ledger = verifier.Ledger()
        tested = verifier.tested_authority(ledger, CONTROL_AUTHORITY, CONTROL_SHA)
        independent_path = verifier.canonical(args.independent_review)
        if independent_path.parent.parent != ROOT / 'build' or independent_path.name != 'result.json':
            raise ValueError('Own closed independent source review path required')
        independent = verifier.object_json(ledger.take(independent_path, args.independent_review_sha256))
        if (independent.get('passed') is not True or independent.get('corrected_verifier_source_clear') is not True or
                independent.get('kind') != 'independent-read-only-tls13-i486-native-verifier-review' or
                not verifier.equal(independent.get('source_sha256'), tested) or
                independent.get('approved_control_authority_sha256') != CONTROL_SHA):
            raise ValueError('Independent source review must clear this generation')
        helper = verifier.load_helper(ledger, HELPER_SHA)
        manifest, authority, provenance = verifier.stage_ledger(ledger, MANIFEST_SHA, AUTHORITY_SHA, PROVENANCE_SHA)
        ledger.take(HARNESS, HARNESS_SHA)
        ledger.take(SCOPE, SCOPE_SHA)
        ledger.take(script, r['controller_sha256'])
        checked_before = helper.check_stage(STAGE / 'guest-files.json', MANIFEST_SHA,
                                            AUTHORITY_SHA, PROVENANCE_SHA, PINS)
        write(out / 'before-cold-hash-stage-guard.json', checked_before)
        if digest(COLD / 'windows-uefi.raw') != COLD_SHA:
            raise ValueError('Actual approved original cold source changed')
        ledger.take(COLD / 'result.json', '13f76fc4f6870a61d5067b76b7c47a49b7d40ddcd9310f271d5d8cbd1fab8ada')
        checked_after = helper.check_stage(STAGE / 'guest-files.json', MANIFEST_SHA,
                                           AUTHORITY_SHA, PROVENANCE_SHA, PINS)
        if not verifier.equal(checked_before, checked_after):
            raise ValueError('Complete TLS stage generation changed around cold-source hash')
        write(out / 'after-cold-hash-stage-guard.json', checked_after)
        # Rehash every consumed stage/source/authority AFTER the second slow replay.
        stamps = ledger.final_rehash()
        verifier.topology(provenance)
        for path, row in ledger.files.items():
            if row['group'] >= 1:
                data, _ = verifier.raw_file(Path(path), row['limit'])
                if verifier.sha(data) != row['sha256']:
                    raise ValueError('Final current input drift: ' + path)
        ledger.final_stamps(stamps)
        r['stage_members_checked'] = len(provenance['stage_sha256'])
        r['actual_complete_stage_guard'] = checked_after
        r['tested_verifier_sources'] = tested
        r['verifier_independent_review'] = str(independent_path)
        r['verifier_independent_review_sha256'] = args.independent_review_sha256
        r['control_authority_sha256'] = CONTROL_SHA
        r['approved_build_sha256'] = PINS
        r['after_second_slow_guard_actual_final_file_sha256'] = {p: x['sha256'] for p,x in ledger.files.items()}
        r['cold_source_sha256'] = COLD_SHA
        r['cold_source_hash_observed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        native, separate = guests()
        r.update(actual_native_win98_candidates=native, separate_known_kernel64_guests=separate,
                 **resources())
        if native or r['free_bytes'] < COPY_FLOOR or r['mem_available_bytes'] < 6 * (1 << 30):
            raise ValueError('Native queue/resources changed under cooperative lock')
        if (BOOT / 'build/shizukudos/csm' / RUN_NAME).exists():
            raise ValueError('Fresh own run name already exists')
        command = [sys.executable, '-B', '-u', str(HARNESS),
            '--archive', '/root/Win98-Modern/build/win98-lab/install-packed-z_kei9n1.qcow2.xz',
            '--checkpoint-record', '/root/Win98-Modern/build/win98-lab/install-packed-current.json',
            '--snapshot', 'windows98-clean-installed', '--resume-owned-run', str(COLD),
            '--csm-dir', 'build/shizukudos/csm-gop-anchor', '--replace-csmwrap', '--firmware-gop',
            '--qemu', '/usr/libexec/qemu-kvm', '--firmware-code', '/usr/share/edk2/ovmf/OVMF_CODE.fd',
            '--firmware-vars', '/usr/share/edk2/ovmf/OVMF_VARS.fd', '--machine', 'q35',
            '--accel', 'kvm', '--smp', '2', '--memory', '128', '--timeout', '600',
            '--capture-interval', '5', '--reserve-gib', '20', '--manual-gui',
            '--manual-purpose', 'diagnostic', '--guest-files-manifest', str(STAGE / 'guest-files.json'),
            '--guest-files-manifest-sha', MANIFEST_SHA, '--run-name', RUN_NAME]
        r.update(status='ADMITTED_OWNED_HARNESS', command=command,
                 admission_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        write(out / 'preflight.json', r)
        print(json.dumps({'status':r['status'], 'run_name':RUN_NAME}), flush=True)
        with (out / 'harness-output.log').open('xb') as log:
            child = subprocess.run(command, cwd=BOOT,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), stdout=log, stderr=subprocess.STDOUT)
        write(out / 'completion.json', dict(harness_returncode=child.returncode,
            harness_output_sha256=digest(out / 'harness-output.log'),
            completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            native_execution_verified=False, independent_native_acceptance_still_required=True))
        print(json.dumps({'harness_returncode': child.returncode}), flush=True)
        return child.returncode
    finally:
        lock.close()


if __name__ == '__main__':
    raise SystemExit(main())
