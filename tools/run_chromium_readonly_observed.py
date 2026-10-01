#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compose the frozen classic observer and unchanged exact CHRLAB staging.

The held Win98 runner is imported unchanged. Only its two staging/readback
callbacks are composed for this explicitly selected diagnostic workflow.
No target entry, default policy, ordinary runner or QEMU launch is changed.
"""
import argparse
import copy
import fcntl
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import datetime
import contextlib

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT/'shizukudos/csm/test_win98_uefi.py'
RUNNER_SHA = '5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857'
LARGE_HELPER_SHA = '3f2ec57acd908adadfb9d958bdc6b796c590b870d385462a32840a7d4066f825'
OBSERVER_RESULT_SHA = '6b643a1fb16fa486bb4b59409e7ddea451450f0707149590b0d41d8b47502832'
OBSERVER_SHA = 'ba57f6e29adbfae7691e81b480856948fbcaab6f613ce934aa71a0a9d096f9e3'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observer-manifest', type=Path, required=True)
    parser.add_argument('--observer-manifest-sha', required=True)
    selected, remaining = parser.parse_known_args()
    sys.path.insert(0, str(ROOT/'tools'))
    import prepare_large_chromium_inputs as large
    sha = large.sha256
    if sha(RUNNER) != RUNNER_SHA or sha(large.__file__) != LARGE_HELPER_SHA:
        parser.error('Exact unchanged runner/stager required')
    if '--large-chromium-inputs' not in remaining:
        parser.error('Only explicitly selected exact large Chromium diagnostic workflow supported')
    manifest = selected.observer_manifest.resolve(strict=True)
    if not manifest.is_relative_to(ROOT/'build') or sha(manifest) != selected.observer_manifest_sha:
        parser.error('Exact private observer manifest required')
    data = json.loads(manifest.read_text())
    if (data.get('schema') != 1 or data.get('kind') != 'isolated-guest-file-inputs' or
            data.get('outputs') != [r'C:\VXDLAB\CHLRUN.LOG'] or data.get('backups') != [] or
            len(data.get('inputs', [])) != 1 or data.get('command') != r'C:\VXDLAB\CHLRUN.EXE'):
        parser.error('Exactly one classic VXDLAB observer and fresh output required')
    item = data['inputs'][0]
    source = Path(item['source']).resolve(strict=True)
    if (not source.is_relative_to(manifest.parent) or item['guest'] != r'C:\VXDLAB\CHLRUN.EXE' or
            item['bytes'] != 21789 or source.stat().st_size != item['bytes'] or
            item['sha256'] != OBSERVER_SHA or sha(source) != OBSERVER_SHA):
        parser.error('Reviewed exact classic observer required')
    refs = data.get('source_receipts', [])
    if len(refs) != 1 or refs[0]['sha256'] != OBSERVER_RESULT_SHA:
        parser.error('Exact reviewed observer producer required')
    producer = Path(refs[0]['path']).resolve(strict=True)
    if not producer.is_relative_to(manifest.parent) or sha(producer) != OBSERVER_RESULT_SHA:
        parser.error('Observer producer identity differs')
    held = json.loads(producer.read_text())
    if held['status'] != 'HOST_BUILD_PASS_NATIVE_PENDING' or held['native_executed']:
        parser.error('Observer has no native acceptance yet')
    pins = {str(manifest): selected.observer_manifest_sha, str(source): OBSERVER_SHA,
        str(producer): OBSERVER_RESULT_SHA, str(Path(__file__).resolve()): sha(__file__)}
    for relative, pin in held['sources'].items():
        current, frozen = ROOT/relative, manifest.parent/'frozen'/relative
        if sha(current) != pin or sha(frozen) != pin:
            parser.error('Observer source changed after build')
        pins[str(current)] = pin
        pins[str(frozen)] = pin
    sys.path.insert(0, str(RUNNER.parent))
    spec = importlib.util.spec_from_file_location('held_chromium_observed_runner', RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    prepare, collect = runner.prepare_guest_files, runner.collect_guest_files
    classic_by_disk = {}

    def composed_prepare(disk, run_dir, partition, args):
        if not args.large_chromium_inputs:
            raise ValueError('Composition is exclusive to exact diagnostic staging')
        record_path = run_dir/'chromium-observer-composition.json'
        if record_path.exists():
            raise ValueError('Fresh composition receipt required')
        record = {'status': 'FAIL', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'held_runner_sha256': RUNNER_SHA, 'exact_large_stager_sha256': LARGE_HELPER_SHA,
            'classic_manifest_sha256': selected.observer_manifest_sha,
            'immutable_sources': pins, 'disk': str(disk), 'native_executed': False,
            'application_success': False, 'scope': 'Classic VXDLAB1 then unchanged CHRLAB3 on same offline owned clone; default caps unchanged'}
        try:
            if any(sha(path) != pin for path, pin in pins.items()):
                raise ValueError('Held observer source changed before private staging')
            checked = large.validate(args.large_chromium_plan['manifest'], args.large_chromium_plan['manifest_sha256'])
            total = 2*(item['bytes']+sum(x['bytes'] for x in checked['inputs'])) + 2*1024**2
            floor = max(runner.RESERVE+runner.DIRTY_BUDGET, 17*1024**3+512*1024**2)
            if shutil.disk_usage(run_dir).free < floor+total:
                raise ValueError('Joint classic/large readback and unchanged reserve/dirty budget required')
            if disk.resolve(strict=True) != disk or run_dir.resolve(strict=True) != run_dir or not disk.is_relative_to(run_dir):
                raise ValueError('Same canonical new owned disk required')
            before = large._boot_hashes(disk, partition['start_lba'])
            if before != (partition['mbr_sha256'], partition['boot_sector_sha256']):
                raise ValueError('Exact retained boot sectors required')
            large._no_open_disk(disk)
            classic_args = copy.copy(args)
            classic_args.large_chromium_inputs = False
            classic_args.guest_files_manifest = manifest
            classic_args.guest_files_manifest_sha = selected.observer_manifest_sha
            with contextlib.ExitStack() as stack:
                raw = stack.enter_context(disk.open('r+b'))
                fcntl.flock(raw, fcntl.LOCK_EX|fcntl.LOCK_NB)
                large._no_open_disk(disk)
                for path in pins:
                    handle = stack.enter_context(Path(path).open('rb'))
                    fcntl.flock(handle, fcntl.LOCK_SH|fcntl.LOCK_NB)
                specifier = f"{disk}@@{partition['start_lba']*512}"
                runner.command(['mdir', '-i', specifier, '::'])
                if not large._absent(specifier, '::CHRLAB'):
                    raise ValueError('CHRLAB must be entirely absent before either staging phase')
                for guest in (item['guest'], data['outputs'][0]):
                    if not large._absent(specifier, '::'+guest[3:].replace('\\', '/')):
                        raise ValueError('Classic observer input and output must be absent before staging')
                if any(sha(path) != pin for path, pin in pins.items()):
                    raise ValueError('Held observer source changed during lock acquisition')
                classic = prepare(disk, run_dir, partition, classic_args)
            # The exact large helper takes its own disk/source locks again.
            large_stage = prepare(disk, run_dir, partition, args)
            if large._boot_hashes(disk, partition['start_lba']) != before:
                raise ValueError('Sequential staging changed retained boot sectors')
            if any(sha(path) != pin for path, pin in pins.items()):
                raise ValueError('Held observer source changed during staging')
            classic_by_disk[str(disk)] = classic
            large_stage['immutable_sources'].update(pins)
            large_stage['classic_observer_stage'] = classic
            record.update(status='PREBOOT_STAGING_COMPLETE_NATIVE_PENDING', classic_stage=classic,
                joint_staging_budget_bytes=total, free_floor_bytes=floor,
                actual_free_after_staging=shutil.disk_usage(run_dir).free,
                final_disk_sha256=sha(disk), legacy_boot_sectors_preserved=True,
                exact_large_inputs=len(large_stage['inputs']), classic_inputs=len(classic['inputs']))
            return large_stage
        except Exception as error:
            record['error'] = str(error)
            raise
        finally:
            record_path.write_text(json.dumps(record, indent=2)+'\n')

    def composed_collect(disk, run_dir, partition, files):
        result = collect(disk, run_dir, partition, files)
        classic = classic_by_disk.get(str(disk))
        if classic is None:
            raise ValueError('Same-disk classic stage provenance missing')
        result['classic_observer_stage'] = collect(disk, run_dir, partition, classic)
        result['observer_acceptance'] = 'Full fresh logs and actual OS waits/exits require independent native review'
        return result

    runner.prepare_guest_files = composed_prepare
    runner.collect_guest_files = composed_collect
    sys.argv = [str(RUNNER)] + remaining
    return runner.main()

if __name__ == '__main__':
    raise SystemExit(main())
