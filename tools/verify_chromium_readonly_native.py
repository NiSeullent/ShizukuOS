#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Review the exact original Chromium read-only diagnostic's three log chain.

This never launches a guest, invokes Chromium, or promotes application support.
A reported zero exit is accepted only with both real parent wait/exit records.
The outer observer's own OS exit and visual boot still require separate review.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
RUNNER_SHA = '5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857'
WRAPPER_SHA = '1ed0edca4cd35eba8d82ab47a518d67916a2cda06913d538512bbf43971db417'
LARGE_HELPER_SHA = '3f2ec57acd908adadfb9d958bdc6b796c590b870d385462a32840a7d4066f825'
LARGE_MANIFEST_SHA = '498162fe9acc5ed110ceabcf8a163374ed4126afe98467fed4fc65110b209f01'
CLASSIC_MANIFEST_SHA = '0f8b210b202ce3228a4d59c240c5aa6680666dac1b33d8ff9635d5831cef2124'
INPUTS = {
    r'C:\CHRLAB\CHROME.DLL': (283207168, 'f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158'),
    r'C:\CHRLAB\CHRLARGE.EXE': (28680, 'c2b14638467626aa1930321c8880d7fd5430cec813ad8f0f4086ac5a1d49ef1a'),
    r'C:\CHRLAB\CHLWAIT.EXE': (8951, '034fdb8f3a1a0e1f83471d6606f092892db622ae862553a3a9bbfd7b50dcad2c'),
    r'C:\VXDLAB\CHLRUN.EXE': (21789, 'ba57f6e29adbfae7691e81b480856948fbcaab6f613ce934aa71a0a9d096f9e3'),
}
LOG_NAMES = ('CHRLARGE.LOG', 'CHLWAIT.LOG', 'CHLRUN.LOG')
MAX_LOG_BYTES = 16384


class EvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def parse_log(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG_BYTES, 'bounded nonempty log required')
    require(raw.endswith(b'\r\n'), 'complete native CRLF log required')
    try:
        lines = raw[:-2].decode('ascii').split('\r\n')
    except UnicodeDecodeError as error:
        raise EvidenceError('ASCII native log required') from error
    values = {}
    for line in lines:
        require(re.fullmatch(r'[A-Z][A-Z0-9_]*=[A-Za-z0-9_]+', line) is not None, 'malformed native log line')
        key, value = line.split('=', 1)
        require(key not in values, 'duplicate native log key: ' + key)
        values[key] = value
    return values


def review_log_chain(structure_raw, wait_raw, outer_raw):
    """Interpret exact diagnostic log bytes, without asserting their provenance."""
    structure, wait, outer = map(parse_log, (structure_raw, wait_raw, outer_raw))
    fixed_structure = {
        'SCOPE': 'ORIGINAL_CHROMIUM_NATIVE_READONLY_STRUCTURE_ONLY',
        'TARGET_ENTRY_CALLS': '0', 'TARGET_IMPORTS_RESOLVED': '0',
        'TARGET_TLS_CALLBACK_CALLS': '0', 'APPLICATION_FUNCTIONALITY_VERIFIED': '0',
        'NATIVE_OS_PLATFORM': '00000001', 'NATIVE_OS_MAJOR': '00000004',
        'NATIVE_OS_MINOR': '0000000A', 'NATIVE_OS_BUILD': '000008AE',
        'ACTUAL_FILE_SHA256': INPUTS[r'C:\CHRLAB\CHROME.DLL'][1],
        'ACTUAL_FILE_BYTES': f'{283207168:08X}',
        'DEFAULT_FILE_CAP': '02000000', 'DEFAULT_IMAGE_CAP': '04000000',
        'DEFAULT_REFUSAL': 'FILE_SIZE', 'DECLARED_IMAGE_BYTES': f'{284966912:08X}',
        'EXACT_LOGICAL_BUDGET': f'{283207168 + 284966912:08X}',
        'IMPORT_RECORDS_CHECKED': f'{1301:08X}',
        'DEFAULT_RELOCATION_REFUSED': 'RELOC_LIMIT',
        'HIGHLOW_ENTRIES_CHECKED': f'{4664381:08X}',
        'TLS_STRUCTURE_PRESENT': '00000001', 'TLS_CALLBACKS_NOT_INVOKED': '00000006',
        'EXECUTION_PROFILE_STILL_REFUSED': '1', 'RUNTIME_PROFILE_STILL_REFUSED': '1',
        'STATUS': 'NATIVE_READONLY_STRUCTURE_PASS', 'SELECTED_EXIT_CODE': '00000000',
    }
    fixed_wait = {
        'FRESH_REPORT_ERROR': '00000002', 'ACTUAL_WAIT_RESULT': '00000000',
        'ACTUAL_WAIT_ERROR': '00000000', 'ACTUAL_CHILD_OS_EXIT': '00000000',
        'OBSERVER_SELECTED_RESULT': '00000000',
    }
    fixed_outer = {
        'OUTER_ENTRY_REACHED': '00000001', 'CHROMIUM_TARGET_ENTRY_CALLS': '00000000',
        'CHROMIUM_APPLICATION_ACCEPTED': '00000000', 'ACTUAL_ORIGINAL_WIN98_GUARD': '00000001',
        'HELPER_ACTUAL_BYTES': f'{8951:08X}', 'HELPER_EXACT_SHA_AND_BYTES': '00000001',
        'HELPER_PROCESS_CREATED': '00000001', 'ACTUAL_HELPER_WAIT': '00000000',
        'ACTUAL_HELPER_WAIT_ERROR': '00000000', 'ACTUAL_HELPER_OS_EXIT': '00000000',
        'INNER_OBSERVER_LOG_READABLE': '00000001', 'INNER_STRUCTURE_LOG_READABLE': '00000001',
        'OUTER_SELECTED_RESULT': '00000000', 'OUTER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER': '00000001',
    }
    for values, fixed, dynamic in (
        (structure, fixed_structure, {'READONLY_NATIVE_VIEW'}),
        (wait, fixed_wait, {'ACTUAL_CHILD_PID'}),
        (outer, fixed_outer, {'ACTUAL_HELPER_PID', 'ORIGINAL_KERNEL_RESOLVER'}),
    ):
        require(set(values) == set(fixed) | dynamic, 'missing or unexpected diagnostic fields')
        for key, expected in fixed.items():
            require(values[key] == expected, 'unexpected native value: ' + key)
        for key in dynamic:
            require(re.fullmatch(r'[0-9A-F]{8}', values[key]) is not None, 'invalid native DWORD: ' + key)
    view = int(structure['READONLY_NATIVE_VIEW'], 16)
    child, helper = int(wait['ACTUAL_CHILD_PID'], 16), int(outer['ACTUAL_HELPER_PID'], 16)
    require(view != 0 and view <= 0xffffffff - 283207168, 'bounded native read-only view required')
    require(child != 0 and helper != 0 and child != helper, 'distinct actual helper and child PIDs required')
    resolver = int(outer['ORIGINAL_KERNEL_RESOLVER'], 16)
    require(resolver in (0, 1), 'original native Kernel32 resolver required')
    return {
        'reported_structure_child_pid': child, 'reported_inner_observer_pid': helper,
        'reported_structure_child_os_exit': 0, 'reported_inner_observer_os_exit': 0,
        'original_kernel_resolver': resolver, 'original_file_bytes': 283207168,
        'original_file_sha256': INPUTS[r'C:\CHRLAB\CHROME.DLL'][1],
        'imports_checked': 1301, 'relocations_checked': 4664381,
        'tls_callbacks_not_invoked': 6, 'target_entry_calls': 0,
        'application_success': False, 'outer_observer_own_os_exit_proven': False,
        'native_evidence_independently_accepted': False,
    }


def inside_file(path, parent):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file(), 'canonical evidence file required')
    require(path.is_relative_to(parent), 'evidence file outside selected run')
    return path


def verify_run(run):
    run = Path(run).resolve(strict=True)
    require(run.is_dir() and run.is_relative_to(ROOT / 'build/shizukudos/csm'), 'owned native run required')
    result_path = inside_file(run / 'result.json', run)
    result = json.loads(result_path.read_text())
    require(result.get('source_sha256') == RUNNER_SHA, 'reviewed actual Win98 runner required')
    require(result.get('profile') == 'actual-win98-uefi-csmwrap', 'actual UEFI Win98 profile required')
    require(result.get('status') == 'NEEDS-VISUAL-REVIEW' and result.get('qemu_exit_code') == 0, 'completed healthy runner required')
    require(result.get('originals_unchanged') is True and result.get('prepared_source_unchanged') is True, 'protected original and cold source integrity required')
    require(result.get('firmware_gop_opt_in') is True, 'explicit firmware GOP run required')
    require(result.get('captures') and result.get('gui_interaction', {}).get('actions'), 'actual captures and visually steered actions required')
    composition_path = inside_file(run / 'chromium-observer-composition.json', run)
    composition = json.loads(composition_path.read_text())
    require(composition.get('status') == 'PREBOOT_STAGING_COMPLETE_NATIVE_PENDING' and
            composition.get('legacy_boot_sectors_preserved') is True and
            composition.get('exact_large_inputs') == 3 and composition.get('classic_inputs') == 1,
            'exact unchanged three-plus-one diagnostic staging required')
    require(composition.get('held_runner_sha256') == RUNNER_SHA, 'composition runner identity mismatch')
    require(composition.get('exact_large_stager_sha256') == LARGE_HELPER_SHA, 'reviewed exact large helper required')
    require(composition.get('immutable_sources', {}).get(str(ROOT / 'tools/run_chromium_readonly_observed.py')) == WRAPPER_SHA,
            'reviewed composition wrapper required')
    for name, digest in composition['immutable_sources'].items():
        source = Path(name)
        require(source.is_absolute() and source.resolve(strict=True) == source and
                source.is_relative_to(ROOT) and re.fullmatch(r'[a-f0-9]{64}', digest) is not None,
                'canonical frozen composition source pin required')
        require(sha(source) == digest, 'composition source changed after native test')
    files = result.get('guest_files', {})
    classic = files.get('classic_observer_stage', {})
    require(files.get('manifest_sha256') == LARGE_MANIFEST_SHA and classic.get('manifest_sha256') == CLASSIC_MANIFEST_SHA,
            'exact large and classic manifests required')
    require(files.get('immutable_sources_unchanged') is True, 'staged sources changed or final integrity check absent')
    require(files.get('output_baseline') == 'CHRLAB and all outputs absent before injection' and
            classic.get('output_baseline') == 'all absent before private injection', 'fresh preboot outputs required')
    inputs = files.get('inputs', []) + classic.get('inputs', [])
    require(len(inputs) == 4 and {x.get('guest') for x in inputs} == set(INPUTS), 'exact original four inputs required')
    for item in inputs:
        size, digest = INPUTS[item['guest']]
        require(item.get('bytes') == size and item.get('sha256') == digest and item.get('private_copy_sha256') == digest,
                'staging input/readback identity differs')
        source = Path(item['source'])
        require(source.is_file() and source.stat().st_size == size and sha(source) == digest, 'original input changed after native test')
    outputs = files.get('readback', []) + classic.get('readback', [])
    require(len(outputs) == 3 and {x.get('guest') for x in outputs} == {
        r'C:\CHRLAB\CHRLARGE.LOG', r'C:\CHRLAB\CHLWAIT.LOG', r'C:\VXDLAB\CHLRUN.LOG'}, 'exact three native output paths required')
    logs, pins = {}, []
    for item in outputs:
        require(item.get('status') == 'captured' and item.get('freshness') == 'new-in-owned-run', 'fresh native log readback required')
        path = inside_file(item['path'], run)
        require(0 < path.stat().st_size <= MAX_LOG_BYTES and item.get('bytes') == path.stat().st_size and sha(path) == item.get('sha256'),
                'native log readback bytes/hash differs')
        raw = path.read_bytes()
        logs[item['guest'].rsplit('\\', 1)[1]] = raw
        pins.append({'path': str(path), 'bytes': len(raw), 'sha256': item['sha256']})
    reviewed = review_log_chain(*(logs[name] for name in LOG_NAMES))
    return reviewed | {
        'status': 'READONLY_LOG_CHAIN_CONSISTENT_INDEPENDENT_ACCEPTANCE_REQUIRED',
        'run': str(run), 'runner_result_sha256': sha(result_path),
        'composition_sha256': sha(composition_path), 'fresh_native_logs': pins,
        'visual_boot_verified': False, 'gpu_acceleration_verified': False,
        'limit': 'Interprets fresh pinned log claims only. Original-file native structure and both parent OS exits still require independent acceptance; visual GOP boot and outer own OS exit need separate evidence.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    require(output.parent.resolve(strict=True) == output.parent and output.is_relative_to(ROOT / 'build'), 'new private build receipt required')
    receipt = {'status': 'FAIL', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'reviewer_source_sha256': sha(__file__), 'application_success': False,
               'outer_observer_own_os_exit_proven': False, 'visual_boot_verified': False}
    try:
        receipt.update(verify_run(args.run))
        code = 0
    except (EvidenceError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        receipt['error'] = str(error)
        code = 1
    with output.open('x') as handle:
        json.dump(receipt, handle, indent=2)
        handle.write('\n')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
