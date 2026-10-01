#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze approved numeric WAMR inputs/evidence; never launch a VM or install."""
import argparse
import json
from pathlib import Path
import sys

from wasm_native_stage_evidence import (ROOT, BOOT_BUILD, PROFILE, INPUTS, OUTPUTS,
    RECEIPTS, MAX_STAGE, canonical, collect, check_stage, need, pin, provenance, read, sha)


def stage(build_receipt_paths, build_pins, destination):
    need(not sys.flags.optimize, 'Python optimization rejected before stage mutation')
    destination = Path(destination)
    need(destination.is_absolute() and canonical(destination, exists=False) == destination and
         destination.parent == BOOT_BUILD and not destination.exists(),
         'fresh canonical direct boot stage required')
    builds, copies, merged = collect(build_receipt_paths, build_pins)
    measured = sum(len(read(source)) for source, _ in copies.values())
    need(measured + (2 << 20) <= MAX_STAGE, 'stage evidence plus metadata exceeds bound')
    # All checks above are read-only. Existing stages are never reused/rewritten.
    destination.mkdir()
    for member, (source, digest) in copies.items():
        data = read(source)
        need(sha(data) == digest, 'source changed immediately before staging')
        target = destination / member
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        need(sha(read(target)) == digest, 'staged byte readback differs')
    after_builds, after_copies, after_merged = collect(build_receipt_paths, build_pins)
    need((builds, copies, merged) == (after_builds, after_copies, after_merged),
         'original closure changed during copy; failed fresh stage retained')
    inputs = [dict(source=str(destination / name), guest='C:\\GOPLAB\\' + name,
        bytes=len(read(destination / name, 1 << 20)), sha256=copies[name][1]) for name in sorted(INPUTS)]
    manifest = dict(schema=1, kind='isolated-guest-file-inputs', inputs=inputs,
        outputs=['C:\\GOPLAB\\' + name for name in sorted(OUTPUTS)], command=PROFILE['self'],
        nonce=builds['observer-build.json']['nonce'], network_required=False,
        source_receipts=[dict(path=str(destination / name), sha256=pin(build_pins[name]))
                         for name in sorted(RECEIPTS)])
    manifest_path = destination / 'guest-files.json'
    with manifest_path.open('x') as stream:
        stream.write(json.dumps(manifest, indent=2) + '\n')
    manifest_sha = sha(read(manifest_path, 65536))
    with (destination / 'provenance.json').open('x') as stream:
        stream.write(json.dumps(provenance(manifest_sha, copies, merged), indent=2) + '\n')
    provenance_sha = sha(read(destination / 'provenance.json', 2 << 20))
    checked = check_stage(manifest_path, manifest_sha, build_pins, provenance_sha)
    return dict(manifest=str(manifest_path), sha256=manifest_sha,
        stage_provenance_sha256=provenance_sha,
        evidence_members=len(copies), evidence_bytes=measured,
        checked_members=len(checked[-1]), native_execution=False,
        native_numeric_execution=False, browser_webassembly=False, full_modern_wasm=False,
        webgl=False, webgpu=False, modern_apps=False, vm_operations=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ('runtime', 'probe', 'observer'):
        parser.add_argument('--' + role + '-receipt', required=True, type=Path)
        parser.add_argument('--' + role + '-sha256', required=True)
    parser.add_argument('--stage', required=True, type=Path)
    args = parser.parse_args()
    paths = {r + '-build.json': getattr(args, r + '_receipt') for r in ('runtime', 'probe', 'observer')}
    pins = {r + '-build.json': getattr(args, r + '_sha256') for r in ('runtime', 'probe', 'observer')}
    try:
        result = stage(paths, pins, args.stage)
    except (ValueError, OSError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps(dict(passed=False, native_execution=False, error=str(error))))
        return 1
    print(json.dumps(dict(passed=True, **result), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
