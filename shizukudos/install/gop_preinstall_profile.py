#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Stage source-bound GOP files through the real private disk constructor.

No hive editing, guest execution or default-display installation is performed.
The existing constructor copies only an owned clone, backs up replaced root
files and independently reads their installed bytes back from FAT.
"""
import argparse
import copy
import contextlib
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gop_startup', HERE/'win98_source_profile.py')
startup = importlib.util.module_from_spec(spec); spec.loader.exec_module(startup)
replacement, need = startup.replacement, startup.need
DRIVERS = ('SHZGOP.DRV', 'SHZGOP.VXD', 'SHZGOP.INF')
BASE = {'KERNEL.SYS', 'COMMAND.COM', 'HIMEMX.EXE', 'CONFIG.SYS', 'AUTOEXEC.BAT'}
UPSTREAMS = {'vmdisp9x': 'd778a911035d414dea9ac852a638a7052c21c400',
             'fixlink': 'a2a74447daea3197255f3a4fb5cfb0c5a453dcc8'}


def read_bytes(held, pin, maximum):
    need(pin['bytes'] <= maximum, 'bounded GOP member required')
    row = held[pin['path']]; row['checkpoint']()
    raw = os.pread(row['fd'], pin['bytes'], 0)
    need(len(raw) == pin['bytes'] and replacement.digest(raw) == pin['sha256'], 'held GOP bytes differ')
    row['checkpoint'](); return raw


def compose_profile(launch, profile, receipt, artifacts, read):
    """Pure admission of already held bytes; produces no execution evidence."""
    launch, profile, receipt, artifacts = copy.deepcopy((launch, profile, receipt, artifacts))
    need(type(profile) is dict and set(profile) == {'schema', 'disk', 'boot_template', 'freedos_source',
         'build_receipt', 'build_source_root', 'payloads'} and profile['schema'] == 'shizukuos.private-replacement-profile.v1',
         'exact existing constructor profile required')
    need(type(launch) is dict and launch.get('schema') == 'shizukuos.private-win98-launch-profile.v1' and
         launch.get('status') == 'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED' and
         launch.get('boot_policy') == 'shz.foundation=win98' and launch.get('source_disk') == profile.get('disk'),
         'original private Win98 HIMEMX/WIN.COM launch profile required')
    for key in ('public_artifact', 'Windows98_boot_verified', 'native_apps_verified', 'VM_executed'):
        need(launch.get(key) is False, 'staging cannot invent native acceptance')
    payloads = profile.get('payloads')
    need(type(payloads) is list and len(payloads) == 5 and
         all(type(p) is dict and set(p) == {'guest', 'file'} for p in payloads) and
         {p['guest'] for p in payloads} == BASE, 'exact existing five startup payloads required')
    selected = launch.get('observed_windows_path')
    need(type(selected) is str and selected.startswith('C:\\') and selected.count('\\') == 1,
         'observed installed Windows directory required')
    need(type(receipt) is dict and receipt.get('schema') == 1 and receipt.get('status') == 'HOST-BUILD-PASS' and
         type(receipt.get('artifacts')) is dict and set(artifacts) == set(DRIVERS),
         'raw baseline GOP producer receipt and three exact driver artifacts required')
    identity = receipt.get('live_provider_identity_sha256')
    need(type(identity) is str and len(identity) == 64 and identity != '0'*64 and all(c in '0123456789abcdef' for c in identity) and
         receipt.get('live_query_opcode') == '0x4f10', 'actual readonly native GOP provider identity/query required')
    for name in DRIVERS:
        pin = artifacts[name]; replacement.pin_fields(pin)
        need(receipt['artifacts'].get(name) == {'bytes': pin['bytes'], 'sha256': pin['sha256']},
             'GOP artifact differs from source producer receipt')
        raw = read(copy.deepcopy(pin))
        need(type(raw) is bytes and len(raw) == pin['bytes'] and replacement.digest(raw) == pin['sha256'],
             'actual source-bound GOP bytes differ')
        if name.endswith(('.DRV', '.VXD')):
            need(len(raw) >= 64 and raw[:2] == b'MZ', 'real DOS executable header required')
            offset = struct.unpack_from('<I', raw, 0x3c)[0]
            need(offset >= 64 and offset + 2 <= len(raw) and
                 raw[offset:offset+2] == (b'NE' if name.endswith('.DRV') else b'LE'), 'native NE DRV/LE VxD required')
        else:
            need(receipt.get('original_inputs', {}).get(name) == pin['sha256'], 'compiled source INF identity required')
            text = raw.decode('cp949').replace('\r\n', '\n')
            for line in ('Class=DISPLAY', 'HKR,DEFAULT,drv,,SHZGOP.DRV', 'HKR,DEFAULT,minivdd,,SHZGOP.VXD'):
                need(text.splitlines().count(line) == 1, 'device-relative GOP INF registration differs')
    # Preserve the existing launch text, locale, XMS, Windows directory and
    # source-disk pins verbatim. Root staging files do not register a display.
    profile['payloads'] += [{'guest': name, 'file': artifacts[name]} for name in DRIVERS]
    return profile


@contextlib.contextmanager
def guarded_inputs(rows, out, owned):
    # The underlying lease union checks again during context exit. A late break
    # must invalidate both consumer-visible receipts, not just staged files.
    try:
        with replacement.leased_inputs(rows) as held:
            yield held
    except BaseException:
        if owned:
            try:
                st = out.stat(follow_symlinks=False)
                if (st.st_dev, st.st_ino) == owned[0]:
                    (out/'replacement-profile.json').unlink(missing_ok=True)
                    (out/'gop-preinstall-profile.json').unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        raise


def lineage_rows(receipt, request):
    rows = []
    def mapping(mapping, root, expected_names=None):
        need(type(mapping) is dict and 0 < len(mapping) <= 30000, 'nonempty bounded recorded source map required')
        if expected_names is not None: need(set(mapping) == expected_names, 'complete producer input map required')
        for name, digest in mapping.items():
            rows.append(replacement.recorded_pin(replacement.source_name(name, root), digest))
    root = replacement.safe_path(request['gop_project_root'])/'drivers/shizuku_gop'
    build = replacement.safe_path(request['gop_build_root'])
    mapping(receipt.get('original_inputs'), root,
            {'backend.c', 'gop_contract.h', 'gop_live_contract.h', 'build.py', 'SHZGOP.INF', 'README.md', 'NOTICE.md'})
    mapping(receipt.get('compiled_sources'), build/'work')
    mapping(receipt.get('generated_link_inputs'), build/'work', {'SHZGOP16.lnk', 'SHZGOP32.lnk'})
    need(type(request['upstream_roots']) is dict and set(request['upstream_roots']) == set(UPSTREAMS), 'exact upstream roots required')
    upstreams = receipt.get('upstreams')
    need(type(upstreams) is dict and set(upstreams) == set(UPSTREAMS), 'actual GOP upstream identities required')
    for name, commit in UPSTREAMS.items():
        source = upstreams[name]
        need(type(source) is dict and source.get('commit') == commit, 'source-built GOP upstream commit differs')
        mapping(source.get('sources'), replacement.safe_path(request['upstream_roots'][name]))
    rows.append(replacement.recorded_pin(build/'source-adaptations.patch', receipt.get('adaptations_sha256')))
    tools = receipt.get('toolchain')
    need(type(tools) is dict and set(tools) == {'wcc', 'wcc386', 'wlink', 'wasm', 'wrc', 'wlib'}, 'complete recorded GOP toolchain required')
    for tool in tools.values():
        need(type(tool) is dict and set(tool) == {'path', 'sha256'}, 'exact recorded compiler pin required')
        rows.append(replacement.recorded_pin(tool['path'], tool['sha256']))
    return rows


def generate(request_path, request_sha, out, capture_budget):
    request_pin = replacement.local_pin(request_path, request_sha)
    request = startup.read_json(request_pin)
    need(type(request) is dict and set(request) == {'schema', 'launch_profile', 'constructor_profile', 'gop_receipt',
         'gop_build_root', 'gop_project_root', 'upstream_roots'} and
         request['schema'] == 'shizukuos.private-gop-preinstall-request.v1', 'exact GOP staging request required')
    out = replacement.safe_path(out); replacement.private_output(out)
    need(not out.exists() and out.parent.is_dir(), 'new owned private output required')
    need(type(capture_budget) is int and 1 << 20 <= capture_budget <= 1 << 30, 'bounded capture budget required')
    producer_inputs = [replacement.local_pin(p) for p in (Path(__file__).resolve(), HERE/'win98_source_profile.py', startup.CONSTRUCTOR)]
    initial = [request_pin, request['launch_profile'], request['constructor_profile'], request['gop_receipt'], *producer_inputs]
    owned = []
    with guarded_inputs(initial, out, owned) as held:
        launch = replacement.bounded_json(held[request['launch_profile']['path']])
        profile = replacement.bounded_json(held[request['constructor_profile']['path']])
        receipt = replacement.bounded_json(held[request['gop_receipt']['path']])
        need(launch.get('constructor_profile') == request['constructor_profile'], 'source launch/constructor pin differs')
        need(profile.get('schema') == 'shizukuos.private-replacement-profile.v1', 'original constructor schema required')
        artifacts = {name: replacement.local_pin(replacement.safe_path(request['gop_build_root'])/'package'/name,
                         receipt['artifacts'][name]['sha256']) for name in DRIVERS}
        source_rows = lineage_rows(receipt, request)
        held.add_inputs([*source_rows, *artifacts.values(), *[p['file'] for p in profile['payloads']]])
        provider_hash = hashlib.sha256()
        provider_root = replacement.safe_path(request['gop_project_root'])/'drivers/shizuku_gop'
        for name in ('backend.c', 'gop_contract.h', 'gop_live_contract.h', 'build.py'):
            pin = next(row for row in source_rows if row['path'] == str(provider_root/name))
            raw = read_bytes(held, pin, 2 << 20)
            provider_hash.update(name.encode()+b'\0'+len(raw).to_bytes(8,'little')+raw)
        need(provider_hash.hexdigest() == receipt.get('live_provider_identity_sha256'),
             'live provider identity differs from actual held source implementation')
        derived = compose_profile(launch, profile, receipt, artifacts, lambda p: read_bytes(held, p, 2 << 20))
        total = sum(p['bytes'] for p in artifacts.values())
        replacement.capacity(out.parent, total + (4 << 20), capture_budget)
        out.mkdir(mode=0o700); st = out.stat(follow_symlinks=False); owned.append((st.st_dev,st.st_ino))
        stage = out/'payloads'; stage.mkdir(mode=0o700)
        staged = {}
        for name, pin in artifacts.items():
            raw = read_bytes(held, pin, 2 << 20); startup.write_private(stage/name, raw)
            staged[name] = {'path': str(stage/name), 'bytes': pin['bytes'], 'sha256': pin['sha256']}
        held.add_inputs(list(staged.values()))
        derived['payloads'][-3:] = [{'guest': name, 'file': staged[name]} for name in DRIVERS]
        profile_path = out/'replacement-profile.json'
        profile_bytes = (json.dumps(derived, indent=2)+'\n').encode()
        profile_pin = {'path': str(profile_path), 'bytes': len(profile_bytes), 'sha256': replacement.digest(profile_bytes)}
        result = {'schema': 'shizukuos.private-gop-preinstall-profile.v1', 'status': 'PRIVATE_GOP_PAYLOADS_PREPARED_NOT_INSTALLED',
                  'public_artifact': False, 'VM_executed': False, 'default_GOP_registered': False,
                  'Windows98_boot_verified': False, 'native_apps_verified': False, 'constructor_profile': profile_pin,
                  'request': request_pin, 'launch_profile': request['launch_profile'], 'gop_receipt': request['gop_receipt'],
                  'gop_artifacts': artifacts, 'staged_payloads': staged,
                  'live_provider_identity_sha256': provider_hash.hexdigest(), 'live_query_opcode': '0x4f10',
                  'Supervisor_epoch_in_descriptor_ABI': False, 'recorded_lineage_pins': source_rows,
                  'producer_inputs': producer_inputs,
                  'native_ingester_compatible': False,
                  'required_live_operation': 'Win98 SetupX16 display class installation for the explicitly observed display devnode and SHZGOP.INF; then registry/file readback and a fresh GOP cold boot',
                  'limitations': ['Root payloads alone do not register the default display.',
                    'Baseline native ingestion deliberately requires five root payloads, not these eight.',
                    'Recorded GOP producer source maps are verified; omitted toolchain headers are not independently recovered.',
                    'Use the existing constructor to clone/apply; it preserves originals and backs up/readbacks replaced root files.']}
        result_path = out/'gop-preinstall-profile.json'
        # The outer ownership-aware lease guard revokes consumer profiles on
        # publication failure or final source drift, including late exit checks.
        startup.publish(result_path, (json.dumps(result, indent=2)+'\n').encode())
        startup.publish(profile_path, profile_bytes)
        held.add_inputs([profile_pin, replacement.local_pin(result_path)])
        for entry in held.values(): entry['checkpoint']()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--capture-budget-bytes', type=int, required=True)
    args = parser.parse_args(); result = generate(args.request, args.request_sha256, args.out, args.capture_budget_bytes)
    print(json.dumps({'status': result['status'], 'constructor_profile': result['constructor_profile'], 'default_GOP_registered': False}))


if __name__ == '__main__': main()
