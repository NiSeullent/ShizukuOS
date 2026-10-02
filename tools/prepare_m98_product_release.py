#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate full-goal receipts and prepare private m98 download metadata.

No guest execution, ISO build/copy, live publication, nginx or DNS operation.
Approved receipts remain claims of their actual producers, not this tool's
execution evidence. Missing full-goal gates never become a component release.
"""
import argparse
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess

SCOPE = 'product-ShizukuOS-1.0.0'
ORIGIN = 'https://m98.nyase.kr'
FLOOR = 22_058_516_480
RESERVE = 16 * 1024 * 1024
ARTIFACTS = {'public_iso', 'boot_loader', 'dos_foundation', 'kernel32', 'kernel64', 'vxd', 'installer'}
CHECKS = {
    'public_iso': {'no Microsoft media or secrets', 'project installer and corresponding source closure', 'builder artifact and source identities verified'},
    'windows98_boot': {'actual Windows 98 started on ShizukuDOS', 'original Microsoft DOS absent from boot chain'},
    'windows98_vmm': {'VMM schedules Windows threads', 'actual asynchronous PMA wait and wake', 'actual DOS executor context'},
    'native_smp': {'two or more native PMA CPUs execute work', 'concurrent work progresses on separate CPUs', 'VMM scheduling authority preserved'},
    'iso_bios': {'exact public ISO boots through BIOS'},
    'iso_uefi': {'exact public ISO boots through UEFI'},
    'installation': {'project installer executes', 'cancel writes no target bytes', 'installed Windows 98 on ShizukuDOS cold boots', 'installed data persists after restart'},
    'full_goal': set(),
}
SPEC_ROLES = {'win98_architecture', 'shizukudos10_integration'}
CATEGORIES = {'distribution', 'windows98_integration', 'vmm_authority',
              'pma_scheduling_smp', 'dos_foundation', 'display_gop', 'installer',
              'modern_applications', 'nt_wrapper_compatibility',
              'legacy_win16_win32', 'failure_lifecycle', 'modern_web_features'}
STATUSES = {'PASS', 'FAIL', 'BLOCKED'}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) and
         value != '0' * 64, 'literal nonzero SHA256 required')
    return value


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def read_pin(path, limit):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and
         not any(p.is_symlink() for p in (path, *path.parents)), 'canonical nonsymlink input required')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'bounded regular input required')
    h = hashlib.sha256()
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        count = 0
        for block in iter(lambda: handle.read(1 << 20), b''):
            count += len(block)
            need(count <= limit, 'input grew beyond bound')
            h.update(block)
        after = os.fstat(handle.fileno())
    shape = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(shape(before) == shape(opened) == shape(after) == shape(path.stat()) and
         count == before.st_size, 'input changed during read')
    return {'path': str(path), 'bytes': count, 'sha256': h.hexdigest()}


def checked_pin(row, limit, pins):
    need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'}, 'exact file pin fields required')
    need(type(row['bytes']) is int and 0 < row['bytes'] <= limit, 'bounded literal file size required')
    sha(row['sha256'])
    actual = read_pin(row['path'], limit)
    need(actual == row, 'file identity differs: ' + row['path'])
    pins[row['path']] = actual
    return actual


def pinned_json(row, pins):
    checked_pin(row, 1 << 20, pins)
    data = Path(row['path']).read_bytes()
    need(hashlib.sha256(data).hexdigest() == row['sha256'], 'JSON changed before parse')
    return json.loads(data, object_pairs_hook=unique_pairs)


def git(source, *args):
    return subprocess.run(['git', '-C', str(source), *args], check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()


def current_source(source, commit):
    need(git(source, 'rev-parse', 'HEAD') == commit, 'source checkout differs from final commit')
    need(not git(source, 'status', '--porcelain', '--untracked-files=no'), 'tracked source is dirty')


def verify_pins(pins):
    for row in pins.values():
        need(read_pin(row['path'], row['bytes']) == row, 'late input drift')


def source_pins(mapping, source, tracked, pins):
    need(isinstance(mapping, dict) and 1 <= len(mapping) <= 30000, 'nonempty bounded transitive source closure required')
    for name, digest in mapping.items():
        need(isinstance(name, str), 'source path must be text')
        p = PurePosixPath(name)
        need(not p.is_absolute() and '..' not in p.parts and '\\' not in name and name in tracked,
             'tracked safe project source required')
        sha(digest)
        actual = read_pin(source / name, 64 << 20)
        need(actual['sha256'] == digest, 'source identity differs: ' + name)
        pins[actual['path']] = actual


def text_field(value, limit, label):
    need(isinstance(value, str) and 1 <= len(value) <= limit and value == value.strip() and
         not any(ord(c) < 32 or ord(c) == 127 for c in value), label + ' must be bounded explicit text')
    return value


def project_pin(row, source, tracked, pins):
    need(isinstance(row, dict) and set(row) == {'path', 'sha256'}, 'exact tracked source pin fields required')
    name = row['path']
    need(isinstance(name, str) and name and '\\' not in name, 'safe project source path required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == name and name in tracked,
         'tracked safe project source required')
    sha(row['sha256'])
    actual = read_pin(source / name, 4 << 20)
    need(actual['sha256'] == row['sha256'], 'goal/source specification identity differs: ' + name)
    pins[actual['path']] = actual
    return actual


def version_field(value):
    text_field(value, 128, 'observed application version')
    need(value.casefold() not in {'unknown', 'unresolved', 'latest', 'unspecified', 'n/a',
                                'none', 'null', 'pending', 'tbd', '*'} and
         any(c.isdigit() for c in value), 'explicit observed application version required')
    return value


def load_contract(row, source, tracked, pins):
    actual = project_pin(row, source, tracked, pins)
    contract = pinned_json(actual, pins)
    need(isinstance(contract, dict) and set(contract) == {'schema', 'scope', 'source_specs', 'requirements'} and
         contract['schema'] == 'shizukuos.requirements.v1' and contract['scope'] == SCOPE,
         'complete full-product requirements contract required')
    specs = contract['source_specs']
    need(isinstance(specs, list) and len(specs) == 2, 'both original source specification roles required')
    roles, closure = set(), {row['path']: row['sha256']}
    for spec_row in specs:
        need(isinstance(spec_row, dict) and set(spec_row) == {'role', 'path', 'sha256'} and
             isinstance(spec_row['role'], str) and spec_row['role'] in SPEC_ROLES and
             spec_row['role'] not in roles, 'unique original specification roles required')
        roles.add(spec_row['role'])
        project_pin({'path': spec_row['path'], 'sha256': spec_row['sha256']}, source, tracked, pins)
        need(spec_row['path'] not in closure, 'distinct original specification source paths required')
        closure[spec_row['path']] = spec_row['sha256']
    need(roles == SPEC_ROLES, 'both original source specification roles required')
    rows = contract['requirements']
    need(isinstance(rows, list) and 1 <= len(rows) <= 4096, 'nonempty bounded concrete requirements required')
    requirements, categories, gates = {}, set(), set()
    for requirement in rows:
        need(isinstance(requirement, dict) and set(requirement) ==
             {'id', 'category', 'description', 'gate', 'checks', 'applications'}, 'exact concrete requirement fields required')
        ident = requirement['id']
        need(isinstance(ident, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', ident) and
             ident not in requirements, 'unique concrete requirement IDs required')
        text_field(requirement['description'], 8192, 'requirement description')
        need(isinstance(requirement['category'], str) and requirement['category'] in CATEGORIES,
             'known requirement category required')
        need(isinstance(requirement['gate'], str) and requirement['gate'] in CHECKS,
             'known requirement producer gate required')
        labels = requirement['checks']
        need(isinstance(labels, list) and 1 <= len(labels) <= 512, 'concrete requirement checks required')
        for label in labels:
            text_field(label, 512, 'requirement check')
        need(len(set(labels)) == len(labels), 'unique requirement check names required')
        apps = requirement['applications']
        need(isinstance(apps, list) and len(apps) <= 256, 'bounded requirement applications required')
        names = set()
        for app in apps:
            need(isinstance(app, dict) and set(app) == {'name', 'version'}, 'exact required application fields required')
            name = text_field(app['name'], 256, 'application name')
            need(name not in names, 'unique application names required')
            names.add(name)
            if app['version'] is not None:
                version_field(app['version'])
        requirements[ident] = requirement
        categories.add(requirement['category'])
        gates.add(requirement['gate'])
    need(categories == CATEGORIES, 'complete requirement categories required')
    need(gates == CHECKS.keys(), 'all eight full-goal producer gates required in contract')
    return requirements, closure


def output_hashes(values, allowed):
    need(isinstance(values, list) and 1 <= len(values) <= 64, 'nonempty actual producer output SHA256 references required')
    for digest in values:
        sha(digest)
        if allowed is not None:
            need(digest in allowed, 'behavior evidence must come from its exact producer check outputs')
    need(len(set(values)) == len(values), 'unique behavior output identities required')
    return set(values)


def validate_requirements(proof, requirements, producers):
    rows = proof.get('requirements')
    need(isinstance(rows, list) and len(rows) == len(requirements), 'exact full-goal requirement receipt set required')
    seen, blocked = set(), []
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'id', 'status', 'checks', 'applications'} and
             isinstance(row['id'], str) and row['id'] in requirements and row['id'] not in seen,
             'unique known full-goal requirement IDs required')
        ident = row['id']
        seen.add(ident)
        required = requirements[ident]
        need(row['status'] in STATUSES, 'explicit requirement status required')
        producer = producers.get(required['gate'])
        passed = row['status'] == 'PASS' and producer is not None and producer['passed']
        if required['category'] == 'modern_applications' and not required['applications']:
            passed = False
        checks = row['checks']
        need(isinstance(checks, list) and len(checks) == len(required['checks']), 'exact requirement behavior checks required')
        seen_checks = set()
        for check in checks:
            need(isinstance(check, dict) and set(check) == {'check', 'status', 'output_sha256'} and
                 isinstance(check['check'], str) and check['check'] in required['checks'] and
                 check['check'] not in seen_checks and check['status'] in STATUSES,
                 'unique required behavior receipt checks required')
            label = check['check']
            seen_checks.add(label)
            actual = producer['checks'][label] if producer is not None else None
            output_hashes(check['output_sha256'], actual['outputs'] if actual is not None else None)
            passed = passed and check['status'] == 'PASS' and actual is not None and actual['status'] == 'PASS'
        apps = row['applications']
        need(isinstance(apps, list) and len(apps) == len(required['applications']), 'exact observed application set required')
        expected_apps = {app['name']: app['version'] for app in required['applications']}
        seen_apps = set()
        behavior_outputs = {digest for check in checks for digest in check['output_sha256']}
        for app in apps:
            need(isinstance(app, dict) and set(app) == {'name', 'version', 'output_sha256'} and
                 isinstance(app['name'], str) and app['name'] in expected_apps and app['name'] not in seen_apps,
                 'unique required observed application names required')
            seen_apps.add(app['name'])
            version_field(app['version'])
            need(expected_apps[app['name']] is None or app['version'] == expected_apps[app['name']],
                 'observed application version differs from required version')
            output_hashes(app['output_sha256'], behavior_outputs)
        if not passed:
            blocked.append(ident)
    need(seen == requirements.keys(), 'exact full-goal requirement receipt set required')
    return {'total': len(requirements), 'passed': len(requirements) - len(blocked), 'blocked': sorted(blocked)}


def inspect_index(path, expected_sha, source):
    """Validate reviewed actual-producer records; this never executes a producer."""
    pins = {}
    path = Path(path).absolute()
    index_pin = read_pin(path, 1 << 20)
    need(index_pin['sha256'] == sha(expected_sha), 'unapproved release index')
    data = pinned_json(index_pin, pins)
    need(isinstance(data, dict) and set(data) == {'schema', 'scope', 'release_id', 'source_commit',
         'goal_contract', 'artifacts', 'gates'}, 'exact release index fields required')
    need(data['schema'] == 'shizukuos.full-release-index.v1' and data['scope'] == SCOPE,
         'full ShizukuOS product scope required')
    need(isinstance(data['source_commit'], str) and re.fullmatch('[0-9a-f]{40}', data['source_commit']), 'exact final source commit required')
    need(isinstance(data['release_id'], str) and re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}', data['release_id']), 'safe release identifier required')
    source = Path(source).resolve(strict=True)
    current_source(source, data['source_commit'])
    tracked = set(git(source, 'ls-files', '--recurse-submodules', '-z').split('\0'))
    requirements, contract_closure = load_contract(data['goal_contract'], source, tracked, pins)
    missing_apps = sorted(ident for ident, row in requirements.items()
                          if row['category'] == 'modern_applications' and not row['applications'])
    required_checks = {role: set(labels) for role, labels in CHECKS.items()}
    for row in requirements.values():
        required_checks[row['gate']].update(row['checks'])
    need(isinstance(data['artifacts'], dict) and data['artifacts'].keys() <= ARTIFACTS, 'only project artifact roles allowed')
    artifacts = {}
    for role, row in data['artifacts'].items():
        checked_pin(row, 512 << 20, pins)
        name = Path(row['path']).name
        need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name), 'safe public artifact basename required')
        need(role != 'public_iso' or name.endswith('.iso') and '-private' not in name.lower(), 'public ISO required')
        artifacts[role] = row
    need(sum(r['bytes'] for r in artifacts.values()) <= 1 << 30, 'project artifact set exceeds bound')
    need(isinstance(data['gates'], dict) and data['gates'].keys() <= CHECKS.keys(), 'known full-goal gates required')
    gates, failures, producers = {}, [], {}
    identities = {role: row['sha256'] for role, row in artifacts.items()}
    for role, entry in data['gates'].items():
        need(isinstance(entry, dict) and set(entry) == {'receipt', 'runner', 'sources_sha256'}, 'exact gate index fields required')
        proof = pinned_json(entry['receipt'], pins)
        need(isinstance(proof, dict) and proof.get('schema') == 'shizukuos.full-release-gate.v1', 'actual full-goal producer receipt required')
        need(proof.get('scope') == SCOPE and proof.get('gate') == role, 'component or wrong-gate scope rejected')
        need(proof.get('source_commit') == data['source_commit'] and proof.get('goal_contract_sha256') == data['goal_contract']['sha256'], 'source or goal predecessor receipt rejected')
        need(proof.get('modeled') is False and proof.get('component_only') is False, 'modeled/component receipt rejected')
        modes = {'actual-readback'} if role == 'public_iso' else {'actual-guest', 'actual-hardware'}
        need(proof.get('execution') in modes, 'actual execution mode required')
        runner = entry['runner']
        need(isinstance(runner, dict) and set(runner) == {'path', 'sha256'} and proof.get('runner') == runner,
             'exact reviewed runner identity required')
        need(proof.get('sources_sha256') == entry['sources_sha256'], 'transitive source closure differs')
        source_pins(entry['sources_sha256'], source, tracked, pins)
        need(all(entry['sources_sha256'].get(name) == digest for name, digest in contract_closure.items()),
             'goal contract and original specifications absent from producer closure')
        need(entry['sources_sha256'].get(runner['path']) == runner['sha256'], 'runner absent from source closure')
        need(proof.get('artifacts_sha256') == identities and set(identities) == ARTIFACTS,
             'exact final project artifact identities required')
        outputs = proof.get('outputs')
        need(isinstance(outputs, list) and 1 <= len(outputs) <= 64, 'bounded actual output hashes required')
        need(all(isinstance(row, dict) and type(row.get('bytes')) is int for row in outputs), 'literal output byte sizes required')
        need(sum(row['bytes'] for row in outputs) <= 64 << 20, 'output budget exceeded')
        output_paths, output_digests = set(), set()
        for row in outputs:
            checked_pin(row, 16 << 20, pins)
            need(row['path'] not in output_paths, 'duplicate output identity')
            output_paths.add(row['path'])
            output_digests.add(row['sha256'])
        rows = proof.get('checks')
        need(isinstance(rows, list) and 1 <= len(rows) <= 512, 'nonempty bounded checks required')
        names, check_records = set(), {}
        for row in rows:
            need(isinstance(row, dict) and set(row) == {'check', 'status', 'output_sha256'} and
                 isinstance(row.get('check'), str) and 1 <= len(row['check']) <= 512 and
                 row['check'] not in names and row.get('status') in STATUSES, 'unique explicit gate checks required')
            names.add(row['check'])
            check_records[row['check']] = {'status': row['status'], 'outputs': output_hashes(row['output_sha256'], output_digests)}
        need(required_checks[role] <= names, 'required actual behavior check omitted: ' + role)
        need(proof.get('status') in ('PASS', 'FAIL', 'BLOCKED'), 'explicit producer status required')
        passed = proof['status'] == 'PASS' and all(r['status'] == 'PASS' for r in rows)
        producers[role] = {'proof': proof, 'checks': check_records, 'outputs': output_digests, 'passed': passed}
        gates[role] = {'status': 'PASS' if passed else 'BLOCKED', 'receipt_sha256': entry['receipt']['sha256'],
                       'execution': proof['execution'], 'runner_sha256': runner['sha256'], 'outputs': len(outputs)}
        if not passed:
            failures.append(role)
    missing = sorted(CHECKS.keys() - gates.keys())
    absent_artifacts = sorted(ARTIFACTS - artifacts.keys())
    requirement_status = {'total': len(requirements), 'passed': 0, 'blocked': sorted(requirements)}
    if 'full_goal' in producers:
        requirement_status = validate_requirements(producers['full_goal']['proof'], requirements, producers)
        if requirement_status['blocked'] and 'full_goal' not in failures:
            failures.append('full_goal')
            gates['full_goal']['status'] = 'BLOCKED'
    verify_pins(pins)
    current_source(source, data['source_commit'])
    return {'schema': 'shizukuos.release-preparation.v1', 'scope': SCOPE,
            'status': 'BLOCKED' if missing or failures or absent_artifacts or missing_apps else 'ACCEPTANCE_RECEIPTS_VALIDATED',
            'release_id': data['release_id'], 'source_commit': data['source_commit'],
            'goal_contract': data['goal_contract'], 'goal_contract_sha256': data['goal_contract']['sha256'],
            'requirements': requirement_status, 'gates': gates,
            'missing_application_inventory': missing_apps,
            'missing_gates': missing, 'failed_gates': failures, 'missing_artifacts': absent_artifacts,
            'artifacts': artifacts, 'index_sha256': expected_sha, 'input_pins': pins,
            'source_root': str(source), 'guest_executed': False, 'published': False,
            'network_performed': False, 'iso_copied': False}


def publication_capacity(available, artifact_bytes):
    required = FLOOR + RESERVE + artifact_bytes
    return {'ready': available >= required, 'available_bytes': available, 'required_bytes': required,
            'preserved_floor_bytes': FLOOR, 'artifact_bytes': artifact_bytes}


def preservation_snapshot(base, expected, route_config):
    """Reuse the existing publisher's read-only complete-release inventory."""
    helper = Path(__file__).resolve().with_name('publish_m98_continuation.py')
    helper_pin = read_pin(helper, 1 << 20)
    spec = importlib.util.spec_from_file_location('m98_existing_publisher', helper)
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)
    base, expected = Path(base).absolute(), Path(expected).absolute()
    publisher.canonical(base, directory=True)
    release, literal = publisher.current_release(base, expected)
    records = publisher.inventory(release)
    config_pin = read_pin(route_config, 1 << 20)
    need(read_pin(helper, 1 << 20) == helper_pin, 'inventory helper changed')
    return {'base': str(base), 'expected_release': str(release), 'current_literal': literal,
            'inventory': records, 'route_config': config_pin, 'helper': helper_pin,
            'body_hashes': {'/' + name[len('site/'):]: {'sha256': row['sha256'], 'bytes': row['size']}
                            for name, row in records.items()},
            'alias_checks_required': {'/': '/index.html', '/en/': '/en/index.html',
                                     '/vnc.html': '/', '/vnc_lite.html': '/'},
            'public_dns_tls_verification_required': True}


def verify_preservation(snapshot):
    try:
        current = preservation_snapshot(snapshot['base'], snapshot['expected_release'], snapshot['route_config']['path'])
    except OSError as error:
        raise ValueError('old site/current/config no longer exists') from error
    need(current == snapshot, 'old site/current/config changed before staging')


def download_assets(report):
    need(report['status'] == 'ACCEPTANCE_RECEIPTS_VALIDATED', 'all full-goal receipts required before download copy')
    iso = report['artifacts']['public_iso']
    name = Path(iso['path']).name
    root = ORIGIN + '/downloads/' + report['release_id'] + '/'
    public = {'schema': 'shizukuos.official-download.v1', 'product': 'ShizukuOS', 'version': '1.0.0',
              'source_commit': report['source_commit'], 'goal_contract_sha256': report['goal_contract_sha256'],
              'origin': ORIGIN, 'windows98_media_included': False,
              'artifact': {'url': root + name, 'filename': name, 'bytes': iso['bytes'], 'sha256': iso['sha256']},
              'acceptance_receipts': report['gates']}
    assets = {'manifest.json': (json.dumps(public, indent=2, ensure_ascii=False) + '\n').encode(),
              'SHA256SUMS': (iso['sha256'] + '  ' + name + '\n').encode('ascii')}
    for english in (False, True):
        lang = 'en' if english else 'ko'
        title = 'ShizukuOS 1.0.0 installation ISO' if english else 'ShizukuOS 1.0.0 설치 ISO'
        note = ('Contains project installation code and required sources/licenses. Provide your licensed Windows 98 media locally.' if english else
                '프로젝트 설치 코드와 필요한 소스·라이선스를 포함합니다. 정당한 라이선스의 Windows 98 매체는 로컬에서 준비하세요.')
        page = '<!doctype html><html lang="' + lang + '"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + title + '</title><body><nav><a href="' + ORIGIN + '/">m98.nyase.kr</a> · <a href="' + ('index.html' if english else 'en.html') + '">' + ('한국어' if english else 'English') + '</a></nav><h1>' + title + '</h1><p>' + note + '</p><p><a download href="' + root + html.escape(name, quote=True) + '">' + html.escape(name) + '</a> (' + str(iso['bytes']) + ' bytes)</p><p>SHA-256: <code>' + iso['sha256'] + '</code></p><p><a href="SHA256SUMS">SHA256SUMS</a> · <a href="manifest.json">manifest.json</a></p><pre>sha256sum --check SHA256SUMS</pre></body></html>\n'
        assets['en.html' if english else 'index.html'] = page.encode()
    return assets


def write_preparation(report, out):
    out = Path(out).absolute()
    need(not out.is_relative_to('/srv/m98') and not out.exists() and not out.is_symlink() and out.parent.resolve(strict=True) == out.parent and
         not any(p.is_symlink() for p in out.parents), 'fresh private owned output required; live m98 writes prohibited')
    if 'preservation' in report:
        need(not out.is_relative_to(report['preservation']['base']), 'preserved origin cannot be a private staging directory')
    verify_pins(report['input_pins'])
    current_source(report['source_root'], report['source_commit'])
    if 'preservation' in report:
        verify_preservation(report['preservation'])
    capacity = publication_capacity(shutil.disk_usage(out.parent).free, sum(r['bytes'] for r in report['artifacts'].values()))
    result = dict(report, capacity=capacity)
    if not capacity['ready']:
        result['status'] = 'BLOCKED'
        result['resource_blocker'] = 'preserved publication floor unavailable'
    out.mkdir(mode=0o700)
    if result['status'] == 'ACCEPTANCE_RECEIPTS_VALIDATED':
        dest = out / 'site' / 'downloads' / result['release_id']
        dest.mkdir(parents=True)
        routes = []
        for name, data in download_assets(report).items():
            (dest / name).write_bytes(data)
            routes.append({'path': '/downloads/' + result['release_id'] + '/' + name,
                           'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        result['prepared_body_hashes'] = routes
    verify_pins(report['input_pins'])
    if 'preservation' in report:
        verify_preservation(report['preservation'])
    current_source(report['source_root'], report['source_commit'])
    (out / 'readiness.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--index-sha256', required=True)
    ap.add_argument('--source-root', type=Path, required=True)
    ap.add_argument('--out', type=Path, help='fresh private output; default prints read-only readiness')
    ap.add_argument('--site-base', type=Path, default=Path('/srv/m98'))
    ap.add_argument('--expected-current', type=Path, help='approved existing immutable release to preserve')
    ap.add_argument('--route-config', type=Path, default=Path('/srv/m98/nginx/locations.conf'))
    args = ap.parse_args()
    report = inspect_index(args.index, args.index_sha256, args.source_root)
    if args.expected_current:
        report['preservation'] = preservation_snapshot(args.site_base, args.expected_current, args.route_config)
    if args.out:
        report = write_preparation(report, args.out)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 2 if report['status'] == 'BLOCKED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
