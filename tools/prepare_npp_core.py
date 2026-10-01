#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare a guarded, byte-preserving merge of freshly read guest CORE.INI.

Never installs files or changes registry/configuration on the host or guest.
The selected existing app profile alone receives provider contents/routes.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    if not data or len(data) > 1024 * 1024 or b'\0' in data or data.startswith((b'\xff\xfe', b'\xfe\xff', b'\xef\xbb\xbf')):
        raise ValueError('Expected the installed ANSI-compatible CORE.INI bytes')
    sections = {}; section = None; offset = 0
    for line in data.splitlines(keepends=True):
        body = line.rstrip(b'\r\n')
        heading = re.fullmatch(rb'\s*\[([A-Za-z0-9_.-]+)\]\s*(?:;[^\r\n]*)?', body)
        if heading:
            name = heading[1].decode('ascii').lower()
            if name in sections:
                raise ValueError('Duplicate section: ' + name)
            if section is not None:
                section['end'] = offset
            section = {'name': name, 'start': offset, 'end': len(data), 'keys': {}}
            sections[name] = section
        elif body.strip() and not body.lstrip().startswith((b';', b'#')):
            key = re.fullmatch(rb'\s*([^=\r\n]+?)\s*=([^\r\n]*)', body)
            if key is None or section is None:
                raise ValueError('Unexpected INI line')
            name = key[1].strip().decode('ascii').lower()
            if name in section['keys']:
                raise ValueError('Duplicate key: ' + section['name'] + '.' + name)
            section['keys'][name] = {'value': key[2].strip(), 'line': offset,
                                    'value_start': offset + key.start(2),
                                    'value_end': offset + key.end(2)}
        offset += len(line)
    return sections


def compiled_provider_catalog(plan):
    """Read hash-bound local API tables; never execute a provider or initializer."""
    metadata = plan.get('provider_metadata', {})
    if not isinstance(metadata, dict) or set(metadata) - set(plan['libraries']):
        raise ValueError('Invalid compiled provider metadata')
    if not metadata:
        return {}
    spec = importlib.util.spec_from_file_location('core_provider_tables', ROOT / 'tools/prepare_vlc_staging.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    catalog = {}
    for library, record in metadata.items():
        if (not isinstance(record, dict) or set(record) != {'path', 'sha256'} or
                not isinstance(record['sha256'], str) or
                not re.fullmatch('[a-f0-9]{64}', record['sha256'])):
            raise ValueError('Exact compiled provider path and hash required')
        path = Path(record['path']).resolve(strict=True)
        if not path.is_relative_to(ROOT / 'build') or path.stat().st_size > 1024 * 1024:
            raise ValueError('Bounded private compiled provider required')
        raw = path.read_bytes()
        if sha(raw) != record['sha256']:
            raise ValueError('Compiled provider hash differs')
        tables = reader.linked_kex_tables(raw, local_functions=True, indexed=True)
        if not tables or path.read_bytes() != raw:
            raise ValueError('Compiled provider changed during static table read')
        # ApiConfigurationManager::parse_overrides appends .DLL to the INI
        # module before ApiConfiguration::merge compares target_library.
        # Inventory normalization alone cannot prove that raw declaration.
        targets = [table.get('target_library', '').upper() for table in tables]
        if (any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}\.DLL', target) for target in targets) or
                len(set(targets)) != len(targets)):
            raise ValueError('Exact unique KernelEx target_library with .DLL required')
        catalog[library] = {table['index']: table for table in tables}
    return catalog


def merge(data, plan, provider_tables=None):
    sections = parse(data)
    if plan.get('schema') != 1 or plan.get('kind') != 'native-npp-provider-routes':
        raise ValueError('Unsupported route plan')
    profile = plan['profile']
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,31}', profile):
        raise ValueError('Invalid app profile')
    profile_key = profile.lower()
    if profile_key not in sections or 'apiconfigurations' not in sections:
        raise ValueError('Selected app profile is absent from the installed configuration')
    configurations = sections['apiconfigurations']['keys']
    # The real loader queries 0, 1, ... and stops at the first absent or empty
    # entry. A later declaration or an ancestor loaded after its child cannot
    # make the selected configuration available to the settings service.
    declared = []
    for index in range(65536):
        entry = configurations.get(str(index))
        if entry is None or not entry['value']:
            break
        declared.append(entry['value'].decode('ascii'))
    if profile not in declared:
        raise ValueError('App profile is not declared in ApiConfigurations')
    # Require a real, acyclic inherited profile chain; do not invent one.
    current = profile; seen = set()
    while current:
        current_key = current.lower()
        if current_key in seen or current_key not in sections or current not in declared:
            raise ValueError('Invalid app profile inheritance')
        seen.add(current_key)
        inherit = sections[current_key]['keys'].get('inherit', {}).get('value', b'none').decode('ascii')
        if inherit.lower() == 'none':
            current = ''
        elif inherit not in declared or declared.index(inherit) >= declared.index(current):
            raise ValueError('Invalid app profile inheritance load order')
        else:
            current = inherit
    libraries = plan['libraries']
    if not libraries or len(libraries) > 16 or len(set(libraries)) != len(libraries) or any(
            not re.fullmatch(r'[a-z][a-z0-9]{0,7}', name) for name in libraries):
        raise ValueError('Invalid provider libraries')
    provider_tables = {} if provider_tables is None else provider_tables
    metadata = plan.get('provider_metadata', {})
    if (not isinstance(metadata, dict) or set(metadata) != set(provider_tables) or
            set(provider_tables) - set(libraries)):
        raise ValueError('Compiled provider metadata must be verified before merging')
    ending = b'\r\n' if b'\r\n' in data else (b'\r' if b'\r' in data else b'\n')
    edits = []; insertions = {}; added = {'libraries': [], 'names': [], 'ordinals': [], 'replaced': []}
    replacements = plan.get('expected_existing', {})
    if not isinstance(replacements, dict) or set(replacements) - {'names', 'ordinals'}:
        raise ValueError('Invalid expected route replacement guards')

    def insert(at, payload):
        insertions[at] = insertions.get(at, b'') + payload

    contents = sections[profile_key]['keys'].get('contents')
    existing = [] if contents is None or contents['value'].lower() == b'none' else contents['value'].decode('ascii').split(',')
    if len(set(s.lower() for s in existing)) != len(existing) or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,15}', item) for item in existing):
        raise ValueError('Invalid existing profile contents')
    added['libraries'] = [name for name in libraries if name.lower() not in {s.lower() for s in existing}]
    final = ','.join(existing + added['libraries']).encode('ascii')
    if len(final) >= 256:
        raise ValueError('Contents exceeds actual KernelEx parser buffer')
    if added['libraries']:
        if contents:
            old = data[contents['value_start']:contents['value_end']]
            leading = old[:len(old)-len(old.lstrip())]; trailing = old[len(old.rstrip()):]
            edits.append((contents['value_start'], contents['value_end'], leading + final + trailing))
        else:
            insert(sections[profile_key]['end'], b'contents=' + final + ending)
    for category in ('names', 'ordinals'):
        routes = plan.get(category, {})
        generic = profile_key + '.' + category
        specific = generic + '.98'
        # KernelEx selects .98 INSTEAD of generic when .98 has entries.
        # Modify the active section; never shadow existing version-mode routes.
        target = specific if specific in sections and sections[specific]['keys'] else generic
        present = sections.get(target, {}).get('keys', {})
        guarded = replacements.get(category, {})
        if not isinstance(guarded, dict) or set(guarded) - set(routes) or any(
                not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.]+', value) for value in guarded.values()):
            raise ValueError('Replacement guards must identify exact selected routes')
        pending = []
        folded = set()
        for name, value in routes.items():
            pattern = r'[A-Z][A-Z0-9_]{0,31}\.[A-Za-z_][A-Za-z0-9_]{0,254}' if category == 'names' else r'[A-Z][A-Z0-9_]{0,31}\.[0-9]{1,5}'
            if not re.fullmatch(pattern, name) or len(name) > 255 or name.lower() in folded:
                raise ValueError('Invalid or duplicate provider route')
            folded.add(name.lower())
            if category == 'ordinals' and not 1 <= int(name.split('.')[1]) <= 65535:
                raise ValueError('Invalid provider ordinal')
            selector = re.fullmatch(r'([a-z][a-z0-9]{0,7})\.(0|[1-9][0-9]{0,2})', value)
            if not selector or selector[1] not in libraries:
                raise ValueError('Route does not reference a selected actual provider')
            library, variant = selector[1], int(selector[2])
            if library in provider_tables:
                module, symbol = name.split('.', 1)
                parsed_module = module + '.DLL'
                matches = [table for table in provider_tables[library].values()
                           if table.get('target_library', '').upper() == parsed_module]
                if len(matches) != 1 or matches[0]['module'] != parsed_module:
                    raise ValueError('Route differs from the actual compiled provider table')
                values = matches[0][category]
                selected = symbol if category == 'names' else int(symbol)
                # Official ApiConfiguration::merge uses lower_bound(symbol),
                # then advances by the suffix to another declaration of that
                # SAME symbol. The suffix never selects the module-table index.
                if values != sorted(values) or variant >= values.count(selected):
                    raise ValueError('Route differs from the actual compiled provider table')
            elif variant != 0:
                raise ValueError('Nonzero provider variant requires exact compiled metadata')
            old = present.get(name.lower())
            if old and old['value'].lower() != value.encode().lower():
                if name not in guarded or old['value'] != guarded[name].encode():
                    raise ValueError('Conflicting existing route: ' + target + '.' + name)
                raw = data[old['value_start']:old['value_end']]
                leading = raw[:len(raw)-len(raw.lstrip())]; trailing = raw[len(raw.rstrip()):]
                edits.append((old['value_start'], old['value_end'], leading + value.encode() + trailing))
                added['replaced'].append({'section': target, 'key': name,
                                          'before': guarded[name], 'after': value})
            if not old and name in guarded:
                raise ValueError('Expected existing route is absent: ' + name)
            if not old:
                pending.append(name.encode() + b'=' + value.encode() + ending)
                added[category].append(name)
        if pending:
            payload = b''.join(pending)
            if target in sections:
                insert(sections[target]['end'], payload)
            else:
                insert(len(data), ending + b'[' + target.encode() + b']' + ending + payload)
    for at, payload in insertions.items():
        prefix = b'' if at == 0 or data[at-1:at] in (b'\r', b'\n') else ending
        edits.append((at, at, prefix + payload))
    result = data
    for start, end, value in sorted(edits, reverse=True):
        result = result[:start] + value + result[end:]
    parse(result)
    return result, added


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.input.resolve(strict=True); plan_path = args.plan.resolve(strict=True)
    output = args.output.resolve(); output.relative_to(ROOT / 'build')
    if output.exists() or output.with_suffix(output.suffix + '.receipt.json').exists():
        parser.error('Use an absent private output path')
    data = source.read_bytes(); plan_bytes = plan_path.read_bytes()
    if sha(data) != args.input_sha256 or sha(plan_bytes) != args.plan_sha256:
        parser.error('Fresh guest configuration or provider plan hash differs')
    plan = json.loads(plan_bytes)
    catalog = compiled_provider_catalog(plan)
    result, additions = merge(data, plan, catalog)
    if source.read_bytes() != data or plan_path.read_bytes() != plan_bytes:
        parser.error('Input changed while preparing configuration')
    if any(sha(Path(record['path']).read_bytes()) != record['sha256']
           for record in plan.get('provider_metadata', {}).values()):
        parser.error('Compiled provider changed while preparing configuration')
    receipt = {'status': 'PASS', 'input': str(source), 'input_sha256': sha(data),
               'plan': str(plan_path), 'plan_sha256': sha(plan_bytes),
               'output': str(output), 'output_sha256': sha(result), 'added': additions,
               'guest_installed': False, 'application_launched': False}
    output.parent.mkdir(parents=True, exist_ok=True); output.write_bytes(result)
    output.with_suffix(output.suffix + '.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
