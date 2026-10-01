#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reproduce factual GEOID records from pinned local inputs, without execution.

Only literal records from Wine's geoids array are read. Neither its Perl
generator nor any downloaded source is executed. The output must be new and
inside build/; --verify compares it with the held production table.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WINE_SHA = 'f0284d8eee7f213cb5ff1db1264fd90d689fe3a36358451574a0511fa019e637'
ISO_SHA = 'f01b812b57fba9f31ff621bf33e7c7570a01964dbeb5be2167e94decf538c89f'
TABLE_SHA = '1c904784993be2bdbf92ee0cdd65f4a1f4da60957e28605ee90fec63504808e6'
HEADER = '''/* SPDX-License-Identifier: GPL-2.0-only
 * Factual GEOID/ISO records extracted from Wine11.0 tools/make_unicode
 * (Copyright2000 Alexandre Julliard, LGPL2.1-or-later upstream source).
 * Source SHA256:f0284d8eee7f213cb5ff1db1264fd90d689fe3a36358451574a0511fa019e637
 * ISO alpha3/numeric facts: system iso-codes iso_3166-1.json, SHA256:f01b812b57fba9f31ff621bf33e7c7570a01964dbeb5be2167e94decf538c89f
 * No generator or upstream code executed.
 */
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pinned(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError('Pinned input changed: ' + str(path))
    return data


def generate(wine, iso):
    match = re.search(r'my @geoids =\s*\(\n(.*?)\n\);', wine.decode('utf-8'), re.S)
    if not match:
        raise ValueError('One bounded factual geoids array is required')
    countries = {}
    for row in json.loads(iso)['3166-1']:
        code = row['alpha_2']
        if (code in countries or not re.fullmatch('[A-Z]{2}', code) or
                not re.fullmatch('[A-Z]{3}', row['alpha_3']) or
                not re.fullmatch('[0-9]{3}', row['numeric'])):
            raise ValueError('Invalid or duplicate ISO fact')
        countries[code] = row
    rows = []
    for literal in re.findall(r'\{([^{}]*)\}', match.group(1)):
        identifier = re.search(r'\bid => ([0-9]+)', literal)
        name = re.search(r'\bname => "([A-Z]{2}|[0-9]{3})"', literal)
        if not identifier:
            raise ValueError('Geographical record is missing its ID')
        number = int(identifier.group(1))
        if not 0 < number <= 0x7fffffff:
            raise ValueError('GEOID outside signed native representation')
        code = name.group(1) if name else 'XX'
        region = code.isdecimal() or bool(re.search(r'\bregion => 1\b', literal))
        country = countries.get(code)
        iso2 = 'XX' if code.isdecimal() else code
        iso3 = country['alpha_3'] if country else 'XX'
        numeric = code if code.isdecimal() else country['numeric'] if country else ''
        rows.append((number, f'{{{number},{14 if region else 16},"{code}","{iso2}","{iso3}","{numeric}"}},\n'))
    if len(rows) != 301 or len({row[0] for row in rows}) != len(rows):
        raise ValueError('Expected exactly 301 distinct factual GEOIDs')
    return (HEADER + ''.join(row[1] for row in sorted(rows))).encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine', type=Path, required=True)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / 'build'):
        parser.error('Fresh repository build output required')
    wine = pinned(args.wine, WINE_SHA)
    iso = pinned(args.iso, ISO_SHA)
    data = generate(wine, iso)
    if digest(data) != TABLE_SHA:
        raise ValueError('Generated facts differ from the held production table')
    if args.verify and args.verify.read_bytes() != data:
        raise ValueError('Production table is not byte-exact reproducible')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    receipt = {'status': 'PASS', 'records': 301, 'output_sha256': digest(data),
               'wine_sha256': WINE_SHA, 'iso_sha256': ISO_SHA,
               'upstream_executed': False, 'verified_production': bool(args.verify)}
    output.with_suffix('.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
