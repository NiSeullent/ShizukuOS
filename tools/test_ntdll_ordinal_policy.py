#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the ordinary NTDLL definition generator without running a compiler.

The existing binary supplies old ordinals and alias identities independently
of source scanning. Compilation and guest validation remain separate checks.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--map', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists(), 'fresh owned output required'
    subset = load('ordinal_subset', ROOT / 'tools/build_frozen_native_subset.py')
    b = subset.load_builder()
    raw = subset.unpack(args.base.read_bytes())['\\SHZ\\SYS64\\ntdll.dll']
    image = subset.interface_pe(raw)
    try:
        old = {s.name.decode('ascii'): (s.ordinal, s.address, s.forwarder)
               for s in image.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    finally:
        image.close()
    policy = json.loads(args.map.read_text())
    pins = policy['ordinals']
    assert len(old) == 494 and old['NtShzBlkControl'][0] == 127
    assert len(pins) == 502 and all(pins[n] == v[0] for n, v in old.items())
    added = set(pins) - set(old)
    assert len(added) == 8 and {pins[n] for n in added} == set(range(495, 503))
    aliases = {n: 'Nt' + n[2:] for n in old if n.startswith('Zw')}
    assert aliases and all(t in old and old[n][1] == old[t][1]
                           and not old[n][2] and not old[t][2] for n, t in aliases.items())
    definitions = sorted(set(pins) - set(aliases) - {'RtlCaptureContext', '__C_specific_handler'})
    args.out.mkdir(parents=True)
    calls = []
    with tempfile.TemporaryDirectory(dir=args.out) as directory:
        temporary = Path(directory)
        b.W64 = temporary / 'win64'
        b.OUT = temporary / 'out'
        (b.W64 / 'ntdll').mkdir(parents=True)
        b.OUT.mkdir()
        b.run = lambda command: calls.append(list(map(str, command)))
        b.version_obj = lambda *a, **k: temporary / 'resource.o'
        b.scan_exports = lambda *a: definitions
        b.gen_stubs = lambda: [f'{n} = {t}' for n, t in aliases.items()]
        map_path = b.W64 / 'ntdll/ordinals.json'
        map_path.write_text(json.dumps(policy))
        b.build_ntdll()
        assert len(calls) == 2 and calls[0][0] == b.CC and calls[1][0] == b.DLLTOOL
        text = (b.OUT / 'ntdll.def').read_text()
        emitted = {}
        for line in text.splitlines()[2:]:
            match = re.fullmatch(r'\s+(\w+)(?:\s*=\s*(\w+))?\s+@(\d+)', line)
            assert match, line
            name, target, ordinal = match.groups()
            assert name not in emitted
            emitted[name] = (target, int(ordinal))
        assert set(emitted) == set(pins)
        assert all(emitted[n] == (aliases.get(n), pins[n]) for n in pins)
        (args.out / 'verified-ntdll.def').write_text(text)
        negative = []
        bad = copy.deepcopy(policy); del bad['ordinals']['NtShzBlkControl']; negative.append(('missing old syscall', bad))
        bad = copy.deepcopy(policy); bad['ordinals']['FakeExport'] = 503; negative.append(('extra name', bad))
        for label, value in [('duplicate', 127), ('zero', 0), ('oversize', 65536), ('boolean', True)]:
            bad = copy.deepcopy(policy); bad['ordinals'][sorted(added)[0]] = value; negative.append((label, bad))
        bad = copy.deepcopy(policy); bad['library'] = 'other.dll'; negative.append(('wrong library', bad))
        for label, bad in negative:
            calls.clear(); map_path.write_text(json.dumps(bad))
            try:
                b.build_ntdll()
            except SystemExit:
                assert not calls, 'invalid policy reached compiler: ' + label
            else:
                raise AssertionError('invalid policy accepted: ' + label)
        map_path.write_text(json.dumps(policy)); calls.clear()
        victim = next(iter(aliases))
        b.gen_stubs = lambda: [f'{n} = {"MissingTarget" if n == victim else t}' for n, t in aliases.items()]
        try:
            b.build_ntdll()
        except SystemExit:
            assert not calls
        else:
            raise AssertionError('alias without actual target accepted')
    result = {'status': 'HOST_GATE_PASS_ORDINARY_LINK_AND_GUEST_PENDING',
              'old_exports': len(old), 'new_exports': len(added), 'local_aliases': len(aliases),
              'negative_policies_rejected_before_link': len(negative) + 1,
              'actual_base_ntdll_sha256': hashlib.sha256(raw).hexdigest(),
              'inputs': {str(p.resolve()): sha(p) for p in
                         (args.base, args.map, ROOT/'shizukudos/win64/build.py', Path(__file__))},
              'emitted_definition_sha256': sha(args.out/'verified-ntdll.def'),
              'claims': {'compiler_run': False, 'guest_run': False, 'app_run': False}}
    (args.out/'host-result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('status', 'old_exports', 'new_exports', 'local_aliases', 'negative_policies_rejected_before_link')}))


if __name__ == '__main__':
    main()
