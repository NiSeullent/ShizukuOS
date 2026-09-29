"""routes.json schema v2: provider order, stub list and generated C table.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ntw_prepare_routes', ROOT / 'ntwin32/prepare.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
STUB_CATEGORIES = {'explicit_unimplemented_macro', 'explicit_stub_body', 'suspicious_stub_body'}


class RoutesSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = mod.routes()
        cls.names = mod.route_names(cls.plan)

    def test_exports_match_the_def_file(self):
        text = (ROOT / 'ntwin32/exports.def').read_text()
        exported = re.findall(r'^\s+(\w+)=Ntw\w+@\d+\s*$', text, re.M)
        self.assertEqual(sorted(exported), sorted(self.names))
        self.assertEqual(len(self.names), 17)

    def test_native_presence_matches_the_oem_manifest(self):
        manifest = json.loads((ROOT / self.plan['native_export_manifest']['path']).read_text())
        native = set(manifest['dlls'][self.plan['native_export_manifest']['module']])
        for entry in self.plan['exports']:
            with self.subTest(name=entry['name']):
                self.assertEqual(entry['native_win98se'], entry['name'] in native)
                if entry['native_win98se']:
                    self.assertEqual(entry['order'][0], 'own')
                    self.assertTrue(entry['reason'])
                else:
                    self.assertEqual(entry['order'], self.plan['default_order'])
        for stub in self.plan['stubs']:
            if stub['provider'] == 'native':
                self.assertIn(stub['name'], native, 'a native stub must be a native export')

    def test_kernelex_stub_list_is_derived_from_the_audit(self):
        audit = json.loads((ROOT / 'benchmarks/kernelex-source-body-audit-v1.json').read_text())
        expected = {row['symbol'] for row in audit['entries']
                    if row['dll'] == self.plan['source_dll'] and row['source_category'] in STUB_CATEGORIES}
        listed = {stub['name'] for stub in self.plan['stubs'] if stub['provider'] == 'kernelex'}
        self.assertEqual(listed, expected)
        categories = {row['symbol']: row['source_category'] for row in audit['entries']
                      if row['dll'] == self.plan['source_dll']}
        for stub in self.plan['stubs']:
            with self.subTest(name=stub['name']):
                self.assertEqual(stub['module'], self.plan['source_dll'])
                if stub['provider'] == 'kernelex':
                    self.assertEqual(stub['category'], categories[stub['name']])
                paths = re.findall(r'(?:docs|benchmarks)/[\w./-]+', stub['evidence'])
                self.assertTrue(paths, 'evidence must cite a repository path')
                for path in paths:
                    self.assertTrue((ROOT / path).exists(), path)

    def test_generated_include_matches_the_build_and_is_well_formed(self):
        rendered = mod.render_routes_inc(self.plan)
        built = ROOT / 'build/platform/routes.inc'
        if built.exists():
            self.assertEqual(built.read_text(), rendered)
        routes = re.findall(r'^NTW_ROUTE\("(\w+)", Ntw(\w+), (NTW_ORDER\d\([^)]*\))\)$', rendered, re.M)
        self.assertEqual([name for name, _, _ in routes], sorted(self.names))
        self.assertTrue(all(name == impl for name, impl, _ in routes))
        stubs = re.findall(r'^NTW_STUB\("([A-Z0-9_.]+)", "(\w+)", (NTW_PROVIDER_\w+)\)$', rendered, re.M)
        self.assertEqual(len(stubs), len(self.plan['stubs']))
        self.assertIn('#define NTW_DEFAULT_ORDER NTW_ORDER3(NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN, NTW_PROVIDER_KERNELEX)',
                      rendered)
        for name, _, order in routes:
            entry = next(e for e in self.plan['exports'] if e['name'] == name)
            self.assertEqual(order, mod.order_macro(entry['order']))

    def test_documented_configuration_names(self):
        self.assertEqual(self.plan['configuration'], {'file': 'NTW32.INI', 'environment': 'NTW32_ROUTING',
                                                      'document': 'docs/NTW32_ROUTING.md'})
        document = (ROOT / 'docs/NTW32_ROUTING.md').read_text()
        for needle in ('NTW32.INI', 'NTW32_ROUTING', '[routing]', '[modules]', '[functions]', '[order]',
                       'mode=', 'log=', 'order=', 'KERNELEX.DLL', 'KEXBASES.DLL', 'KEXBASEN.DLL', 'get_api_table',
                       'USER_REPORTED', 'HOST_TESTED'):
            self.assertIn(needle, document)
        for mode in mod.MODES:
            self.assertIn(mode, document)
        self.assertEqual(self.plan['kernelex_modules']['core'], 'KERNELEX.DLL')
        self.assertEqual(self.plan['kernelex_modules']['api_libraries'], ['KEXBASES.DLL', 'KEXBASEN.DLL'])
        self.assertEqual(self.plan['kernelex_modules']['api_library_export'], 'get_api_table')

    def mutated(self, mutate):
        plan = copy.deepcopy(self.plan)
        mutate(plan)
        return plan

    def test_validation_rejects_inconsistent_tables(self):
        cases = {
            'schema': lambda p: p.update(schema='ntwin32wrapper9x.routes.v1'),
            'providers': lambda p: p.update(providers=['native', 'own']),
            'default order': lambda p: p.update(default_order=['native', 'own']),
            'mode set': lambda p: p['modes'].pop('kernelex'),
            'fixed order': lambda p: p['modes'].update(own=['native', 'own']),
            'duplicate export': lambda p: p['exports'].append(dict(p['exports'][0])),
            'export name': lambda p: p['exports'][0].update(name='9bad'),
            'export name width': lambda p: p['exports'][0].update(name='A' * 64),
            'order without own': lambda p: p['exports'][0].update(order=['native', 'kernelex']),
            'order duplicate': lambda p: p['exports'][0].update(order=['own', 'own']),
            'order unknown': lambda p: p['exports'][0].update(order=['own', 'wine']),
            'native flag type': lambda p: p['exports'][0].update(native_win98se='yes'),
            'native without reason': lambda p: p['exports'][0].update(native_win98se=True, order=['own', 'native']),
            'native not own-first': lambda p: p['exports'][0].update(native_win98se=True, reason='x',
                                                                     order=['native', 'own']),
            'stub provider': lambda p: p['stubs'][0].update(provider='own'),
            'stub module case': lambda p: p['stubs'][0].update(module='kernel32.dll'),
            'stub module path': lambda p: p['stubs'][0].update(module='C:\\KERNEL32.DLL'),
            'stub name': lambda p: p['stubs'][0].update(name='Compare-String'),
            'stub evidence': lambda p: p['stubs'][0].update(evidence=''),
            'stub duplicate': lambda p: p['stubs'].append(dict(p['stubs'][0])),
            'own export as native stub': lambda p: p['stubs'].append(
                {'module': 'KERNEL32.DLL', 'name': 'GetProcAddress', 'provider': 'native', 'evidence': 'x'}),
            'stubs type': lambda p: p.update(stubs={}),
            'exports empty': lambda p: p.update(exports=[]),
            'provider lower': lambda p: p.update(provider='ntw32.dll'),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label), self.assertRaises(mod.PEError):
                mod.validate_routes(self.mutated(mutate))
        mod.validate_routes(copy.deepcopy(self.plan))

    def test_prepare_still_redirects_every_export(self):
        original = ROOT / 'build/platform/probe-original.exe'
        if not original.exists():
            self.skipTest('platform/build.py has not produced the probe')
        _, report = mod.prepare(original.read_bytes())
        self.assertEqual(sorted(report['redirected']), sorted(self.names))


if __name__ == '__main__':
    unittest.main()
