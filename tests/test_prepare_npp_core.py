# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('npp_core', Path(__file__).resolve().parents[1] / 'tools/prepare_npp_core.py')
core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
SOURCE = (b';\xb1\xe2\xba\xbb\r\n[ApiConfigurations]\r\n0=DCFG1\r\n1=WINXP\r\n'
          b'[DCFG1]\r\ncontents=std,kexbases,kexbasen\r\n[WINXP]\r\ninherit=DCFG1\r\n'
          b'[WINXP.names]\r\nKERNEL32.GetVersion=kexbases.5\r\n'
          b'[OTHER]\r\nuntouched=keep\r\n')
PLAN = {'schema': 1, 'kind': 'native-npp-provider-routes', 'profile': 'WINXP',
        'libraries': ['m98wrap', 'm98ctl3'],
        'names': {'KERNEL32.GetTickCount64': 'm98wrap.0'},
        'ordinals': {'COMCTL32.381': 'm98ctl3.0'}}


class CoreMergeTests(unittest.TestCase):
    def test_app_profile_preserves_base_version_and_ansi(self):
        output, additions = core.merge(SOURCE, PLAN)
        self.assertTrue(output.startswith(b';\xb1\xe2\xba\xbb\r\n'))
        self.assertIn(b'[DCFG1]\r\ncontents=std,kexbases,kexbasen\r\n', output)
        self.assertIn(b'KERNEL32.GetVersion=kexbases.5\r\n', output)
        self.assertIn(b'[OTHER]\r\nuntouched=keep\r\n', output)
        self.assertEqual(additions['libraries'], ['m98wrap', 'm98ctl3'])
        self.assertIn(b'contents=m98wrap,m98ctl3\r\n', output)
        self.assertEqual(output.count(b'\n'), output.count(b'\r\n'))

    def test_idempotent(self):
        once, _ = core.merge(SOURCE, PLAN); twice, added = core.merge(once, PLAN)
        self.assertEqual(once, twice); self.assertFalse(any(added.values()))

    def test_active_specific_route_keeps_generic_ignored(self):
        source = SOURCE + b'[WINXP.names.98]\r\nKERNEL32.GetVersion=kexbases.5\r\n'
        output, _ = core.merge(source, PLAN); sections = core.parse(output)
        self.assertIn('kernel32.gettickcount64', sections['winxp.names.98']['keys'])
        self.assertNotIn('kernel32.gettickcount64', sections['winxp.names']['keys'])

    def test_empty_specific_does_not_shadow_generic(self):
        output, _ = core.merge(SOURCE + b'[WINXP.names.98]\r\n; empty\r\n', PLAN)
        sections = core.parse(output)
        self.assertFalse(sections['winxp.names.98']['keys'])
        self.assertIn('kernel32.gettickcount64', sections['winxp.names']['keys'])

    def test_existing_contents_spacing_and_names_preserved(self):
        source = SOURCE.replace(b'inherit=DCFG1\r\n', b'inherit=DCFG1\r\n Contents = kexbases  \r\n')
        output, _ = core.merge(source, PLAN)
        self.assertIn(b' Contents = kexbases,m98wrap,m98ctl3  \r\n', output)

    def test_existing_none_contents(self):
        source = SOURCE.replace(b'inherit=DCFG1\r\n', b'inherit=DCFG1\r\ncontents=none\r\n')
        output, _ = core.merge(source, PLAN); self.assertIn(b'contents=m98wrap,m98ctl3\r\n', output)

    def test_no_final_newline(self):
        output, _ = core.merge(SOURCE.rstrip(b'\r\n'), PLAN)
        self.assertIn(b'untouched=keep\r\n', output); core.parse(output)

    def test_lf_and_cr_preserved(self):
        for ending in (b'\n', b'\r'):
            output, _ = core.merge(SOURCE.replace(b'\r\n', ending), PLAN)
            self.assertNotIn(b'\r\n', output)
            self.assertIn(b'KERNEL32.GetVersion=kexbases.5' + ending, output)

    def test_conflicting_route_rejected(self):
        source = SOURCE.replace(b'[WINXP.names]\r\n', b'[WINXP.names]\r\nKERNEL32.GetTickCount64=foreign.0\r\n')
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            core.merge(source, PLAN)

    def test_duplicate_section_or_key_rejected(self):
        for data in (SOURCE + b'[winxp]\r\n', SOURCE.replace(b'1=WINXP', b'1=WINXP\r\n1=WINXP')):
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                core.merge(data, PLAN)

    def test_exact_known_replacement_only(self):
        source = SOURCE.replace(b'[WINXP.names]\r\n', b'[WINXP.names]\r\nKERNEL32.GetTickCount64=none\r\n')
        guarded = {**PLAN, 'expected_existing': {'names': {'KERNEL32.GetTickCount64': 'none'}}}
        output, changes = core.merge(source, guarded)
        self.assertIn(b'KERNEL32.GetTickCount64=m98wrap.0\r\n', output)
        self.assertEqual(changes['replaced'][0]['before'], 'none')
        twice, changes = core.merge(output, guarded)
        self.assertEqual(output, twice); self.assertFalse(any(changes.values()))
        for data in (SOURCE, source.replace(b'=none', b'=foreign.0')):
            with self.assertRaises(ValueError):
                core.merge(data, guarded)

    def test_missing_or_cyclic_inheritance_rejected(self):
        for parent in (b'WINXP', b'ABSENT'):
            with self.assertRaisesRegex(ValueError, 'inheritance'):
                core.merge(SOURCE.replace(b'inherit=DCFG1', b'inherit=' + parent), PLAN)

    def test_encoding_and_nul_rejected(self):
        for data in (b'\xff\xfe' + SOURCE, b'\xef\xbb\xbf' + SOURCE, SOURCE + b'\0'):
            with self.assertRaises(ValueError):
                core.merge(data, PLAN)

    def test_invalid_route_and_ordinal_rejected(self):
        for field, entries in [('names', {'KERNEL32.Bad/Name': 'm98wrap.0'}),
                               ('ordinals', {'COMCTL32.0': 'm98ctl3.0'}),
                               ('ordinals', {'COMCTL32.65536': 'm98ctl3.0'}),
                               ('names', {'KERNEL32.Good': 'absent.0'})]:
            with self.assertRaises(ValueError):
                core.merge(SOURCE, {**PLAN, field: entries})

    def test_absent_profile_declaration_rejected(self):
        with self.assertRaises(ValueError):
            core.merge(SOURCE.replace(b'1=WINXP\r\n', b''), PLAN)

    def test_loader_stops_at_first_configuration_gap(self):
        for replacement in (b'2=WINXP', b'1=\r\n2=WINXP'):
            with self.assertRaisesRegex(ValueError, 'declared'):
                core.merge(SOURCE.replace(b'1=WINXP', replacement), PLAN)

    def test_ancestor_must_be_loaded_before_child_with_exact_name(self):
        for data in (SOURCE.replace(b'0=DCFG1\r\n1=WINXP', b'0=WINXP\r\n1=DCFG1'),
                     SOURCE.replace(b'0=DCFG1', b'0=OTHER'),
                     SOURCE.replace(b'inherit=DCFG1', b'inherit=Dcfg1')):
            with self.assertRaisesRegex(ValueError, 'inheritance'):
                core.merge(data, PLAN)

    def test_nonzero_variant_requires_compiled_evidence(self):
        for index in ('1', '2', '127', '128', '01'):
            plan = {**PLAN, 'names': {'KERNEL32.GetTickCount64': 'm98wrap.' + index}}
            with self.assertRaises(ValueError):
                core.merge(SOURCE, plan)

    def test_module_table_index_is_not_variant_selector(self):
        plan = {**PLAN, 'libraries': ['m98vlc'], 'ordinals': {},
                'names': {'GDI32.RemoveFontResourceExW': 'm98vlc.0',
                          'USER32.RealGetWindowClassW': 'm98vlc.0'},
                'provider_metadata': {'m98vlc': {'path': 'compiled', 'sha256': 'a' * 64}}}
        tables = {'m98vlc': {
            0: {'index': 0, 'module': 'KERNEL32.DLL', 'target_library': 'KERNEL32.DLL',
                'names': ['SetFilePointerEx'], 'ordinals': []},
            1: {'index': 1, 'module': 'GDI32.DLL', 'target_library': 'GDI32.DLL',
                'names': ['RemoveFontResourceExW'], 'ordinals': []},
            2: {'index': 2, 'module': 'USER32.DLL', 'target_library': 'USER32.DLL',
                'names': ['RealGetWindowClassW'], 'ordinals': []}}}
        output, _ = core.merge(SOURCE, plan, tables)
        self.assertIn(b'GDI32.RemoveFontResourceExW=m98vlc.0\r\n', output)
        self.assertIn(b'USER32.RealGetWindowClassW=m98vlc.0\r\n', output)
        for name, value in [('GDI32.RemoveFontResourceExW', 'm98vlc.1'),
                            ('USER32.RealGetWindowClassW', 'm98vlc.2'),
                            ('GDI32.Nonexistent', 'm98vlc.0'),
                            ('GDI32.RemoveFontResourceExW', 'm98vlc.3')]:
            with self.assertRaisesRegex(ValueError, 'compiled provider table'):
                core.merge(SOURCE, {**plan, 'names': {name: value}}, tables)
        with self.assertRaisesRegex(ValueError, 'verified before merging'):
            core.merge(SOURCE, plan)

    def test_same_symbol_duplicate_variants_keep_sdk_order(self):
        plan = {**PLAN, 'libraries': ['m98vlc'], 'ordinals': {},
                'names': {'KERNEL32.SetFilePointerEx': 'm98vlc.1'},
                'provider_metadata': {'m98vlc': {}}}
        tables = {'m98vlc': {7: {'index': 7, 'module': 'KERNEL32.DLL',
                  'target_library': 'KERNEL32.DLL', 'names': ['SetFilePointerEx', 'SetFilePointerEx'],
                  'ordinals': []}}}
        output, _ = core.merge(SOURCE, plan, tables)
        self.assertIn(b'KERNEL32.SetFilePointerEx=m98vlc.1', output)
        with self.assertRaisesRegex(ValueError, 'compiled provider table'):
            core.merge(SOURCE, {**plan, 'names': {'KERNEL32.SetFilePointerEx': 'm98vlc.2'}}, tables)

    def test_normalized_dll_spelling_cannot_prove_raw_module_match(self):
        plan = {**PLAN, 'libraries': ['m98vlc'], 'ordinals': {},
                'names': {'KERNEL32.SetFilePointerEx': 'm98vlc.0'},
                'provider_metadata': {'m98vlc': {}}}
        for target in ('KERNEL32', 'KERNEL32.DLL.DLL', ''):
            tables = {'m98vlc': {0: {'index': 0, 'module': 'KERNEL32.DLL',
                      'target_library': target, 'names': ['SetFilePointerEx'], 'ordinals': []}}}
            with self.assertRaisesRegex(ValueError, 'compiled provider table'):
                core.merge(SOURCE, plan, tables)

    def test_profile_declaration_spelling_matches_sdk_lookup(self):
        with self.assertRaisesRegex(ValueError, 'declared'):
            core.merge(SOURCE.replace(b'1=WINXP', b'1=WinXP'), PLAN)

    def test_compiled_ordinal_binding(self):
        plan = {**PLAN, 'names': {}, 'provider_metadata': {'m98ctl3': {}}}
        tables = {'m98ctl3': {0: {'index': 0, 'module': 'COMCTL32.DLL', 'target_library': 'COMCTL32.DLL',
                                'names': [], 'ordinals': [381]}}}
        output, _ = core.merge(SOURCE, plan, tables)
        self.assertIn(b'COMCTL32.381=m98ctl3.0', output)
        with self.assertRaisesRegex(ValueError, 'compiled provider table'):
            core.merge(SOURCE, {**plan, 'ordinals': {'COMCTL32.345': 'm98ctl3.0'}}, tables)


if __name__ == '__main__':
    unittest.main()
