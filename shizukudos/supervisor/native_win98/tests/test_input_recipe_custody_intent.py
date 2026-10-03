# SPDX-License-Identifier: GPL-2.0-only
"""Guardian intent -> generated manifest for the optional original input recipe.

Acceptance for .codex/handoff/gui-intent-to-perf-b9.patch (task_custody.py): runs the production
prepare_original_intent through the existing generated-manifest fixture. Host only; no VM.
"""
import hashlib
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_original_epoch_generated_manifest as base

guardian=base.guardian
EXAMPLE=Path(__file__).resolve().parent/'fixtures'/'t_gui_native_enter_close.input.json'


def _fixture_class():
    for value in vars(base).values():
        if isinstance(value,type) and issubclass(value,unittest.TestCase) and hasattr(value,'generate'):return value
    raise RuntimeError('generated-manifest fixture class missing')


class InputRecipeIntent(_fixture_class()):
    def generate_with(self,tag,recipe):
        original=guardian.prepare_original_intent
        def wrapped(intent,*args):
            if recipe is not None:intent=dict(intent,input_recipe=recipe)
            return original(intent,*args)
        with patch.object(guardian,'prepare_original_intent',wrapped):return self.generate(tag)

    def recipe(self,data=None):
        return self.write('input.json',EXAMPLE.read_bytes() if data is None else data)

    def test_recipe_leased_and_copied_into_generated_manifest(self):
        row=self.recipe()
        manifest,context=self.generate_with('r',row)
        self.assertEqual(manifest['input_recipe'],row)
        entry=self.union.rows[row['path']]
        self.assertTrue(entry['full_SHA_admitted']);self.assertEqual(entry['pin'],row)
        self.assertEqual(os.fstat(entry['fd']).st_ino,os.stat(row['path']).st_ino)
        self.assertIsNone(self.admit(manifest,context))

    def test_console_first_manifest_has_no_recipe_field(self):
        manifest,_=self.generate_with('c',None)
        self.assertNotIn('input_recipe',manifest)
        self.assertEqual(list(manifest),['schema','repo','sources','limits','timeout','plan','lineage','producers',
                                         'optional_native_inputs','optional_native_provenance','original_device_epoch'])

    def test_bad_recipe_pins_refused_before_preparation(self):
        row=self.recipe()
        link=Path(row['path']).with_name('link.json');os.symlink(row['path'],link)
        cases=[dict(row,sha256='1'*64),dict(row,bytes=row['bytes']+1),dict(row,extra=1),dict(row,path=str(link)),
               {'path':row['path'],'bytes':20000,'sha256':row['sha256']},None]
        for index,bad in enumerate(cases):
            with self.subTest(case=index),self.assertRaises(ValueError):
                original=guardian.prepare_original_intent
                def wrapped(intent,*args):return original(dict(intent,input_recipe=bad),*args)
                with patch.object(guardian,'prepare_original_intent',wrapped):self.generate('b%d'%index)


for name in [n for n in dir(InputRecipeIntent) if n.startswith('test_') and not n.startswith(('test_recipe','test_console','test_bad'))]:
    setattr(InputRecipeIntent,name,None)

if __name__=='__main__':unittest.main()
