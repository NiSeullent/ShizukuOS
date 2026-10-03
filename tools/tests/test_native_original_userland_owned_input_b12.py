"""Intent emitter option: exact guardian-compatible owned_input, absent = unchanged bytes."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module
tool = load(ROOT / 'tools/native_original_userland.py', 'nou_b12')
custody = load(ROOT / 'shizukudos/supervisor/native_win98/task_custody.py', 'tc_b12')
INTENT = b'{"schema": "shizukuos.native-original-userland-epoch-intent.v1", "timeout": 60}\n'


class OwnedInputOption(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(t.cleanup)
        self.dir = Path(t.name); os.chmod(self.dir, 0o700)
        self.src = self.dir / 'intent.json'; self.src.write_bytes(INTENT)

    def emit(self, spec, name):
        out = self.dir / name
        tool.add_owned_input(self.src, spec, out)
        return out.read_bytes()

    def test_options_accepted_by_guardian_validator(self):
        for spec, flags in (('keyboard', 1), ('mouse', 2), ('keyboard,mouse', 3), ('mouse,keyboard', 3)):
            with self.subTest(spec=spec):
                intent = json.loads(self.emit(spec, spec.replace(',', '_')))
                self.assertEqual(list(intent['owned_input']), ['schema', 'machine', 'keyboard', 'mouse'])
                self.assertEqual(custody.owned_input_flags(intent['owned_input']), flags)
                self.assertEqual(intent['timeout'], 60)

    def test_none_is_byte_identical(self):
        self.assertEqual(self.emit('none', 'none.json'), INTENT)

    def test_bad_specs_and_inputs_refused(self):
        for spec in ('', 'keyboard,keyboard', 'vga', 'keyboard,', 'Keyboard', None):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                tool.owned_input_option(spec)
        with self.assertRaises(ValueError):
            self.emit('mouse', 'a.json'); tool.add_owned_input(self.dir / 'a.json', 'mouse', self.dir / 'b.json')
        (self.dir / 'bad.json').write_bytes(b'{"schema": "x"}')
        with self.assertRaises(ValueError):
            tool.add_owned_input(self.dir / 'bad.json', 'mouse', self.dir / 'c.json')
        with self.assertRaises(ValueError):
            tool.add_owned_input(self.src, 'mouse', self.src)
        self.assertEqual(self.src.read_bytes(), INTENT)

    def test_no_extra_authority_fields(self):
        intent = json.loads(self.emit('keyboard,mouse', 'k.json'))
        self.assertEqual(set(intent), {'schema', 'timeout', 'owned_input'})
        self.assertNotIn('nonce', json.dumps(intent))

    def test_cli(self):
        out = self.dir / 'cli.json'
        self.assertEqual(tool.main(['--owned-input', 'mouse', '--intent', str(self.src), '--out', str(out)]), 0)
        self.assertEqual(json.loads(out.read_bytes())['owned_input']['mouse'], True)
        with self.assertRaises(SystemExit):
            tool.main(['--owned-input', 'mouse', '--out', str(self.dir / 'z.json')])


if __name__ == '__main__':
    unittest.main()
