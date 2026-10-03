"""perf-b9: bounded guardian streaming checks keep every custody guarantee.

Real LeaseUnion over owned temporary files with real Linux read leases and the
real SIGIO latch. Covers the scheduled complete sweep, per-block streamed-FD
checks, lease break mid-read, path swap, wrong SHA, short/extended reads, and
the gui-intent original-phase input recipe pin (handoff applied by perf-b9).
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_original_epoch_generated_manifest as generated  # noqa: E402

guardian = generated.guardian


class StreamGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.union = guardian.LeaseUnion()
        self.addCleanup(self.release)

    def release(self):
        # Negative cases leave a deliberately broken union: close() still
        # unlocks/closes every FD and then reports the custody failure.
        if not self.union.closed:
            try: self.union.close()
            except ValueError: pass

    def file(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        return {'path': str(p), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def test_scheduled_complete_sweep_and_bounded_cost(self):
        rows = [self.union.add(self.file('s/%d/m%03d.py' % (i % 7, i), os.urandom(512 + i))) for i in range(200)]
        disk = self.union.add(self.file('disk.img', os.urandom(9 << 20)))
        calls = []
        real = guardian.LeaseUnion.check
        with patch.object(guardian.LeaseUnion, 'check', autospec=True,
                          side_effect=lambda union: (calls.append(1), real(union))[1]), \
             patch.object(guardian, 'SWEEP_TICKS', 64), patch.object(guardian, 'SWEEP_SECONDS', 3600):
            guard = self.union.stream_guard(disk)
            for _ in range(640): guard()
        # start sweep + one complete sweep per 64 ticks, never one per tick.
        self.assertEqual(len(calls), 1 + 640 // 64)
        self.assertTrue(all(row['full_SHA_admitted'] for row in rows))

    def test_lease_break_mid_stream_refused(self):
        row = self.file('disk.img', os.urandom(12 << 20))
        entry = self.union.add(row)
        broke = []
        def writer_open():
            # Another process opening for write breaks the held read lease.
            subprocess.run([sys.executable, '-c',
                            'import os,sys\ntry:os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)\nexcept OSError:pass',
                            row['path']], check=True, timeout=20)
            for _ in range(200):
                if self.union.broken: break
                time.sleep(.01)
            broke.append(self.union.broken)
        guard = self.union.stream_guard(entry)
        def mid():
            if not broke: writer_open()
            guard()
        with self.assertRaisesRegex(ValueError, 'lease break'):
            guardian.full_hash(entry['fd'], row['bytes'], mid)
        self.assertEqual(broke, [True])

    def test_other_row_path_swap_detected_by_scheduled_sweep(self):
        disk = self.union.add(self.file('disk.img', os.urandom(1 << 20)))
        other = self.file('src/other.py', b'print(1)\n'); self.union.add(other)
        guard = self.union.stream_guard(disk)
        replacement = self.root / 'src/other.new'; replacement.write_bytes(b'print(1)\n')
        os.replace(replacement, other['path'])
        with patch.object(guardian, 'SWEEP_TICKS', 4), patch.object(guardian, 'SWEEP_SECONDS', 3600):
            with self.assertRaisesRegex(ValueError, 'lease|identity'):
                for _ in range(8): guard()

    def test_streamed_path_swap_detected_every_block(self):
        row = self.file('disk.img', os.urandom(1 << 20))
        entry = self.union.add(row)
        guard = self.union.stream_guard(entry)
        os.rename(row['path'], str(self.root / 'moved.img'))
        with patch.object(guardian, 'SWEEP_TICKS', 1 << 30), patch.object(guardian, 'SWEEP_SECONDS', 3600):
            with self.assertRaises((ValueError, FileNotFoundError)): guard()

    def test_ancestor_symlink_detected(self):
        row = self.file('a/b/disk.img', os.urandom(4096))
        entry = self.union.add(row)
        os.rename(self.root / 'a/b', self.root / 'a/real')
        os.symlink(self.root / 'a/real', self.root / 'a/b')
        with self.assertRaisesRegex(ValueError, 'symlink|identity'): self.union.check()
        with self.assertRaisesRegex(ValueError, 'symlink|identity'): self.union._entry(entry, ancestors=True)

    def test_wrong_full_sha_refused_and_not_held(self):
        row = self.file('disk.img', os.urandom(5 << 20)); row['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'full leased SHA mismatch'): self.union.add(row)
        self.assertNotIn(row['path'], self.union.rows)

    def test_short_and_extended_reads_refused(self):
        row = self.file('disk.img', os.urandom(5 << 20))
        fd = os.open(row['path'], os.O_RDONLY); self.addCleanup(os.close, fd)
        with self.assertRaisesRegex(ValueError, 'short immutable input read'): guardian.full_hash(fd, row['bytes'] + 1)
        with self.assertRaisesRegex(ValueError, 'unexpected extent'): guardian.full_hash(fd, row['bytes'] - 1)
        self.assertEqual(guardian.full_hash(fd, row['bytes']), row['sha256'])

    def test_close_rehashes_every_row_and_refuses_change(self):
        row = self.file('disk.img', os.urandom(3 << 20)); entry = self.union.add(row)
        entry['pin'] = dict(row, sha256='e' * 64)  # in-memory expectation differs from held bytes
        with self.assertRaisesRegex(ValueError, 'late leased full SHA differs'): self.union.close()
        self.assertTrue(self.union.closed)


class OriginalInputRecipe(generated.GeneratedOriginalEpochManifest):
    """gui-intent handoff: optional held recipe pin in the original phase only."""
    def generate_with(self, tag, recipe):
        real = guardian.prepare_original_intent
        def inject(intent, *args, **kw):
            return real(dict(intent, input_recipe=recipe), *args, **kw)
        with patch.object(guardian, 'prepare_original_intent', side_effect=inject):
            return self.generate(tag)

    def test_recipe_held_with_full_sha_and_carried(self):
        recipe = self.write('recipe.json', b'{"steps":[]}\n')
        manifest, context = self.generate_with('r', recipe)
        self.assertEqual(manifest['input_recipe'], recipe)
        self.assertIs(self.union.rows[recipe['path']]['full_SHA_admitted'], True)
        self.assertIsNone(self.admit(manifest, context))

    def test_oversize_wrong_sha_or_unknown_key_refused(self):
        big = self.write('big.json', b' ' * (guardian.INPUT_RECIPE_MAX + 1))
        with self.assertRaises(ValueError): self.generate_with('big', big)
        bad = dict(self.write('ok.json', b'{}\n'), sha256='a' * 64)
        with self.assertRaises(ValueError): self.generate_with('sha', bad)
        real = guardian.prepare_original_intent
        with patch.object(guardian, 'prepare_original_intent',
                          side_effect=lambda intent, *a, **k: real(dict(intent, input_recipe_x={}), *a, **k)):
            with self.assertRaises(ValueError): self.generate('x')

    def test_dos3_manifest_cannot_carry_recipe(self):
        recipe = self.write('recipe.json', b'{"steps":[]}\n')
        manifest = {'schema': 'shizukuos.native-custody-manifest.v1', 'plan': recipe, 'repo': str(self.root),
                    'sources': {}, 'lineage': [], 'producers': [], 'limits': {}, 'timeout': 60, 'input_recipe': recipe}
        with patch.object(guardian, 'admit_runtime_sources', return_value={}):
            with self.assertRaisesRegex(ValueError, 'only in the original-userland phase'):
                guardian.admit_manifest(manifest, self.union)


if __name__ == '__main__':
    unittest.main()
