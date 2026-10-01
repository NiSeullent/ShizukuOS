"""Continuation preservation controls; prepare only, never publish or boot."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

PUBLISHER = Path(__file__).resolve().parents[1] / 'publish_static.py'
spec = importlib.util.spec_from_file_location('m98_continuation_publisher', PUBLISHER)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
ADDED = {
    'continuation/index.html', 'continuation/guide.html',
    'continuation/styles.css', 'continuation/downloads.json',
    'continuation/modern-apps-guide.md', 'continuation/environment-guide.md',
    'continuation/official-distribution.md',
    'downloads/win98-modern-usb-helper.zip',
    'downloads/win98-modern-usb-helper.zip.sha256',
}


class ContinuationAssets(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='m98-continuation-controls-')
        self.addCleanup(temporary.cleanup)
        self.site = Path(temporary.name) / 'site'
        shutil.copytree(publisher.SITE, self.site, ignore=shutil.ignore_patterns('__pycache__'))
        patcher = patch.object(publisher, 'SITE', self.site)
        patcher.start()
        self.addCleanup(patcher.stop)

    def prepared(self):
        with patch.object(publisher, 'publish', side_effect=AssertionError('publication forbidden')):
            return publisher.prepare_assets()

    def test_full_static_inventory_preserves_all_existing_assets_and_exact_nine_additions(self):
        prepared = self.prepared()
        assets = prepared['assets']
        self.assertEqual(len(assets), 92)
        self.assertTrue(ADDED.issubset(assets))
        existing = set(publisher.STATIC) | set(publisher.AUTHORSHIP_STATIC)
        existing.update('authorship/images/' + name for name in publisher.AUTHORSHIP_IMAGES)
        preview = json.loads((self.site / 'evidence/preview.json').read_bytes())
        existing.update('evidence/' + Path(frame['src']).as_posix() for collection in preview['collections'] for frame in collection['frames'])
        self.assertEqual(len(existing), 83)
        self.assertEqual(set(assets), existing | ADDED)
        for name, raw in assets.items():
            self.assertEqual(raw, (self.site / name).read_bytes(), name)
        self.assertIsNone(prepared['iso'])
        manifest = json.loads(assets['continuation/downloads.json'])
        self.assertEqual(manifest['version'], '0.9.0-dev')
        self.assertFalse(manifest['full_modern_apps_verified'])
        self.assertFalse(manifest['native_windows98_modern_apps_verified'])
        self.assertEqual([item['role'] for item in manifest['items'] if item['state'] == 'ready'], ['usb_helpers'])

    def test_any_missing_continuation_or_helper_asset_stops_preparation(self):
        for name in sorted(ADDED):
            with self.subTest(path=name):
                path = self.site / name
                raw = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        self.prepared()
                finally:
                    path.write_bytes(raw)

    def test_any_changed_continuation_or_helper_bytes_stop_preparation(self):
        for name in sorted(ADDED):
            with self.subTest(path=name):
                path = self.site / name
                raw = path.read_bytes()
                path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
                try:
                    with self.assertRaises(ValueError):
                        self.prepared()
                finally:
                    path.write_bytes(raw)

    def with_modified_manifest(self, change):
        self.assertTrue(hasattr(publisher, 'CONTINUATION_PINS'), 'Reviewed continuation identity pins are absent')
        name = 'continuation/downloads.json'
        path = self.site / name
        original = path.read_bytes()
        manifest = json.loads(original)
        change(manifest)
        raw = (json.dumps(manifest, indent=2) + '\n').encode()
        pins = dict(publisher.CONTINUATION_PINS)
        pins[name] = (len(raw), hashlib.sha256(raw).hexdigest())
        path.write_bytes(raw)
        try:
            # Re-reviewing only JSON bytes cannot admit a new artifact or claim.
            with patch.object(publisher, 'CONTINUATION_PINS', pins), self.assertRaises(ValueError):
                self.prepared()
        finally:
            path.write_bytes(original)

    def test_reviewed_helper_sha_size_and_source_commit_cannot_be_relabelled(self):
        for field, value in [('sha256', '0' * 64), ('bytes', 17917),
                             ('source_commit', '0' * 40), ('url', '/downloads/other.zip')]:
            with self.subTest(field=field):
                self.with_modified_manifest(lambda m: m['items'][3].update({field: value}))

    def test_unreviewed_iso_source_archive_and_git_bundle_stay_pending(self):
        for index in range(3):
            for field, value in [('state', 'ready'), ('url', '/downloads/not-reviewed.iso'),
                                 ('sha256', '0' * 64), ('bytes', 1), ('source_commit', '0' * 40)]:
                with self.subTest(role=index, field=field):
                    self.with_modified_manifest(lambda m: m['items'][index].update({field: value}))

    def test_duplicate_roles_cannot_hide_a_missing_artifact_gate(self):
        self.with_modified_manifest(lambda m: m['items'][1].update(role='development_iso'))

    def test_false_native_private_media_setup_and_architecture_claims_are_refused(self):
        changes = [
            lambda m: m.update(full_modern_apps_verified=True),
            lambda m: m.update(native_windows98_modern_apps_verified=True),
            lambda m: m['private_media_policy'].update(windows_media_published=True),
            lambda m: m['private_media_policy'].update(product_keys_published=True),
            lambda m: m['private_media_policy'].update(vm_disks_published=True),
            lambda m: m['private_media_policy'].update(vendor_app_installers_published=True),
            lambda m: m['usb_scope'].update(windows98_setup_boot_verified=True),
            lambda m: m['usb_scope'].update(full_public_usb_payload_available=True),
            lambda m: m['architecture_goal'].update(installed_windows98_complete=True),
            lambda m: m['architecture_goal'].update(replaces='none'),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.with_modified_manifest(change)

    def test_local_navigation_keeps_current_product_and_source_only_distribution_policy(self):
        for name, href, label in [('index.html', './continuation/', '소스·USB 도구'),
                                  ('en/index.html', '../continuation/', 'Source &amp; USB tools')]:
            with self.subTest(path=name):
                text = (self.site / name).read_text()
                self.assertIn('href="' + href + '">' + label + '</a>', text)
                self.assertIn('ShizukuOS', text)
                self.assertIn('1.0.0', text)
                self.assertNotIn('1.0.0 complete', text)
                self.assertIn('https://github.com/NiSeullent/Win98-Modern', text)
        handoff = (self.site / 'authorship/handoff.html').read_text()
        self.assertIn('href="../continuation/"', handoff)
        self.assertIn('href="../continuation/guide.html"', handoff)
        self.assertIn('0.9', handoff)
        self.assertIn('1.0.0', handoff)
        self.assertIn('https://github.com/NiSeullent/Win98-Modern/tree/main', handoff)


if __name__ == '__main__':
    unittest.main()
