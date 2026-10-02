"""Product route and artifact controls. No origin publication or guest boot."""
import copy
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import tempfile
import unittest
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch

PUBLISHER = Path(__file__).resolve().parents[1] / 'publish_static.py'
spec = importlib.util.spec_from_file_location('m98_refactor_publisher', PUBLISHER)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
NEW = {page + '.html' for page in ('downloads', 'install', 'apps', 'develop')}
NEW |= {'en/' + page for page in tuple(NEW)}
REFACTORED = NEW | {'index.html', 'en/index.html', 'preview.html', 'en/preview.html',
                    'dead-screen.html', 'en/dead-screen.html',
                    'authorship/index.html', 'authorship/handoff.html'}
PREVIEW_PINS = {
    'evidence/preview.json': 'd201c6ee90e512bc3a11ddd40ac771197eb8ce17ffc8272b4288cf637178cacb',
    'en/evidence/preview.json': 'd0aed30baf69d6b3ead23bc4cdd8ecd4ed5b1c96fd5aa46477df35d82f3ac0f4',
}
COMMIT = '1234567890abcdef1234567890abcdef12345678'


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.ids, self.images, self.languages = [], [], [], []
        self.h1 = self.main = 0
        self.alternates = {}

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'html':
            self.languages.append(attrs.get('lang'))
        if tag == 'h1':
            self.h1 += 1
        if tag == 'main':
            self.main += 1
        if tag in ('a', 'link') and 'href' in attrs:
            self.links.append(attrs['href'])
        if tag == 'img':
            self.images.append(attrs)
        if tag == 'link' and attrs.get('rel') == 'alternate':
            self.alternates[attrs.get('hreflang')] = attrs['href']


def parse(raw):
    doc = Document()
    doc.feed(raw.decode())
    return doc


class SiteRefactor(unittest.TestCase):
    def prepare(self):
        with patch.object(publisher, 'publish', side_effect=AssertionError('No publication in controls')):
            return publisher.prepare_assets()

    def test_exact_eight_routes_and_source_only_exclusions(self):
        prepared = self.prepare()
        assets = prepared['assets']
        self.assertEqual(len(assets), 100)
        self.assertTrue(NEW.issubset(assets))
        self.assertIsNone(prepared['iso'])
        self.assertIsNone(prepared['component_installer_proof'])
        self.assertNotIn('downloads/release.json', assets)
        for name in assets:
            self.assertFalse(name.startswith(('authorship-v09/', 'deploy/', 'evidence/component-installer/')))
            self.assertNotIn(name, ('README.md', 'authorship/README.md', 'export-preview-evidence.py'))
            self.assertFalse(name.endswith(('.iso', '.vmdk', '.qcow2', '.img')))

    def test_original_thirteen_collections_and_all_forty_eight_frames_stay_exact(self):
        assets = self.prepare()['assets']
        for name, digest in PREVIEW_PINS.items():
            self.assertEqual(hashlib.sha256(assets[name]).hexdigest(), digest)
        manifest = json.loads(assets['evidence/preview.json'])
        self.assertEqual(len(manifest['collections']), 13)
        frames = [frame for collection in manifest['collections'] for frame in collection['frames']]
        self.assertEqual(len(frames), 48)
        self.assertFalse(manifest['live']['available'])
        for frame in frames:
            self.assertEqual(hashlib.sha256(assets['evidence/' + PurePosixPath(frame['src']).as_posix()]).hexdigest(), frame['sha256'])

    def test_product_routes_fragments_and_evidence_deep_links_resolve(self):
        assets = self.prepare()['assets']
        docs = {name: parse(raw) for name, raw in assets.items() if name.endswith('.html')}
        collections = {row['id'] for row in json.loads(assets['evidence/preview.json'])['collections']}
        for name in sorted(REFACTORED):
            for href in docs[name].links:
                with self.subTest(page=name, href=href):
                    parsed = urlsplit(href)
                    if parsed.scheme or parsed.netloc:
                        continue
                    route = posixpath.normpath(posixpath.join(posixpath.dirname(name), parsed.path)) if parsed.path else name
                    if parsed.path.endswith('/'):
                        route += '/index.html'
                    if route in ('legacy-console/index.html',):
                        continue
                    self.assertIn(route, assets)
                    if parsed.fragment:
                        self.assertIn(parsed.fragment, docs[route].ids)
                    if route in ('preview.html', 'en/preview.html') and 'view' in parse_qs(parsed.query):
                        self.assertIn(parse_qs(parsed.query)['view'][0], collections)

    def test_language_pairs_skip_targets_headings_and_captures_are_accessible(self):
        assets = self.prepare()['assets']
        for name in sorted(NEW | {'index.html', 'en/index.html'}):
            doc = parse(assets[name])
            lang = 'en' if name.startswith('en/') else 'ko'
            self.assertEqual(doc.languages, [lang], name)
            self.assertEqual(doc.h1, 1, name)
            self.assertEqual(doc.main, 1, name)
            self.assertEqual(len(doc.ids), len(set(doc.ids)), name)
            self.assertIn('main', doc.ids, name)
            self.assertIn('#main', doc.links, name)
            counterpart = name[3:] if lang == 'en' else 'en/' + name
            self.assertIn(('./' if lang == 'ko' else '../') + counterpart, doc.links, name)
            self.assertEqual(set(doc.alternates), {'ko', 'en'}, name)
            for image in doc.images:
                self.assertTrue(image.get('alt', '').strip(), name)
                self.assertGreater(int(image['width']), 0)
                self.assertGreater(int(image['height']), 0)

    def test_all_ten_required_apps_and_original_dos_scope_are_bilingual(self):
        assets = self.prepare()['assets']
        apps = ('Notepad++', 'VLC', 'Google Chrome', 'Firefox', 'Chromium', 'Legcord',
                'LibreOffice', 'Steam', 'Supermium', 'Visual Studio Code')
        versions = ('8.9.8.1', '3.0.24', '154.0.8037.93', '157.0', '157.0.8079.0',
                    '1.3.0', '26.8.0.3', '1788652215', '144.0.7559.256', '1.140.0')
        for name in ('apps.html', 'en/apps.html'):
            text = assets[name].decode()
            self.assertIn('2026-10-01', text)
            for value in apps + versions:
                self.assertIn(value, text, name)
            self.assertEqual(text.count('<th scope="row">'), 10)
            self.assertIn('ShizukuDOS', text)
        self.assertIn('기존 DOS 부팅 경로의 대조 시험', assets['apps.html'].decode())
        self.assertIn('original DOS boot path', assets['en/apps.html'].decode())

    def test_pending_pages_never_offer_an_iso_or_final_install_claim(self):
        assets = self.prepare()['assets']
        for name in ('index.html', 'en/index.html', 'downloads.html', 'en/downloads.html'):
            doc = parse(assets[name])
            self.assertFalse(any(urlsplit(link).path.endswith('.iso') for link in doc.links), name)
            self.assertIn('development-iso', doc.ids)
            self.assertIn('1.0.0', assets[name].decode())
        self.assertIn('최종 1.0.0 · 준비 중', assets['downloads.html'].decode())
        self.assertIn('Final 1.0.0 · Pending', assets['en/downloads.html'].decode())

    def test_download_cards_bind_visible_bytes_hashes_and_actual_links(self):
        assets = self.prepare()['assets']
        for page in ('downloads.html', 'en/downloads.html'):
            parser = publisher.DownloadCards(); parser.feed(assets[page].decode())
            self.assertEqual(len(parser.cards), 5)
            for card in parser.cards:
                name = card['data-download']; raw = assets['downloads/' + name]
                self.assertEqual(card['data-download-bytes'], str(len(raw)))
                self.assertIn(format(len(raw), ','), card['visible_text'])
                self.assertIn(hashlib.sha256(raw).hexdigest(), card['visible_text'])

    def test_stale_hidden_or_visible_download_facts_and_duplicate_cards_refuse(self):
        assets = self.prepare()['assets']
        for page in ('downloads.html', 'en/downloads.html'):
            raw = assets[page]
            text = raw.decode()
            digest = hashlib.sha256(assets['downloads/SHZGOP.zip']).hexdigest()
            mutations = (
                text.replace('data-download-bytes="415345"', 'data-download-bytes="415346"', 1),
                text.replace('<code>' + digest + '</code>', '<code>' + '0' * 64 + '</code>', 1),
                text.replace('415,345', '415,346', 1),
                text.replace('data-download="SHZGOP.zip"', 'data-download="SHZNPP.zip"', 1),
                text.replace('downloads/SHZGOP.zip" download', 'downloads/PLACEHOLDER.zip" download').replace('downloads/SHZNPP.zip" download', 'downloads/SHZGOP.zip" download').replace('downloads/PLACEHOLDER.zip" download', 'downloads/SHZNPP.zip" download'),
            )
            for mutation in mutations:
                with self.subTest(page=page, mutation=mutations.index(mutation)):
                    modified = dict(assets); modified[page] = mutation.encode()
                    with self.assertRaises(ValueError): publisher.validate_download_pages(modified)

    def test_missing_duplicate_or_reversed_iso_slots_refuse(self):
        raw = (publisher.SITE / 'index.html').read_bytes()
        for mutation in (raw.replace(publisher.ISO_SLOT_START.encode(), b''),
                         raw + publisher.ISO_SLOT_START.encode(),
                         raw.replace(publisher.ISO_SLOT_START.encode(), b'PLACEHOLDER').replace(publisher.ISO_SLOT_END.encode(), publisher.ISO_SLOT_START.encode()).replace(b'PLACEHOLDER', publisher.ISO_SLOT_END.encode())):
            with self.assertRaises(ValueError): publisher.replace_iso_slot(mutation, '<p>control</p>')

    def test_no_js_preview_exposes_original_frame_and_localized_manifest(self):
        assets = self.prepare()['assets']
        manifest = json.loads(assets['evidence/preview.json'])
        frame = next(row for row in manifest['collections'] if row['id'] == 'latest-npp-gop')['frames'][0]
        original = 'evidence/' + PurePosixPath(frame['src']).as_posix()
        for page, prefix, language in (('preview.html', './', 'ko'), ('en/preview.html', '../', 'en')):
            text = assets[page].decode()
            self.assertEqual(text.count('<noscript>'), 1, page)
            fallback = text.split('<noscript>', 1)[1].split('</noscript>', 1)[0]
            doc = parse(fallback.encode())
            self.assertIn('preview-fallback', doc.ids)
            self.assertIn(prefix + original, doc.links)
            self.assertIn('./evidence/preview.json', doc.links)
            self.assertEqual(len(doc.images), 1)
            image = doc.images[0]
            self.assertEqual(image['src'], prefix + original)
            self.assertEqual(int(image['width']), frame['width'])
            self.assertEqual(int(image['height']), frame['height'])
            self.assertTrue(image.get('alt', '').strip())
            self.assertEqual(hashlib.sha256(assets[original]).hexdigest(), frame['sha256'])
            self.assertIn('기존 DOS 부팅 경로의 대조 시험' if language == 'ko' else 'original DOS boot path', fallback)
            self.assertIn('ShizukuDOS', fallback)
            self.assertNotIn('불러오는 중', text)
            self.assertNotIn('Loading screenshot', text)

    def test_one_admitted_iso_identity_is_rendered_on_all_four_pages(self):
        with tempfile.TemporaryDirectory(prefix='m98-refactor-iso-control-') as temporary:
            path = Path(temporary) / 'component.iso'
            raw = bytearray(81920); raw[32768:32775] = b'\x01CD001\x01'
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            receipt = {'iso': str(path), 'bytes': len(raw), 'sha256': digest, 'private': False,
                       'git': {'revision': COMMIT, 'dirty': True}}
            path.with_suffix('.json').write_text(json.dumps(receipt))
            source = {name: (publisher.SITE / name).read_bytes() for name in ('index.html', 'en/index.html', 'downloads.html', 'en/downloads.html')}
            prepared = publisher.prepare_assets(path, COMMIT)
            try:
                self.assertEqual(len(prepared['assets']) + 1, 103)
                metadata = prepared['iso'].metadata
                self.assertFalse(metadata['validation']['windows98_installer_complete'])
                self.assertFalse(metadata['validation']['latest_apps_complete'])
                for name in source:
                    text = prepared['assets'][name].decode()
                    prefix = '../' if name.startswith('en/') else './'
                    self.assertIn('href="' + prefix + metadata['artifact']['path'] + '" download', text)
                    self.assertIn(digest, text)
                    self.assertIn('81,920', text)
                    self.assertIn(COMMIT, text)
                    self.assertIn('not-verified-for-this-download', prepared['assets']['downloads/release.json'].decode())
                    self.assertEqual((publisher.SITE / name).read_bytes(), source[name])
                self.assertEqual(path.read_bytes(), bytes(raw))
                changed = copy.deepcopy(metadata); changed['windows98_media_included'] = True
                with self.assertRaises(ValueError): publisher.render_iso_downloadpage(source['downloads.html'], changed, 'ko')
            finally:
                prepared['iso'].close()


if __name__ == '__main__':
    unittest.main()
