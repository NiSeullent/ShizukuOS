#!/usr/bin/env python3
"""Publish only reviewed m98 static assets to the existing local origin.

Creates a new immutable release, swaps only /srv/m98/current, and validates
every exact response through loopback HTTPS with m98 Host/SNI. A failed check
restores the previous symlink. No nginx, DNS or unrelated service is changed.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / 'site'
BASE = Path('/srv/m98')
STATIC = ('index.html', 'preview.html', 'styles.css', 'preview.css', 'preview.js',
          'dead-screen.html', 'dead-screen.css', 'dead-screen.js',
          'dead-screen-preview.wasm', 'en/index.html', 'en/preview.html',
          'en/preview.js', 'en/dead-screen.html', 'en/evidence/preview.json',
          'favicon.svg', 'evidence/preview.json', 'downloads/SHZGOP.zip',
          'downloads/SHZGOP.zip.sha256', 'downloads/SHZNPP.zip',
          'downloads/SHZNPP.zip.sha256', 'downloads/SHZNPP-README.md',
          'downloads/shizuku-modern-preview-2026.10.01.zip',
          'downloads/shizuku-modern-preview-2026.10.01.zip.sha256',
          'downloads/dead-screen-preview-source.zip',
          'downloads/dead-screen-preview-source.zip.sha256')
AUTHORSHIP_STATIC = ('authorship/index.html', 'authorship/styles.css',
                    'authorship/evidence.json', 'authorship/handoff.html')
AUTHORSHIP_IMAGES = {
    'npp-cold-open.png': 'cb630d9533decbe718cdaddd79f93ec8b9d7da3ebd3eaaadcfdc62d5695a9990',
    'npp-keyboard-saved.png': '10699734c6334687e95b8b6150f98bef3a27d9acda7f06ac4c2f78f702787417',
    'gop-start.png': '574a70e9ee600e7f458eb6c93e54ae8ac88584addd0887e8af78328c510e2062',
    'gop-gdi.png': '41bf02431b194a3889eac4f80da8ceb22ec390875fcdd084a9c6bf9593288eb4',
    'legcord-welcome.png': '28fc8a9c451a610160ca833be12056e9497fb5bf85753a6169d3d3bbadf62238',
    'chromium-loading.png': 'ca6b5ce2e239170b91fc4372b98979efa6f3c7cf73f16efcd501c2be4282453e',
}


CONTINUATION_STATIC = ('continuation/index.html', 'continuation/guide.html',
                       'continuation/styles.css', 'continuation/downloads.json',
                       'continuation/modern-apps-guide.md',
                       'continuation/environment-guide.md',
                       'continuation/official-distribution.md')
# Artifact bytes and source revisions are reviewed outside the web manifest.
# Add each final artifact here only after its producer/boot/source review closes.
CONTINUATION_DOWNLOAD_PINS = {
    'usb_helpers': {
        'path': 'downloads/win98-modern-usb-helper.zip',
        'sha256': 'f5492becf55ecbfea079c829d473133cbe6073dbcb1b762a94f933f5679d9e54',
        'bytes': 17916,
        'source_commit': '899c51ec6f4c731fe3181570feec0fa52bfbd591',
    },
}
CONTINUATION_GUIDE_PINS = {
    'continuation/modern-apps-guide.md': '69b1fc3c9afdfd21ba46acdcb66fa7d26b0459f96b2528f86d891297b466013f',
    'continuation/environment-guide.md': '22371d3abfaf731d9cd39b60ccb5b8e8e83012317ae042eb71edf0fc47cdf060',
    'continuation/official-distribution.md': '16d663f0743af8eaafd9ac6ea84b2884939ffbae5cf9695abc5e771d15b165d4',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_translation(original, translated):
    """Permit localized copy and asset paths, preserving every evidence fact."""
    localized = json.loads(json.dumps(translated))
    original_collections = original['collections']
    if len(localized['collections']) != len(original_collections):
        raise ValueError('English evidence collections differ')
    for source, target in zip(original_collections, localized['collections']):
        if source.keys() != target.keys():
            raise ValueError('English evidence fields differ')
        for field in ('title', 'platform', 'display', 'result', 'scope'):
            if not isinstance(target[field], str) or not target[field].strip():
                raise ValueError('English evidence copy missing: ' + field)
            target[field] = source[field]
        if (not isinstance(target['observations'], list)
                or len(target['observations']) != len(source['observations'])
                or not all(isinstance(text, str) and text.strip()
                           for text in target['observations'])):
            raise ValueError('English observations differ')
        target['observations'] = source['observations']
        if len(source['frames']) != len(target['frames']):
            raise ValueError('English evidence frames differ')
        for original_frame, english_frame in zip(source['frames'], target['frames']):
            if original_frame.keys() != english_frame.keys():
                raise ValueError('English frame fields differ')
            expected_src = '../../evidence/images/' + Path(original_frame['src']).name
            if english_frame['src'] != expected_src:
                raise ValueError('English original image path differs')
            english_frame['src'] = original_frame['src']
            for field in ('caption', 'alt', 'chapter', 'runLabel'):
                if not isinstance(english_frame[field], str) or not english_frame[field].strip():
                    raise ValueError('English frame copy missing: ' + field)
                english_frame[field] = original_frame[field]
    if localized != original:
        raise ValueError('English translation changed an evidence fact')


def add_authorship_assets(assets):
    """Add only the reviewed development checkpoint and unchanged captures."""
    assets.update({name: (SITE / name).read_bytes() for name in AUTHORSHIP_STATIC})
    manifest = json.loads(assets['authorship/evidence.json'])
    if (manifest['schema'] != 'win98modern.authorship-evidence.v2'
            or manifest['release_state'] != 'development_checkpoint'
            or manifest['full_project_goal_complete'] is not False
            or manifest['current_checkpoint']['release_0_9_complete'] is not False):
        raise ValueError('Reviewed incomplete development checkpoint required')
    records = manifest['screenshots']
    expected_paths = {'./images/' + name for name in AUTHORSHIP_IMAGES}
    if len(records) != len(expected_paths) or {row['src'] for row in records} != expected_paths:
        raise ValueError('Authorship capture allowlist differs')
    for row in records:
        relative = Path(row['src'])
        name = 'authorship/images/' + relative.name
        data = (SITE / name).read_bytes()
        if (row['pixel_transform'] is not False
                or row['kind'] != 'original-guest-capture'
                or row['sha256'] != AUTHORSHIP_IMAGES[relative.name]
                or sha(data) != row['sha256']
                or not data.startswith(b'\x89PNG\r\n\x1a\n')):
            raise ValueError('Reviewed original Authorship PNG changed: ' + name)
        assets[name] = data
    results = {row['id']: row for row in manifest['results']}
    gui = results['chromium-gui']
    headless = results['chromium-headless']
    if (gui['version'] != '157.0.8079.0' or gui['revision'] != '1706750'
            or gui['raw_record_rewritten'] is not False
            or gui['app_functionality_verified'] is not False
            or gui['native_windows98_verified'] is not False
            or gui['local_page_loaded'] is not False
            or gui['actual_exit'] != '0xc0000005'
            or headless['executable_tree_sha_pinned_in_legacy_result'] is not False
            or headless['disk_image_byte_audit_performed_for_this_page'] is not False
            or headless['native_windows98_verified'] is not False):
        raise ValueError('Authorship Chromium provenance or scope differs')
    return len(records)



def add_continuation_assets(assets):
    """Publish local guidance plus only independently pinned public artifacts."""
    assets.update({name: (SITE / name).read_bytes() for name in CONTINUATION_STATIC})
    for path, expected in CONTINUATION_GUIDE_PINS.items():
        if sha(assets[path]) != expected:
            raise ValueError('Reviewed continuation guide changed: ' + path)
    manifest = json.loads(assets['continuation/downloads.json'])
    if (manifest['schema'] != 'win98modern.official-downloads.v1'
            or manifest['version'] != '0.9.0-dev'
            or manifest['official_origin'] != 'https://m98.nyase.kr'
            or manifest['source_commit'] is not None
            or manifest['full_modern_apps_verified'] is not False
            or manifest['native_windows98_modern_apps_verified'] is not False):
        raise ValueError('Reviewed incomplete official download checkpoint required')
    goal = manifest['architecture_goal']
    if (goal['project'] != 'ShizukuDOS for Windows98'
            or goal['replaces'] != 'MS-DOS'
            or goal['kernel32_kernel64_scope'] != 'Windows98 integration components of ShizukuDOS'
            or goal['separate_standalone_os_goal'] is not False
            or goal['installed_windows98_complete'] is not False):
        raise ValueError('Windows98 ShizukuDOS architecture goal differs')
    privacy = manifest['private_media_policy']
    for field in ('windows_media_published', 'product_keys_published',
                  'vendor_app_installers_published', 'vm_disks_published'):
        if privacy[field] is not False:
            raise ValueError('Private media cannot be published: ' + field)
    scope = manifest['usb_scope']
    for field in ('uefi_file_copy_preparation_verified', 'bios_hybrid_image_boot_verified',
                  'windows98_setup_boot_verified', 'full_public_usb_payload_available'):
        if scope[field] is not False:
            raise ValueError('Actual final USB/Setup scope has not been reviewed: ' + field)
    if (scope['helper_source_package_verified'] is not True
            or scope['helper_host_fixture_checks'] != 9):
        raise ValueError('Reviewed helper source package evidence required')
    provenance = manifest['guide_provenance']
    for field, path in (('modern_original_sha256', 'continuation/modern-apps-guide.md'),
                        ('modern_web_sha256', 'continuation/modern-apps-guide.md'),
                        ('environment_source_sha256', 'continuation/environment-guide.md'),
                        ('policy_source_sha256', 'continuation/official-distribution.md')):
        if provenance[field] != CONTINUATION_GUIDE_PINS[path]:
            raise ValueError('Continuation guide provenance differs: ' + field)
    rows = manifest['items']
    roles = {'development_iso', 'source_archive', 'main_git_bundle', 'usb_helpers'}
    if len(rows) != len(roles) or {row['role'] for row in rows} != roles:
        raise ValueError('Official artifact role allowlist differs')
    ready = 0
    for row in rows:
        role = row['role']
        if role not in CONTINUATION_DOWNLOAD_PINS:
            if (row['state'] != 'pending'
                    or any(row[field] is not None for field in ('url', 'sha256', 'bytes', 'source_commit'))):
                raise ValueError('Unreviewed artifact must remain pending: ' + role)
            continue
        pin = CONTINUATION_DOWNLOAD_PINS[role]
        path = Path(pin['path'])
        if (path.is_absolute() or len(path.parts) != 2 or path.parts[0] != 'downloads'
                or path.name in ('.', '..') or path.suffix not in ('.iso', '.zip', '.gz', '.bundle')):
            raise ValueError('Only bounded reviewed artifact paths are permitted')
        if (row['state'] != 'ready' or row['url'] != '/' + pin['path']
                or row['sha256'] != pin['sha256'] or row['bytes'] != pin['bytes']
                or row['source_commit'] != pin['source_commit']):
            raise ValueError('Reviewed official artifact metadata differs: ' + role)
        data = (SITE / pin['path']).read_bytes()
        if len(data) != pin['bytes'] or sha(data) != pin['sha256']:
            raise ValueError('Reviewed official artifact bytes changed: ' + role)
        checksum_path = pin['path'] + '.sha256'
        checksum = (SITE / checksum_path).read_bytes()
        if checksum != (pin['sha256'] + '  ' + path.name + '\n').encode('ascii'):
            raise ValueError('Reviewed official artifact checksum changed: ' + role)
        assets[pin['path']] = data
        assets[checksum_path] = checksum
        ready += 1
    return {'ready_artifacts': ready, 'pending_artifacts': len(rows) - ready,
            'state': manifest['publication_state']}

def main():
    manifest = json.loads((SITE / 'evidence/preview.json').read_text())
    if manifest['schema'] != 1 or manifest['live']['available']:
        raise ValueError('Reviewed recorded preview manifest required')
    assets = {name: (SITE / name).read_bytes() for name in STATIC}
    validate_translation(manifest, json.loads(assets['en/evidence/preview.json']))
    authorship_images = add_authorship_assets(assets)
    continuation = add_continuation_assets(assets)
    # Each redistributed component download remains bound to its reviewed bytes.
    expected_downloads = {
        'downloads/SHZGOP.zip': '5fdc6ca5942012b6d29a291ca85e6ad4e5ca28421477394bfd2909c64f9c5dbb',
        'downloads/SHZNPP.zip': '9ae5a7628f99783e79b935a6eb04dfdc38ddafd02e540079877ae3dcac7df042',
        'downloads/shizuku-modern-preview-2026.10.01.zip': '6b322139ff1b2417b6a1792f036082f284883d095e4bda57d560c85c57f958e7',
        'downloads/dead-screen-preview-source.zip': '9a41d2ab8af79b79e72eb63f160eca95c9c159259ddc938940c711f751af7b72',
    }
    for name, expected in expected_downloads.items():
        if sha(assets[name]) != expected:
            raise ValueError('Reviewed download changed: ' + name)
        checksum = assets[name + '.sha256'].decode('ascii')
        if checksum != expected + '  ' + Path(name).name + '\n':
            raise ValueError('Download checksum changed: ' + name)
    if sha(assets['dead-screen-preview.wasm']) != '7156b7bb536b2388df3cb6052c40d08789478c0c9d445281c39b9fc0a7ba54fb':
        raise ValueError('Reviewed game preview changed')
    images = set()
    for collection in manifest['collections']:
        for frame in collection['frames']:
            relative = Path(frame['src'])
            if relative.is_absolute() or relative.parts[0] != 'images' or len(relative.parts) != 2:
                raise ValueError('Only bounded original image assets may be published')
            if relative.suffix != '.png' or relative.name in ('.', '..'):
                raise ValueError('Expected bounded PNG asset')
            name = (Path('evidence') / relative).as_posix()
            data = (SITE / name).read_bytes()
            if sha(data) != frame['sha256'] or not data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('Reviewed original PNG changed')
            assets[name] = data
            images.add(name)
    if not images or len(assets) > 128:
        raise ValueError('Unexpected static publication size')
    previous = (BASE / 'current').resolve(strict=True)
    if not previous.is_relative_to(BASE / 'releases'):
        raise ValueError('Existing scoped m98 release required')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
    release = BASE / 'releases' / stamp
    output = ROOT / 'build/m98-self-host'
    capture = output / ('origin-' + stamp)
    hashes = {name: sha(data) for name, data in assets.items()}
    release.mkdir(parents=True, exist_ok=False)
    for name, data in assets.items():
        dest = release / 'site' / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o644)
    for directory in [release, *[path for path in release.rglob('*') if path.is_dir()]]:
        directory.chmod(0o755)
    capture.mkdir(parents=True, exist_ok=False)
    staged = BASE / ('current-' + stamp)
    staged.symlink_to(release)
    os.replace(staged, BASE / 'current')
    checks = []
    try:
        for index, name in enumerate(assets):
            dest = capture / str(index)
            command = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '*',
                       '--insecure', '--resolve', 'm98.nyase.kr:443:127.0.0.1',
                       '--max-time', '10', '--output', str(dest),
                       'https://m98.nyase.kr/' + name]
            fetched = subprocess.run(command, capture_output=True, text=True, timeout=15)
            if fetched.returncode:
                raise RuntimeError('Origin fetch failed: ' + name)
            body = dest.read_bytes()
            if sha(body) != hashes[name]:
                raise ValueError('Origin returned different bytes: ' + name)
            checks.append({'path': '/' + name, 'status': 'PASS',
                           'bytes': len(body), 'sha256': hashes[name]})
    except Exception:
        rollback = BASE / ('rollback-' + stamp)
        rollback.symlink_to(previous)
        os.replace(rollback, BASE / 'current')
        raise
    receipt = {'status': 'PASS', 'release': str(release), 'previous_release': str(previous),
               'static_files': hashes, 'origin_checks': checks, 'origin_check_count': len(checks),
               'certificate_validation': False, 'public_edge_verified': False,
               'preview_images': len(images), 'collections': len(manifest['collections']),
               'authorship_images': authorship_images,
               'authorship_state': 'development_checkpoint',
               'continuation': continuation,
               'languages': ['ko', 'en'], 'game_demo_native_execution': False,
               'scope': 'Exact loopback HTTPS origin bodies with m98 Host/SNI. Public Cloudflare challenge is not counted as successful external fetch.'}
    path = output / ('release-' + stamp + '.json')
    payload = (json.dumps(receipt, indent=2) + '\n').encode()
    path.write_bytes(payload)
    print(json.dumps({'status': 'PASS', 'release': str(release), 'checks': len(checks),
                      'receipt': str(path), 'sha256': sha(payload)}))


if __name__ == '__main__':
    main()
