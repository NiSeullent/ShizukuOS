#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stage a pinned native shell into an existing Win64 runtime; no compile/boot/install."""
import argparse
import ast
import hashlib
import json
import re
import shutil
import struct
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
CAP = 16 << 20


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pinned(path, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected) is not None, 'Invalid SHA-256 pin')
    require(path.is_file() and not path.is_symlink(), 'Expected regular input: ' + str(path))
    require(path.stat().st_size <= CAP, 'Input exceeds 16 MiB')
    data = path.read_bytes()
    require(sha(data) == expected, 'Input pin mismatch: ' + str(path))
    return data


def unpack(data):
    require(data[:8] == b'SHZARC01' and len(data) >= 16, 'Invalid runtime archive')
    count, reserved = struct.unpack_from('<II', data, 8)
    end = 16 + count * 136
    require(not reserved and 0 < count <= 1024 and end <= len(data), 'Invalid archive table')
    files, seen, spans = [], set(), []
    for i in range(count):
        at = 16 + i * 136
        raw = data[at:at + 120]
        require(b'\0' in raw, 'Unterminated archive path')
        head, tail = raw.split(b'\0', 1)
        require(not any(tail), 'Nonzero archive path padding')
        name = head.decode('ascii')
        parts = name.split('\\')
        require(parts[0] == '' and len(parts) >= 3 and all(p and p not in ('.', '..') for p in parts[1:])
                and '/' not in name and ':' not in name, 'Unsafe archive path')
        key = name.upper()
        require(key not in seen, 'Duplicate archive member')
        offset, size = struct.unpack_from('<QQ', data, at + 120)
        require(offset >= end and offset % 16 == 0 and offset <= len(data)
                and size <= len(data) - offset, 'Archive member outside image')
        seen.add(key)
        spans.append((offset, offset + size))
        files.append((name, data[offset:offset + size]))
    spans.sort()
    require(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])), 'Overlapping archive members')
    return files




SOUND_DESTINATIONS = {'\\SHZ\\MEDIA\\'+n for n in (
    'SHIZUKUCONNECT.WAV', 'SHIZUKUDISCONNECT.WAV', 'SHIZUKUERROR.WAV', 'SHIZUKULOGIN.WAV', 'SHIZUKULOGOUT.WAV', 'SHIZUKUNAVIGATION.WAV', 'SHIZUKUNOTIFICATION.WAV', 'SHIZUKUSHUTDOWN.WAV', 'SHIZUKUSTARTUP.WAV', 'SHIZUKUWARNING.WAV')}
PROGRAM_DESTINATIONS = {'\\SHZ\\SYS64\\'+n for n in ('WINMM.DLL','MUZIK.EXE','GAMES.EXE')}

def pcm_wave(data):
    require(len(data)>=12 and data[:4]==b'RIFF' and data[8:12]==b'WAVE'
            and struct.unpack_from('<I',data,4)[0]+8==len(data),'Invalid WAV RIFF extent')
    at=12;fmt=payload=None
    while at<len(data):
        require(at+8<=len(data),'Truncated WAV chunk')
        kind=data[at:at+4];size=struct.unpack_from('<I',data,at+4)[0];start=at+8
        require(size<=len(data)-start,'WAV chunk extent')
        if kind==b'fmt ':require(fmt is None and size>=16,'Duplicate/short WAV fmt');fmt=struct.unpack_from('<HHIIHH',data,start)
        if kind==b'data':require(payload is None,'Duplicate WAV data');payload=size
        at=start+size+(size&1)
    require(at==len(data) and fmt is not None and payload is not None,'Incomplete WAV')
    tag,channels,rate,byte_rate,align,bits=fmt
    require(tag==1 and channels in (1,2) and bits in (8,16) and rate in (11025,22050,44100,48000)
            and align==channels*(bits//8) and byte_rate==rate*align and payload>0 and payload%align==0,'Unsupported/inconsistent PCM')
    return {'channels':channels,'bits':bits,'rate':rate,'frames':payload//align}

def validate_sound_scheme(sound_files):
    """Bind the installed INI to the same complete WAV inventory.
    Event aliases are the existing WINMM sndscheme.c Events contract; no new service.
    """
    import configparser
    wavs={n.upper() for n,_ in sound_files if n.upper().endswith('.WAV')}
    schemes=[data for n,data in sound_files if n.upper()=='\\SHZ\\SHZSOUND.INI']
    require(wavs==SOUND_DESTINATIONS and len(schemes)==1, 'Sound and scheme must be one complete paired set')
    parser=configparser.ConfigParser(interpolation=None,strict=True)
    try:
        parser.read_string(schemes[0].decode('ascii'))
    except (UnicodeError,configparser.Error) as exc:
        raise ValueError('Invalid sound Events scheme') from exc
    require(not parser.defaults() and len(parser.sections())==1 and parser.sections()[0].lower()=='events', 'Unexpected sound scheme section')
    events=dict(parser[parser.sections()[0]])
    aliases={'systemstart','windowslogon','windowslogoff','systemexit','systemasterisk',
             'notification.default','mailbeep','systemexclamation','systemhand','.default',
             'deviceconnect','devicedisconnect','menucommand','navigating'}
    require(set(events)==aliases, 'Incomplete or unknown WINMM event aliases')
    targets=set()
    for value in events.values():
        require(value and '/' not in value and '\\' not in value and ':' not in value,
                'Scheme must reference installed WAV basenames')
        target='\\SHZ\\MEDIA\\'+value.upper()
        require(target in wavs, 'Sound scheme points outside its installed WAV set')
        targets.add(target)
    require(targets==wavs, 'Sound scheme omits an installed event WAV')


def local_manifest_reference(parent, reference, inputs, blobs):
    require(isinstance(reference,dict),'Missing receipt/source binding')
    name=reference.get('path')
    require(isinstance(name,str) and name and not PurePosixPath(name).is_absolute()
            and '\\' not in name and ':' not in name and all(p not in ('','.','..') for p in name.split('/')),'Unsafe receipt path')
    path=parent/name
    require(path.resolve().is_relative_to(parent.resolve()),'Receipt escapes asset map')
    data=pinned(path,reference.get('sha256'));require(len(data)==reference.get('bytes'),'Receipt size mismatch')
    inputs[path]=reference['sha256'];blobs[path]=data
    return json.loads(data)

def verify_program_maps(manifest_path, mapped, members, inputs, blobs):
    # No compiler or invented provider: consume actual PE/import and source receipts.
    import pefile
    manifest=json.loads(blobs[manifest_path]);default=manifest.get('verification_receipt')
    source=local_manifest_reference(manifest_path.parent,manifest.get('source_correspondence_receipt'),inputs,blobs)
    require(source.get('status')=='PASS_LIVE_SOURCE_CORRESPONDENCE_9_COMPILED_COPIES_2_PRODUCER_INTEGRATION_CONFIGS'
            and source.get('guest_execution') is False,'Unapproved source correspondence receipt')
    require(isinstance(source.get('source_files'),list) and len(source['source_files'])==11,'Incomplete source correspondence')
    for entry in source['source_files']:
        path=Path(entry['live_path'])
        require(path.is_absolute() and path.resolve().is_relative_to(ROOT.resolve()),'Source correspondence escapes project')
        digest=entry['live_pin']['sha256'];encoded=pinned(path,digest)
        require(len(encoded)==entry['live_pin']['bytes'],'Source correspondence size mismatch')
        inputs[path]=digest;blobs[path]=encoded
    metadata={}
    for (target,data),entry in zip(mapped,manifest['files']):
        require(target.upper()!='\\SHZ\\SYS64\\SAPPHIRE.EXE',
                'Sapphire separate source/import proof normalization pending; native eleven-source receipt is insufficient')
        proof=local_manifest_reference(manifest_path.parent,entry.get('verification_receipt',default),inputs,blobs)
        require(proof.get('status')=='PASS_FOUR_REAL_NATIVE64_PE_IMPORT_FORWARDER_EXPORT_BINDINGS_NO_GUEST'
                and proof.get('guest_execution') is False,'Missing actual native PE/import proof')
        matches=[i for i in proof.get('images',[]) if i.get('pin')=={'bytes':len(data),'sha256':sha(data)}]
        require(len(matches)==1,'PE receipt does not bind exact asset')
        pe=pefile.PE(data=data);is_dll=bool(pe.FILE_HEADER.Characteristics&0x2000)
        require(is_dll==target.upper().endswith('.DLL') and pe.OPTIONAL_HEADER.AddressOfEntryPoint!=0,'PE DLL/EXE kind or entry mismatch')
        actual=[]
        for module in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
            provider=module.dll.decode().lower();key='\\SHZ\\SYS64\\'+provider.upper()
            require(key in members and sha(members[key])==proof.get('provider_pins',{}).get(provider,{}).get('sha256'),'Program provider cohort mismatch '+provider)
            for imp in module.imports:
                require(imp.name is not None,'Unexpected ordinal import')
                actual.append({'provider':provider,'name':imp.name.decode()})
        expected=[{'provider':i['provider'],'name':i['name']} for i in matches[0]['imports']]
        require(actual==expected,'Actual PE imports differ from proof')
        # Bind every provider used by recursive forwarder chains as well.
        for item in matches[0]['imports']:
            for step in item.get('resolved_actual_PE_export_chain',[]):
                provider=step.split('!',1)[0];key='\\SHZ\\SYS64\\'+provider.upper()
                require(key in members and sha(members[key])==proof['provider_pins'][provider]['sha256'],'Forwarder provider cohort mismatch')
        metadata[target.upper()]={'sha256':sha(data),'bytes':len(data),'image_kind':'DLL' if is_dll else 'EXE','imports':actual}
    return metadata


def verify_sapphire_map(manifest_path, mapped, members, inputs, blobs):
    """Consume Sapphire's own actual source/link receipt, separately from WinMM."""
    manifest = json.loads(blobs[manifest_path])
    proof = local_manifest_reference(manifest_path.parent, manifest.get('producer_result'), inputs, blobs)
    freeze = local_manifest_reference(manifest_path.parent, manifest.get('source_freeze'), inputs, blobs)
    require(proof.get('status') == 'PASS_REAL_NATIVE64_SAPPHIRE_SELECT_TRANSACTION_SUCCESSOR_NO_GUEST'
            and proof.get('native_guest_claim') is False and proof.get('inputs_unchanged') is True,
            'Missing actual Sapphire source/link proof')
    expected = {'shizukudos/win64/apps/sapphire/' + n for n in
                ('main.c', 'sapphire_img.c', 'sapphire_img.h', 'sapphire_png.c')}
    expected |= {'src/vendor/lodepng/lodepng.c', 'src/vendor/lodepng/lodepng.h',
                 'shizukudos/win64/crt/shzcrt.c', 'shizukudos/win64/crt/shzcrt.h'}
    sources = freeze.get('source_before')
    require(isinstance(sources, dict) and set(sources) == expected
            and freeze.get('source_maps_equal') is True and sources == freeze.get('source_after')
            and sources == proof.get('source_before') == proof.get('source_after'),
            'Incomplete or unstable Sapphire sources')
    for name, digest in sources.items():
        path = ROOT / name
        require(path.resolve().is_relative_to(ROOT.resolve()), 'Sapphire source escapes project')
        inputs[path] = digest
        blobs[path] = pinned(path, digest)
    require(len(mapped) == 1, 'Expected one Sapphire executable')
    target, data = mapped[0]
    artifact = proof.get('artifact', {})
    require(artifact.get('pin') == {'bytes': len(data), 'sha256': sha(data)}
            and artifact.get('machine') == 'AMD64' and artifact.get('magic') == 'PE32+',
            'Sapphire receipt does not bind exact executable')
    import pefile
    pe = pefile.PE(data=data)
    require(not pe.FILE_HEADER.Characteristics & 0x2000
            and pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0
            and pe.OPTIONAL_HEADER.AddressOfEntryPoint == artifact.get('entry_rva'),
            'Sapphire image kind or entry mismatch')
    providers = proof.get('provider_pins', {})
    actual = []
    for module in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        provider = module.dll.decode().lower()
        for symbol in module.imports:
            require(symbol.name is not None, 'Unexpected Sapphire ordinal import')
            actual.append({'provider': provider, 'symbol': symbol.name.decode()})
    claimed = artifact.get('imports', [])
    require(actual and actual == [{'provider': e['provider'], 'symbol': e['symbol']} for e in claimed],
            'Actual Sapphire imports differ from source/link proof')
    for provider, pin in providers.items():
        key = '\\SHZ\\SYS64\\' + provider.upper()
        require(key in members and pin == {'bytes': len(members[key]), 'sha256': sha(members[key])},
                'Sapphire provider cohort mismatch: ' + provider)
    for item in claimed:
        chain = item.get('actual_export_chain', [])
        require(chain and chain[0] == item['provider'] + '!' + item['symbol'], 'Missing Sapphire export chain')
        for step in chain:
            provider = step.split('!', 1)[0]
            require(provider in providers, 'Unbound Sapphire forwarder provider')
    return {target.upper(): {'sha256': sha(data), 'bytes': len(data), 'image_kind': 'EXE',
                             'imports': actual, 'source_link_receipt_sha256': sha(blobs[manifest_path.parent / manifest['producer_result']['path']])}}


def mapped_assets(manifest_path, manifest_sha, kind, inputs, blobs):
    """Read a closed asset map; admit only exact known runtime destinations."""
    encoded = pinned(manifest_path, manifest_sha)
    inputs[manifest_path] = manifest_sha
    blobs[manifest_path] = encoded
    manifest = json.loads(encoded)
    entries = manifest.get('files')
    require(isinstance(entries, list), 'Missing asset files')
    allowed = {
        'font': {'\\SHZ\\FONTS\\NOTOSANS.TTF', '\\SHZ\\FONTS\\NOTOSANSKR.OTF',
                 '\\SHZ\\FONTS\\OFL-LATIN.TXT', '\\SHZ\\FONTS\\OFL-KR.TXT'},
        'caption': {'\\SHZ\\FONTS\\NOTOCAP.BIN'},
        'notice': {'\\SHZ\\FONTS\\NOTICE.TXT'},
        'runtime': {'\\SHZ\\SYS64\\GDI32.DLL', '\\SHZ\\SYS64\\USER32.DLL'},
        'probe': {'\\SHZ\\SYS64\\FONTCHK.EXE'},
        'ntdll': {'\\SHZ\\SYS64\\NTDLL.DLL'},
        'program': PROGRAM_DESTINATIONS,
        'sound': SOUND_DESTINATIONS,
        'scheme': {'\\SHZ\\SHZSOUND.INI'},
        'sapphire': {'\\SHZ\\SYS64\\SAPPHIRE.EXE'},
        'sample': {'\\SHZ\\SYS64\\SAPPHIRE-SAMPLE.PNG'},
    }[kind]
    if kind=='program':
        targets={e.get('media_target','').upper() for e in entries if isinstance(e,dict)}
        require(targets in (PROGRAM_DESTINATIONS,PROGRAM_DESTINATIONS|{'\\SHZ\\SYS64\\SAPPHIRE.EXE'}),'Unknown program set')
        allowed=targets
    require(len(entries) == len(allowed), 'Incomplete asset map')
    files, seen = [], set()
    for entry in entries:
        require(isinstance(entry, dict), 'Invalid asset entry')
        target = entry.get('media_target')
        require(isinstance(target, str) and target.upper() in allowed and target.upper() not in seen,
                'Unexpected or duplicate asset destination')
        seen.add(target.upper())
        name = entry.get('path')
        require(isinstance(name, str) and name and '\\' not in name and ':' not in name
                and not PurePosixPath(name).is_absolute()
                and all(x not in ('', '.', '..') for x in name.split('/')), 'Unsafe asset source')
        path = manifest_path.parent / name
        require(path.resolve().is_relative_to(manifest_path.parent.resolve()), 'Asset escapes manifest directory')
        data = pinned(path, entry.get('sha256'))
        require(len(data) == entry.get('bytes') and len(data) > 0, 'Asset size mismatch')
        if kind == 'font' and target.upper().endswith('.TXT'):
            require(b'SIL OPEN FONT LICENSE Version 1.1' in data, 'Missing outline font license')
        if kind=='sound':require(pcm_wave(data)==entry.get('format'),'WAV PCM format does not bind NAS readback')
        if kind=='scheme':require(len(data)<=65536 and b'[' in data and b'=' in data and b'\x00' not in data,'Invalid bounded sound scheme')
        if kind=='sample':
            require(len(data)>=33 and data[:8]==b'\x89PNG\r\n\x1a\n' and data[12:16]==b'IHDR', 'Invalid PNG fixture')
            width,height=struct.unpack_from('>II',data,16)
            require(0<width<=8192 and 0<height<=8192 and width*height<=8388608, 'PNG fixture dimensions exceed Sapphire bounds')
        if kind in ('runtime', 'probe','ntdll','program','sapphire'):
            require(data[:2] == b'MZ' and len(data) >= 64, 'Runtime override is not a PE')
            pe = struct.unpack_from('<I', data, 60)[0]
            require(pe <= len(data) - 26 and data[pe:pe+4] == b'PE\0\0'
                    and struct.unpack_from('<H', data, pe+4)[0] == 0x8664
                    and struct.unpack_from('<H', data, pe+24)[0] == 0x20b,
                    'Runtime override is not PE64')
        inputs[path] = entry['sha256']
        blobs[path] = data
        files.append((target, data))
    return files


def bundled_theme_licenses(theme_map, shell_dir, source_hashes, inputs, blobs):
    """Extend the producer's existing theme map with exactly two license files.

    Historical receipts without GPL3 data remain usable. A new producer source
    or a GPL3 declaration cannot lose either notice/license during staging.
    """
    names = ('THEME-NOTICE.TXT', 'THEME-GPL3.TXT')
    sources = {'integration/shizuku-shell/themes/' + n for n in names}
    require(isinstance(source_hashes, dict), 'Invalid theme source pins')
    declared = theme_map.get('data_license') if isinstance(theme_map, dict) else None
    entries = theme_map.get('license_files') if isinstance(theme_map, dict) else None
    if declared is None:
        require(entries in (None, []) and not sources.intersection(source_hashes),
                'GPL3 theme source lacks its declared notice/license map')
        return [], {}
    require(declared == 'GPL-3.0' and isinstance(entries, list) and len(entries) == 2
            and sources <= source_hashes.keys(), 'Incomplete GPL3 theme notice/license map')
    files, hashes, seen = [], {}, set()
    for entry in entries:
        require(isinstance(entry, dict), 'Invalid theme license entry')
        name = entry.get('name')
        require(name in names and name not in seen, 'Invalid or duplicate theme license destination')
        seen.add(name)
        source = 'integration/shizuku-shell/themes/' + name
        beside = 'THEMES/' + name
        target = '\\SHZ\\SYSTEM\\THEMES\\' + name
        digest = entry.get('sha256')
        require(entry.get('source') == source and entry.get('beside_exe') == beside
                and entry.get('media_target') == 'C:' + target and source_hashes[source] == digest,
                'Unexpected theme license mapping or producer source pin')
        path = shell_dir / beside
        data = pinned(path, digest)
        limit = 16384 if name == 'THEME-NOTICE.TXT' else 65536
        require(0 < len(data) <= limit and len(data) == entry.get('bytes'), 'Invalid theme license size')
        require(pinned(ROOT / source, digest) == data, 'Staged theme license differs from source')
        if name == 'THEME-GPL3.TXT':
            require(b'GNU GENERAL PUBLIC LICENSE' in data and b'Version 3, 29 June 2007' in data,
                    'Missing full GPL version 3 theme data license')
        else:
            require(b'ShizukuOS' in data and b'B00merang-Project' in data, 'Missing native theme attribution')
        for bound in (path, ROOT / source):
            inputs[bound] = digest
            blobs[bound] = data
        files.append((target, data))
        hashes[target.upper()] = digest
    return files, hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime-dir', 'shell-exe', 'shell-receipt', 'ofl', 'shell-license', 'gpl-license', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('archive-sha', 'runtime-receipt-sha', 'shell-sha', 'shell-receipt-sha', 'ofl-sha', 'shell-license-sha', 'gpl-license-sha', 'packer-sha'):
        parser.add_argument('--' + name, required=True)
    for kind in ('font', 'caption', 'runtime', 'probe', 'notice','ntdll','program','sound','scheme','sapphire','sample'):
        parser.add_argument('--' + kind + '-manifest', type=Path)
        parser.add_argument('--' + kind + '-manifest-sha')
    args = parser.parse_args()
    for kind in ('font', 'caption', 'runtime', 'probe', 'notice','ntdll','program','sound','scheme','sapphire','sample'):
        require(bool(getattr(args, kind + '_manifest')) == bool(getattr(args, kind + '_manifest_sha')), 'Manifest and pin must be paired')
    rt, out = args.runtime_dir.resolve(), args.out.resolve()
    require(not out.exists(), 'Output must be a new directory')
    require(rt != out and rt not in out.parents and out not in rt.parents, 'Output overlaps runtime')
    require(shutil.disk_usage(out.parent).free >= (17 << 30) + CAP, 'Insufficient output reserve')
    inputs = {
        rt / 'WIN64.IMG': args.archive_sha,
        rt / 'build-result.json': args.runtime_receipt_sha,
        args.shell_exe: args.shell_sha,
        args.shell_receipt: args.shell_receipt_sha,
        args.ofl: args.ofl_sha,
        args.shell_license: args.shell_license_sha,
        args.gpl_license: args.gpl_license_sha,
        ROOT / 'shizukudos/win64/build.py': args.packer_sha,
    }
    blobs = {p: pinned(p, digest) for p, digest in inputs.items()}
    base = json.loads(blobs[rt / 'build-result.json'])
    receipt = json.loads(blobs[args.shell_receipt])
    theme_files = []
    theme_hashes = {}
    theme_map = receipt.get('theme_stage_map')
    if theme_map is not None:
        entries = theme_map.get('files') if isinstance(theme_map, dict) else None
        require(isinstance(entries, list) and len(entries) == 3, 'Expected three bundled themes')
        seen_themes = set()
        for entry in entries:
            require(isinstance(entry, dict), 'Invalid theme entry')
            name = entry.get('name')
            require(name in ('Slade', 'Flute', 'Jade') and name not in seen_themes, 'Invalid or duplicate theme')
            seen_themes.add(name)
            beside = 'THEMES/' + name + '/theme.ini'
            target = '\\SHZ\\SYSTEM\\THEMES\\' + name + '\\theme.ini'
            source = 'integration/shizuku-shell/themes/' + name + '/theme.ini'
            require(entry.get('beside_exe') == beside and entry.get('media_target') == 'C:' + target
                    and entry.get('source') == source, 'Unexpected theme mapping')
            path = args.shell_exe.parent / beside
            data = pinned(path, entry.get('sha256'))
            require(len(data) == entry.get('bytes') and len(data) <= 65536, 'Invalid theme size')
            require(pinned(ROOT / source, entry['sha256']) == data, 'Staged theme differs from source')
            inputs[path] = entry['sha256']
            blobs[path] = data
            theme_files.append((target, data))
            theme_hashes[target.upper()] = entry['sha256']
    theme_license_files, theme_license_hashes = bundled_theme_licenses(
        theme_map, args.shell_exe.parent, receipt.get('source_sha256_before'), inputs, blobs)
    require(base.get('status') == 'PASS' and base.get('archive', {}).get('sha256') == args.archive_sha,
            'Base archive is not bound to a completed runtime receipt')
    require(receipt.get('stageable') is True and receipt.get('source_unchanged_during_build') is True,
            'Shell compile/import receipt is not stageable')
    require(receipt.get('exe', {}).get('sha256') == args.shell_sha and receipt['exe'].get('machine') == '0x8664'
            and receipt['exe'].get('optional_magic') == '0x20b', 'Shell receipt does not bind this PE64')
    require(not receipt.get('missing_exports') and not receipt.get('dlls_without_runtime_export_table'), 'Unresolved shell imports')
    before = receipt.get('source_sha256_before')
    require(isinstance(before, dict) and before and before == receipt.get('source_sha256_after'), 'Missing stable shell sources')
    if 'integration/shizuku-font/noto_provider.c' in before:
        require(args.font_manifest is not None, 'Native Noto shell requires its pinned outline font asset map')
    for name, digest in before.items():
        require(isinstance(name, str) and '\\' not in name and ':' not in name
                and not PurePosixPath(name).is_absolute() and all(x not in ('', '.', '..') for x in name.split('/')), 'Unsafe source path')
        path = ROOT / name
        require(path.resolve().is_relative_to(ROOT), 'Source escapes project')
        pinned(path, digest)
    files = unpack(blobs[rt / 'WIN64.IMG'])
    members = {name.upper(): data for name, data in files}
    runtime_files = []
    if args.runtime_manifest:
        runtime_files = mapped_assets(args.runtime_manifest, args.runtime_manifest_sha, 'runtime', inputs, blobs)
        replacements = {name.upper(): data for name, data in runtime_files}
        require(set(replacements) <= set(members), 'Runtime override has no base member')
        files = [(name, replacements.get(name.upper(), data)) for name, data in files]
        members = {name.upper(): data for name, data in files}
    ntdll_files=[]
    if args.ntdll_manifest:
        ntdll_files=mapped_assets(args.ntdll_manifest,args.ntdll_manifest_sha,'ntdll',inputs,blobs)
        replacement={n.upper():d for n,d in ntdll_files}
        require(set(replacement)<=set(members),'NTDLL replacement missing base member')
        files=[(n,replacement.get(n.upper(),d)) for n,d in files];members={n.upper():d for n,d in files}
    added_programs=[];sound_files=[]
    if args.program_manifest:added_programs=mapped_assets(args.program_manifest,args.program_manifest_sha,'program',inputs,blobs)
    sapphire_files=[]
    if args.sapphire_manifest:
        sapphire_files=mapped_assets(args.sapphire_manifest,args.sapphire_manifest_sha,'sapphire',inputs,blobs)
        added_programs+=sapphire_files
    for kind in ('sound','scheme'):
        path=getattr(args,kind+'_manifest')
        if path:sound_files+=mapped_assets(path,getattr(args,kind+'_manifest_sha'),kind,inputs,blobs)
    require(bool(args.sound_manifest)==bool(args.scheme_manifest), 'Sound and scheme manifests must be paired')
    if sound_files:validate_sound_scheme(sound_files)
    sample_files=[]
    if args.sample_manifest:
        require(args.sapphire_manifest is not None, 'Image fixture requires its actual executable proof')
        sample_files=mapped_assets(args.sample_manifest,args.sample_manifest_sha,'sample',inputs,blobs)
    require(not any(n.upper() in members for n,_ in added_programs+sound_files),'New module/app/sound already in base')
    future_members=dict(members);future_members.update({n.upper():d for n,d in added_programs})
    program_metadata={}
    for path,group in ((args.ntdll_manifest,ntdll_files),(args.program_manifest,added_programs)):
        if path:program_metadata.update(verify_program_maps(path,[e for e in group if e not in sapphire_files],future_members,inputs,blobs))
    if args.sapphire_manifest:
        program_metadata.update(verify_sapphire_map(args.sapphire_manifest,sapphire_files,future_members,inputs,blobs))
    font_files = []
    for kind in ('font', 'caption', 'notice'):
        path = getattr(args, kind + '_manifest')
        if path:
            font_files += mapped_assets(path, getattr(args, kind + '_manifest_sha'), kind, inputs, blobs)
    probe_files = []
    if args.probe_manifest:
        require(args.font_manifest is not None and args.runtime_manifest is not None, 'Font diagnostic needs outline and runtime maps')
        probe_files = mapped_assets(args.probe_manifest, args.probe_manifest_sha, 'probe', inputs, blobs)
        require(not any(name.upper() in members for name, _ in probe_files), 'Base already contains font diagnostic')
    require(not args.caption_manifest or (args.font_manifest and args.notice_manifest), 'Caption cache needs its outline source assets and copyright notice')
    require(not any(name.upper() in members for name, _ in font_files), 'Base already contains new font assets')
    for dll, info in receipt.get('runtime_dlls', {}).items():
        key = '\\SHZ\\SYS64\\' + dll.upper()
        require(key in future_members and sha(future_members[key]) == info.get('sha256'), 'Shell runtime DLL cohort mismatch: ' + dll)
    require({'kernel32.dll', 'user32.dll', 'gdi32.dll', 'ntdll.dll'} <= set(receipt.get('runtime_dlls', {})), 'Missing core runtime pins')
    require(b'SIL OPEN FONT LICENSE Version 1.1' in blobs[args.ofl], 'Missing font license')
    require(b'GNU LESSER GENERAL PUBLIC LICENSE' in blobs[args.shell_license], 'Missing adapted shell license')
    require(b'GNU GENERAL PUBLIC LICENSE' in blobs[args.gpl_license] and
            b'Version 2' in blobs[args.gpl_license], 'Missing GPL2 renderer license')
    require('\\SHZ\\SYS64\\SHZDESK.EXE' not in members, 'Base runtime already contains a desktop')
    files += [('\\SHZ\\SYS64\\SHZDESK.EXE', blobs[args.shell_exe]),
              ('\\SHZ\\FONTS\\SHZKR-OFL.TXT', blobs[args.ofl]),
              ('\\SHZ\\SYS64\\SHELL-LICENSE.TXT', blobs[args.shell_license]),
              ('\\SHZ\\SYS64\\SHELL-GPL2.TXT', blobs[args.gpl_license])]
    require(not any(name.upper() in members for name, _ in theme_files), 'Base runtime already contains bundled themes')
    require(not any(name.upper() in members for name, _ in theme_license_files), 'Base runtime already contains theme licenses')
    require(not any(n.upper() in members for n,_ in sample_files), 'Image fixture already exists in base')
    files += theme_files + theme_license_files + font_files + probe_files + added_programs + sound_files + sample_files
    # Execute only the unchanged production packing function, without importing
    # build.py or running its compiler/global build hooks.
    tree = ast.parse(blobs[ROOT / 'shizukudos/win64/build.py'])
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'pack_archive')
    scope = {'struct': struct}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<production-pack_archive>', 'exec'), scope)
    archive = scope['pack_archive'](files)
    require(len(archive) <= CAP and unpack(archive) == files, 'Staged archive failed exact readback')
    require('\\SHZ\\SETUP\\SHZSETUP.EXE' in members and
            {'\\SHZ\\TESTS\\T_HELLO.EXE', '\\SHZ\\TESTS\\T_W64CON.EXE'} <= set(members),
            'Base archive lacks the installer or retained bridge applications')
    loose = {}
    for name, data in files:
        key = name.upper()
        direct_system = key.startswith('\\SHZ\\SYS64\\') and len(name.split('\\')) == 4 and key.endswith(('.DLL', '.EXE'))
        retained_test = key in ('\\SHZ\\TESTS\\T_HELLO.EXE', '\\SHZ\\TESTS\\T_W64CON.EXE')
        retained_installer = key == '\\SHZ\\SETUP\\SHZSETUP.EXE'
        if direct_system or retained_test or retained_installer:
            destination = name.split('\\')[-1].lower()
            require(destination not in loose, 'Duplicate loose-file destination: ' + destination)
            loose[destination] = data
    loose_size = sum(map(len, loose.values()))
    require(len(archive) + loose_size + (1 << 20) <= CAP, 'Staged archive, loose files and receipt exceed cap')
    require(all(pinned(p, h) == blobs[p] for p, h in inputs.items()), 'Inputs changed during staging')
    for name, digest in before.items():
        pinned(ROOT / name, digest)
    modules = json.loads(json.dumps(base['modules']))
    for name, data in runtime_files:
        module = name.split('\\')[-1].lower().removesuffix('.dll')
        require(module in modules, 'Missing overridden runtime module metadata')
        modules[module]['sha256'] = sha(data)
    for target,info in program_metadata.items():
        if info['image_kind']=='DLL':
            name=target.split('\\')[-1].lower().removesuffix('.dll')
            # The installer already handles these two core DLLs explicitly.
            # Keep the module registry free of duplicate core runtime entries.
            if name not in ('ntdll','kernel32'):
                modules[name]={**modules.get(name,{}),**info}
    staged = {'status': 'STAGED_PENDING_GUI_VALIDATION', 'scope': 'existing runtime plus native shell; packaging only',
              'modules': modules, 'added_program_metadata': program_metadata,
              'sound_sha256': {n.upper():sha(d) for n,d in sound_files},
              'image_fixture_sha256': {n.upper():sha(d) for n,d in sample_files},
              'ntdll_replacement_sha256': {n.upper():sha(d) for n,d in ntdll_files}, 'archive': {'sha256': sha(archive), 'bytes': len(archive), 'members': len(files)},
              'base_runtime_receipt_sha256': args.runtime_receipt_sha, 'shell_receipt_sha256': args.shell_receipt_sha,
              'inputs': {str(p): h for p, h in inputs.items()}, 'shell_source_sha256': before,
              'kernel_entry_alias': 'SHZDESK.EXE contains the exact new shizuku-shell.exe bytes',
              'member_sha256': {name.upper(): sha(data) for name, data in files}, 'guest_execution': False,
              'theme_sha256': theme_hashes,
              'theme_license_sha256': theme_license_hashes,
              'theme_data_license': theme_map.get('data_license') if isinstance(theme_map, dict) else None,
              'font_sha256': {name.upper(): sha(data) for name, data in font_files},
              'diagnostic_sha256': {name.upper(): sha(data) for name, data in probe_files},
              'runtime_override_sha256': {name.upper(): sha(data) for name, data in runtime_files},
              'installed': False, 'Windows10_full_compatibility': False, 'published': False}
    encoded_receipt = (json.dumps(staged, indent=2) + '\n').encode()
    require(len(encoded_receipt) <= (1 << 20) and len(archive) + loose_size + len(encoded_receipt) <= CAP, 'Receipt or total output exceeds cap')
    out.mkdir()
    (out / 'WIN64.IMG').write_bytes(archive)
    # Keep the exact base DLL/application files expected by mkpayload.py. This
    # copies archived bytes, not a potentially newer loose-file build cohort.
    for name, data in loose.items():
        (out / name).write_bytes(data)
    # Installer selector uses this case-sensitive loose filename.
    (out / 'shzsetup.exe').rename(out / 'SHZSETUP.EXE')
    (out / 'build-result.json').write_bytes(encoded_receipt)
    require(sum(p.stat().st_size for p in out.iterdir()) <= CAP, 'Staged output exceeds cap')
    print(json.dumps(staged['archive']))


if __name__ == '__main__':
    main()
