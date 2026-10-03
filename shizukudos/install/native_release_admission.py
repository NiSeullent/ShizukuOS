#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build-owner admission from independently anchored, held actual producer bytes.

This does not certify Windows boot or issue runtime authority from JSON flags.
Only kbuild's private installer profile consumes the generated record. All
original producer inputs, saved manifest/SIM and generated C remain leased
through compilation and final receipt validation. No large image is created.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

import native_release_policy as policy

ROOT = Path(__file__).resolve().parent
MAX_ENCODED = 512 << 20
MAGIC = 0x31524e53


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def anchored(row, approved, name):
    require(type(row) is dict and approved is not None and
            (row.get('bytes'), row.get('sha256')) == approved,
            'independent producer anchor differs: ' + name)


def load_ingester():
    source = ROOT / 'native_payload_ingest.py'
    raw = source.read_bytes()
    require(digest(raw) == policy.INGEST_SHA, 'reviewed ingestion source epoch changed')
    spec = importlib.util.spec_from_file_location('release_held_ingest', source)
    module = importlib.util.module_from_spec(spec)
    # Execute the authenticated bytes, not a second mutable pathname read.
    exec(compile(raw, str(source), 'exec'), module.__dict__)
    return module


def manifest_expected(ingest, request_pin, lineage, sim):
    return {
        'schema': ingest.SCHEMA, 'status': 'PRIVATE_NATIVE_ESP_INPUT_EXPORTED_NOT_INSTALLED',
        'private': True, 'public_artifact': False,
        'redistribution': 'PROHIBITED_PRIVATE_LICENSED_INPUT', 'boot_profile': 'native-win98',
        'source_request': request_pin, 'lineage': lineage, 'esp_sim': sim,
        'ESP_geometry': 'LBA0_SUPERFLOPPY_UNCHANGED_NOT_PARTITION_REBASED', 'first_lba': 0,
        'input_linux_read_leases': True, 'inputs_before_after_full_SHA_match': True,
        'independent_expanded_ESP_readback': True, 'compiler_tool_closure_verified': False,
        **{key: False for key in ingest.FALSE_FLAGS},
    }


def render_record(manifest, sim, evidence):
    require(0 < manifest['bytes'] <= 4 << 20 and 0 < sim['bytes'] <= MAX_ENCODED,
            'actual encoded source exceeds kernel sealed-copy capability')
    def array(value):
        raw = bytes.fromhex(value)
        require(len(raw) == 32 and any(raw), 'nonzero SHA256 required')
        return '{' + ','.join('0x%02x' % byte for byte in raw) + '}'
    return ('/* Private generated data: never publish or add to Git. */\n'
            '#include "setup_native_release.h"\n'
            'const setup_native_release_record_v1 shz_installer_release_v1 = {\n'
            f'0x{MAGIC:08x}u,1u,128u,0u,{manifest["bytes"]}ull,{sim["bytes"]}ull,\n'
            f'{array(manifest["sha256"])},{array(sim["sha256"])},{array(evidence)}\n'
            '};\n').encode()


def file_pin(ingest, value):
    p = ingest.path(str(value))
    size = p.stat().st_size
    require(0 < size <= ingest.MAX_FILE, 'bounded saved file required')
    # Discovery supplies a custody pin, never independent producer authority.
    with p.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(p), 'bytes': size, 'sha256': sha}


_CUSTODY_KEY = object()


class BuildCustody:
    """Ephemeral build capability, never serialized or issued by caller JSON."""
    def __init__(self, key, ingest, held, roles):
        require(key is _CUSTODY_KEY, 'generator-owned custody required')
        self._ingest, self._held, self._roles = ingest, held, roles
        self._active = True

    def check(self):
        require(self._active, 'build custody closed')
        self._held.check()

    def pin(self, role):
        self.check()
        require(role in self._roles and self._roles[role] is not None,
                'independent producer component absent: ' + role)
        return dict(self._roles[role])

    def read(self, role, offset, size):
        row = self.pin(role)
        require(type(offset) is int and type(size) is int and
                0 <= offset <= row['bytes'] and 0 <= size <= min(1 << 20, row['bytes']-offset),
                'bounded custody read required')
        entry = self._held.entries[self._ingest.path(row['path'])]
        return self._ingest.read_exact(entry['fd'], size, offset,
                                      lambda: self._held.io_check(entry))

    def finish(self):
        self.check()
        self._held.finish()

    def retain_output(self, row, identity):
        self.check()
        self._held.add(row, written_identity=identity)

    def guard(self, callback):
        self.check()
        self._held.guards.append(callback)


@contextmanager
def admit_for_build(manifest_path, output, build_pins=()):
    require(policy.NATIVE_SOURCE_MAP_SHA is not None and policy.NATIVE_ARTIFACTS is not None,
            'independently approved native producer anchors absent; admission refused')
    ingest = load_ingester()
    output = ingest.path(str(output))
    require(not output.exists() and output.parent.is_dir() and
            not any((p / '.git').exists() for p in output.parents),
            'fresh private admission directory outside Git required')
    # A single Union avoids nested SIGIO handlers and maintains every input's
    # actual read lease until the compiler and receipt have finished.
    with ingest.Union() as held:
        source_files = [Path(__file__).resolve(), ROOT / 'native_release_policy.py',
                        ROOT / 'native_payload_ingest.py', ROOT / 'native_capacity_profile.py']
        for source in source_files:
            held.add(file_pin(ingest, source))
        held.add({'path': str(ROOT / 'native_payload_ingest.py'),
                  'bytes': (ROOT / 'native_payload_ingest.py').stat().st_size,
                  'sha256': policy.INGEST_SHA})
        for row in build_pins:
            held.add(row)
        mrow = file_pin(ingest, manifest_path)
        require(mrow['bytes'] <= ingest.MAX_JSON, 'bounded saved manifest required')
        saved = held.json(mrow)
        request_pin = saved.get('source_request')
        request = held.json(request_pin)
        source_custody = policy.verify_private_source_custody(request, held)
        require(type(source_custody) is dict and source_custody,
                'independent installed-source custody did not provide typed evidence')
        anchored(request['dos_build_receipt'], policy.DOS_RECEIPT, 'original DOS receipt')
        dos = held.json(request['dos_build_receipt'])
        require(dos.get('toolchain', {}).get('open-watcom', {}).get('snapshot_sha256') == policy.WATCOM_SHA,
                'independent DOS compiler archive anchor differs')
        profile = held.json(request['constructor_profile'])
        payloads = {row['guest']: row['file'] for row in profile.get('payloads', [])}
        for name, approved in policy.DOS_ARTIFACTS.items():
            anchored(payloads.get(name), approved, name)
        native = held.json(request['native_build_receipt'])
        require(digest(canonical(native.get('sources_sha256'))) == policy.NATIVE_SOURCE_MAP_SHA,
                'independent native producer source epoch differs')
        actual = dict(native.get('input_pins', {}))
        actual['BOOTX64.EFI'] = native.get('members', {}).get('EFI/BOOT/BOOTX64.EFI')
        require(set(policy.NATIVE_ARTIFACTS) == {'KERNEL32.BIN', 'KERNEL64.BIN', 'BOOTX64.EFI'} |
                ({'WIN64.IMG'} if 'WIN64.IMG' in actual else set()),
                'complete independent native component anchors required')
        for name, approved in policy.NATIVE_ARTIFACTS.items():
            anchored(actual.get(name), approved, name)
        esp, lineage = ingest.validate_lineage(request, held)
        sim = saved.get('esp_sim')
        require(type(sim) is dict and type(sim.get('bytes')) is int and
                0 < sim['bytes'] <= MAX_ENCODED, 'encoded SIM exceeds actual kernel capability')
        sim_entry = held.add(sim)
        ingest.verify_sim(sim_entry['fd'], sim['bytes'], esp['pin'], held.check)
        expected = manifest_expected(ingest, request_pin, lineage, sim)
        require(held.bytes(mrow) == (json.dumps(expected, indent=2) + '\n').encode(),
                'saved manifest differs from independently reconstructed producer result')
        evidence = digest(canonical({'policy_sha256': digest((ROOT / 'native_release_policy.py').read_bytes()),
                                     'request': request_pin, 'source_custody': source_custody, 'lineage': lineage,
                                     'manifest': mrow, 'sim': sim}))
        raw = render_record(mrow, sim, evidence)
        output.mkdir(mode=0o700)
        owned = ingest.identity(output.stat())[:2]
        def guard():
            require(ingest.identity(output.stat())[:2] == owned and
                    stat.S_IMODE(output.stat().st_mode) == 0o700 and
                    output.stat().st_uid == os.getuid() and not output.is_symlink(),
                    'private output custody changed')
        held.guards.append(guard)
        generated = output / 'native_release_admitted.c'
        directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            guard()
            require(ingest.identity(os.fstat(directory))[:2] == owned,
                    'private writer directory descriptor changed')
            fd = os.open(generated.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                ingest.write_all(fd, raw)
                os.fsync(fd)
                written = ingest.identity(os.fstat(fd))
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)
        record = {'path': str(generated), 'bytes': len(raw), 'sha256': digest(raw)}
        held.add(record, written_identity=written)
        held.finish()
        custody = BuildCustody(_CUSTODY_KEY, ingest, held,
                               {'manifest': mrow, 'sim': sim, 'runtime': actual.get('WIN64.IMG')})
        private_profile = None
        if actual.get('WIN64.IMG') is not None:
            import native_capacity_profile
            private_profile = native_capacity_profile.from_admitted_custody(custody)
        else:
            require(sim['bytes'] <= 256 << 20,
                    'large source requires actual target runtime and measured compiler profile')
        try:
            yield {'profile': private_profile, 'custody': custody, 'source': generated, 'record': record, 'manifest': mrow, 'sim': sim,
               'evidence_sha256': evidence, 'private': True, 'public_artifact': False,
               'producer_anchors': {'DOS_receipt': policy.DOS_RECEIPT,
                                   'native_source_map_sha256': policy.NATIVE_SOURCE_MAP_SHA,
                                   'native_artifacts': policy.NATIVE_ARTIFACTS},
               'generator_sources': [held.entries[p]['pin'] for p in source_files],
               'independent_source_custody': source_custody,
               'held_producer_and_build_inputs': [held.entries[p]['pin'] for p in sorted(held.entries)]}
            held.finish()
        finally:
            custody._active = False
    # All lease releases and closes have succeeded before kbuild finalizes its
    # receipt. On any error the build has no successful admission receipt.
