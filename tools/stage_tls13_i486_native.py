#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare exactly one approved TLS Win98 stage; no VM, download or install."""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys

import tls13_i486_native_stage_evidence as evidence


def write(stage, name, data):
    evidence.relative(name)
    evidence.need(isinstance(data, bytes) and len(data) <= evidence.MAX_MEMBER, 'bounded preparation write')
    evidence.resource_guard(min(evidence.MAX_STAGE, len(data) + (1 << 20)))
    target = stage / name
    evidence.canonical(target, exists=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600 if target.name.endswith('.KEY') else 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    evidence.need(evidence.read(target) == data, 'fresh write byte readback')
    evidence.resource_guard()
    return evidence.sha(data)


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def copy_inputs(stage, c):
    for name, (source, digest) in c.copies.items():
        data = evidence.read(source)
        evidence.need(evidence.sha(data) == digest, 'source drift immediately before copy')
        write(stage, name, data)
    # Implied directories are derived from ALL archive members, including links.
    for source in sorted(c.directories):
        evidence.resource_guard(1 << 20)
        target = stage / evidence.member_of(Path(source))
        evidence.canonical(target, exists=False)
        target.mkdir(parents=True, exist_ok=True)
    for source, item in sorted(c.aliases.items()):
        evidence.resource_guard(1 << 20)
        target = stage / evidence.member_of(Path(source))
        evidence.canonical(target.parent)
        evidence.need(not target.exists() and not target.is_symlink(), 'fresh alias collision')
        target.symlink_to(item['target'])
    frozen = evidence.Closure(stage)
    frozen.aliases, frozen.directories = c.aliases, c.directories
    evidence.verify_aliases(frozen)
    c.unchanged()


def _file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (evidence.MAX_MEMBER, evidence.MAX_MEMBER))


def run_builder(stage):
    """Only one reviewed own builder, in a newly owned process group."""
    evidence.resource_guard(64 << 20)
    command = evidence.guest_command(stage)
    log = stage / 'builder-stdout.log'
    timed_out = False
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=evidence.ROOT, stdout=stream, stderr=subprocess.STDOUT,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), start_new_session=True, preexec_fn=_file_limit)
        try:
            process.wait(timeout=420)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            if timed_out or process.returncode:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    record = dict(schema=1, command=command, returncode=process.returncode, timed_out=timed_out,
                  deadline_seconds=420, owned_process_group=True, log_sha256=evidence.sha(evidence.read(log)))
    write(stage, 'builder-invocation.json', json_bytes(record))
    evidence.need(not timed_out and process.returncode == 0, 'approved own guest builder failed; fresh partial stage retained')


def full_listing(path):
    command = ['i686-w64-mingw32-objdump', '-d', '-z', '--show-raw-insn', '--insn-width=16', str(path)]
    p = subprocess.run(command, capture_output=True, timeout=60)
    evidence.need(p.returncode == 0 and not p.stderr and 0 < len(p.stdout) <= evidence.MAX_MEMBER,
                  'actual full raw objdump failed or exceeded bound')
    return p.stdout


def prepare(destination, pins):
    evidence.need(not sys.flags.optimize, 'optimized preparation rejected before mutation')
    destination = Path(destination)
    evidence.need(destination == evidence.DESTINATION and evidence.canonical(destination, exists=False) == destination and
                  not destination.exists(), 'one fresh exact canonical stage required')
    evidence.approved_pins(pins)
    evidence.resource_guard(evidence.MAX_STAGE)
    builds, old_cpu, installed, table, c = evidence.collect(pins)
    evidence.need(c.total + (64 << 20) <= evidence.MAX_STAGE, 'measured original closure plus bounded metadata/build space')
    evidence.resource_guard(evidence.MAX_STAGE)
    destination.mkdir()
    try:
        copy_inputs(destination, c)
        # Exact eight source bytes are physically frozen before compilation.
        for name, digest in evidence.PROBE_SOURCES.items():
            evidence.need(evidence.sha(evidence.read(evidence.ROOT / name)) == digest and
                evidence.sha(evidence.read(destination / evidence.member_of(evidence.ROOT / name))) == digest,
                'before-build original eight current/frozen source bytes')
        run_builder(destination)
        for name, digest in evidence.PROBE_SOURCES.items():
            evidence.need(evidence.sha(evidence.read(evidence.ROOT / name)) == digest and
                evidence.sha(evidence.read(destination / evidence.member_of(evidence.ROOT / name))) == digest,
                'after-build original eight current/frozen source bytes')
        c.unchanged()
        for name in sorted(evidence.INPUTS):
            write(destination, name, evidence.read(destination / 'guest-build' / name, 1 << 20))
        # The original builder uses older metadata gates; these exact four PEs
        # receive a new complete byte/loader/ABI replay under the approved policy.
        for name in ('M98TLS13.DLL', 'M98TLS.DLL', 'TLSDLL.EXE', 'T13RUN.EXE'):
            path = destination / name
            before = evidence.read(path, 1 << 20)
            raw = full_listing(path)
            evidence.need(evidence.read(path, 1 << 20) == before, 'native image drift while decoding')
            write(destination, 'cpu/' + name + '.log', raw)
        build, cpu, members = evidence.generated(destination, c, table, installed)
        builds2, old_cpu2, installed2, table2, c2 = evidence.collect(pins)
        evidence.need((c.copies, c.sources, c.aliases, c.directories, old_cpu, installed, table) ==
                      (c2.copies, c2.sources, c2.aliases, c2.directories, old_cpu2, installed2, table2),
                      'closure changed during deterministic compile/copy')
        authority = evidence.stage_authority(c, build, cpu, members)
        authority_sha = write(destination, 'stage-authority.json', json_bytes(authority))
        members['stage-authority.json'] = authority_sha
        manifest = dict(schema=1, kind='isolated-guest-file-inputs',
            inputs=[dict(source=str(destination / name), guest=evidence.PREFIX + name,
                bytes=len(evidence.read(destination / name, 1 << 20)), sha256=members[name])
                for name in sorted(evidence.INPUTS)], outputs=[evidence.PREFIX + n for n in sorted(evidence.OUTPUTS)],
            backups=[], nonce=evidence.NONCE, command=evidence.PREFIX + 'T13RUN.EXE',
            source_receipts=[dict(path=str(destination / 'stage-authority.json'), sha256=authority_sha)],
            guest_execution='NOT-VERIFIED', network_required=False,
            scope='Corrected original latest/LTS DLL preparation only; no WinSock/OS/apps acceptance')
        manifest_data = json_bytes(manifest)
        manifest_sha = evidence.sha(manifest_data)
        prov_data = json_bytes(evidence.provenance(manifest_sha, authority_sha, c, members))
        evidence.need(len(prov_data) <= evidence.PROVENANCE_LIMIT, 'measured provenance bound')
        write(destination, 'provenance.json', prov_data)
        # Root ready manifest appears only after all prior real closed gates.
        write(destination, 'guest-files.json', manifest_data)
        checked = evidence.check_stage(destination / 'guest-files.json', manifest_sha,
                                      authority_sha, evidence.sha(prov_data), pins)
        evidence.resource_guard()
        return checked
    except BaseException:
        ready = destination / 'guest-files.json'
        if ready.exists() and not ready.is_symlink():
            ready.rename(destination / 'failed-guest-files.json')
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', required=True, type=Path)
    for key in evidence.APPROVED:
        p.add_argument('--' + key.replace('_', '-') + '-sha256', required=True)
    p.add_argument('--check', action='store_true')
    p.add_argument('--manifest-sha256')
    p.add_argument('--authority-sha256')
    p.add_argument('--provenance-sha256')
    args = p.parse_args()
    pins = {n: getattr(args, n + '_sha256') for n in evidence.APPROVED}
    try:
        if args.check:
            result = evidence.check_stage(args.stage / 'guest-files.json', args.manifest_sha256,
                                          args.authority_sha256, args.provenance_sha256, pins)
        else:
            evidence.need(not any((args.manifest_sha256, args.authority_sha256, args.provenance_sha256)),
                          'independent output pins are check-only')
            result = prepare(args.stage, pins)
    except (ValueError, OSError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(passed=False, error=str(error), **evidence.SCOPE)))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
