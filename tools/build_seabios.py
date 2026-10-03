#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the native Supervisor's 256 KiB system BIOS from pinned SeaBIOS.

Uses the reviewed ROM producer's actual read leases and owned-unit cleanup.
The resulting BIOS is a component artifact; no VM or Windows runs here.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

import build_stdvga_rom as custody

COMMIT = custody.COMMIT
CONFIG = b'CONFIG_QEMU=y\nCONFIG_ROM_SIZE=256\nCONFIG_BOOTMENU=n\nCONFIG_XEN=n\n'


def bios_metadata(raw):
    custody.need(len(raw) == 256 << 10 and raw[-16] == 0xea and
                 raw[-13:-11] == b'\0\xf0' and
                 re.fullmatch(rb'[0-9]{2}/[0-9]{2}/[0-9]{2}', raw[-11:-3]) and
                 raw[-2] == 0xfc, 'exact 256KiB SeaBIOS reset/date/model layout required')
    return {'bytes': len(raw), 'reset_segment': 0xf000, 'model_id': raw[-2]}


def map_digest(rows):
    return custody.sha(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode())


def verify_configuration(raw):
    lines = set(raw.splitlines())
    for wanted in CONFIG.splitlines():
        key, value = wanted.split(b'=', 1)
        actual = b'# '+key+b' is not set' if value == b'n' else wanted
        custody.need(actual in lines, 'generated BIOS configuration differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--private-out', type=Path, required=True)
    parser.add_argument('--unit', required=True)
    args = parser.parse_args()
    source = custody.canonical(args.source)
    out = custody.canonical(args.private_out)
    parent = out.parent.stat()
    custody.need(not out.exists() and stat.S_IMODE(parent.st_mode) == 0o700 and
                 parent.st_uid == os.getuid() and not any((p/'.git').exists() for p in (out, *out.parents)),
                 'fresh owned private0700 output outside Git required')
    custody.need(re.fullmatch(r'shz-seabios-[a-z0-9-]{1,64}\.service', args.unit), 'independent BIOS unit required')
    fields = subprocess.check_output(['systemctl', 'show', args.unit, '--property=MainPID,ActiveState,Delegate,RuntimeMaxUSec'], text=True, timeout=5)
    observed = dict(line.split('=', 1) for line in fields.splitlines())
    custody.need(observed == {'MainPID': str(os.getpid()), 'ActiveState': 'active', 'Delegate': 'yes', 'RuntimeMaxUSec': 'infinity'}, 'sole surviving delegated BIOS owner required')
    group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1].lstrip('/')
    custody.need(not custody.census(group), 'fresh producer has unrelated children')
    os.umask(0o077)
    leases = custody.Leases()
    created = False
    commands = []
    stop = time.monotonic() + 300
    tools = {name: Path(shutil.which(name)).resolve() for name in ('gcc', 'make', 'git', 'sh', 'python3', 'ld', 'as', 'objcopy', 'objdump', 'strip')}
    for name in ('cc1', 'collect2'):
        tools[name] = Path(subprocess.check_output([tools['gcc'], '-print-prog-name='+name], text=True).strip()).resolve()
    try:
        for p in (Path(__file__).resolve(), Path(custody.__file__).resolve(), *tools.values()):
            leases.add(custody.pin(p))

        def run(argv, cwd=None):
            leases.check()
            remaining = stop - time.monotonic()
            custody.need(remaining > 0, 'fixed BIOS build budget exhausted')
            command = list(map(str, argv)); commands.append(command)
            try:
                result = subprocess.check_output(command, cwd=cwd, stderr=subprocess.STDOUT, timeout=remaining)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                if created:
                    (out/'failed-command-output.log').write_bytes((error.output or b'')[:1 << 20])
                raise
            leases.check()
            return result

        custody.need(run([tools['git'], '-C', source, 'rev-parse', 'HEAD']).decode().strip() == COMMIT, 'pinned SeaBIOS commit differs')
        tree = {}
        for row in run([tools['git'], '-C', source, 'ls-tree', '-rz', COMMIT]).split(b'\0'):
            if not row:
                continue
            meta, name = row.split(b'\t'); mode, kind, blob = meta.decode().split()
            custody.need(kind == 'blob' and mode in ('100644', '100755'), 'tracked regular source required')
            name = name.decode(); tree[name] = (mode, blob)
            leases.add(custody.pin(source/name))
        for p in (source/'.git').rglob('*'):
            if p.is_file():
                leases.add(custody.pin(p))
        archive = run([tools['git'], '-c', 'tar.umask=0022', '-C', source, 'archive', '--format=tar', COMMIT])
        files = custody.archive_files(archive, tree)
        out.mkdir(mode=0o700); created = True; (out/'source').mkdir(mode=0o700)
        (out/'source.tar').write_bytes(archive); leases.add(custody.pin(out/'source.tar'))
        sources = {}
        for name, (raw, mode) in sorted(files.items()):
            p = out/'source'/name; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw); p.chmod(mode)
            pin = custody.pin(p)
            original = leases.rows[str(source/name)]['pin']
            custody.need((pin['bytes'], pin['sha256']) == (original['bytes'], original['sha256']), 'original source differs from Git archive')
            leases.add(pin); sources['source/'+name] = pin['sha256']
        config = out/'generated.config'; config.write_bytes(CONFIG)
        version = out/'source/.version'; version.write_text('shizuku-'+COMMIT+'\n')
        leases.add(custody.pin(version)); sources['source/.version'] = custody.pin(version)['sha256']
        (out/'config-fragment').write_bytes(CONFIG); leases.add(custody.pin(out/'config-fragment'))
        sources['config-fragment'] = custody.pin(out/'config-fragment')['sha256']
        make = [tools['make'], '-j2', 'KCONFIG_CONFIG='+str(config), 'EXTRAVERSION=-source-built', 'CC='+str(tools['gcc']), 'HOSTCC='+str(tools['gcc']), 'CONFIG_SHELL='+str(tools['sh']), 'LD='+str(tools['ld']), 'AS='+str(tools['as']), 'OBJCOPY='+str(tools['objcopy']), 'OBJDUMP='+str(tools['objdump']), 'STRIP='+str(tools['strip']), 'PYTHON='+str(tools['python3'])]
        (out/'configure.log').write_bytes(run([*make, 'olddefconfig'], out/'source'))
        (out/'configure-header.log').write_bytes(run([*make, 'out/autoconf.h'], out/'source'))
        verify_configuration(config.read_bytes())
        leases.add(custody.pin(config)); sources['generated.config'] = custody.pin(config)['sha256']
        (out/'make.log').write_bytes(run([*make, 'out/bios.bin'], out/'source'))
        raw = (out/'source/out/bios.bin').read_bytes(); layout = bios_metadata(raw)
        (out/'SEABIOS.BIN').write_bytes(raw)
        for name in ('source/out/autoconf.h', 'source/out/autoversion.h', 'SEABIOS.BIN'):
            pin = custody.pin(out/name); leases.add(pin)
            if name != 'SEABIOS.BIN':
                sources[name] = pin['sha256']
        for p in (Path(__file__).resolve(), Path(custody.__file__).resolve()):
            sources[str(p)] = custody.pin(p)['sha256']
        licenses = {name: custody.pin(out/'source'/name) for name in ('COPYING', 'COPYING.LESSER')}
        tool_map = {name: {'path': str(p), 'sha256': leases.rows[str(p)]['pin']['sha256']} for name, p in tools.items()}
        custody.retained_cleanup(group); leases.verify_all()
        receipt = {'schema': 'shizukuos.actual-source-built-system-bios.v1', 'status': 'ACTUAL_SOURCE_BOUND_SYSTEM_BIOS_BUILT_NOT_RUN', 'source_commit': COMMIT, 'source_archive': custody.pin(out/'source.tar'), 'artifact': custody.pin(out/'SEABIOS.BIN'), 'sources_sha256': sources, 'source_root': str(out), 'source_map_sha256': map_digest(sources), 'tools_sha256': tool_map, 'tool_map_sha256': map_digest(tool_map), 'license_files': licenses, 'configuration': custody.pin(config), 'layout': layout, 'commands': commands, 'actual_unit': observed, 'source_tool_RDLKs_held_through_build': True, 'original_source_tools_full_SHA_unchanged': True, 'actual_owned_children_reaped': not custody.census(group), 'complete_SDK_shared_library_closure': False, 'VM_executed': False, 'Windows98_verified': False}
        (out/'build-result.json').write_text(json.dumps(receipt, indent=2)+'\n')
        leases.verify_all(); custody.need(not custody.census(group), 'late BIOS child appeared')
        print(json.dumps({'status': receipt['status'], 'artifact': receipt['artifact']}))
    except BaseException:
        if created:
            (out/'build-result.json').unlink(missing_ok=True)
        raise
    finally:
        custody.retained_cleanup(group)
        try:
            leases.verify_all()
        except BaseException:
            if created:
                (out/'build-result.json').unlink(missing_ok=True)
            raise
        finally:
            try:
                leases.close()
            except BaseException:
                if created:
                    (out/'build-result.json').unlink(missing_ok=True)
                raise


if __name__ == '__main__':
    main()
