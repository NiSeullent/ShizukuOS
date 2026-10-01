#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Preserve bytes while compacting reviewed, stopped PRIVATE build artifacts.

The CLI always uses one fixed PRIVATE directory. Without --execute it validates
the exact plan and approval bytes and writes a receipt only. Execution obtains
exclusive destination leases, makes temporary reflink backups, punches verified
zero blocks and asks the kernel to compare and deduplicate identical blocks.
No installation disk, current app image, source file or other chat is eligible.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import tempfile
import time

PRIVATE = Path('/root/Win98-Modern-apps-cb43/build/modern-apps')
FLOOR = 17 * 1024**3
MARGIN = 8 * 1024**2
BLOCK = 4096
FICLONE = 0x40049409
FIDEDUPERANGE = 0xC0189436
PROTECTED = {'chromium.img', 'steam.img', 'chromium-latest-prep-01a0f3d0cb43',
             'app-runtime-v18', 'app-runtime-v18-public-roots-v3',
             'app-runtime-v19-reg', 'app-runtime-v19-mpr', 'app-runtime-v20-unload',
             'app-runtime-v21-ncrypt', 'app-runtime-v22-ncrypt-unload',
             'app-runtime-v23-mpr-fixture', 'app-runtime-v24-written-fixture'}
SOURCE_SUFFIXES = {'.c', '.h', '.py', '.asm', '.ps1', '.sh'}
ALLOWED_SUFFIXES = {'.img', '.bin', '.elf', '.a', '.o', '.txt'}
# Only these two ended disk-test artifacts may be DLL destinations. This does
# not make application DLLs or other directories eligible for compaction.
FIXTURE_DLLS = {'disk-guest-v9/generated/lazy-dll/BIGLAZY.DLL',
                'disk-guest-v9/generated/lazy-dll/BIGRELOC.DLL'}


def digest_fd(fd):
    h = hashlib.sha256()
    size = os.fstat(fd).st_size
    for off in range(0, size, 1024**2):
        data = os.pread(fd, min(1024**2, size-off), off)
        if len(data) != min(1024**2, size-off):
            raise RuntimeError('Short artifact read')
        h.update(data)
    return h.hexdigest()


def pin(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_blocks]


def active_files(root):
    """Only paths under this scope; never read command lines or environments."""
    found = set()
    prefix = str(root) + '/'
    for p in Path('/proc').glob('[0-9]*'):
        if p.name == str(os.getpid()):
            continue
        try:
            entries = list((p/'fd').iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                name = os.readlink(entry)
                if name.endswith(' (deleted)'):
                    name = name[:-10]
                if name.startswith(prefix):
                    found.add(name)
            except OSError:
                pass
        # Mappings can outlive a closed descriptor. Such files stay ineligible.
        try:
            content = (p/'maps').read_text()
        except OSError:
            continue
        if prefix not in content:
            continue
        for line in content.splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and fields[5].startswith('/'):
                name = fields[5].removesuffix(' (deleted)')
                if name.startswith(prefix):
                    found.add(name)
    return found


class Compactor:
    def __init__(self, root, plan, approval, output, execute=False, *, _host_test=False):
        self.root = Path(root).resolve()
        if not _host_test and self.root != PRIVATE:
            raise RuntimeError('Only the fixed PRIVATE artifact directory is allowed')
        self.plan, self.approval = plan, approval
        self.output = Path(output)
        self.execute = execute
        self.floor = 0 if _host_test else FLOOR
        self.margin = 0 if _host_test else MARGIN
        self.fds = {}
        self.lease_types = {}
        self.broken_lease = False
        self.backups = []
        self.last_foreign_scan = 0.0
        self.proof = {'status': 'VALIDATING', 'execute': execute, 'root': str(self.root),
                      'reserve_bytes': self.floor, 'actions': [], 'targets': [],
                      'bytes_preserved': False, 'installation_disks_modified': False,
                      'free_space_delta_is_global_and_can_include_other_actors': True}

    def path(self, rel):
        if not isinstance(rel, str) or not rel or '\\' in rel:
            raise RuntimeError('Invalid artifact-relative path')
        part = Path(rel)
        if part.is_absolute() or any(x in {'.', '..'} for x in rel.split('/')):
            raise RuntimeError('Noncanonical artifact path')
        p = self.root/part
        if p.resolve() != p or not p.is_relative_to(self.root):
            raise RuntimeError('Symlink or scope escape')
        prefixes = PROTECTED | set(self.plan.get('protected_current_inputs', [])) | set(self.approval.get('protected_prefixes', []))
        if part.parts[0].startswith(('kernel-', 'native-w64-', 'app-runtime-v25', 'app-runtime-v26', 'app-runtime-v27')):
            raise RuntimeError('Kernel, native VM or current runtime artifact is protected')
        if any(part == Path(x) or part.is_relative_to(Path(x)) for x in prefixes):
            raise RuntimeError('Protected input or source')
        if p.suffix.lower() in SOURCE_SUFFIXES or (p.suffix.lower() not in ALLOWED_SUFFIXES and rel not in FIXTURE_DLLS):
            raise RuntimeError('Only non-source artifact files are eligible')
        return p

    def free_bytes(self):
        s = os.statvfs(self.root)
        return s.f_bavail*s.f_frsize

    def checkpoint(self, modifying=False):
        if self.broken_lease:
            raise RuntimeError('An external process requested access: lease broken')
        if self.free_bytes() < self.floor + (self.margin if modifying else 0):
            raise RuntimeError('17 GiB reserve would be crossed')
        # Held kernel leases stop incompatible opens immediately and SIGIO is
        # checked before every mutation. A complete /proc scan is bounded to
        # once a second rather than repeated for every 4 KiB range.
        now = time.monotonic()
        if now-self.last_foreign_scan >= 1.0:
            foreign = active_files(self.root)
            self.last_foreign_scan = time.monotonic()
            if any(str(self.root/x) in foreign for x in self.fds):
                raise RuntimeError('Artifact now has a foreign descriptor or mapping')
        for rel, fd in self.fds.items():
            p = self.path(rel)
            current = p.stat()
            opened = os.fstat(fd)
            if (current.st_dev, current.st_ino, current.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise RuntimeError('Artifact identity changed')
            if self.execute and fcntl.fcntl(fd, fcntl.F_GETLEASE) != self.lease_types[rel]:
                raise RuntimeError('Artifact lease is no longer held')
        if self.broken_lease:
            raise RuntimeError('An external process requested access during checkpoint')

    def persist(self):
        (self.output/'receipt.json').write_text(json.dumps(self.proof, indent=2)+'\n')

    def validate(self):
        if self.plan.get('status') != 'READ_ONLY_SURVEY_COMPLETE_REQUIRES_ROOT_CANDIDATE_REVIEW' or self.plan.get('root') != str(self.root):
            raise RuntimeError('Wrong survey status or root')
        if self.approval.get('schema') != 1 or self.approval.get('root') != str(self.root):
            raise RuntimeError('Wrong root approval schema')
        targets = self.approval.get('targets')
        if not isinstance(targets, list) or not targets or len(set(targets)) != len(targets):
            raise RuntimeError('Explicit unique root-reviewed targets required')
        self.records = {x['path']: x for x in self.plan['files']}
        if len(self.records) != len(self.plan['files']):
            raise RuntimeError('Duplicate survey records')
        needed = set(targets)
        for rel in targets:
            self.path(rel)
            record = self.records[rel]
            if rel in FIXTURE_DLLS and any(x.get('kind') != 'zero' for x in record['ranges']):
                raise RuntimeError('The exact ended fixture DLLs permit verified zero holes only')
            for item in record['ranges']:
                off, count = item['offset'], item['bytes']
                if not isinstance(off, int) or not isinstance(count, int) or off < 0 or count <= 0 or off % BLOCK or count % BLOCK or off+count > record['logical_bytes']:
                    raise RuntimeError('Range is not a bounded whole filesystem block')
                if item['kind'] == 'duplicate':
                    src = item['source']; self.path(src); needed.add(src)
                    start = item['source_offset']
                    if not isinstance(start, int) or start < 0 or start % BLOCK or start+count > self.records[src]['logical_bytes']:
                        raise RuntimeError('Invalid duplicate source range')
                    if src == rel and start < off+count and off < start+count:
                        raise RuntimeError('Overlapping self-dedup ranges')
                elif item['kind'] != 'zero':
                    raise RuntimeError('Unknown compaction action')
        foreign = active_files(self.root)
        if any(str(self.path(x)) in foreign for x in needed):
            raise RuntimeError('Reviewed artifact is active')
        for rel in sorted(needed):
            p = self.path(rel)
            fd = os.open(p, (os.O_RDWR if self.execute and rel in targets else os.O_RDONLY) | os.O_NOFOLLOW)
            self.fds[rel] = fd
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or pin(s) != self.records[rel]['stat_pin']:
                raise RuntimeError('Artifact stat pin, type or link count changed')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB if self.execute and rel in targets else fcntl.LOCK_SH | fcntl.LOCK_NB)
            if digest_fd(fd) != self.records[rel]['sha256']:
                raise RuntimeError('Artifact SHA changed')
            if self.execute:
                lease = fcntl.F_WRLCK if rel in targets else fcntl.F_RDLCK
                fcntl.fcntl(fd, fcntl.F_SETLEASE, lease)
                self.lease_types[rel] = lease
        self.target_names = targets
        self.proof.update(validated_sources_sha256={x:self.records[x]['sha256'] for x in needed},
                          reviewed_targets=targets)
        self.checkpoint(modifying=self.execute)

    def backup(self, rel, index):
        directory = self.output/'backups'
        directory.mkdir(exist_ok=True, mode=0o700)
        p = directory/f'{index:04d}.reflink-backup'
        fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.ioctl(fd, FICLONE, self.fds[rel])
            if digest_fd(fd) != self.records[rel]['sha256']:
                raise RuntimeError('Backup SHA mismatch')
            self.backups.append((rel, p, fd, os.fstat(fd).st_ino))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def compact_target(self, rel, index):
        fd = self.fds[rel]; record = self.records[rel]
        self.checkpoint(modifying=True)
        before = os.fstat(fd)
        backup_fd = self.backup(rel, index)
        entry = {'path':rel, 'sha256_before':digest_fd(fd), 'stat_before':pin(before),
                 'allocated_before':before.st_blocks*512, 'backup_sha256':digest_fd(backup_fd)}
        self.proof['targets'].append(entry); self.persist()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
        libc.fallocate.restype = ctypes.c_int
        for item in record['ranges']:
            off, left = item['offset'], item['bytes']
            source_off = item.get('source_offset', 0)
            while left:
                self.checkpoint(modifying=True)
                count = min(left, 1024**2)
                data = os.pread(fd, count, off)
                if len(data) != count:
                    raise RuntimeError('Short target range read')
                action = {'target':rel, 'offset':off, 'bytes':count, 'kind':item['kind']}
                if item['kind'] == 'zero':
                    if data != bytes(count):
                        raise RuntimeError('Planned zero range contains nonzero bytes')
                    # A blocking pread can outlast a kernel lease-break timeout.
                    # Check again after the read, immediately before mutation.
                    self.checkpoint(modifying=True)
                    rc = libc.fallocate(fd, 3, off, count) # KEEP_SIZE | PUNCH_HOLE
                    if rc != 0:
                        raise OSError(ctypes.get_errno(), 'Zero hole punch failed')
                    action['syscall'] = 'fallocate(PUNCH_HOLE|KEEP_SIZE)'
                    completed = count
                else:
                    src = item['source']; source_fd = self.fds[src]
                    if os.pread(source_fd, count, source_off) != data:
                        raise RuntimeError('Planned duplicate bytes differ')
                    b = bytearray(56)
                    struct.pack_into('QQHHI', b, 0, source_off, count, 1, 0, 0)
                    struct.pack_into('qQQiI', b, 24, fd, off, 0, 0, 0)
                    self.checkpoint(modifying=True)
                    fcntl.ioctl(source_fd, FIDEDUPERANGE, b, True)
                    _, _, completed, status, _ = struct.unpack_from('qQQiI', b, 24)
                    action.update(syscall='FIDEDUPERANGE', source=src, source_offset=source_off,
                                  kernel_status=status, kernel_bytes_deduped=completed)
                    self.proof['actions'].append(action); self.persist()
                    if status != 0 or not completed or completed > count or completed % BLOCK:
                        raise RuntimeError('Kernel did not confirm the entire compared dedup slice')
                if item['kind'] == 'zero':
                    self.proof['actions'].append(action); self.persist()
                off += completed; source_off += completed; left -= completed
        os.fsync(fd)
        if digest_fd(fd) != record['sha256']:
            raise RuntimeError('Artifact bytes changed; owned backup preserved')
        entry.update(sha256_after=digest_fd(fd), stat_after=pin(os.fstat(fd)),
                     allocated_after=os.fstat(fd).st_blocks*512, bytes_preserved=True)
        self.checkpoint()
        # Only the temporary snapshot created by this invocation is removed,
        # after the target has passed full SHA verification while leased.
        _, p, snapshot, inode = self.backups[-1]
        if p.stat().st_ino != inode or os.fstat(snapshot).st_ino != inode:
            raise RuntimeError('Owned backup identity changed')
        os.close(snapshot); self.backups[-1] = (rel, p, -1, inode)
        p.unlink(); entry['verified_temporary_backup_removed'] = True
        self.persist()

    def run(self):
        if self.output.exists() or self.output.resolve() != self.output or not self.output.is_relative_to(self.root):
            raise RuntimeError('Fresh canonical owned output below scope required')
        self.output.mkdir(parents=False, mode=0o700)
        self.proof['free_bytes_before'] = self.free_bytes()
        previous = signal.getsignal(signal.SIGIO)
        signal.signal(signal.SIGIO, lambda *_: setattr(self, 'broken_lease', True))
        try:
            self.validate(); self.persist()
            if self.execute:
                for index, rel in enumerate(self.target_names):
                    self.compact_target(rel, index)
                for rel, fd in self.fds.items():
                    if digest_fd(fd) != self.records[rel]['sha256']:
                        raise RuntimeError('Source bytes changed after compaction')
                self.checkpoint()
            self.proof.update(status='PASS_BYTES_PRESERVED' if self.execute else 'VALIDATION_ONLY_PASS',
                              bytes_preserved=True)
        except BaseException as exc:
            self.proof.update(status='FAIL_STOPPED', error=f'{type(exc).__name__}: {exc}',
                              owned_backups_preserved=[str(p) for _,p,_,_ in self.backups if p.exists()])
            self.proof['actual_sha256_after_failure'] = {rel:digest_fd(fd) for rel,fd in self.fds.items()}
            raise
        finally:
            for _,_,fd,_ in self.backups:
                if fd >= 0: os.close(fd)
            for rel, fd in self.fds.items():
                if rel in self.lease_types:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                os.close(fd)
            signal.signal(signal.SIGIO, previous)
            self.proof.update(free_bytes_after=self.free_bytes())
            self.proof['global_free_bytes_delta'] = self.proof['free_bytes_after']-self.proof['free_bytes_before']
            self.persist()
        return self.proof


def checked_json(path, expected):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Plan or root approval receipt hash mismatch')
    return json.loads(data)


def self_test():
    # The production CLI has no arbitrary root override. Only newly created
    # host-temporary fixtures reach the injected test root below.
    checks = []
    after_read_evidence = []
    def fixture(directory):
        root = Path(directory).resolve()
        src = root/'old-runtime.img'; dst = root/'old-contract.img'
        nonzero = b'actual-data-contract'.ljust(BLOCK, b'X')
        src.write_bytes(nonzero*4)
        dst.write_bytes(nonzero*4+bytes(BLOCK*4))
        records=[]
        for p in (src,dst):
            records.append({'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                            'stat_pin':pin(p.stat()),'logical_bytes':p.stat().st_size,'ranges':[]})
        records[1]['ranges']=[{'kind':'duplicate','offset':0,'bytes':BLOCK*4,'source':src.name,'source_offset':0},
                               {'kind':'zero','offset':BLOCK*4,'bytes':BLOCK*4}]
        plan={'status':'READ_ONLY_SURVEY_COMPLETE_REQUIRES_ROOT_CANDIDATE_REVIEW','root':str(root),'files':records}
        approval={'schema':1,'root':str(root),'targets':[dst.name]}
        return root,plan,approval
    with tempfile.TemporaryDirectory(prefix='win98-artifact-compact-test-') as directory:
        root,plan,approval=fixture(directory)
        proof=Compactor(root,plan,approval,root/'validation',_host_test=True).run()
        assert proof['status']=='VALIDATION_ONLY_PASS' and not proof['actions']
        checks.append('readonly validation leaves exact source and destination bytes')
        proof=Compactor(root,plan,approval,root/'execution',True,_host_test=True).run()
        assert proof['status']=='PASS_BYTES_PRESERVED' and proof['bytes_preserved']
        assert len(proof['actions'])==2 and proof['actions'][0]['kernel_bytes_deduped']==BLOCK*4
        assert proof['targets'][0]['allocated_after']<proof['targets'][0]['allocated_before']
        assert not list((root/'execution/backups').iterdir())
        checks.append('real kernel dedup and real zero hole preserve full SHA and reclaim allocation')
    failures=['changed-sha','symlink','scope-escape','protected','nonzero-hole','different-duplicate',
              'foreign-open','reserve','overlap','hardlink','unsurveyed','range-overshoot','partial-failure','lease-break',
              'lease-break-after-target-read-zero','lease-break-after-target-read-duplicate',
              'lease-break-after-source-read-duplicate','unreviewed-dll','other-fixture-dll',
              'fixture-dll-escape','fixture-dll-not-in-approval','fixture-dll-dedup-rejected']
    for mode in failures:
        with tempfile.TemporaryDirectory(prefix='win98-artifact-compact-test-') as directory:
            root,plan,approval=fixture(directory); foreign=None
            if mode=='changed-sha':(root/'old-contract.img').write_bytes(b'changed')
            if mode=='symlink':
                (root/'old-contract.img').unlink();(root/'old-contract.img').symlink_to(root/'old-runtime.img')
            if mode=='scope-escape':approval['targets']=['../outside.img']
            if mode=='protected':approval['targets']=['steam.img']
            if mode=='nonzero-hole':plan['files'][1]['ranges'][0]={'kind':'zero','offset':0,'bytes':BLOCK}
            if mode=='different-duplicate':plan['files'][1]['ranges'][0]['offset']=BLOCK*4
            if mode=='overlap':plan['files'][1]['ranges'][0].update(source='old-contract.img',source_offset=0)
            if mode=='hardlink':os.link(root/'old-contract.img',root/'linked.img')
            if mode=='unsurveyed':approval['targets']=['unlisted.img']
            if mode=='range-overshoot':plan['files'][1]['ranges'][0]['bytes']=BLOCK*16
            if mode=='partial-failure':plan['files'][1]['ranges'][1]['offset']=0
            if mode in {'unreviewed-dll','other-fixture-dll','fixture-dll-escape'}:
                old='old-contract.img'
                name={'unreviewed-dll':'application.dll',
                      'other-fixture-dll':'disk-guest-v9/generated/lazy-dll/OTHER.DLL',
                      'fixture-dll-escape':'other-disk-guest/generated/lazy-dll/BIGLAZY.DLL'}[mode]
                dst=root/name;dst.parent.mkdir(parents=True,exist_ok=True)
                (root/old).rename(dst)
                plan['files'][1]['path']=name
                plan['files'][1]['stat_pin']=pin(dst.stat())
                approval['targets']=[name]
            if mode=='fixture-dll-not-in-approval':
                approval['targets']=['disk-guest-v9/generated/lazy-dll/BIGLAZY.DLL']
            if mode=='fixture-dll-dedup-rejected':
                name='disk-guest-v9/generated/lazy-dll/BIGLAZY.DLL'
                dst=root/name;dst.parent.mkdir(parents=True)
                (root/'old-contract.img').rename(dst)
                plan['files'][1].update(path=name,stat_pin=pin(dst.stat()))
                approval['targets']=[name]
            actor=Compactor(root,plan,approval,root/'failure',True,_host_test=True)
            launched=[]
            original_pread=os.pread
            original_ioctl=fcntl.ioctl
            original_cdll=ctypes.CDLL
            mutation_calls=[]
            if mode=='reserve':actor.floor=2**64-1
            if mode=='foreign-open':
                import subprocess
                foreign=subprocess.Popen(['python3','-c','import sys; f=open(sys.argv[1],"rb"); print("ready",flush=True); sys.stdin.read()',str(root/'old-contract.img')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
                assert foreign.stdout.readline().strip()=='ready'
            if mode=='lease-break':
                import subprocess
                original_checkpoint=actor.checkpoint
                def break_lease(modifying=False):
                    original_checkpoint(modifying)
                    if modifying and actor.fds and not launched:
                        child=subprocess.Popen(['python3','-c','import sys; print("opening",flush=True); f=open(sys.argv[1],"rb"); print("opened",flush=True)',str(root/'old-contract.img')],stdout=subprocess.PIPE,text=True)
                        launched.append(child)
                        assert child.stdout.readline().strip()=='opening'
                        deadline=time.monotonic()+5
                        while not actor.broken_lease and time.monotonic()<deadline:time.sleep(0.01)
                        assert actor.broken_lease,'Kernel failed to deliver lease-break signal'
                        # Exercise the production checkpoint after the actual
                        # signal; the test itself must not manufacture refusal.
                        original_checkpoint(modifying)
                actor.checkpoint=break_lease
            after_read=mode.startswith('lease-break-after-')
            if after_read:
                import subprocess
                if mode.endswith('-zero'):
                    plan['files'][1]['ranges']=plan['files'][1]['ranges'][1:]
                def read_then_break(fd,count,off):
                    data=original_pread(fd,count,off)
                    target=actor.fds.get('old-contract.img')
                    source=actor.fds.get('old-runtime.img')
                    expected_fd=source if '-source-read-' in mode else target
                    expected_off=BLOCK*4 if mode.endswith('-zero') else 0
                    if actor.backups and actor.proof['targets'] and fd==expected_fd and count==BLOCK*4 and off==expected_off and not launched:
                        child=subprocess.Popen(['python3','-c','import sys; print("opening",flush=True); f=open(sys.argv[1],"rb"); print("opened",flush=True)',str(root/'old-contract.img')],stdout=subprocess.PIPE,text=True)
                        launched.append(child)
                        assert child.stdout.readline().strip()=='opening'
                        deadline=time.monotonic()+5
                        while not actor.broken_lease and time.monotonic()<deadline:time.sleep(0.01)
                        assert actor.broken_lease,'Kernel failed to signal after actual range read'
                    return data
                def counted_ioctl(fd,request,*args):
                    if request==FIDEDUPERANGE:mutation_calls.append('FIDEDUPERANGE')
                    return original_ioctl(fd,request,*args)
                class CountedFallocate:
                    def __init__(self,fn):self.fn=fn
                    def __call__(self,*args):
                        mutation_calls.append('fallocate')
                        return self.fn(*args)
                class CountedLibc:
                    def __init__(self,*args,**kwargs):
                        self.real=original_cdll(*args,**kwargs)
                        fn=self.real.fallocate
                        fn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_longlong,ctypes.c_longlong]
                        fn.restype=ctypes.c_int
                        self.fallocate=CountedFallocate(fn)
                # These spies forward every call to the real kernel. They do
                # not suppress a mutation or manufacture production refusal.
                os.pread=read_then_break
                fcntl.ioctl=counted_ioctl
                ctypes.CDLL=CountedLibc
            hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.img')}
            try:
                try:actor.run()
                except (RuntimeError,KeyError,OSError):pass
                else:raise AssertionError('Negative accepted: '+mode)
                assert hashes=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.img')},mode
                if mode=='partial-failure':
                    assert len(actor.proof['actions'])==1 and actor.proof['owned_backups_preserved']
                    assert actor.proof['actual_sha256_after_failure']['old-contract.img']==plan['files'][1]['sha256']
                if after_read:
                    assert launched and not mutation_calls and not actor.proof['actions'],mode
                    assert actor.proof['owned_backups_preserved'],mode
                    assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==plan['files'][1]['sha256']
                               for p in actor.proof['owned_backups_preserved']),mode
                    after_read_evidence.append({'case':mode,'actual_sigio_received':actor.broken_lease,
                                                'kernel_mutation_calls':list(mutation_calls),
                                                'owned_backup_count':len(actor.proof['owned_backups_preserved'])})
                checks.append(mode+' rejected without changing artifact bytes')
            finally:
                os.pread=original_pread
                fcntl.ioctl=original_ioctl
                ctypes.CDLL=original_cdll
                if foreign:foreign.stdin.close();foreign.wait(timeout=10)
                if mode=='lease-break' or after_read:
                    for child in launched:assert child.wait(timeout=10)==0
    for name in sorted(FIXTURE_DLLS):
        with tempfile.TemporaryDirectory(prefix='win98-artifact-compact-test-') as directory:
            root,plan,approval=fixture(directory)
            dst=root/name;dst.parent.mkdir(parents=True)
            (root/'old-contract.img').rename(dst)
            plan['files'][1].update(path=name,stat_pin=pin(dst.stat()))
            plan['files'][1]['ranges']=plan['files'][1]['ranges'][1:]
            approval['targets']=[name]
            before=hashlib.sha256(dst.read_bytes()).hexdigest()
            proof=Compactor(root,plan,approval,root/'fixture-execution',True,_host_test=True).run()
            assert proof['status']=='PASS_BYTES_PRESERVED' and len(proof['actions'])==1
            assert proof['actions'][0]['kind']=='zero' and before==hashlib.sha256(dst.read_bytes()).hexdigest()
            checks.append('exact ended fixture '+name+' zero hole preserves SHA')
    return {'status':'PASS','host_temp_only':True,'private_artifacts_mutated':False,'checks':checks,
            'actual_post_read_lease_break_evidence':after_read_evidence}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',type=Path);p.add_argument('--plan-sha256')
    p.add_argument('--approved-targets',type=Path);p.add_argument('--approved-targets-sha256')
    p.add_argument('--output',type=Path);p.add_argument('--execute',action='store_true')
    p.add_argument('--self-test',action='store_true')
    a=p.parse_args()
    if a.self_test:
        if a.execute or a.plan or a.approved_targets or a.output:p.error('--self-test uses fresh host temporary fixtures only')
        before=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result=self_test()
        after=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if before!=after:raise RuntimeError('Self-test source changed during execution')
        result.update(utility_source_sha256_before=before,utility_source_sha256_after=after)
        print(json.dumps(result,indent=2));return
    if not all((a.plan,a.plan_sha256,a.approved_targets,a.approved_targets_sha256,a.output)):
        p.error('Pinned survey, pinned root-reviewed target list and fresh output are required')
    plan=checked_json(a.plan,a.plan_sha256);approval=checked_json(a.approved_targets,a.approved_targets_sha256)
    if not a.output.is_absolute() or a.output.resolve()!=a.output:
        p.error('An absolute canonical output path without symlink aliases is required')
    actor=Compactor(PRIVATE,plan,approval,a.output,a.execute)
    actor.proof.update(plan_sha256=a.plan_sha256,root_approval_sha256=a.approved_targets_sha256,
                       utility_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    print(json.dumps(actor.run(),indent=2))


if __name__=='__main__':main()
