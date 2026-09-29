#!/usr/bin/env python3
"""Actual COM instruction tests under a synthetic, bounded Unicorn V86 model."""
from __future__ import annotations
import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
import random
import sys
import time

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR
from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
    UC_X86_REG_DX, UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_SP,
    UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_EFLAGS)

import build

CHECKS = 0
SCENARIOS = 0


def check(condition: bool, detail: str = '') -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(detail)


@dataclasses.dataclass
class Scenario:
    data: bytes | None = None
    entry_segment: int = 0x6000
    entry_offset: int = 0x0100
    create_error: int = 0
    open_error: int = 0
    read_error: int = 0
    eof_error: int = 0
    read_count: int | None = None
    file_close_error: int = 0
    log_close_error: int = 0
    fail_write: int = -1
    short_write: int = -1
    short_count: int = 0
    version_ax: int = 0
    version_dx: int = 0x0100
    version_cf: int = 0
    load_ax: int = 0
    load_dx: int = 0xcafe
    load_cf: int = 0
    unload_ax: int = 0
    unload_dx: int = 0xbabe
    unload_cf: int = 0
    existing_log: bytes | None = None
    clobber: bool = True
    seed: int = 1


class Model:
    """Scripted external interfaces; the COM itself executes on Unicorn's CPU."""
    SEG = 0x2000
    BASE = SEG << 4
    LOG = b'C:\\NTWLAB\\NTWLDR.LOG'
    DRIVER = b'C:\\NTWLAB\\NTWRAP9X.VXD'
    NAME = b'NTWRAP9X'

    def __init__(self, code: bytes, candidate: bytes, scenario: Scenario):
        self.s = scenario
        self.code, self.candidate = code, candidate
        self.data = candidate if scenario.data is None else scenario.data
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x100000)
        self.uc.mem_write(self.BASE + 0x100, code)
        # Actual FAR CALL pushes a return address. INT FE injects only the
        # external response, then the real RETF instruction returns to the COM.
        self.entry = (scenario.entry_segment << 4) + scenario.entry_offset
        if scenario.entry_segment:
            self.uc.mem_write(self.entry, b'\xcd\xfe\xcb')
        for reg in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.uc.reg_write(reg, self.SEG)
        self.uc.reg_write(UC_X86_REG_SP, 0xfffe)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0602)  # start with DF set
        self.uc.reg_write(UC_X86_REG_EAX, 0xaaaa0000)
        self.uc.reg_write(UC_X86_REG_EDX, 0xbbbb0000)
        self.uc.hook_add(UC_HOOK_INTR, self.interrupt)
        self.log = bytearray(scenario.existing_log or b'')
        self.writes: list[bytes] = []
        self.calls: list[int] = []
        self.events: list[str] = []
        self.handles: set[int] = set()
        self.position = 0
        self.reads = 0
        self.exit: int | None = None
        self.failed_write = False
        self.random = random.Random(scenario.seed)

    def r(self, reg: int) -> int:
        return self.uc.reg_read(reg)

    def w(self, reg: int, value: int) -> None:
        self.uc.reg_write(reg, value)

    def flag(self, carry: bool) -> None:
        self.w(UC_X86_REG_EFLAGS, (self.r(UC_X86_REG_EFLAGS) & ~1) | int(carry))

    def string(self) -> bytes:
        address = (self.r(UC_X86_REG_DS) << 4) + self.r(UC_X86_REG_DX)
        data = bytes(self.uc.mem_read(address, 64))
        check(b'\0' in data, 'bounded ASCIIZ pointer')
        return data.split(b'\0', 1)[0]

    def dos_result(self, ax: int, error: bool = False) -> None:
        self.w(UC_X86_REG_AX, ax)
        self.flag(error)

    def external_result(self, ax: int, dx: int, cf: int) -> None:
        if self.s.clobber:
            for reg in (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_ESI,
                        UC_X86_REG_EDI, UC_X86_REG_EBP):
                self.w(reg, self.random.getrandbits(32))
            self.w(UC_X86_REG_DS, 0x5000)
            self.w(UC_X86_REG_ES, 0x5100)
        self.w(UC_X86_REG_EAX, 0xface0000 | ax)
        self.w(UC_X86_REG_EDX, 0xabcd0000 | dx)
        # Flags include DF and unrelated status bits, detecting premature CLD
        # or arithmetic before PUSHF. No trap flag or privileged mode changes.
        self.w(UC_X86_REG_EFLAGS, 0x0e96 | cf)

    def interrupt(self, _uc: Uc, number: int, _user: object) -> None:
        if number == 0x2f:
            check(self.r(UC_X86_REG_AX) == 0x1684 and self.r(UC_X86_REG_BX) == 0x27)
            check(self.r(UC_X86_REG_ES) == 0 and self.r(UC_X86_REG_DI) == 0)
            check(not self.calls and 'entry' not in self.events)
            self.events.append('entry')
            self.external_result(0xdada, 0xbeef, 1)
            self.w(UC_X86_REG_ES, self.s.entry_segment)
            self.w(UC_X86_REG_DI, self.s.entry_offset)
            return
        if number == 0xfe:
            self.loader()
            return
        check(number == 0x21, f'unexpected interrupt {number:x}')
        check(self.r(UC_X86_REG_DS) == self.SEG, 'DOS DS restoration')
        check(not self.r(UC_X86_REG_EFLAGS) & 0x400, 'DOS DF restoration')
        ah = self.r(UC_X86_REG_AX) >> 8
        self.events.append(f'dos:{ah:02x}')
        if ah == 0x5b:
            check(self.string() == self.LOG and self.r(UC_X86_REG_CX) == 0)
            check(not self.handles)
            error = self.s.create_error or (80 if self.s.existing_log is not None else 0)
            if error:
                self.dos_result(error, True)
            else:
                self.handles.add(5)
                self.dos_result(5)
        elif ah == 0x40:
            check(self.r(UC_X86_REG_BX) == 5 and 5 in self.handles)
            check(not self.failed_write, 'retry after failed log write')
            size = self.r(UC_X86_REG_CX)
            check(0 < size <= 100, 'bounded nonempty log write')
            data = bytes(self.uc.mem_read(self.BASE + self.r(UC_X86_REG_DX), size))
            index = len(self.writes)
            self.writes.append(data)
            if index == self.s.fail_write:
                self.failed_write = True
                self.dos_result(5, True)
            elif index == self.s.short_write:
                check(0 <= self.s.short_count < size)
                self.log.extend(data[:self.s.short_count])
                self.failed_write = True
                self.dos_result(self.s.short_count)
            else:
                self.log.extend(data)
                self.dos_result(size)
        elif ah == 0x3d:
            check(self.string() == self.DRIVER and self.r(UC_X86_REG_AX) == 0x3d00)
            check(self.calls == [0], 'version before ordinary file access')
            if self.s.open_error:
                self.dos_result(self.s.open_error, True)
            else:
                self.handles.add(6)
                self.dos_result(6)
        elif ah == 0x3f:
            check(self.r(UC_X86_REG_BX) == 6 and 6 in self.handles)
            count = self.r(UC_X86_REG_CX)
            check(count == (9390 if self.reads == 0 else 1))
            check(self.reads < 2)
            self.reads += 1
            error = self.s.read_error if self.reads == 1 else self.s.eof_error
            if error:
                self.dos_result(error, True)
                return
            size = min(count, len(self.data) - self.position)
            if self.reads == 1 and self.s.read_count is not None:
                size = min(size, self.s.read_count)
            self.uc.mem_write(self.BASE + self.r(UC_X86_REG_DX),
                              self.data[self.position:self.position + size])
            self.position += size
            self.dos_result(size)
        elif ah == 0x3e:
            handle = self.r(UC_X86_REG_BX)
            check(handle in self.handles and handle in (5, 6), 'close owned handle once')
            error = self.s.log_close_error if handle == 5 else self.s.file_close_error
            if error:
                self.dos_result(error, True)
            else:
                self.handles.remove(handle)
                self.dos_result(0)
        elif ah == 0x4c:
            self.exit = self.r(UC_X86_REG_AX) & 255
            self.uc.emu_stop()
        else:
            raise AssertionError(f'unexpected DOS API {ah:02x}')

    def loader(self) -> None:
        check(self.r(UC_X86_REG_CS) == self.s.entry_segment, 'saved far entry used')
        check(self.r(UC_X86_REG_DS) == self.SEG)
        check(not self.r(UC_X86_REG_EFLAGS) & 0x400)
        operation = self.r(UC_X86_REG_EAX)
        check(operation in (0, 1, 2), 'full EAX initialized')
        check(self.r(UC_X86_REG_ECX) == 0)
        self.calls.append(operation)
        if operation == 0:
            check(self.calls == [0])
            check(self.r(UC_X86_REG_EBX) == 0 and self.r(UC_X86_REG_EDX) == 0)
            self.external_result(self.s.version_ax, self.s.version_dx, self.s.version_cf)
        elif operation == 1:
            check(self.calls == [0, 1])
            check(self.string() == self.DRIVER and self.r(UC_X86_REG_EBX) == 0)
            check(self.r(UC_X86_REG_EDX) < 65536)
            check(self.reads == 2 and self.position == 9390 and 6 not in self.handles)
            check(self.data == self.candidate)
            check(b'PREFLIGHT=EXACT_9390_BYTES_AND_EOF\r\n' in self.log)
            self.external_result(self.s.load_ax, self.s.load_dx, self.s.load_cf)
            # This VxD has no V86 target API. Unload must keep the saved VXDLDR
            # entry, not follow the returned null target ES:DI.
            self.w(UC_X86_REG_ES, 0)
            self.w(UC_X86_REG_DI, 0)
        else:
            check(self.calls == [0, 1, 2])
            check(self.s.load_cf == 0 and self.s.load_ax == 0, 'no unload without ownership')
            check(self.string() == self.NAME)
            check(self.r(UC_X86_REG_EBX) == 0xffff and self.r(UC_X86_REG_EDX) < 65536)
            self.external_result(self.s.unload_ax, self.s.unload_dx, self.s.unload_cf)

    def run(self) -> 'Model':
        global SCENARIOS
        SCENARIOS += 1
        self.uc.emu_start(self.BASE + 0x100, self.BASE + 0x100 + len(self.code),
                          timeout=2_000_000, count=100_000)
        check(self.exit is not None, 'bounded COM reached DOS exit')
        check(len(self.calls) <= 3 and len(self.log) < 2048)
        check(self.calls.count(0) <= 1 and self.calls.count(1) <= 1 and self.calls.count(2) <= 1)
        if not self.s.log_close_error:
            check(5 not in self.handles, 'log handle cleanup')
        if not self.s.file_close_error:
            check(6 not in self.handles, 'read handle cleanup')
        return self


def suite(code: bytes, candidate: bytes) -> dict:
    def run(**kw: object) -> Model:
        return Model(code, candidate, Scenario(**kw)).run()

    success = run()
    check(success.exit == 0 and success.calls == [0, 1, 2])
    expected = (
        'NTWLDR FORMAT=1\r\nEVIDENCE=GUEST_REPORTED_ONLY\r\n'
        f'EXPECTED_SHA256={build.CANDIDATE_SHA}\r\n'
        'ENTRY    FLAGS=0E97 AX=DADA DX=BEEF\r\n'
        'ENTRY SEG=6000 OFF=0100\r\n'
        'VERSION  FLAGS=0E96 AX=0000 DX=0100\r\n')
    check(success.log.startswith(expected.encode('ascii')), repr(bytes(success.log)))
    check(b'LOAD     FLAGS=0E96 AX=0000 DX=CAFE\r\n' in success.log)
    check(b'UNLOAD   FLAGS=0E96 AX=0000 DX=BABE\r\n' in success.log)
    check(success.log.endswith(b'RESULT_CODE=0000\r\nEND=BEFORE_LOG_CLOSE\r\n'))
    check(success.events.count('dos:3e') == 2)
    for seed in range(2, 18):
        m = run(seed=seed)
        check(m.log == success.log and m.exit == 0)
    m = run(clobber=False)
    check(m.log == success.log and m.exit == 0)
    for ax, dx, cf in ((0x1234, 0x4567, 0), (11, 0xffff, 1), (0, 0, 0)):
        m = run(version_ax=ax, version_dx=dx, version_cf=cf)
        check(m.exit == 0 and m.calls == [0, 1, 2], 'version is informational')
        check(f'VERSION  FLAGS={0xe96|cf:04X} AX={ax:04X} DX={dx:04X}\r\n'.encode() in m.log)
    for offset in (0, 0x0100, 0xffff):
        m = run(entry_segment=0, entry_offset=offset)
        check(m.exit == 3 and not m.calls)
    for error in (2, 5, 80, 0xffff):
        m = run(create_error=error)
        check(m.exit == 1 and not m.calls and not m.log)
    m = run(existing_log=b'prior evidence\r\n')
    check(m.exit == 1 and m.log == b'prior evidence\r\n' and not m.calls)
    for error in (2, 5, 0xffff):
        for field in ('open_error', 'read_error', 'eof_error', 'file_close_error'):
            m = run(**{field: error})
            check(m.exit == 4 and m.calls == [0], field)
    for size in (0, 1, 356, 4096, 9389):
        m = run(read_count=size)
        check(m.exit == 4 and m.calls == [0])
    for data in (b'', candidate[:-1], candidate + b'x', candidate + bytes(1024)):
        m = run(data=data)
        check(m.exit == 4 and m.calls == [0])
    offsets = sorted({0, 1, 0x164, 4095, 4096, 8191, 8192, 9389} |
                     set(random.Random(19).sample(range(9390), 64)))
    for offset in offsets:
        changed = bytearray(candidate)
        changed[offset] ^= 0x20
        m = run(data=bytes(changed))
        check(m.exit == 4 and m.calls == [0], f'byte mutation {offset}')
    # Every documented native error, plus unknown full 16-bit values and
    # inconsistent CF/AX pairs, must remain raw and never establish ownership.
    for error in (*range(1, 12), 0x1234, 0xffff):
        for carry in (0, 1):
            m = run(load_ax=error, load_cf=carry)
            check(m.exit == 5 and m.calls == [0, 1])
            check(f'LOAD     FLAGS={0xe96|carry:04X} AX={error:04X} DX=CAFE\r\n'.encode() in m.log)
            m = run(unload_ax=error, unload_cf=carry)
            check(m.exit == 6 and m.calls == [0, 1, 2])
            check(f'UNLOAD   FLAGS={0xe96|carry:04X} AX={error:04X} DX=BABE\r\n'.encode() in m.log)
    m = run(load_cf=1)
    check(m.exit == 5 and m.calls == [0, 1])
    m = run(unload_cf=1)
    check(m.exit == 6 and m.calls == [0, 1, 2])
    # Every write position and every possible short byte count. In particular,
    # a failed LOAD result write still triggers the real unload call sequence.
    load_index = next(i for i, data in enumerate(success.writes) if data.startswith(b'LOAD '))
    for index, data in enumerate(success.writes):
        for count in range(-1, len(data)):
            kw = {'fail_write': index} if count == -1 else {'short_write': index, 'short_count': count}
            m = run(**kw)
            check(m.exit == 0xe0)
            if index >= load_index:
                check(m.calls == [0, 1, 2], f'cleanup despite logging failure at {index}')
            else:
                check(1 not in m.calls, f'failed pre-load log at {index}')
    for error in (5, 6, 0xffff):
        m = run(log_close_error=error)
        check(m.exit == 0xe1 and m.calls == [0, 1, 2])
        check(m.log.endswith(b'RESULT_CODE=0000\r\nEND=BEFORE_LOG_CLOSE\r\n'), 'final-close gap explicit')
        m = run(fail_write=load_index, log_close_error=error)
        check(m.exit == 0xe1 and m.calls == [0, 1, 2])
    # Combined primary errors and cleanup faults never erase ownership rules.
    for load_error in (0, 5, 6, 7):
        for write_error in (load_index, load_index + 1):
            m = run(load_ax=load_error, load_cf=int(load_error != 0), fail_write=write_error)
            check(m.exit != 0)
            check((2 in m.calls) == (load_error == 0))
    return {'checks': CHECKS, 'scenarios': SCENARIOS, 'candidate_mutations': len(offsets),
            'write_fault_positions': len(success.writes),
            'success_log_bytes': len(success.log),
            'synthetic_success_log': bytes(success.log).decode('ascii')}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=build.DEFAULT_BUILD)
    parser.add_argument('--tool-provenance', required=True, type=Path)
    args = parser.parse_args()
    if unicorn.__version__ != '2.1.4':
        raise ValueError('this receipt requires the pinned Unicorn 2.1.4 tool')
    provenance_bytes = args.tool_provenance.read_bytes()
    provenance = json.loads(provenance_bytes)
    check(provenance['version'] == '2.1.4' and provenance['size'] == 16436886)
    check(provenance['sha256'] == '9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239')
    check(Path(unicorn.__file__).resolve().is_relative_to(Path(provenance['private_target']).resolve()))
    # Verify the wheel bytes again, and bind every extracted package file to
    # its original wheel entry before accepting external CPU tooling evidence.
    import zipfile
    wheel = args.tool_provenance.parent / 'unicorn.whl'
    check(build.digest(wheel.read_bytes()) == provenance['sha256'])
    with zipfile.ZipFile(wheel) as package:
        for member in package.infolist():
            if member.is_dir():
                continue
            p = Path(provenance['private_target']) / member.filename
            check(p.read_bytes() == package.read(member), f'changed tool file {member.filename}')
    receipt = build.build(args.output)
    # Bind precisely the bytes executed, not a later pathname read or a claim
    # copied from an earlier build. Refuse replacement during the test as well.
    receipt_bytes = (args.output / 'build-result.json').read_bytes()
    check(json.loads(receipt_bytes) == receipt)
    initial_sources = build.source_map()
    check(initial_sources == receipt['sources'])
    code = (args.output / 'NTWLDR.COM').read_bytes()
    candidate = build.CANDIDATE.read_bytes()
    baseline = build.BASELINE.read_bytes()
    check(build.digest(code) == receipt['artifact']['sha256'])
    check(len(code) == receipt['artifact']['size'])
    check(build.digest(candidate) == build.CANDIDATE_SHA)
    check(build.digest(baseline) == build.BASELINE_SHA)
    started = time.monotonic()
    stats = suite(code, candidate)
    elapsed = time.monotonic() - started
    check(build.source_map() == initial_sources)
    check((args.output / 'NTWLDR.COM').read_bytes() == code)
    check((args.output / 'build-result.json').read_bytes() == receipt_bytes)
    check(build.CANDIDATE.read_bytes() == candidate)
    check(build.BASELINE.read_bytes() == baseline)
    check(args.tool_provenance.read_bytes() == provenance_bytes)
    stats['checks'] = CHECKS
    log = stats.pop('synthetic_success_log')
    (args.output / 'synthetic-success.log').write_bytes(log.encode('ascii'))
    (args.output / 'tool-provenance.json').write_bytes(provenance_bytes)
    result = {'schema': 1, 'kind': 'original-v86diag-host-cpu-test',
              'passed': True, 'native_execution_verified': False,
              'fixture': 'synthetic DOS and VXDLDR callbacks; actual generated COM instructions',
              'sources': initial_sources, 'artifact': receipt['artifact'],
              'build_receipt_sha256': build.digest(receipt_bytes),
              'tool_provenance_sha256': build.digest(provenance_bytes),
              'synthetic_log_sha256': build.digest(log.encode('ascii')),
              'unicorn': unicorn.__version__, 'elapsed_seconds': elapsed,
              'stats': stats}
    (args.output / 'test-result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
