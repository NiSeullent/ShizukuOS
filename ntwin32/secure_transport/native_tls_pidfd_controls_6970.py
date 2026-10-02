# SPDX-License-Identifier: GPL-2.0-only
"""Explicit hosted parent-first pidfd controls; importing runs no control.

The verified-buffer builder calls run_controls directly.  Four preparation
commands belong to the parent Guard; each of five process cases owns a fresh
child Guard and separately closed epoch.  The ELF/object are host fixtures,
never a Windows artifact or an authorized binary transfer.  Only generated
assembly/map and closed child receipt/capture text appear in proof_files.

The handwritten assembly uses Linux x86_64 syscall ABI constants, modelled on
Linux v6.8 uapi sched.h and arch/x86/entry/syscalls/syscall_64.tbl.  These are
source-model references, not an attestation of the hosted kernel version.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import time
import types

CONTROL_NAMES = (
    "positive-vfork-parent-first",
    "positive-nested-vfork-parent-first",
    "negative-vfork-preexec-timeout",
    "negative-ancestry-cycle",
    "negative-pidfd-token-change",
)
CONTROL_EXPECTATIONS = {
    CONTROL_NAMES[0]: {"child_epoch": "PASS_CONTROL_CHILD", "command_count": 1,
                       "injected_fault": False, "stop_request_expected": True,
                       "reason": None},
    CONTROL_NAMES[1]: {"child_epoch": "PASS_CONTROL_CHILD", "command_count": 1,
                       "injected_fault": False, "stop_request_expected": True,
                       "reason": None},
    CONTROL_NAMES[2]: {"child_epoch": "FAIL", "command_count": 1,
                       "injected_fault": False, "stop_request_expected": True,
                       "reason": "owned group stop confirmation exceeded one second"},
    CONTROL_NAMES[3]: {"child_epoch": "FAIL", "command_count": 1,
                       "injected_fault": True, "stop_request_expected": False,
                       "reason": "owned group ancestry cycle refused"},
    CONTROL_NAMES[4]: {"child_epoch": "FAIL", "command_count": 1,
                       "injected_fault": True, "stop_request_expected": False,
                       "reason": "owned pidfd process identity changed"},
}
FIXTURE_BYTES_LIMIT = 8 * 1024**2
CASE_SECONDS = 5.0
TOTAL_SECONDS = 60.0
PAYLOAD_LIMIT = 4096
SOURCE_BYTES_LIMIT = 8192
OBJECT_BYTES_LIMIT = 2 * 1024**2
MAP_BYTES_LIMIT = 256 * 1024
SOURCE_PIN_LIMIT = 200 * 1024
TOOL_PIN_LIMIT = 256 * 1024**2
PREP_LABELS = ("pidfd-as-version", "pidfd-ld-version",
               "pidfd-fixture-as", "pidfd-fixture-ld")
CASE_SCHEMA = "native-tls-pidfd-control-child-6970-v1"
REPORT_SCHEMA = "native-tls-pidfd-vfork-controls-6970-v1"

# No includes, incbin, response files, libc, shell, process-group changes or
# external executable.  clone(flags=0x4111, stack=top, 0,0,0) has a private
# 64-KiB stack although VM is shared; only raw syscalls run before self-exec.
# The initial argv[0] is the exact absolute pinned ELF supplied by this helper.
ASSEMBLY = r''' .section .text
.globl _start
.type _start,@function
_start:
    cmpq $2,(%rsp)
    jne .Lfail
    movq 8(%rsp),%r12
    movq 16(%rsp),%rbx
    movq %rbx,%rdi
    leaq .Lleaf_name(%rip),%rsi
    call .Lequal
    testl %eax,%eax
    jnz .Lleaf
    movq %rbx,%rdi
    leaq .Ldirect_name(%rip),%rsi
    call .Lequal
    testl %eax,%eax
    jnz .Ldirect
    movq %rbx,%rdi
    leaq .Lstuck_name(%rip),%rsi
    call .Lequal
    testl %eax,%eax
    jnz .Lstuck
    movq %rbx,%rdi
    leaq .Lnested_name(%rip),%rsi
    call .Lequal
    testl %eax,%eax
    jz .Lfail
    movl $57,%eax
    syscall
    testq %rax,%rax
    js .Lfail
    jz .Lworker
    movq %rax,%r14
    call .Lwait
    leaq .Lnested_ok(%rip),%rsi
    movl $.Lnested_ok_end-.Lnested_ok,%edx
    call .Lwrite
    jmp .Lexit_ok
.Lworker:
    xorl %r15d,%r15d
    call .Lclone
    leaq .Lworker_ok(%rip),%rsi
    movl $.Lworker_ok_end-.Lworker_ok,%edx
    call .Lwrite
    jmp .Lexit_ok
.Ldirect:
    xorl %r15d,%r15d
    jmp .Lparent
.Lstuck:
    movl $1,%r15d
.Lparent:
    call .Lclone
    leaq .Ldirect_ok(%rip),%rsi
    movl $.Ldirect_ok_end-.Ldirect_ok,%edx
    call .Lwrite
    jmp .Lexit_ok
.Lclone:
    movl $56,%eax
    movl $0x4111,%edi
    leaq ntw6970_child_stack_end(%rip),%rsi
    xorl %edx,%edx
    xorl %r10d,%r10d
    xorl %r8d,%r8d
    syscall
    testq %rax,%rax
    js .Lfail
    jz .Lchild
    movq %rax,%r14
    call .Lwait
    ret
.Lchild:
    subq $64,%rsp
    leaq .Lready(%rip),%rsi
    movl $.Lready_end-.Lready,%edx
    call .Lwrite
    xorl %eax,%eax
    movq %rax,0(%rsp)
    movq $200000000,8(%rsp)
    testl %r15d,%r15d
    jz .Lsleep
    movq $2,0(%rsp)
    movq %rax,8(%rsp)
.Lsleep:
    movl $35,%eax
    movq %rsp,%rdi
    leaq 16(%rsp),%rsi
    syscall
    testq %rax,%rax
    jz .Lexec
    cmpq $-4,%rax
    jne .Lfail
    movq 16(%rsp),%rax
    movq %rax,0(%rsp)
    movq 24(%rsp),%rax
    movq %rax,8(%rsp)
    jmp .Lsleep
.Lexec:
    movq %r12,32(%rsp)
    leaq .Lleaf_name(%rip),%rax
    movq %rax,40(%rsp)
    movq $0,48(%rsp)
    movq $0,56(%rsp)
    movq %r12,%rdi
    leaq 32(%rsp),%rsi
    leaq 56(%rsp),%rdx
    movl $59,%eax
    syscall
    jmp .Lfail
.Lwait:
    subq $16,%rsp
.Lwait_again:
    movq %r14,%rdi
    movq %rsp,%rsi
    xorl %edx,%edx
    xorl %r10d,%r10d
    movl $61,%eax
    syscall
    cmpq $-4,%rax
    je .Lwait_again
    cmpq %r14,%rax
    jne .Lfail
    cmpl $0,(%rsp)
    jne .Lfail
    addq $16,%rsp
    ret
.Lleaf:
    leaq .Lleaf_ok(%rip),%rsi
    movl $.Lleaf_ok_end-.Lleaf_ok,%edx
    call .Lwrite
.Lexit_ok:
    xorl %edi,%edi
    movl $60,%eax
    syscall
    ud2
.Lwrite:
    movl $1,%edi
    movl $1,%eax
    syscall
    cmpq %rdx,%rax
    jne .Lfail
    ret
.Lequal:
    movb (%rdi),%al
    cmpb (%rsi),%al
    jne .Lnot_equal
    incq %rdi
    incq %rsi
    testb %al,%al
    jnz .Lequal
    movl $1,%eax
    ret
.Lnot_equal:
    xorl %eax,%eax
    ret
.Lfail:
    movl $2,%edi
    leaq .Lerror(%rip),%rsi
    movl $.Lerror_end-.Lerror,%edx
    movl $1,%eax
    syscall
    movl $111,%edi
    movl $60,%eax
    syscall
    ud2
.size _start,.-_start
.section .rodata
.Lleaf_name: .asciz "--leaf"
.Ldirect_name: .asciz "direct"
.Lstuck_name: .asciz "stuck"
.Lnested_name: .asciz "nested"
.Lready: .ascii "VFORK_READY\n"
.Lready_end:
.Lleaf_ok: .ascii "LEAF_OK\n"
.Lleaf_ok_end:
.Ldirect_ok: .ascii "DIRECT_OK\n"
.Ldirect_ok_end:
.Lworker_ok: .ascii "WORKER_OK\n"
.Lworker_ok_end:
.Lnested_ok: .ascii "NESTED_OK\n"
.Lnested_ok_end:
.Lerror: .ascii "FIXTURE_FAIL\n"
.Lerror_end:
.section .bss
.balign 16
.globl ntw6970_child_stack
.type ntw6970_child_stack,@object
ntw6970_child_stack:
    .skip 65536
.size ntw6970_child_stack,65536
.globl ntw6970_child_stack_end
.type ntw6970_child_stack_end,@object
ntw6970_child_stack_end:
.size ntw6970_child_stack_end,0
.section .note.GNU-stack,"",@progbits
'''


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _small_read(path, maximum, resources):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum, "bounded regular fixture read required")
        raw = bytearray()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            raw.extend(block)
            _require(len(raw) <= maximum, "fixture file grew beyond bound")
        _require(len(raw) == before.st_size
                 and resources.identity(os.fstat(fd)) == resources.identity(before)
                 and resources.identity(Path(path).lstat()) == resources.identity(before),
                 "fixture held/named identity changed during read")
        return bytes(raw)
    finally:
        os.close(fd)


def _proof_pin(guard, path, maximum):
    return {"path": str(path), "relative_path": str(path.relative_to(guard.output)),
            **guard.pin(path, maximum=maximum)}


def _elf(raw, expected_type):
    """Small actual-byte ELF64 validator, not a runtime or ISA attestation."""
    _require(64 <= len(raw) <= OBJECT_BYTES_LIMIT, "bounded actual ELF file required")
    _require(raw[:7] == b"\x7fELF\x02\x01\x01", "ELF64 little-endian version1 required")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    _require(kind == expected_type and machine == 62 and version == 1 and flags == 0
             and ehsize == 64 and shsize == 64 and 1 <= shnum <= 128 and shstr < shnum,
             "actual ELF x86_64 type/header bounds differ")
    _require(shoff >= 64 and shoff + shnum * 64 <= len(raw), "ELF section table outside bytes")
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + index * 64) for index in range(shnum)]
    for row in sections:
        _name, stype, _flags, _addr, off, size, _link, _info, align, _entsize = row
        _require(size <= OBJECT_BYTES_LIMIT and (align == 0 or align & (align - 1) == 0),
                 "bounded ELF section size/alignment required")
        if stype != 8:
            _require(off <= len(raw) and off + size <= len(raw), "ELF section bytes outside file")
    strings_row = sections[shstr]
    _require(strings_row[1] == 3, "actual ELF section names table required")
    strings = raw[strings_row[4]:strings_row[4] + strings_row[5]]

    def string_at(table, offset):
        _require(isinstance(offset, int) and 0 <= offset < len(table), "ELF string offset outside table")
        end = table.find(b"\0", offset)
        _require(end >= offset and end - offset <= 256, "bounded terminated ELF name required")
        return table[offset:end].decode("ascii")

    names = [string_at(strings, row[0]) for row in sections]
    symbols = {}
    for row in sections:
        if row[1] != 2:
            continue
        _require(row[9] == 24 and row[5] % 24 == 0 and row[5] // 24 <= 4096
                 and row[6] < len(sections) and sections[row[6]][1] == 3,
                 "bounded actual ELF symbol table required")
        string_row = sections[row[6]]
        table = raw[string_row[4]:string_row[4] + string_row[5]]
        for offset in range(row[4], row[4] + row[5], 24):
            name, info, other, index, value, size = struct.unpack_from("<IBBHQQ", raw, offset)
            name = string_at(table, name)
            if name in ("_start", "ntw6970_child_stack", "ntw6970_child_stack_end"):
                _require(name not in symbols and index < len(sections) and info >> 4 == 1,
                         "unique defined global fixture symbol required")
                symbols[name] = {"value": value, "size": size, "section": index,
                                 "type": info & 15, "other": other}
    _require(set(symbols) == {"_start", "ntw6970_child_stack", "ntw6970_child_stack_end"},
             "actual fixture entry/stack symbols missing")
    start, stack, end = (symbols[name] for name in ("_start", "ntw6970_child_stack", "ntw6970_child_stack_end"))
    _require(start["type"] == 2 and start["size"] > 0
             and sections[start["section"]][2] & 4,
             "fixture entry must be a defined executable function")
    _require(stack["section"] == end["section"] and sections[stack["section"]][1] == 8
             and names[stack["section"]] == ".bss" and stack["value"] % 16 == 0
             and stack["size"] == 65536 and end["value"] - stack["value"] == 65536
             and sections[stack["section"]][5] == 65536,
             "actual private64KiB aligned NOBITS stack extent differs")
    programs = []
    if expected_type == 1:
        _require(phnum == 0 and entry == 0, "fixture object unexpectedly has program headers/entry")
    else:
        _require(phsize == 56 and 1 <= phnum <= 32 and phoff >= 64
                 and phoff + phnum * 56 <= len(raw), "bounded ELF program headers required")
        programs = [struct.unpack_from("<IIQQQQQQ", raw, phoff + index * 56) for index in range(phnum)]
        _require(all(row[0] not in (2, 3) for row in programs), "host fixture must have no PT_DYNAMIC/PT_INTERP")
        loads = [row for row in programs if row[0] == 1]
        stacks = [row for row in programs if row[0] == 0x6474E551]
        _require(1 <= len(loads) <= 8 and len(stacks) == 1 and stacks[0][1] & 1 == 0,
                 "bounded loads and non-executable GNU_STACK required")
        _require(sum(row[6] for row in loads) <= OBJECT_BYTES_LIMIT
                 and all(row[5] <= row[6] and row[2] + row[5] <= len(raw)
                         and row[1] & 3 != 3 for row in loads),
                 "ELF load bytes/memory bound or RWX policy differs")
        _require(entry == start["value"]
                 and sum(row[1] == 5 and row[3] <= entry < row[3] + row[5] for row in loads) == 1,
                 "entry is not actual _start within one RX file-backed segment")
    return {"class": "ELF64", "byteorder": "little", "machine": "EM_X86_64",
            "type": "ET_REL" if expected_type == 1 else "ET_EXEC", "entry": entry,
            "file_bytes": len(raw), "section_count": shnum, "program_header_count": phnum,
            "private_nobits_stack_bytes": 65536, "stack_alignment": 16,
            "no_PT_INTERP": expected_type == 2, "no_PT_DYNAMIC": expected_type == 2,
            "nonexecutable_GNU_STACK": expected_type == 2,
            "entry_in_RX_segment": expected_type == 2,
            "metadata_only": True, "binary_transfer_authorized": False,
            "runtime_execution_or_loaded_code_attestation": False}


def _prepare(parent, resources, as_path, ld_path, started):
    _require(os.uname().sysname == "Linux" and os.uname().machine == "x86_64",
             "actual Linux x86_64 host is required for the raw syscall fixture")
    paths = {"as": Path(as_path), "ld": Path(ld_path)}
    for path in paths.values():
        _require(path.is_absolute() and ".." not in path.parts
                 and "mingw" not in str(path).lower() and "i686" not in str(path).lower(),
                 "explicit native Linux assembler/linker paths required")
    tools = {name: parent.pin(path, maximum=TOOL_PIN_LIMIT, readonly_system_input=True)
             for name, path in paths.items()}
    source, obj, elf, link_map = (parent.tmp / ("pidfd-fixture" + suffix)
                                for suffix in (".S", ".o", ".ELF", ".map"))
    raw_source = ASSEMBLY.encode("ascii")
    _require(len(raw_source) <= SOURCE_BYTES_LIMIT and ".include" not in ASSEMBLY
             and ".incbin" not in ASSEMBLY, "bounded include-free handwritten GAS required")
    parent.check(FIXTURE_BYTES_LIMIT)
    parent.write(source, raw_source)
    source_pin = _proof_pin(parent, source, SOURCE_BYTES_LIMIT)
    argvs = [[str(paths["as"]), "--version"], [str(paths["ld"]), "--version"],
             [str(paths["as"]), "--64", "--fatal-warnings", "-o", str(obj), str(source)],
             [str(paths["ld"]), "-m", "elf_x86_64", "-e", "_start", "--build-id=none",
              "-z", "noexecstack", "--fatal-warnings", "-Map", str(link_map), "-o", str(elf), str(obj)]]
    indexes = []
    compiled_object = None
    capture_before, decoder_before = parent.capture_bytes, parent.decoder_bytes
    for index, argv in enumerate(argvs):
        remaining = TOTAL_SECONDS - (time.monotonic() - started)
        _require(remaining > 0, "fixture preparation total deadline")
        if index == 3:
            _require(_proof_pin(parent, obj, OBJECT_BYTES_LIMIT) == compiled_object,
                     "actual assembled object changed before link")
        indexes.append(len(parent.commands))
        result = parent.run(argv, PREP_LABELS[index], cwd=parent.tmp, timeout=min(10.0, remaining))
        _require(result.returncode == 0 and result.stderr == b"", "actual native fixture preparation failed")
        if index < 2:
            _require(result.stdout.startswith(b"GNU "), "actual native GNU tool version text required")
        else:
            _require(result.stdout == b"", "assembler/linker unexpectedly produced standard output")
        if index == 2:
            compiled_object = _proof_pin(parent, obj, OBJECT_BYTES_LIMIT)
        _require(_proof_pin(parent, source, SOURCE_BYTES_LIMIT) == source_pin,
                 "fixture source changed across actual preparation")
        for name, path in paths.items():
            _require(parent.pin(path, maximum=TOOL_PIN_LIMIT, readonly_system_input=True) == tools[name],
                     "selected native tool changed across actual preparation")
    object_pin = _proof_pin(parent, obj, OBJECT_BYTES_LIMIT)
    _require(object_pin == compiled_object, "actual assembled object changed across link")
    elf_pin = _proof_pin(parent, elf, OBJECT_BYTES_LIMIT)
    map_pin = _proof_pin(parent, link_map, MAP_BYTES_LIMIT)
    object_raw = _small_read(obj, OBJECT_BYTES_LIMIT, resources)
    elf_raw = _small_read(elf, OBJECT_BYTES_LIMIT, resources)
    _require(_sha(object_raw) == object_pin["sha256"] and len(object_raw) == object_pin["bytes"]
             and _sha(elf_raw) == elf_pin["sha256"] and len(elf_raw) == elf_pin["bytes"],
             "actual interpreted ELF bytes differ from whole-file pins")
    object_metadata = _elf(object_raw, 1)
    elf_metadata = _elf(elf_raw, 2)
    _require(elf.lstat().st_mode & stat.S_IXUSR, "actual pinned fixture ELF is not executable")
    map_raw = _small_read(link_map, MAP_BYTES_LIMIT, resources)
    _require(_sha(map_raw) == map_pin["sha256"] and len(map_raw) == map_pin["bytes"],
             "actual interpreted map differs from whole-file pin")
    loads = [line[5:] for line in map_raw.decode("utf-8").splitlines() if line.startswith("LOAD ")]
    _require(loads == [str(obj)], "actual linker map must LOAD only the explicit fixture object")
    return {"tools_before": tools, "tools_after_equal": True,
            "source": source_pin, "object": object_pin, "elf": elf_pin, "map": map_pin,
            "object_metadata": object_metadata, "elf_metadata": elf_metadata,
            "command_indexes": indexes, "command_labels": list(PREP_LABELS), "argvs": argvs,
            "capture_pool_before_prepare": capture_before, "decoder_pool_before_prepare": decoder_before,
            "capture_pool_after_prepare": parent.capture_bytes, "decoder_pool_after_prepare": parent.decoder_bytes,
            "prepare_capture_pool_delta": parent.capture_bytes - capture_before,
            "prepare_decoder_pool_delta": parent.decoder_bytes - decoder_before,
            "proof_files": [source_pin, map_pin], "source_bytes_limit": SOURCE_BYTES_LIMIT,
            "object_elf_bytes_limit_each": OBJECT_BYTES_LIMIT, "map_bytes_limit": MAP_BYTES_LIMIT,
            "private_stack_memory_bytes": 65536, "fixture_bytes_limit": FIXTURE_BYTES_LIMIT,
            "headers_libraries_crt_used": False, "tool_dynamic_runtime_closure_verified": False,
            "binary_transfer_authorized": False, "metadata_only_host_binaries": True}


def _stopped(snapshot):
    return (isinstance(snapshot, dict) and bool(snapshot.get("members"))
            and bool(snapshot.get("tasks"))
            and all(row.get("state") in ("T", "Z") for row in snapshot["members"])
            and all(row.get("state") in ("T", "Z") for row in snapshot["tasks"]))


def _readiness(snapshot, leader_pid, nested):
    """Match actual complete single-thread fixture PPID/state observations."""
    if (not isinstance(snapshot, dict) or snapshot.get("stable") is not True
            or not isinstance(snapshot.get("leader"), dict)
            or snapshot["leader"].get("pid") != leader_pid
            or not isinstance(snapshot.get("members"), list)
            or not isinstance(snapshot.get("tasks"), list)):
        return None
    members, tasks = snapshot["members"], snapshot["tasks"]
    expected = 3 if nested else 2
    if len(members) != expected or len(tasks) != expected:
        return None
    by_pid = {row.get("pid"): row for row in members}
    if len(by_pid) != expected or leader_pid not in by_pid:
        return None
    if snapshot["leader"] != by_pid[leader_pid]:
        return None
    if any(not isinstance(row.get("ppid"), int) or isinstance(row.get("ppid"), bool)
           or row.get("pgrp") != leader_pid or row.get("session") != leader_pid
           or row.get("uid") != os.getuid() for row in members):
        return None
    if any(row.get("pid") != row.get("tid") or row.get("pid") not in by_pid
           or any(row.get(key) != by_pid[row["pid"]].get(key)
                  for key in ("pid", "ppid", "startticks", "pgrp", "session", "uid", "state"))
           for row in tasks):
        return None
    leader = by_pid[leader_pid]
    if nested:
        workers = [row for row in members if row["pid"] != leader_pid
                   and row["ppid"] == leader_pid and row["state"] == "D"]
        if leader["state"] not in ("S", "R") or len(workers) != 1:
            return None
        parent = workers[0]
    else:
        if leader["state"] != "D":
            return None
        parent = leader
    children = [row for row in members if row["pid"] != parent["pid"]
                and row["ppid"] == parent["pid"] and row["state"] in ("S", "R")]
    if len(children) != 1:
        return None
    return {"blocking_parent_pid": parent["pid"], "preexec_child_pid": children[0]["pid"],
            "leader_pid": leader_pid, "nested": nested}


class _Monitor:
    """Actual readiness/signal observations plus two labelled fault boundaries.

    Waiting happens in the first production snapshot callback after pause's
    original deadline is started.  It does not count a live filesystem, extend
    that deadline, change the original token/state predicate or send a signal.
    """
    def __init__(self, guard, resources, index):
        self.guard, self.resources, self.index = guard, resources, index
        self.original_observer = guard._group_observer
        self.original_identity = resources._OwnedGroupObservation._pidfd_signal_identity
        self.original_send = resources.signal.pidfd_send_signal
        self.original_killpg = resources.os.killpg
        self.ready = None
        self.identity_injected = False
        self.metrics = {"scans": 0, "paused_scans": 0, "readiness_wait_seconds": 0.0,
                        "readiness_snapshot": None, "readiness_sha256": None,
                        "observed_D_ppid_ready": False, "ready_before_any_stop": False,
                        "stop_requests": 0, "wrong_target_stop_requests": 0,
                        "all_zombie_group_stop_requests": 0,
                        "early_continue_requests": 0, "injected_fault_count": 0,
                        "identity_fault_original_row": None, "signal_samples": [],
                        "signal_samples_truncated": False,
                        "readiness_does_not_prove_production_vfork_cause": True}

    def __enter__(self):
        monitor = self

        def observe(_self, proc):
            group = monitor.guard._active_group
            _require(group is not None and group.proc is proc, "fixture requires its active owned observer")
            snapshot = monitor.original_observer(proc)
            monitor.metrics["scans"] += 1
            if monitor.ready is None:
                _require(group.pause_deadline is not None and group.pause_started is not None
                         and group.telemetry["stop_requests"] == 0 and not group.paused,
                         "first actual snapshot must precede every STOP inside original pause deadline")
                began = time.monotonic()
                while True:
                    group.check_time()
                    ready = _readiness(snapshot, proc.pid, monitor.index == 1)
                    if ready is not None:
                        break
                    # This is an actual numeric proc scan, not a live recursive
                    # output check.  Both original command/pause deadlines apply.
                    time.sleep(0.001)
                    snapshot = monitor.original_observer(proc)
                    monitor.metrics["scans"] += 1
                raw = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
                _require(len(raw) <= 16384, "readiness snapshot diagnostic bound")
                monitor.ready = ready
                monitor.metrics["readiness_snapshot"] = json.loads(raw)
                monitor.metrics["readiness_sha256"] = _sha(raw)
                monitor.metrics["readiness_wait_seconds"] = time.monotonic() - began
                monitor.metrics["observed_D_ppid_ready"] = True
                monitor.metrics["ready_before_any_stop"] = True
                if monitor.index == 3:
                    copied = {**snapshot, "members": [dict(row) for row in snapshot["members"]]}
                    target = next(row for row in copied["members"] if row["pid"] == proc.pid)
                    # Original direct child already has PPID==leader.  Exactly
                    # one member PPID now makes the member forest cyclic.
                    target["ppid"] = ready["preexec_child_pid"]
                    monitor.metrics["injected_fault_count"] += 1
                    return copied
            if monitor.guard._quiescence_depth > 0:
                _require(_stopped(snapshot), "verified pidfd pause contains a non-T/Z process/task")
                monitor.metrics["paused_scans"] += 1
            return snapshot

        def identity(observer, pid):
            actual = monitor.original_identity(observer, pid)
            if observer.guard is not monitor.guard or monitor.index != 4 or monitor.identity_injected:
                return actual
            _require(monitor.ready is not None and pid == observer.proc.pid
                     and monitor.metrics["stop_requests"] == 0,
                     "token injection must precede the first leader STOP")
            row, tasks, stable = actual
            binding = observer._pidfds.get(pid)
            _require(binding is not None and stable
                     and tuple(row[key] for key in ("pid", "startticks", "pgrp", "session", "uid"))
                     == binding["token"], "token injection must start with the actual bound birth identity")
            monitor.identity_injected = True
            monitor.metrics["injected_fault_count"] += 1
            monitor.metrics["identity_fault_original_row"] = dict(row)
            copied = dict(row)
            copied["startticks"] += 1
            return copied, tasks, stable

        def send(fd, number, siginfo=None, flags=0):
            group = monitor.guard._active_group
            if number == signal.SIGSTOP and group is not None:
                bindings = [(pid, row) for pid, row in group._pidfds.items() if row["fd"] == fd]
                if len(bindings) != 1 or flags != 0 or siginfo is not None:
                    monitor.metrics["wrong_target_stop_requests"] += 1
                    raise AssertionError("fixture refused an unbound/non-process pidfd STOP")
                pid, _binding = bindings[0]
                if monitor.index in (3, 4):
                    monitor.metrics["wrong_target_stop_requests"] += 1
                    raise AssertionError("injected invalid ancestry/identity reached a real STOP")
                actual = monitor.original_observer(group.proc)
                by_pid = {row["pid"]: row for row in actual["members"]}
                ancestors, seen = [], {pid}
                cursor = by_pid.get(pid)
                while cursor is not None and cursor["ppid"] in by_pid:
                    parent_pid = cursor["ppid"]
                    _require(parent_pid not in seen, "actual pre-send ancestry unexpectedly cyclic")
                    seen.add(parent_pid)
                    cursor = by_pid[parent_pid]
                    parent_tasks = [row for row in actual["tasks"] if row["pid"] == parent_pid]
                    if cursor["state"] not in ("T", "Z") or not parent_tasks or any(
                            row["state"] not in ("T", "Z") for row in parent_tasks):
                        monitor.metrics["wrong_target_stop_requests"] += 1
                        raise AssertionError("descendant STOP preceded actual ancestor all-T/Z")
                    ancestors.append(parent_pid)
                monitor.metrics["stop_requests"] += 1
                if len(monitor.metrics["signal_samples"]) < 8:
                    monitor.metrics["signal_samples"].append({"pid": pid, "flags": flags,
                                                              "observed_ancestor_pids": ancestors,
                                                              "actual_snapshot_stable": actual["stable"]})
                else:
                    monitor.metrics["signal_samples_truncated"] = True
            return monitor.original_send(fd, number, siginfo, flags)

        def killpg(pgid, number):
            active = monitor.guard._active_group
            if active is not None and pgid == active.proc.pid:
                if number == signal.SIGSTOP:
                    actual = monitor.original_observer(active.proc)
                    if (actual["stable"] and actual["members"] and actual["tasks"]
                            and all(row["state"] == "Z" for row in actual["members"])
                            and all(row["state"] == "Z" for row in actual["tasks"])):
                        monitor.metrics["all_zombie_group_stop_requests"] += 1
                    else:
                        monitor.metrics["wrong_target_stop_requests"] += 1
                        raise AssertionError("active fixture STOP must be process-targeted pidfd")
                if number == signal.SIGCONT and monitor.guard._quiescence_depth > 0:
                    monitor.metrics["early_continue_requests"] += 1
                    raise AssertionError("fixture resumed during an owned recursive count")
            return monitor.original_killpg(pgid, number)

        self.guard._group_observer = types.MethodType(observe, self.guard)
        self.resources._OwnedGroupObservation._pidfd_signal_identity = identity
        self.resources.signal.pidfd_send_signal = send
        self.resources.os.killpg = killpg
        return self

    def __exit__(self, *_):
        self.guard._group_observer = self.original_observer
        self.resources._OwnedGroupObservation._pidfd_signal_identity = self.original_identity
        self.resources.signal.pidfd_send_signal = self.original_send
        self.resources.os.killpg = self.original_killpg


def _run_case(child, resources, fixture, index, remaining):
    name = CONTROL_NAMES[index]
    expectation = CONTROL_EXPECTATIONS[name]
    mode = "direct" if index == 0 else "nested" if index == 1 else "stuck"
    expected_stdout = (b"VFORK_READY\nLEAF_OK\nDIRECT_OK\n" if index == 0 else
                       b"VFORK_READY\nLEAF_OK\nWORKER_OK\nNESTED_OK\n" if index == 1 else None)
    observed_error = None
    with _Monitor(child, resources, index) as monitor:
        try:
            result = child.run([fixture, mode], "control", timeout=min(3.0, remaining))
            _require(index < 2 and result.returncode == 0, "negative pidfd case unexpectedly completed")
            _require(result.stdout == expected_stdout and result.stderr == b"",
                     "actual self-exec fixture output differs")
        except resources.ResourceFailure as error:
            observed_error = str(error)
            _require(index >= 2 and expectation["reason"] in observed_error,
                     "pidfd control failed for unrelated reason: " + observed_error[:256])
        _require(len(child.commands) == 1, "pidfd case must retain one actual command")
        command = child.commands[0]
        quiescence = command.get("quiescence") or {}
        cleanup = command["group_kill"] == "REQUESTED_BEFORE_REAP"
        if index < 2 and command["group_kill"] == "NO_SUCH_GROUP_BEFORE_REAP":
            cleanup = (quiescence.get("stop_no_live_group_observations", 0) > 0
                       and monitor.metrics["all_zombie_group_stop_requests"] > 0)
        _require(command["reaped"] and cleanup
                 and child._quiescence_depth == 0, "pidfd fixture lacks owned kill-before-reap cleanup")
        _require(monitor.metrics["observed_D_ppid_ready"] and monitor.metrics["ready_before_any_stop"]
                 and monitor.metrics["wrong_target_stop_requests"] == 0
                 and monitor.metrics["early_continue_requests"] == 0,
                 "actual D/PPID readiness or signal order is unverified")
        if expectation["stop_request_expected"]:
            _require(monitor.metrics["stop_requests"] > 0 and quiescence.get("stop_requests", 0) > 0,
                     "case never exercised actual process-targeted STOP")
        else:
            _require(monitor.metrics["stop_requests"] == 0 and quiescence.get("stop_requests") == 0
                     and quiescence.get("continue_requests") == 0
                     and quiescence.get("failure_stop_retained_until_owned_kill") is False,
                     "pre-STOP refusal fabricated a STOP/CONT or held-stop claim")
        if index < 2:
            _require(observed_error is None and command["returncode"] == 0 and command["aborted"] is None
                     and monitor.metrics["paused_scans"] > 0
                     and quiescence.get("verified_pauses", 0) > 0
                     and quiescence.get("continue_requests", 0) > 0,
                     "positive parent-first fixture lacks actual successful all-T/Z count")
        else:
            _require(observed_error is not None and command["returncode"] == -signal.SIGKILL
                     and command["aborted"], "negative pidfd fixture did not fail/kill/reap")
            if expectation["stop_request_expected"]:
                _require(quiescence.get("failure_stop_retained_until_owned_kill") is True,
                         "actual timeout did not retain partial STOP ownership for kill")
        _require(monitor.metrics["injected_fault_count"] == int(expectation["injected_fault"]),
                 "pidfd case injection count differs")
    return {"observation": dict(monitor.metrics), "observed_error": observed_error}


def _recheck_fixture(parent, fixture):
    for name, maximum in (("source", SOURCE_BYTES_LIMIT), ("map", MAP_BYTES_LIMIT),
                          ("object", OBJECT_BYTES_LIMIT), ("elf", OBJECT_BYTES_LIMIT)):
        before = fixture[name]
        _require(_proof_pin(parent, Path(before["path"]), maximum) == before,
                 "actual fixture " + name + " changed across hosted cases")
    for name, before in fixture["tools_before"].items():
        _require(parent.pin(Path(fixture["argvs"][0 if name == "as" else 1][0]),
                            maximum=TOOL_PIN_LIMIT, readonly_system_input=True) == before,
                 "actual native tool changed across hosted cases")


def _command_row(command):
    keys = ("label", "returncode", "reaped", "aborted", "group_kill",
            "nonreaping_leader_exit_observed", "full_stdout_bytes", "full_stderr_bytes",
            "full_stdout_sha256", "full_stderr_sha256", "captured_bytes", "captured_sha256",
            "raw_stdout_stream", "stdout_delivered_to_consumer_bytes")
    row = {key: command[key] for key in keys}
    row["argv_sha256"] = _sha(json.dumps(command["argv"], separators=(",", ":")).encode())
    row["quiescence"] = command.get("quiescence")
    return row


def _closed_argvs(receipt):
    """Decode the resource's lossless schema without calling its encoder."""
    table = receipt.get("command_argv_string_table")
    commands = receipt.get("commands")
    _require(isinstance(table, list) and all(isinstance(text, str) for text in table)
             and isinstance(commands, list), "actual child lossless argv envelope absent")
    vectors = []
    for command in commands:
        indexes = command.get("argv_refs")
        _require(isinstance(indexes, list) and 0 < len(indexes) <= 256
                 and all(isinstance(index, int) and not isinstance(index, bool)
                         and 0 <= index < len(table) for index in indexes)
                 and "argv" not in command, "actual child argv references malformed")
        vectors.append([table[index] for index in indexes])
    return vectors


def run_controls(parent_guard, resources_module, native_as_path, native_ld_path):
    """Direct hosted driver; a PASS requires four prep and five closed cases."""
    resources = resources_module
    started = time.monotonic()
    _require(not parent_guard._running and parent_guard._quiescence_depth == 0,
             "pidfd controls must be directly driven outside a parent command")
    _require(hasattr(resources._OwnedGroupObservation, "_pidfd_signal_identity")
             and hasattr(resources.signal, "pidfd_send_signal") and hasattr(resources.os, "pidfd_open"),
             "actual production process-targeted pidfd API unavailable")
    source_path = Path(resources.__file__)
    source_pin = parent_guard.pin(source_path, maximum=SOURCE_PIN_LIMIT)
    _require(getattr(resources, "__6970_bound_source_sha256__", None) == source_pin["sha256"]
             and getattr(resources, "__6970_bound_source_bytes__", None) == source_pin["bytes"],
             "resource module has no matching verified-buffer loader envelope")
    helper_path = Path(__file__)
    helper_pin = parent_guard.pin(helper_path, maximum=SOURCE_PIN_LIMIT)
    _require(globals().get("__6970_bound_source_sha256__") == helper_pin["sha256"]
             and globals().get("__6970_bound_source_bytes__") == helper_pin["bytes"],
             "pidfd helper has no matching verified-buffer loader envelope")
    _require(parent_guard.capture_bytes + PAYLOAD_LIMIT <= resources.CAPTURE_LIMIT,
             "pidfd four-KiB payload reservation does not fit shared normal pool")
    parent_guard.check(FIXTURE_BYTES_LIMIT)
    initial_bytes = parent_guard.count()
    fixture = _prepare(parent_guard, resources, native_as_path, native_ld_path, started)
    parent_guard.check()
    _require(parent_guard.count() - initial_bytes <= FIXTURE_BYTES_LIMIT,
             "actual fixture preparation exceeds internal8MiB subprofile")
    cases = []
    proof_files = list(fixture["proof_files"])
    payload_total = charged_capture = charged_decoder = 0
    for index, name in enumerate(CONTROL_NAMES):
        remaining = TOTAL_SECONDS - (time.monotonic() - started)
        _require(remaining > 0, "pidfd controls total wall deadline")
        _recheck_fixture(parent_guard, fixture)
        parent_guard.check(PAYLOAD_LIMIT)
        case_started = time.monotonic()
        child = resources.Guard(parent_guard.tmp / ("pidfd-%02d" % index), parent_guard.repository)
        capture_offset, decoder_offset = parent_guard.capture_bytes, parent_guard.decoder_bytes
        child.capture_bytes, child.decoder_bytes = capture_offset, decoder_offset
        expected = CONTROL_EXPECTATIONS[name]
        row = {"name": name, "result": "FAIL", "executed": True,
               "expected_child_epoch": expected["child_epoch"],
               "injected_fault": expected["injected_fault"],
               "stop_request_expected": expected["stop_request_expected"],
               "expected_negative_reason": expected["reason"], "expected_command_count": 1}
        details = error = closed = None
        try:
            details = _run_case(child, resources, fixture["elf"]["path"], index, remaining)
        except BaseException as failure:
            error = type(failure).__name__ + ": " + str(failure)[:512]
        finally:
            try:
                _require(child.capture_bytes >= capture_offset and child.decoder_bytes >= decoder_offset,
                         "pidfd inherited pool counter moved backwards")
                capture_delta = child.capture_bytes - capture_offset
                decoder_delta = child.decoder_bytes - decoder_offset
                parent_guard.capture_bytes, parent_guard.decoder_bytes = child.capture_bytes, child.decoder_bytes
                charged_capture += capture_delta
                charged_decoder += decoder_delta
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                _require(parent_guard.capture_bytes <= resources.CAPTURE_LIMIT
                         and parent_guard.decoder_bytes <= resources.DECODER_LIMIT,
                         "nested pidfd case crossed actual shared pool bounds")
                _require(parent_guard.minimum_free is not None and parent_guard.minimum_free >= resources.RESERVE,
                         "nested pidfd case observed a below-reserve floor")
                child_receipt = {"schema": CASE_SCHEMA,
                                 "result": "PASS_CONTROL_CHILD" if error is None and index < 2 else "FAIL",
                                 "control": name, "expected_negative": index >= 2,
                                 "injected_fault": expected["injected_fault"],
                                 "stop_request_expected": expected["stop_request_expected"],
                                 "inherited_parent_capture_bytes": capture_offset,
                                 "inherited_parent_decoder_bytes": decoder_offset,
                                 "control_capture_pool_delta": capture_delta,
                                 "control_decoder_pool_delta": decoder_delta,
                                 "control_capture_accounting_scope": "inherited global pools; commands retain actual case bytes",
                                 "observed_control_error": error,
                                 "actual_control_observation": details["observation"] if details else None,
                                 "expected_fault_observed": details["observed_error"] if details else None,
                                 "fixture_elf_sha256": fixture["elf"]["sha256"],
                                 "source_flags_are_not_readiness_attestation": True,
                                 "native_execution_verified": False, "windows98_integration_verified": False,
                                 "tls_execution_verified": False}
                closed = child.close_receipt(child_receipt, child.output / "result.json")
            except BaseException as failure:
                error = error or (type(failure).__name__ + ": " + str(failure)[:512])
            finally:
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                    if child.minimum_free < resources.RESERVE:
                        parent_guard._fail("pidfd case observed below-reserve floor at closure")
                child.close()
        row.update({"child_epoch": closed["result"] if closed is not None else None,
                    "observed_error": details["observed_error"] if details else error,
                    "observation": details["observation"] if details else None,
                    "command_count": len(child.commands), "capture_pool_offset": capture_offset,
                    "decoder_pool_offset": decoder_offset,
                    "capture_pool_delta": child.capture_bytes - capture_offset,
                    "decoder_pool_delta": child.decoder_bytes - decoder_offset,
                    "commands": [_command_row(command) for command in child.commands],
                    "capture_payloads": [], "child_receipt_path": str(child.output / "result.json"),
                    "child_receipt_sha256": closed["sha256"] if closed else None})
        actual_paths = [child.output / "result.json", child.output / "control.stdout", child.output / "control.stderr"]
        for command in child.commands:
            payloads = {}
            _require(command["label"] == "control", "pidfd child command label differs")
            for stream in ("stdout", "stderr"):
                raw = _small_read(child.output / ("control." + stream), PAYLOAD_LIMIT, resources)
                payload_total += len(raw)
                _require(payload_total <= PAYLOAD_LIMIT and _sha(raw) == command["captured_sha256"][stream],
                         "physical pidfd capture exceeds bound or differs from closed command")
                payloads[stream + "_hex"] = raw.hex()
            row["capture_payloads"].append(payloads)
        for path in actual_paths:
            if not path.exists():
                error = error or "actual pidfd closed receipt/capture absent"
                continue
            pin = _proof_pin(parent_guard, path, resources.RECEIPT_LIMIT)
            proof_files.append(pin)
            if path == child.output / "result.json" and closed is not None:
                _require(pin["sha256"] == closed["sha256"] and pin["bytes"] == closed["bytes"]
                         and pin["identity"] == closed["identity"], "closed pidfd child receipt pin changed")
                actual = json.loads(_small_read(path, resources.RECEIPT_LIMIT, resources))
                _require(actual["control"] == name and actual["result"] == closed["result"]
                         and actual["receipt_accounting_verified"] is True,
                         "actual child receipt lacks closed self-inclusive accounting")
                _require(_closed_argvs(actual) == [command["argv"] for command in child.commands],
                         "physical closed pidfd argv vectors differ from actual commands")
                row["child_receipt_bytes"] = pin["bytes"]
        row["elapsed_seconds"] = time.monotonic() - case_started
        _recheck_fixture(parent_guard, fixture)
        parent_guard.check()
        _require(parent_guard.count() - initial_bytes <= FIXTURE_BYTES_LIMIT,
                 "actual cumulative pidfd fixture/cases exceed internal8MiB profile")
        if (error is None and closed is not None and row["child_epoch"] == expected["child_epoch"]
                and row["command_count"] == 1 and row["elapsed_seconds"] <= CASE_SECONDS):
            row["result"] = "PASS"
        else:
            row["error"] = error or "closed pidfd child epoch/count/case wall bound differs"
        cases.append(row)
        if row["result"] != "PASS":
            break
    _require(parent_guard.pin(source_path, maximum=SOURCE_PIN_LIMIT) == source_pin,
             "resource source changed across actual pidfd controls")
    _require(parent_guard.pin(helper_path, maximum=SOURCE_PIN_LIMIT) == helper_pin,
             "pidfd control source changed across actual cases")
    _recheck_fixture(parent_guard, fixture)
    for before in proof_files:
        maximum = SOURCE_BYTES_LIMIT if before["path"] == fixture["source"]["path"] else (
            MAP_BYTES_LIMIT if before["path"] == fixture["map"]["path"] else resources.RECEIPT_LIMIT)
        _require(_proof_pin(parent_guard, Path(before["path"]), maximum) == before,
                 "actual selected pidfd text proof changed before return")
    _require(payload_total == charged_capture and charged_decoder == 0,
             "physical pidfd capture bytes differ from inherited normal/raw charge")
    parent_guard.check()
    elapsed = time.monotonic() - started
    failures = sum(row["result"] != "PASS" for row in cases)
    if elapsed > TOTAL_SECONDS:
        failures += 1
    passed = len(cases) == len(CONTROL_NAMES) and failures == 0
    _require(not passed or len(proof_files) == 17, "five pidfd cases require exact17 text proof paths")
    return {"schema": REPORT_SCHEMA, "result": "PASS_PIDFD_VFORK_CONTROLS_ONLY" if passed else "FAIL",
            "completed": len(cases), "failures": failures if not passed else 0,
            "cases": cases, "fixture_build": fixture, "proof_files": proof_files,
            "resource_source": source_pin, "control_source": helper_pin,
            "resource_source_before_after_equal": True, "control_source_before_after_equal": True,
            "actual_controls_execution_verified": len(cases) == len(CONTROL_NAMES),
            "capture_bytes_charged_to_parent": charged_capture,
            "raw_bytes_charged_to_parent": charged_decoder, "capture_payload_bytes": payload_total,
            "case_pool_charges_exclude_parent_prepare_commands": True,
            "fixture_bytes_limit": FIXTURE_BYTES_LIMIT, "elapsed_seconds": elapsed,
            "case_timeout_seconds": CASE_SECONDS, "total_timeout_seconds": TOTAL_SECONDS,
            "source_input_count_delta": 1, "original_production_and_support_sources_changed": False,
            "expected_negative_commands_added_to_parent": False,
            "fault_injection_is_not_kernel_identity_reuse_attestation": True,
            "readiness_does_not_prove_production_vfork_cause": True,
            "host_elf_object_binary_transfer_authorized": False,
            "tool_dynamic_runtime_closure_verified": False,
            "escaped_writers_excluded_verified": False, "continuous_group_stop_verified": False,
            "filesystem_quota_verified": False, "native_execution_verified": False,
            "windows98_integration_verified": False, "tls_execution_verified": False}
