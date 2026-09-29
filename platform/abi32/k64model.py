#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Python model of the Kernel64 end of the WIN64 subsystem bridge (shizukudos/kernel64/subsys64.c).

Used by w64_e2e.py: the harness pops each frame NTWRAP9X.VXD's bridge pushed and hands the raw 256-byte slot
(plus pool data) to this model, which decodes it with shizukudos/abi/test_abi.py's independent decoder
(struct + zlib CRC-32, no shz_ipc.h), applies the service rules of subsys64.c and answers with slots encoded
by test_abi.py's encoder. It records every rule violation it sees instead of trusting the client.

The Win64 programs are behavioural models of shizukudos/win64/tests/t_hello.c and t_w64con.c (same output
format and exit codes); nothing here executes a PE32+ image. The real service and programs run in the
Kernel64 standalone loopback self-test (shizukudos/tests/run_k64_standalone.py).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shizukudos" / "abi"))
import test_abi as abi  # noqa: E402  (the independent Python wire model)

MAX_PROCS = 4                   # W64_MAX_PROCS
OUT_FIFO = 2048                 # W64_OUT_FIFO, per stream
IN_FIFO = 1024                  # W64_IN_FIFO
WRITE_WAIT_MS = 10000           # W64_WRITE_WAIT_MS
STATUS_OBJECT_NAME_NOT_FOUND = struct.unpack("<i", struct.pack("<I", 0xC0000034))[0]
GENERATION = 1


def split_args(cmdline: str) -> list[str]:
    """Windows argv rules sufficient for the tests: blanks separate, double quotes group and are removed."""
    args, cur, quoted, have = [], [], False, False
    for ch in cmdline:
        if ch == '"':
            quoted, have = not quoted, True
        elif ch in " \t" and not quoted:
            if have:
                args.append("".join(cur))
                cur, have = [], False
        else:
            cur.append(ch)
            have = True
    if have:
        args.append("".join(cur))
    return args


# ---------------------------------------------------------------- Win64 program models (generators)
# A program yields ("write", stream, bytes), ("read", max) -> bytes (b"" = EOF), ("sleep",) or returns its exit code.
def t_hello(pid, cmdline):
    argv = split_args(cmdline)
    yield ("write", 1, (f"hello from Win64 PE32+: argc={len(argv)} argv1={argv[1] if len(argv) > 1 else '-'} "
                        f"image=0000000140000000 pid={pid} tid={pid + 1000}\n").encode())
    yield ("write", 1, b"PROCESSOR_ARCHITECTURE=AMD64 (5 chars)\n")
    return 7


def t_w64con(pid, cmdline):
    argv = split_args(cmdline)
    if len(argv) > 1 and argv[1] == "hang":
        yield ("write", 1, b"t_w64con: hanging until killed\n")
        while True:
            yield ("sleep",)
    for i in range(30):
        head = f"line {i:02d} ".encode()
        line = bytearray(head + bytes(ord("a") + (i + k) % 26 for k in range(len(head), 99)) + b"\n")
        assert len(line) == 100
        yield ("write", 1, bytes(line))
    yield ("write", 1, f"t_w64con: cmdline={len(cmdline)} chars argc={len(argv)}\n".encode())
    yield ("write", 2, b"t_w64con: stderr marker\n")
    total = 0
    while True:
        chunk = yield ("read", 255)
        if not chunk:
            break
        yield ("write", 1, b"echo:" + chunk)
        total += len(chunk)
    yield ("write", 1, f"t_w64con: stdin closed after {total} bytes\n".encode())
    return 0


PROGRAMS = {"\\SHZ\\TESTS\\T_HELLO.EXE": t_hello, "\\SHZ\\TESTS\\T_W64CON.EXE": t_w64con}


class Proc:
    def __init__(self, pid, gen, cwd):
        self.pid, self.gen, self.cwd = pid, gen, cwd
        self.state = abi.W64_PS_STARTED
        self.out = [bytearray(), bytearray()]
        self.stdin, self.stdin_eof = bytearray(), False
        self.seq_sent = self.seq_acked = 0
        self.dropped = 0
        self.terminated = self.reaped = self.exited_sent = False
        self.exit_code = 0
        self.program = None
        self.pending = None            # the op the program is blocked on
        self.pending_value = None
        self.waited = 0
        self.max_unacked = 0


class Kernel64Model:
    def __init__(self):
        self.now_ms = 0
        self.slots: list[Proc | None] = [None] * MAX_PROCS
        self.next_pid = 3
        self.next_gen = 1
        self.violations: list[str] = []
        self.seen_request_ids: set[int] = set()
        self.stats = {"frames": 0, "by_opcode": {}, "c_python_agree": 0, "pool_creates": 0, "max_pool_bytes": 0,
                      "inline_creates": 0, "output_frames": 0, "acks": 0, "input_frames": 0, "eof": 0,
                      "started": 0, "failed": 0, "exited": 0, "killed": 0, "released": 0, "nomem": 0,
                      "queue_full": 0, "stale": 0, "unsupported": 0, "window_full_events": 0,
                      "max_unacked": 0, "corrupted_sent": 0, "muted": 0, "cwd_seen": [], "notes": 0,
                      "slots_sent": 0}
        self.corrupt_next_reply = False
        self.mute_next_request = False
        self.scenario = ""

    # ------------------------------------------------------------ output
    def _slot(self, opcode, payload=b"", *, flags, request_id=0, status=0, capability_id=0):
        self.stats["slots_sent"] += 1
        return abi.encode_slot(opcode, payload, flags=flags, src=abi.DOM_KERNEL64, dst=abi.DOM_WIN98,
                               request_id=request_id, generation=GENERATION, status=status,
                               capability_id=capability_id)

    def _reply(self, out, h, status, payload=b""):
        if self.corrupt_next_reply:
            bad = bytearray(self._slot(abi.OP_W64_QUERY, abi.w64_info(), flags=abi.MSGF_REPLY,
                                       request_id=h["request_id"]))
            bad[abi.HEADER_SIZE + 3] ^= 0x40          # payload byte after the CRC was computed
            out.append(bytes(bad))
            self.stats["corrupted_sent"] += 1
            self.corrupt_next_reply = False
        out.append(self._slot(h["opcode"], payload, flags=abi.MSGF_REPLY, request_id=h["request_id"], status=status,
                              capability_id=h["capability_id"]))

    def _event(self, out, opcode, payload):
        out.append(self._slot(opcode, payload, flags=abi.MSGF_ONEWAY))

    # ------------------------------------------------------------ helpers
    def _violation(self, text):
        self.violations.append(f"[{self.scenario}] {text}")

    def _by_pid(self, pid):
        for p in self.slots:
            if p is not None and p.pid == pid:
                return p
        return None

    def _active(self):
        return sum(1 for p in self.slots if p is not None and not p.reaped)

    def _event_payload(self, p, state, status=0):
        return abi.w64_event(p.pid, state, status, 0, p.exit_code, p.seq_sent, p.dropped)

    # ------------------------------------------------------------ programs
    def _run(self, p: Proc, elapsed):
        """Advances one process until it blocks (full output FIFO, empty stdin, sleep) or ends."""
        while not p.terminated:
            op = p.pending
            if op is None:
                try:
                    op = p.program.send(p.pending_value)
                except StopIteration as done:
                    p.exit_code, p.terminated = int(done.value), True
                    break
                p.pending, p.pending_value = op, None
            if op[0] == "write":
                fifo = p.out[0 if op[1] == 1 else 1]
                space = OUT_FIFO - len(fifo)
                data = op[2]
                fifo += data[:space]
                if len(data) <= space:
                    p.pending, p.waited = None, 0
                    continue
                p.pending = ("write", op[1], data[space:])
                p.waited += elapsed
                if p.waited >= WRITE_WAIT_MS:                  # the client never drained: drop, do not wedge
                    p.dropped += len(data) - space
                    p.pending, p.waited = None, 0
                    continue
                return
            if op[0] == "read":
                if p.stdin:
                    n = min(op[1], len(p.stdin))
                    p.pending_value = bytes(p.stdin[:n])
                    del p.stdin[:n]
                    p.pending = None
                    continue
                if p.stdin_eof:
                    p.pending_value, p.pending = b"", None
                    continue
                return
            if op[0] == "sleep":
                if elapsed:
                    p.pending = None                           # one loop iteration per elapsed tick
                    elapsed = 0
                    continue
                return

    def _pump(self, out):
        for i, p in enumerate(self.slots):
            if p is None:
                continue
            if not p.reaped and p.terminated:
                if p.state != abi.W64_PS_KILLED:
                    p.state = abi.W64_PS_EXITED
                p.reaped = True
            for stream in (0, 1):
                fifo = p.out[stream]
                while fifo and p.seq_sent - p.seq_acked < abi.W64_CONSOLE_WINDOW:
                    data = bytes(fifo[:abi.W64_CONSOLE_CHUNK])
                    del fifo[:len(data)]
                    p.seq_sent += 1
                    self._event(out, abi.OP_W64_CONSOLE_OUTPUT, abi.w64_console(p.pid, p.seq_sent, data, stream + 1))
                    self.stats["output_frames"] += 1
                unacked = p.seq_sent - p.seq_acked
                p.max_unacked = max(p.max_unacked, unacked)
                self.stats["max_unacked"] = max(self.stats["max_unacked"], unacked)
                if fifo and unacked >= abi.W64_CONSOLE_WINDOW:
                    self.stats["window_full_events"] += 1
                if unacked > abi.W64_CONSOLE_WINDOW:
                    self._violation(f"pid {p.pid}: {unacked} unacknowledged output frames")
            if p.reaped and not p.exited_sent and not p.out[0] and not p.out[1]:
                self._event(out, abi.OP_W64_PROCESS_EXITED, self._event_payload(p, p.state))
                p.exited_sent = True
                self.stats["killed" if p.state == abi.W64_PS_KILLED else "exited"] += 1

    def _schedule(self, out, elapsed):
        for p in self.slots:
            if p is not None and not p.terminated:
                self._run(p, elapsed)
        self._pump(out)
        # a pump can free FIFO space only through acknowledgements; run again so writers continue
        for p in self.slots:
            if p is not None and not p.terminated:
                self._run(p, 0)
        self._pump(out)

    # ------------------------------------------------------------ requests
    def _create(self, out, h, payload, pool):
        rc, lens, block = abi.w64_check_create(h, payload, pool)
        if rc != abi.OK:
            self._violation(f"CREATE rejected by the receiver rules: {rc}")
            self._reply(out, h, rc)
            return
        if h["flags"] & abi.MSGF_BUFFER:
            self.stats["pool_creates"] += 1
            self.stats["max_pool_bytes"] = max(self.stats["max_pool_bytes"], len(block))
        else:
            self.stats["inline_creates"] += 1
        text = block.decode("utf-16-le")
        path, cmdline, cwd = text[:lens[0]], text[lens[0]:lens[0] + lens[1]], text[lens[0] + lens[1]:]
        if cwd:
            self.stats["cwd_seen"].append(cwd)
        free = next((i for i, p in enumerate(self.slots) if p is None), None)
        if free is None:
            self.stats["nomem"] += 1
            self._reply(out, h, abi.E_NOMEM)
            return
        program = next((f for name, f in PROGRAMS.items() if name.upper() == path.upper()), None)
        if program is None:
            self.stats["failed"] += 1
            self._reply(out, h, abi.OK, abi.w64_event(0, abi.W64_PS_FAILED, STATUS_OBJECT_NAME_NOT_FOUND))
            return
        p = Proc(self.next_pid, self.next_gen, cwd)
        self.next_pid += 1
        self.next_gen += 1
        p.program = program(p.pid, cmdline)
        self.slots[free] = p
        self.stats["started"] += 1
        self._reply(out, h, abi.OK, abi.w64_event(p.pid, abi.W64_PS_STARTED, 0))

    def _console_ack(self, h, payload):
        rc, c = abi.w64_check_console(h, payload)
        if rc != abi.OK or c[2] != 0:
            self._violation(f"malformed CONSOLE_ACK {rc}")
            return
        p = self._by_pid(c[0])
        if p is None:
            self._violation(f"CONSOLE_ACK for unknown pid {c[0]}")
            return
        if c[1] > p.seq_sent:
            self._violation(f"pid {p.pid}: ACK {c[1]} beyond sent {p.seq_sent}")
            return
        if c[1] <= p.seq_acked:
            self._violation(f"pid {p.pid}: ACK {c[1]} not above {p.seq_acked}")
            return
        p.seq_acked = c[1]
        self.stats["acks"] += 1

    def _console_input(self, out, h, payload):
        rc, c = abi.w64_check_console(h, payload)
        if rc != abi.OK or c[3] != 0:
            self._violation("malformed CONSOLE_INPUT")
            self._reply(out, h, rc if rc != abi.OK else abi.E_INVALID)
            return
        p = self._by_pid(c[0])
        if p is None or p.reaped:
            self._reply(out, h, abi.E_NOENT)
            return
        if p.stdin_eof:
            self._reply(out, h, abi.E_INVALID)
            return
        if c[2] > IN_FIFO - len(p.stdin):
            self.stats["queue_full"] += 1
            self._reply(out, h, abi.E_QUEUE_FULL)
            return
        p.stdin += payload[16:16 + c[2]]
        if c[4] & abi.W64_CONF_EOF:
            p.stdin_eof = True
            self.stats["eof"] += 1
        self.stats["input_frames"] += 1
        self._reply(out, h, abi.OK)

    def _kill(self, out, h, payload, release):
        if h["payload_length"] != 8:
            self._violation("malformed KILL/RELEASE")
            self._reply(out, h, abi.E_INVALID)
            return
        pid, code = struct.unpack_from(abi.KILL_FMT, payload, 0)
        p = self._by_pid(pid)
        if p is None:
            self._reply(out, h, abi.E_NOENT)
            return
        if release:
            if not p.reaped or not p.exited_sent:
                self._reply(out, h, abi.E_BUSY)
                return
            self.slots[self.slots.index(p)] = None
            self.stats["released"] += 1
            self._reply(out, h, abi.OK)
            return
        if not p.terminated:
            p.terminated, p.exit_code, p.state = True, code, abi.W64_PS_KILLED
            p.pending = None
        self._reply(out, h, abi.OK)

    # ------------------------------------------------------------ entry points (harness messages)
    def on_frame(self, raw: bytes, extra: bytes) -> list[bytes]:
        out: list[bytes] = []
        c_rc, c_reason = struct.unpack_from("<iI", extra, 0)
        rc, reason, h, payload = abi.decode_slot(raw)
        self.stats["frames"] += 1
        if (rc, reason) != (c_rc, c_reason):
            self._violation(f"C pop ({c_rc},{c_reason}) and Python decode ({rc},{reason}) disagree")
        else:
            self.stats["c_python_agree"] += 1
        if rc != abi.OK:
            self._violation(f"the VxD put a malformed slot on the ring (reason {reason})")
            return out
        op = h["opcode"]
        self.stats["by_opcode"][hex(op)] = self.stats["by_opcode"].get(hex(op), 0) + 1
        if h["src_domain"] != abi.DOM_WIN98 or h["dst_domain"] != abi.DOM_KERNEL64 or h["abi_minor"] != abi.ABI_MINOR:
            self._violation(f"frame endpoints/version {h['src_domain']}->{h['dst_domain']} 1.{h['abi_minor']}")
        pool = None
        if h["flags"] & abi.MSGF_BUFFER:
            if op != abi.OP_W64_CREATE_PROCESS:
                self._violation(f"pool data on opcode {op:#x}")
            pool_offset, pool_size, first, blocks = struct.unpack_from("<IIII", extra, 8)
            owners = {first + i: extra[24 + i] for i in range(blocks)}
            memory = bytearray(pool_size)
            data = extra[24 + blocks:]
            start = h["buffer_offset"] - pool_offset
            memory[start:start + len(data)] = data
            if len(data) != h["buffer_length"]:
                self._violation("pool data length differs from buffer_length")
            pool = (pool_offset, pool_size, owners, memory)
        oneway = bool(h["flags"] & abi.MSGF_ONEWAY)
        if not oneway:
            if h["request_id"] == 0 or h["request_id"] in self.seen_request_ids:
                self._violation(f"request id {h['request_id']:#x} reused or zero")
            self.seen_request_ids.add(h["request_id"])
            if self.mute_next_request:
                self.mute_next_request = False
                self.stats["muted"] += 1
                self._schedule(out, 0)
                return out
        if h["generation"] != GENERATION or h["dst_domain"] != abi.DOM_KERNEL64:
            self.stats["stale"] += 1
            if not oneway:
                self._reply(out, h, abi.E_STALE)
            return out
        if op == abi.OP_W64_QUERY:
            info = abi.w64_info(MAX_PROCS, self._active(), self.now_ms * 1_000_000)
            self._reply(out, h, abi.OK, info)
        elif op == abi.OP_W64_CREATE_PROCESS:
            self._create(out, h, payload, pool)
        elif op == abi.OP_W64_CONSOLE_ACK:
            if not oneway:
                self._violation("CONSOLE_ACK must be one-way")
            self._console_ack(h, payload)
        elif op == abi.OP_W64_CONSOLE_INPUT:
            self._console_input(out, h, payload)
        elif op in (abi.OP_W64_KILL_PROCESS, abi.OP_W64_RELEASE):
            self._kill(out, h, payload, op == abi.OP_W64_RELEASE)
        elif op == abi.OP_W64_SHUTDOWN:
            self._reply(out, h, abi.OK)
        else:
            self.stats["unsupported"] += 1
            if not oneway:
                self._reply(out, h, abi.E_UNSUPPORTED)
        self._schedule(out, 0)
        return out

    def on_tick(self, ms: int) -> list[bytes]:
        out: list[bytes] = []
        self.now_ms += ms
        self._schedule(out, ms)
        return out

    def on_note(self, text: str) -> list[bytes]:
        self.stats["notes"] += 1
        if text == "corrupt-next-reply":
            self.corrupt_next_reply = True
        elif text == "mute-next-request":
            self.mute_next_request = True
        elif text == "process-start":
            self.seen_request_ids.clear()             # a new Win98 process: its NTW32.DLL counts ids from 0x100 again
        else:
            self.scenario = text
        return []

    def report(self) -> dict:
        live = [p.pid for p in self.slots if p is not None]
        return {"violations": list(self.violations), "stats": self.stats, "simulated_ms": self.now_ms,
                "slots_still_used": live}
