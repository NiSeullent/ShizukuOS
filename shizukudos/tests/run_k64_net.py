#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""End-to-end network verification of Kernel64's TCP/IP stack and ws2_32.dll under QEMU (standalone profile, TCG).

Two boots of the same images, each with an RTL8139:

  direct  guest NIC -> QEMU user-mode networking (SLIRP)       host servers reached as 10.0.2.2
  lossy   guest NIC -> QEMU dgram netdev -> THIS SCRIPT (a frame-level proxy that drops/duplicates/reorders TCP
          segments and blackholes one port) -> QEMU dgram netdev -> QEMU hub -> SLIRP

Host side (all independent of the guest code): TCP echo / sink / seeded-source servers, a control server (close, reset,
hold, half-close), a UDP echo server, a hand-written DNS server, and a mode banner. The guest test programs
(win64/tests/t_net_*.c) print PASS:/FAIL: lines and machine-readable WIRE lines; this script

  * requires every guest program to exit 0,
  * recomputes the byte streams the guest sent/received on the host (sha256/crc32) and compares with the servers' logs,
  * parses QEMU's own packet capture (filter-dump) with a separate Python implementation of the Internet checksum, DHCP,
    ARP, ICMP, TCP and UDP: every frame the guest transmitted must carry valid IP/TCP/UDP/ICMP checksums, DHCP/ARP/ICMP
    must have the values the guest reported, TCP streams reassembled from the capture must equal the expected data, and
    in the lossy run retransmissions and the SYN backoff schedule must be visible on the wire.

If the DHCP-provided resolver (SLIRP -> the host's resolver) does not answer, DNS through SLIRP is reported BLOCKED rather
than faked; the resolver's wire format is still verified against the host DNS server.
"""
import argparse
import hashlib
import json
import random
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
GUEST_MAC = bytes.fromhex("525400123456")
SLIRP_MAC = bytes.fromhex("52550a000202")
HOST_IP = "10.0.2.2"

# host ports (mirrored in win64/tests/t_net_wire.c)
P_MODE, P_ECHO, P_SINK, P_SOURCE, P_CTRL, P_UDP, P_BLACKHOLE, P_OUTAGE, P_DNS = 17000, 17001, 17002, 17003, 17004, 17005, 17006, 17007, 17053
VMAC = bytes.fromhex("52550a000263")            # the proxy's virtual host (lossy boot only): 10.0.2.99
VIP = "10.0.2.99"
GUEST_IP = "10.0.2.15"


def pat_stream(n, start):
    """The guest's deterministic byte pattern (nettest.h pat())."""
    return bytes(((i * 131) ^ (i >> 8) ^ (i >> 17)) & 255 for i in range(start, start + n))


def crc32(data):
    return zlib.crc32(data) & 0xffffffff


# ---------------------------------------------------------------------------------------------------------- servers
class Servers:
    def __init__(self, mode):
        self.mode = mode
        self.lock = threading.Lock()
        self.sink = []          # (n, sha256, crc)
        self.source = []        # (n, seed, sha256, crc)
        self.ctrl = []          # commands seen
        self.udp = []           # datagram sizes echoed
        self.dns_queries = []   # (name, qtype, qclass, rd, id)
        self.echo_bytes = 0
        self.echo_conns = 0
        self.threads = []
        self.socks = []
        self.stop = False
        self._dns_seen = {}

    def _tcp_server(self, port, handler):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(128)
        s.settimeout(0.3)
        self.socks.append(s)

        def loop():
            while not self.stop:
                try:
                    c, _ = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=self._guard, args=(handler, c), daemon=True).start()
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        self.threads.append(t)

    def _guard(self, handler, c):
        try:
            handler(c)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def h_mode(self, c):
        c.sendall(f"MODE {self.mode}\n".encode())

    def h_echo(self, c):
        with self.lock:
            self.echo_conns += 1
        while True:
            d = c.recv(65536)
            if not d:
                return
            with self.lock:
                self.echo_bytes += len(d)
            c.sendall(d)

    def h_sink(self, c):
        h = hashlib.sha256()
        crc = 0
        n = 0
        while True:
            d = c.recv(65536)
            if not d:
                break
            h.update(d)
            crc = zlib.crc32(d, crc)
            n += len(d)
        c.sendall(struct.pack("<II", crc & 0xffffffff, n))
        with self.lock:
            self.sink.append((n, h.hexdigest(), crc & 0xffffffff))

    def h_source(self, c):
        req = b""
        while len(req) < 12:
            d = c.recv(12 - len(req))
            if not d:
                return
            req += d
        n, seed, _ = struct.unpack("<III", req)
        data = random.Random(seed).randbytes(n)
        c.sendall(data)
        c.shutdown(socket.SHUT_WR)
        with self.lock:
            self.source.append((n, seed, hashlib.sha256(data).hexdigest(), crc32(data)))
        c.settimeout(5)
        try:
            while c.recv(4096):
                pass
        except OSError:
            pass

    def h_ctrl(self, c):
        line = b""
        while not line.endswith(b"\n"):
            d = c.recv(1)
            if not d:
                return
            line += d
        cmd = line.strip().decode()
        with self.lock:
            self.ctrl.append(cmd)
        if cmd == "CLOSE":
            return
        if cmd == "RESET":
            time.sleep(0.05)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        if cmd == "HOLD":
            c.settimeout(20)
            try:
                while c.recv(1024):
                    pass
            except OSError:
                pass
            return
        if cmd == "HALF":
            n = 0
            while True:
                d = c.recv(65536)
                if not d:
                    break
                n += len(d)
            c.sendall(f"HALF-OK {n}\n".encode())
            return

    def start_udp_echo(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", P_UDP))
        s.settimeout(0.3)
        self.socks.append(s)

        def loop():
            while not self.stop:
                try:
                    d, a = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                with self.lock:
                    self.udp.append(len(d))
                s.sendto(d, a)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        self.threads.append(t)

    # -- DNS ---------------------------------------------------------------------------------------------------
    @staticmethod
    def _qname(pkt, off):
        labels = []
        while pkt[off]:
            l = pkt[off]
            labels.append(pkt[off + 1:off + 1 + l].decode())
            off += 1 + l
        return ".".join(labels), off + 1

    @staticmethod
    def _enc(name):
        return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"

    def dns_answer(self, pkt):
        ident, flags, qd = struct.unpack(">HHH", pkt[:6])
        name, off = self._qname(pkt, 12)
        qtype, qclass = struct.unpack(">HH", pkt[off:off + 4])
        question = pkt[12:off + 4]
        low = name.lower()
        with self.lock:
            self.dns_queries.append((low, qtype, qclass, (flags >> 8) & 1, qd))
            seen = self._dns_seen.get(low, 0)
            self._dns_seen[low] = seen + 1
        hdr = lambda rcode, an: struct.pack(">HHHHHH", ident, 0x8180 | rcode, 1, an, 0, 0)  # noqa: E731
        rr = lambda owner_ptr, typ, ttl, rdata: struct.pack(">HHHIH", owner_ptr, typ, 1, ttl, len(rdata)) + rdata  # noqa: E731
        if low == "a.shizuku.test":
            return hdr(0, 1) + question + rr(0xc00c, 1, 120, socket.inet_aton("192.0.2.10"))
        if low == "alias.shizuku.test":
            target = self._enc("a.shizuku.test")
            cname_rr = struct.pack(">HHHIH", 0xc00c, 5, 1, 300, len(target)) + target
            target_off = 12 + len(question) + 12                       # offset of the CNAME rdata inside the packet
            return hdr(0, 2) + question + cname_rr + rr(0xc000 | target_off, 1, 90, socket.inet_aton("192.0.2.10"))
        if low == "multi.shizuku.test":
            return hdr(0, 3) + question + b"".join(rr(0xc00c, 1, 60, socket.inet_aton(f"192.0.2.{20 + i}")) for i in (1, 2, 3))
        if low == "mixed.shizuku.test":
            return hdr(0, 1) + question + rr(0xc00c, 1, 60, socket.inet_aton("192.0.2.40"))
        if low == "nx.shizuku.test":
            return hdr(3, 0) + question
        if low == "nodata.shizuku.test":
            return hdr(0, 0) + question
        if low == "servfail.shizuku.test":
            return hdr(2, 0) + question
        if low == "drop-first.shizuku.test":
            if seen == 0:
                return None
            return hdr(0, 1) + question + rr(0xc00c, 1, 60, socket.inet_aton("192.0.2.30"))
        return hdr(3, 0) + question

    def start_dns(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", P_DNS))
        s.settimeout(0.3)
        self.socks.append(s)

        def loop():
            while not self.stop:
                try:
                    d, a = s.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    r = self.dns_answer(d)
                except Exception:
                    r = None
                if r:
                    s.sendto(r, a)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        self.threads.append(t)

    def start(self):
        self._tcp_server(P_MODE, self.h_mode)
        self._tcp_server(P_ECHO, self.h_echo)
        self._tcp_server(P_SINK, self.h_sink)
        self._tcp_server(P_OUTAGE, self.h_sink)
        self._tcp_server(P_SOURCE, self.h_source)
        self._tcp_server(P_CTRL, self.h_ctrl)
        self.start_udp_echo()
        self.start_dns()

    def close(self):
        self.stop = True
        for t in self.threads:                          # the accept/recv loops poll every 0.3 s; wait until they let go of their sockets
            t.join(1.5)
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------------------------------------- proxy
class LossyProxy(threading.Thread):
    """Frame-level L2 forwarder between the two QEMU dgram netdevs (guest side A, SLIRP side B)."""

    def __init__(self, seed, drop_g2h=0.025, drop_h2g=0.006, ack_drop=0.01, dup=0.01, reorder=0.015, blackhole=(P_BLACKHOLE,)):
        # SLIRP's TCP sender is BSD Reno with a 1 s retransmission granularity, so host->guest loss is kept low to bound the run time;
        # guest->host loss (which exercises OUR sender) is higher.
        super().__init__(daemon=True)
        self.rng = random.Random(seed)
        self.sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sa.bind(("127.0.0.1", 20002))
        self.sb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sb.bind(("127.0.0.1", 20004))
        self.drop = {"g2h": drop_g2h, "h2g": drop_h2g}
        self.ack_drop, self.dup, self.reorder, self.blackhole = ack_drop, dup, reorder, set(blackhole)
        self.stats = {"frames": 0, "tcp": 0, "dropped_data": 0, "dropped_ack": 0, "blackholed": 0, "duplicated": 0, "reordered": 0,
                      "outage_dropped": 0}
        self.outage = {"segs": 0, "start": None, "until": 0.0, "log": []}
        self.vhost_rx = []                              # (ts, frame): what the guest sent to the virtual host
        self.injected = []                              # descriptions of injected frames (for the report)
        self.inject_started = False
        self.held = {"g2h": None, "h2g": None}
        self.stop_flag = False

    @staticmethod
    def classify(f):
        if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
            return None
        ihl = (f[14] & 15) * 4
        t = 14 + ihl
        if len(f) < t + 20:
            return None
        dport = struct.unpack(">H", f[t + 2:t + 4])[0]
        sport = struct.unpack(">H", f[t:t + 2])[0]
        flags = f[t + 13]
        paylen = struct.unpack(">H", f[16:18])[0] - ihl - (f[t + 12] >> 4) * 4
        return sport, dport, flags, paylen

    def forward(self, f, direction):
        dst = (("127.0.0.1", 20003), self.sb) if direction == "g2h" else (("127.0.0.1", 20001), self.sa)
        dst[1].sendto(f, dst[0])

    # -- virtual host at 10.0.2.99: answers ARP for itself, collects everything the guest sends to it ---------------------------
    def to_guest(self, frame):
        self.sa.sendto(frame, ("127.0.0.1", 20001))

    def vhost(self, f):
        """True if the frame was consumed by the virtual host."""
        if len(f) >= 42 and f[12:14] == b"\x08\x06" and struct.unpack(">H", f[20:22])[0] == 1 and socket.inet_ntoa(f[38:42]) == VIP:
            rep = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) + VMAC + socket.inet_aton(VIP) + f[22:28] + f[28:32]
            self.to_guest(f[6:12] + VMAC + b"\x08\x06" + rep)
            return True
        if f[0:6] == VMAC or (f[0:6] == b"\xff" * 6 and len(f) >= 42 and f[12:14] == b"\x08\x06" and socket.inet_ntoa(f[38:42]) == VIP):
            self.vhost_rx.append((time.time(), f))
            return True
        return False

    def handle(self, f, direction):
        self.stats["frames"] += 1
        if direction == "g2h" and self.vhost(f):
            return
        if direction == "g2h" and not self.inject_started and len(f) >= 54 and f[12:14] == b"\x08\x00" and f[23] == 6:
            c0 = self.classify(f)
            if c0 and c0[1] == P_MODE and c0[2] & 2:                    # the guest's first connection of T_NET_WIRE: start the injection script
                self.inject_started = True
                threading.Thread(target=self.injector, daemon=True).start()
        c = self.classify(f)
        if c is not None and P_OUTAGE in (c[0], c[1]):                   # total outage on this port for 2.5 s once 30 data segments went up
            o = self.outage
            if direction == "g2h" and c[3] > 0:
                o["segs"] += 1
                if o["segs"] == 30 and o["start"] is None:
                    o["start"] = time.time()
                    o["until"] = o["start"] + 2.5
            if o["start"] is not None and time.time() < o["until"]:
                self.stats["outage_dropped"] += 1
                return
        c = self.classify(f)
        if c is None:
            self.forward(f, direction)
            return
        sport, dport, flags, paylen = c
        self.stats["tcp"] += 1
        if direction == "g2h" and dport in self.blackhole:
            self.stats["blackholed"] += 1
            return
        is_data = paylen > 0 or flags & 3          # data, SYN or FIN
        if self.rng.random() < (self.drop[direction] if is_data else self.ack_drop):
            self.stats["dropped_data" if is_data else "dropped_ack"] += 1
            return
        if self.rng.random() < self.dup:
            self.stats["duplicated"] += 1
            self.forward(f, direction)
        if self.held[direction] is not None:            # release a frame that was held back, after this one
            self.forward(f, direction)
            self.forward(self.held[direction], direction)
            self.held[direction] = None
            return
        if paylen > 0 and self.rng.random() < self.reorder:
            self.stats["reordered"] += 1
            self.held[direction] = f
            return
        self.forward(f, direction)

    def run(self):
        while not self.stop_flag:
            r, _, _ = select.select([self.sa, self.sb], [], [], 0.05)
            for s in r:
                try:
                    f, _ = s.recvfrom(4096)
                except OSError:
                    continue
                self.handle(f, "g2h" if s is self.sa else "h2g")
            for d in ("g2h", "h2g"):                     # never hold a frame indefinitely
                if self.held[d] is not None and not r:
                    self.forward(self.held[d], d)
                    self.held[d] = None

    # -- injected traffic: crafted by this script, independent of the guest's own stack ----------------------------------------
    @staticmethod
    def ip_packet(src, dst, proto, payload, ident, frag=0, ttl=64, bad_hdr=False):
        h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag, ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
        c = inet_csum(h)
        if bad_hdr:
            c ^= 0x00ff
        return h[:10] + struct.pack(">H", c) + h[12:] + payload

    @staticmethod
    def icmp_echo(ident, seq, data, bad=False):
        m = struct.pack(">BBHHH", 8, 0, 0, ident, seq) + data
        c = inet_csum(m)
        if bad:
            c ^= 0x0f0f
        return m[:2] + struct.pack(">H", c) + m[4:]

    def send_ip(self, ippkt):
        self.to_guest(GUEST_MAC + VMAC + b"\x08\x00" + ippkt)

    def injector(self):
        time.sleep(0.6)
        vmac_frame = lambda payload: GUEST_MAC + VMAC + payload  # noqa: E731
        # 1. ARP request: the guest must answer with its own MAC
        arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + VMAC + socket.inet_aton(VIP) + b"\0" * 6 + socket.inet_aton(GUEST_IP)
        self.to_guest(b"\xff" * 6 + VMAC + b"\x08\x06" + arp)
        self.injected.append("arp-request")
        time.sleep(0.3)
        # 2. plain echo request
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 1, self.icmp_echo(0x7a7a, 1, bytes(range(56))), 0x1001))
        self.injected.append("echo 56")
        time.sleep(0.3)
        # 3. fragmented echo request, fragments delivered out of order (2, 1, 3) with fragment 2 duplicated
        data = bytes((i * 7 + 3) & 255 for i in range(3000))
        icmp = self.icmp_echo(0x7a7a, 2, data)
        cut = [(0, 1480), (1480, 1480), (2960, len(icmp) - 2960)]
        frags = [self.ip_packet(VIP, GUEST_IP, 1, icmp[o:o + n], 0x2002, (o // 8) | (0x2000 if o + n < len(icmp) else 0)) for o, n in cut]
        for i in (1, 0, 1, 2):
            self.send_ip(frags[i])
            time.sleep(0.02)
        self.injected.append("echo 3000 fragmented 2,1,2,3")
        time.sleep(0.4)
        # 4. UDP to a closed port -> ICMP port unreachable quoting our header + 8 bytes
        udp = struct.pack(">HHHH", 5555, 9, 8 + 12, 0) + b"hello-closed!"[:12]
        pseudo = socket.inet_aton(VIP) + socket.inet_aton(GUEST_IP) + struct.pack(">BBH", 0, 17, len(udp))
        udp = udp[:6] + struct.pack(">H", inet_csum(pseudo + udp) or 0xffff) + udp[8:]
        self.udp_probe = self.ip_packet(VIP, GUEST_IP, 17, udp, 0x3003)
        self.send_ip(self.udp_probe)
        self.injected.append("udp closed port")
        time.sleep(0.3)
        # 5/6. TCP SYN and bare ACK to a closed port -> RST
        def tcp(sport, dport, seq, ack, flags, bad=False):
            t = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
            ps = socket.inet_aton(VIP) + socket.inet_aton(GUEST_IP) + struct.pack(">BBH", 0, 6, len(t))
            c = inet_csum(ps + t)
            if bad:
                c ^= 0x1234
            return t[:16] + struct.pack(">H", c) + t[18:]
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 6, tcp(40001, 9, 1000000, 0, 2), 0x4004))
        self.injected.append("tcp syn closed port")
        time.sleep(0.2)
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 6, tcp(40002, 9, 555, 777777, 0x10), 0x4005))
        self.injected.append("tcp ack closed port")
        time.sleep(0.2)
        # 7. corrupted / illegal packets: none may be answered
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 1, self.icmp_echo(0x7b7b, 1, b"badip"), 0x5006, bad_hdr=True))
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 1, self.icmp_echo(0x7b7b, 2, b"badicmp", bad=True), 0x5007))
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 6, tcp(40003, 9, 42, 0, 2, bad=True), 0x5008))
        bu = struct.pack(">HHHH", 5556, 9, 8, 0x1234)
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 17, bu, 0x5009))
        self.send_ip(self.ip_packet(VIP, GUEST_IP, 1, self.icmp_echo(0x7b7b, 3, b"ttl0"), 0x500a, ttl=0))
        self.injected.append("5 corrupted/illegal packets")

    def close(self):
        self.stop_flag = True
        time.sleep(0.15)
        self.sa.close()
        self.sb.close()


# ---------------------------------------------------------------------------------------------------------- pcap
def inet_csum(data, init=0):
    if len(data) & 1:
        data += b"\0"
    s = init + sum(struct.unpack(f">{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def read_pcap(path):
    d = Path(path).read_bytes()
    assert struct.unpack("<I", d[:4])[0] == 0xa1b2c3d4, "unexpected pcap magic"
    off, out = 24, []
    while off + 16 <= len(d):
        ts, tu, incl, _ = struct.unpack("<IIII", d[off:off + 16])
        out.append((ts + tu / 1e6, d[off + 16:off + 16 + incl]))
        off += 16 + incl
    return out


class Cap:
    """Parsed view of the capture: frames the guest sent (src MAC == guest) and received."""

    def __init__(self, path):
        self.frames = read_pcap(path)
        self.ip = []            # dicts for IPv4 packets
        self.arp = []
        for ts, f in self.frames:
            if len(f) < 14:
                continue
            et = struct.unpack(">H", f[12:14])[0]
            outgoing = f[6:12] == GUEST_MAC
            if et == 0x0806 and len(f) >= 42:
                op = struct.unpack(">H", f[20:22])[0]
                self.arp.append({"ts": ts, "out": outgoing, "op": op, "sha": f[22:28], "spa": socket.inet_ntoa(f[28:32]),
                                 "tha": f[32:38], "tpa": socket.inet_ntoa(f[38:42])})
            elif et == 0x0800 and len(f) >= 34:
                ihl = (f[14] & 15) * 4
                total = struct.unpack(">H", f[16:18])[0]
                ip = {"ts": ts, "out": outgoing, "frame": f, "ihl": ihl, "total": total, "proto": f[23], "id": struct.unpack(">H", f[18:20])[0],
                      "frag": struct.unpack(">H", f[20:22])[0], "src": socket.inet_ntoa(f[26:30]), "dst": socket.inet_ntoa(f[30:34]),
                      "hdr_ok": inet_csum(f[14:14 + ihl]) == 0, "l4": f[14 + ihl:14 + total]}
                self.ip.append(ip)

    def guest_ip(self):
        return [p for p in self.ip if p["out"]]

    def checksums(self):
        """-> (packets checked, list of failures) for every complete (non-fragmented) L4 datagram the guest sent."""
        checked, bad = 0, []
        for p in self.guest_ip():
            if not p["hdr_ok"]:
                bad.append(("ip-header", p["ts"]))
            checked += 1
            if p["frag"] & 0x3fff:                      # a fragment: the L4 checksum covers the reassembled datagram
                continue
            l4 = p["l4"]
            pseudo = socket.inet_aton(p["src"]) + socket.inet_aton(p["dst"]) + struct.pack(">BBH", 0, p["proto"], len(l4))
            if p["proto"] == 6 and len(l4) >= 20:
                if inet_csum(pseudo + l4) != 0:
                    bad.append(("tcp", p["ts"]))
            elif p["proto"] == 17 and len(l4) >= 8:
                if struct.unpack(">H", l4[6:8])[0] != 0 and inet_csum(pseudo + l4) != 0:
                    bad.append(("udp", p["ts"]))
            elif p["proto"] == 1:
                if inet_csum(l4) != 0:
                    bad.append(("icmp", p["ts"]))
        return checked, bad

    def tcp(self):
        out = []
        for p in self.ip:
            if p["proto"] == 6 and not (p["frag"] & 0x3fff) and len(p["l4"]) >= 20:
                l4 = p["l4"]
                sp, dp, seq, ack, off, fl, win = struct.unpack(">HHIIBBH", l4[:16])
                hl = (off >> 4) * 4
                opts = l4[20:hl]
                mss = None
                i = 0
                while i < len(opts):
                    k = opts[i]
                    if k == 0:
                        break
                    if k == 1:
                        i += 1
                        continue
                    if i + 1 >= len(opts) or opts[i + 1] < 2:
                        break
                    if k == 2 and opts[i + 1] == 4:
                        mss = struct.unpack(">H", opts[i + 2:i + 4])[0]
                    i += opts[i + 1]
                out.append({"ts": p["ts"], "out": p["out"], "src": p["src"], "dst": p["dst"], "sport": sp, "dport": dp, "seq": seq, "ack": ack,
                            "flags": fl, "win": win, "data": l4[hl:], "mss": mss, "opts": opts})
        return out

    def guest_stream(self, dport):
        """Payload the guest sent to 10.0.2.2:dport in the first connection, reassembled by sequence number (retransmits collapse)."""
        segs = [t for t in self.tcp() if t["out"] and t["dport"] == dport]
        syns = [t for t in segs if t["flags"] & 2]
        if not syns:
            return None
        sport = syns[0]["sport"]
        isn = syns[0]["seq"]
        buf = {}
        for t in segs:
            if t["sport"] == sport and t["data"]:
                buf[(t["seq"] - isn - 1) & 0xffffffff] = t["data"]
        out = bytearray()
        for off in sorted(buf):
            d = buf[off]
            if off > len(out):
                return None                                # hole
            out[off:off + len(d)] = d
        return bytes(out)


def dhcp_parse(payload):
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    d = {"op": payload[0], "xid": struct.unpack(">I", payload[4:8])[0], "flags": struct.unpack(">H", payload[10:12])[0],
         "ciaddr": socket.inet_ntoa(payload[12:16]), "yiaddr": socket.inet_ntoa(payload[16:20]), "chaddr": payload[28:34], "opts": {}}
    i = 240
    while i < len(payload) and payload[i] != 255:
        if payload[i] == 0:
            i += 1
            continue
        code, l = payload[i], payload[i + 1]
        d["opts"][code] = payload[i + 2:i + 2 + l]
        i += 2 + l
    return d


# ---------------------------------------------------------------------------------------------------------- QEMU
def qemu_cmd(args, out, mode):
    accel = "kvm" if (args.accel == "auto" and Path("/dev/kvm").exists()) or args.accel == "kvm" else "tcg"
    serial = out / "serial.log"
    pcap = out / "guest.pcap"
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           "-kernel", str(K64S / "boot.elf"), "-initrd", f"{K64S / 'KERNEL64S.BIN'},{WIN64 / 'WIN64.IMG'}",
           "-serial", f"file:{serial}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    user = "user,id=u0,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.15,dns=10.0.2.3"
    if mode == "direct":
        cmd += ["-netdev", user, "-device", f"rtl8139,netdev=u0,mac={GUEST_MAC.hex(':')}",
                "-object", f"filter-dump,id=f0,netdev=u0,file={pcap}"]
    else:
        cmd += ["-netdev", "dgram,id=A,local.type=inet,local.host=127.0.0.1,local.port=20001,remote.type=inet,remote.host=127.0.0.1,remote.port=20002",
                "-device", f"rtl8139,netdev=A,mac={GUEST_MAC.hex(':')}",
                "-object", f"filter-dump,id=f0,netdev=A,file={pcap}",
                "-netdev", "dgram,id=B,local.type=inet,local.host=127.0.0.1,local.port=20003,remote.type=inet,remote.host=127.0.0.1,remote.port=20004",
                "-netdev", user,
                "-netdev", "hubport,id=hb,hubid=1,netdev=B", "-netdev", "hubport,id=hu,hubid=1,netdev=u0"]
    return cmd, serial, pcap, accel


def run_boot(args, mode, out):
    out.mkdir(parents=True, exist_ok=True)
    cmd, serial, pcap, accel = qemu_cmd(args, out, mode)
    for f in (serial, pcap):
        f.unlink(missing_ok=True)
    servers = Servers(mode)
    servers.start()
    proxy = None
    if mode == "lossy":
        proxy = LossyProxy(args.seed)
        proxy.start()
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timed_out = False
    try:
        proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    qout = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    secs = time.time() - t0
    time.sleep(0.3)
    servers.close()
    if proxy:
        proxy.close()
    text = serial.read_text(errors="replace") if serial.exists() else ""
    return {"servers": servers, "proxy": proxy, "serial": text, "pcap": pcap, "qemu_out": qout, "timed_out": timed_out, "seconds": secs,
            "accel": accel, "rc": proc.returncode, "cmd": cmd}


# ---------------------------------------------------------------------------------------------------------- checks
class Checks:
    def __init__(self):
        self.rows = []

    def add(self, name, ok, detail=""):
        self.rows.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")
        return ok

    def blocked(self, name, detail=""):
        self.rows.append({"check": name, "status": "BLOCKED", "detail": detail})
        print(f"  [BLOCKED] {name}  {detail}")


def guest_lines(serial, app):
    return re.findall(r"\[win64 " + app + r" pid \d+\] (.*)", serial)


def verify(run, mode, ck):
    s = run["serial"]
    servers = run["servers"]
    ck.add(f"[{mode}] guest run finished before the timeout", not run["timed_out"], f"{run['seconds']:.1f} s, accel={run['accel']}")
    ck.add(f"[{mode}] Kernel64 finished its self-tests with exit 0", "SHZ-EXIT:0" in s and "0 self-test failure(s)" in s)
    for app in ("T_NET_NIC.EXE", "T_NET_LOOP.EXE", "T_NET_WIRE.EXE"):
        m = re.search(r"K64 win64 app: " + re.escape(app) + r" exit=(-?\d+) faulted=(\d)", s)
        fails = [l for l in guest_lines(s, app) if l.startswith("FAIL")]
        passes = [l for l in guest_lines(s, app) if l.startswith("PASS")]
        ck.add(f"[{mode}] guest {app} exits 0 without a fault, no FAIL line", bool(m) and m.group(1) == "0" and m.group(2) == "0" and not fails,
               f"{len(passes)} PASS, {len(fails)} FAIL" + ("; " + "; ".join(fails[:3]) if fails else ""))
    nic = guest_lines(s, "T_NET_NIC.EXE")
    wl = guest_lines(s, "T_NET_WIRE.EXE")
    info = next((dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv) for l in nic if l.startswith("NETINFO ")), None)
    cap = Cap(run["pcap"])
    # ---- checksums on everything the guest transmitted
    checked, bad = cap.checksums()
    ck.add(f"[{mode}] every IPv4/TCP/UDP/ICMP checksum in {checked} guest frames verifies with an independent implementation", checked > 100 and not bad,
           f"{len(bad)} bad" + (f": {bad[:3]}" if bad else ""))
    # ---- DHCP
    dh = []
    for p in cap.ip:
        if p["proto"] == 17 and len(p["l4"]) >= 8 and struct.unpack(">HH", p["l4"][:4]) in ((68, 67), (67, 68)):
            d = dhcp_parse(p["l4"][8:])
            if d:
                dh.append((p["out"], d))
    types = {(o, d["opts"].get(53, b"\0")[0]) for o, d in dh}
    ck.add(f"[{mode}] DHCP exchange on the wire: DISCOVER, OFFER, REQUEST, ACK", {(True, 1), (False, 2), (True, 3), (False, 5)} <= types, str(sorted(types)))
    ack = next((d for o, d in dh if not o and d["opts"].get(53) == b"\x05"), None)
    req = next((d for o, d in dh if o and d["opts"].get(53) == b"\x03"), None)
    disc = next((d for o, d in dh if o and d["opts"].get(53) == b"\x01"), None)
    if ack and req and disc and info:
        lease = struct.unpack(">I", ack["opts"][51])[0]
        ck.add(f"[{mode}] DHCP ACK on the wire: yiaddr {ack['yiaddr']}, lease {lease} s, mask {socket.inet_ntoa(ack['opts'][1])}, "
               f"router {socket.inet_ntoa(ack['opts'][3][:4])}, dns {socket.inet_ntoa(ack['opts'][6][:4])} == guest NETINFO",
               ack["yiaddr"] == info["ip"] == "10.0.2.15" and str(lease) == info["lease"] and socket.inet_ntoa(ack["opts"][1]) == info["mask"] and
               socket.inet_ntoa(ack["opts"][3][:4]) == info["gw"] and socket.inet_ntoa(ack["opts"][6][:4]) == info["dns"],
               f"guest reported {info}")
        ck.add(f"[{mode}] guest DHCP REQUEST is well-formed (chaddr {req['chaddr'].hex(':')}, requested-ip {socket.inet_ntoa(req['opts'][50])}, "
               f"server-id {socket.inet_ntoa(req['opts'][54])}, client-id, BROADCAST flag, xid matches DISCOVER)",
               req["chaddr"] == GUEST_MAC and req["opts"][50] == socket.inet_aton("10.0.2.15") and req["opts"][54] == socket.inet_aton("10.0.2.2") and
               req["opts"].get(61) == b"\x01" + GUEST_MAC and req["flags"] & 0x8000 and req["xid"] == disc["xid"] and req["ciaddr"] == "0.0.0.0")
    else:
        ck.add(f"[{mode}] DHCP messages could be decoded", False, f"ack={bool(ack)} req={bool(req)} disc={bool(disc)} info={bool(info)}")
    # ---- ARP
    reqs = [a for a in cap.arp if a["out"] and a["op"] == 1 and a["tpa"] == HOST_IP]
    reps = [a for a in cap.arp if not a["out"] and a["op"] == 2 and a["spa"] == HOST_IP]
    ck.add(f"[{mode}] ARP on the wire: who-has {HOST_IP} from {reqs[0]['spa'] if reqs else '?'} answered by {reps[0]['sha'].hex(':') if reps else '?'}",
           bool(reqs) and bool(reps) and reps[0]["sha"] == SLIRP_MAC and reqs[0]["sha"] == GUEST_MAC and reqs[0]["spa"] == "10.0.2.15" and reps[0]["ts"] >= reqs[0]["ts"])
    ann = [a for a in cap.arp if a["out"] and a["spa"] == a["tpa"] == "10.0.2.15"]
    ck.add(f"[{mode}] gratuitous ARP announcement of 10.0.2.15 after DHCP (RFC 5227)", bool(ann))
    # ---- ICMP
    echo_req = [p for p in cap.ip if p["out"] and p["proto"] == 1 and p["l4"][0] == 8]
    echo_rep = [p for p in cap.ip if not p["out"] and p["proto"] == 1 and p["l4"][0] == 0]
    ids = {struct.unpack(">HH", p["l4"][4:8]) for p in echo_req}
    ck.add(f"[{mode}] ICMP echo requests id=0x4242 seq 1 and 2 (payload 32 and 1400) got replies with identical id/seq/payload",
           (0x4242, 1) in ids and (0x4242, 2) in ids and all(any(r["l4"][4:] == q["l4"][4:] and r["src"] == q["dst"] for r in echo_rep) for q in echo_req if struct.unpack(">H", q["l4"][4:6])[0] == 0x4242),
           f"{len(echo_req)} requests, {len(echo_rep)} replies")
    # ---- ARP re-resolution and ARP failure, DHCP renewal, keepalive
    tcp = cap.tcp()
    ghost = next((l for l in nic if l.startswith("ARP-FAIL ")), "")
    m = re.search(r"ghost=(\S+) requests=(\d+)", ghost)
    if m:
        greqs = sorted(a["ts"] for a in cap.arp if a["out"] and a["op"] == 1 and a["tpa"] == m.group(1))
        groups, cur = [], []
        for t in greqs:                                     # one cycle per unresolvable send: the ping, then the TCP connect
            if cur and t - cur[-1] > 1.6:
                groups.append(cur)
                cur = []
            cur.append(t)
        if cur:
            groups.append(cur)
        gaps = [[round(g[i + 1] - g[i], 2) for i in range(len(g) - 1)] for g in groups]
        ck.add(f"[{mode}] ARP failure: {len(groups)} cycles of who-has {m.group(1)} ({[len(g) for g in groups]} requests), gaps {gaps} s (retry every second, 3 tries, then give up)",
               len(groups) == 2 and all(len(g) == 3 for g in groups) and all(0.9 <= x <= 1.3 for gg in gaps for x in gg))
    else:
        ck.add(f"[{mode}] ARP failure test ran", False)
    gw_reqs = [a for a in cap.arp if a["out"] and a["op"] == 1 and a["tpa"] == HOST_IP]
    ck.add(f"[{mode}] ARP cache flush forced a second who-has {HOST_IP} ({len(gw_reqs)} on the wire)", len(gw_reqs) >= 2)
    renew = [p for p in cap.guest_ip() if p["proto"] == 17 and len(p["l4"]) > 248 and struct.unpack(">HH", p["l4"][:4]) == (68, 67) and p["dst"] == HOST_IP]
    rd = dhcp_parse(renew[0]["l4"][8:]) if renew else None
    ck.add(f"[{mode}] DHCP renewal REQUEST is unicast from 10.0.2.15 to the server (ciaddr {rd['ciaddr'] if rd else '?'}, no server-id/requested-ip, no BROADCAST flag)",
           bool(rd) and rd["ciaddr"] == "10.0.2.15" and rd["opts"].get(53) == b"\x03" and 50 not in rd["opts"] and 54 not in rd["opts"] and not rd["flags"] & 0x8000 and renew[0]["src"] == "10.0.2.15")
    ka = next((d for d, _ in wire_kv(wl, "keepalive")), None)
    if ka:
        segs = [t for t in tcp if t["out"] and t["sport"] == int(ka["sport"]) and t["dport"] == P_ECHO]
        syn = next((t for t in segs if t["flags"] & 2), None)
        probes = [t for t in segs if syn and not t["data"] and t["flags"] == 0x10 and t["seq"] == (syn["seq"] + 1 + 10 - 1) & 0xffffffff]
        ck.add(f"[{mode}] keep-alive probes on the wire: {len(probes)} empty ACK segments with seq = snd_una - 1 at {[round(p['ts'] - probes[0]['ts'], 2) for p in probes]} s (guest counted {ka['probes']})",
               len(probes) >= 2 and int(ka["probes"]) >= 2 and 0.8 <= probes[1]["ts"] - probes[0]["ts"] <= 1.4)
    else:
        ck.add(f"[{mode}] keepalive evidence present", False)
    # ---- guest evidence cross-check
    npass = len([l for l in wl if l.startswith("PASS")])
    ck.add(f"[{mode}] T_NET_WIRE printed {npass} PASS lines", npass >= 40)
    # ---- TCP handshakes / MSS / options
    syns = [t for t in tcp if t["out"] and t["flags"] & 0x12 == 0x02]
    ck.add(f"[{mode}] every guest SYN advertises MSS 1460 and no window scaling/SACK/timestamps ({len(syns)} SYNs)",
           bool(syns) and all(t["mss"] == 1460 and t["opts"] == b"\x02\x04\x05\xb4" for t in syns))
    conns = {(t["sport"], t["seq"]) for t in syns if t["dport"] == P_ECHO}          # a retransmitted SYN repeats sport and seq
    isns = [seq for _, seq in conns]
    ck.add(f"[{mode}] initial sequence numbers of {len(isns)} connections to the echo port are all different (RFC 6528 hashing)", len(isns) > 20 and len(set(isns)) == len(isns))
    rst = [t for t in tcp if not t["out"] and t["sport"] == 17999 and t["flags"] & 4]
    syn17999 = [t for t in syns if t["dport"] == 17999]
    ck.add(f"[{mode}] connection to the closed port 17999 was refused with a RST that acknowledges the guest's SYN",
           bool(rst) and bool(syn17999) and rst[0]["ack"] == syn17999[0]["seq"] + 1)
    # ---- upload stream as it crossed the wire
    up = [d for d, _ in wire_kv(wl, "upload")]
    if up:
        u = up[0]
        n = int(u["n"])
        expect = pat_stream(n, int(u["start"]))
        stream = cap.guest_stream(P_SINK)
        ck.add(f"[{mode}] upload: bytes the guest put on the wire ({len(stream) if stream is not None else 'incomplete'}) reassembled from the capture == expected {n}-byte pattern",
               stream is not None and stream[:n] == expect and len(stream) == n)
        exp_sha = hashlib.sha256(expect).hexdigest()
        rec = [x for x in servers.sink if x[0] == n]
        ck.add(f"[{mode}] upload: the host sink received {n} bytes with sha256 {exp_sha[:16]}... and crc32 {crc32(expect):08x} (guest printed {u['crc']}, host replied {u['server_crc']})",
               bool(rec) and rec[0][1] == exp_sha and rec[0][2] == crc32(expect) == int(u["crc"], 16) == int(u["server_crc"], 16))
    else:
        ck.add(f"[{mode}] upload evidence present", False)
    dn = [d for d, _ in wire_kv(wl, "download")]
    if dn:
        d = dn[0]
        rec = [x for x in servers.source if x[0] == int(d["n"]) and x[1] == int(d["seed"])]
        ck.add(f"[{mode}] download: the host source sent {d['n']} bytes (sha256 {rec[0][2][:16] if rec else '?'}..., crc32 {rec[0][3]:08x}" if rec else f"[{mode}] download recorded",
               bool(rec) and int(d["got"]) == int(d["n"]) and int(d["crc"], 16) == rec[0][3],
               f"the guest received {d['got']} bytes with crc32 {d['crc']}")
    else:
        ck.add(f"[{mode}] download evidence present", False)
    ck.add(f"[{mode}] host echo server: {servers.echo_conns} connections, {servers.echo_bytes} bytes echoed", servers.echo_conns >= 65 and servers.echo_bytes > 100000)
    ck.add(f"[{mode}] control server saw CLOSE, RESET, HOLD, HALF from the guest", {"CLOSE", "RESET", "HOLD", "HALF"} <= set(servers.ctrl), str(servers.ctrl))
    sizes = [1, 100, 1472, 1473, 4000, 9000]
    ck.add(f"[{mode}] UDP echo server received datagrams of {sizes} bytes (fragments reassembled by SLIRP)", all(sz in servers.udp for sz in sizes), str(servers.udp[:10]))
    frag = [p for p in cap.guest_ip() if p["proto"] == 17 and (p["frag"] & 0x2000 or p["frag"] & 0x1fff)]
    ck.add(f"[{mode}] guest transmitted IP fragments (MF/offset) for the >1500-byte datagrams: {len(frag)} fragments, offsets multiple of 8",
           len(frag) >= 6 and all(((p["frag"] & 0x1fff) * 8) % 8 == 0 for p in frag) and any(not (p["frag"] & 0x2000) for p in frag))
    # ---- DNS
    q = servers.dns_queries
    names = [x[0] for x in q]
    ck.add(f"[{mode}] DNS wire format: {len(q)} queries, all QTYPE A / QCLASS IN / RD=1 / QDCOUNT=1",
           len(q) >= 8 and all(x[1] == 1 and x[2] == 1 and x[3] == 1 and x[4] == 1 for x in q), str(names))
    ck.add(f"[{mode}] DNS retransmission: drop-first.shizuku.test was asked exactly twice, a.shizuku.test once (second lookup came from the guest cache), "
           f"servfail retried, mixed-case name lower-cased",
           names.count("drop-first.shizuku.test") >= 2 and names.count("a.shizuku.test") == 1 and names.count("servfail.shizuku.test") >= 2 and "mixed.shizuku.test" in names)
    dns_lines = list(wire_kv(wl, "dns"))
    slirp = [raw for d, raw in dns_lines if raw.startswith("slirp-example.com")]
    if slirp and "BLOCKED" in slirp[0]:
        ck.blocked(f"[{mode}] DNS through SLIRP (10.0.2.3 -> host resolver) for example.com", slirp[0])
    elif slirp:
        got = re.findall(r"\d+\.\d+\.\d+\.\d+", slirp[0])
        try:
            host_ips = {x[4][0] for x in socket.getaddrinfo("example.com", 80, socket.AF_INET)}
        except OSError:
            host_ips = set()
        ck.add(f"[{mode}] DNS through SLIRP: guest resolved example.com to {got}; the host resolver says {sorted(host_ips)}", bool(got) and (not host_ips or bool(set(got) & host_ips)))
    else:
        ck.add(f"[{mode}] SLIRP DNS attempt recorded", False)
    return cap


def wire_kv(lines, tag):
    for l in lines:
        m = re.match(r"WIRE " + tag + r" (.*)", l)
        if m:
            raw = m.group(1)
            yield dict(kv.split("=", 1) for kv in raw.split() if "=" in kv), raw


def verify_outage(run, cap, ck, wl):
    o = run["proxy"].outage
    ck.add(f"[lossy] outage rule fired: 2.5 s of total loss on port {P_OUTAGE} after 30 data segments ({run['proxy'].stats['outage_dropped']} frames dropped)",
           o["start"] is not None and run["proxy"].stats["outage_dropped"] >= 4)
    tx = {}
    for t in cap.tcp():
        if t["out"] and t["dport"] == P_OUTAGE and t["data"]:
            tx.setdefault((t["sport"], t["seq"]), []).append(t["ts"])
    if not tx:
        ck.add("[lossy] outage traffic captured", False)
        return
    seq, times = max(tx.items(), key=lambda kv: len(kv[1]))
    times.sort()
    raw = [round(times[i + 1] - times[i], 3) for i in range(len(times) - 1)]
    gaps = [g for g in raw if g > 0.1]                  # a sub-100 ms repeat is a duplicate-ACK fast retransmit, not a timeout
    ratios = [round(gaps[i + 1] / gaps[i], 2) for i in range(len(gaps) - 1)]
    ck.add(f"[lossy] data RTO backoff: one segment was sent {len(times)} times, gaps {raw} s; the timeout gaps {gaps} double each time (ratios {ratios}), first RTO {gaps[0] if gaps else '?'} s",
           len(gaps) >= 4 and 0.15 <= gaps[0] <= 0.6 and all(1.6 <= r <= 2.5 for r in ratios[:3]))
    up = [d for d, _ in wire_kv(wl, "outage_upload")]
    if up:
        u = up[0]
        n = int(u["n"])
        expect = pat_stream(n, int(u["start"]))
        rec = [x for x in run["servers"].sink if x[0] == n]
        ck.add(f"[lossy] the {n}-byte upload that lived through the outage arrived intact: host sha256 {rec[0][1][:16] if rec else '?'}... == expected, crc32 {u['crc']} == {u['server_crc']}, {u['retrans']} retransmissions",
               bool(rec) and rec[0][1] == hashlib.sha256(expect).hexdigest() and int(u["crc"], 16) == int(u["server_crc"], 16) == crc32(expect))
    else:
        ck.add("[lossy] outage upload evidence present", False)


def verify_injection(run, cap, ck, wl):
    px = run["proxy"]
    rx = [(ts, f) for ts, f in px.vhost_rx]
    ck.add(f"[lossy] proxy injected {len(px.injected)} probe groups toward the guest ({px.injected}) and received {len(rx)} frames back at its virtual host {VIP}",
           len(px.injected) == 7 and len(rx) >= 8)

    def ips(proto):
        out = []
        for _, f in rx:
            if len(f) >= 34 and f[12:14] == b"\x08\x00" and f[23] == proto and socket.inet_ntoa(f[30:34]) == VIP:
                ihl = (f[14] & 15) * 4
                total = struct.unpack(">H", f[16:18])[0]
                out.append({"id": struct.unpack(">H", f[18:20])[0], "frag": struct.unpack(">H", f[20:22])[0], "hdr_ok": inet_csum(f[14:14 + ihl]) == 0,
                            "l4": f[14 + ihl:14 + total], "src": socket.inet_ntoa(f[26:30]), "hdr": f[14:14 + ihl]})
        return out
    # 1. ARP responder
    arps = [f for _, f in rx if len(f) >= 42 and f[12:14] == b"\x08\x06" and struct.unpack(">H", f[20:22])[0] == 2]
    ck.add(f"[lossy] ARP responder: the guest answered our who-has {GUEST_IP} with is-at {arps[0][22:28].hex(':') if arps else '?'} addressed to the requester",
           bool(arps) and arps[0][22:28] == GUEST_MAC and socket.inet_ntoa(arps[0][28:32]) == GUEST_IP and arps[0][32:38] == VMAC and arps[0][0:6] == VMAC)
    # 2. echo replies (fragments grouped by IP identification; only the first fragment carries the ICMP header)
    icmp = ips(1)
    byid = {}
    for p in icmp:
        byid.setdefault(p["id"], []).append(p)
    reps = {}
    for ident, ps in byid.items():
        ps.sort(key=lambda p: p["frag"] & 0x1fff)
        if ps[0]["l4"][0] == 0:
            reps[(struct.unpack(">HH", ps[0]["l4"][4:8]), ident)] = ps
    plain = [v for (k, _), v in reps.items() if k == (0x7a7a, 1)]
    ok = bool(plain) and len(plain[0]) == 1 and plain[0][0]["hdr_ok"] and inet_csum(plain[0][0]["l4"]) == 0 and plain[0][0]["l4"][8:] == bytes(range(56)) and plain[0][0]["src"] == GUEST_IP
    ck.add(f"[lossy] ICMP echo request from the wire answered: id 0x7a7a seq 1, 56 bytes returned unchanged, checksums valid", ok)
    # 3. fragmented request reassembled by the guest (fragments arrived 2,1,2,3), reply fragmented by the guest and reassembled here
    fr = [v for (k, _), v in reps.items() if k == (0x7a7a, 2)]
    if fr:
        frags = fr[0]
        offs = [(p["frag"] & 0x1fff) * 8 for p in frags]
        body = b"".join(p["l4"] for p in frags)
        want = bytes((i * 7 + 3) & 255 for i in range(3000))
        ck.add(f"[lossy] out-of-order + duplicated IP fragments (2,1,2,3) of a 3008-byte echo request were reassembled by the guest; its reply came back as {len(frags)} fragments at offsets {offs}, "
               f"reassembled here == the {len(want)} bytes we sent, ICMP checksum valid",
               len(frags) == 3 and offs == [0, 1480, 2960] and bool(frags[0]["frag"] & 0x2000) and not frags[-1]["frag"] & 0x2000 and body[8:] == want and inet_csum(body) == 0 and
               all(p["hdr_ok"] for p in frags))
    else:
        ck.add("[lossy] fragmented echo request was answered", False)
    # 4. ICMP port unreachable
    un = [ps[0] for ps in byid.values() if ps[0]["l4"][0] == 3]
    probe = getattr(px, "udp_probe", b"")
    quoted_ok = [u for u in un if u["l4"][1] == 3 and u["l4"][8:8 + 28] == probe[:28]]
    ck.add(f"[lossy] UDP to closed guest port 9 drew exactly one ICMP port-unreachable (type 3 code 3) quoting our IP header + 8 bytes, checksum valid ({len(un)} ICMP errors in total)",
           len(un) == 1 and len(quoted_ok) == 1 and inet_csum(quoted_ok[0]["l4"]) == 0 and quoted_ok[0]["hdr_ok"])
    # 5/6. RSTs
    tcps = []
    for _, f in rx:
        if len(f) >= 54 and f[12:14] == b"\x08\x00" and f[23] == 6:
            ihl = (f[14] & 15) * 4
            tl = struct.unpack(">H", f[16:18])[0] - ihl                     # TCP length from the IP header (the frame carries Ethernet padding)
            l4 = f[14 + ihl:14 + ihl + tl]
            sp, dp, seq, ack, off, fl = struct.unpack(">HHIIBB", l4[:14])
            pseudo = f[26:30] + f[30:34] + struct.pack(">BBH", 0, 6, tl)
            tcps.append({"sport": sp, "dport": dp, "seq": seq, "ack": ack, "flags": fl, "csum_ok": inet_csum(pseudo + l4) == 0})
    r1 = [t for t in tcps if t["dport"] == 40001]
    r2 = [t for t in tcps if t["dport"] == 40002]
    ck.add(f"[lossy] RFC 793 reset generation: SYN(seq 1000000) to a closed port -> RST|ACK seq 0 ack 1000001; ACK(seq 555, ack 777777) -> RST seq 777777 without ACK",
           len(r1) == 1 and r1[0]["flags"] == 0x14 and r1[0]["seq"] == 0 and r1[0]["ack"] == 1000001 and r1[0]["sport"] == 9 and r1[0]["csum_ok"] and
           len(r2) == 1 and r2[0]["flags"] == 0x04 and r2[0]["seq"] == 777777 and r2[0]["csum_ok"])
    # 7. corrupted/illegal packets were not answered
    silent = (not any(k[0] == 0x7b7b for k in reps)) and not [t for t in tcps if t["dport"] == 40003] and \
        not [u for u in un if u["l4"][8 + 20 + 0:8 + 20 + 2] == struct.pack(">H", 5556)]
    ck.add("[lossy] silence on corrupted input: echo with a bad IP header checksum, bad ICMP checksum and TTL 0, a SYN with a bad TCP checksum and a datagram with a bad UDP checksum drew no reply", silent)
    ab = next((d for d, _ in wire_kv(wl, "stats_abs")), {})
    ck.add(f"[lossy] guest error counters match what we injected: ip_bad={ab.get('ip_bad')} (1), udp_bad={ab.get('udp_bad')} (1), tcp_bad={ab.get('tcp_bad')} (1); "
           f"arp_req_rx={ab.get('arp_req_rx')} arp_rep_tx={ab.get('arp_rep_tx')} unreach_tx={ab.get('unreach_tx')} (2: the injected UDP + the loopback test's) rst_tx>={ab.get('rst_tx')} reasm={ab.get('reasm')}",
           ab.get("ip_bad") == "1" and ab.get("udp_bad") == "1" and ab.get("tcp_bad") == "1" and int(ab.get("arp_rep_tx", 0)) >= 1 and int(ab.get("unreach_tx", 0)) == 2 and
           int(ab.get("rst_tx", 0)) >= 3 and int(ab.get("reasm", 0)) >= 1)


def verify_lossy(run, ck, cap):
    proxy = run["proxy"]
    st = proxy.stats
    ck.add(f"[lossy] proxy really disturbed the traffic: {st}", st["dropped_data"] >= 5 and st["blackholed"] >= 3 and (st["duplicated"] + st["reordered"]) >= 1)
    wl = guest_lines(run["serial"], "T_NET_WIRE.EXE")
    stats = next((d for d, _ in wire_kv(wl, "stats")), {})
    tcp = cap.tcp()
    # retransmissions visible in the guest-side capture: same (sport, seq) with payload sent more than once
    seen, dup = {}, 0
    for t in tcp:
        if t["out"] and t["data"]:
            k = (t["sport"], t["dport"], t["seq"], len(t["data"]))
            seen[k] = seen.get(k, 0) + 1
    dup = sum(v - 1 for v in seen.values() if v > 1)
    retr = int(stats.get("retrans", 0))
    ck.add(f"[lossy] retransmissions are visible on the wire: capture shows {dup} repeated guest data segments, the guest counted {retr} retransmissions (+ {stats.get('fast_retrans', '?')} fast)",
           dup >= 3 and retr >= 3)
    ck.add(f"[lossy] receiver side: guest saw {stats.get('ooo', '?')} out-of-order segments (held, answered with duplicate ACKs)", int(stats.get("ooo", 0)) >= 1)
    # SYN backoff towards the blackholed port
    syn = sorted(t["ts"] for t in tcp if t["out"] and t["dport"] == P_BLACKHOLE and t["flags"] & 2)
    if len(syn) >= 4:
        gaps = [round(syn[i + 1] - syn[i], 2) for i in range(len(syn) - 1)]
        ck.add(f"[lossy] SYN retransmission schedule towards the blackholed port: {len(syn)} SYNs, gaps {gaps} s (RFC 6298 exponential backoff 1, 2, 4)",
               len(syn) == 4 and 0.9 <= gaps[0] <= 1.6 and 1.8 <= gaps[1] <= 2.6 and 3.8 <= gaps[2] <= 4.6)
    else:
        ck.add("[lossy] SYN retransmission schedule captured", False, f"{len(syn)} SYNs")
    verify_outage(run, cap, ck, wl)
    verify_injection(run, cap, ck, wl)
    ct = [d for d, _ in wire_kv(wl, "connect_timeout")]
    ck.add(f"[lossy] guest connect() to the blackholed port failed with WSAETIMEDOUT after {ct[0]['ms'] if ct else '?'} ms with {ct[0]['syn_retrans'] if ct else '?'} SYN retransmissions",
           bool(ct) and 12000 <= int(ct[0]["ms"]) < 30000 and int(ct[0]["syn_retrans"]) == 3)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="tcg")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--seed", type=int, default=20260929)
    ap.add_argument("--skip-lossy", action="store_true")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "net-run"))
    args = ap.parse_args()
    for f in (K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    out = Path(args.out)
    ck = Checks()
    record = {"profile": "kernel64-standalone + RTL8139 (QEMU)", "runs": {}, "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    for mode in (("direct",) if args.skip_lossy else ("direct", "lossy")):
        print(f"== {mode} boot ==")
        run = run_boot(args, mode, out / mode)
        cap = verify(run, mode, ck)
        if mode == "lossy":
            verify_lossy(run, ck, cap)
        record["runs"][mode] = {"seconds": round(run["seconds"], 1), "qemu_rc": run["rc"], "timed_out": run["timed_out"], "command": run["cmd"],
                                "serial_tail": run["serial"][-3000:], "proxy": run["proxy"].stats if run["proxy"] else None}
        (out / mode / "serial-net.txt").write_text("\n".join(l for l in run["serial"].splitlines() if "T_NET" in l or "K64 net" in l))
    record["checks"] = ck.rows
    status = "PASS" if all(r["status"] in ("PASS", "BLOCKED") for r in ck.rows) else "FAIL"
    record["status"] = status
    shzlib.write_json(out / "result.json", record)
    blocked = [r for r in ck.rows if r["status"] == "BLOCKED"]
    print(f"{status}" + (f"  ({len(blocked)} check(s) BLOCKED by the environment)" if blocked else ""))
    if status != "PASS":
        for mode, r in record["runs"].items():
            print(f"---- {mode} serial tail ----\n{r['serial_tail'][-1800:]}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
