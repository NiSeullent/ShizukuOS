/* SPDX-License-Identifier: GPL-2.0-only
 * T_IPC_STRESS: a parent serves NCHILD child processes over overlapped named pipes driven by one I/O completion port, while
 * parent and children share counters through a named section. Mid-run the parent kills one child (blocked in a pipe read,
 * with a second thread spinning and the section mapped) with TerminateProcess; the others run to completion. Every
 * completion must arrive within a timeout (no hang), the killed child's pipe must report ERROR_BROKEN_PIPE, the counters
 * in the section must agree with what the parent received, and after several rounds the kernel must be back to where it
 * started: no pipes, IRPs, completion packets, sections, views or thread slots left, heap and pages within a small margin.
 *
 * Expected behaviour is Win32's: a completion port delivers one packet per finished overlapped request with the handle's
 * key; a pipe whose client process died completes the server's read with ERROR_BROKEN_PIPE; GetExitCodeProcess reports
 * the TerminateProcess code. */
#include "ipc_test.h"

#define NCHILD 4
#define MSGS 150                /* requests each surviving child sends */
#define ROUNDS 5
#define VICTIM 1                /* the child killed mid-run */
#define KILL_AFTER 30           /* requests of the victim served before it is killed */
#define KILL_CODE 0xDEADu
#define MAGIC 0x51A7u

typedef struct { unsigned idx, seq, magic, check; } msg_t;                 /* 16 bytes each way */
typedef struct { volatile LONG sent, acked, spins, pad; } slot_t;          /* one per child in the shared section */

static void names(WCHAR *pipe, WCHAR *section, unsigned ppid, unsigned round, unsigned idx)
{
    char a[96];
    snprintf(a, sizeof a, "\\\\.\\pipe\\ipcstress_%u_%u_%u", ppid, round, idx);
    wcopy(pipe, a);
    snprintf(a, sizeof a, "Local\\ipcstress_%u_%u", ppid, round);
    wcopy(section, a);
}

/* ---------------------------------------------------------------- child */
static volatile LONG *g_spin_counter;
static DWORD WINAPI spin_thread(LPVOID p)
{
    (void)p;
    for (;;) InterlockedIncrement(g_spin_counter);
    return 0;
}

static int read_full(HANDLE h, void *buf, DWORD len)
{
    DWORD got = 0, n;
    while (got < len) {
        if (!ReadFile(h, (char *)buf + got, len - got, &n, 0) || !n) return 0;
        got += n;
    }
    return 1;
}

static int child_worker(unsigned ppid, unsigned round, unsigned idx)
{
    WCHAR pname[96], sname[64];
    HANDLE pipe, map;
    slot_t *slots;
    unsigned seq;
    names(pname, sname, ppid, round, idx);
    if (!WaitNamedPipeW(pname, 10000)) return 10;
    pipe = CreateFileW(pname, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (pipe == INVALID_HANDLE_VALUE) return 11;
    map = OpenFileMappingW(FILE_MAP_WRITE, FALSE, sname);
    if (!map) return 12;
    slots = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
    if (!slots) return 13;
    if (idx == VICTIM) {                                        /* a second thread keeps running until the kill */
        g_spin_counter = &slots[idx].spins;
        if (!CreateThread(0, 0, spin_thread, 0, 0, 0)) return 14;
    }
    for (seq = 0; idx == VICTIM || seq < MSGS; ++seq) {
        msg_t m = { idx, seq, MAGIC, idx ^ seq ^ MAGIC }, r;
        DWORD n;
        slots[idx].sent = (LONG)(seq + 1);
        if (!WriteFile(pipe, &m, sizeof m, &n, 0) || n != sizeof m) return 20;
        if (!read_full(pipe, &r, sizeof r)) return 21;          /* the victim is killed while it waits here */
        if (r.idx != idx || r.seq != seq || r.magic != ~MAGIC || r.check != (idx ^ seq ^ ~MAGIC)) return 22;
        slots[idx].acked = (LONG)(seq + 1);
    }
    UnmapViewOfFile(slots);
    CloseHandle(map);
    CloseHandle(pipe);
    return 0;
}

/* ---------------------------------------------------------------- parent */
typedef struct {
    HANDLE pipe, proc;
    OVERLAPPED ov_conn, ov_read, ov_write;
    msg_t in, out;
    DWORD have;                 /* bytes of `in` received so far */
    unsigned expect;            /* next sequence number */
    int done, broken, killed;
} peer_t;

/* 1: a completion packet will come (pending, or completed at once with success). 0: the request failed at once - as on
 * Windows no packet is queued for that - e.g. ERROR_BROKEN_PIPE when the client end is already closed. */
static int start_read(peer_t *c)
{
    memset(&c->ov_read, 0, sizeof c->ov_read);
    if (ReadFile(c->pipe, (char *)&c->in + c->have, sizeof c->in - c->have, 0, &c->ov_read)) return 1;
    if (GetLastError() == ERROR_IO_PENDING) return 1;
    c->broken = GetLastError() == ERROR_BROKEN_PIPE;
    return 0;
}

/* One round; returns the number of failed checks. */
static int run_round(unsigned round, unsigned *served)
{
    peer_t peers[NCHILD];
    WCHAR pname[96], sname[64];
    HANDLE map, port;
    slot_t *slots;
    unsigned i, active = 0, hangs = 0, bad_msgs = 0, bad_order = 0;
    const unsigned ppid = (unsigned)GetCurrentProcessId();
    const int bad0 = g_bad;
    char args[64];
    memset(peers, 0, sizeof peers);
    names(pname, sname, ppid, round, 0);
    map = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 4096, sname);
    slots = map ? MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0) : 0;
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
    if (!slots || !port) { CHECK(0, "round %u: section and completion port", round); return g_bad - bad0; }
    for (i = 0; i < NCHILD; ++i) {
        peer_t *c = &peers[i];
        names(pname, sname, ppid, round, i);
        c->pipe = CreateNamedPipeW(pname, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   1, 4096, 4096, 0, 0);
        if (c->pipe == INVALID_HANDLE_VALUE || CreateIoCompletionPort(c->pipe, port, i, 0) != port) {
            CHECK(0, "round %u: pipe %u created and bound to the port", round, i);
            continue;
        }
        if (!ConnectNamedPipe(c->pipe, &c->ov_conn)) {
            if (GetLastError() == ERROR_PIPE_CONNECTED) PostQueuedCompletionStatus(port, 0, i, &c->ov_conn);
            else if (GetLastError() != ERROR_IO_PENDING) { CHECK(0, "round %u: ConnectNamedPipe %u", round, i); continue; }
        }
        snprintf(args, sizeof args, "worker %u %u %u", ppid, round, i);
        c->proc = ipc_spawn_self(args, 0, FALSE, 0, 0);
        if (!c->proc) { CHECK(0, "round %u: child %u started", round, i); continue; }
        ++active;
    }
    while (active) {
        DWORD n = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED ov = 0;
        BOOL ok = GetQueuedCompletionStatus(port, &n, &key, &ov, 15000);
        const DWORD err = ok ? 0 : GetLastError();
        peer_t *c;
        if (!ov) {                                              /* no completion within 15 s: something hangs */
            ++hangs;
            for (i = 0; i < NCHILD; ++i)
                if (!peers[i].done)
                    printf("  round %u: peer %u still active: %u served, %u bytes pending, child sent %d acked %d\n", round, i,
                           peers[i].expect, (unsigned)peers[i].have, (int)slots[i].sent, (int)slots[i].acked);
            break;
        }
        if (key >= NCHILD) { ++bad_msgs; continue; }
        c = &peers[key];
        if (ov == &c->ov_conn) {
            if (!ok) { c->done = 1; --active; continue; }
            if (!start_read(c)) { c->done = 1; --active; }
        } else if (ov == &c->ov_read) {
            if (!ok) {                                          /* the client end closed: done, or killed */
                c->broken = err == ERROR_BROKEN_PIPE;
                c->done = 1;
                --active;
                continue;
            }
            c->have += n;
            if (c->have < sizeof c->in) { if (!start_read(c)) { c->done = 1; --active; } continue; }
            c->have = 0;
            if (c->in.idx != (unsigned)key || c->in.magic != MAGIC || c->in.check != (c->in.idx ^ c->in.seq ^ MAGIC)) ++bad_msgs;
            if (c->in.seq != c->expect) ++bad_order;
            c->expect = c->in.seq + 1;
            ++*served;
            if (key == VICTIM && c->expect >= KILL_AFTER && !c->killed) {
                c->killed = TerminateProcess(c->proc, KILL_CODE);    /* no reply: the victim is blocked in ReadFile */
                if (!start_read(c)) { c->done = 1; --active; }
                continue;
            }
            c->out.idx = c->in.idx; c->out.seq = c->in.seq; c->out.magic = ~MAGIC; c->out.check = c->in.idx ^ c->in.seq ^ ~MAGIC;
            memset(&c->ov_write, 0, sizeof c->ov_write);
            if (!WriteFile(c->pipe, &c->out, sizeof c->out, 0, &c->ov_write) && GetLastError() != ERROR_IO_PENDING) {
                c->done = 1; --active;
            }
        } else if (ov == &c->ov_write) {
            if (!ok || n != sizeof c->out) ++bad_msgs;
            if (!start_read(c)) { c->done = 1; --active; }
        } else {
            ++bad_msgs;
        }
    }
    CHECK(!hangs, "round %u: every completion arrived within 15 s", round);
    CHECK(!bad_msgs && !bad_order, "round %u: requests intact and in order (%u bad, %u out of order)", round, bad_msgs, bad_order);
    for (i = 0; i < NCHILD; ++i) {
        peer_t *c = &peers[i];
        DWORD code = 0xffffffffu;
        if (!c->proc) continue;
        if (WaitForSingleObject(c->proc, 20000) == WAIT_OBJECT_0) GetExitCodeProcess(c->proc, &code);
        if (i == VICTIM) {
            CHECK(c->killed && code == KILL_CODE, "round %u: the victim was killed mid-run (exit 0x%x)", round, (unsigned)code);
            CHECK(c->broken, "round %u: its pipe reported ERROR_BROKEN_PIPE to the server", round);
            CHECK(slots[i].acked + 1 >= (LONG)c->expect && slots[i].acked <= (LONG)c->expect && slots[i].spins > 0,
                  "round %u: its section counters agree (acked %d of %u served, %u spins)", round, (int)slots[i].acked,
                  c->expect, (unsigned)slots[i].spins);
        } else if (code != 0 || c->expect != MSGS || slots[i].acked != MSGS || slots[i].sent != MSGS) {
            CHECK(0, "round %u: child %u exit %u, %u served, section sent %d acked %d (want 0, %u)", round, i, (unsigned)code,
                  c->expect, (int)slots[i].sent, (int)slots[i].acked, MSGS);
        }
        CloseHandle(c->proc);
    }
    for (i = 0; i < NCHILD; ++i) if (peers[i].pipe && peers[i].pipe != INVALID_HANDLE_VALUE) CloseHandle(peers[i].pipe);
    CloseHandle(port);
    UnmapViewOfFile(slots);
    CloseHandle(map);
    return g_bad - bad0;
}

int main(int argc, char **argv)
{
    kstats_t k0, k1;
    unsigned r, served = 0;
    int have0, have1, round_bad = 0;
    DWORD t0;
    if (argc >= 5 && !strcmp(argv[1], "worker")) return child_worker(ipc_atou(argv[2]), ipc_atou(argv[3]), ipc_atou(argv[4]));
    printf("T_IPC_STRESS: %d rounds of %d children over pipes + a completion port + a section, one killed per round\n",
           ROUNDS, NCHILD);
    have0 = kstats(&k0);
    t0 = GetTickCount();
    for (r = 0; r < ROUNDS; ++r) round_bad += run_round(r, &served);
    printf("  %u requests served in %u ms\n", served, (unsigned)(GetTickCount() - t0));
    CHECK(!round_bad, "%d rounds without a failed check", ROUNDS);
    CHECK(served >= ROUNDS * ((NCHILD - 1) * MSGS + KILL_AFTER), "%u requests served", served);
    have1 = kstats(&k1);
    CHECK(have0 && have1, "kernel statistics available");
    if (have0 && have1) {
        const long long dheap = (long long)k1.kheap_used - (long long)k0.kheap_used;
        const long long dpages = (long long)k0.pmm_free - (long long)k1.pmm_free;
        printf("  kernel: pipes %llu->%llu irps %llu->%llu packets %llu->%llu sections %llu->%llu views %llu->%llu threads "
               "%llu->%llu heap %lld pages %lld\n", k0.pipes, k1.pipes, k0.irps, k1.irps, k0.packets, k1.packets, k0.sections,
               k1.sections, k0.views, k1.views, k0.threads, k1.threads, dheap, dpages);
        CHECK(k1.pipes == k0.pipes && k1.irps == k0.irps && k1.packets == k0.packets, "no pipe, IRP or completion packet left");
        CHECK(k1.sections == k0.sections && k1.views == k0.views, "no section or view left");
        CHECK(k1.threads <= k0.threads, "no thread slot left (%llu -> %llu)", k0.threads, k1.threads);
        CHECK(dheap < 32768, "kernel heap back within 32 KiB (%lld bytes)", dheap);
        CHECK(dpages < 16, "physical pages back within 16 (%lld)", dpages);
    }
    printf("T_IPC_STRESS: %d failure(s)\n", g_bad);
    return g_bad;
}
