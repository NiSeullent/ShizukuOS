/* SPDX-License-Identifier: GPL-2.0-only
 * Original NTWin32Wrapper9x WIN64 subsystem client (see ntw64.h). Stock Win98 imports only, no CRT.
 *
 * Model: one synchronous request at a time (callers serialize; NTW64RUN.EXE is single-threaded). A request
 * frame goes to the VxD (W64_SEND); the reply and any one-way frames (CONSOLE_OUTPUT, PROCESS_EXITED) are
 * pulled with W64_RECV and sorted into per-process records here. Console output is acknowledged as the
 * application consumes it, which is what throttles Kernel64 (SHZ_W64_CONSOLE_WINDOW unacknowledged frames).
 * Polling uses Sleep(1) between empty W64_RECV calls, like the rest of this runtime; W64_WAIT is advisory in
 * this VxD revision.
 *
 * Native imports added by this file: CreateFileA, DeviceIoControl, GetLastError (plus the existing Sleep,
 * GetTickCount and SetLastError). */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include "ntw64.h"
#include "../../ntwrapper/vxd/bridge.h"

static void ntw_copy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static void ntw_zero(void *d, int c, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)c; }
#define SHZ_IPC_MEMCPY(d, s, n) ntw_copy((d), (s), (n))
#define SHZ_IPC_MEMSET(d, c, n) ntw_zero((d), (c), (n))
#include "../../shizukudos/abi/shz_ipc.h"

typedef char info_matches_header[(sizeof(ntw64_info_t) == NTW64_INFO_SIZE) ? 1 : -1];

#define NTW64_MAX_RECORDS 8u
#define NTW64_FIFO 16384u
#define NTW64_HANDLE_TAG 0x57340000u
#define NTW64_HANDLE_GEN_MAX 0x1fffu
#define NTW64_CALL_TIMEOUT_MS 5000u
#define NTW64_TRANSPORT (-1000)             /* last_status: the VxD refused the request, see GetLastError() */

struct record {
    int used;
    int closed;                         /* handle closed while the process ran: output discarded, released on EXITED */
    uint32_t gen;                       /* per-record 13-bit generation; retain on close and retire at the maximum */
    uint32_t pid, state;
    uint8_t fifo[NTW64_FIFO];
    uint32_t head, tail;                /* head - tail = bytes queued for the application */
    uint32_t seq_received, seq_acked;
    int exited, stdin_closed;
    int32_t exit_code;
    uint32_t fault_status, dropped;
};

static struct record records[NTW64_MAX_RECORDS];
static HANDLE device = INVALID_HANDLE_VALUE;
static int opened;
static struct ntwv_w64_open vxd_info;
static uint64_t next_request_id = 0x100;
static int32_t last_status;
static uint8_t frame[NTWV_W64_SEND_MAX], slot[SHZ_MSG_SLOT_SIZE];

static BOOL fail(DWORD error) { SetLastError(error); return FALSE; }

static DWORD win32_of_status(int32_t st)
{
    switch (st) {
    case SHZ_OK: return 0;
    case SHZ_E_INVALID: case SHZ_E_RANGE: case SHZ_E_PROTO: return ERROR_INVALID_PARAMETER;
    case SHZ_E_NOENT: return ERROR_FILE_NOT_FOUND;
    case SHZ_E_BUSY: case SHZ_E_QUEUE_FULL: return ERROR_BUSY;
    case SHZ_E_TIMEOUT: return NTW64_ERROR_TIMEOUT;
    case SHZ_E_NOMEM: return ERROR_NOT_ENOUGH_MEMORY;
    case SHZ_E_UNSUPPORTED: return ERROR_NOT_SUPPORTED;
    case SHZ_E_DENIED: return ERROR_ACCESS_DENIED;
    default: return ERROR_GEN_FAILURE;
    }
}

static DWORD win32_of_ntstatus(int32_t st)
{
    switch ((uint32_t)st) {
    case 0xC0000034u: case 0xC000003Au: case 0xC000000Fu: return ERROR_FILE_NOT_FOUND;   /* name/path not found */
    case 0xC000007Bu: case 0xC0000135u: case 0xC0000139u: return ERROR_BAD_EXE_FORMAT;   /* image/DLL/entry problems */
    case 0xC0000017u: return ERROR_NOT_ENOUGH_MEMORY;
    default: return ERROR_GEN_FAILURE;
    }
}

/* ---------------------------------------------------------------- VxD transport */
static BOOL ensure_open(void)
{
    DWORD returned = 0;
    if (opened)
        return TRUE;
    if (device == INVALID_HANDLE_VALUE) {
        /* Dynamic load by module name (Windows\System or the search path). The earlier guest trial of the
         * absolute-path form failed in the loader: docs/VXD_LOADER_TRIAGE.md. */
        device = CreateFileA("\\\\.\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (device == INVALID_HANDLE_VALUE)
            return FALSE;                       /* the loader's error stands */
    }
    if (!DeviceIoControl(device, NTWV_IOCTL_W64_OPEN, NULL, 0, &vxd_info, sizeof vxd_info, &returned, NULL))
        return FALSE;                           /* 50: no Supervisor, 55: no Kernel64 channel, ... (bridge.h) */
    if (returned != sizeof vxd_info || vxd_info.magic != NTWV_W64_MAGIC || vxd_info.abi_major != SHZ_ABI_MAJOR)
        return fail(ERROR_REVISION_MISMATCH);
    opened = 1;
    return TRUE;
}

static int pump(uint64_t want_id, shz_msg_hdr_t *reply, uint8_t *reply_payload);

/* One W64_SEND. `retry`: while the VxD reports a full ring or four outstanding pool blocks (ERROR_BUSY), keep
 * draining incoming frames (which frees both) until the call deadline. Acknowledgements never retry: they are
 * sent from inside the drain loop and are simply attempted again with the next frame. */
static BOOL vxd_send(shz_msg_hdr_t *h, const void *payload, const void *extra, uint32_t extra_bytes, int retry)
{
    const DWORD start = GetTickCount();
    DWORD total = (DWORD)sizeof *h + h->payload_length + extra_bytes;
    if (h->payload_length > SHZ_MSG_MAX_INLINE || total > NTWV_W64_SEND_MAX)
        return fail(ERROR_INVALID_PARAMETER);
    for (;;) {
        DWORD returned = 0;
        int32_t status = 0;
        shz_msg_hdr_t unused;
        uint8_t unused_payload[SHZ_MSG_MAX_INLINE];
        ntw_copy(frame, h, sizeof *h);
        if (h->payload_length) ntw_copy(frame + sizeof *h, payload, h->payload_length);
        if (extra_bytes) ntw_copy(frame + sizeof *h + h->payload_length, extra, extra_bytes);
        if (DeviceIoControl(device, NTWV_IOCTL_W64_SEND, frame, total, &status, sizeof status, &returned, NULL)) {
            if (returned != sizeof status || status != SHZ_OK)
                return fail(win32_of_status(status));
            return TRUE;
        }
        if (!retry || GetLastError() != NTWV_ERROR_BUSY)
            return FALSE;
        if (GetTickCount() - start >= NTW64_CALL_TIMEOUT_MS)
            return fail(NTW64_ERROR_TIMEOUT);
        if (pump(0, &unused, unused_payload) < 0)
            return FALSE;
        Sleep(1);
    }
}

/* One frame from the VxD: 1 with the header and payload, 0 when nothing is queued, -1 on a transport error
 * (LastError set). */
static int vxd_recv(shz_msg_hdr_t *h, uint8_t *payload)
{
    DWORD returned = 0;
    if (!DeviceIoControl(device, NTWV_IOCTL_W64_RECV, NULL, 0, slot, sizeof slot, &returned, NULL))
        return GetLastError() == NTWV_ERROR_NO_MORE_ITEMS ? 0 : -1;
    if (returned != sizeof slot) {
        SetLastError(ERROR_GEN_FAILURE);
        return -1;
    }
    ntw_copy(h, slot, sizeof *h);
    if (h->payload_length > SHZ_MSG_MAX_INLINE) {
        SetLastError(ERROR_GEN_FAILURE);
        return -1;
    }
    ntw_copy(payload, slot + sizeof *h, SHZ_MSG_MAX_INLINE);
    return 1;
}

/* ---------------------------------------------------------------- records */
static struct record *record_of(HANDLE handle)
{
    const uintptr_t v = (uintptr_t)handle;
    struct record *r;
    if ((v & 0xffff0000u) != NTW64_HANDLE_TAG || (v & 7u) >= NTW64_MAX_RECORDS)
        return NULL;
    r = &records[v & 7u];
    return r->used && !r->closed && r->gen == ((v >> 3) & NTW64_HANDLE_GEN_MAX) ? r : NULL;
}

static HANDLE handle_of(const struct record *r)
{
    return (HANDLE)(uintptr_t)(NTW64_HANDLE_TAG | (r->gen << 3) | (uint32_t)(r - records));
}

static struct record *record_by_pid(uint32_t pid)
{
    unsigned i;
    for (i = 0; i < NTW64_MAX_RECORDS; ++i)
        if (records[i].used && records[i].pid == pid) return &records[i];
    return NULL;
}

static BOOL send_oneway(uint32_t opcode, const void *payload, uint16_t len)
{
    shz_msg_hdr_t h;
    ntw_zero(&h, 0, sizeof h);
    h.flags = SHZ_MSGF_ONEWAY;
    h.opcode = opcode;
    h.payload_length = len;
    return vxd_send(&h, payload, NULL, 0, 0);
}

/* Acknowledges received console frames whenever the queue can take another full window, so Kernel64 never has a
 * frame in flight that would not fit. A closed record's output is discarded, so it is always acknowledged. */
static void maybe_ack(struct record *r)
{
    if (r->seq_received > r->seq_acked &&
        (r->closed || NTW64_FIFO - (r->head - r->tail) >= SHZ_W64_CONSOLE_WINDOW * SHZ_W64_CONSOLE_CHUNK)) {
        shz_w64_console_t c;
        ntw_zero(&c, 0, sizeof c);
        c.pid = r->pid;
        c.seq = r->seq_received;
        if (send_oneway(SHZ_OP_W64_CONSOLE_ACK, &c, sizeof c))
            r->seq_acked = r->seq_received;
    }
}

static void deliver_oneway(const shz_msg_hdr_t *h, const uint8_t *payload)
{
    if (h->opcode == SHZ_OP_W64_CONSOLE_OUTPUT) {
        shz_w64_console_t c;
        struct record *r;
        uint32_t k;
        if (shz_w64_console_check(h, payload, &c) != SHZ_OK || !(r = record_by_pid(c.pid)) || r->exited)
            return;
        if (c.seq != r->seq_received + 1)
            return;                                 /* out of order or duplicate: the sender is not trusted */
        if (r->closed) {
            /* nobody reads it any more */
        } else if (NTW64_FIFO - (r->head - r->tail) < c.length) {
            r->dropped += c.length;                 /* only possible if the peer ignores the window */
        } else {
            for (k = 0; k < c.length; ++k)
                r->fifo[(r->head + k) % NTW64_FIFO] = payload[sizeof c + k];
            r->head += c.length;
        }
        r->seq_received = c.seq;
    } else if (h->opcode == SHZ_OP_W64_PROCESS_EXITED && h->payload_length == sizeof(shz_w64_event_t)) {
        shz_w64_event_t ev;
        struct record *r;
        ntw_copy(&ev, payload, sizeof ev);
        if (!(r = record_by_pid(ev.pid)) || r->exited)
            return;
        r->exited = 1;
        r->state = ev.state;
        r->exit_code = (int32_t)ev.exit_code;
        r->fault_status = ev.fault_status;
        r->dropped += ev.console_dropped;
    }
}

/* Pulls queued frames until the ring is empty (0) or the reply for `want_id` arrives (1, returned instead of
 * delivered); -1 on a transport error. Every record gets its acknowledgement afterwards. */
static int pump(uint64_t want_id, shz_msg_hdr_t *reply, uint8_t *reply_payload)
{
    shz_msg_hdr_t h;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int got, result = 0;
    unsigned i;
    while ((got = vxd_recv(&h, payload)) > 0) {
        if (h.flags & SHZ_MSGF_REPLY) {
            if (want_id && h.request_id == want_id) {
                *reply = h;
                ntw_copy(reply_payload, payload, sizeof payload);
                result = 1;
                break;
            }
            continue;                               /* late reply to an abandoned request */
        }
        if (h.flags & SHZ_MSGF_ONEWAY)
            deliver_oneway(&h, payload);
    }
    if (got < 0)
        result = -1;
    for (i = 0; i < NTW64_MAX_RECORDS; ++i)
        if (records[i].used && !records[i].exited)
            maybe_ack(&records[i]);
    return result;
}

/* Synchronous request: sends, then pumps until the matching reply or the deadline. last_status receives the
 * reply's SHZ status (or NTW64_TRANSPORT / SHZ_E_TIMEOUT). */
static BOOL call(uint32_t opcode, const void *payload, uint16_t len, const void *extra, uint32_t extra_bytes,
                 shz_msg_hdr_t *reply, uint8_t *reply_payload)
{
    shz_msg_hdr_t h;
    DWORD start;
    ntw_zero(&h, 0, sizeof h);
    h.opcode = opcode;
    h.request_id = next_request_id++;
    h.payload_length = len;
    last_status = NTW64_TRANSPORT;
    if (!vxd_send(&h, payload, extra, extra_bytes, 1))
        return FALSE;
    start = GetTickCount();
    for (;;) {
        const int got = pump(h.request_id, reply, reply_payload);
        if (got > 0) {
            last_status = reply->status;
            return reply->status == SHZ_OK ? TRUE : fail(win32_of_status(reply->status));
        }
        if (got < 0)
            return FALSE;
        if (GetTickCount() - start >= NTW64_CALL_TIMEOUT_MS) {
            last_status = SHZ_E_TIMEOUT;
            return fail(NTW64_ERROR_TIMEOUT);
        }
        Sleep(1);
    }
}

/* Records whose handle was closed while the process ran are released once its EXITED event has arrived. Runs at
 * API entry only, never from inside a pump. */
static void release_closed(void)
{
    unsigned i;
    for (i = 0; i < NTW64_MAX_RECORDS; ++i) {
        struct record *r = &records[i];
        shz_w64_kill_t k;
        shz_msg_hdr_t reply;
        uint8_t reply_payload[SHZ_MSG_MAX_INLINE];
        if (!r->used || !r->closed || !r->exited)
            continue;
        k.pid = r->pid;
        k.exit_code = 0;
        if (call(SHZ_OP_W64_RELEASE, &k, sizeof k, NULL, 0, &reply, reply_payload) || last_status == SHZ_E_NOENT)
            r->used = 0;
    }
}

static uint32_t wlen(LPCWSTR s) { uint32_t n = 0; while (s && s[n]) ++n; return n; }

/* ---------------------------------------------------------------- exported API */
BOOL WINAPI NtwQuerySubsystem64(ntw64_info_t *info)
{
    shz_msg_hdr_t reply;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    shz_w64_info_t w;
    if (!info) return fail(ERROR_INVALID_PARAMETER);
    if (!ensure_open()) return FALSE;
    release_closed();
    if (!call(SHZ_OP_W64_QUERY, NULL, 0, NULL, 0, &reply, payload)) return FALSE;
    if (reply.payload_length != sizeof w) return fail(ERROR_GEN_FAILURE);
    ntw_copy(&w, payload, sizeof w);
    /* refresh the VxD counters (the OPEN control is idempotent once the channel is mapped) */
    {
        DWORD returned = 0;
        struct ntwv_w64_open now;
        if (DeviceIoControl(device, NTWV_IOCTL_W64_OPEN, NULL, 0, &now, sizeof now, &returned, NULL) &&
            returned == sizeof now && now.magic == NTWV_W64_MAGIC)
            vxd_info = now;
    }
    ntw_zero(info, 0, sizeof *info);
    info->size = NTW64_INFO_SIZE;
    info->abi_major = w.abi_major;
    info->abi_minor = w.abi_minor;
    info->subsystem_version = w.subsystem_version;
    info->capabilities = w.capabilities;
    info->max_processes = w.max_processes;
    info->active_processes = w.active_processes;
    info->console_window = w.console_window;
    info->console_chunk = w.console_chunk;
    info->channel_id = vxd_info.channel_id;
    info->generation = vxd_info.generation;
    info->vxd_sent = vxd_info.sent;
    info->vxd_received = vxd_info.received;
    info->vxd_proto_errors = vxd_info.proto_errors;
    return TRUE;
}

BOOL WINAPI NtwCreateProcess64W(LPCWSTR path, LPCWSTR cmdline, LPCWSTR cwd, HANDLE *handle)
{
    static uint16_t block[SHZ_W64_MAX_ARGS_BYTES / 2];
    static uint8_t payload[SHZ_MSG_MAX_INLINE];
    shz_w64_create_t ch;
    shz_msg_hdr_t reply;
    uint8_t reply_payload[SHZ_MSG_MAX_INLINE];
    shz_w64_event_t ev;
    struct record *r = NULL;
    unsigned i;
    uint32_t bytes, generation;
    int needs_pool = 0;
    if (!handle) return fail(ERROR_INVALID_PARAMETER);
    *handle = NULL;
    if (!path || !path[0]) return fail(ERROR_INVALID_PARAMETER);
    bytes = shz_w64_create_pack(&ch, (const uint16_t *)path, wlen(path), (const uint16_t *)cmdline, wlen(cmdline),
                                (const uint16_t *)cwd, wlen(cwd), block, SHZ_W64_MAX_ARGS_BYTES / 2, &needs_pool);
    if (!bytes) return fail(ERROR_INVALID_PARAMETER);
    if (needs_pool && sizeof(shz_msg_hdr_t) + sizeof ch + bytes > NTWV_W64_SEND_MAX)
        return fail(ERROR_INVALID_PARAMETER);       /* 4,016 argument bytes per SEND through the VxD */
    if (!ensure_open()) return FALSE;
    release_closed();
    for (i = 0; i < NTW64_MAX_RECORDS; ++i)
        if (!records[i].used && records[i].gen < NTW64_HANDLE_GEN_MAX) { r = &records[i]; break; }
    /* Retired records cannot name another process. Refuse exhaustion before
     * sending CREATE, so no remote process is launched without a local handle. */
    if (!r) return fail(ERROR_TOO_MANY_OPEN_FILES);
    ntw_copy(payload, &ch, sizeof ch);
    if (needs_pool) {
        if (!call(SHZ_OP_W64_CREATE_PROCESS, payload, sizeof ch, block, bytes, &reply, reply_payload)) return FALSE;
    } else {
        ntw_copy(payload + sizeof ch, block, bytes);
        if (!call(SHZ_OP_W64_CREATE_PROCESS, payload, (uint16_t)(sizeof ch + bytes), NULL, 0, &reply, reply_payload))
            return FALSE;
    }
    if (reply.payload_length != sizeof ev) return fail(ERROR_GEN_FAILURE);
    ntw_copy(&ev, reply_payload, sizeof ev);
    if (ev.state != SHZ_W64_PS_STARTED || ev.pid == 0)
        return fail(win32_of_ntstatus(ev.status));
    generation = r->gen + 1;              /* failed CREATE/RELEASE never resets this history */
    ntw_zero(r, 0, sizeof *r);
    r->used = 1;
    r->gen = generation;
    r->pid = ev.pid;
    r->state = ev.state;
    *handle = handle_of(r);
    return TRUE;
}

BOOL WINAPI NtwReadConsole64(HANDLE handle, void *buffer, DWORD capacity, DWORD *got)
{
    struct record *r = record_of(handle);
    shz_msg_hdr_t unused;
    uint8_t unused_payload[SHZ_MSG_MAX_INLINE];
    if (got) *got = 0;
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    if (!buffer || !got || !capacity) return fail(ERROR_INVALID_PARAMETER);
    for (;;) {
        uint32_t avail = r->head - r->tail, k;
        if (avail) {
            if (avail > capacity) avail = capacity;
            for (k = 0; k < avail; ++k)
                ((uint8_t *)buffer)[k] = r->fifo[(r->tail + k) % NTW64_FIFO];
            r->tail += avail;
            *got = avail;
            if (!r->exited)
                maybe_ack(r);
            return TRUE;
        }
        if (r->exited) return fail(NTW64_ERROR_HANDLE_EOF);
        if (pump(0, &unused, unused_payload) < 0) return FALSE;
        if (r->head == r->tail && !r->exited)
            Sleep(1);
    }
}

BOOL WINAPI NtwWriteConsole64(HANDLE handle, const void *buffer, DWORD bytes, DWORD *written)
{
    struct record *r = record_of(handle);
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    shz_msg_hdr_t reply;
    uint8_t reply_payload[SHZ_MSG_MAX_INLINE];
    DWORD done = 0;
    if (written) *written = 0;
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    if ((!buffer && bytes) || r->stdin_closed) return fail(ERROR_INVALID_PARAMETER);
    if (r->exited) return fail(ERROR_BROKEN_PIPE);
    while (done < bytes) {
        shz_w64_console_t c;
        const uint32_t n = bytes - done > SHZ_W64_CONSOLE_CHUNK ? SHZ_W64_CONSOLE_CHUNK : bytes - done;
        const DWORD start = GetTickCount();
        ntw_zero(&c, 0, sizeof c);
        c.pid = r->pid;
        c.length = (uint16_t)n;
        ntw_copy(payload, &c, sizeof c);
        ntw_copy(payload + sizeof c, (const uint8_t *)buffer + done, n);
        while (!call(SHZ_OP_W64_CONSOLE_INPUT, payload, (uint16_t)(sizeof c + n), NULL, 0, &reply, reply_payload)) {
            if (written) *written = done;
            if (r->exited || last_status == SHZ_E_NOENT)
                return fail(ERROR_BROKEN_PIPE);         /* the process ended (its EXITED may still be in flight) */
            /* QUEUE_FULL: the process has not drained its stdin queue yet */
            if (last_status != SHZ_E_QUEUE_FULL || GetTickCount() - start >= NTW64_CALL_TIMEOUT_MS)
                return FALSE;
            Sleep(1);
        }
        done += n;
    }
    if (written) *written = done;
    return TRUE;
}

BOOL WINAPI NtwCloseConsole64(HANDLE handle)
{
    struct record *r = record_of(handle);
    shz_w64_console_t c;
    shz_msg_hdr_t reply;
    uint8_t reply_payload[SHZ_MSG_MAX_INLINE];
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    if (r->stdin_closed) return TRUE;
    if (r->exited) { r->stdin_closed = 1; return TRUE; }
    ntw_zero(&c, 0, sizeof c);
    c.pid = r->pid;
    c.flags = SHZ_W64_CONF_EOF;
    if (!call(SHZ_OP_W64_CONSOLE_INPUT, &c, sizeof c, NULL, 0, &reply, reply_payload) && last_status != SHZ_E_NOENT)
        return FALSE;                               /* NOENT: the process already ended, its stdin with it */
    r->stdin_closed = 1;
    return TRUE;
}

BOOL WINAPI NtwWaitProcess64(HANDLE handle, DWORD timeout_ms, DWORD *exit_code)
{
    struct record *r = record_of(handle);
    const DWORD start = GetTickCount();
    shz_msg_hdr_t unused;
    uint8_t unused_payload[SHZ_MSG_MAX_INLINE];
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    while (!r->exited) {
        if (pump(0, &unused, unused_payload) < 0) return FALSE;
        if (r->exited) break;
        if (timeout_ms != INFINITE && GetTickCount() - start >= timeout_ms) return fail(NTW64_ERROR_TIMEOUT);
        Sleep(1);
    }
    if (exit_code) *exit_code = (DWORD)r->exit_code;
    return TRUE;
}

BOOL WINAPI NtwKillProcess64(HANDLE handle, DWORD exit_code)
{
    struct record *r = record_of(handle);
    shz_w64_kill_t k;
    shz_msg_hdr_t reply;
    uint8_t reply_payload[SHZ_MSG_MAX_INLINE];
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    k.pid = r->pid;
    k.exit_code = (int32_t)exit_code;
    return call(SHZ_OP_W64_KILL_PROCESS, &k, sizeof k, NULL, 0, &reply, reply_payload);
}

BOOL WINAPI NtwCloseProcess64(HANDLE handle)
{
    struct record *r = record_of(handle);
    shz_w64_kill_t k;
    shz_msg_hdr_t reply;
    uint8_t reply_payload[SHZ_MSG_MAX_INLINE];
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    if (!r->exited) {                               /* like closing a process handle: the process keeps running */
        r->closed = 1;
        r->head = r->tail = 0;
        return TRUE;
    }
    k.pid = r->pid;
    k.exit_code = 0;
    if (!call(SHZ_OP_W64_RELEASE, &k, sizeof k, NULL, 0, &reply, reply_payload) && last_status != SHZ_E_NOENT)
        return FALSE;
    r->used = 0;
    return TRUE;
}

/* ---------------------------------------------------------------- NTW32-internal GUI transport (not exported)
 * ntw64_gui.c reuses this file's single serialized call()/pump() and record table: the HANDLE must be a live,
 * not-closed record of this generation; its pid is written into the request selector (offset 8). The reply must
 * echo the opcode, carry no pool buffer and have exactly `want_len` bytes. */
BOOL ntw64_gui_transact(HANDLE handle, uint32_t opcode, uint8_t *payload, uint16_t len, uint8_t *reply_payload,
                        uint16_t want_len, int32_t *status)
{
    struct record *r = record_of(handle);
    shz_msg_hdr_t reply;
    *status = NTW64_TRANSPORT;
    if (!r || r->closed) return fail(NTW64_ERROR_INVALID_HANDLE);
    if (len < 12u || len > SHZ_MSG_MAX_INLINE || !payload || !reply_payload) return fail(ERROR_INVALID_PARAMETER);
    if (!ensure_open()) return FALSE;
    ntw_copy(payload + 8, &r->pid, 4);
    if (!call(opcode, payload, len, NULL, 0, &reply, reply_payload)) { *status = last_status; return FALSE; }
    *status = last_status;
    if (reply.opcode != opcode || (reply.flags & SHZ_MSGF_BUFFER) || reply.buffer_length || reply.payload_length != want_len) {
        *status = SHZ_E_PROTO;
        return fail(ERROR_INVALID_DATA);
    }
    return TRUE;
}

/* Drains pending frames once and reports whether the process behind `handle` has exited. */
BOOL ntw64_gui_poll_exit(HANDLE handle, int *exited, DWORD *exit_code)
{
    struct record *r = record_of(handle);
    shz_msg_hdr_t unused;
    uint8_t unused_payload[SHZ_MSG_MAX_INLINE];
    if (!r) return fail(NTW64_ERROR_INVALID_HANDLE);
    if (!r->exited && pump(0, &unused, unused_payload) < 0) return FALSE;
    *exited = r->exited;
    if (r->exited && exit_code) *exit_code = (DWORD)r->exit_code;
    return TRUE;
}
