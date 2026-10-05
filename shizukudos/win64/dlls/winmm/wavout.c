/* SPDX-License-Identifier: GPL-2.0-only
 * winmm waveOut* over the ShizukuOS Core audio service (NtShzSound, shizukudos/abi/shz_audio.h).
 *
 * There is no emulated device. waveOutGetNumDevs is 1 only while Core QUERY reports an initialised AC97 function, else 0.
 * A WAVEHDR gets WHDR_DONE and WOM_DONE only when Core reports the write cookie(s) of that header completed (hardware
 * consumed the data) or aborted after a successful RESET; never from elapsed time or the queue timestamp.
 *
 * Each open stream owns one worker thread that submits queued headers in <=64 KiB pieces (the Core copies the data during
 * the call) and polls STATUS (<=50 ms wait, so it never parks in the kernel for long). Callbacks run on that worker:
 * CALLBACK_NULL, CALLBACK_EVENT (SetEvent) and CALLBACK_FUNCTION are supported; CALLBACK_WINDOW needs user32 already
 * loaded (PostMessageW) and is otherwise MMSYSERR_NOTSUPPORTED; CALLBACK_TASK is MMSYSERR_NOTSUPPORTED.
 * Limits: 4 open streams (Core grants one exclusive stream), 32 queued headers, header <= 8 MiB.
 */
#include "wavxp.h"
#include <string.h>

#define WO_SLOTS 4u
#define WO_QMAX 32u
#define WO_HDR_MAX (8u * 1024u * 1024u)
#define WO_CHUNK SHZ_SND_MAX_WRITE_BYTES
#define CALLBACK_TYPES_ (CALLBACK_WINDOW | CALLBACK_TASK | CALLBACK_FUNCTION | CALLBACK_EVENT)

typedef struct { WAVEHDR *hdr; uint32_t off; uint32_t pending; uint64_t seq; int done; } wq_t;

typedef struct wstream {
    int used;
    unsigned slot;
    uint32_t gen;
    uint64_t h;                         /* Core stream handle */
    unsigned ch, bits, rate, block;
    DWORD cbtype; DWORD_PTR cb, inst;
    HANDLE wake, thread;
    HMODULE mod;                /* loader reference owned by the worker */
    DWORD thread_id;
    volatile LONG closing;
    wq_t q[WO_QMAX];
    uint32_t head, count;
    uint64_t next_seq;
    uint64_t played_hw;
    NTSTATUS fault; DWORD fault_tick;
} wstream;

static CRITICAL_SECTION g_wl;
static int g_wl_init;
static wstream g_ws[WO_SLOTS];
static uint32_t g_gen = 1;

static HWAVEOUT enc(unsigned slot, uint32_t gen) { return (HWAVEOUT)(ULONG_PTR)(((ULONG_PTR)gen << 8) | (slot + 1)); }
/* caller holds g_wl */
static wstream *lookup(HWAVEOUT h)
{
    ULONG_PTR v = (ULONG_PTR)h;
    unsigned slot = (unsigned)(v & 0xff);
    if (!slot || slot > WO_SLOTS || (v >> 8) == 0 || (v >> 8) > 0xffffffffu) return 0;
    if (!g_ws[slot - 1].used || g_ws[slot - 1].gen != (uint32_t)(v >> 8)) return 0;
    return &g_ws[slot - 1];
}

static wq_t *qat(wstream *s, uint32_t i) { return &s->q[(s->head + i) % WO_QMAX]; }

/* ---------------------------------------------------------------- completion helpers (g_wl held) */
static void finish(wq_t *e)
{
    if (e->done) return;
    e->done = 1;
    e->hdr->dwFlags = (e->hdr->dwFlags & ~(DWORD)WHDR_INQUEUE) | WHDR_DONE;
}

static void settle(wq_t *e)         /* complete once everything accepted by Core is reported and nothing is left to send */
{
    if (!e->done && e->off >= e->hdr->dwBufferLength && e->pending == 0) finish(e);
}

static void abort_all(wstream *s)   /* only after Core confirmed RESET */
{
    uint32_t i;
    for (i = 0; i < s->count; ++i) { wq_t *e = qat(s, i); e->off = e->hdr->dwBufferLength; e->pending = 0; finish(e); }
}

static int drain_status(wstream *s)
{
    uint32_t round;
    shz_snd_status st;
    for (round = 0; round < 8; ++round) {
        uint32_t i, k;
        NTSTATUS rc = xp_status(s->h, &st);
        if (!NT_SUCCESS(rc)) { s->fault = rc; return 0; }
        s->played_hw = st.played_bytes;
        for (k = 0; k < st.cookie_count; ++k) {
            for (i = 0; i < s->count; ++i) {
                wq_t *e = qat(s, i);
                if (e->seq == st.cookies[k].cookie && e->pending) { --e->pending; settle(e); break; }
            }
        }
        if (st.flags & SHZ_SND_STF_FAULT) { s->fault = STATUS_DEVICE_NOT_READY; return 0; }
        if (!(st.flags & SHZ_SND_STF_MORE_COOKIES)) break;
    }
    return 1;
}

static void pump(wstream *s)
{
    uint32_t i;
    for (i = 0; i < s->count; ++i) {
        wq_t *e = qat(s, i);
        while (!e->done && e->off < e->hdr->dwBufferLength) {
            uint32_t rem = e->hdr->dwBufferLength - e->off, n = rem < WO_CHUNK ? rem : WO_CHUNK, acc, fl;
            NTSTATUS rc;
            if (!e->seq) e->seq = s->next_seq++;
            rc = xp_write(s->h, (const BYTE *)e->hdr->lpData + e->off, n, e->seq, &acc, &fl);
            if (rc == STATUS_DEVICE_BUSY) return;                       /* ring full */
            if (!NT_SUCCESS(rc)) {
                if (rc == STATUS_ACCESS_VIOLATION || rc == STATUS_INVALID_USER_BUFFER || rc == STATUS_INVALID_PARAMETER) {
                    e->off = e->hdr->dwBufferLength;                    /* unreadable data: nothing more can be sent */
                    settle(e);
                    break;
                }
                s->fault = rc;
                return;
            }
            if (acc) { e->off += acc; ++e->pending; }
            if (acc < n || (fl & SHZ_SND_WRITEF_QUEUE_FULL)) return;
            if (e->off >= e->hdr->dwBufferLength) { settle(e); }
        }
        settle(e);
    }
}

static void do_fault(wstream *s)
{
    DWORD now = GetTickCount();
    if (s->fault == 0 || now - s->fault_tick < 50) return;
    s->fault_tick = now;
    if (NT_SUCCESS(xp_reset(s->h))) { drain_status(s); abort_all(s); s->fault = 0; }
}

/* ---------------------------------------------------------------- notifications (called without g_wl) */
static void notify(wstream *s, UINT msg, DWORD_PTR p1)
{
    switch (s->cbtype) {
    case CALLBACK_EVENT: SetEvent((HANDLE)s->cb); break;
    case CALLBACK_FUNCTION: ((void (CALLBACK *)(HANDLE, UINT, DWORD_PTR, DWORD_PTR, DWORD_PTR))s->cb)(
                                (HANDLE)enc(s->slot, s->gen), msg, s->inst, p1, 0); break;
    case CALLBACK_WINDOW: {
        HMODULE u = GetModuleHandleW(L"user32.dll");
        BOOL (WINAPI *post)(HWND, UINT, WPARAM, LPARAM) = u ? (BOOL (WINAPI *)(HWND, UINT, WPARAM, LPARAM))GetProcAddress(u, "PostMessageW") : 0;
        if (post) post((HWND)s->cb, msg, (WPARAM)enc(s->slot, s->gen), (LPARAM)p1);
        break; }
    default: break;
    }
}

static DWORD WINAPI wave_thread(LPVOID p)
{
    wstream *s = p;
    for (;;) {
        WAVEHDR *done = 0;
        EnterCriticalSection(&g_wl);
        if (s->count) {
            if (s->fault) do_fault(s);
            if (!s->fault) { pump(s); if (s->count) drain_status(s); }
            if (s->count) {
                wq_t *e = qat(s, 0);
                if (e->done) { done = e->hdr; s->head = (s->head + 1) % WO_QMAX; --s->count; }
            }
        }
        if (!done && s->closing) { LeaveCriticalSection(&g_wl); break; }
        LeaveCriticalSection(&g_wl);
        if (done) { notify(s, WOM_DONE, (DWORD_PTR)done); continue; }
        WaitForSingleObject(s->wake, s->count ? 5 : 50);
    }
    xp_modexit(s->mod);         /* the slot is only cleared after this thread is signalled; s->mod is stable */
}

/* ---------------------------------------------------------------- API */
UINT shz_wave_numdevs(void)
{
    shz_snd_caps c;
    return xp_present(&c) ? 1u : 0u;
}

DLLAPI UINT WINAPI waveOutGetNumDevs(void) { return shz_wave_numdevs(); }

static DWORD formats_from_caps(const shz_snd_caps *c)
{
    static const struct { UINT rate_bit; DWORD m08, s08, m16, s16; } t[4] = {
        { SHZ_SND_RATE_11025, 0x1, 0x2, 0x4, 0x8 }, { SHZ_SND_RATE_22050, 0x10, 0x20, 0x40, 0x80 },
        { SHZ_SND_RATE_44100, 0x100, 0x200, 0x400, 0x800 }, { SHZ_SND_RATE_48000, 0x1000, 0x2000, 0x4000, 0x8000 } };
    DWORD f = 0;
    unsigned i;
    for (i = 0; i < 4; ++i) {
        if (!(c->rate_mask & t[i].rate_bit)) continue;
        if (c->bits_mask & SHZ_SND_FMT_8BIT) { f |= t[i].m08; if (c->max_channels >= 2) f |= t[i].s08; }
        if (c->bits_mask & SHZ_SND_FMT_16BIT) { f |= t[i].m16; if (c->max_channels >= 2) f |= t[i].s16; }
    }
    return f;
}

static MMRESULT devcaps(UINT_PTR id, void *out, UINT cb, int wide)
{
    shz_snd_caps c;
    WAVEOUTCAPSW w;
    static const char base[] = "ShizukuOS Core AC97 Audio";
    unsigned i;
    if (!out || !cb) return MMSYSERR_INVALPARAM;
    if (!xp_present(&c)) return id == (UINT_PTR)WAVE_MAPPER ? MMSYSERR_NODRIVER : MMSYSERR_BADDEVICEID;
    if (id != 0 && id != (UINT_PTR)WAVE_MAPPER) {
        int ok;
        EnterCriticalSection(&g_wl);
        ok = lookup((HWAVEOUT)id) != 0;
        LeaveCriticalSection(&g_wl);
        if (!ok) return MMSYSERR_BADDEVICEID;
    }
    memset(&w, 0, sizeof w);
    w.vDriverVersion = 0x0100;                 /* ShizukuOS Core audio ABI v1; no vendor/product ids are invented */
    for (i = 0; base[i]; ++i) w.szPname[i] = (WCHAR)base[i];
    w.dwFormats = formats_from_caps(&c);
    w.wChannels = (WORD)c.max_channels;
    if (wide) {
        memcpy(out, &w, cb < sizeof w ? cb : sizeof w);
    } else {
        WAVEOUTCAPSA a;
        memset(&a, 0, sizeof a);
        a.vDriverVersion = w.vDriverVersion; a.dwFormats = w.dwFormats; a.wChannels = w.wChannels;
        for (i = 0; base[i]; ++i) a.szPname[i] = base[i];
        memcpy(out, &a, cb < sizeof a ? cb : sizeof a);
    }
    return MMSYSERR_NOERROR;
}
DLLAPI MMRESULT WINAPI waveOutGetDevCapsW(UINT_PTR id, LPWAVEOUTCAPSW caps, UINT cb) { return devcaps(id, caps, cb, 1); }
DLLAPI MMRESULT WINAPI waveOutGetDevCapsA(UINT_PTR id, LPWAVEOUTCAPSA caps, UINT cb) { return devcaps(id, caps, cb, 0); }

static const struct { UINT code; const char *text; } g_err[] = {
    { MMSYSERR_NOERROR, "The specified command was carried out." }, { MMSYSERR_ERROR, "Undefined external error." },
    { MMSYSERR_BADDEVICEID, "A device ID has been used that is out of range for your system." },
    { MMSYSERR_NOTENABLED, "The driver was not enabled." }, { MMSYSERR_ALLOCATED, "The specified device is already in use." },
    { MMSYSERR_INVALHANDLE, "The specified device handle is invalid." }, { MMSYSERR_NODRIVER, "There is no driver installed on your system." },
    { MMSYSERR_NOMEM, "Not enough memory available for this task." }, { MMSYSERR_NOTSUPPORTED, "This function is not supported." },
    { MMSYSERR_BADERRNUM, "An error number was specified that is not defined in the system." },
    { MMSYSERR_INVALFLAG, "An invalid flag was passed to a system function." },
    { MMSYSERR_INVALPARAM, "An invalid parameter was passed to a system function." },
    { WAVERR_BADFORMAT, "The specified format is not supported or cannot be translated." },
    { WAVERR_STILLPLAYING, "The wave header is still queued; reset the device or wait for it to finish." },
    { WAVERR_UNPREPARED, "The wave header was not prepared." }, { WAVERR_SYNC, "The device is synchronous." } };

static const char *err_text(UINT code)
{
    unsigned i;
    for (i = 0; i < sizeof g_err / sizeof g_err[0]; ++i) if (g_err[i].code == code) return g_err[i].text;
    return 0;
}
DLLAPI MMRESULT WINAPI waveOutGetErrorTextW(MMRESULT code, LPWSTR buf, UINT cch)
{
    const char *t;
    UINT i;
    if (!buf || !cch) return MMSYSERR_INVALPARAM;
    t = err_text(code);
    if (!t) return MMSYSERR_BADERRNUM;
    for (i = 0; t[i] && i + 1 < cch; ++i) buf[i] = (WCHAR)(unsigned char)t[i];
    buf[i] = 0;
    return MMSYSERR_NOERROR;
}
DLLAPI MMRESULT WINAPI waveOutGetErrorTextA(MMRESULT code, LPSTR buf, UINT cch)
{
    const char *t;
    UINT i;
    if (!buf || !cch) return MMSYSERR_INVALPARAM;
    t = err_text(code);
    if (!t) return MMSYSERR_BADERRNUM;
    for (i = 0; t[i] && i + 1 < cch; ++i) buf[i] = t[i];
    buf[i] = 0;
    return MMSYSERR_NOERROR;
}

/* Extract and validate PCM format; returns 0 or WAVERR_BADFORMAT. Reads 16 bytes for PCM, 40 for EXTENSIBLE. */
static MMRESULT parse_fmt(const WAVEFORMATEX *f, unsigned *ch, unsigned *bits, unsigned *rate)
{
    WORD tag = f->wFormatTag;
    if (tag == WAVE_FORMAT_EXTENSIBLE) {
        const BYTE *p = (const BYTE *)f;
        static const BYTE g[16] = { 1, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71 };
        if (f->cbSize < 22 || memcmp(p + 24, g, 16) != 0 || *(const WORD *)(p + 18) != f->wBitsPerSample) return WAVERR_BADFORMAT;
    } else if (tag != WAVE_FORMAT_PCM) return WAVERR_BADFORMAT;
    if (f->nChannels < 1 || f->nChannels > 2 || (f->wBitsPerSample != 8 && f->wBitsPerSample != 16)) return WAVERR_BADFORMAT;
    if (f->nBlockAlign != f->nChannels * (f->wBitsPerSample / 8) || f->nAvgBytesPerSec != f->nSamplesPerSec * f->nBlockAlign) return WAVERR_BADFORMAT;
    *ch = f->nChannels; *bits = f->wBitsPerSample; *rate = f->nSamplesPerSec;
    return MMSYSERR_NOERROR;
}

DLLAPI MMRESULT WINAPI waveOutOpen(LPHWAVEOUT phwo, UINT id, LPCWAVEFORMATEX fmt, DWORD_PTR cb, DWORD_PTR inst, DWORD flags)
{
    shz_snd_caps c;
    unsigned ch, bits, rate, slot;
    MMRESULT mr;
    NTSTATUS st;
    uint64_t kh;
    wstream *s;
    DWORD cbtype = flags & CALLBACK_TYPES_;
    if (!fmt || (!phwo && !(flags & WAVE_FORMAT_QUERY))) return MMSYSERR_INVALPARAM;
    if (flags & ~(DWORD)(CALLBACK_TYPES_ | WAVE_FORMAT_QUERY | WAVE_ALLOWSYNC | WAVE_MAPPED | WAVE_FORMAT_DIRECT)) return MMSYSERR_INVALFLAG;
    if (phwo && !(flags & WAVE_FORMAT_QUERY)) *phwo = 0;
    if (!xp_present(&c)) return id == WAVE_MAPPER ? MMSYSERR_NODRIVER : MMSYSERR_BADDEVICEID;
    if (id != 0 && id != WAVE_MAPPER) return MMSYSERR_BADDEVICEID;
    if (flags & WAVE_MAPPED) return MMSYSERR_NOTSUPPORTED;                  /* no format-converting mapper exists here */
    mr = parse_fmt(fmt, &ch, &bits, &rate);
    if (mr) return mr;
    if (!xp_format_ok(ch, bits, rate, &c)) return WAVERR_BADFORMAT;
    if (flags & WAVE_FORMAT_QUERY) return MMSYSERR_NOERROR;                 /* answered from QUERY caps; nothing allocated/opened */
    if (cbtype == CALLBACK_TASK) return MMSYSERR_NOTSUPPORTED;
    if (cbtype == CALLBACK_WINDOW) { if (!cb || !GetModuleHandleW(L"user32.dll")) return MMSYSERR_NOTSUPPORTED; }
    if ((cbtype == CALLBACK_FUNCTION || cbtype == CALLBACK_EVENT) && !cb) return MMSYSERR_INVALPARAM;

    EnterCriticalSection(&g_wl);
    for (slot = 0; slot < WO_SLOTS && g_ws[slot].used; ++slot) ;
    if (slot == WO_SLOTS) { LeaveCriticalSection(&g_wl); return MMSYSERR_ALLOCATED; }
    s = &g_ws[slot];
    memset(s, 0, sizeof *s);
    s->wake = CreateEventW(0, FALSE, FALSE, 0);
    if (!s->wake) { LeaveCriticalSection(&g_wl); return MMSYSERR_NOMEM; }
    st = xp_open(ch, bits, rate, &kh);                                     /* real Core stream; failure is returned as is */
    if (!NT_SUCCESS(st)) { CloseHandle(s->wake); memset(s, 0, sizeof *s); LeaveCriticalSection(&g_wl); return xp_mm(st); }
    s->h = kh; s->ch = ch; s->bits = bits; s->rate = rate; s->block = ch * (bits / 8);
    s->cbtype = cbtype; s->cb = cb; s->inst = inst; s->next_seq = 1;
    s->gen = g_gen++; if (!g_gen || g_gen > 0xffffff) g_gen = 1;
    s->used = 1; s->slot = slot;
    s->mod = xp_modref();                                                   /* module stays mapped until the worker exits */
    s->thread = s->mod ? CreateThread(0, 0, wave_thread, s, 0, &s->thread_id) : 0;
    if (!s->thread) {
        xp_modunref(s->mod);
        xp_close(kh); CloseHandle(s->wake); memset(s, 0, sizeof *s);
        LeaveCriticalSection(&g_wl);
        return MMSYSERR_NOMEM;
    }
    *phwo = enc(slot, s->gen);
    { wstream snap = *s; LeaveCriticalSection(&g_wl); notify(&snap, WOM_OPEN, 0); }
    return MMSYSERR_NOERROR;
}

/* Tear down a stream whose queue is empty. Called without g_wl. */
static MMRESULT teardown(HWAVEOUT h, int kernel_reset)
{
    wstream *s;
    HANDLE thr, wake;
    DWORD tid;
    uint64_t kh;
    NTSTATUS st;
    EnterCriticalSection(&g_wl);
    s = lookup(h);
    if (!s) { LeaveCriticalSection(&g_wl); return MMSYSERR_INVALHANDLE; }
    tid = s->thread_id;
    if (GetCurrentThreadId() == tid) { LeaveCriticalSection(&g_wl); return MMSYSERR_HANDLEBUSY; }
    if (!kernel_reset) {
        uint32_t i;
        for (i = 0; i < s->count; ++i) if (!qat(s, i)->done) { LeaveCriticalSection(&g_wl); return WAVERR_STILLPLAYING; }
    }
    InterlockedExchange((LONG *)&s->closing, 1);
    thr = s->thread; wake = s->wake;
    LeaveCriticalSection(&g_wl);
    SetEvent(wake);
    /* The worker delivers pending notifications and exits; it is never abandoned. */
    if (WaitForSingleObject(thr, 10000) != WAIT_OBJECT_0) return MMSYSERR_HANDLEBUSY;   /* stream stays valid, Close may be retried */
    EnterCriticalSection(&g_wl);
    s = lookup(h);
    if (!s) { LeaveCriticalSection(&g_wl); return MMSYSERR_INVALHANDLE; }
    kh = s->h;
    LeaveCriticalSection(&g_wl);
    if (kernel_reset) xp_reset(kh);
    st = xp_close(kh);
    EnterCriticalSection(&g_wl);
    s = lookup(h);
    if (s) {
        wstream snap = *s;
        CloseHandle(s->thread); CloseHandle(s->wake);
        memset(s, 0, sizeof *s);
        LeaveCriticalSection(&g_wl);
        if (!kernel_reset) notify(&snap, WOM_CLOSE, 0);
    } else LeaveCriticalSection(&g_wl);
    return NT_SUCCESS(st) ? MMSYSERR_NOERROR : xp_mm(st);
}

DLLAPI MMRESULT WINAPI waveOutClose(HWAVEOUT h) { return teardown(h, 0); }

static MMRESULT with_stream(HWAVEOUT h, wstream **out)
{
    *out = lookup(h);
    return *out ? ((*out)->closing ? MMSYSERR_HANDLEBUSY : MMSYSERR_NOERROR) : MMSYSERR_INVALHANDLE;
}

DLLAPI MMRESULT WINAPI waveOutPause(HWAVEOUT h)
{
    wstream *s; MMRESULT mr;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) mr = xp_mm(xp_pause(s->h, 1));
    LeaveCriticalSection(&g_wl);
    return mr;
}

DLLAPI MMRESULT WINAPI waveOutRestart(HWAVEOUT h)
{
    wstream *s; MMRESULT mr;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) { mr = xp_mm(xp_pause(s->h, 0)); if (!mr) SetEvent(s->wake); }
    LeaveCriticalSection(&g_wl);
    return mr;
}

DLLAPI MMRESULT WINAPI waveOutReset(HWAVEOUT h)
{
    wstream *s; MMRESULT mr;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) {
        NTSTATUS st = xp_reset(s->h);
        mr = xp_mm(st);
        if (!mr) { drain_status(s); abort_all(s); s->fault = 0; SetEvent(s->wake); }   /* Core stopped: queued headers are done */
    }
    LeaveCriticalSection(&g_wl);
    return mr;
}

static MMRESULT hdr_check(const WAVEHDR *hdr, UINT cb)
{
    if (!hdr || cb < sizeof(WAVEHDR)) return MMSYSERR_INVALPARAM;
    return MMSYSERR_NOERROR;
}

DLLAPI MMRESULT WINAPI waveOutPrepareHeader(HWAVEOUT h, LPWAVEHDR hdr, UINT cb)
{
    wstream *s; MMRESULT mr;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) mr = hdr_check(hdr, cb);
    if (!mr && (!hdr->lpData || !hdr->dwBufferLength || hdr->dwBufferLength > WO_HDR_MAX)) mr = MMSYSERR_INVALPARAM;
    if (!mr && !(hdr->dwFlags & WHDR_PREPARED)) { hdr->dwFlags = WHDR_PREPARED; hdr->dwLoops = 0; }
    LeaveCriticalSection(&g_wl);
    return mr;
}

DLLAPI MMRESULT WINAPI waveOutUnprepareHeader(HWAVEOUT h, LPWAVEHDR hdr, UINT cb)
{
    wstream *s; MMRESULT mr;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) mr = hdr_check(hdr, cb);
    if (!mr && (hdr->dwFlags & WHDR_INQUEUE)) mr = WAVERR_STILLPLAYING;
    if (!mr) hdr->dwFlags &= ~(DWORD)(WHDR_PREPARED | WHDR_DONE);
    LeaveCriticalSection(&g_wl);
    return mr;
}

DLLAPI MMRESULT WINAPI waveOutWrite(HWAVEOUT h, LPWAVEHDR hdr, UINT cb)
{
    wstream *s; MMRESULT mr;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) mr = hdr_check(hdr, cb);
    if (!mr) {
        if (!(hdr->dwFlags & WHDR_PREPARED)) mr = WAVERR_UNPREPARED;
        else if (hdr->dwFlags & WHDR_INQUEUE) mr = WAVERR_STILLPLAYING;
        else if (!hdr->lpData || !hdr->dwBufferLength || hdr->dwBufferLength > WO_HDR_MAX || hdr->dwBufferLength % s->block) mr = MMSYSERR_INVALPARAM;
        else if (hdr->dwFlags & (WHDR_BEGINLOOP | WHDR_ENDLOOP)) mr = MMSYSERR_NOTSUPPORTED;     /* looping is not implemented */
        else if (s->count >= WO_QMAX) mr = MMSYSERR_NOMEM;
        else if (s->fault) mr = xp_mm(s->fault);
    }
    if (!mr) {
        wq_t *e = qat(s, s->count);
        memset(e, 0, sizeof *e);
        e->hdr = hdr;
        hdr->dwFlags = (hdr->dwFlags & ~(DWORD)WHDR_DONE) | WHDR_INQUEUE;
        ++s->count;
        pump(s);
        SetEvent(s->wake);
    }
    LeaveCriticalSection(&g_wl);
    return mr;
}

DLLAPI MMRESULT WINAPI waveOutGetPosition(HWAVEOUT h, LPMMTIME t, UINT cb)
{
    wstream *s; MMRESULT mr;
    if (!t || cb < sizeof(MMTIME)) return MMSYSERR_INVALPARAM;
    EnterCriticalSection(&g_wl);
    mr = with_stream(h, &s);
    if (!mr) {
        shz_snd_status st;
        NTSTATUS rc = xp_status(s->h, &st);          /* cookies drained here are applied so no completion is lost */
        mr = xp_mm(rc);
        if (!mr) {
            uint64_t hwframes = st.played_bytes / 4, frames = hwframes * s->rate / 48000;
            uint32_t k, i;
            for (k = 0; k < st.cookie_count; ++k)
                for (i = 0; i < s->count; ++i) {
                    wq_t *e = qat(s, i);
                    if (e->seq == st.cookies[k].cookie && e->pending) { --e->pending; settle(e); break; }
                }
            s->played_hw = st.played_bytes;
            if (t->wType == TIME_MS) t->u.ms = (DWORD)(hwframes * 1000 / 48000);
            else if (t->wType == TIME_SAMPLES) t->u.sample = (DWORD)frames;
            else { t->wType = TIME_BYTES; t->u.cb = (DWORD)(frames * s->block); }
            SetEvent(s->wake);
        }
    }
    LeaveCriticalSection(&g_wl);
    return mr;
}

/* ---------------------------------------------------------------- DllMain hooks */
void shz_wave_attach(void) { if (!g_wl_init) { InitializeCriticalSection(&g_wl); g_wl_init = 1; } }

/* DLL_PROCESS_DETACH by FreeLibrary: every open stream has a worker holding a loader reference, so none can exist here
 * except the one whose own FreeLibraryAndExitThread dropped the last reference (its closer is then inside code the
 * application no longer holds loaded: an application contract violation we cannot repair). No wait is made: waiting for
 * a worker under the loader lock cannot succeed (thread exit needs that lock). A slot without a worker only holds a Core
 * stream, which is closed here. */
void shz_wave_detach(int dynamic_unload)
{
    unsigned i;
    if (!g_wl_init || !dynamic_unload) return;     /* at process exit Core releases the process's streams itself */
    for (i = 0; i < WO_SLOTS; ++i) {
        uint64_t kh = 0;
        EnterCriticalSection(&g_wl);
        if (g_ws[i].used && g_ws[i].thread_id != GetCurrentThreadId()) { kh = g_ws[i].h; g_ws[i].used = 0; }
        LeaveCriticalSection(&g_wl);
        if (kh) xp_close(kh);
    }
}
