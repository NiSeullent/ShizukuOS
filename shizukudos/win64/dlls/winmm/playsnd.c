/* SPDX-License-Identifier: GPL-2.0-only
 * winmm PlaySoundW/A and sndPlaySoundW/A over the ShizukuOS Core audio service (NtShzSound).
 *
 * Only real RIFF/WAVE PCM (8/16 bit, mono/stereo, 11025/22050/44100/48000 Hz, via wavefile.c) is played, from a file
 * (SND_FILENAME, also the meaning of a name without SND_ALIAS/SND_MEMORY/SND_RESOURCE) or from memory (SND_MEMORY).
 * Files are read with ReadFile and are limited to 8 MiB. SND_MEMORY input is bounded by VirtualQuery readability and the RIFF
 * size, then copied. SND_ALIAS resolves a sound-event name (".Default", "SystemStart", "WindowsLogon", ...) through the scheme
 * policy in sndscheme.h (%WINDIR%\\SHZSOUND.INI [Events], else %WINDIR%\\MEDIA\\<built-in file>) and then follows the same file
 * path; unmapped, muted ("-") or missing files return FALSE. SND_LOOP requires SND_ASYNC and repeats until stopped/purged.
 * Not supported and returning FALSE: SND_ALIAS_ID, SND_RESOURCE, SND_APPLICATION, SND_ALIAS combined with FILENAME/MEMORY.
 * There is no default beep: SND_NODEFAULT is accepted and a failure never plays a substitute sound.
 *
 * SND_SYNC returns TRUE only after Core reported every write cookie completed (hardware consumed the data) or the sound was
 * cancelled. SND_ASYNC copies the parsed PCM into a heap block owned by a worker thread; it returns TRUE once that thread is
 * started; if its stream cannot be opened the worker just ends (no later report). Only one sound plays per process; a new one stops the previous one (SND_NOSTOP: FALSE instead).
 * PlaySound(NULL, ..) / SND_PURGE cancel through Core RESET. Stopping waits for the owned worker, bounded (10 s).
 */
#include "wavxp.h"
#include "wavefile.h"
#include "sndscheme.c"          /* pure alias policy, unity-included so no build-list change is needed */
#include <string.h>

#ifndef SND_SYNC
#define SND_SYNC 0
#endif
#define PS_ASYNC 0x0001u
#define PS_NODEFAULT 0x0002u
#define PS_MEMORY 0x0004u
#define PS_LOOP 0x0008u
#define PS_NOSTOP 0x0010u
#define PS_PURGE 0x0040u
#define PS_APPLICATION 0x0080u
#define PS_NOWAIT 0x00002000u
#define PS_ALIAS 0x00010000u
#define PS_FILENAME 0x00020000u
#define PS_RESOURCE 0x00040004u
#define PS_ALIAS_ID 0x00110000u
#define PS_STALL_MS 5000u

typedef struct psnd {
    BYTE *data;                 /* PCM frames (heap, owned) */
    uint32_t len;
    unsigned ch, bits, rate;
    volatile LONG stop;
    int loop;
    HANDLE done, thread;
    HMODULE mod;                /* loader reference owned by the async worker */
    volatile LONG ok;
} psnd;

static CRITICAL_SECTION g_ps;
static int g_ps_init;
static psnd *g_cur;

static BYTE *heap_alloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), 0, n); }

/* ---------------------------------------------------------------- input */
static BYTE *load_file(LPCWSTR name, DWORD *len_out)
{
    HANDLE f;
    DWORD hi = 0, lo, got = 0;
    BYTE *buf;
    if (!name || !*name) return 0;
    f = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) return 0;
    lo = GetFileSize(f, &hi);
    if (lo == INVALID_FILE_SIZE || hi || lo < 12 || lo > SHZ_WAV_MAX) { CloseHandle(f); return 0; }
    buf = heap_alloc(lo);
    if (!buf) { CloseHandle(f); return 0; }
    while (got < lo) {
        DWORD n = 0;
        if (!ReadFile(f, buf + got, lo - got, &n, 0) || !n) { HeapFree(GetProcessHeap(), 0, buf); CloseHandle(f); return 0; }
        got += n;
    }
    CloseHandle(f);
    *len_out = lo;
    return buf;
}

/* Number of bytes readable from p, capped at cap, according to the page protections of the process. */
static SIZE_T readable_len(const void *p, SIZE_T cap)
{
    SIZE_T total = 0;
    const BYTE *a = p;
    while (total < cap) {
        MEMORY_BASIC_INFORMATION mi;
        SIZE_T avail;
        if (!VirtualQuery(a, &mi, sizeof mi)) break;
        if (mi.State != MEM_COMMIT || (mi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) || !(mi.Protect & 0xEE)) break;   /* any readable protection */
        avail = (SIZE_T)((const BYTE *)mi.BaseAddress + mi.RegionSize - a);
        if (!avail) break;
        total += avail; a += avail;
    }
    return total < cap ? total : cap;
}

static BYTE *load_memory(const void *p, DWORD *len_out)
{
    SIZE_T avail;
    DWORD riff, n;
    BYTE *buf;
    if (!p) return 0;
    avail = readable_len(p, SHZ_WAV_MAX);
    if (avail < 12) return 0;
    memcpy(&riff, (const BYTE *)p + 4, 4);
    n = (riff > SHZ_WAV_MAX - 8) ? SHZ_WAV_MAX : riff + 8;
    if (n > avail) n = (DWORD)avail;               /* RIFF size past readable memory: parser rejects an overrunning chunk */
    buf = heap_alloc(n);
    if (!buf) return 0;
    memcpy(buf, p, n);
    *len_out = n;
    return buf;
}

/* Event alias (UTF-16, validated) -> file path. 0 only on success; never substitutes a sound. */
static int resolve_alias(const uint16_t *alias, WCHAR *path)
{
    WCHAR windir[MAX_PATH], ini[MAX_PATH + 16], val[MAX_PATH];
    static const WCHAR tail[] = { '\\', 'S', 'H', 'Z', 'S', 'O', 'U', 'N', 'D', '.', 'I', 'N', 'I', 0 };
    static const WCHAR sect[] = { 'E', 'v', 'e', 'n', 't', 's', 0 };
    UINT n, i;
    if (!shz_scheme_alias_valid(alias)) return -1;
    n = GetWindowsDirectoryW(windir, MAX_PATH);
    if (!n || n >= MAX_PATH - 1) return -1;
    while (n && (windir[n - 1] == '\\' || windir[n - 1] == '/')) windir[--n] = 0;
    for (i = 0; i < n; ++i) ini[i] = windir[i];
    for (i = 0; i < sizeof tail / sizeof tail[0]; ++i) ini[n + i] = tail[i];
    val[0] = 0;
    n = GetPrivateProfileStringW(sect, (LPCWSTR)alias, L"", val, MAX_PATH, ini);
    if (n >= MAX_PATH - 1) return -1;                  /* truncated INI value would name a different file: fail closed */
    val[MAX_PATH - 1] = 0;
    return shz_scheme_resolve(alias, val, (const uint16_t *)windir, (uint16_t *)path, MAX_PATH) == SHZ_SCHEME_OK ? 0 : -1;
}

/* ---------------------------------------------------------------- playback */
static int play_run(psnd *ps)
{
    uint64_t h, cookie = 1;
    uint32_t off = 0, outstanding = 0, last_prog = 0;
    uint64_t last_played = ~0ull;
    DWORD stall = GetTickCount();
    int ok = 0, aborted = 0;
    shz_snd_caps caps;
    shz_snd_status st;
    if (!xp_present(&caps) || !xp_format_ok(ps->ch, ps->bits, ps->rate, &caps)) return 0;
    if (!NT_SUCCESS(xp_open(ps->ch, ps->bits, ps->rate, &h))) return 0;
    for (;;) {
        uint32_t k;
        if (ps->stop) { aborted = 1; break; }
        while (off < ps->len || ps->loop) {                             /* submit as much as the ring accepts */
            uint32_t n, acc, fl;
            if (off >= ps->len) off = 0;                                /* SND_LOOP: wrap at a frame boundary */
            n = ps->len - off;
            NTSTATUS rc;
            if (n > SHZ_SND_MAX_WRITE_BYTES) n = SHZ_SND_MAX_WRITE_BYTES;
            rc = xp_write(h, ps->data + off, n, cookie, &acc, &fl);
            if (rc == STATUS_DEVICE_BUSY) break;
            if (!NT_SUCCESS(rc)) { aborted = 1; goto out; }
            if (acc) { off += acc; ++cookie; ++outstanding; stall = GetTickCount(); }
            if (acc < n || (fl & SHZ_SND_WRITEF_QUEUE_FULL)) break;
        }
        if (!NT_SUCCESS(xp_status(h, &st)) || (st.flags & SHZ_SND_STF_FAULT)) { aborted = 1; break; }
        for (k = 0; k < st.cookie_count; ++k) {
            if (st.cookies[k].flags & SHZ_SND_COOKIEF_ABORTED) aborted = 1;
            if (outstanding) --outstanding;
        }
        if (st.cookie_count || st.played_bytes != last_played) { last_played = st.played_bytes; stall = GetTickCount(); }
        (void)last_prog;
        if (aborted) break;
        if (!ps->loop && off >= ps->len && outstanding == 0) { ok = 1; break; }   /* SND_LOOP never completes naturally: only stop/stall/reset end it */
        if (!(st.flags & SHZ_SND_STF_PAUSED) && GetTickCount() - stall > PS_STALL_MS) { aborted = 1; break; }   /* no hardware progress */
        WaitForSingleObject(ps->done, 5);       /* manual-reset event, signalled only at the very end: acts as a 5 ms sleep */
    }
out:
    if (aborted) { xp_reset(h); }
    xp_close(h);
    return ok;
}

static DWORD WINAPI async_thread(LPVOID p)
{
    psnd *ps = p;
    ps->ok = play_run(ps);
    HeapFree(GetProcessHeap(), 0, ps->data);
    ps->data = 0;
    xp_modexit(ps->mod);        /* ps outlives this thread (owned by stop_current / the next sound), ps->mod is stable */
}

/* Stop and release the current sound. Returns 0 if the worker could not be stopped within the bound (it is kept). */
static int stop_current(void)
{
    psnd *ps;
    if (!g_ps_init) return 1;
    EnterCriticalSection(&g_ps);
    ps = g_cur; g_cur = 0;
    LeaveCriticalSection(&g_ps);
    if (!ps) return 1;
    InterlockedExchange((LONG *)&ps->stop, 1);
    if (WaitForSingleObject(ps->thread ? ps->thread : ps->done, 10000) != WAIT_OBJECT_0) {
        EnterCriticalSection(&g_ps);
        if (!g_cur) g_cur = ps;
        LeaveCriticalSection(&g_ps);
        return 0;
    }
    if (ps->thread) CloseHandle(ps->thread);
    CloseHandle(ps->done);
    if (ps->data) HeapFree(GetProcessHeap(), 0, ps->data);
    HeapFree(GetProcessHeap(), 0, ps);
    return 1;
}

static BOOL play_common(const void *snd, BOOL wide, DWORD flags)
{
    BYTE *buf = 0;
    DWORD len = 0;
    shz_wav_info wi;
    psnd *ps;
    BOOL ret = FALSE;
    WCHAR wpath[MAX_PATH];
    if (!g_ps_init) return FALSE;
    if (flags & PS_APPLICATION) return FALSE;
    if ((flags & PS_LOOP) && !(flags & PS_ASYNC)) return FALSE;                        /* Windows: SND_LOOP requires SND_ASYNC */
    if ((flags & PS_ALIAS_ID) == PS_ALIAS_ID || (flags & PS_RESOURCE) == PS_RESOURCE) return FALSE;
    if ((flags & PS_ALIAS) && (flags & (PS_FILENAME | PS_MEMORY))) return FALSE;
    if (flags & ~(DWORD)(PS_ASYNC | PS_NODEFAULT | PS_MEMORY | PS_LOOP | PS_NOSTOP | PS_PURGE | PS_NOWAIT | PS_FILENAME | PS_ALIAS)) return FALSE;
    if ((flags & PS_PURGE) || !snd) { return stop_current() ? TRUE : FALSE; }
    if (flags & PS_NOSTOP) {
        BOOL busy;
        EnterCriticalSection(&g_ps);
        busy = g_cur && WaitForSingleObject(g_cur->thread ? g_cur->thread : g_cur->done, 0) != WAIT_OBJECT_0;
        LeaveCriticalSection(&g_ps);
        if (busy) return FALSE;
    }
    if (flags & PS_MEMORY) buf = load_memory(snd, &len);
    else if (flags & PS_ALIAS) {
        uint16_t alias[SHZ_SCHEME_ALIAS_MAX + 1u];
        size_t i;
        for (i = 0; i <= SHZ_SCHEME_ALIAS_MAX; ++i) {
            alias[i] = wide ? ((const uint16_t *)snd)[i] : (uint16_t)((const unsigned char *)snd)[i];
            if (!alias[i]) break;
        }
        if (i > SHZ_SCHEME_ALIAS_MAX || resolve_alias(alias, wpath)) return FALSE;
        buf = load_file(wpath, &len);
    } else {
        if (wide) { size_t i; const WCHAR *w = snd; for (i = 0; i < MAX_PATH && w[i]; ++i) wpath[i] = w[i]; if (i == MAX_PATH) return FALSE; wpath[i] = 0; }
        else {
            const char *a = snd; size_t i;
            for (i = 0; i < MAX_PATH && a[i]; ++i) wpath[i] = (unsigned char)a[i];
            if (i == MAX_PATH) return FALSE;
            wpath[i] = 0;
        }
        buf = load_file(wpath, &len);
    }
    if (!buf) return FALSE;
    if (shz_wav_parse(buf, len, &wi) != SHZ_WAV_OK) { HeapFree(GetProcessHeap(), 0, buf); return FALSE; }
    ps = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *ps);
    if (!ps) { HeapFree(GetProcessHeap(), 0, buf); return FALSE; }
    ps->data = buf;
    if (wi.data_off) { memmove(buf, buf + wi.data_off, wi.data_len); }          /* keep only the PCM payload */
    ps->loop = (flags & PS_LOOP) ? 1 : 0;
    ps->len = wi.data_len; ps->ch = wi.channels; ps->bits = wi.bits; ps->rate = wi.rate;
    ps->done = CreateEventW(0, TRUE, FALSE, 0);
    if (!ps->done) goto fail;
    if (!stop_current()) goto fail;                                              /* previous worker still running: do not overlap */
    EnterCriticalSection(&g_ps);
    if (g_cur) { LeaveCriticalSection(&g_ps); goto fail; }                      /* another thread won the race */
    g_cur = ps;
    if (flags & PS_ASYNC) {
        /* thread and handle are published under g_ps so a concurrent stop_current never sees g_cur without ps->thread */
        ps->mod = xp_modref();
        ps->thread = ps->mod ? CreateThread(0, 0, async_thread, ps, 0, 0) : 0;
        if (!ps->thread) {
            xp_modunref(ps->mod);
            g_cur = 0; LeaveCriticalSection(&g_ps);
            goto fail;
        }
        LeaveCriticalSection(&g_ps);
        return TRUE;
    }
    LeaveCriticalSection(&g_ps);
    ret = play_run(ps) ? TRUE : FALSE;
    {
        int mine;
        EnterCriticalSection(&g_ps);
        mine = g_cur == ps;
        if (mine) g_cur = 0;
        LeaveCriticalSection(&g_ps);
        if (mine) { CloseHandle(ps->done); HeapFree(GetProcessHeap(), 0, ps->data); HeapFree(GetProcessHeap(), 0, ps); }
        else { if (ps->stop) ret = TRUE; SetEvent(ps->done); }                 /* a stopper owns ps now and waits for this event */
    }
    return ret;
fail:
    if (ps->done) CloseHandle(ps->done);
    HeapFree(GetProcessHeap(), 0, ps->data);
    HeapFree(GetProcessHeap(), 0, ps);
    return FALSE;
}

DLLAPI BOOL WINAPI PlaySoundW(LPCWSTR s, HMODULE m, DWORD f) { (void)m; return play_common(s, TRUE, f); }
DLLAPI BOOL WINAPI PlaySoundA(LPCSTR s, HMODULE m, DWORD f) { (void)m; return play_common(s, FALSE, f); }
DLLAPI BOOL WINAPI sndPlaySoundW(LPCWSTR s, UINT f) { return play_common(s, TRUE, f); }
DLLAPI BOOL WINAPI sndPlaySoundA(LPCSTR s, UINT f) { return play_common(s, FALSE, f); }

void shz_play_attach(void) { if (!g_ps_init) { InitializeCriticalSection(&g_ps); g_ps_init = 1; } }
/* FreeLibrary reaches here only with no async worker alive (each holds a loader reference), so there is nothing to wait for;
 * a sound that was stopped but not yet reaped is released. No wait under the loader lock. */
void shz_play_detach(int dynamic_unload)
{
    psnd *ps;
    if (!g_ps_init || !dynamic_unload) return;     /* at process exit Core releases the process's streams */
    EnterCriticalSection(&g_ps);
    ps = g_cur; g_cur = 0;
    LeaveCriticalSection(&g_ps);
    if (ps && ps->thread && WaitForSingleObject(ps->thread, 0) == WAIT_OBJECT_0) {
        CloseHandle(ps->thread); CloseHandle(ps->done);
        if (ps->data) HeapFree(GetProcessHeap(), 0, ps->data);
        HeapFree(GetProcessHeap(), 0, ps);
    }
}
