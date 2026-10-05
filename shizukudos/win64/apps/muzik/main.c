/* SPDX-License-Identifier: GPL-2.0-only
 * Muzik (candidate, console stage): bounded native WAV library + player over the exported winmm waveOut API.
 *
 *   muzik devices                    waveOutGetNumDevs / waveOutGetDevCapsW
 *   muzik info  FILE|@LIST ...       validate and describe tracks (no audio)
 *   muzik play  [--max-ms N] FILE|@LIST ...   play tracks in order through waveOutOpen/Prepare/Write
 *
 * A library is a plain-text list file (one path per line, '#' comments, max MZ_LIB_MAX entries, 64 KiB).
 * Real behaviour only: every result is a waveOut/Win32 return code; a missing device, bad format or open failure is
 * reported and the program exits nonzero. Nothing is "played" unless waveOutWrite accepted it and the header was
 * reported WHDR_DONE by winmm. Not provided and NOT advertised: directory scan (no FindFirstFile consumer proven in
 * this tree), tags/cover art, video, visualization, GUI. */
#include "nt.h"
#include "shzcrt.h"
#include <mmsystem.h>
#include <string.h>
#include "muzik_wav.h"
#include "muzik_rundown.h"
#define MZ_FATAL 3   /* rundown failed: header array + PCM quarantined (retained), no further tracks */

#define MZ_LIB_MAX 64u
#define MZ_LIST_BYTES (64u * 1024u)
#define MZ_HDRS 8u
#define MZ_CHUNK 16384u              /* multiple of every block align (1,2,4) */
#define MZ_WAIT_STEP 10u

typedef struct { WCHAR path[MAX_PATH]; } mz_entry;

static BYTE *load(const WCHAR *path, DWORD cap, DWORD *out)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    DWORD hi = 0, lo, got = 0; BYTE *b;
    if (f == INVALID_HANDLE_VALUE) return 0;
    lo = GetFileSize(f, &hi);
    if (lo == INVALID_FILE_SIZE || hi || !lo || lo > cap) { CloseHandle(f); return 0; }
    b = HeapAlloc(GetProcessHeap(), 0, lo);
    if (!b) { CloseHandle(f); return 0; }
    while (got < lo) {
        DWORD n = 0;
        if (!ReadFile(f, b + got, lo - got, &n, 0) || !n) { HeapFree(GetProcessHeap(), 0, b); CloseHandle(f); return 0; }
        got += n;
    }
    CloseHandle(f); *out = lo; return b;
}

/* ASCII paths only: no NLS conversion API is a proven consumer here, so non-ASCII is rejected (fail closed). */
static int widen(const char *a, WCHAR *w)
{
    unsigned i;
    for (i = 0; i < MAX_PATH - 1 && a[i]; ++i) { if ((unsigned char)a[i] >= 0x80) return 0; w[i] = (unsigned char)a[i]; }
    if (a[i]) return 0;
    w[i] = 0;
    return i > 0;
}

/* Parse list text in place; entries are appended to e[*n]. Returns 0 or -1 (over-limit/bad UTF-8 => whole list rejected). */
static int read_list(const WCHAR *lp, mz_entry *e, unsigned *n)
{
    DWORD len; char *t = (char *)load(lp, MZ_LIST_BYTES - 1, &len), *p, *end;
    if (!t) return -1;
    { char *g = HeapReAlloc(GetProcessHeap(), 0, t, len + 1);
      if (!g) { HeapFree(GetProcessHeap(), 0, t); return -1; }   /* original block is still ours on failure */
      t = g; }
    t[len] = 0;
    for (p = t, end = t + len; p < end;) {
        char *s = p, *q;
        while (p < end && *p != '\n') ++p;
        *p = 0; if (p < end) ++p;
        for (q = s + strlen(s); q > s && (q[-1] == '\r' || q[-1] == ' ' || q[-1] == '\t'); ) *--q = 0;
        while (*s == ' ' || *s == '\t') ++s;
        if (!*s || *s == '#') continue;
        if (*n >= MZ_LIB_MAX || !widen(s, e[*n].path)) { HeapFree(GetProcessHeap(), 0, t); return -1; }
        ++*n;
    }
    HeapFree(GetProcessHeap(), 0, t);
    return 0;
}

static int collect(int argc, char **argv, int i, mz_entry *e, unsigned *n)
{
    for (; i < argc; ++i) {
        if (argv[i][0] == '@') {
            WCHAR lp[MAX_PATH];
            if (!widen(argv[i] + 1, lp) || read_list(lp, e, n)) { printf("library list rejected: %s\n", argv[i] + 1); return -1; }
        } else {
            if (*n >= MZ_LIB_MAX || !widen(argv[i], e[*n].path)) { printf("track rejected: %s\n", argv[i]); return -1; }
            ++*n;
        }
    }
    if (!*n) { printf("no tracks\n"); return -1; }
    return 0;
}

static void mm_err(const char *what, MMRESULT r)
{
    char t[MAXERRORLENGTH]; WCHAR w[MAXERRORLENGTH]; unsigned i;
    t[0] = 0;
    if (waveOutGetErrorTextW(r, w, MAXERRORLENGTH) == MMSYSERR_NOERROR)
        for (i = 0; i < MAXERRORLENGTH - 1 && w[i]; ++i) { t[i] = w[i] < 128 ? (char)w[i] : '?'; t[i + 1] = 0; }
    printf("%s failed: mmresult=%u %s\n", what, (unsigned)r, t);
}

static int cmd_devices(void)
{
    UINT n = waveOutGetNumDevs(), i;
    printf("waveOut devices: %u\n", (unsigned)n);
    if (!n) { printf("no audio output device (Core audio service absent): playback unavailable\n"); return 1; }
    for (i = 0; i < n; ++i) {
        WAVEOUTCAPSW c; MMRESULT r = waveOutGetDevCapsW(i, &c, sizeof c);
        if (r) { mm_err("waveOutGetDevCapsW", r); return 1; }
        printf("  #%u ch=%u formats=%08x\n", (unsigned)i, (unsigned)c.wChannels, (unsigned)c.dwFormats);
    }
    return 0;
}

static int describe(const WCHAR *path, BYTE **buf, DWORD *len, mz_wav *w)
{
    int rc;
    *buf = load(path, MZ_WAV_MAX, len);
    if (!*buf) return -1;
    rc = mz_wav_parse(*buf, *len, w);
    if (rc) { HeapFree(GetProcessHeap(), 0, *buf); *buf = 0; return -2; }
    return 0;
}

static int cmd_info(const mz_entry *e, unsigned n)
{
    unsigned i, bad = 0;
    for (i = 0; i < n; ++i) {
        BYTE *b; DWORD l; mz_wav w; int rc = describe(e[i].path, &b, &l, &w);
        if (rc) { printf("[%u] %s\n", i + 1, rc == -1 ? "unreadable or over 8 MiB" : "not supported PCM WAV"); ++bad; continue; }
        printf("[%u] %uch %ubit %uHz %u ms\n", i + 1, w.ch, w.bits, (unsigned)w.rate,
               (unsigned)((uint64_t)w.len * 1000u / ((uint64_t)w.rate * w.ch * (w.bits / 8))));
        HeapFree(GetProcessHeap(), 0, b);
    }
    printf("%u track(s), %u unusable\n", n, bad);
    return bad ? 1 : 0;
}

typedef struct { WAVEHDR hd[MZ_HDRS]; BYTE *pcm; HWAVEOUT h; } mz_ctx;   /* heap: winmm retains header addresses */
static int op_reset(void *s) { MMRESULT r = waveOutReset((HWAVEOUT)s); if (r) mm_err("waveOutReset", r); return r != 0; }
static int op_unprep(void *s, void *h) { MMRESULT r = waveOutUnprepareHeader((HWAVEOUT)s, (LPWAVEHDR)h, sizeof(WAVEHDR)); if (r) mm_err("waveOutUnprepareHeader", r); return r != 0; }
static int op_close(void *s) { MMRESULT r = waveOutClose((HWAVEOUT)s); if (r) mm_err("waveOutClose", r); return r != 0; }
static int op_isprep(void *h) { return (((LPWAVEHDR)h)->dwFlags & WHDR_PREPARED) != 0; }

/* Play one track. Returns 0 ok, 1 failed (all resources released), 2 stopped by --max-ms, MZ_FATAL when rundown failed:
 * the heap context (headers+PCM) is then deliberately retained until process exit and the caller must stop. */
static int play_one(const WCHAR *path, DWORD max_ms)
{
    BYTE *b; DWORD l, pos, t0; mz_wav w; WAVEFORMATEX f; mz_ctx *c; void *hp[MZ_HDRS];
    unsigned i; int rc = 1, d; MMRESULT r; mz_ops ops = { op_reset, op_unprep, op_close };
    if ((d = describe(path, &b, &l, &w))) { printf("track open failed: %s\n", d == -1 ? "unreadable" : "unsupported WAV"); return 1; }
    c = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *c);
    if (!c) { HeapFree(GetProcessHeap(), 0, b); return 1; }
    c->pcm = b;
    memset(&f, 0, sizeof f);
    f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = w.ch; f.nSamplesPerSec = w.rate; f.wBitsPerSample = w.bits;
    f.nBlockAlign = (WORD)(w.ch * (w.bits / 8)); f.nAvgBytesPerSec = w.rate * f.nBlockAlign;
    /* Core audio is exclusive: a short Shell notification may still own it.
     * Retry only ALLOCATED before any header is submitted. Both elapsed time
     * and attempts are bounded; failures never disturb another owner's stream. */
    {
        DWORD open_start = GetTickCount();
        unsigned retries = 0;
        for (;;) {
            r = waveOutOpen(&c->h, WAVE_MAPPER, &f, 0, 0, CALLBACK_NULL);
            if (r != MMSYSERR_ALLOCATED || retries >= 30 ||
                (DWORD)(GetTickCount() - open_start) >= 3000u) break;
            Sleep(100);
            ++retries;
            if ((DWORD)(GetTickCount() - open_start) >= 3000u) break;
        }
    }
    if (r) { mm_err("waveOutOpen", r); HeapFree(GetProcessHeap(), 0, c); HeapFree(GetProcessHeap(), 0, b); return 1; }
    for (i = 0; i < MZ_HDRS; ++i) hp[i] = &c->hd[i];
    pos = 0; t0 = GetTickCount();
    for (;;) {
        int busy = 0;
        for (i = 0; i < MZ_HDRS; ++i) {
            WAVEHDR *hd = &c->hd[i];
            if (hd->dwFlags & WHDR_PREPARED) {
                if (hd->dwFlags & WHDR_DONE) { if (op_unprep(c->h, hd)) goto out; }
                else { busy = 1; continue; }
            }
            if (pos < w.len) {
                DWORD n = w.len - pos > MZ_CHUNK ? MZ_CHUNK : w.len - pos;
                memset(hd, 0, sizeof *hd);
                hd->lpData = (LPSTR)(b + w.off + pos); hd->dwBufferLength = n;
                if ((r = waveOutPrepareHeader(c->h, hd, sizeof *hd))) { mm_err("waveOutPrepareHeader", r); goto out; }
                if ((r = waveOutWrite(c->h, hd, sizeof *hd))) { mm_err("waveOutWrite", r); op_unprep(c->h, hd); goto out; }  /* a failed unprepare leaves PREPARED set: rundown retries and quarantines */
                pos += n; busy = 1;
            }
        }
        if (!busy && pos >= w.len) { rc = 0; break; }
        if (max_ms && GetTickCount() - t0 >= max_ms) { printf("stopped at --max-ms limit\n"); rc = 2; goto out; }
        if (GetTickCount() - t0 > 600000u + (DWORD)(((uint64_t)w.len * 1000u) / f.nAvgBytesPerSec)) { printf("playback stalled: device never completed headers\n"); goto out; }
        Sleep(MZ_WAIT_STEP);
    }
out:
    if (!mz_rundown(&ops, c->h, hp, op_isprep, MZ_HDRS)) {
        printf("rundown failed: stream/headers/PCM quarantined until exit\n");
        return MZ_FATAL;                                       /* never free: winmm may still reference headers and PCM */
    }
    HeapFree(GetProcessHeap(), 0, c);
    HeapFree(GetProcessHeap(), 0, b);
    return rc;
}

static int cmd_play(const mz_entry *e, unsigned n, DWORD max_ms)
{
    unsigned i, fail = 0;
    if (!waveOutGetNumDevs()) { printf("no audio output device: nothing played\n"); return 1; }
    for (i = 0; i < n; ++i) {
        int rc;
        printf("track %u/%u\n", i + 1, n);
        rc = play_one(e[i].path, max_ms);
        if (rc == MZ_FATAL) return MZ_FATAL;   /* stop: quarantined context stays the only live one */
        if (rc == 2) return 2;
        if (rc) ++fail;
    }
    printf("%u played, %u failed\n", n - fail, fail);
    return fail ? 1 : 0;
}

int main(int argc, char **argv)
{
    static mz_entry lib[MZ_LIB_MAX]; unsigned n = 0; DWORD max_ms = 0; int i = 2;
    if (argc >= 2 && !strcmp(argv[1], "devices")) return cmd_devices();
    if (argc >= 3 && !strcmp(argv[1], "info")) return collect(argc, argv, 2, lib, &n) ? 2 : cmd_info(lib, n);
    if (argc >= 3 && !strcmp(argv[1], "play")) {
        if (!strcmp(argv[2], "--max-ms")) {
            const char *s; if (argc < 5) goto usage;
            for (s = argv[3], max_ms = 0; *s; ++s) { if (*s < '0' || *s > '9' || max_ms > 3600000u) goto usage; max_ms = max_ms * 10 + (DWORD)(*s - '0'); }
            i = 4;
        }
        return collect(argc, argv, i, lib, &n) ? 2 : cmd_play(lib, n, max_ms);
    }
usage:
    printf("muzik devices | info FILE|@LIST... | play [--max-ms N] FILE|@LIST...\nPCM WAV only (8/16 bit, 1-2 ch, 11025-48000 Hz). Lists: one path per line.\n");
    return 2;
}
