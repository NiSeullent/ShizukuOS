/* SPDX-License-Identifier: GPL-2.0-only
 * Registry self-check, part 3: concurrency. Several threads of one process hammer one registry (racing creators,
 * writers into a shared key, torn-read detection on rewritten values, enumeration during modification, create/delete
 * churn on shared names, handle-table churn). Everything a worker observes is recorded in shared counters and judged by
 * the main thread; workers never print. Also verifies that the previous program (t_reg_native, which exits with 150
 * deleted-but-open key handles) leaked nothing: the registry budget must be completely free at the start.
 */
#include "reg_check.h"

#define NT 6                               /* worker threads */
#define STRESS L"Software\\ShzStress"
#define TSTACK (256 * 1024)

static volatile LONG g_go;                 /* start gate */
static volatile LONG g_arrive[512];        /* per-round barrier counters */
static volatile LONG g_stop;               /* readers run until the writers are done */
static volatile LONG g_created[NT];        /* racing creators: disposition == REG_CREATED_NEW_KEY per thread */
static volatile LONG g_errors[NT];         /* unexpected results per thread */
static volatile LONG g_reads[NT];          /* successful verified reads per thread */
static volatile LONG g_enums[NT];
static volatile LONG g_done[NT];

static void barrier(int round)
{
    InterlockedIncrement(&g_arrive[round]);
    while (g_arrive[round] < NT) SwitchToThread();
}

static void wait_go(void) { while (!g_go) SwitchToThread(); }

/* ------------------------------------------------------------ blob format for torn-read detection */
typedef struct { DWORD len, seq, crc; } blob_hdr;
#define BLOB_MAX 3000

static BYTE blob_byte(DWORD seq, DWORD i) { return (BYTE)(seq * 31u + i * 7u + (i >> 5)); }

static DWORD blob_make(BYTE *out, DWORD seq, DWORD len)
{
    blob_hdr *h = (blob_hdr *)out;
    DWORD i;
    for (i = 0; i < len; ++i) out[sizeof *h + i] = blob_byte(seq, i);
    h->len = len;
    h->seq = seq;
    h->crc = shz_crc32(out + sizeof *h, len);
    return (DWORD)sizeof *h + len;
}

static int blob_ok(const BYTE *in, DWORD cb)
{
    const blob_hdr *h = (const blob_hdr *)in;
    DWORD i;
    if (cb < sizeof *h || h->len != cb - sizeof *h || h->len > BLOB_MAX) return 0;
    for (i = 0; i < h->len; ++i) if (in[sizeof *h + i] != blob_byte(h->seq, i)) return 0;
    return h->crc == shz_crc32(in + sizeof *h, h->len);
}

static HKEY g_shared;                      /* handle to STRESS\Shared, opened by main before the threads start */
static HKEY volatile g_hot;                /* phase 6: a handle that thread 0 keeps closing and replacing */
static volatile LONG g_hot_done;
static volatile LONG g_hot_uses;

/* ------------------------------------------------------------ workers */
static DWORD WINAPI worker(LPVOID arg)
{
    const int t = (int)(INT_PTR)arg;
    int round = 0, j;
    HKEY s;
    LONG e;
    DWORD disp;
    BYTE *buf = shz_malloc(BLOB_MAX + 64);
    if (!buf) { g_errors[t] += 1000; g_done[t] = 1; return 1; }
    wait_go();

    /* phase 1: exactly one thread creates each shared key, the others open it */
    for (j = 0; j < 150; ++j, ++round) {
        HKEY r;
        WCHAR nm[24] = L"Race\\Same000";
        nm[9] = (WCHAR)(L'0' + j / 100); nm[10] = (WCHAR)(L'0' + j / 10 % 10); nm[11] = (WCHAR)(L'0' + j % 10);
        barrier(round);
        disp = 0;
        r = 0;
        e = RegCreateKeyExW(g_shared, nm, 0, 0, 0, KEY_ALL_ACCESS, 0, &r, &disp);
        if (e || !r || (disp != REG_CREATED_NEW_KEY && disp != REG_OPENED_EXISTING_KEY)) ++g_errors[t];
        else if (disp == REG_CREATED_NEW_KEY) ++g_created[t];
        if (r) RegCloseKey(r);
    }

    /* phase 2: every thread adds 100 values and 40 sub-keys to one shared key */
    barrier(round++);
    for (j = 0; j < 100; ++j) {
        DWORD v = (DWORD)(t * 1000 + j);
        WCHAR vn[24] = L"T0_000";
        vn[1] = (WCHAR)(L'0' + t); vn[3] = (WCHAR)(L'0' + j / 100); vn[4] = (WCHAR)(L'0' + j / 10 % 10); vn[5] = (WCHAR)(L'0' + j % 10);
        if (RegSetValueExW(g_shared, vn, 0, REG_DWORD, (const BYTE *)&v, 4)) ++g_errors[t];
    }
    for (j = 0; j < 40; ++j) {
        WCHAR kn[24] = L"Sub\\S0_000";
        HKEY r = 0;
        kn[5] = (WCHAR)(L'0' + t); kn[7] = (WCHAR)(L'0' + j / 100); kn[8] = (WCHAR)(L'0' + j / 10 % 10); kn[9] = (WCHAR)(L'0' + j % 10);
        if (RegCreateKeyExW(g_shared, kn, 0, 0, 0, KEY_READ, 0, &r, &disp) || disp != REG_CREATED_NEW_KEY) ++g_errors[t];
        if (r) RegCloseKey(r);
    }

    /* phase 3: writers rewrite one value with self-verifying blobs of changing length, readers verify them, an
     * enumerator walks the key while it changes */
    barrier(round++);
    if (t < 2) {
        DWORD seq = (DWORD)t * 100000u, lcg = 12345u + (DWORD)t * 777u;
        for (j = 0; j < 400; ++j) {
            DWORD len, cb;
            lcg = lcg * 1103515245u + 12345u;
            len = 1 + (lcg >> 8) % BLOB_MAX;
            cb = blob_make(buf, ++seq, len);
            if (RegSetValueExW(g_shared, L"blob", 0, REG_BINARY, buf, cb)) ++g_errors[t];
            if ((j & 7) == 0) {                         /* also add and delete values while others enumerate */
                DWORD x = 1;
                WCHAR vn[16] = L"tmp0";
                vn[3] = (WCHAR)(L'0' + t);
                if (RegSetValueExW(g_shared, vn, 0, REG_DWORD, (const BYTE *)&x, 4)) ++g_errors[t];
                e = RegDeleteValueW(g_shared, vn);
                if (e) ++g_errors[t];
            }
        }
    } else if (t < 4) {
        while (!g_stop) {
            DWORD cb = BLOB_MAX + 64, type = 0;
            e = RegQueryValueExW(g_shared, L"blob", 0, &type, buf, &cb);
            if (e == ERROR_FILE_NOT_FOUND) { SwitchToThread(); continue; }      /* before the first write */
            if (e || type != REG_BINARY || !blob_ok(buf, cb)) ++g_errors[t]; else ++g_reads[t];
        }
    } else {
        while (!g_stop) {
            DWORD i;
            for (i = 0; !g_stop; ++i) {
                WCHAR vn[64];
                DWORD vnn = 64, cb = BLOB_MAX + 64, type = 0;
                e = RegEnumValueW(g_shared, i, vn, &vnn, 0, &type, buf, &cb);
                if (e == ERROR_NO_MORE_ITEMS) break;
                if (e) { ++g_errors[t]; break; }
                if (vnn == 4 && vn[0] == L'b' && vn[1] == L'l') { if (!blob_ok(buf, cb)) ++g_errors[t]; }
                ++g_enums[t];
            }
        }
    }
    g_done[t] = 1;                                       /* main watches g_done[0], g_done[1] to raise g_stop */
    barrier(round++);

    /* phase 4: create/set/delete churn on names all threads share; races may lose, but only in the documented ways */
    for (j = 0; j < 250; ++j) {
        WCHAR kn[32] = L"Churn\\X0";
        kn[7] = (WCHAR)(L'0' + j % 5);
        s = 0;
        e = RegCreateKeyExW(g_shared, kn, 0, 0, 0, KEY_ALL_ACCESS, 0, &s, &disp);
        if (e) { ++g_errors[t]; continue; }
        e = RegSetValueExW(s, L"v", 0, REG_SZ, (const BYTE *)L"churn", 12);
        if (e && e != ERROR_KEY_DELETED) ++g_errors[t];
        e = RegDeleteKeyW(g_shared, kn);
        if (e && e != ERROR_FILE_NOT_FOUND && e != ERROR_KEY_DELETED) ++g_errors[t];       /* another thread deleted it first */
        e = RegQueryValueExW(s, L"v", 0, 0, 0, &(DWORD){ 0 });
        if (e && e != ERROR_KEY_DELETED && e != ERROR_FILE_NOT_FOUND) ++g_errors[t];
        RegCloseKey(s);
    }

    /* phase 5: handle table churn on one key: handles handed out to different threads never collide */
    barrier(round++);
    {
        HKEY hs[16];
        for (j = 0; j < 200; ++j) {
            int i, m;
            for (i = 0; i < 16; ++i) {
                hs[i] = 0;
                if (RegOpenKeyExW(g_shared, NULL, 0, KEY_READ, &hs[i])) ++g_errors[t];
            }
            for (i = 0; i < 16; ++i) for (m = i + 1; m < 16; ++m) if (hs[i] && hs[i] == hs[m]) ++g_errors[t];
            for (i = 0; i < 16; ++i) {
                DWORD cnt = 0;
                if (hs[i]) {
                    if (RegQueryInfoKeyW(hs[i], 0, 0, 0, &cnt, 0, 0, 0, 0, 0, 0, 0) || cnt == 0) ++g_errors[t];
                    if (RegCloseKey(hs[i])) ++g_errors[t];
                }
            }
        }
    }

    /* phase 6: use a handle while another thread closes it and opens a replacement (the handle value may even be reused).
     * The only acceptable outcomes are success and ERROR_INVALID_HANDLE; the kernel must never fault or hang. */
    barrier(round++);
    if (t == 0) {
        for (j = 0; j < 400; ++j) {
            HKEY nh = 0, old;
            if (RegOpenKeyExW(g_shared, NULL, 0, KEY_READ, &nh)) { ++g_errors[t]; break; }
            old = g_hot;
            g_hot = nh;
            if (old) RegCloseKey(old);
        }
        g_hot_done = 1;
    } else {
        while (!g_hot_done) {
            HKEY h = g_hot;
            DWORD cnt = 0, cb = 4, ty = 0, dv = 0;
            if (!h) continue;
            e = (t & 1) ? RegQueryInfoKeyW(h, 0, 0, 0, &cnt, 0, 0, 0, 0, 0, 0, 0)
                        : RegQueryValueExW(h, L"T0_000", 0, &ty, (BYTE *)&dv, &cb);
            if (e && e != ERROR_INVALID_HANDLE) ++g_errors[t];
            else if (!e) InterlockedIncrement(&g_hot_uses);
        }
    }
    barrier(round++);
    if (t == 0 && g_hot) { RegCloseKey(g_hot); g_hot = 0; }
    shz_free(buf);
    g_done[t] = 2;
    return 0;
}

int main(void)
{
    HANDLE th[NT];
    HKEY root, budget;
    DWORD i, j, tid, disp, cnt;
    LONG e;
    BYTE *blob = shz_malloc(200000);
    printf("t_reg_stress: %d threads on one registry\n", NT);

    /* the previous program left 150 deleted-but-open key handles (about 900 KB of classes) behind: they must have been released */
    delete_tree(HKEY_CURRENT_USER, STRESS);
    e = RegCreateKeyExW(HKEY_CURRENT_USER, STRESS L"\\Budget", 0, 0, 0, KEY_ALL_ACCESS, 0, &budget, &disp);
    CHECK_ERR(e, 0, "create the stress key tree");
    if (blob && budget) {
        DWORD ok = 0;
        static const WCHAR *const vn[4] = { L"b0", L"b1", L"b2", L"b3" };
        memset(blob, 0x33, 200000);
        for (i = 0; i < 4; ++i) if (!RegSetValueExW(budget, vn[i], 0, REG_BINARY, blob, 200000)) ++ok;
        CHECK(ok == 4, "the registry budget is completely free at start: 4 x 200,000 bytes fit (no key node leaked at process exit)");
        for (i = 0; i < 4; ++i) RegDeleteValueW(budget, vn[i]);
    }
    if (budget) RegCloseKey(budget);
    if (blob) shz_free(blob);

    e = RegCreateKeyExW(HKEY_CURRENT_USER, STRESS L"\\Shared", 0, 0, 0, KEY_ALL_ACCESS, 0, &g_shared, &disp);
    CHECK_ERR(e, 0, "create the shared key");
    RegCreateKeyExW(g_shared, L"Race", 0, 0, 0, KEY_ALL_ACCESS, 0, &root, &disp);
    RegCloseKey(root);
    RegCreateKeyExW(g_shared, L"Sub", 0, 0, 0, KEY_ALL_ACCESS, 0, &root, &disp);
    RegCloseKey(root);
    RegCreateKeyExW(g_shared, L"Churn", 0, 0, 0, KEY_ALL_ACCESS, 0, &root, &disp);
    RegCloseKey(root);
    for (i = 0; i < NT; ++i) {
        th[i] = CreateThread(0, TSTACK, worker, (LPVOID)(INT_PTR)i, 0, &tid);
        if (!th[i]) { printf("FAIL: CreateThread %d\n", (int)i); ++g_fail; }
    }
    g_go = 1;
    /* raise g_stop when both writers finished phase 3 (their g_done becomes 1) */
    while (!(g_done[0] && g_done[1])) Sleep(1);
    g_stop = 1;
    for (i = 0; i < NT; ++i) if (th[i]) WaitForSingleObject(th[i], 120000);
    for (i = 0; i < NT; ++i) if (th[i]) CloseHandle(th[i]);

    /* judge */
    {
        LONG created = 0, errors = 0, reads = 0, enums = 0;
        int all_done = 1;
        for (i = 0; i < NT; ++i) { created += g_created[i]; errors += g_errors[i]; reads += g_reads[i]; enums += g_enums[i]; if (g_done[i] != 2) all_done = 0; }
        printf("info: created=%d reads=%d enums=%d errors=%d\n", (int)created, (int)reads, (int)enums, (int)errors);
        CHECK(all_done, "every worker thread ran to the end");
        CHECK(created == 150, "phase 1: of NT racing creators exactly one created each of the 150 keys (150 REG_CREATED_NEW_KEY in total)");
        CHECK(errors == 0, "no worker saw an unexpected result in any phase");
        CHECK(reads > 20 && enums > 20, "readers and the enumerator made progress while the writers ran");
        CHECK(g_hot_uses > 20, "phase 6: handles were used successfully while being closed and replaced under them");
    }
    /* phase 2 verification: nothing was lost */
    e = RegQueryInfoKeyW(g_shared, 0, 0, 0, &cnt, 0, 0, 0, 0, 0, 0, 0);
    CHECK(e == 0 && cnt == 3, "the shared key holds exactly Race, Sub and Churn as sub-keys (all churn keys are gone)");
    {
        HKEY sub, race;
        DWORD subs = 0, vals = 0, bad = 0;
        e = RegOpenKeyExW(g_shared, L"Sub", 0, KEY_READ, &sub);
        if (e == 0) { RegQueryInfoKeyW(sub, 0, 0, 0, &subs, 0, 0, 0, 0, 0, 0, 0); RegCloseKey(sub); }
        CHECK(e == 0 && subs == NT * 40, "phase 2: all 240 sub-keys created concurrently exist");
        e = RegOpenKeyExW(g_shared, L"Race", 0, KEY_READ, &race);
        if (e == 0) { RegQueryInfoKeyW(race, 0, 0, 0, &subs, 0, 0, 0, 0, 0, 0, 0); RegCloseKey(race); }
        CHECK(e == 0 && subs == 150, "phase 1: all 150 racing keys exist exactly once");
        RegQueryInfoKeyW(g_shared, 0, 0, 0, 0, 0, 0, &vals, 0, 0, 0, 0);
        CHECK(vals == NT * 100 + 1, "phase 2: all 600 concurrently written values are there, plus the blob (601)");
        for (i = 0; i < NT; ++i)
            for (j = 0; j < 100; ++j) {
                DWORD v = 0, cb = 4, type = 0;
                WCHAR vn[24] = L"T0_000";
                vn[1] = (WCHAR)(L'0' + i); vn[3] = (WCHAR)(L'0' + j / 100); vn[4] = (WCHAR)(L'0' + j / 10 % 10); vn[5] = (WCHAR)(L'0' + j % 10);
                e = RegQueryValueExW(g_shared, vn, 0, &type, (BYTE *)&v, &cb);
                if (e || type != REG_DWORD || cb != 4 || v != i * 1000 + j) ++bad;
            }
        CHECK(bad == 0, "phase 2: every one of the 600 values has exactly the data its writer stored");
    }
    {
        BYTE *b = shz_malloc(BLOB_MAX + 64);
        DWORD cb = BLOB_MAX + 64, type = 0;
        e = b ? RegQueryValueExW(g_shared, L"blob", 0, &type, b, &cb) : 1;
        CHECK(e == 0 && blob_ok(b, cb), "phase 3: the final blob value is intact");
        if (b) shz_free(b);
    }
    RegCloseKey(g_shared);
    e = delete_tree(HKEY_CURRENT_USER, STRESS);
    CHECK_ERR(e, 0, "the whole stress tree deletes cleanly (every key was empty of sub-keys by the time it was removed)");
    {   /* nothing leaked in the kernel: the budget is free again after 240+150+... keys and thousands of value writes */
        HKEY b2 = 0;
        BYTE *bl = shz_malloc(200000);
        DWORD ok = 0;
        RegCreateKeyExW(HKEY_CURRENT_USER, STRESS, 0, 0, 0, KEY_ALL_ACCESS, 0, &b2, &disp);
        if (bl && b2) {
            memset(bl, 1, 200000);
            for (i = 0; i < 4; ++i) {
                WCHAR vn[4] = L"z0";
                vn[1] = (WCHAR)(L'0' + i);
                if (!RegSetValueExW(b2, vn, 0, REG_BINARY, bl, 200000)) ++ok;
            }
        }
        CHECK(ok == 4, "after the stress run the registry budget is free again (4 x 200,000 bytes fit)");
        if (b2) RegCloseKey(b2);
        if (bl) shz_free(bl);
        delete_tree(HKEY_CURRENT_USER, STRESS);
    }
    return finish_tests("t_reg_stress");
}
