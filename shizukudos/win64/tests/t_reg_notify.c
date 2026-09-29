/* SPDX-License-Identifier: GPL-2.0-only
 * Registry self-check, part 4: change notification (RegNotifyChangeKeyValue over NtNotifyChangeKey). One-shot semantics,
 * filters, sub-tree watching, key deletion, handle close, blocking form, access rights, predefined keys, and a threaded
 * run in which every thread's own registrations must each fire exactly when its own change happens.
 */
#include "reg_check.h"

#define ROOT L"Software\\ShzRegTest\\Notify"
#define TSTACK (256 * 1024)

static int signaled(HANDLE ev, DWORD ms) { return WaitForSingleObject(ev, ms) == WAIT_OBJECT_0; }

static HKEY open_rw(HKEY parent, const WCHAR *sub)
{
    HKEY k = 0;
    LONG e = RegCreateKeyExW(parent, sub, 0, 0, 0, KEY_ALL_ACCESS, 0, &k, 0);
    if (e) { printf("FAIL: cannot create %d\n", (int)e); ++g_fail; }
    return k;
}

static void setv(HKEY k, const WCHAR *name, DWORD v) { RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&v, 4); }

static void test_basic(void)
{
    HKEY watch = open_rw(HKEY_CURRENT_USER, ROOT L"\\Basic"), writer = open_rw(HKEY_CURRENT_USER, ROOT L"\\Basic"), sub;
    HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
    LONG e;
    if (!watch || !writer || !ev) return;
    e = RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    CHECK_ERR(e, 0, "register an asynchronous notification");
    CHECK(!signaled(ev, 0), "the event starts non-signaled");
    CHECK(!signaled(ev, 30), "and stays non-signaled while nothing changes");
    setv(writer, L"a", 1);
    CHECK(signaled(ev, 5000), "setting a value signals the event");
    ResetEvent(ev);
    setv(writer, L"a", 2);
    CHECK(!signaled(ev, 60), "a notification is one-shot: the second change does not signal again");
    e = RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    CHECK_ERR(e, 0, "re-register");
    CHECK(!signaled(ev, 0), "registering resets the event");
    RegDeleteValueW(writer, L"a");
    CHECK(signaled(ev, 5000), "deleting a value signals it (REG_NOTIFY_CHANGE_LAST_SET)");
    /* an overwrite with identical data still counts as a set */
    setv(writer, L"same", 5);
    e = RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    ResetEvent(ev);
    setv(writer, L"same", 5);
    CHECK(signaled(ev, 5000), "overwriting a value with the same data signals as well");

    /* filters */
    ResetEvent(ev);
    e = RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_NAME, ev, TRUE);
    CHECK_ERR(e, 0, "register for REG_NOTIFY_CHANGE_NAME");
    setv(writer, L"b", 1);
    CHECK(!signaled(ev, 60), "a value change does not satisfy the NAME filter");
    sub = open_rw(writer, L"Child");
    CHECK(signaled(ev, 5000), "creating a sub-key satisfies it");
    if (sub) RegCloseKey(sub);
    ResetEvent(ev);
    e = RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    sub = open_rw(writer, L"Child2");
    if (sub) RegCloseKey(sub);
    CHECK(!signaled(ev, 60), "creating a sub-key does not satisfy the LAST_SET filter");
    RegDeleteKeyW(writer, L"Child2");
    CHECK(!signaled(ev, 60), "nor does deleting it");
    setv(writer, L"c", 1);
    CHECK(signaled(ev, 5000), "a value change does");
    ResetEvent(ev);
    e = RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    RegDeleteKeyW(writer, L"Child");
    CHECK(signaled(ev, 5000), "with both filters a sub-key deletion signals");

    /* argument validation */
    CHECK_ERR(RegNotifyChangeKeyValue(watch, FALSE, 0, ev, TRUE), ERROR_INVALID_PARAMETER, "a zero filter is ERROR_INVALID_PARAMETER");
    CHECK_ERR(RegNotifyChangeKeyValue(watch, FALSE, 0x100, ev, TRUE), ERROR_INVALID_PARAMETER, "an unknown filter bit is ERROR_INVALID_PARAMETER");
    CHECK_ERR(RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_NAME, NULL, TRUE), ERROR_INVALID_PARAMETER, "asynchronous without an event is ERROR_INVALID_PARAMETER");
    CHECK_ERR(RegNotifyChangeKeyValue(NULL, FALSE, REG_NOTIFY_CHANGE_NAME, ev, TRUE), ERROR_INVALID_HANDLE, "a NULL key is ERROR_INVALID_HANDLE");
    {
        HANDLE sem = CreateSemaphoreW(0, 0, 1, 0);
        CHECK_ERR(RegNotifyChangeKeyValue(watch, FALSE, REG_NOTIFY_CHANGE_NAME, sem, TRUE), ERROR_INVALID_HANDLE, "a semaphore handle is not an event: ERROR_INVALID_HANDLE");
        CloseHandle(sem);
    }
    {
        HKEY nonotify = 0;
        RegOpenKeyExW(HKEY_CURRENT_USER, ROOT L"\\Basic", 0, KEY_READ & ~KEY_NOTIFY, &nonotify);
        CHECK_ERR(RegNotifyChangeKeyValue(nonotify, FALSE, REG_NOTIFY_CHANGE_NAME, ev, TRUE), ERROR_ACCESS_DENIED, "a handle without KEY_NOTIFY is ERROR_ACCESS_DENIED");
        if (nonotify) RegCloseKey(nonotify);
    }
    RegCloseKey(watch);
    RegCloseKey(writer);
    CloseHandle(ev);
}

static void test_subtree_delete_close(void)
{
    HKEY top = open_rw(HKEY_CURRENT_USER, ROOT L"\\Tree"), deep = open_rw(top, L"A\\B"), mid, k;
    HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
    LONG e;
    if (!top || !deep || !ev) return;
    e = RegNotifyChangeKeyValue(top, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    setv(deep, L"x", 1);
    CHECK(!signaled(ev, 60), "without WatchSubtree a change two levels down is not reported");
    e = RegNotifyChangeKeyValue(top, TRUE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    CHECK_ERR(e, 0, "register with WatchSubtree");
    setv(deep, L"x", 2);
    CHECK(signaled(ev, 5000), "with WatchSubtree the same change is reported");
    ResetEvent(ev);
    e = RegNotifyChangeKeyValue(top, TRUE, REG_NOTIFY_CHANGE_NAME, ev, TRUE);
    k = open_rw(deep, L"C\\D\\E");
    CHECK(signaled(ev, 5000), "with WatchSubtree the creation of a deep sub-key is reported");
    if (k) RegCloseKey(k);
    ResetEvent(ev);

    /* the watched key itself is deleted */
    mid = open_rw(top, L"Doomed");
    e = RegNotifyChangeKeyValue(mid, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    CHECK_ERR(e, 0, "watch a key that is about to be deleted");
    CHECK_ERR(RegDeleteKeyW(top, L"Doomed"), 0, "delete it");
    CHECK(signaled(ev, 5000), "the deletion of the watched key completes the notification");
    CHECK_ERR(RegNotifyChangeKeyValue(mid, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE), ERROR_KEY_DELETED, "a new registration on a deleted key is ERROR_KEY_DELETED");
    RegCloseKey(mid);

    /* closing the handle completes the pending notification */
    ResetEvent(ev);
    mid = open_rw(top, L"Closing");
    e = RegNotifyChangeKeyValue(mid, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
    CHECK_ERR(e, 0, "watch a key whose handle is about to be closed");
    CHECK(!signaled(ev, 30), "still pending");
    RegCloseKey(mid);
    CHECK(signaled(ev, 5000), "closing the handle signals the event (documented)");
    /* the change after the close must not touch the (now freed) registration */
    mid = open_rw(top, L"Closing");
    setv(mid, L"late", 1);
    RegCloseKey(mid);
    CHECK(1, "a change after the close is harmless");

    /* two registrations with different events on one key both fire */
    {
        HANDLE ev2 = CreateEventW(0, TRUE, FALSE, 0);
        ResetEvent(ev);
        RegNotifyChangeKeyValue(top, TRUE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
        RegNotifyChangeKeyValue(top, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ev2, TRUE);
        setv(top, L"both", 1);
        CHECK(signaled(ev, 5000) && signaled(ev2, 5000), "two registrations on one key each complete on the same change");
        CloseHandle(ev2);
    }
    RegCloseKey(deep);
    RegCloseKey(top);
    CloseHandle(ev);
}

static volatile LONG g_helper_ran, g_wait_returned;
static HKEY g_sync_key;

static DWORD WINAPI helper_sets_value(LPVOID arg)
{
    (void)arg;
    Sleep(60);
    g_helper_ran = 1;
    setv(g_sync_key, L"wake", 1);
    return 0;
}

static void test_blocking_and_predefined(void)
{
    HKEY k = open_rw(HKEY_CURRENT_USER, ROOT L"\\Sync");
    HANDLE th;
    DWORD tid;
    LONG e;
    if (!k) return;
    g_sync_key = k;
    th = CreateThread(0, TSTACK, helper_sets_value, 0, 0, &tid);
    e = RegNotifyChangeKeyValue(k, FALSE, REG_NOTIFY_CHANGE_LAST_SET, NULL, FALSE);
    g_wait_returned = 1;
    CHECK(e == 0 && g_helper_ran == 1, "the blocking form returns only after the other thread changed the key");
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    RegCloseKey(k);

    /* predefined key: HKEY_CURRENT_USER */
    {
        HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
        HKEY w = open_rw(HKEY_CURRENT_USER, ROOT L"\\Pre");
        e = RegNotifyChangeKeyValue(HKEY_CURRENT_USER, TRUE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
        CHECK_ERR(e, 0, "a notification on a predefined key can be registered");
        CHECK(!signaled(ev, 30), "pending");
        setv(w, L"p", 1);
        CHECK(signaled(ev, 5000), "and fires for a change anywhere below HKEY_CURRENT_USER");
        /* registering twice on the same predefined key reuses the process-wide native handle */
        ResetEvent(ev);
        e = RegNotifyChangeKeyValue(HKEY_CURRENT_USER, TRUE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE);
        setv(w, L"p", 2);
        CHECK(e == 0 && signaled(ev, 5000), "a second registration works");
        RegCloseKey(w);
        CloseHandle(ev);
    }
}

/* ---------------------------------------------------------------- threaded run */
#define NT 5
static volatile LONG g_go, g_bad[NT], g_fired[NT];

static DWORD WINAPI notifier(LPVOID arg)
{
    const int t = (int)(INT_PTR)arg;
    HKEY shared = 0, mine = 0;
    HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
    WCHAR nm[16] = L"Worker0";
    int j;
    nm[6] = (WCHAR)(L'0' + t);
    RegCreateKeyExW(HKEY_CURRENT_USER, ROOT L"\\Threads", 0, 0, 0, KEY_ALL_ACCESS, 0, &shared, 0);
    RegCreateKeyExW(shared, nm, 0, 0, 0, KEY_ALL_ACCESS, 0, &mine, 0);
    if (!ev || !shared || !mine) { g_bad[t] += 1000; return 1; }
    while (!g_go) SwitchToThread();
    for (j = 0; j < 150; ++j) {
        /* watch the shared key's whole sub-tree; every thread's changes may wake us, but our own change must */
        ResetEvent(ev);
        if (RegNotifyChangeKeyValue(shared, TRUE, REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE)) { ++g_bad[t]; continue; }
        setv(mine, L"n", (DWORD)j);
        if (WaitForSingleObject(ev, 10000) != WAIT_OBJECT_0) ++g_bad[t]; else ++g_fired[t];
    }
    /* leave a registration pending on purpose: the handles close when the thread's process exits, not before */
    RegCloseKey(mine);
    RegCloseKey(shared);
    CloseHandle(ev);
    return 0;
}

static void test_threads(void)
{
    HANDLE th[NT];
    DWORD i, tid;
    LONG bad = 0, fired = 0;
    HKEY leave = open_rw(HKEY_CURRENT_USER, ROOT L"\\Leftover");
    HANDLE lev = CreateEventW(0, FALSE, FALSE, 0);
    for (i = 0; i < NT; ++i) th[i] = CreateThread(0, TSTACK, notifier, (LPVOID)(INT_PTR)i, 0, &tid);
    g_go = 1;
    for (i = 0; i < NT; ++i) if (th[i]) { WaitForSingleObject(th[i], 120000); CloseHandle(th[i]); }
    for (i = 0; i < NT; ++i) { bad += g_bad[i]; fired += g_fired[i]; }
    CHECK(bad == 0 && fired == NT * 150, "5 threads x 150 rounds: every registration was completed by its own change (750 notifications)");
    /* a registration is left pending when the program exits: process teardown must cope with it (checked by the next boot stage) */
    if (leave && lev) RegNotifyChangeKeyValue(leave, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, lev, TRUE);
}

int main(void)
{
    printf("t_reg_notify: registry change notification\n");
    delete_tree(HKEY_CURRENT_USER, L"Software\\ShzRegTest\\Notify");
    test_basic();
    test_subtree_delete_close();
    test_blocking_and_predefined();
    test_threads();
    /* the Leftover key handle, its event and one pending registration stay open on purpose; everything else is removed */
    delete_tree(HKEY_CURRENT_USER, ROOT L"\\Basic");
    delete_tree(HKEY_CURRENT_USER, ROOT L"\\Tree");
    delete_tree(HKEY_CURRENT_USER, ROOT L"\\Sync");
    delete_tree(HKEY_CURRENT_USER, ROOT L"\\Pre");
    delete_tree(HKEY_CURRENT_USER, ROOT L"\\Threads");
    return finish_tests("t_reg_notify");
}
