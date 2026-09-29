/* SPDX-License-Identifier: GPL-2.0-only
 * Window station, desktop, and a few window calls. A null class, hwnd, or
 * short buffer fails. Wine user32 was not copied.
 */
#include "user32.h"
#define STATION 0x5100u
#define DESKTOP 0x5200u
#define OBJ_N 4u
static struct { int live; uint16_t name[16]; } stations[OBJ_N];
static struct { int live; uint16_t name[16]; } desks[OBJ_N];
static uint32_t current_station;
static uint32_t current_desk;
static int objects_ready;
static void put_ascii(uint16_t *out, const char *text) {
    uint32_t i = 0;
    while (text[i] && i + 1 < 16) { out[i] = (uint8_t)text[i]; i++; }
    out[i] = 0;
}
static void ensure_objects(void) {
    if (objects_ready) return;
    objects_ready = 1;
    stations[0].live = 1;
    put_ascii(stations[0].name, "WinSta0");
    desks[0].live = 1;
    put_ascii(desks[0].name, "Default");
    current_station = STATION;
    current_desk = DESKTOP;
}
static int station_slot(uint32_t handle) {
    uint32_t slot;
    ensure_objects();
    if (handle < STATION || handle - STATION >= OBJ_N) return -1;
    slot = handle - STATION;
    return stations[slot].live ? (int)slot : -1;
}
static int desk_slot(uint32_t handle) {
    uint32_t slot;
    ensure_objects();
    if (handle < DESKTOP || handle - DESKTOP >= OBJ_N) return -1;
    slot = handle - DESKTOP;
    return desks[slot].live ? (int)slot : -1;
}
#define WIN_BASE 0x5300u
#define WIN_SLOTS 32u
static uint32_t *errp;
static uint32_t quit;
static struct { int live; uint16_t name[64]; uint32_t atom; } classes[16];
static struct { int live; uint32_t cls; } windows[WIN_SLOTS];
static uint32_t next_atom = 0xc000u;
static void (*user_note)(const char *);
void ntw_user_bind(uint32_t *last_error) { errp = last_error; }
void ntw_user_set_log(void (*fn)(const char *text)) { user_note = fn; }
static void note(const char *text) { if (user_note) user_note(text); }
int ntw_user_owns(uint32_t handle) {
    return station_slot(handle) >= 0 || desk_slot(handle) >= 0;
}
static void fail(uint32_t code) { if (errp) *errp = code; }
static int same(const char *a, const char *b) {
    while (*a && *b) {
        char x = *a++, y = *b++;
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return 0;
    }
    return *a == *b;
}
static int copy_name(const uint16_t *name, uint16_t *out) {
    uint32_t i = 0;
    if (!name || !name[0]) return 0;
    while (name[i] && i + 1 < 64) { out[i] = name[i]; i++; }
    if (name[i]) return 0;
    out[i] = 0;
    return 1;
}
static int class_index(const uint16_t *name) {
    uint16_t tmp[64];
    uint32_t i, k;
    if (!copy_name(name, tmp)) return -1;
    for (i = 0; i < 16; ++i) if (classes[i].live) {
        for (k = 0; classes[i].name[k] && classes[i].name[k] == tmp[k]; ++k);
        if (classes[i].name[k] == tmp[k]) return (int)i;
    }
    return -1;
}
static uint32_t __attribute__((stdcall)) allow_fg(uint32_t pid) { (void)pid; return 1; }
static uint32_t __attribute__((stdcall)) close_desktop(uint32_t desk) {
    int slot = desk_slot(desk);
    if (slot <= 0) { fail(slot < 0 ? 6u : 5u); return 0; }
    desks[slot].live = 0;
    if (current_desk == desk) current_desk = DESKTOP;
    return 1;
}
static uint32_t __attribute__((stdcall)) close_station(uint32_t station) {
    int slot = station_slot(station);
    if (slot <= 0) { fail(slot < 0 ? 6u : 5u); return 0; }
    stations[slot].live = 0;
    if (current_station == station) current_station = STATION;
    return 1;
}
static uint32_t __attribute__((stdcall)) create_desktop(uint32_t name, uint32_t a, uint32_t b, uint32_t flags, uint32_t access, uint32_t sec) {
    uint32_t i;
    (void)a; (void)b; (void)flags; (void)access; (void)sec;
    ensure_objects();
    if (name && !*(const uint16_t *)(unsigned long)name) { fail(87); return 0; }
    for (i = 1; i < OBJ_N; ++i) if (!desks[i].live) {
        desks[i].live = 1;
        if (name) {
            uint32_t n = 0;
            const uint16_t *src = (const uint16_t *)(unsigned long)name;
            while (src[n] && n + 1 < 16) { desks[i].name[n] = src[n]; n++; }
            if (src[n]) { desks[i].live = 0; fail(87); return 0; }
            desks[i].name[n] = 0;
        } else put_ascii(desks[i].name, "AltDesk");
        note("desktop\n");
        return DESKTOP + i;
    }
    fail(8);
    return 0;
}
static uint32_t __attribute__((stdcall)) create_station(uint32_t name, uint32_t a, uint32_t access, uint32_t sec) {
    uint32_t i;
    (void)a; (void)access; (void)sec;
    ensure_objects();
    if (name && !*(const uint16_t *)(unsigned long)name) { fail(87); return 0; }
    for (i = 1; i < OBJ_N; ++i) if (!stations[i].live) {
        stations[i].live = 1;
        if (name) {
            uint32_t n = 0;
            const uint16_t *src = (const uint16_t *)(unsigned long)name;
            while (src[n] && n + 1 < 16) { stations[i].name[n] = src[n]; n++; }
            if (src[n]) { stations[i].live = 0; fail(87); return 0; }
            stations[i].name[n] = 0;
        } else put_ascii(stations[i].name, "AltSta");
        note("winsta\n");
        return STATION + i;
    }
    fail(8);
    return 0;
}
static uint32_t __attribute__((stdcall)) create_window(uint32_t ex, const uint16_t *cls, const uint16_t *title, uint32_t style,
                                                     int32_t x, int32_t y, int32_t w, int32_t h, uint32_t parent,
                                                     uint32_t menu, uint32_t inst, uint32_t param) {
    int idx;
    uint32_t i;
    (void)ex; (void)title; (void)style; (void)x; (void)y; (void)w; (void)h; (void)parent; (void)menu; (void)inst; (void)param;
    idx = class_index(cls);
    if (idx < 0) { fail(1407); return 0; }
    for (i = 0; i < WIN_SLOTS; ++i) if (!windows[i].live) {
        windows[i].live = 1;
        windows[i].cls = (uint32_t)idx;
        return WIN_BASE + i;
    }
    fail(8);
    return 0;
}
static uint32_t __attribute__((stdcall)) def_proc(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    (void)hwnd; (void)msg; (void)wp; (void)lp;
    return 0;
}
static uint32_t __attribute__((stdcall)) destroy_window(uint32_t hwnd) {
    uint32_t slot = hwnd - WIN_BASE;
    if (hwnd < WIN_BASE || slot >= WIN_SLOTS || !windows[slot].live) { fail(1400); return 0; }
    windows[slot].live = 0;
    return 1;
}
static int32_t __attribute__((stdcall)) dispatch_message(uint32_t msg) { (void)msg; return 0; }
static uint32_t __attribute__((stdcall)) find_window(uint32_t parent, uint32_t child, const uint16_t *cls, const uint16_t *title) {
    (void)parent; (void)child; (void)cls; (void)title;
    return 0;
}
static int32_t __attribute__((stdcall)) get_message(uint32_t msg, uint32_t hwnd, uint32_t min, uint32_t max) {
    (void)msg; (void)hwnd; (void)min; (void)max;
    return quit ? 0 : 0;
}
static uint32_t __attribute__((stdcall)) process_station(void) { ensure_objects(); return current_station; }
static uint32_t __attribute__((stdcall)) queue_status(uint32_t flags) { (void)flags; return 0; }
static uint32_t __attribute__((stdcall)) thread_desktop(uint32_t tid) { (void)tid; ensure_objects(); return current_desk; }
static uint32_t __attribute__((stdcall)) user_object_info(uint32_t object, uint32_t index, uint32_t buffer, uint32_t bytes, uint32_t *needed) {
    const uint16_t *name = 0;
    uint32_t n = 0, i;
    int ss = station_slot(object), ds = desk_slot(object);
    if (ss >= 0) name = stations[ss].name;
    else if (ds >= 0) name = desks[ds].name;
    else { fail(6); return 0; }
    if (index != 2) { fail(87); note("uoi\n"); return 0; }
    while (name[n]) n++;
    n++;
    if (needed) *needed = n * 2u;
    if (bytes < n * 2u || !buffer) { fail(122); return 0; }
    {
        uint16_t *out = (uint16_t *)(unsigned long)buffer;
        for (i = 0; i < n; ++i) out[i] = name[i];
    }
    return 1;
}
static int32_t __attribute__((stdcall)) get_window_long(uint32_t hwnd, int32_t index) {
    uint32_t slot = hwnd - WIN_BASE;
    (void)index;
    if (hwnd < WIN_BASE || slot >= WIN_SLOTS || !windows[slot].live) { fail(1400); return 0; }
    return 0;
}
static uint32_t __attribute__((stdcall)) window_thread(uint32_t hwnd, uint32_t *pid) {
    uint32_t slot = hwnd - WIN_BASE;
    if (hwnd < WIN_BASE || slot >= WIN_SLOTS || !windows[slot].live) { fail(1400); return 0; }
    if (pid) *pid = 1;
    return 1;
}
static uint32_t __attribute__((stdcall)) is_window(uint32_t hwnd) {
    uint32_t slot = hwnd - WIN_BASE;
    return hwnd >= WIN_BASE && slot < WIN_SLOTS && windows[slot].live;
}
static uint32_t __attribute__((stdcall)) kill_timer(uint32_t hwnd, uint32_t id) { (void)hwnd; (void)id; return 1; }
static uint32_t __attribute__((stdcall)) msg_wait(uint32_t count, uint32_t handles, uint32_t wake, uint32_t ms, uint32_t flags) {
    (void)count; (void)handles; (void)wake; (void)ms; (void)flags;
    return 258;
}
static uint32_t __attribute__((stdcall)) peek_message(uint32_t msg, uint32_t hwnd, uint32_t min, uint32_t max, uint32_t remove) {
    (void)msg; (void)hwnd; (void)min; (void)max; (void)remove;
    return 0;
}
static uint32_t __attribute__((stdcall)) post_message(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    (void)msg; (void)wp; (void)lp;
    if (hwnd && !is_window(hwnd)) { fail(1400); return 0; }
    return 1;
}
static void __attribute__((stdcall)) post_quit(int32_t code) { (void)code; quit = 1; }
static uint32_t register_named(const uint16_t *name) {
    uint32_t i;
    if (class_index(name) >= 0) { fail(1410); return 0; }
    for (i = 0; i < 16; ++i) if (!classes[i].live) {
        if (!copy_name(name, classes[i].name)) { fail(87); return 0; }
        classes[i].live = 1;
        classes[i].atom = next_atom++;
        return classes[i].atom;
    }
    fail(8);
    return 0;
}
static uint32_t __attribute__((stdcall)) register_class_ex(uint32_t cls) {
    if (!cls) { fail(87); return 0; }
    return register_named(*(const uint16_t **)(unsigned long)(cls + 40));
}
static uint32_t __attribute__((stdcall)) register_class(uint32_t cls) {
    if (!cls) { fail(87); return 0; }
    return register_named(*(const uint16_t **)(unsigned long)(cls + 36));
}
static uint32_t __attribute__((stdcall)) send_timeout(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp, uint32_t flags, uint32_t ms, uint32_t *result) {
    (void)msg; (void)wp; (void)lp; (void)flags; (void)ms;
    if (!is_window(hwnd)) { fail(1400); return 0; }
    if (result) *result = 0;
    return 1;
}
static uint32_t __attribute__((stdcall)) set_station(uint32_t station) {
    if (station_slot(station) < 0) { fail(6); note("setstafail\n"); return 0; }
    current_station = station;
    note("setsta\n");
    return 1;
}
static uint32_t __attribute__((stdcall)) set_desktop(uint32_t desk) {
    if (desk_slot(desk) < 0) { fail(6); return 0; }
    current_desk = desk;
    return 1;
}
static uint32_t __attribute__((stdcall)) set_timer(uint32_t hwnd, uint32_t id, uint32_t elapse, uint32_t proc) {
    (void)hwnd; (void)elapse; (void)proc;
    return id ? id : 1u;
}
static int32_t __attribute__((stdcall)) set_window_long(uint32_t hwnd, int32_t index, int32_t value) {
    (void)index; (void)value;
    if (!is_window(hwnd)) { fail(1400); return 0; }
    return 0;
}
static uint32_t __attribute__((stdcall)) translate_message(uint32_t msg) { (void)msg; return 0; }
static uint32_t __attribute__((stdcall)) unregister_class(const uint16_t *name, uint32_t inst) {
    int idx;
    (void)inst;
    idx = class_index(name);
    if (idx < 0) { fail(1411); return 0; }
    classes[idx].live = 0;
    return 1;
}
uint32_t ntw_user_export(const char *name) {
    if (same(name, "AllowSetForegroundWindow")) return (uint32_t)(unsigned long)allow_fg;
    if (same(name, "CloseDesktop")) return (uint32_t)(unsigned long)close_desktop;
    if (same(name, "CloseWindowStation")) return (uint32_t)(unsigned long)close_station;
    if (same(name, "CreateDesktopW")) return (uint32_t)(unsigned long)create_desktop;
    if (same(name, "CreateWindowExW")) return (uint32_t)(unsigned long)create_window;
    if (same(name, "CreateWindowStationW")) return (uint32_t)(unsigned long)create_station;
    if (same(name, "DefWindowProcW")) return (uint32_t)(unsigned long)def_proc;
    if (same(name, "DestroyWindow")) return (uint32_t)(unsigned long)destroy_window;
    if (same(name, "DispatchMessageW")) return (uint32_t)(unsigned long)dispatch_message;
    if (same(name, "FindWindowExW")) return (uint32_t)(unsigned long)find_window;
    if (same(name, "GetMessageW")) return (uint32_t)(unsigned long)get_message;
    if (same(name, "GetProcessWindowStation")) return (uint32_t)(unsigned long)process_station;
    if (same(name, "GetQueueStatus")) return (uint32_t)(unsigned long)queue_status;
    if (same(name, "GetThreadDesktop")) return (uint32_t)(unsigned long)thread_desktop;
    if (same(name, "GetUserObjectInformationW")) return (uint32_t)(unsigned long)user_object_info;
    if (same(name, "GetWindowLongW")) return (uint32_t)(unsigned long)get_window_long;
    if (same(name, "GetWindowThreadProcessId")) return (uint32_t)(unsigned long)window_thread;
    if (same(name, "IsWindow")) return (uint32_t)(unsigned long)is_window;
    if (same(name, "KillTimer")) return (uint32_t)(unsigned long)kill_timer;
    if (same(name, "MsgWaitForMultipleObjectsEx")) return (uint32_t)(unsigned long)msg_wait;
    if (same(name, "PeekMessageW")) return (uint32_t)(unsigned long)peek_message;
    if (same(name, "PostMessageW")) return (uint32_t)(unsigned long)post_message;
    if (same(name, "PostQuitMessage")) return (uint32_t)(unsigned long)post_quit;
    if (same(name, "RegisterClassExW")) return (uint32_t)(unsigned long)register_class_ex;
    if (same(name, "RegisterClassW")) return (uint32_t)(unsigned long)register_class;
    if (same(name, "SendMessageTimeoutW")) return (uint32_t)(unsigned long)send_timeout;
    if (same(name, "SetProcessWindowStation")) return (uint32_t)(unsigned long)set_station;
    if (same(name, "SetThreadDesktop")) return (uint32_t)(unsigned long)set_desktop;
    if (same(name, "SetTimer")) return (uint32_t)(unsigned long)set_timer;
    if (same(name, "SetWindowLongW")) return (uint32_t)(unsigned long)set_window_long;
    if (same(name, "TranslateMessage")) return (uint32_t)(unsigned long)translate_message;
    if (same(name, "UnregisterClassW")) return (uint32_t)(unsigned long)unregister_class;
    return 0;
}
