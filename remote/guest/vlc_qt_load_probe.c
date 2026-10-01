/* SPDX-License-Identifier: GPL-2.0-only
 * GUI-only fixed-path resolver diagnostic. No VLC/Core/provider bytes change.
 * Only an absent registry setting for this new helper may be created.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "sha256.h"
#include "vlc_qt_pins.h"
#define SELF "C:\\VXDLAB\\QTLOAD.EXE"
#define CONFIGS "Software\\KernelEx\\AppSettings\\Configs"
#define FLAGS "Software\\KernelEx\\AppSettings\\Flags"
static HANDLE report = INVALID_HANDLE_VALUE;
static int io_failed;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; } return *a == *b;
}
static int same_path(const char *a, const char *b) {
    while (*a && *b) {
        char x = *a++, y = *b++;
        if (x >= 'a' && x <= 'z') x -= 'a' - 'A';
        if (y >= 'a' && y <= 'z') y -= 'a' - 'A';
        if (x != y) return 0;
    }
    return *a == *b;
}
static void text(const char *s) {
    DWORD n = length(s), done;
    if (!WriteFile(report, s, n, &done, NULL) || done != n) io_failed = 1;
}
static void number(const char *name, DWORD n) {
    char data[9]; unsigned i;
    for (i = 0; i < 8; ++i) data[i] = "0123456789ABCDEF"[(n >> (28 - i * 4)) & 15];
    data[8] = 0; text(name); text(data); text("\r\n");
}
static int flush(void) {
    if (io_failed || !FlushFileBuffers(report)) { io_failed = 1; return 0; } return 1;
}
static const char *argument(void) {
    const char *s = GetCommandLineA(); BOOL quoted = FALSE;
    while (*s) {
        if (*s == '"') quoted = !quoted;
        else if (!quoted && (*s == ' ' || *s == '\t')) break;
        ++s;
    }
    while (*s == ' ' || *s == '\t') ++s;
    return s;
}
static int absent(const char *path) {
    DWORD error;
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) return 0;
    error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
static int exact(const char *path, const char *pin, DWORD bytes) {
    static BYTE block[4096];
    HANDLE file; sha256_ctx hash; BYTE digest[32]; char hex[65];
    DWORD count, total = 0; int good = 1;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    sha256_init(&hash);
    for (;;) {
        if (!ReadFile(file, block, sizeof(block), &count, NULL)) { good = 0; break; }
        if (!count) break;
        if (total > bytes || count > bytes - total) { good = 0; break; }
        total += count; sha256_update(&hash, block, count);
    }
    if (!CloseHandle(file)) good = 0;
    sha256_final(&hash, digest); sha256_hex(digest, hex);
    return good && total == bytes && same(hex, pin);
}
static int pinned_inputs(void) {
    unsigned i; int good = 1;
    for (i = 0; i < QT_PIN_COUNT; ++i) {
        int match = exact(qt_pins[i].path, qt_pins[i].sha256, qt_pins[i].bytes);
        text("PIN_PATH="); text(qt_pins[i].path); text("\r\n"); number("EXACT_INPUT_SHA256=", match);
        if (!match) good = 0;
    }
    return good && flush();
}
typedef PROC (__cdecl *original_resolver)(HMODULE, LPCSTR);
typedef void (__cdecl *get_settings)(const char *, char *, DWORD *);
typedef void (__cdecl *set_settings)(const char *, const char *, DWORD);
typedef void (__cdecl *reset_settings)(const char *);
static int actual_win98(void) {
    HMODULE kex = LoadLibraryA("C:\\WINDOWS\\KernelEx\\KERNELEX.DLL");
    union { FARPROC raw; original_resolver resolver; } service;
    union { FARPROC raw; BOOL (WINAPI *version)(LPOSVERSIONINFOA); } version;
    OSVERSIONINFOA info = {0}; int good = 0;
    if (!kex) { number("KERNELEX_LOAD_ERROR=", GetLastError()); return 0; }
    service.raw = GetProcAddress(kex, "kexGetProcAddress");
    number("ORIGINAL_RESOLVER_ADDRESS=", (DWORD)(ULONG_PTR)service.raw);
    if (service.raw) {
        version.raw = service.resolver(GetModuleHandleA("KERNEL32.DLL"), "GetVersionExA");
        number("ORIGINAL_VERSION_ADDRESS=", (DWORD)(ULONG_PTR)version.raw);
        info.dwOSVersionInfoSize = sizeof(info);
        if (version.raw && version.version(&info)) {
            number("ORIGINAL_OS_MAJOR=", info.dwMajorVersion); number("ORIGINAL_OS_MINOR=", info.dwMinorVersion);
            number("ORIGINAL_OS_BUILD=", info.dwBuildNumber & 0xffff); number("ORIGINAL_OS_PLATFORM=", info.dwPlatformId);
            good = info.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && info.dwMajorVersion == 4 &&
                   info.dwMinorVersion == 10 && (info.dwBuildNumber & 0xffff) == 2222;
        }
    }
    if (!FreeLibrary(kex)) good = 0;
    return good;
}
static int inspect_mode(HKEY configs, HKEY flags, int *missing, int *expected) {
    char name[16] = {0}; DWORD bytes = sizeof(name), kind = 0, value = 0, value_bytes = sizeof(value), value_kind = 0;
    LONG a = RegQueryValueExA(configs, SELF, NULL, &kind, (BYTE *)name, &bytes);
    LONG b = RegQueryValueExA(flags, SELF, NULL, &value_kind, (BYTE *)&value, &value_bytes);
    number("OWN_CONFIG_QUERY_STATUS=", a); number("OWN_CONFIG_TYPE=", kind);
    number("OWN_CONFIG_BYTES=", bytes);
    if (a == ERROR_SUCCESS && kind == REG_SZ && bytes > 0 && bytes <= sizeof(name) && name[bytes - 1] == 0) {
        text("OWN_CONFIG_VALUE="); text(name); text("\r\n");
    }
    number("OWN_FLAGS_QUERY_STATUS=", b); number("OWN_FLAGS_TYPE=", value_kind);
    number("OWN_FLAGS_BYTES=", value_bytes); number("OWN_FLAGS_VALUE=", value);
    *missing = a == ERROR_FILE_NOT_FOUND && b == ERROR_FILE_NOT_FOUND;
    *expected = a == ERROR_SUCCESS && b == ERROR_SUCCESS && kind == REG_SZ && bytes == 6 && name[5] == 0 &&
                same(name, "WINXP") && value_kind == REG_DWORD && value_bytes == 4 && value == 0;
    return (a == ERROR_SUCCESS || a == ERROR_FILE_NOT_FOUND) && (b == ERROR_SUCCESS || b == ERROR_FILE_NOT_FOUND);
}
static int configure_own_mode(void) {
    HKEY configs = NULL, flags = NULL; DWORD zero = 0; LONG error; int missing = 0, expected = 0, good = 0;
    int owned_config = 0, owned_flags = 0, runtime_owned = 0;
    HMODULE kex = NULL; char runtime_name[256] = {0}; DWORD runtime_flags = 0;
    union { FARPROC raw; get_settings get; } getter;
    union { FARPROC raw; set_settings set; } setter;
    union { FARPROC raw; reset_settings reset; } resetter;
    kex = LoadLibraryA("C:\\WINDOWS\\KernelEx\\KERNELEX.DLL");
    if (!kex) return 0;
    getter.raw = GetProcAddress(kex, "kexGetModuleSettings");
    setter.raw = GetProcAddress(kex, "kexSetModuleSettings");
    resetter.raw = GetProcAddress(kex, "kexResetModuleSettings");
    if (!getter.raw || !setter.raw || !resetter.raw) { FreeLibrary(kex); return 0; }
    /* Read existing settings before changing only this new helper's absent
     * entry. These observations distinguish a dropped WINXP API configuration
     * from a registry/profile-name or same-boot cache failure. */
    getter.get(SELF, runtime_name, &runtime_flags);
    text("OWN_RUNTIME_PROFILE_BEFORE="); text(runtime_name); text("\r\n");
    number("OWN_RUNTIME_FLAGS_BEFORE=", runtime_flags);
    getter.get("C:\\VLCLAB\\VLC\\PLUGINS\\GUI\\LIBQT_PLUGIN.DLL", runtime_name, &runtime_flags);
    text("QT_EXISTING_RUNTIME_PROFILE="); text(runtime_name); text("\r\n");
    number("QT_EXISTING_RUNTIME_FLAGS=", runtime_flags);
    getter.get("C:\\NPPLAB\\APP\\NPP.EXE", runtime_name, &runtime_flags);
    text("NPP_EXISTING_RUNTIME_PROFILE="); text(runtime_name); text("\r\n");
    number("NPP_EXISTING_RUNTIME_FLAGS=", runtime_flags);
    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, CONFIGS, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &configs);
    if (error != ERROR_SUCCESS) goto done;
    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, FLAGS, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &flags);
    if (error != ERROR_SUCCESS) goto done;
    if (!inspect_mode(configs, flags, &missing, &expected) || !missing) {
        number("MODE_REFUSED_NONABSENT_OR_INVALID_VALUES=", 1); goto done;
    }
    number("OWN_MODE_VALUES_PREVIOUSLY_ABSENT=", 1);
    error = RegSetValueExA(configs, SELF, 0, REG_SZ, (const BYTE *)"WINXP", 6);
    if (error != ERROR_SUCCESS) goto done;
    owned_config = 1;
    error = RegSetValueExA(flags, SELF, 0, REG_DWORD, (const BYTE *)&zero, 4);
    if (error != ERROR_SUCCESS) goto done;
    owned_flags = 1;
    /* KernelEx caches AppSettings; direct registry writes alone are insufficient
     * in this same boot. Its original narrow service refreshes this owned path
     * only. No global flush, module/default mode or other app setting changes. */
    setter.set(SELF, "WINXP", 0); runtime_owned = 1;
    getter.get(SELF, runtime_name, &runtime_flags);
    text("OWN_RUNTIME_PROFILE_AFTER="); text(runtime_name); text("\r\n");
    number("OWN_RUNTIME_MODE_FLAGS=", runtime_flags);
    number("OWN_POST_SETTER_REGISTRY_INSPECTION=", 1);
    if (!inspect_mode(configs, flags, &missing, &expected)) goto done;
    if (!same(runtime_name, "WINXP") || runtime_flags != 128) goto done;
    error = RegFlushKey(configs);
    number("OWN_CONFIG_FLUSH_STATUS=", error); if (error != ERROR_SUCCESS) goto done;
    error = RegFlushKey(flags);
    number("OWN_FLAGS_FLUSH_STATUS=", error); if (error != ERROR_SUCCESS) goto done;
    if (!inspect_mode(configs, flags, &missing, &expected) || !expected) goto done;
    good = 1; number("OWN_MODE_EXACT_WINXP_ZERO=", 1);
done:
    if (!good) {
        int restored = 1;
        if (runtime_owned) {
            resetter.reset(SELF);
            getter.get(SELF, runtime_name, &runtime_flags);
            if (runtime_name[0] || (runtime_flags & 128)) restored = 0;
        } else {
            if (owned_config && RegDeleteValueA(configs, SELF) != ERROR_SUCCESS) restored = 0;
            if (owned_flags && RegDeleteValueA(flags, SELF) != ERROR_SUCCESS) restored = 0;
        }
        if (owned_config || owned_flags) {
            if (RegFlushKey(configs) != ERROR_SUCCESS || RegFlushKey(flags) != ERROR_SUCCESS ||
                !inspect_mode(configs, flags, &missing, &expected) || !missing) restored = 0;
            number("OWN_PARTIAL_MODE_ROLLBACK_ABSENT=", restored);
        }
        number("MODE_FAILURE_ERROR=", error);
    }
    if (flags && RegCloseKey(flags) != ERROR_SUCCESS) good = 0;
    if (configs && RegCloseKey(configs) != ERROR_SUCCESS) good = 0;
    if (!FreeLibrary(kex)) good = 0;
    return good && flush();
}
static DWORD worker(void) {
    HMODULE modules[QT_MODULE_COUNT] = {0}, qt = NULL;
    DWORD load_error = 0, unresolved = 0, release_failed = 0, inspected = 0; unsigned i;
    HKEY configs = NULL, flags = NULL; int missing = 0, expected = 0;
    if (!pinned_inputs() || !actual_win98()) return 3;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CONFIGS, 0, KEY_QUERY_VALUE, &configs) != ERROR_SUCCESS ||
        RegOpenKeyExA(HKEY_LOCAL_MACHINE, FLAGS, 0, KEY_QUERY_VALUE, &flags) != ERROR_SUCCESS) goto mode_fail;
    if (!inspect_mode(configs, flags, &missing, &expected) || !expected) goto mode_fail;
    if (RegCloseKey(configs) != ERROR_SUCCESS || RegCloseKey(flags) != ERROR_SUCCESS) return 3;
    configs = flags = NULL;
    number("WORKER_MODE_EXACT_WINXP_ZERO=", 1); if (!flush()) return 31;
    {
        HMODULE kex = LoadLibraryA("C:\\WINDOWS\\KernelEx\\KERNELEX.DLL");
        union { FARPROC raw; get_settings get; } getter;
        char name[256]; DWORD flags_value = 0;
        if (!kex) return 3;
        getter.raw = GetProcAddress(kex, "kexGetModuleSettings");
        if (!getter.raw) { FreeLibrary(kex); return 3; }
        getter.get(SELF, name, &flags_value);
        text("WORKER_RUNTIME_PROFILE="); text(name); text("\r\n"); number("WORKER_RUNTIME_FLAGS=", flags_value);
        if (!same(name, "WINXP") || flags_value != 128) { FreeLibrary(kex); return 3; }
        getter.get("C:\\VLCLAB\\VLC\\PLUGINS\\GUI\\LIBQT_PLUGIN.DLL", name, &flags_value);
        text("QT_RUNTIME_PROFILE="); text(name); text("\r\n"); number("QT_RUNTIME_FLAGS=", flags_value);
        expected = same(name, "WINXP") && flags_value == 128;
        if (!FreeLibrary(kex)) expected = 0;
        if (!expected) return 3;
    }
    SetLastError(0); qt = LoadLibraryA(QT_TARGET); load_error = qt ? 0 : GetLastError();
    number("QT_NATIVE_LOAD_HANDLE=", (DWORD)(ULONG_PTR)qt); number("QT_NATIVE_LOAD_SUCCESS=", qt != NULL);
    number("QT_NATIVE_LOAD_ERROR=", load_error);
    if (!flush()) goto release;
    for (i = 0; i < QT_MODULE_COUNT; ++i) {
        DWORD error;
        SetLastError(0); modules[i] = LoadLibraryA(qt_modules[i].path); error = modules[i] ? 0 : GetLastError();
        text("IMPORT_MODULE="); text(qt_modules[i].name); text("\r\n"); number("MODULE_LOAD_ERROR=", error);
    }
    for (i = 0; i < QT_IMPORT_COUNT && !io_failed; ++i) {
        const struct qt_import *item = &qt_imports[i]; FARPROC address = NULL; DWORD error = ERROR_MOD_NOT_FOUND;
        if (modules[item->module]) { SetLastError(0); address = GetProcAddress(modules[item->module], item->name); error = address ? 0 : GetLastError(); }
        if (!address || item->candidate) {
            text("IMPORT="); text(qt_modules[item->module].name); text("!"); text(item->name); text("\r\n");
            number("RESOLVED_ADDRESS=", (DWORD)(ULONG_PTR)address); number("RESOLVER_ERROR=", error);
            if (address) {
                MEMORY_BASIC_INFORMATION memory; char owner[MAX_PATH]; DWORD n = 0;
                if (VirtualQuery((LPCVOID)(ULONG_PTR)address, &memory, sizeof(memory)) == sizeof(memory))
                    n = GetModuleFileNameA((HMODULE)memory.AllocationBase, owner, sizeof(owner));
                if (n && n < sizeof(owner)) { text("RESOLVED_OWNER="); text(owner); text("\r\n"); }
                else number("OWNER_QUERY_UNAVAILABLE=", 1);
            }
        }
        if (!address) ++unresolved;
        ++inspected;
    }
    number("QT_IMPORTS_INSPECTED=", inspected); number("UNRESOLVED_IMPORTS=", unresolved);
release:
    for (i = 0; i < QT_MODULE_COUNT; ++i) if (modules[i] && !FreeLibrary(modules[i])) ++release_failed;
    if (qt && !FreeLibrary(qt)) ++release_failed;
    number("OWN_MODULE_RELEASE_FAILURES=", release_failed);
    text("SCOPE=RESOLVER_DIAGNOSIS_ONLY_NO_QT_GUI_ACCEPTANCE\r\n");
    /* A null native handle always fails, even if a compatibility hook leaves
     * LastError zero. The error field is evidence, not the success predicate. */
    return io_failed ? 31 : !qt || unresolved || release_failed ? 3 : 0;
mode_fail:
    if (flags) RegCloseKey(flags);
    if (configs) RegCloseKey(configs);
    text("WORKER_MODE_MISMATCH=1\r\n"); return 3;
}
static DWORD bootstrap(void) {
    STARTUPINFOA startup = {0}; PROCESS_INFORMATION process = {0};
    char command[] = SELF " worker"; DWORD wait, error, exit = STILL_ACTIVE, code = 3;
    if (!absent("C:\\VXDLAB\\QTWORK.LOG") || !pinned_inputs() || !actual_win98() || !configure_own_mode()) return 3;
    startup.cb = sizeof(startup);
    if (!CreateProcessA(SELF, command, NULL, NULL, FALSE, 0, NULL, "C:\\VLCLAB\\VLC", &startup, &process)) {
        number("CREATE_CHILD_ERROR=", GetLastError()); return 3;
    }
    number("ACTUAL_CHILD_PID=", process.dwProcessId); if (!flush()) goto terminate;
    wait = WaitForSingleObject(process.hProcess, 45000); error = wait == WAIT_FAILED ? GetLastError() : 0;
    number("ACTUAL_WAIT_RESULT=", wait); number("ACTUAL_WAIT_ERROR=", error);
    if (wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit)) {
        number("ACTUAL_CHILD_EXIT_CODE=", exit); code = exit; goto closed;
    }
    if (wait == WAIT_OBJECT_0) number("GET_CHILD_EXIT_ERROR=", GetLastError());
terminate:
    number("GUARD_TERMINATION_REQUIRED=", 1);
    if (!TerminateProcess(process.hProcess, 119)) number("TERMINATE_ERROR=", GetLastError());
    wait = WaitForSingleObject(process.hProcess, 5000); error = wait == WAIT_FAILED ? GetLastError() : 0;
    number("GUARD_REAP_RESULT=", wait); number("GUARD_REAP_ERROR=", error); code = 5;
closed:
    if (!CloseHandle(process.hThread)) io_failed = 1;
    if (!CloseHandle(process.hProcess)) io_failed = 1;
    return code;
}
void WINAPI entry(void) {
    BOOL is_worker = same(argument(), "worker"); DWORD code, n; char filename[MAX_PATH];
    if (!is_worker && !same(argument(), "")) ExitProcess(2);
    n = GetModuleFileNameA(NULL, filename, sizeof(filename));
    if (!n || n >= sizeof(filename) || !same_path(filename, SELF)) ExitProcess(2);
    report = CreateFileA(is_worker ? "C:\\VXDLAB\\QTWORK.LOG" : "C:\\VXDLAB\\QTBOOT.LOG", GENERIC_WRITE, 0,
                         NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=FIXED_OFFICIAL_VLC_QT_NATIVE_RESOLVER_DIAGNOSTIC\r\n");
    code = is_worker ? worker() : bootstrap();
    number("SELECTED_EXIT_CODE=", code);
    if (!flush()) code = 31;
    if (!CloseHandle(report)) code = 31;
    ExitProcess(io_failed ? 31 : code);
}
