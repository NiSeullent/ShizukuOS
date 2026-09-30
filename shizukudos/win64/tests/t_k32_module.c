/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 modules and resources: GetModuleHandleEx, the PSAPI module functions for the calling process, FreeLibraryAndExitThread,
 * RtlCaptureStackBackTrace, and PE resources (FindResource*, LoadResource, LockResource, SizeofResource, EnumResource*) read from
 * the resources linked into this program (t_k32_module.rc). */
#include "k32test.h"
#include <psapi.h>

BOOL WINAPI K32EnumProcessModulesEx(HANDLE, HMODULE *, DWORD, LPDWORD, DWORD);

#define RSRC_INT(i) ((LPWSTR)(ULONG_PTR)(i))
#define RCDATA RSRC_INT(10)

/* ---------------------------------------------------------------- resources */
static int name_calls, saw_strname, saw_100, saw_300, first_was_string;
static BOOL CALLBACK on_name(HMODULE m, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    (void)m; (void)lp;
    if (!name_calls) first_was_string = ((ULONG_PTR)name >> 16) != 0;
    ++name_calls;
    if (type != RCDATA) return FALSE;
    if (((ULONG_PTR)name >> 16) == 0) { if ((ULONG_PTR)name == 100) saw_100 = 1; if ((ULONG_PTR)name == 300) saw_300 = 1; }
    else if (k32t_weq(name, L"STRNAME")) saw_strname = 1;
    return TRUE;
}
static BOOL CALLBACK on_name_stop(HMODULE m, LPCWSTR type, LPWSTR name, LONG_PTR lp) { (void)m; (void)type; (void)name; ++*(int *)lp; return FALSE; }

static int type_calls, saw_rcdata, saw_shztype, saw_version;
static BOOL CALLBACK on_type(HMODULE m, LPWSTR type, LONG_PTR lp)
{
    (void)m; (void)lp;
    ++type_calls;
    if (((ULONG_PTR)type >> 16) == 0) { if ((ULONG_PTR)type == 10) saw_rcdata = 1; if ((ULONG_PTR)type == 16) saw_version = 1; }
    else if (k32t_weq(type, L"SHZTYPE")) saw_shztype = 1;
    return TRUE;
}

static int lang_calls, saw_en, saw_de;
static BOOL CALLBACK on_lang(HMODULE m, LPCWSTR type, LPCWSTR name, WORD lang, LONG_PTR lp)
{
    (void)m; (void)type; (void)name; (void)lp;
    ++lang_calls;
    if (lang == 0x0409) saw_en = 1;
    if (lang == 0x0407) saw_de = 1;
    return TRUE;
}

static int ansi_calls, ansi_saw_strname;
static BOOL CALLBACK on_name_a(HMODULE m, LPCSTR type, LPSTR name, LONG_PTR lp)
{
    (void)m; (void)type; (void)lp;
    ++ansi_calls;
    if (((ULONG_PTR)name >> 16) != 0 && !strcmp(name, "STRNAME")) ansi_saw_strname = 1;
    return TRUE;
}

static void test_resources(void)
{
    HRSRC r;
    HGLOBAL g;
    const unsigned char *p;
    static const unsigned char words[6] = { 0x22, 0x11, 0x44, 0x33, 0x66, 0x55 };

    r = FindResourceW(NULL, RSRC_INT(100), RCDATA);
    CHECK(r != NULL, "FindResourceW(100, RT_RCDATA) finds the resource");
    CHECKV(SizeofResource(NULL, r) == 12, "neutral lookup prefers the en-US data (12 bytes)", "size=%u", (unsigned)SizeofResource(NULL, r));
    g = LoadResource(NULL, r);
    p = LockResource(g);
    CHECK(g != NULL && p != NULL && !memcmp(p, "SHZ-RES-100", 12), "LoadResource/LockResource give the bytes (en-US)");
    r = FindResourceExW(NULL, RCDATA, RSRC_INT(100), MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN));
    CHECK(r != NULL && SizeofResource(NULL, r) == 15, "FindResourceExW with LANG_GERMAN finds the German copy (15 bytes)");
    p = LockResource(LoadResource(NULL, r));
    CHECK(p && !memcmp(p, "SHZ-RES-100-DE", 15), "the German data is the German string");
    r = FindResourceExW(NULL, RCDATA, RSRC_INT(100), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    CHECK(r != NULL && SizeofResource(NULL, r) == 12, "explicit en-US finds the English copy");
    SetLastError(0);
    r = FindResourceExW(NULL, RCDATA, RSRC_INT(100), MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH));
    CHECK(r == NULL, "an absent explicit language is not found");
    CHECK_ERR(ERROR_RESOURCE_LANG_NOT_FOUND, "absent language: ERROR_RESOURCE_LANG_NOT_FOUND");
    r = FindResourceW(NULL, L"STRNAME", RCDATA);
    CHECK(r != NULL && SizeofResource(NULL, r) == 6, "named resource STRNAME (6 bytes)");
    p = LockResource(LoadResource(NULL, r));
    CHECK(p && !memcmp(p, words, 6), "RCDATA words are stored little-endian");
    CHECK(FindResourceW(NULL, L"strname", RCDATA) == r, "resource names are case-insensitive");
    r = FindResourceW(NULL, RSRC_INT(200), L"SHZTYPE");
    CHECK(r != NULL && SizeofResource(NULL, r) == 16, "custom string type SHZTYPE (16 bytes)");
    p = LockResource(LoadResource(NULL, r));
    CHECK(p && !memcmp(p, "custom type data", 16), "custom type data");
    CHECK(FindResourceW(NULL, RSRC_INT(200), L"shztype") == r, "type names are case-insensitive");
    CHECK(FindResourceW(NULL, L"#100", L"#10") == FindResourceW(NULL, RSRC_INT(100), RCDATA), "#nnn strings are integer ids");
    r = FindResourceW(NULL, RSRC_INT(300), RCDATA);
    CHECK(r != NULL && SizeofResource(NULL, r) == 12, "language-neutral resource is found by a neutral lookup");
    SetLastError(0);
    CHECK(FindResourceW(NULL, RSRC_INT(100), RSRC_INT(999)) == NULL, "unknown type is not found");
    CHECK_ERR(ERROR_RESOURCE_TYPE_NOT_FOUND, "unknown type: ERROR_RESOURCE_TYPE_NOT_FOUND");
    SetLastError(0);
    CHECK(FindResourceW(NULL, RSRC_INT(555), RCDATA) == NULL, "unknown name is not found");
    CHECK_ERR(ERROR_RESOURCE_NAME_NOT_FOUND, "unknown name: ERROR_RESOURCE_NAME_NOT_FOUND");
    r = FindResourceA(NULL, "STRNAME", (LPCSTR)RCDATA);
    CHECK(r != NULL && SizeofResource(NULL, r) == 6, "FindResourceA");
    r = FindResourceExA(NULL, "SHZTYPE", (LPCSTR)(ULONG_PTR)200, 0);
    CHECK(r != NULL && SizeofResource(NULL, r) == 16, "FindResourceExA with a string type");
    CHECK(FindResourceW(GetModuleHandleW(NULL), L"STRNAME", RCDATA) != NULL, "an explicit module handle works like NULL");
    SetLastError(0);
    CHECK(FindResourceW(GetModuleHandleW(L"kernel32.dll"), RSRC_INT(1), RSRC_INT(999)) == NULL && GetLastError() != 0, "a module without that resource fails with an error");

    name_calls = saw_strname = saw_100 = saw_300 = 0;
    CHECK(EnumResourceNamesW(NULL, RCDATA, on_name, 0), "EnumResourceNamesW returns TRUE when every callback returned TRUE");
    CHECKV(name_calls == 3 && saw_strname && saw_100 && saw_300, "EnumResourceNamesW reports STRNAME, 100 and 300", "calls=%d", name_calls);
    CHECK(first_was_string, "named entries are enumerated before integer ids");
    name_calls = 0;
    SetLastError(0);
    CHECK(!EnumResourceNamesW(NULL, RCDATA, on_name_stop, (LONG_PTR)&name_calls) && name_calls == 1, "a callback returning FALSE stops the enumeration and the call returns FALSE");
    SetLastError(0);
    CHECK(!EnumResourceNamesW(NULL, RSRC_INT(999), on_name, 0), "enumerating an absent type fails");
    CHECK_ERR(ERROR_RESOURCE_TYPE_NOT_FOUND, "absent type: ERROR_RESOURCE_TYPE_NOT_FOUND");
    ansi_calls = ansi_saw_strname = 0;
    CHECK(EnumResourceNamesA(NULL, (LPCSTR)RCDATA, on_name_a, 0) && ansi_calls == 3 && ansi_saw_strname, "EnumResourceNamesA converts the names");
    type_calls = saw_rcdata = saw_shztype = saw_version = 0;
    CHECK(EnumResourceTypesW(NULL, on_type, 0) && type_calls == 3 && saw_rcdata && saw_shztype && saw_version,
          "EnumResourceTypesW: RT_RCDATA, SHZTYPE and RT_VERSION (the build gives every image a version resource)");
    lang_calls = saw_en = saw_de = 0;
    CHECK(EnumResourceLanguagesW(NULL, RCDATA, RSRC_INT(100), on_lang, 0) && lang_calls == 2 && saw_en && saw_de, "EnumResourceLanguagesW: en-US and de-DE");
}

/* ---------------------------------------------------------------- modules */
static DWORD WINAPI free_and_exit(LPVOID arg)
{
    HMODULE h = 0;
    (void)arg;
    if (!GetModuleHandleExW(0, L"kernel32.dll", &h)) return 1;
    FreeLibraryAndExitThread(h, 7);
    return 2;                                        /* not reached */
}

static void test_modules(void)
{
    HMODULE exe = GetModuleHandleW(NULL), k32 = GetModuleHandleW(L"kernel32.dll"), h = (HMODULE)1;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)exe;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const BYTE *)exe + dos->e_lfanew);
    MODULEINFO mi;
    WCHAR w1[300], w2[300], base[64];
    char a1[300], a2[300];
    HMODULE mods[256];
    DWORD needed = 0, n;
    HANDLE th;
    DWORD code = 0;

    CHECK(k32 != NULL && exe != NULL && exe != k32, "have module handles");
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll", &h) && h == k32, "GetModuleHandleExW(UNCHANGED_REFCOUNT, kernel32.dll) == GetModuleHandleW");
    CHECK(GetModuleHandleExW(0, L"kernel32.dll", &h) && h == k32, "GetModuleHandleExW(0, kernel32.dll)");
    CHECK(FreeLibrary(k32), "the reference taken by GetModuleHandleExW can be released");
    CHECK(GetModuleHandleExW(0, NULL, &h) && h == exe, "GetModuleHandleExW(NULL) is the executable");
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)test_modules, &h) && h == exe,
          "FROM_ADDRESS with a function of this program gives the executable");
    {
        FARPROC p = GetProcAddress(k32, "GetModuleHandleExW");
        MODULEINFO m2;
        CHECK(p != NULL && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p, &h) && h != NULL,
              "FROM_ADDRESS with an exported function finds a module");
        CHECK(GetModuleInformation(GetCurrentProcess(), h, &m2, sizeof m2) && (BYTE *)p >= (BYTE *)m2.lpBaseOfDll && (BYTE *)p < (BYTE *)m2.lpBaseOfDll + m2.SizeOfImage,
              "the module returned for an address contains that address");
    }
    h = (HMODULE)1;
    SetLastError(0);
    CHECK(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)8, &h) && h == NULL, "FROM_ADDRESS with an unmapped address fails and clears the output");
    CHECK_ERR(ERROR_MOD_NOT_FOUND, "unmapped address: ERROR_MOD_NOT_FOUND");
    h = (HMODULE)1;
    SetLastError(0);
    CHECK(!GetModuleHandleExW(0, L"no_such_module.dll", &h) && h == NULL, "unknown module name fails and clears the output");
    CHECK_ERR(ERROR_MOD_NOT_FOUND, "unknown module: ERROR_MOD_NOT_FOUND");
    SetLastError(0);
    CHECK(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll", &h), "PIN together with UNCHANGED_REFCOUNT fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "PIN|UNCHANGED_REFCOUNT: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(!GetModuleHandleExW(0, L"kernel32.dll", NULL), "NULL output pointer fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "NULL output: ERROR_INVALID_PARAMETER");
    CHECK(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "KERNEL32.DLL", &h) && h == k32, "GetModuleHandleExA is case-insensitive");
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, L"kernel32.dll", &h) && h == k32, "PIN succeeds");
    CHECK(FreeLibrary(k32) && GetModuleHandleW(L"kernel32.dll") == k32, "a pinned module stays loaded after FreeLibrary");

    /* PSAPI, current process */
    CHECK(GetModuleInformation(GetCurrentProcess(), exe, &mi, sizeof mi), "GetModuleInformation(exe)");
    CHECK(mi.lpBaseOfDll == exe, "MODULEINFO.lpBaseOfDll is the image base");
    CHECKV(mi.SizeOfImage == nt->OptionalHeader.SizeOfImage, "MODULEINFO.SizeOfImage equals the PE header value", "%u vs %u", (unsigned)mi.SizeOfImage, (unsigned)nt->OptionalHeader.SizeOfImage);
    CHECK((BYTE *)mi.EntryPoint == (BYTE *)exe + nt->OptionalHeader.AddressOfEntryPoint, "MODULEINFO.EntryPoint = base + AddressOfEntryPoint");
    SetLastError(0);
    CHECK(!GetModuleInformation(GetCurrentProcess(), exe, &mi, sizeof mi - 1), "cb smaller than MODULEINFO fails");
    CHECK_ERR(ERROR_INSUFFICIENT_BUFFER, "small cb: ERROR_INSUFFICIENT_BUFFER");
    SetLastError(0);
    CHECK(!GetModuleInformation((HANDLE)(ULONG_PTR)0x12345670, exe, &mi, sizeof mi), "an invalid process handle fails");
    CHECK_ERR(ERROR_INVALID_HANDLE, "invalid process handle: ERROR_INVALID_HANDLE");
    CHECK(GetModuleInformation(GetCurrentProcess(), k32, &mi, sizeof mi) && mi.lpBaseOfDll == k32 && mi.SizeOfImage > 0x1000, "GetModuleInformation(kernel32)");

    n = GetModuleFileNameW(NULL, w1, 300);
    CHECK(n > 0 && GetModuleFileNameExW(GetCurrentProcess(), NULL, w2, 300) == n && k32t_weq(w1, w2), "GetModuleFileNameExW(NULL) equals GetModuleFileNameW(NULL)");
    CHECK(GetModuleFileNameExA(GetCurrentProcess(), NULL, a1, 300) > 0 && GetModuleFileNameA(NULL, a2, 300) > 0 && !strcmp(a1, a2), "GetModuleFileNameExA equals GetModuleFileNameA");
    {
        const WCHAR *slash = w1 + n;
        while (slash > w1 && slash[-1] != '\\') --slash;
        CHECK(GetModuleBaseNameW(GetCurrentProcess(), NULL, base, 64) == (DWORD)(w1 + n - slash) && k32t_weq(base, slash), "GetModuleBaseNameW is the file name part");
    }
    CHECK(GetModuleBaseNameA(GetCurrentProcess(), k32, a1, 64) > 0, "GetModuleBaseNameA(kernel32) succeeds");
    {
        char lower[64];
        unsigned i;
        for (i = 0; a1[i] && i < 63; ++i) lower[i] = (char)(a1[i] >= 'A' && a1[i] <= 'Z' ? a1[i] + 32 : a1[i]);
        lower[i] = 0;
        CHECK(!strcmp(lower, "kernel32.dll"), "the base name of kernel32 is kernel32.dll (ignoring case)");
    }
    SetLastError(0);
    CHECK(GetModuleFileNameExW(GetCurrentProcess(), NULL, w2, 4) <= 4, "a short buffer is truncated");

    CHECK(EnumProcessModules(GetCurrentProcess(), mods, sizeof mods, &needed), "EnumProcessModules");
    {
        const unsigned count = needed / (unsigned)sizeof(HMODULE);
        unsigned i;
        int has_k32 = 0, has_ntdll = 0;
        CHECKV(needed % sizeof(HMODULE) == 0 && count >= 3 && count <= 256, "at least the executable, ntdll and kernel32 are listed", "count=%u", count);
        CHECK(mods[0] == exe, "the executable is the first module");
        for (i = 0; i < count && i < 256; ++i) {
            if (mods[i] == k32) has_k32 = 1;
            if (mods[i] == GetModuleHandleW(L"ntdll.dll")) has_ntdll = 1;
        }
        CHECK(has_k32 && has_ntdll, "kernel32 and ntdll are in the list");
    }
    CHECK(EnumProcessModules(GetCurrentProcess(), mods, 0, &n) && n == needed, "a zero-size buffer still reports the needed size");
    CHECK(K32EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof mods, &n, LIST_MODULES_64BIT) && n == needed, "LIST_MODULES_64BIT lists the same modules");
    CHECK(K32EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof mods, &n, LIST_MODULES_ALL) && n == needed, "LIST_MODULES_ALL lists the same modules");

    th = CreateThread(0, 0, free_and_exit, 0, 0, 0);
    CHECK(th != NULL, "thread for FreeLibraryAndExitThread");
    if (th) {
        WaitForSingleObject(th, INFINITE);
        GetExitCodeThread(th, &code);
        CloseHandle(th);
        CHECKV(code == 7, "FreeLibraryAndExitThread ends the thread with the given code", "code=%u", (unsigned)code);
    }
}

/* ---------------------------------------------------------------- stack traces */
#define FN __attribute__((noinline, aligned(256)))
static PVOID g_frames[16];
static USHORT g_count;
static ULONG g_hash;
static USHORT g_count_skip1;
static PVOID g_frames_skip1[16];

FN static void level3(void)
{
    g_count = RtlCaptureStackBackTrace(0, 16, g_frames, &g_hash);
    g_count_skip1 = RtlCaptureStackBackTrace(1, 16, g_frames_skip1, NULL);
    __asm__ volatile("" ::: "memory");
}
FN static void level2(void) { level3(); __asm__ volatile("" ::: "memory"); }
FN static void level1(void) { level2(); __asm__ volatile("" ::: "memory"); }

static int in_fn(PVOID pc, void (*fn)(void)) { return (ULONG_PTR)pc >= (ULONG_PTR)fn && (ULONG_PTR)pc < (ULONG_PTR)fn + 256; }

static void test_backtrace(void)
{
    PVOID one[1];
    level1();
    CHECKV(g_count >= 4, "the trace has at least four frames", "count=%u", g_count);
    CHECK(in_fn(g_frames[0], level3), "frame 0 is inside the function that captured the trace");
    CHECK(in_fn(g_frames[1], level2), "frame 1 is inside its caller");
    CHECK(in_fn(g_frames[2], level1), "frame 2 is inside the caller's caller");
    CHECK(g_hash != 0, "the back trace hash is filled in");
    CHECK(g_count_skip1 + 1 == g_count || g_count_skip1 == g_count - 1, "FramesToSkip=1 drops one frame");
    CHECK(in_fn(g_frames_skip1[0], level2), "with FramesToSkip=1 the first frame is the caller");
    CHECK(RtlCaptureStackBackTrace(0, 1, one, NULL) == 1 && !in_fn(one[0], level1), "FramesToCapture limits the count to one frame");
    CHECK(RtlCaptureStackBackTrace(0, 0, one, NULL) == 0, "FramesToCapture of zero captures nothing");
}

int main(void)
{
    test_resources();
    test_modules();
    test_backtrace();
    return k32t_finish("t_k32_module");
}
