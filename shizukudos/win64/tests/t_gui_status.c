/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: runtime status screen. Loads EVERY system DLL present in C:\SHZ\SYS64 with LoadLibraryW, resolves each DLL's first
 * named export with GetProcAddress, and shows the result in one window (DLL, state, export count, load address) together
 * with the version the loader reports (RtlGetVersion), the processor count, the physical memory, and every PCI function
 * with the kernel driver bound to it (NtQuerySystemInformation class 0x101, kernel64/sysx.c). Each DLL is also
 * reported on the serial console as `STATUS-DLL: <name> loaded=<0|1> exports=<n> resolved=<0|1>` so the host runner
 * (run_k64_gui.py) can require that every DLL it built was loaded inside the guest; the screendump is the visible record.
 * Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

LONG NTAPI RtlGetVersion(OSVERSIONINFOW *);
LONG NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

#define MAXDLL 64
static struct dll_row { WCHAR name[40]; int loaded, resolved; DWORD exports; ULONG_PTR base; } g_rows[MAXDLL];
static int g_n, g_loaded;
static WCHAR g_head[3][128];
#define MAXPCI 32
static struct pci_row { BYTE bus, dev, fn, cls, sub, pif, irq, pad; WORD vendor, device; DWORD pad2; char driver[24]; } g_pci[MAXPCI];
static ULONG g_npci;

static void query_pci(void)
{
    ULONG i;
    LONG st = NtQuerySystemInformation(0x101, g_pci, sizeof g_pci, &g_npci);
    CHECK(st == 0, "NtQuerySystemInformation(0x101) lists the PCI functions");
    if (st) g_npci = 0;
    for (i = 0; i < g_npci; ++i)
        printf("STATUS-PCI: %02x:%02x.%x %04x:%04x class %02x%02x%02x irq %u driver=%s\n", g_pci[i].bus, g_pci[i].dev, g_pci[i].fn,
               g_pci[i].vendor, g_pci[i].device, g_pci[i].cls, g_pci[i].sub, g_pci[i].pif, g_pci[i].irq,
               g_pci[i].driver[0] ? g_pci[i].driver : "-");
}

static DWORD export_count(HMODULE m, const char **first)
{
    const BYTE *b = (const BYTE *)m;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(b + ((const IMAGE_DOS_HEADER *)b)->e_lfanew);
    const IMAGE_DATA_DIRECTORY *d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const IMAGE_EXPORT_DIRECTORY *e;
    *first = 0;
    if (!d->VirtualAddress || !d->Size) return 0;
    e = (const IMAGE_EXPORT_DIRECTORY *)(b + d->VirtualAddress);
    if (e->NumberOfNames) *first = (const char *)(b + ((const DWORD *)(b + e->AddressOfNames))[0]);
    return e->NumberOfFunctions;
}

static void wfmt(WCHAR *dst, int cap, const char *src)
{
    int i;
    for (i = 0; src[i] && i < cap - 1; ++i) dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

static void load_all(void)
{
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(L"C:\\SHZ\\SYS64\\*.dll", &fd);
    CHECK(h != INVALID_HANDLE_VALUE, "FindFirstFileW(C:\\SHZ\\SYS64\\*.dll) finds the system DLLs");
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        struct dll_row *r;
        HMODULE m;
        const char *first;
        char nm[40];
        int i;
        if (g_n == MAXDLL) break;
        r = &g_rows[g_n++];
        for (i = 0; fd.cFileName[i] && i < 39; ++i) r->name[i] = fd.cFileName[i];
        r->name[i] = 0;
        m = LoadLibraryW(r->name);
        r->loaded = m != 0;
        if (m) {
            ++g_loaded;
            r->base = (ULONG_PTR)m;
            r->exports = export_count(m, &first);
            r->resolved = !first || GetProcAddress(m, first) != 0;
        }
        for (i = 0; r->name[i] && i < 39; ++i) nm[i] = (char)r->name[i];
        nm[i] = 0;
        printf("STATUS-DLL: %s loaded=%d exports=%lu resolved=%d\n", nm, r->loaded, (unsigned long)r->exports, r->resolved);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void header(void)
{
    OSVERSIONINFOW vi;
    SYSTEM_INFO si;
    MEMORYSTATUSEX ms;
    char t[128];
    memset(&vi, 0, sizeof vi);
    vi.dwOSVersionInfoSize = sizeof vi;
    RtlGetVersion(&vi);
    GetSystemInfo(&si);
    memset(&ms, 0, sizeof ms);
    ms.dwLength = sizeof ms;
    CHECK(GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys >= ms.ullAvailPhys && ms.ullAvailPhys > 0, "GlobalMemoryStatusEx reports physical memory");
    snprintf(t, sizeof t, "ShizukuDOS Kernel64 - Win64 runtime   RtlGetVersion: %lu.%lu build %lu",
             (unsigned long)vi.dwMajorVersion, (unsigned long)vi.dwMinorVersion, (unsigned long)vi.dwBuildNumber);
    wfmt(g_head[0], 128, t);
    snprintf(t, sizeof t, "processors: %lu   physical memory: %lu MB   page size: %lu", (unsigned long)si.dwNumberOfProcessors,
             (unsigned long)(ms.ullTotalPhys >> 20), (unsigned long)si.dwPageSize);
    wfmt(g_head[1], 128, t);
    snprintf(t, sizeof t, "system DLLs in C:\\SHZ\\SYS64: %d   loaded by LoadLibraryW in this process: %d", g_n, g_loaded);
    wfmt(g_head[2], 128, t);
    printf("STATUS-VERSION: %lu.%lu.%lu\n", (unsigned long)vi.dwMajorVersion, (unsigned long)vi.dwMinorVersion,
           (unsigned long)vi.dwBuildNumber);
}

static void paint(HDC dc)
{
    int i, j, half = (g_n + 1) / 2;
    WCHAR w[64];
    char t[64];
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(0, 0, 0));
    for (i = 0; i < 3; ++i) TextOutW(dc, 8, 6 + i * 18, g_head[i], lstrlenW(g_head[i]));
    for (j = 0; j < 2; ++j) {
        int x = 8 + j * 496;
        TextOutW(dc, x, 70, L"DLL", 3);
        TextOutW(dc, x + 168, 70, L"state", 5);
        TextOutW(dc, x + 248, 70, L"exports", 7);
        TextOutW(dc, x + 328, 70, L"base", 4);
    }
    for (i = 0; i < g_n; ++i) {
        const struct dll_row *r = &g_rows[i];
        int x = 8 + (i >= half) * 496, y = 90 + (i % half) * 18;
        SetTextColor(dc, RGB(0, 0, 0));
        TextOutW(dc, x, y, r->name, lstrlenW(r->name));
        SetTextColor(dc, r->loaded && r->resolved ? RGB(0, 128, 0) : RGB(192, 0, 0));
        TextOutW(dc, x + 168, y, r->loaded ? (r->resolved ? L"LOADED" : L"NO-EXP") : L"FAILED", 6);
        SetTextColor(dc, RGB(0, 0, 0));
        snprintf(t, sizeof t, "%lu", (unsigned long)r->exports);
        wfmt(w, 64, t);
        TextOutW(dc, x + 248, y, w, lstrlenW(w));
        snprintf(t, sizeof t, "%012llx", (unsigned long long)r->base);
        wfmt(w, 64, t);
        TextOutW(dc, x + 328, y, w, lstrlenW(w));
    }
    {
        int y = 90 + half * 18 + 18;
        TextOutW(dc, 8, y, L"PCI function  vendor:device  class   irq  kernel driver", 55);
        for (i = 0; i < (int)g_npci; ++i) {
            const struct pci_row *r = &g_pci[i];
            y += 18;
            snprintf(t, sizeof t, "%02x:%02x.%x       %04x:%04x      %02x%02x%02x  %-3u  ", r->bus, r->dev, r->fn, r->vendor, r->device,
                     r->cls, r->sub, r->pif, r->irq);
            wfmt(w, 64, t);
            SetTextColor(dc, RGB(0, 0, 0));
            TextOutW(dc, 8, y, w, lstrlenW(w));
            SetTextColor(dc, r->driver[0] ? RGB(0, 128, 0) : RGB(128, 128, 128));
            wfmt(w, 64, r->driver[0] ? r->driver : "(no driver)");
            TextOutW(dc, 8 + 8 * lstrlenW(L"PCI function  vendor:device  class   irq  "), y, w, lstrlenW(w));
        }
    }
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        paint(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_TIMER:
        if (w == 9) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int main(void)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg;
    int i, all = 1;
    HINSTANCE inst = GetModuleHandleW(0);
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    load_all();
    for (i = 0; i < g_n; ++i) all &= g_rows[i].loaded && g_rows[i].resolved;
    CHECK(g_n >= 3, "at least ntdll, kernel32 and one more system DLL are present");
    CHECK(all, "every system DLL loads and its first named export resolves");
    header();
    query_pci();
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ShzStatus";
    CHECK(RegisterClassExW(&wc) != 0, "RegisterClassExW");
    hwnd = CreateWindowExW(0, L"ShzStatus", L"Shizuku Win64 runtime status", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 8, 8, 1008, 752, 0, 0, inst, 0);
    CHECK(hwnd != 0, "CreateWindowExW");
    if (!hwnd) return 1;
    UpdateWindow(hwnd);
    SetTimer(hwnd, 9, 1500, 0);
    printf("GUI-READY: status\n");
    while (GetMessageW(&msg, 0, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    DestroyWindow(hwnd);
    UnregisterClassW(L"ShzStatus", inst);
    printf("%s: status screen\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
