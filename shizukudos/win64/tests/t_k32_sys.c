/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 system information and devices: processor topology, firmware, computer names, version checks, power, time zones,
 * initialization files, console, serial ports and hard links. Expectations follow the documented Win32 behaviour; time-zone
 * results are published civil-time facts (US Pacific 2024: PDT = UTC-7 from 2024-03-10 10:00 UTC to 2024-11-03 09:00 UTC).
 */
#include "k32test.h"

static const WCHAR *W(const char *s) { static WCHAR b[4][128]; static int k; WCHAR *w = b[k++ & 3]; int i = 0; while ((w[i] = (WCHAR)(unsigned char)s[i])) ++i; return w; }
static int weq(const WCHAR *a, const char *b) { while (*a && *a == (WCHAR)(unsigned char)*b) { ++a; ++b; } return *a == (WCHAR)(unsigned char)*b; }

static void test_processors(void)
{
    SYSTEM_INFO si;
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION lpi[32];
    DWORD len = 0, i, cores = 0, pkgs = 0, nodes = 0, caches = 0, bad_cache = 0;
    BYTE ex[4096];
    GROUP_AFFINITY ga;
    GetSystemInfo(&si);
    CHECK(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) == si.dwNumberOfProcessors && GetActiveProcessorCount(0) == si.dwNumberOfProcessors,
          "GetActiveProcessorCount agrees with GetSystemInfo");
    CHECK(GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS) >= GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) && GetMaximumProcessorGroupCount() == 1,
          "maximum processor and group counts");
    SetLastError(0);
    CHECK(GetActiveProcessorCount(5) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "group 5 does not exist");
    CHECK(GetCurrentProcessorNumber() < si.dwNumberOfProcessors, "the current processor number is an active processor");
    CHECK(GetThreadGroupAffinity(GetCurrentThread(), &ga) && ga.Group == 0 && (ga.Mask & si.dwActiveProcessorMask) == ga.Mask && ga.Mask,
          "GetThreadGroupAffinity: group 0, active processors");
    SetLastError(0);
    CHECK(!GetLogicalProcessorInformation(lpi, &len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && len % sizeof lpi[0] == 0 && len,
          "GetLogicalProcessorInformation reports the size it needs");
    len = sizeof lpi;
    CHECK(GetLogicalProcessorInformation(lpi, &len), "GetLogicalProcessorInformation");
    for (i = 0; i < len / sizeof lpi[0]; ++i) {
        switch (lpi[i].Relationship) {
        case RelationProcessorCore: ++cores; break;
        case RelationProcessorPackage: ++pkgs; break;
        case RelationNumaNode: ++nodes; break;
        case RelationCache:
            ++caches;
            if (lpi[i].Cache.Level < 1 || lpi[i].Cache.Level > 4 || !lpi[i].Cache.LineSize || (lpi[i].Cache.LineSize & (lpi[i].Cache.LineSize - 1)) ||
                lpi[i].Cache.Size % lpi[i].Cache.LineSize)
                ++bad_cache;
            break;
        default: break;
        }
    }
    CHECKV(cores == si.dwNumberOfProcessors && pkgs >= 1 && nodes == 1 && !bad_cache, "one core per logical processor, a package, a node, sane caches",
           "cores=%u pkgs=%u nodes=%u caches=%u bad=%u", (unsigned)cores, (unsigned)pkgs, (unsigned)nodes, (unsigned)caches, (unsigned)bad_cache);
    len = sizeof ex;
    CHECK(GetLogicalProcessorInformationEx(RelationAll, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)ex, &len), "GetLogicalProcessorInformationEx(RelationAll)");
    {
        DWORD off = 0, recs = 0, groups = 0, ok = 1;
        while (off + 8 <= len) {
            const DWORD rel = *(DWORD *)(ex + off), size = *(DWORD *)(ex + off + 4);
            if (size < 8 || off + size > len) { ok = 0; break; }
            if (rel == RelationGroup) { ++groups; ok &= *(WORD *)(ex + off + 10) == 1 && ex[off + 8 + 24 + 1] == si.dwNumberOfProcessors; }
            off += size;
            ++recs;
        }
        CHECKV(ok && off == len && groups == 1 && recs == cores + pkgs + nodes + caches + 1, "the Ex records chain exactly and describe one active group",
               "recs=%u groups=%u off=%u len=%u", (unsigned)recs, (unsigned)groups, (unsigned)off, (unsigned)len);
    }
    len = 4;
    SetLastError(0);
    CHECK(!GetLogicalProcessorInformationEx(RelationProcessorCore, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)ex, &len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
          len == 48 * si.dwNumberOfProcessors, "a core record is 48 bytes");
}

static void test_identity(void)
{
    FIRMWARE_TYPE ft = (FIRMWARE_TYPE)77;
    WCHAR name[64], nb[64];
    DWORD n = 64, nn = 64, type = 0xdead;
    OSVERSIONINFOEXW vi;
    ULONGLONG m;
    CHECK(GetFirmwareType(&ft) && ft >= FirmwareTypeUnknown && ft < FirmwareTypeMax, "GetFirmwareType reports a FIRMWARE_TYPE");
    CHECK(GetComputerNameW(nb, &nn), "GetComputerNameW");
    CHECK(GetComputerNameExW(ComputerNameNetBIOS, name, &n) && n == nn && k32t_weq(name, nb), "ComputerNameNetBIOS is the computer name");
    n = 64;
    CHECK(GetComputerNameExW(ComputerNameDnsHostname, name, &n) && n == nn, "ComputerNameDnsHostname");
    n = 64;
    CHECK(GetComputerNameExW(ComputerNameDnsDomain, name, &n) && n == 0 && name[0] == 0, "no DNS domain is configured");
    n = 64;
    CHECK(GetComputerNameExW(ComputerNameDnsFullyQualified, name, &n) && n == nn, "the fully qualified name is the host name");
    n = 2;
    SetLastError(0);
    CHECK(!GetComputerNameExW(ComputerNameNetBIOS, name, &n) && GetLastError() == ERROR_MORE_DATA && n == nn + 1, "a short buffer reports the size with the NUL");
    n = 64;
    SetLastError(0);
    CHECK(!GetComputerNameExW(ComputerNameMax, name, &n) && GetLastError() == ERROR_INVALID_PARAMETER, "ComputerNameMax is not a format");
    CHECK(GetProductInfo(10, 0, 0, 0, &type) && type == PRODUCT_UNDEFINED, "GetProductInfo: not a Windows edition (PRODUCT_UNDEFINED)");

    {   /* this program has no manifest: GetVersionExW lies like Windows 8.1+ does to a manifest-less program */
        OSVERSIONINFOEXW ov;
        memset(&ov, 0, sizeof ov);
        ov.dwOSVersionInfoSize = sizeof ov;
        CHECK(GetVersionExW((LPOSVERSIONINFOW)&ov) && ov.dwMajorVersion == 6 && ov.dwMinorVersion == 2 && ov.dwBuildNumber == 9200 &&
              ov.wProductType == VER_NT_WORKSTATION && ov.dwPlatformId == VER_PLATFORM_WIN32_NT,
              "GetVersionExW without a compatibility manifest reports 6.2.9200 (workstation), while the PEB says 10.0");
    }
    CHECK(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL) == 0x18, "VerSetConditionMask(MAJOR, >=) = 3 << 3");
    CHECK(VerSetConditionMask(0x18, VER_MINORVERSION, VER_GREATER_EQUAL) == 0x1b, "... plus MINOR at bits 0-2");
    CHECK(VerSetConditionMask(0, VER_MAJORVERSION | VER_MINORVERSION, VER_EQUAL) == 0x08, "with two type bits only the higher one is set");
    CHECK(VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL) == (1ull << 21), "VER_PRODUCT_TYPE is the eighth field");
    memset(&vi, 0, sizeof vi);
    vi.dwOSVersionInfoSize = sizeof vi;
    vi.dwMajorVersion = 10;
    m = VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL);
    CHECK(VerifyVersionInfoW(&vi, VER_MAJORVERSION | VER_MINORVERSION, m), "Windows 10.0 or greater (the PEB reports 10.0)");
    vi.dwMajorVersion = 6; vi.dwMinorVersion = 3;
    CHECK(VerifyVersionInfoW(&vi, VER_MAJORVERSION | VER_MINORVERSION, m), "6.3 or greater: 10 > 6 decides although minor 0 < 3");
    vi.dwMajorVersion = 11; vi.dwMinorVersion = 0;
    SetLastError(0);
    CHECK(!VerifyVersionInfoW(&vi, VER_MAJORVERSION | VER_MINORVERSION, m) && GetLastError() == ERROR_OLD_WIN_VERSION, "11.0 or greater fails with ERROR_OLD_WIN_VERSION");
    vi.dwBuildNumber = 22631;
    CHECK(VerifyVersionInfoW(&vi, VER_BUILDNUMBER, VerSetConditionMask(0, VER_BUILDNUMBER, VER_EQUAL)), "build 22631");
    vi.dwBuildNumber = 22632;
    CHECK(!VerifyVersionInfoW(&vi, VER_BUILDNUMBER, VerSetConditionMask(0, VER_BUILDNUMBER, VER_GREATER_EQUAL)), "not build 22632 or later");
    vi.wProductType = VER_NT_WORKSTATION;
    CHECK(VerifyVersionInfoW(&vi, VER_PRODUCT_TYPE, VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL)), "a workstation product type");
    vi.dwMajorVersion = 10; vi.dwMinorVersion = 0;
    CHECK(!VerifyVersionInfoW(&vi, VER_MAJORVERSION | VER_MINORVERSION,
                              VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER), VER_MINORVERSION, VER_GREATER)),
          "10.0 is not strictly greater than 10.0");
    SetLastError(0);
    CHECK(!VerifyVersionInfoW(&vi, VER_MAJORVERSION, 0) && GetLastError() == ERROR_BAD_ARGUMENTS, "an empty condition mask is ERROR_BAD_ARGUMENTS");
}

static void test_power(void)
{
    SYSTEM_POWER_STATUS ps;
    REASON_CONTEXT rc;
    HANDLE r;
    EXECUTION_STATE prev;
    memset(&ps, 0x11, sizeof ps);
    CHECK(GetSystemPowerStatus(&ps) && ps.ACLineStatus == 255 && ps.BatteryFlag == 255 && ps.BatteryLifePercent == 255 &&
          ps.BatteryLifeTime == (DWORD)-1, "no AC / battery driver: every power field is 'unknown'");
    prev = SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
    CHECK(prev == ES_CONTINUOUS, "the first SetThreadExecutionState returns the empty continuous state");
    prev = SetThreadExecutionState(ES_DISPLAY_REQUIRED);
    CHECK(prev == (ES_CONTINUOUS | ES_SYSTEM_REQUIRED), "... then the continuous state that was set");
    prev = SetThreadExecutionState(ES_CONTINUOUS);
    CHECK(prev == (ES_CONTINUOUS | ES_SYSTEM_REQUIRED), "a one-shot request does not change the continuous state");
    CHECK(SetThreadExecutionState(ES_USER_PRESENT) == 0, "ES_USER_PRESENT is not a valid flag");
    memset(&rc, 0, sizeof rc);
    rc.Version = POWER_REQUEST_CONTEXT_VERSION;
    rc.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING;
    rc.Reason.SimpleReasonString = (LPWSTR)W("playing video");
    r = PowerCreateRequest(&rc);
    CHECK(r != INVALID_HANDLE_VALUE, "PowerCreateRequest");
    CHECK(PowerSetRequest(r, PowerRequestDisplayRequired) && PowerClearRequest(r, PowerRequestDisplayRequired), "PowerSetRequest / PowerClearRequest");
    SetLastError(0);
    CHECK(!PowerClearRequest(r, PowerRequestDisplayRequired) && GetLastError() == ERROR_INVALID_PARAMETER, "clearing a request that is not set fails");
    CHECK(CloseHandle(r), "CloseHandle(power request)");
    SetLastError(0);
    CHECK(!PowerSetRequest(r, PowerRequestSystemRequired) && GetLastError() == ERROR_INVALID_HANDLE, "a closed request is ERROR_INVALID_HANDLE");
    rc.Version = 7;
    SetLastError(0);
    CHECK(PowerCreateRequest(&rc) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER, "an unknown REASON_CONTEXT version is refused");
}

static void test_time(void)
{
    TIME_ZONE_INFORMATION tz, pac;
    DYNAMIC_TIME_ZONE_INFORMATION dz;
    FILETIME utc, loc, back;
    SYSTEMTIME st, out;
    GetTimeZoneInformation(&tz);
    GetSystemTimeAsFileTime(&utc);
    CHECK(FileTimeToLocalFileTime(&utc, &loc) && LocalFileTimeToFileTime(&loc, &back) && back.dwLowDateTime == utc.dwLowDateTime &&
          back.dwHighDateTime == utc.dwHighDateTime, "FileTimeToLocalFileTime and back is the identity");
    CHECK((LONGLONG)((((ULONGLONG)utc.dwHighDateTime << 32) | utc.dwLowDateTime) - (((ULONGLONG)loc.dwHighDateTime << 32) | loc.dwLowDateTime)) ==
          (LONGLONG)tz.Bias * 600000000, "local = UTC - Bias of the current zone");
    CHECK(GetDynamicTimeZoneInformation(&dz) != TIME_ZONE_ID_INVALID && dz.Bias == tz.Bias && weq(dz.TimeZoneKeyName, "UTC"), "GetDynamicTimeZoneInformation: the UTC zone");
    memset(&pac, 0, sizeof pac);
    pac.Bias = 480; pac.DaylightBias = -60;
    pac.StandardDate.wMonth = 11; pac.StandardDate.wDay = 1; pac.StandardDate.wHour = 2;           /* first Sunday of November */
    pac.DaylightDate.wMonth = 3; pac.DaylightDate.wDay = 2; pac.DaylightDate.wHour = 2;             /* second Sunday of March */
    memset(&st, 0, sizeof st);
    st.wYear = 2024; st.wMonth = 7; st.wDay = 1; st.wHour = 12;
    CHECK(SystemTimeToTzSpecificLocalTime(&pac, &st, &out) && out.wHour == 5 && out.wDay == 1 && out.wDayOfWeek == 1,
          "2024-07-01 12:00 UTC is 05:00 PDT, a Monday");
    st.wMonth = 3; st.wDay = 10; st.wHour = 10;
    CHECK(SystemTimeToTzSpecificLocalTime(&pac, &st, &out) && out.wHour == 3, "PDT begins at 10:00 UTC on 2024-03-10 (03:00 local)");
    st.wMonth = 11; st.wDay = 3; st.wHour = 9;
    CHECK(SystemTimeToTzSpecificLocalTime(&pac, &st, &out) && out.wHour == 1, "PST again at 09:00 UTC on 2024-11-03 (01:00 local)");
    st.wMonth = 12; st.wDay = 25; st.wHour = 20;
    CHECK(TzSpecificLocalTimeToSystemTime(&pac, &st, &out) && out.wDay == 26 && out.wHour == 4, "20:00 PST on Dec 25 is 04:00 UTC on Dec 26");
    CHECK(SystemTimeToTzSpecificLocalTime(0, &st, &out) && out.wHour == 20 - tz.Bias / 60, "a NULL zone means the current zone");
    pac.StandardDate.wMonth = 0;
    SetLastError(0);
    CHECK(!SystemTimeToTzSpecificLocalTime(&pac, &st, &out) && GetLastError() == ERROR_INVALID_PARAMETER, "a daylight rule without a standard rule is invalid");
}

static void write_file(const char *path, const void *data, DWORD n)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    DWORD w;
    if (h != INVALID_HANDLE_VALUE) { WriteFile(h, data, n, &w, 0); CloseHandle(h); }
}

static void test_profile(void)
{
    static const char ini[] = "[App]\r\nName = Shizuku\r\nPath=\"C:\\SHZ\"\r\n[Other]\r\nx=1\r\n";
    static const WCHAR ini16[] = { 0xfeff, '[', 'U', ']', '\n', 'k', '=', 0x00e9, 't', 0x00e9, '\n', 0 };
    WCHAR out[64];
    DWORD r;
    write_file("C:\\TEMP\\k32sys.ini", ini, sizeof ini - 1);
    r = GetPrivateProfileStringW(W("App"), W("Name"), W("none"), out, 64, W("C:\\TEMP\\k32sys.ini"));
    CHECK(r == 7 && weq(out, "Shizuku"), "GetPrivateProfileStringW reads a value (blanks trimmed)");
    r = GetPrivateProfileStringW(W("app"), W("PATH"), W(""), out, 64, W("C:\\TEMP\\k32sys.ini"));
    CHECK(r == 6 && weq(out, "C:\\SHZ"), "names compare without case; surrounding quotes are removed");
    SetLastError(0);
    r = GetPrivateProfileStringW(W("App"), W("Missing"), W("dflt  "), out, 64, W("C:\\TEMP\\k32sys.ini"));
    CHECK(r == 4 && weq(out, "dflt") && GetLastError() == ERROR_FILE_NOT_FOUND, "a missing key returns the default without trailing blanks");
    r = GetPrivateProfileStringW(0, 0, 0, out, 64, W("C:\\TEMP\\k32sys.ini"));
    CHECK(r == 10 && weq(out, "App") && weq(out + 4, "Other") && out[10] == 0, "section names, each NUL-terminated, then a final NUL");
    r = GetPrivateProfileStringW(W("App"), 0, 0, out, 64, W("C:\\TEMP\\k32sys.ini"));
    CHECK(r == 10 && weq(out, "Name") && weq(out + 5, "Path"), "key names of a section");
    r = GetPrivateProfileStringW(W("App"), W("Name"), 0, out, 4, W("C:\\TEMP\\k32sys.ini"));
    CHECK(r == 3 && weq(out, "Shi"), "a value is truncated to nSize - 1");
    SetLastError(0);
    r = GetPrivateProfileStringW(W("App"), W("Name"), W("d"), out, 64, W("C:\\TEMP\\no-such.ini"));
    CHECK(r == 1 && weq(out, "d") && GetLastError() == ERROR_FILE_NOT_FOUND, "a missing file gives the default and ERROR_FILE_NOT_FOUND");
    write_file("C:\\TEMP\\k32sys16.ini", ini16, sizeof ini16 - 2);
    r = GetPrivateProfileStringW(W("U"), W("k"), 0, out, 64, W("C:\\TEMP\\k32sys16.ini"));
    CHECK(r == 3 && out[0] == 0x00e9 && out[1] == 't' && out[2] == 0x00e9, "a UTF-16 file (byte-order mark)");
    DeleteFileA("C:\\TEMP\\k32sys.ini");
    DeleteFileA("C:\\TEMP\\k32sys16.ini");
}

static BOOL WINAPI ctrl_a(DWORD t) { (void)t; return FALSE; }
static BOOL WINAPI ctrl_b(DWORD t) { (void)t; return FALSE; }

static void test_console(void)
{
    CONSOLE_SCREEN_BUFFER_INFO a, b;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE), in = GetStdHandle(STD_INPUT_HANDLE), f;
    DWORD mode, got = 99, fl = 7, w;
    WCHAR buf[8];
    BOOL initial_buffer_ok = GetConsoleScreenBufferInfo(out, &a) && a.dwSize.X == 80 && a.dwSize.Y == 25 && a.srWindow.Right == 79 && a.srWindow.Bottom == 24;
    WriteFile(out, "abc", 3, &w, 0);
    BOOL cursor_write_ok = GetConsoleScreenBufferInfo(out, &b) && b.dwCursorPosition.X == a.dwCursorPosition.X + 3 && b.dwCursorPosition.Y == a.dwCursorPosition.Y;
    WriteConsoleW(out, W("\r\n"), 2, &w, 0);
    BOOL cursor_crlf_ok = GetConsoleScreenBufferInfo(out, &b) && b.dwCursorPosition.X == 0;
    BOOL attribute_ok = SetConsoleTextAttribute(out, FOREGROUND_GREEN | FOREGROUND_INTENSITY) && GetConsoleScreenBufferInfo(out, &b) &&
          b.wAttributes == (FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    CHECK(initial_buffer_ok, "GetConsoleScreenBufferInfo: an 80x25 buffer and window");
    CHECK(cursor_write_ok, "writing 3 characters moves the cursor 3 columns");
    CHECK(cursor_crlf_ok, "CR LF returns to column 0");
    CHECK(attribute_ok, "SetConsoleTextAttribute is reported back");
    SetConsoleTextAttribute(out, a.wAttributes);
    SetLastError(0);
    CHECK(!GetConsoleScreenBufferInfo(in, &b) && GetLastError() == ERROR_INVALID_HANDLE, "the input handle is no screen buffer");
    f = CreateFileA("C:\\TEMP\\k32con.txt", GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, 0);
    SetLastError(0);
    CHECK(f != INVALID_HANDLE_VALUE && !GetConsoleScreenBufferInfo(f, &b) && GetLastError() == ERROR_INVALID_HANDLE, "a file handle is no console");
    CHECK(GetConsoleDisplayMode(&fl) && fl == 0, "GetConsoleDisplayMode: not full screen");
    CHECK(ReadConsoleW(in, buf, 8, &got, 0) && got == 0, "ReadConsoleW: the serial console has no input (0 characters)");
    CHECK(SetConsoleCtrlHandler(ctrl_a, TRUE) && SetConsoleCtrlHandler(ctrl_b, TRUE) && SetConsoleCtrlHandler(ctrl_a, FALSE), "add two handlers, remove one");
    SetLastError(0);
    CHECK(!SetConsoleCtrlHandler(ctrl_a, FALSE) && GetLastError() == ERROR_INVALID_PARAMETER, "removing a handler that is not registered fails");
    CHECK(SetConsoleCtrlHandler(ctrl_b, FALSE) && SetConsoleCtrlHandler(0, TRUE) && SetConsoleCtrlHandler(0, FALSE), "the ignore-CTRL+C flag");

    SetLastError(0);
    CHECK(!AllocConsole() && GetLastError() == ERROR_ACCESS_DENIED, "AllocConsole while attached fails (one console per process)");
    SetLastError(0);
    CHECK(!AttachConsole(ATTACH_PARENT_PROCESS) && GetLastError() == ERROR_ACCESS_DENIED, "AttachConsole while attached fails");
    CHECK(FreeConsole(), "FreeConsole");
    SetLastError(0);
    CHECK(!GetConsoleMode(out, &mode) && GetLastError() == ERROR_INVALID_HANDLE, "after FreeConsole the console handles are no console");
    CHECK(AllocConsole(), "AllocConsole after FreeConsole");
    CHECK(GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE && GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode),
          "the new standard output is a console");
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
}

static void test_devices(void)
{
    HANDLE f, ev = CreateEventW(0, TRUE, FALSE, 0);
    DCB dcb;
    COMMTIMEOUTS to;
    DWORD st, vflags = 0;
    SetLastError(0);
    CHECK(CreateFileW(W("COM1"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND,
          "COM1 does not exist (ERROR_FILE_NOT_FOUND)");
    SetLastError(0);
    CHECK(CreateFileW(W("\\\\.\\COM1"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND,
          "\\\\.\\COM1 does not exist either");
    f = CreateFileA("C:\\TEMP\\k32dev.txt", GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    memset(&dcb, 0, sizeof dcb);
    dcb.DCBlength = sizeof dcb;
    SetLastError(0);
    CHECK(!GetCommState(f, &dcb) && GetLastError() == ERROR_INVALID_FUNCTION, "GetCommState(disk file) is ERROR_INVALID_FUNCTION");
    SetLastError(0);
    CHECK(!SetCommState(GetStdHandle(STD_OUTPUT_HANDLE), &dcb) && GetLastError() == ERROR_INVALID_FUNCTION, "SetCommState(console) is ERROR_INVALID_FUNCTION");
    SetLastError(0);
    CHECK(!ClearCommError(ev, &st, 0) && GetLastError() == ERROR_INVALID_HANDLE, "ClearCommError(event) is ERROR_INVALID_HANDLE");
    memset(&to, 0, sizeof to);
    SetLastError(0);
    CHECK(!SetCommTimeouts(f, &to) && GetLastError() == ERROR_INVALID_FUNCTION, "SetCommTimeouts(disk file)");
    SetLastError(0);
    CHECK(!GetCommModemStatus(f, &st) && GetLastError() == ERROR_INVALID_FUNCTION, "GetCommModemStatus(disk file)");
    SetLastError(0);
    CHECK(!EscapeCommFunction(f, 99) && GetLastError() == ERROR_INVALID_PARAMETER, "EscapeCommFunction(99) is ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(!EscapeCommFunction(f, SETDTR) && GetLastError() == ERROR_INVALID_FUNCTION, "EscapeCommFunction(disk file, SETDTR)");
    SetLastError(0);
    CHECK(!PurgeComm(f, 0x100) && GetLastError() == ERROR_INVALID_PARAMETER, "PurgeComm with an unknown flag");
    SetLastError(0);
    CHECK(!PurgeComm(f, PURGE_RXCLEAR) && GetLastError() == ERROR_INVALID_FUNCTION, "PurgeComm(disk file)");
    CloseHandle(f);

    GetVolumeInformationW(W("C:\\"), 0, 0, 0, 0, &vflags, 0, 0);
    CHECK(!(vflags & FILE_SUPPORTS_HARD_LINKS), "volume C: does not report FILE_SUPPORTS_HARD_LINKS");
    SetLastError(0);
    CHECK(!CreateHardLinkW(W("C:\\TEMP\\k32link.txt"), W("C:\\TEMP\\k32dev.txt"), 0) && GetLastError() == ERROR_INVALID_FUNCTION,
          "so CreateHardLinkW is refused by the file system (ERROR_INVALID_FUNCTION, as on FAT)");
    CHECK(GetFileAttributesA("C:\\TEMP\\k32link.txt") == INVALID_FILE_ATTRIBUTES, "... and no link name appears");
    SetLastError(0);
    CHECK(!CreateHardLinkW(W("C:\\TEMP\\k32link.txt"), W("C:\\TEMP\\no-such-file"), 0) && GetLastError() == ERROR_FILE_NOT_FOUND, "a missing target");
    SetLastError(0);
    CHECK(!CreateHardLinkW(W("C:\\TEMP\\k32dev.txt"), W("C:\\TEMP\\k32dev.txt"), 0) && GetLastError() == ERROR_ALREADY_EXISTS, "an existing link name");
    DeleteFileA("C:\\TEMP\\k32dev.txt");
    CloseHandle(ev);
}

int main(void)
{
    test_processors();
    test_identity();
    test_power();
    test_time();
    test_profile();
    test_console();
    test_devices();
    return k32t_finish("t_k32_sys");
}
