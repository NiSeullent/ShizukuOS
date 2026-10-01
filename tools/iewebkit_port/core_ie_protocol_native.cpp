/* Actual IE5 protocol ingress plus unchanged DocObject Load acceptance diagnostic.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * Run only in a disposable Win98SE clone with its NIC absent. GUI subsystem.
 */
#include <windows.h>
#include <exdisp.h>
#include <tlhelp32.h>
#include <winver.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char* const wizardKey = "Software\\Microsoft\\Internet Connection Wizard";
static const char* const tracePath = "C:\\ZUKUQA\\IENAV.LOG";
static const char* const docKey = "CLSID\\{9B07CC1A-E5D2-434C-95E8-DF2FA0694A13}";
static const char* const mimeKey = "MIME\\Database\\Content Type\\application/x-iewebkit-document";
static const char* const bhoKey = "CLSID\\{73926903-B304-4B92-8604-20065047A13A}";
static const char* const bhoListKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{73926903-B304-4B92-8604-20065047A13A}";
static HANDLE logFile = INVALID_HANDLE_VALUE;
static DWORD logBytes;
static bool logGood = true;
static char nonce[81];

static bool writeBytes(HANDLE file, const void* data, DWORD length)
{
    DWORD written = 0;
    return WriteFile(file, data, length, &written, NULL) && written == length;
}

static void record(const char* format, ...)
{
    char line[1024];
    va_list args;
    va_start(args, format);
    int length = _vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (length < 0 || length >= static_cast<int>(sizeof(line)) || logBytes > 65536UL - static_cast<DWORD>(length)) {
        logGood = false;
        return;
    }
    logGood = writeBytes(logFile, line, static_cast<DWORD>(length)) && logGood;
    logBytes += static_cast<DWORD>(length);
    logGood = FlushFileBuffers(logFile) && logGood;
}

static bool absentFile(const char* path)
{
    DWORD value = GetFileAttributesA(path);
    return value == INVALID_FILE_ATTRIBUTES && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
}

static bool freshFile(const char* path, const void* data, DWORD bytes)
{
    HANDLE file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    bool ok = writeBytes(file, data, bytes) && FlushFileBuffers(file);
    return CloseHandle(file) && ok;
}

static void pump(DWORD duration)
{
    DWORD begin = GetTickCount();
    do {
        MSG message;
        while (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
            if (message.message != WM_QUIT) {
                TranslateMessage(&message);
                DispatchMessageA(&message);
            }
        }
        Sleep(10);
    } while (GetTickCount() - begin < duration);
}

static bool parameters(const char* command, char* provenance)
{
    const char* start = command;
    while (*start == ' ')
        ++start;
    const char* end = start;
    while (*end && *end != ' ')
        ++end;
    size_t length = static_cast<size_t>(end - start);
    if (!length || length > 80)
        return false;
    memcpy(nonce, start, length);
    nonce[length] = 0;
    if (strspn(nonce, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != length)
        return false;
    while (*end == ' ')
        ++end;
    if (strcmp(end, "C:\\GOPLAB\\IEPROV.TXT"))
        return false;
    strcpy(provenance, end);
    return true;
}

static bool provenanceFile(const char* path)
{
    static const char* const names[] = {"source", "binary", "host", "bho", "host-receipt", "patch", "pin", "receipt"};
    FILE* file = fopen(path, "rb");
    if (!file)
        return false;
    bool ok = true;
    for (unsigned row = 0; row < sizeof(names) / sizeof(names[0]) && ok; ++row) {
        char value[68];
        ok = fgets(value, sizeof(value), file) != NULL;
        if (!ok)
            break;
        value[strcspn(value, "\r\n")] = 0;
        ok = strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
        if (ok)
            record("expected.%s.sha256=%s\r\n", names[row], value);
    }
    ok = ok && fgetc(file) == EOF && !ferror(file);
    fclose(file);
    return ok;
}

static bool fileVersion(const char* path, DWORD* ms, DWORD* ls)
{
    DWORD ignored = 0, bytes = GetFileVersionInfoSizeA(path, &ignored);
    if (!bytes || bytes > 1024UL * 1024)
        return false;
    void* data = HeapAlloc(GetProcessHeap(), 0, bytes);
    VS_FIXEDFILEINFO* info = NULL;
    UINT size = 0;
    bool ok = data && GetFileVersionInfoA(path, 0, bytes, data)
        && VerQueryValueA(data, "\\", reinterpret_cast<void**>(&info), &size)
        && size >= sizeof(*info) && info->dwSignature == 0xfeef04bd;
    if (ok) {
        *ms = info->dwFileVersionMS;
        *ls = info->dwFileVersionLS;
    }
    if (data)
        HeapFree(GetProcessHeap(), 0, data);
    return ok;
}

static bool exactTarget()
{
    OSVERSIONINFOA os = {};
    os.dwOSVersionInfoSize = sizeof(os);
    bool osOK = GetVersionExA(&os) && os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS
        && os.dwMajorVersion == 4 && os.dwMinorVersion == 10 && (os.dwBuildNumber & 0xffff) == 2222;
    record("os=%lu.%lu.%lu\r\nplatform=%lu\r\n", os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber & 0xffff, os.dwPlatformId);
    char shdocvw[MAX_PATH] = {}, ie[MAX_PATH] = {};
    UINT n = GetSystemDirectoryA(shdocvw, sizeof(shdocvw));
    bool shPath = n && n + sizeof("\\SHDOCVW.DLL") <= sizeof(shdocvw);
    if (shPath)
        strcat(shdocvw, "\\SHDOCVW.DLL");
    HKEY key = NULL;
    DWORD type = 0, bytes = sizeof(ie);
    bool iePath = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE", 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS;
    if (iePath) {
        iePath = RegQueryValueExA(key, NULL, NULL, &type, reinterpret_cast<BYTE*>(ie), &bytes) == ERROR_SUCCESS
            && type == REG_SZ && bytes > 1 && bytes <= sizeof(ie) && ie[bytes - 1] == 0;
        RegCloseKey(key);
    }
    DWORD shMS = 0, shLS = 0, ieMS = 0, ieLS = 0;
    bool shOK = shPath && fileVersion(shdocvw, &shMS, &shLS);
    bool ieOK = iePath && fileVersion(ie, &ieMS, &ieLS);
    record("shdocvw_version=%u.%u.%u.%u\r\niexplore_version=%u.%u.%u.%u\r\n", HIWORD(shMS), LOWORD(shMS), HIWORD(shLS), LOWORD(shLS), HIWORD(ieMS), LOWORD(ieMS), HIWORD(ieLS), LOWORD(ieLS));
    bool ok = osOK && shOK && ieOK && shMS == 0x00050000 && ieMS == shMS && shLS == MAKELONG(3500, 2614) && ieLS == shLS;
    record("target_matched=%u\r\n", static_cast<unsigned>(ok));
    return ok;
}

static bool noExistingIE()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;
    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    BOOL found = Process32First(snapshot, &entry);
    bool ok = found != FALSE;
    unsigned count = 0;
    while (found) {
        if (++count > 4096) {
            ok = false;
            break;
        }
        const char* base = strrchr(entry.szExeFile, '\\');
        base = base ? base + 1 : entry.szExeFile;
        if (!lstrcmpiA(base, "IEXPLORE.EXE")) {
            record("preexisting.ie.pid=%lu\r\n", entry.th32ProcessID);
            ok = false;
        }
        found = Process32Next(snapshot, &entry);
    }
    if (GetLastError() != ERROR_NO_MORE_FILES)
        ok = false;
    CloseHandle(snapshot);
    record("preexisting.ie.absent=%u\r\n", static_cast<unsigned>(ok));
    return ok;
}

static bool ownedIEProcess(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;
    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    BOOL found = Process32First(snapshot, &entry);
    unsigned count = 0, matches = 0;
    bool ownsPID = false, valid = found != FALSE;
    while (found) {
        if (++count > 4096 || !memchr(entry.szExeFile, 0, sizeof(entry.szExeFile))) {
            valid = false;
            break;
        }
        const char* base = strrchr(entry.szExeFile, '\\');
        base = base ? base + 1 : entry.szExeFile;
        if (!lstrcmpiA(base, "IEXPLORE.EXE")) {
            ++matches;
            if (entry.th32ProcessID == pid) {
                ownsPID = true;
                record("browser.process.image=%s\r\n", entry.szExeFile);
            }
        }
        found = Process32Next(snapshot, &entry);
    }
    valid = valid && GetLastError() == ERROR_NO_MORE_FILES && matches == 1 && ownsPID;
    CloseHandle(snapshot);
    record("browser.process.unique-iexplore=%u\r\n", static_cast<unsigned>(valid));
    return valid;
}

static bool keyAbsent(HKEY root, const char* path)
{
    HKEY key = NULL;
    LONG result = RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE, &key);
    if (key)
        RegCloseKey(key);
    return result == ERROR_FILE_NOT_FOUND;
}

static bool registrationsAbsent(const char* label)
{
    bool doc = keyAbsent(HKEY_CLASSES_ROOT, docKey), mime = keyAbsent(HKEY_CLASSES_ROOT, mimeKey);
    bool bho = keyAbsent(HKEY_CLASSES_ROOT, bhoKey), list = keyAbsent(HKEY_LOCAL_MACHINE, bhoListKey);
    record("%s.doc.absent=%u\r\n%s.mime.absent=%u\r\n%s.bho.absent=%u\r\n%s.bholist.absent=%u\r\n", label, static_cast<unsigned>(doc), label, static_cast<unsigned>(mime), label, static_cast<unsigned>(bho), label, static_cast<unsigned>(list));
    return doc && mime && bho && list;
}

struct WizardState {
    DWORD magic, version, keyPresent, valuePresent, type, bytes;
    char testNonce[81];
    BYTE data[256];
};

static bool readWizard(WizardState* state)
{
    memset(state, 0, sizeof(*state));
    state->magic = 0x39575a49;
    state->version = 1;
    strcpy(state->testNonce, nonce);
    HKEY key = NULL;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, wizardKey, 0, KEY_QUERY_VALUE, &key);
    if (result == ERROR_FILE_NOT_FOUND)
        return true;
    if (result != ERROR_SUCCESS)
        return false;
    state->keyPresent = 1;
    state->bytes = sizeof(state->data);
    result = RegQueryValueExA(key, "Completed", NULL, &state->type, state->data, &state->bytes);
    RegCloseKey(key);
    if (result == ERROR_FILE_NOT_FOUND) {
        state->type = state->bytes = 0;
        memset(state->data, 0, sizeof(state->data));
        return true;
    }
    if (result != ERROR_SUCCESS || state->bytes > sizeof(state->data))
        return false;
    state->valuePresent = 1;
    return true;
}

static void wizardRecord(const char* label, const WizardState& state)
{
    char hex[513];
    static const char digits[] = "0123456789abcdef";
    for (DWORD i = 0; i < state.bytes; ++i) {
        hex[i * 2] = digits[state.data[i] >> 4];
        hex[i * 2 + 1] = digits[state.data[i] & 15];
    }
    hex[state.bytes * 2] = 0;
    record("%s.key.present=%lu\r\n%s.value.present=%lu\r\n%s.type=%lu\r\n%s.bytes=%lu\r\n%s.data.hex=%s\r\n", label, state.keyPresent, label, state.valuePresent, label, state.type, label, state.bytes, label, hex);
}

static bool wizardSet(const WizardState& before, bool* keyCreated, bool* restoreNeeded)
{
    HKEY key = NULL;
    LONG result;
    if (before.keyPresent)
        result = RegOpenKeyExA(HKEY_CURRENT_USER, wizardKey, 0, KEY_SET_VALUE, &key);
    else {
        // Require the parent to exist; do not create a registry ancestor chain.
        HKEY parent = NULL;
        result = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft", 0, KEY_CREATE_SUB_KEY, &parent);
        if (result != ERROR_SUCCESS)
            return false;
        DWORD disposition = 0;
        result = RegCreateKeyExA(parent, "Internet Connection Wizard", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, &disposition);
        RegCloseKey(parent);
        *keyCreated = result == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY;
        if (*keyCreated)
            *restoreNeeded = true;
        if (result == ERROR_SUCCESS && !*keyCreated) {
            RegCloseKey(key);
            return false;
        }
    }
    if (result != ERROR_SUCCESS)
        return false;
    *restoreNeeded = true;
    DWORD completed = 1;
    result = RegSetValueExA(key, "Completed", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&completed), sizeof(completed));
    RegCloseKey(key);
    WizardState installed;
    bool ok = result == ERROR_SUCCESS && readWizard(&installed) && installed.keyPresent && installed.valuePresent
        && installed.type == REG_DWORD && installed.bytes == sizeof(completed) && !memcmp(installed.data, &completed, sizeof(completed));
    record("wizard.set.status=%lu\r\nwizard.set.verified=%u\r\n", static_cast<DWORD>(result), static_cast<unsigned>(ok));
    return ok;
}

static bool wizardRestore(const WizardState& before, bool keyCreated)
{
    HKEY key = NULL;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, wizardKey, 0, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key);
    bool ok = result == ERROR_SUCCESS;
    if (ok) {
        result = before.valuePresent ? RegSetValueExA(key, "Completed", 0, before.type, before.data, before.bytes) : RegDeleteValueA(key, "Completed");
        ok = result == ERROR_SUCCESS || (!before.valuePresent && result == ERROR_FILE_NOT_FOUND);
        if (ok && keyCreated) {
            DWORD subkeys = 0, values = 0;
            result = RegQueryInfoKeyA(key, NULL, NULL, NULL, &subkeys, NULL, NULL, &values, NULL, NULL, NULL, NULL);
            ok = result == ERROR_SUCCESS && !subkeys && !values;
        }
        RegCloseKey(key);
        if (ok && keyCreated)
            ok = RegDeleteKeyA(HKEY_CURRENT_USER, wizardKey) == ERROR_SUCCESS;
    } else if (!before.keyPresent && result == ERROR_FILE_NOT_FOUND)
        ok = true;
    WizardState after;
    bool readOK = readWizard(&after);
    if (readOK)
        wizardRecord("wizard.after", after);
    ok = ok && readOK && after.keyPresent == before.keyPresent && after.valuePresent == before.valuePresent
        && after.type == before.type && after.bytes == before.bytes && !memcmp(after.data, before.data, before.bytes);
    record("wizard.restore.exact=%u\r\n", static_cast<unsigned>(ok));
    return ok;
}

typedef HRESULT (STDAPICALLTYPE* RegisterFunction)();
struct Registration {
    HMODULE module;
    RegisterFunction install, uninstall;
    bool attempted;
};

static bool loadRegistration(const char* path, Registration* reg)
{
    reg->module = LoadLibraryA(path);
    if (!reg->module)
        return false;
    reg->install = reinterpret_cast<RegisterFunction>(GetProcAddress(reg->module, "DllRegisterServer"));
    reg->uninstall = reinterpret_cast<RegisterFunction>(GetProcAddress(reg->module, "DllUnregisterServer"));
    return reg->install && reg->uninstall;
}

static bool installRegistration(const char* label, Registration* reg)
{
    reg->attempted = true;
    record("%s.register.enter=1\r\n", label);
    HRESULT result = reg->install();
    record("%s.register.hr=0x%08lx\r\n", label, static_cast<DWORD>(result));
    return result == S_OK;
}

static bool uninstallRegistration(const char* label, Registration* reg)
{
    if (!reg->attempted)
        return true;
    record("%s.unregister.enter=1\r\n", label);
    HRESULT result = reg->uninstall();
    record("%s.unregister.hr=0x%08lx\r\n", label, static_cast<DWORD>(result));
    return result == S_OK;
}

static bool readTrace(char* data, DWORD capacity)
{
    HANDLE file = CreateFileA(tracePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD high = 0, bytes = GetFileSize(file, &high), read = 0;
    bool ok = !high && bytes != INVALID_FILE_SIZE && bytes < capacity && ReadFile(file, data, bytes, &read, NULL) && read == bytes;
    CloseHandle(file);
    if (ok)
        data[bytes] = 0;
    return ok;
}

static bool handoffTrace()
{
    static char data[65537];
    if (!readTrace(data, sizeof(data)))
        return false;
    char prefix[128];
    wsprintfA(prefix, "nonce=%s\r\n", nonce);
    return !strncmp(data, prefix, strlen(prefix))
        && strstr(data, "BHO.browser=0x00000000\r\n")
        && strstr(data, "BHO.attach=0x00000000\r\n")
        && strstr(data, "BHO.top_navigation=0x00000001\r\n")
        && strstr(data, "BHO.arm_get=0x00000000\r\n")
        && strstr(data, "Document.Load=0x00000001\r\n")
        && strstr(data, "Document.remote_https=0x00000001\r\n")
        && strstr(data, "Document.show=0x00000001\r\n")
        && strstr(data, "Document.engine_missing=0x00000001\r\n");
}


// Keys include a real per-Start ID so reentrant callbacks cannot combine fields
// from separate URLMon requests into a component verdict.
static const char* protocolField(const char* data, DWORD event, const char* field)
{
    char prefix[128];
    wsprintfA(prefix, "Handoff.%lu.%s=", event, field);
    const char* first = NULL;
    const char* next = data;
    while ((next = strstr(next, prefix)) != NULL) {
        if (next == data || next[-1] == '\n') {
            if (first)
                return NULL;
            first = next + strlen(prefix);
        }
        ++next;
    }
    return first;
}

static bool protocolEquals(const char* data, DWORD event, const char* field, const char* expected)
{
    const char* value = protocolField(data, event, field);
    size_t length = strlen(expected);
    return value && !strncmp(value, expected, length) && !strncmp(value + length, "\r\n", 2);
}

static bool protocolHex(const char* data, DWORD event, const char* field, DWORD* result)
{
    const char* value = protocolField(data, event, field);
    if (!value || strncmp(value, "0x", 2) || strspn(value + 2, "0123456789abcdef") != 8 || strncmp(value + 10, "\r\n", 2))
        return false;
    DWORD number = 0;
    for (unsigned i = 2; i < 10; ++i)
        number = (number << 4) | (value[i] <= '9' ? value[i] - '0' : value[i] - 'a' + 10);
    *result = number;
    return true;
}

static bool protocolTrace()
{
    static char data[65537];
    if (!readTrace(data, sizeof(data)))
        return false;
    char header[128], url[160];
    wsprintfA(header, "nonce=%s\r\n", nonce);
    wsprintfA(url, "https://reserved.invalid/iewebkit-83bd/%s", nonce);
    if (strncmp(data, header, strlen(header)) || !strstr(data, "BHO.arm_get=0x00000000\r\n")
        || !strstr(data, "BHO.attach=0x00000000\r\n") || !strstr(data, "BHO.top_navigation=0x00000001\r\n"))
        return false;
    const char* cursor = data;
    unsigned starts = 0;
    while ((cursor = strstr(cursor, "\nHandoff.")) != NULL) {
        ++cursor;
        const char* number = cursor + strlen("Handoff.");
        DWORD event = 0;
        unsigned digits = 0;
        while (*number >= '0' && *number <= '9' && digits < 10) {
            DWORD digit = static_cast<DWORD>(*number - '0');
            if (event > (0xffffffffUL - digit) / 10)
                return false;
            event = event * 10 + digit;
            ++number;
            ++digits;
        }
        if (!event || !digits || strncmp(number, ".enter=0x00000001\r\n", strlen(".enter=0x00000001\r\n")))
            continue;
        if (++starts > 256)
            return false;
        DWORD bindHR = 0, clsidHR = 0, returnedHR = 0, aborted = 0;
        bool valid = protocolEquals(data, event, "url.valid", "0x00000001")
            && protocolEquals(data, event, "url", url)
            && protocolEquals(data, event, "nonce.valid", "0x00000001")
            && protocolEquals(data, event, "nonce", nonce)
            && protocolEquals(data, event, "attached", "0x00000001")
            && protocolEquals(data, event, "thread_match", "0x00000001")
            && protocolEquals(data, event, "pending.present", "0x00000001")
            && protocolEquals(data, event, "matched", "0x00000001")
            && protocolEquals(data, event, "parse_url", "0x00000000")
            && protocolEquals(data, event, "eligible.before_bind", "0x00000001")
            && protocolEquals(data, event, "bind.enter", "0x00000001")
            && protocolHex(data, event, "bind.hr", &bindHR) && !(bindHR & 0x80000000UL)
            && protocolEquals(data, event, "bind.verb", "0x00000000")
            && protocolEquals(data, event, "bind.bytes", "0x00000000")
            && protocolEquals(data, event, "bind.tymed", "0x00000000")
            && protocolEquals(data, event, "eligible", "0x00000001")
            && protocolEquals(data, event, "delegated", "0x00000000")
            && protocolEquals(data, event, "pending.before_consume", "0x00000001")
            && protocolEquals(data, event, "pending.after_consume", "0x00000000")
            && protocolEquals(data, event, "report.clsid.enter", "0x00000001")
            && protocolHex(data, event, "report.clsid.hr", &clsidHR)
            && protocolHex(data, event, "aborted", &aborted) && aborted <= 1
            && protocolHex(data, event, "return.hr", &returnedHR);
        if (!valid)
            continue;
        DWORD mimeHR = 0, dataHR = 0, resultHR = 0, inputHR = 0;
        bool reportingComplete = protocolEquals(data, event, "report.mime.enter", "0x00000001")
            && protocolHex(data, event, "report.mime.hr", &mimeHR)
            && protocolEquals(data, event, "report.data.enter", "0x00000001")
            && protocolHex(data, event, "report.data.hr", &dataHR)
            && protocolEquals(data, event, "report.result.enter", "0x00000001")
            && protocolHex(data, event, "report.result.input_hr", &inputHR) && inputHR == returnedHR
            && protocolHex(data, event, "report.result.hr", &resultHR);
        bool reportingSuccess = reportingComplete && !aborted
            && !((clsidHR | mimeHR | dataHR | resultHR | returnedHR) & 0x80000000UL);
        record("protocol.event=%lu\r\nprotocol.bind.hr=0x%08lx\r\nprotocol.report.clsid.hr=0x%08lx\r\nprotocol.return.hr=0x%08lx\r\nprotocol.aborted=%lu\r\nprotocol.reporting.complete=%u\r\nprotocol.reporting.success=%u\r\n", event, bindHR, clsidHR, returnedHR, aborted, static_cast<unsigned>(reportingComplete), static_cast<unsigned>(reportingSuccess));
        // This proves the actual Start URL and GET/no-body pending consumption.
        // ReportData and Document.Load may still fail because no engine exists.
        return true;
    }
    return false;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR command, int)
{
    char provenance[MAX_PATH];
    if (!parameters(command, provenance))
        return 2;
    logFile = CreateFileA("C:\\GOPLAB\\IEACT.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (logFile == INVALID_HANDLE_VALUE)
        return 2;
    record("schema=iewebkit-win98-ie5-protocol-activation-v2\r\nnonce=%s\r\nscope=actual-IE-localserver-protocol-ingress-diagnostic\r\nprovider_status=UNVERIFIED\r\nrendering_verified=0\r\ntls_verified=0\r\nrequires.nic.absent=1\r\n", nonce);
    int code = 10;
    bool oleReady = false, wizardAttempted = false, wizardCreated = false, traceCreated = false, directoryCreated = false;
    bool cocreateAttempted = false, ownedClosed = true, cleanupOK = true, handoffOK = false, protocolOK = false;
    WizardState wizard = {};
    Registration host = {}, bho = {};
    IWebBrowser2* browser = NULL;
    HWND window = NULL;
    HANDLE ieProcess = NULL;
    DWORD pid = 0;
    HRESULT result = E_FAIL;
    if (!provenanceFile(provenance) || !exactTarget())
        goto cleanup;
    if (!absentFile("C:\\GOPLAB\\IENAV.LOG") || !absentFile("C:\\GOPLAB\\IEWIZ.BAK")
        || !absentFile("C:\\GOPLAB\\IEDONE.TXT") || !absentFile("C:\\GOPLAB\\IEFAIL.TXT")
        || !absentFile("C:\\GOPLAB\\IPROTO.TXT")
        || !absentFile("C:\\GOPLAB\\iewebkit-engine.dll") || !absentFile(tracePath)) {
        code = 11;
        record("preflight.output-provider-trace.absent=0\r\n");
        goto cleanup;
    }
    if (!registrationsAbsent("registration.before") || !noExistingIE()) {
        code = 12;
        goto cleanup;
    }
    if (!readWizard(&wizard)) {
        code = 14;
        goto cleanup;
    }
    wizardRecord("wizard.before", wizard);
    if (!freshFile("C:\\GOPLAB\\IEWIZ.BAK", &wizard, sizeof(wizard))) {
        code = 15;
        goto cleanup;
    }
    // Persist the exact bounded original bytes before the first registry write.
    if (!wizardSet(wizard, &wizardCreated, &wizardAttempted)) {
        code = 16;
        goto cleanup;
    }
    result = OleInitialize(NULL);
    record("ole.initialize.hr=0x%08lx\r\n", static_cast<DWORD>(result));
    if (FAILED(result)) {
        code = 17;
        goto cleanup;
    }
    oleReady = true;
    if (!loadRegistration("C:\\GOPLAB\\IEWKHOST.DLL", &host) || !loadRegistration("C:\\GOPLAB\\NAVBHO.DLL", &bho)) {
        record("registration.load.error=%lu\r\n", GetLastError());
        code = 18;
        goto cleanup;
    }
    if (!installRegistration("host", &host) || !installRegistration("bho", &bho)) {
        code = 19;
        goto cleanup;
    }
    directoryCreated = CreateDirectoryA("C:\\ZUKUQA", NULL) != FALSE;
    if (!directoryCreated && GetLastError() != ERROR_ALREADY_EXISTS) {
        code = 20;
        goto cleanup;
    }
    {
        char prefix[128];
        wsprintfA(prefix, "nonce=%s\r\n", nonce);
        traceCreated = freshFile(tracePath, prefix, static_cast<DWORD>(strlen(prefix)));
    }
    if (!traceCreated) {
        code = 21;
        goto cleanup;
    }
    // Recheck immediately before activation: a concurrently opened IE is not ours.
    if (!noExistingIE()) {
        code = 22;
        goto cleanup;
    }
    cocreateAttempted = true;
    ownedClosed = false;
    record("browser.cocreate.enter=1\r\n");
    result = CoCreateInstance(CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER, IID_IWebBrowser2, reinterpret_cast<void**>(&browser));
    record("browser.cocreate.hr=0x%08lx\r\n", static_cast<DWORD>(result));
    if (FAILED(result) || !browser) {
        code = 23;
        goto cleanup;
    }
    {
        DWORD begin = GetTickCount();
        SHANDLE_PTR handle = 0;
        do {
            result = browser->get_HWND(&handle);
            window = reinterpret_cast<HWND>(handle);
            if (SUCCEEDED(result) && window && IsWindow(window))
                break;
            pump(20);
        } while (GetTickCount() - begin < 5000UL);
    }
    if (FAILED(result) || !window || !IsWindow(window) || !GetWindowThreadProcessId(window, &pid) || !pid || pid == GetCurrentProcessId()) {
        code = 24;
        goto cleanup;
    }
    ieProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    record("browser.hwnd=0x%08lx\r\nbrowser.pid=%lu\r\nbrowser.process.handle=%u\r\nbrowser.ownership=new-object-new-IE-process\r\n", reinterpret_cast<DWORD>(window), pid, static_cast<unsigned>(ieProcess != NULL));
    if (!ieProcess || !ownedIEProcess(pid)) {
        code = 25;
        goto cleanup;
    }
    record("browser.visible.enter=1\r\n");
    result = browser->put_Visible(VARIANT_TRUE);
    record("browser.visible.hr=0x%08lx\r\n", static_cast<DWORD>(result));
    if (FAILED(result)) {
        code = 26;
        goto cleanup;
    }
    {
        wchar_t url[160];
        char ascii[160];
        wsprintfA(ascii, "https://reserved.invalid/iewebkit-83bd/%s", nonce);
        unsigned i = 0;
        for (; ascii[i]; ++i)
            url[i] = static_cast<unsigned char>(ascii[i]);
        url[i] = 0;
        VARIANT target, empty;
        VariantInit(&target);
        VariantInit(&empty);
        target.vt = VT_BSTR;
        target.bstrVal = SysAllocString(url);
        if (!target.bstrVal) {
            code = 27;
            goto cleanup;
        }
        record("browser.url=%s\r\nbrowser.navigate.enter=1\r\n", ascii);
        result = browser->Navigate2(&target, &empty, &empty, &empty, &empty);
        record("browser.navigate.hr=0x%08lx\r\n", static_cast<DWORD>(result));
        VariantClear(&target);
        // An engine-missing DocObject can make navigation itself fail. The
        // fresh component trace, rather than Navigate2 success, proves handoff.
    }
    {
        DWORD begin = GetTickCount();
        do {
            pump(20);
            handoffOK = handoffTrace();
            if (!protocolOK)
                protocolOK = protocolTrace();
        } while (!handoffOK && GetTickCount() - begin < 10000UL);
        record("handoff.expected-engine-missing=%u\r\nbrowser.window.visible=%u\r\n", static_cast<unsigned>(handoffOK), static_cast<unsigned>(IsWindowVisible(window) != FALSE));
    }
    code = handoffOK && IsWindowVisible(window) ? 0 : 29;
    if ((handoffOK || protocolOK) && IsWindowVisible(window)) {
        // Allow the operator's bounded screenshots to capture the actual IE
        // surface before this probe quits its owned browser. No page is drawn.
        record("browser.visible.hold.ms=20000\r\n");
        pump(20000);
        if (!IsWindow(window) || !IsWindowVisible(window))
            code = 29;
    }
cleanup:
    if (browser) {
        record("browser.quit.enter=1\r\n");
        result = browser->Quit();
        record("browser.quit.hr=0x%08lx\r\n", static_cast<DWORD>(result));
        browser->Release();
        browser = NULL;
        DWORD begin = GetTickCount();
        do {
            pump(20);
            ownedClosed = SUCCEEDED(result) && window && !IsWindow(window) && ieProcess && WaitForSingleObject(ieProcess, 0) == WAIT_OBJECT_0;
        } while (!ownedClosed && GetTickCount() - begin < 10000UL);
    } else if (cocreateAttempted)
        ownedClosed = noExistingIE();
    if (ieProcess)
        CloseHandle(ieProcess);
    record("browser.owned.closed=%u\r\n", static_cast<unsigned>(ownedClosed));
    if (ownedClosed) {
        bool bhoClean = uninstallRegistration("bho", &bho);
        bool hostClean = uninstallRegistration("host", &host);
        cleanupOK = bhoClean && hostClean;
        if (host.attempted || bho.attempted)
            cleanupOK = registrationsAbsent("registration.after") && cleanupOK;
        if (wizardAttempted)
            cleanupOK = wizardRestore(wizard, wizardCreated) && cleanupOK;
        if (traceCreated) {
            static char data[65537];
            bool copied = readTrace(data, sizeof(data)) && freshFile("C:\\GOPLAB\\IENAV.LOG", data, static_cast<DWORD>(strlen(data)));
            record("trace.copied=%u\r\n", static_cast<unsigned>(copied));
            cleanupOK = copied && DeleteFileA(tracePath) && cleanupOK;
        }
        if (directoryCreated)
            cleanupOK = RemoveDirectoryA("C:\\ZUKUQA") && cleanupOK;
    } else {
        cleanupOK = false;
        record("cleanup.deferred=owned-IE-shutdown-unconfirmed\r\n");
    }
    if (bho.module)
        FreeLibrary(bho.module);
    if (host.module)
        FreeLibrary(host.module);
    if (oleReady)
        OleUninitialize();
    if (!cleanupOK && !code)
        code = 30;
    record("cleanup.verified=%u\r\nrendering_verified=0\r\nexit=%d\r\n", static_cast<unsigned>(cleanupOK), code);
    if (!logGood && !code)
        code = 31;
    char component[256];
    wsprintfA(component, "nonce=%s\r\nprotocol_ingress=1\r\nDocObject_Load_verified=%u\r\nprovider_status=UNVERIFIED\r\nrendering_verified=0\r\nexit=%d\r\n", nonce, static_cast<unsigned>(handoffOK), code);
    bool componentMarked = protocolOK && cleanupOK && logGood && freshFile("C:\\GOPLAB\\IPROTO.TXT", component, static_cast<DWORD>(strlen(component)));
    record("protocol.ingress.verified=%u\r\nDocObject.Load.acceptance=%u\r\nprotocol.component.marker=%u\r\n", static_cast<unsigned>(componentMarked), static_cast<unsigned>(handoffOK), static_cast<unsigned>(componentMarked));
    char marker[128];
    wsprintfA(marker, "nonce=%s\r\nexit=%d\r\n", nonce, code);
    bool marked = freshFile(code ? "C:\\GOPLAB\\IEFAIL.TXT" : "C:\\GOPLAB\\IEDONE.TXT", marker, static_cast<DWORD>(strlen(marker)));
    CloseHandle(logFile);
    return marked ? code : 32;
}
