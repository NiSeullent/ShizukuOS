/* Closed-handle Win9x checkpoint/abort diagnostics; engine behavior is retained.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 */
#ifndef IEWK_CORE_WIN9X_DIAGNOSTIC_LOG_H
#define IEWK_CORE_WIN9X_DIAGNOSTIC_LOG_H
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdint>

static volatile LONG iewkDiagnosticMainPhase;
static volatile LONG iewkDiagnosticWorkerPhase;
static volatile LONG iewkDiagnosticAbortEntered;
static char iewkDiagnosticNonce[81];

static bool iewkClosedWrite(HANDLE handle, const char* data, DWORD count)
{
    DWORD written = 0;
    bool succeeded = WriteFile(handle, data, count, &written, nullptr)
        && written == count;
    if (succeeded)
        succeeded = !!FlushFileBuffers(handle);
    bool closed = !!CloseHandle(handle);
    return succeeded && closed;
}

class IEWKDiagnosticLog {
public:
    explicit IEWKDiagnosticLog(const char* path) : m_path(path)
    {
        if (!path || !*path || std::strlen(path) >= MAX_PATH)
            return;
        HANDLE handle = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle != INVALID_HANDLE_VALUE)
            m_good = !!CloseHandle(handle);
    }
    bool good() const { return m_good; }
    int printf(const char* format, ...)
    {
        if (!m_good)
            return -1;
        char buffer[2048];
        va_list arguments;
        va_start(arguments, format);
        int count = std::vsnprintf(buffer, sizeof(buffer), format, arguments);
        va_end(arguments);
        if (count < 0 || static_cast<size_t>(count) >= sizeof(buffer)) {
            m_good = false;
            return -1;
        }
        HANDLE handle = CreateFileA(m_path, GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            m_good = false;
            return -1;
        }
        SetLastError(0);
        DWORD offset = SetFilePointer(handle, 0, nullptr, FILE_END);
        if (offset == INVALID_SET_FILE_POINTER && GetLastError()) {
            CloseHandle(handle);
            m_good = false;
            return -1;
        }
        m_good = iewkClosedWrite(handle, buffer, static_cast<DWORD>(count));
        return m_good ? count : -1;
    }
private:
    const char* m_path;
    bool m_good { false };
};

static char* iewkDiagnosticLiteral(char* output, const char* value)
{
    while (*value)
        *output++ = *value++;
    return output;
}
static char* iewkDiagnosticHex(char* output, uintptr_t value)
{
    const char digits[] = "0123456789abcdef";
    for (unsigned shift = 32; shift; shift -= 4)
        *output++ = digits[(value >> (shift - 4)) & 15];
    return output;
}

/* No heap, stdio, recursive formatting, or exception processing in this path.
 * This records only abort calls that GNU --wrap actually redirects; it does
 * not intercept independent aborts internal to a loaded system CRT DLL.
 */
static void iewkDiagnosticAbortRecord(const void* returnAddress)
{
    if (InterlockedCompareExchange(&iewkDiagnosticAbortEntered, 1, 0))
        return;
    char buffer[512];
    char* cursor = buffer;
    cursor = iewkDiagnosticLiteral(cursor, "scope=GNU-wrapped-direct-abort\r\nnonce=");
    cursor = iewkDiagnosticLiteral(cursor, iewkDiagnosticNonce[0] ? iewkDiagnosticNonce : "UNAVAILABLE-BEFORE-MAIN");
    cursor = iewkDiagnosticLiteral(cursor, "\r\nabort.wrapper=1\r\nabort.return-pc=0x");
    cursor = iewkDiagnosticHex(cursor, reinterpret_cast<uintptr_t>(returnAddress));
    cursor = iewkDiagnosticLiteral(cursor, "\r\nabort.image-base=0x");
    cursor = iewkDiagnosticHex(cursor, reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)));
    cursor = iewkDiagnosticLiteral(cursor, "\r\nabort.thread-id=0x");
    cursor = iewkDiagnosticHex(cursor, GetCurrentThreadId());
    cursor = iewkDiagnosticLiteral(cursor, "\r\nabort.main-phase=0x");
    cursor = iewkDiagnosticHex(cursor, static_cast<uintptr_t>(InterlockedCompareExchange(&iewkDiagnosticMainPhase, 0, 0)));
    cursor = iewkDiagnosticLiteral(cursor, "\r\nabort.worker-phase=0x");
    cursor = iewkDiagnosticHex(cursor, static_cast<uintptr_t>(InterlockedCompareExchange(&iewkDiagnosticWorkerPhase, 0, 0)));
    cursor = iewkDiagnosticLiteral(cursor, "\r\n");
    HANDLE handle = CreateFileA("C:\\GOPLAB\\WTFABRT.LOG", GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE)
        iewkClosedWrite(handle, buffer, static_cast<DWORD>(cursor - buffer));
}
#endif
