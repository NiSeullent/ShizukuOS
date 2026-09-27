/* SPDX-License-Identifier: GPL-2.0-only -- original Windows 98 guest probe.
 * Run beside NTWRAP9X.VXD in a disposable Windows 98 guest, never on the host.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "bridge.h"

static HANDLE log_file, device = INVALID_HANDLE_VALUE;
static DWORD cycle;

static void record(const char *message, DWORD error)
{
    char line[160];
    static const char hex[] = "0123456789abcdef";
    DWORD length = 0, written, i;
    while (*message && length < sizeof(line) - 16)
        line[length++] = *message++;
    line[length++] = ' ';
    line[length++] = '0';
    line[length++] = 'x';
    for (i = 0; i < 8; ++i)
        line[length++] = hex[(error >> (28 - i * 4)) & 15];
    line[length++] = '\r';
    line[length++] = '\n';
    if (!WriteFile(log_file, line, length, &written, NULL) || written != length)
        ExitProcess(3);
    if (!FlushFileBuffers(log_file))
        ExitProcess(4);
}

static void failed(const char *stage, DWORD error)
{
    record(stage, error);
    if (device != INVALID_HANDLE_VALUE)
        CloseHandle(device);
    CloseHandle(log_file);
    ExitProcess(1);
}

static void rejected(DWORD code, void *input, DWORD input_size,
                     void *output, DWORD output_size, DWORD expected)
{
    DWORD returned = 0xa5a5a5a5, error;
    BOOL success = DeviceIoControl(device, code, input, input_size,
                                  output, output_size, &returned, NULL);
    error = GetLastError();
    if (success || error != expected)
        failed("FAIL rejection", success ? 0 : error);
}

void mainCRTStartup(void)
{
    struct ntwv_query reply;
    DWORD returned;
    log_file = CreateFileA("NTWQUERY.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_file == INVALID_HANDLE_VALUE)
        ExitProcess(2);
    record("START NTWrapper9x native VxD query ABI", 1);
    for (cycle = 0; cycle < 2; ++cycle) {
        record("BEGIN load cycle", cycle + 1);
        device = CreateFileA("\\\\.\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING,
                             FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (device == INVALID_HANDLE_VALUE)
            failed("FAIL CreateFile NTWRAP9X.VXD", GetLastError());
        record("PASS dynamic load/open", cycle + 1);
        returned = 0;
        if (!DeviceIoControl(device, NTWV_IOCTL_QUERY, NULL, 0,
                             &reply, sizeof(reply), &returned, NULL))
            failed("FAIL version query", GetLastError());
        if (returned != sizeof(reply) || reply.magic != NTWV_QUERY_MAGIC ||
            reply.size != sizeof(reply) || reply.abi != 1 ||
            reply.core_abi != NTW_ABI_VERSION || reply.max_objects != NTW_MAX_OBJECTS ||
            reply.features != 1 || reply.initialized != 1 || reply.selftest != 1)
            failed("FAIL query payload", returned);
        record("PASS version/core initialization/event selftest", reply.core_abi);
        rejected(NTWV_IOCTL_QUERY + 1, NULL, 0, &reply, sizeof(reply),
                 NTWV_ERROR_NOT_SUPPORTED);
        rejected(NTWV_IOCTL_QUERY, NULL, 0, &reply, sizeof(reply) - 1,
                 NTWV_ERROR_INSUFFICIENT_BUFFER);
        rejected(NTWV_IOCTL_QUERY, &cycle, sizeof(cycle), &reply, sizeof(reply),
                 NTWV_ERROR_INVALID_PARAMETER);
        record("PASS unknown/short/input request errors", 3);
        if (!CloseHandle(device))
            failed("FAIL CloseHandle", GetLastError());
        device = INVALID_HANDLE_VALUE;
        record("PASS close/unload request", cycle + 1);
    }
    record("PASS: NTWrapper9x native VxD probe", 0);
    CloseHandle(log_file);
    ExitProcess(0);
}
