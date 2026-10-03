/* SPDX-License-Identifier: GPL-2.0-only -- original explicit Core clock client. */
#ifndef NTW_CORE_CLOCK_HOST
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#endif
#include "core_clock.h"
#include "../ntwrapper/vxd/bridge.h"

static int enter(struct ntw_core_clock_client *client)
{
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&client->admitted, &expected, 1, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}
static void leave(struct ntw_core_clock_client *client)
{ __atomic_store_n(&client->admitted, 0, __ATOMIC_RELEASE); }
static int valid_output(const int64_t *p)
{
    uintptr_t address = (uintptr_t)p;
    return p && !(address & 3u) && address <= UINTPTR_MAX - sizeof(*p);
}
static int ops_valid(const struct ntw_core_clock_ops *ops)
{ return ops && ops->open && ops->query && ops->close && ops->writable; }

static uint32_t drain(struct ntw_core_clock_client *client)
{
    uint32_t error;
    if (!client->held) return 0;
    error = client->retained_close(client->retained_opaque, client->retained);
    if (!error) {
        client->held = 0;
        client->retained_close = 0;
        client->retained_opaque = 0;
        client->retained = 0;
    }
    return error;
}
static void publish(int64_t *output, uint64_t value)
{
    unsigned char *destination = (unsigned char *)output;
    const unsigned char *source = (const unsigned char *)&value;
    /* Win32 LARGE_INTEGER permits four-byte alignment. Avoid a stricter
     * host int64_t alignment/aliasing requirement in this shared body. */
    for (unsigned i = 0; i < sizeof(value); ++i) destination[i] = source[i];
}

static uint32_t query(struct ntw_core_clock_client *client,
    const struct ntw_core_clock_ops *ops, int64_t *counter, int64_t *frequency, int allow_overlap)
{
    shz_clock_reply_t reply = { 0, 0, 0, 0, 0, 0 };
    uintptr_t handle = 0;
    uint32_t error, close_error, returned = 0;
    if (!client || !valid_output(counter) || (frequency && !valid_output(frequency)) ||
        (!allow_overlap && frequency && (uintptr_t)counter < (uintptr_t)frequency + sizeof(*frequency) &&
         (uintptr_t)frequency < (uintptr_t)counter + sizeof(*counter)))
        return NTWV_ERROR_INVALID_PARAMETER;
    if (!ops_valid(ops)) return NTWV_ERROR_NOT_SUPPORTED;
    if (__atomic_load_n(&client->stopped, __ATOMIC_ACQUIRE)) return NTWV_ERROR_NOT_READY;
    if (!enter(client)) return NTWV_ERROR_BUSY;
    if (__atomic_load_n(&client->stopped, __ATOMIC_ACQUIRE)) {
        leave(client);
        return NTWV_ERROR_NOT_READY;
    }
    error = ops->writable(ops->opaque, counter);
    if (!error && frequency) error = ops->writable(ops->opaque, frequency);
    if (error) { leave(client); return error; }
    error = drain(client);
    if (error) { leave(client); return error; }
    error = ops->open(ops->opaque, &handle);
    if (error) { leave(client); return error; }
    error = ops->query(ops->opaque, handle, &reply, &returned);
    if (!error && (returned != sizeof(reply) || reply.size != sizeof(reply) ||
        reply.magic != SHZ_CLOCK_MAGIC || reply.version != SHZ_CLOCK_VERSION ||
        reply.reserved || reply.frequency != SHZ_CLOCK_FREQUENCY ||
        reply.counter > (uint64_t)INT64_MAX))
        error = NTWV_ERROR_REVISION_MISMATCH;
    /* Capture transport failure first; cleanup cannot overwrite its cause. */
    close_error = ops->close(ops->opaque, handle);
    if (close_error) {
        client->held = 1;
        client->retained = handle;
        client->retained_opaque = ops->opaque;
        client->retained_close = ops->close;
    }
    if (!error) error = close_error;
    if (!error) error = ops->writable(ops->opaque, counter);
    if (!error && frequency) error = ops->writable(ops->opaque, frequency);
    if (!error) {
        publish(counter, reply.counter);
        if (frequency) publish(frequency, reply.frequency);
    }
    leave(client);
    return error;
}
uint32_t ntw_core_clock_query(struct ntw_core_clock_client *client,
    const struct ntw_core_clock_ops *ops, int64_t *counter, int64_t *frequency)
{ return query(client, ops, counter, frequency, 0); }

static int32_t ntstatus(uint32_t error)
{
    switch (error) {
    case 0: return 0;
    case NTWV_ERROR_INVALID_PARAMETER: return (int32_t)0xc000000du;
    case NTWV_ERROR_NOACCESS: return (int32_t)0xc0000005u;
    case 5: return (int32_t)0xc0000022u;
    case NTWV_ERROR_NOT_SUPPORTED: return (int32_t)0xc00000bbu;
    case NTWV_ERROR_REVISION_MISMATCH: return (int32_t)0xc0000059u;
    case NTWV_ERROR_NOT_READY: return (int32_t)0xc00000a3u;
    case NTWV_ERROR_BUSY: return (int32_t)0xc000009eu;
    default: return (int32_t)0xc0000185u; /* STATUS_IO_DEVICE_ERROR */
    }
}
int32_t ntw_core_clock_ntquery(struct ntw_core_clock_client *client,
    const struct ntw_core_clock_ops *ops, int64_t *counter, int64_t *frequency)
{ return ntstatus(query(client, ops, counter, frequency, 1)); }

uint32_t ntw_core_clock_stop(struct ntw_core_clock_client *client)
{
    uint32_t error = 0;
    if (!client) return NTWV_ERROR_INVALID_PARAMETER;
    __atomic_store_n(&client->stopped, 1, __ATOMIC_RELEASE);
    if (!enter(client)) return NTWV_ERROR_BUSY;
    error = drain(client);
    leave(client);
    return error;
}

#ifndef NTW_CORE_CLOCK_HOST
#include <windows.h>
#ifndef NTW_CORE_CLOCK_NATIVE_TEST
_Static_assert(sizeof(void *) == 4, "native Core clock is PE32");
#endif
_Static_assert(sizeof(LARGE_INTEGER) == sizeof(int64_t), "native counter ABI");
static struct ntw_core_clock_client native_client;
static uint32_t actual_error(void)
{
    DWORD error = GetLastError();
    return error ? error : NTWV_ERROR_GEN_FAILURE;
}
static uint32_t native_open(void *opaque, uintptr_t *handle)
{
    HANDLE device;
    (void)opaque;
    device = CreateFileA("\\\\.\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING,
                         FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (device == INVALID_HANDLE_VALUE) return actual_error();
    *handle = (uintptr_t)device;
    return 0;
}
static uint32_t native_query(void *opaque, uintptr_t handle, shz_clock_reply_t *reply,
                             uint32_t *returned)
{
    DWORD bytes = 0;
    (void)opaque;
    if (!DeviceIoControl((HANDLE)handle, NTWV_IOCTL_CLOCK, NULL, 0,
                         reply, sizeof(*reply), &bytes, NULL)) return actual_error();
    *returned = bytes;
    return 0;
}
static uint32_t native_close(void *opaque, uintptr_t handle)
{
    (void)opaque;
    return CloseHandle((HANDLE)handle) ? 0 : actual_error();
}
static uint32_t native_writable(void *opaque, const int64_t *output)
{
    uintptr_t cursor = (uintptr_t)output, end = cursor + sizeof(*output);
    (void)opaque;
    /* These API pointers stay local. Check committed writable memory both
     * before transport and before publication. As for ordinary Win32 output
     * arguments, the caller must keep the range alive until the call returns. */
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info;
        uintptr_t region_end;
        DWORD access;
        if (VirtualQuery((const void *)cursor, &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return NTWV_ERROR_NOACCESS;
        access = info.Protect & 0xffu;
        if (access != PAGE_READWRITE && access != PAGE_WRITECOPY &&
            access != PAGE_EXECUTE_READWRITE && access != PAGE_EXECUTE_WRITECOPY)
            return NTWV_ERROR_NOACCESS;
        if (info.RegionSize > UINTPTR_MAX - (uintptr_t)info.BaseAddress)
            return NTWV_ERROR_NOACCESS;
        region_end = (uintptr_t)info.BaseAddress + info.RegionSize;
        if ((uintptr_t)info.BaseAddress > cursor || region_end <= cursor)
            return NTWV_ERROR_NOACCESS;
        cursor = region_end < end ? region_end : end;
    }
    return 0;
}
static const struct ntw_core_clock_ops native_ops = {
    0, native_open, native_query, native_close, native_writable
};
BOOL WINAPI NtwQueryCoreClock(PLARGE_INTEGER counter, PLARGE_INTEGER frequency)
{
    DWORD saved = GetLastError();
    uint32_t error = ntw_core_clock_query(&native_client, &native_ops,
        (int64_t *)(void *)counter, (int64_t *)(void *)frequency);
    if (error) { SetLastError(error); return FALSE; }
    SetLastError(saved);
    return TRUE;
}
/* Direct provider export: an NTDLL-level contract, never a KERNEL32 route. */
LONG WINAPI NtwNtQueryPerformanceCounter(PLARGE_INTEGER counter, PLARGE_INTEGER frequency)
{
    DWORD saved = GetLastError();
    int32_t status = ntw_core_clock_ntquery(&native_client, &native_ops,
        (int64_t *)(void *)counter, (int64_t *)(void *)frequency);
    SetLastError(saved);
    return status;
}
void ntw_core_clock_native_stop(void)
{
    __atomic_store_n(&native_client.stopped, 1, __ATOMIC_RELEASE);
}
BOOL WINAPI NtwShutdownCoreClock(void)
{
    DWORD saved = GetLastError();
    uint32_t error = ntw_core_clock_stop(&native_client);
    if (error) { SetLastError(error); return FALSE; }
    SetLastError(saved);
    return TRUE;
}
#endif
