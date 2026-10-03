/* SPDX-License-Identifier: GPL-2.0-only -- production clock fault controls. */
#include "../core_clock.h"
#include "../../ntwrapper/vxd/bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifdef NTW_CORE_CLOCK_NATIVE_TEST
#include <windows.h>
#endif
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while (0)
static _Atomic unsigned checks;
struct mock {
    struct ntw_core_clock_client client;
    struct ntw_core_clock_ops ops;
    unsigned opens, queries, closes, validates, samples, held, reenter;
    uintptr_t handle;
    uint32_t open_error, query_error, close_error, validate_failure;
    shz_clock_reply_t reply;
    uint32_t returned;
};
static uint32_t open_device(void *opaque, uintptr_t *handle)
{
    struct mock *m = opaque;
    ++m->opens;
    CHECK(!m->held);
    if (m->open_error) return m->open_error;
    *handle = m->handle; m->held = 1; return 0;
}
static uint32_t query_device(void *opaque, uintptr_t handle, shz_clock_reply_t *reply,
                             uint32_t *returned)
{
    struct mock *m = opaque;
    ++m->queries;
    CHECK(m->held && handle == m->handle);
    if (m->reenter) {
        int64_t nested = 42;
        CHECK(ntw_core_clock_query(&m->client, &m->ops, &nested, NULL) == NTWV_ERROR_BUSY);
        CHECK(nested == 42 && m->opens == 1);
    }
    *reply = m->reply; *returned = m->returned;
    return m->query_error;
}
static uint32_t close_device(void *opaque, uintptr_t handle)
{
    struct mock *m = opaque;
    ++m->closes;
    CHECK(m->held && handle == m->handle);
    if (m->close_error) return m->close_error;
    m->held = 0; return 0;
}
static uint32_t writable(void *opaque, const int64_t *output)
{
    struct mock *m = opaque;
    CHECK(output != NULL);
    return ++m->validates == m->validate_failure ? NTWV_ERROR_NOACCESS : 0;
}
static void init(struct mock *m)
{
    memset(m, 0, sizeof(*m));
    m->handle = 0x1234;
    m->ops = (struct ntw_core_clock_ops){m, open_device, query_device, close_device, writable};
    m->reply = (shz_clock_reply_t){SHZ_CLOCK_MAGIC, sizeof(shz_clock_reply_t),
        SHZ_CLOCK_VERSION, 0, UINT64_C(0x100000007), SHZ_CLOCK_FREQUENCY};
    m->returned = sizeof(shz_clock_reply_t);
}
static int32_t sample(void *opaque, uint64_t *value)
{
    struct mock *m = opaque;
    ++m->samples; *value = m->reply.counter; return (int32_t)m->query_error;
}
static void test_numeric(void)
{
    struct mock m;
    uint64_t low, high, ns;
    init(&m); low = 12; high = 34;
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION + 1u, 0, sample, &m, &low, &high) == SHZ_E_UNSUPPORTED);
    CHECK(!m.samples && low == 12 && high == 34);
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 1, sample, &m, &low, &high) == SHZ_E_INVALID);
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 0, sample, &m, &low, &low) == SHZ_E_INVALID);
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 0, NULL, &m, &low, &high) == SHZ_E_INVALID);
    CHECK(!m.samples);
    m.reply.counter = UINT64_C(0xffffffff);
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 0, sample, &m, &low, &high) == SHZ_OK);
    CHECK(low == UINT32_MAX && high == 0 && m.samples == 1);
    m.reply.counter = UINT64_C(0x100000001);
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 0, sample, &m, &low, &high) == SHZ_OK);
    CHECK(low == 1 && high == 1 && m.samples == 2);
    low = 12; high = 34; m.query_error = (uint32_t)SHZ_E_DENIED;
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 0, sample, &m, &low, &high) == SHZ_E_DENIED);
    CHECK(low == 12 && high == 34 && m.samples == 3);
    m.query_error = 0; m.reply.counter = UINT64_C(0x8000000000000000);
    CHECK(shz_clock_split(SHZ_CLOCK_VERSION, 0, sample, &m, &low, &high) == SHZ_E_RANGE);
    CHECK(low == 12 && high == 34);
    ns = 42;
    CHECK(shz_clock_ticks_ns(1, 0, &ns) == SHZ_E_INVALID && ns == 42);
    CHECK(shz_clock_ticks_ns(1, 1, NULL) == SHZ_E_INVALID);
    CHECK(shz_clock_ticks_ns(1, UINT64_MAX, &ns) == SHZ_E_RANGE && ns == 42);
    CHECK(shz_clock_ticks_ns(UINT64_MAX, 1, &ns) == SHZ_E_RANGE && ns == 42);
    CHECK(shz_clock_ticks_ns(4294967297ULL, SHZ_CLOCK_FREQUENCY, &ns) == SHZ_OK);
    CHECK(ns == 4294967297ULL);
    CHECK(shz_clock_ticks_ns(15, 10, &ns) == SHZ_OK && ns == 1500000000ULL);
    CHECK(shz_clock_ticks_ns(1, 3, &ns) == SHZ_OK && ns == 333333333ULL);
    CHECK(shz_clock_ticks_ns(INT64_MAX, SHZ_CLOCK_FREQUENCY, &ns) == SHZ_OK && ns == INT64_MAX);
    CHECK(shz_clock_ticks_ns((uint64_t)INT64_MAX+1, SHZ_CLOCK_FREQUENCY, &ns) == SHZ_E_RANGE && ns == INT64_MAX);
    CHECK(SHZ_HC_TIME == 6 && SHZ_HC_NATIVE_GOP_EPOCH == 14 && SHZ_HC_CLOCK_SPLIT == 15);
    CHECK(NTWV_IOCTL_CLOCK != NTWV_IOCTL_QUERY + 1u);
}
static void test_validation(void)
{
    struct mock m;
    int64_t c = 42, f = 43;
    _Alignas(8) uint8_t unaligned[24];
    init(&m);
    CHECK(ntw_core_clock_query(NULL, &m.ops, &c, &f) == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, NULL, &f) == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &c) == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, (int64_t *)(uintptr_t)(UINTPTR_MAX - 3u), &f) == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, (int64_t *)(void *)(unaligned + 1), &f) == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntw_core_clock_query(&m.client, NULL, &c, &f) == NTWV_ERROR_NOT_SUPPORTED);
    CHECK(!m.opens && c == 42 && f == 43);
    for (unsigned at = 1; at <= 4; ++at) {
        init(&m); m.validate_failure = at;
        CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == NTWV_ERROR_NOACCESS);
        CHECK(c == 42 && f == 43 && !m.held);
        CHECK(m.opens == (at <= 2 ? 0u : 1u));
    }
    for (unsigned at = 0; at < 8; ++at) {
        init(&m);
        if (at == 0) m.returned--;
        if (at == 1) m.reply.size--;
        if (at == 2) m.reply.magic ^= 1;
        if (at == 3) m.reply.version++;
        if (at == 4) m.reply.reserved = 1;
        if (at == 5) m.reply.frequency = 0;
        if (at == 6) m.reply.frequency--;
        if (at == 7) m.reply.counter = UINT64_C(0x8000000000000000);
        CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == NTWV_ERROR_REVISION_MISMATCH);
        CHECK(c == 42 && f == 43 && m.closes == 1 && !m.held);
    }
    init(&m); m.open_error = 2;
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == 2);
    CHECK(!m.queries && !m.closes && !m.held && c == 42 && f == 43);
    init(&m); m.query_error = 5;
    CHECK(ntw_core_clock_ntquery(&m.client, &m.ops, &c, &f) == (int32_t)0xc0000022u);
    CHECK(m.opens == 1 && m.queries == 1 && m.closes == 1 && !m.held);
    CHECK(c == 42 && f == 43);
    init(&m); m.reenter = 1;
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == 0);
    CHECK(c == (int64_t)m.reply.counter && f == 1000000000 && !m.held);
    init(&m); m.handle = 0;
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, NULL) == 0);
    CHECK(m.closes == 1 && !m.held);
    CHECK(ntw_core_clock_ntquery(&m.client, &m.ops, &c, &c) == 0 && c == 1000000000);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, (int64_t *)(void *)(unaligned + 4), NULL) == 0);
    memcpy(&c, unaligned + 4, sizeof(c)); CHECK(c == (int64_t)m.reply.counter);
    CHECK(ntw_core_clock_ntquery(&m.client, &m.ops, (int64_t *)(void *)unaligned,
                                (int64_t *)(void *)(unaligned + 4)) == 0);
    memcpy(&f, unaligned + 4, sizeof(f)); CHECK(f == 1000000000);
}
static void test_retention(void)
{
    struct mock m, next;
    int64_t c = 42, f = 43;
    init(&m); init(&next); m.query_error = 5; m.close_error = 6; m.handle = 0;
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == 5);
    CHECK(m.client.held && m.held && m.closes == 1 && c == 42 && f == 43);
    CHECK(ntw_core_clock_query(&m.client, &next.ops, &c, &f) == 6);
    CHECK(m.closes == 2 && next.opens == 0 && m.opens == 1);
    m.close_error = 0;
    CHECK(ntw_core_clock_query(&m.client, &next.ops, &c, &f) == 0);
    CHECK(m.closes == 3 && !m.held && next.opens == 1 && next.closes == 1 && !m.client.held);
    init(&m); m.close_error = 6; c = 42; f = 43;
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == 6);
    CHECK(c == 42 && f == 43 && m.client.held && m.held);
    CHECK(ntw_core_clock_stop(&m.client) == 6);
    CHECK(m.client.stopped && m.client.held && m.closes == 2);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &c, &f) == NTWV_ERROR_NOT_READY);
    CHECK(m.opens == 1 && m.closes == 2);
    m.close_error = 0;
    CHECK(ntw_core_clock_stop(&m.client) == 0 && !m.client.held && !m.held);
    CHECK(ntw_core_clock_stop(&m.client) == 0 && m.closes == 3);
}
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static unsigned in_query, release_query;
static uint32_t thread_result;
static int64_t thread_count;
static uint32_t blocked_query(void *opaque, uintptr_t handle, shz_clock_reply_t *reply, uint32_t *returned)
{
    pthread_mutex_lock(&mutex);
    in_query = 1; pthread_cond_broadcast(&condition);
    while (!release_query) pthread_cond_wait(&condition, &mutex);
    pthread_mutex_unlock(&mutex);
    return query_device(opaque, handle, reply, returned);
}
static void *thread_entry(void *opaque)
{
    struct mock *m = opaque;
    thread_result = ntw_core_clock_query(&m->client, &m->ops, &thread_count, NULL);
    return NULL;
}
static void test_stop_inflight(void)
{
    struct mock m;
    pthread_t thread;
    init(&m); m.ops.query = blocked_query; thread_count = 42;
    CHECK(pthread_create(&thread, NULL, thread_entry, &m) == 0);
    pthread_mutex_lock(&mutex);
    while (!in_query) pthread_cond_wait(&condition, &mutex);
    CHECK(ntw_core_clock_stop(&m.client) == NTWV_ERROR_BUSY);
    /* The stopped API refuses before callbacks: no mutable mock access races. */
    CHECK(m.client.stopped && m.client.admitted);
    unsigned validates = m.validates;
    int64_t refused = 77;
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &refused, NULL) == NTWV_ERROR_NOT_READY);
    CHECK(m.validates == validates && refused == 77);
    release_query = 1; pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&mutex);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(thread_result == 0 && thread_count == (int64_t)m.reply.counter);
    CHECK(m.opens == 1 && m.closes == 1 && !m.held && !m.client.admitted);
    CHECK(ntw_core_clock_query(&m.client, &m.ops, &thread_count, NULL) == NTWV_ERROR_NOT_READY);
    CHECK(m.opens == 1 && m.closes == 1);
}
#ifdef NTW_CORE_CLOCK_NATIVE_TEST
BOOL WINAPI NtwQueryCoreClock(PLARGE_INTEGER, PLARGE_INTEGER);
LONG WINAPI NtwNtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
BOOL WINAPI NtwShutdownCoreClock(void);
static DWORD last_error, native_open_error, native_query_error, native_close_error;
static DWORD map_protection = PAGE_READWRITE, map_state = MEM_COMMIT;
static unsigned native_opens, native_queries, native_closes, probes;
static unsigned query_revokes, broken_map, map_quantum = 4096;
static uintptr_t native_handle = 17;
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD error) { last_error = error; }
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *security,
                   DWORD disposition,DWORD flags,HANDLE template_file)
{
    CHECK(!strcmp(path,"\\\\.\\NTWRAP9X.VXD") && !access && !share && !security &&
          disposition==OPEN_EXISTING && flags==FILE_FLAG_DELETE_ON_CLOSE && !template_file);
    ++native_opens; last_error=native_open_error ? native_open_error : 71;
    return native_open_error ? INVALID_HANDLE_VALUE : (HANDLE)native_handle;
}
BOOL DeviceIoControl(HANDLE handle,DWORD code,void *input,DWORD input_bytes,
                     void *output,DWORD output_bytes,DWORD *returned,void *overlapped)
{
    shz_clock_reply_t reply={SHZ_CLOCK_MAGIC,32,SHZ_CLOCK_VERSION,0,UINT64_C(0x2345678900000001),SHZ_CLOCK_FREQUENCY};
    CHECK((uintptr_t)handle==native_handle && code==NTWV_IOCTL_CLOCK && !input && !input_bytes &&
          output && output_bytes==32 && returned && !overlapped);
    ++native_queries; last_error=native_query_error ? native_query_error : 72;
    if(native_query_error) return FALSE;
    if(query_revokes) map_protection=PAGE_NOACCESS;
    memcpy(output,&reply,sizeof(reply));*returned=32;return TRUE;
}
BOOL CloseHandle(HANDLE handle)
{ CHECK((uintptr_t)handle==native_handle);++native_closes;last_error=native_close_error ? native_close_error : 73;return !native_close_error; }
SIZE_T VirtualQuery(const void *address,MEMORY_BASIC_INFORMATION *info,SIZE_T bytes)
{
    ++probes;CHECK(bytes==sizeof(*info));
    info->BaseAddress=(void *)((uintptr_t)address & ~((uintptr_t)map_quantum-1));
    info->RegionSize=map_quantum;info->State=map_state;info->Protect=map_protection;
    if(broken_map==1) return 0;
    if(broken_map==2) info->RegionSize=0;
    if(broken_map==3) info->RegionSize=UINTPTR_MAX;
    last_error=74;return sizeof(*info);
}
void OutputDebugStringA(const char *message) { CHECK(message != NULL); }
static void native_wrappers(void)
{
    LARGE_INTEGER c,f;
    unsigned before;
    static const DWORD writable_modes[]={PAGE_READWRITE,PAGE_WRITECOPY,PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY};
    c.QuadPart=-1;f.QuadPart=-2;last_error=0x5a5a;
    CHECK(NtwQueryCoreClock(&c,&f) && last_error==0x5a5a && f.QuadPart==1000000000);
    CHECK(c.QuadPart==INT64_C(0x2345678900000001) && native_opens==1 && native_queries==1 && native_closes==1);
    last_error=0x5a5b;CHECK(NtwNtQueryPerformanceCounter(&c,NULL)==0 && last_error==0x5a5b);
    last_error=0x5a5c;CHECK(NtwNtQueryPerformanceCounter(&c,&c)==0 && c.QuadPart==1000000000 && last_error==0x5a5c);
    c.QuadPart=-1;f.QuadPart=-2;last_error=0x5a5d;before=native_opens;
    CHECK((uint32_t)NtwNtQueryPerformanceCounter(NULL,&f)==0xc000000du && last_error==0x5a5d && f.QuadPart==-2 && native_opens==before);
    CHECK(!NtwQueryCoreClock(NULL,&f) && last_error==87 && f.QuadPart==-2 && native_opens==before);
    for(unsigned at=0;at<4;++at){
        map_protection=writable_modes[at];map_quantum=4;before=probes;
        last_error=0x5a5e;CHECK(NtwQueryCoreClock(&c,NULL) && last_error==0x5a5e && probes-before==4);
    }
    map_quantum=4096;c.QuadPart=-1;f.QuadPart=-2;
    for(unsigned at=0;at<6;++at){
        before=native_opens;map_protection=PAGE_READWRITE;map_state=MEM_COMMIT;broken_map=0;
        if(at==0) map_protection=PAGE_READONLY;
        if(at==1) map_protection=PAGE_READWRITE|PAGE_GUARD;
        if(at==2) map_state=0;
        if(at>=3) broken_map=at-2;
        last_error=0x5a5f;CHECK((uint32_t)NtwNtQueryPerformanceCounter(&c,&f)==0xc0000005u && last_error==0x5a5f);
        CHECK(c.QuadPart==-1 && f.QuadPart==-2 && native_opens==before);
    }
    broken_map=0;map_state=MEM_COMMIT;map_protection=PAGE_READWRITE;query_revokes=1;
    before=native_closes;CHECK(!NtwQueryCoreClock(&c,&f) && last_error==998 && native_closes==before+1);
    CHECK(c.QuadPart==-1 && f.QuadPart==-2);query_revokes=0;map_protection=PAGE_READWRITE;
    native_handle=0;native_query_error=5;native_close_error=31;
    CHECK(!NtwQueryCoreClock(&c,&f) && last_error==5 && c.QuadPart==-1 && f.QuadPart==-2);
    before=native_opens;last_error=0x5a60;
    CHECK((uint32_t)NtwNtQueryPerformanceCounter(&c,&f)==0xc0000185u && last_error==0x5a60 && native_opens==before);
    native_close_error=0;native_query_error=50;last_error=0x5a61;
    CHECK((uint32_t)NtwNtQueryPerformanceCounter(&c,&f)==0xc00000bbu && last_error==0x5a61 && c.QuadPart==-1 && f.QuadPart==-2);
    native_query_error=0;native_open_error=2;
    CHECK(!NtwQueryCoreClock(&c,&f) && last_error==2 && c.QuadPart==-1 && f.QuadPart==-2);
    native_open_error=0;native_close_error=31;
    CHECK(!NtwQueryCoreClock(&c,&f) && last_error==31 && c.QuadPart==-1 && f.QuadPart==-2);
    before=native_opens;unsigned closes=native_closes, saved_probes=probes;
    ntw_core_clock_native_stop();CHECK(native_opens==before && native_closes==closes);
    CHECK(!NtwQueryCoreClock(&c,&f) && last_error==21 && native_opens==before && native_closes==closes && probes==saved_probes);
    CHECK(!NtwShutdownCoreClock() && last_error==31 && native_closes==closes+1);
    CHECK((uint32_t)NtwNtQueryPerformanceCounter(&c,&f)==0xc00000a3u && last_error==31 && c.QuadPart==-1 && f.QuadPart==-2);
    native_close_error=0;last_error=0x5a62;
    CHECK(NtwShutdownCoreClock() && last_error==0x5a62 && native_closes==closes+2);
    CHECK(NtwShutdownCoreClock() && native_closes==closes+2);
    CHECK((uint32_t)NtwNtQueryPerformanceCounter(&c,&f)==0xc00000a3u && last_error==0x5a62 && native_opens==before);
}
#endif
int main(void)
{
    test_numeric(); test_validation(); test_retention(); test_stop_inflight();
#ifdef NTW_CORE_CLOCK_NATIVE_TEST
    native_wrappers();
#endif
    printf("PASS: Core clock %u assertions; production numeric/client, original leases, real threaded stop\n", checks);
    return 0;
}
