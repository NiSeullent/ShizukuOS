/* SPDX-License-Identifier: GPL-2.0-only
 * Real main/IPC consumers of the native handoff. Privileged instructions and
 * scheduling are host boundaries; channel mapping, headers, rings and replies
 * are the production implementations. This does not execute a guest.
 */
#define main existing_ipc_host_main
#include "test_ipc_host.c"
#undef main
#include "../../boot_profile/win98_foundation.h"

static jmp_buf main_return;
static shz_bootinfo_t active_bootinfo;
static thread_t server_thread;
static unsigned exit_code, arch_calls, memory_calls, scheduler_calls;
static unsigned thread_calls, timer_calls, owner_queries, main_sleeps;
static unsigned qa_calls, reports, expect_persistent;

static void host_arch_init(void) { ++arch_calls; }
static void host_mem_init(const shz_bootinfo_t *bi)
{
    CHECK(bi == &active_bootinfo);
    ++memory_calls;
}
static void host_sched_init(void) { ++scheduler_calls; }
static void host_sti(void) { }
static long host_timer_set(unsigned vector, uint32_t period)
{
    CHECK(vector == VEC_TIMER && period == TICK_US);
    ++timer_calls;
    return SHZ_OK;
}
static thread_t *host_thread_create(const char *name, void (*fn)(void *), void *arg)
{
    CHECK(!strcmp(name, "ipc-server") && fn == ipc_server_thread && arg == NULL);
    ++thread_calls;
    return &server_thread;
}
static void endpoint_session_end(void)
{
    shz_msg_hdr_t h;
    enqueue(OP_SESSION_END, NULL, 0);
    run_passes(1);
    h = receive_reply(NULL, 0);
    CHECK(h.opcode == OP_SESSION_END && h.request_id == 1 && h.payload_length == 0);
    CHECK(h.status == (expect_persistent ? SHZ_E_UNSUPPORTED : SHZ_OK));
    CHECK(ipc_session_end == !expect_persistent);
    CHECK(ipc_requests_served() == 1 && ipc_protocol_errors() == 0);
}
static long host_owner_state(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value)
{
    CHECK(op == SHZ_HC_DOMAIN_STATE && a == SHZ_DOM_WIN98 && b == 0 && value);
    CHECK(expect_persistent && qa_calls == 0 && reports == 0);
    if (++owner_queries == 1) {
        endpoint_session_end();
        *value = SHZ_DS_RUNNABLE;
    } else {
        CHECK(owner_queries == 2);
        *value = SHZ_DS_EXITED;
    }
    return SHZ_OK;
}
static void host_main_sleep(uint32_t ms)
{
    CHECK(ms == (expect_persistent ? 100u : 20u));
    ++main_sleeps;
}
static void host_qa_tests(const shz_bootinfo_t *bi)
{
    CHECK(bi == &active_bootinfo && !expect_persistent);
    ++qa_calls;
    endpoint_session_end();
}
static void host_main_exit(unsigned code) __attribute__((noreturn));
static void host_main_exit(unsigned code)
{
    exit_code = code;
    longjmp(main_return, 1);
}
void kprintf(const char *fmt, ...) { (void)fmt; }
void report_final(void) { ++reports; }
unsigned tests_failed(void) { return 0; }

#define arch_init host_arch_init
#define mem_init host_mem_init
#define sched_init host_sched_init
#define sti host_sti
#define shz_timer_set host_timer_set
#define thread_create host_thread_create
#define shz_hcall host_owner_state
#define thread_sleep_ms host_main_sleep
#define run_self_tests host_qa_tests
#define shz_exit host_main_exit
#include "../main.c"
#undef arch_init
#undef mem_init
#undef sched_init
#undef sti
#undef shz_timer_set
#undef thread_create
#undef shz_hcall
#undef thread_sleep_ms
#undef run_self_tests
#undef shz_exit

static void native_handoff(const char *command)
{
    size_t length = strlen(command);
    CHECK(length < SHZ_CMDLINE_MAX);
    channel_bytes = SHZ_IPC_REGION_SIZE;
    channel_memory = mmap((void *)(uintptr_t)SHZ_IPC_GPA_BASE, channel_bytes,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(channel_memory == (void *)(uintptr_t)SHZ_IPC_GPA_BASE);
    CHECK(shz_channel_init(channel_memory, channel_bytes, 0,
                          SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64, 8, 7) == SHZ_OK);
    memset(&active_bootinfo, 0, sizeof active_bootinfo);
    active_bootinfo.magic = SHZ_BOOTINFO_MAGIC;
    active_bootinfo.abi_major = SHZ_ABI_MAJOR;
    active_bootinfo.abi_minor = SHZ_ABI_MINOR;
    active_bootinfo.size = sizeof active_bootinfo;
    active_bootinfo.domain_id = SHZ_DOM_KERNEL32;
    active_bootinfo.generation = 7;
    active_bootinfo.channel_count = 1;
    active_bootinfo.channel[0].gpa = SHZ_IPC_GPA_BASE;
    active_bootinfo.channel[0].size = SHZ_IPC_REGION_SIZE;
    active_bootinfo.channel[0].peer_domain = SHZ_DOM_KERNEL64;
    active_bootinfo.channel[0].channel_id = 0;
    memcpy(active_bootinfo.cmdline, command, length + 1);
    active_bootinfo.cmdline_size = (uint32_t)length;
    served = proto_errors = refused_buffers = stale_msgs = doorbells = ipc_session_end = 0;
    waits = yields = acks = notifications = sleep_calls = refill = 0;
    next_request = 1;
}

static void corrupt(const char *name)
{
    if (!strcmp(name, "bad-token")) {
        memcpy(active_bootinfo.cmdline, "shz.foundation=dos", 19);
        active_bootinfo.cmdline_size = 18;
    } else if (!strcmp(name, "conflict")) {
        static const char text[] = "shz.foundation=win98 shz.k32-service=win98";
        memcpy(active_bootinfo.cmdline, text, sizeof text);
        active_bootinfo.cmdline_size = sizeof text - 1;
    } else if (!strcmp(name, "partial-tail")) {
        active_bootinfo.size = offsetof(shz_bootinfo_t, cmdline) + 1;
    } else if (!strcmp(name, "generation")) active_bootinfo.generation = 0;
    else if (!strcmp(name, "flags")) active_bootinfo.flags = 1;
    else if (!strcmp(name, "missing-channel")) active_bootinfo.channel_count = 0;
    else if (!strcmp(name, "wrong-peer")) active_bootinfo.channel[0].peer_domain = SHZ_DOM_WIN98;
    else if (!strcmp(name, "wrong-gpa")) active_bootinfo.channel[0].gpa += SHZ_IPC_REGION_SIZE;
    else if (!strcmp(name, "minor")) active_bootinfo.abi_minor = 0;
    else { fprintf(stderr, "unknown corruption: %s\n", name); exit(2); }
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    signal(SIGALRM, deadline);
    if (!strncmp(argv[1], "existing-", 9)) {
        argv[1] += 9;
        return existing_ipc_host_main(argc, argv);
    }
    native_handoff("shz.foundation=win98");
    expect_persistent = 1;
    if (!strcmp(argv[1], "foundation-ipc")) {
        CHECK(shz_win98_foundation_policy(&active_bootinfo) == 1);
        ipc_init(&active_bootinfo);
        endpoint_session_end();
    } else {
        volatile unsigned want_exit = 0;
        if (!strcmp(argv[1], "legacy-main")) {
            memcpy(active_bootinfo.cmdline, K32_WIN98_SERVICE_CMDLINE,
                   sizeof K32_WIN98_SERVICE_CMDLINE);
            active_bootinfo.cmdline_size = sizeof K32_WIN98_SERVICE_CMDLINE - 1;
        } else if (!strcmp(argv[1], "qa-main") || !strcmp(argv[1], "abi10-main")) {
            memset(active_bootinfo.cmdline, 0, sizeof active_bootinfo.cmdline);
            active_bootinfo.cmdline_size = 0;
            expect_persistent = 0;
            if (!strcmp(argv[1], "abi10-main")) {
                active_bootinfo.size = 176;
                active_bootinfo.abi_minor = 0;
            }
        } else if (!strncmp(argv[1], "reject-main-", 12)) {
            corrupt(argv[1] + 12);
            want_exit = 97;
        } else if (!strncmp(argv[1], "reject-ipc-", 11)) {
            corrupt(argv[1] + 11);
            ipc_init(&active_bootinfo); /* Must panic before admission. */
            fprintf(stderr, "FAIL: malformed handoff admitted by actual ipc_init\n");
            return 2;
        } else CHECK(!strcmp(argv[1], "foundation-main"));
        alarm(2);
        if (!setjmp(main_return)) kmain(&active_bootinfo);
        alarm(0);
        CHECK(exit_code == want_exit);
        if (want_exit) {
            CHECK(arch_calls == 0 && memory_calls == 0 && scheduler_calls == 0 &&
                  timer_calls == 0 && thread_calls == 0 && notifications == 0);
        } else {
            CHECK(arch_calls == 1 && memory_calls == 1 && scheduler_calls == 1 &&
                  timer_calls == 1 && thread_calls == 1 && main_sleeps == 1);
            CHECK(owner_queries == (expect_persistent ? 2u : 0u));
            CHECK(qa_calls == !expect_persistent && reports == !expect_persistent);
        }
    }
    CHECK(munmap(channel_memory, channel_bytes) == 0);
    printf("PASS %s: %lu real main/IPC/ring checks (privileged/scheduler boundaries modeled; no guest)\n",
           argv[1], checks);
    return 0;
}
