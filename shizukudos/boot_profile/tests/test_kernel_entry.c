/* SPDX-License-Identifier: GPL-2.0-only
 * Calls the actual production entry. Privileged operations and unavailable
 * runtime workers are boundary substitutes; this does not execute a VM.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(TEST_KERNEL32)
#include "../../kernel32/k32.h"
#elif defined(TEST_KERNEL64)
#include "../../kernel64/proc_internal.h"
#include "../../dead_screen/native.h"
#include "../../kernel64/fs.h"
#else
#error Select TEST_KERNEL32 or TEST_KERNEL64
#endif

static jmp_buf return_to_test;
static unsigned checks, exit_code, fixture_sequence;
static unsigned arch_calls, mem_calls, sched_calls, timer_calls, sti_calls, ipc_calls, ipc_sequence;
static unsigned service_calls, service_sequence, owner_calls;
static unsigned qa_calls, ntdrv_calls, setup_calls, autorun_calls, desktop_calls, control_calls, report_calls;
static unsigned fs_calls, archive_calls, random_calls, ds_calls, disk_calls, thread_calls;
#if defined(TEST_KERNEL64)
static unsigned bringup_prepare_calls, bringup_verify_calls, bringup_prepare_sequence, bringup_verify_sequence;
static uint64_t mock_read_cr3(void) { return 0x1000; }
#define read_cr3 mock_read_cr3
#endif
static uint64_t simulated_ms;
static uint32_t final_owner_state;
static long owner_hcall_status;
static shz_bootinfo_t fixture;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL line %u: %s (exit=%u simulated=%llu ms)\n", \
        (unsigned)__LINE__, #expression, exit_code, (unsigned long long)simulated_ms); exit(1); \
} } while (0)

static void mock_exit(unsigned code) __attribute__((noreturn));
static void mock_exit(unsigned code)
{
    exit_code = code;
    longjmp(return_to_test, 1);
}
static long mock_timer(unsigned vector, uint32_t period)
{
    CHECK(vector == VEC_TIMER && period == TICK_US);
    ++timer_calls; ++fixture_sequence;
    return SHZ_OK;
}
static void mock_sti(void) { ++sti_calls; ++fixture_sequence; }
long mock_hcall(hcreg_t opcode, hcreg_t domain, hcreg_t unused, hcreg_t *out)
{
    CHECK(opcode == SHZ_HC_DOMAIN_STATE && domain == SHZ_DOM_WIN98 && unused == 0 && out != NULL);
    ++owner_calls;
#if defined(TEST_KERNEL32)
    if (simulated_ms < 30000)
        *out = (simulated_ms / 100) & 1 ? SHZ_DS_WAITING : SHZ_DS_RUNNABLE;
    else
        *out = final_owner_state;
    return simulated_ms < 30000 ? SHZ_OK : owner_hcall_status;
#else
    CHECK(service_calls == 1 && ipc_calls == 1);
    *out = final_owner_state;
    return owner_hcall_status;
#endif
}
#define shz_hcall mock_hcall
#define shz_exit mock_exit
#define shz_timer_set mock_timer
#define sti mock_sti
#define kmain production_kmain
#if defined(TEST_KERNEL32)
#include "../../kernel32/main.c"
#else
#include "../../kernel64/main.c"
#endif
#undef kmain

void arch_init(void) { ++arch_calls; ++fixture_sequence; }
void mem_init(const shz_bootinfo_t *bi)
{
    CHECK(bi->magic == SHZ_BOOTINFO_MAGIC);
    ++mem_calls; ++fixture_sequence;
}
void sched_init(void) { ++sched_calls; ++fixture_sequence; }
void kprintf(const char *format, ...) { (void)format; }
void kpanic(const char *format, ...)
{
    fprintf(stderr, "unexpected production KASSERT: %s\n", format);
    mock_exit(199);
}
void run_self_tests(const shz_bootinfo_t *bi) { (void)bi; ++qa_calls; ++fixture_sequence; }
void report_final(void) { ++report_calls; ++fixture_sequence; }
unsigned tests_failed(void) { return 0; }
#if defined(TEST_KERNEL32)
/* Native AP boundaries: this entry fixture advertises no AP request. */
int k32_ap_policy(const shz_bootinfo_t *bi,unsigned *count)
{ CHECK(bi != NULL && count != NULL); *count=0; return 0; }
int k32_ap_snapshot(const shz_bootinfo_t *bi,unsigned count)
{ (void)bi; (void)count; CHECK(0); return -1; }
int k32_ap_run(void) { CHECK(0); return -1; }
void thread_sleep_ms(uint32_t milliseconds)
{
    simulated_ms += milliseconds;
    if (simulated_ms > 100000) mock_exit(198);
}
volatile uint32_t ipc_session_end = 1; /* Legacy session signal must not end the owned native service. */
static thread_t server_thread;
void ipc_init(const shz_bootinfo_t *bi)
{
    CHECK(bi->channel_count == 1);
    ++ipc_calls; ipc_sequence = ++fixture_sequence;
}
void ipc_server_thread(void *unused) { (void)unused; }
thread_t *thread_create(const char *name, void (*worker)(void *), void *arg)
{
    CHECK(strcmp(name, "ipc-server") == 0 && worker == ipc_server_thread && arg == NULL);
    CHECK(ipc_calls == 1);
    ++thread_calls; ++fixture_sequence;
    return &server_thread;
}
uint32_t ipc_requests_served(void) { return 0; }
#else
uint64_t phys_base_va;
static uint8_t archive[64];
void ds_native_init(void) { ++ds_calls; ++fixture_sequence; }
void ds_native_control(void) { ++control_calls; ++fixture_sequence; }
void ds_native_timer_ready(void) { }
void krandom_init(const void *data, size_t length)
{
    CHECK(data != NULL && length == sizeof(shz_bootinfo_t));
    ++random_calls; ++fixture_sequence;
}
void fs_init(void) { ++fs_calls; ++fixture_sequence; }
int fs_load_archive(const uint8_t *data, uint64_t length)
{
    CHECK(data == archive && length == sizeof archive);
    ++archive_calls; ++fixture_sequence;
    return 7;
}
void disk_init(void) { ++disk_calls; ++fixture_sequence; }
/* No modeled storage devices in entry fixture. Actual binder is separately
 * tested against the production registry in host/test_blk_authority.c. */
int k64_boot_storage_bind(const shz_bootinfo_t *bi,int archive_loaded)
{
 CHECK(bi != NULL && archive_loaded && disk_calls==1 && sti_calls==0);
 return -1;
}
void shz_cpu_bringup_prepare(const shz_bootinfo_t *bi, uint64_t initial_cr3)
{
    CHECK(bi != NULL && bi->magic == SHZ_BOOTINFO_MAGIC && initial_cr3 == 0x1000);
    CHECK(mem_calls == 1 && arch_calls == 1 && sti_calls == 0);
    ++bringup_prepare_calls; bringup_prepare_sequence = ++fixture_sequence;
}
void shz_cpu_bringup_verify(void)
{
    CHECK(bringup_prepare_calls == 1 && sti_calls == 1 && sched_calls == 1);
    ++bringup_verify_calls; bringup_verify_sequence = ++fixture_sequence;
}
/* This fixture does not request native AP service. Any unexpected AP call
 * fails the fixture; dedicated AP harnesses own real worker behavior. */
int shz_cpu_workers_requested(void) { return 0; }
int shz_cpu_workers_start(void) { CHECK(0); return -1; }
void thread_reap_exited(void) { CHECK(0); }
int sched_ap_work_quiescent(void) { CHECK(0); return 0; }
uint64_t sched_cpu_online_mask(void) { CHECK(0); return 0; }
uint64_t ticks_now(void) { CHECK(0); return 0; }
void *kmalloc(size_t n) { (void)n; CHECK(0); return NULL; }
void kfree(void *p) { (void)p; CHECK(0); }
int sched_validate(void) { CHECK(0); return 0; }
int sched_ap_work_submit(const void *p,unsigned n,uint64_t mask,uint64_t *cookie)
{ (void)p; (void)n; (void)mask; (void)cookie; CHECK(0); return -1; }
int sched_ap_work_poll(uint64_t cookie,uint64_t *digest)
{ (void)cookie; (void)digest; CHECK(0); return -1; }
int sched_ap_work_release(uint64_t cookie) { (void)cookie; CHECK(0); return -1; }
int sched_ap_work_migrate(unsigned origin,unsigned slot,unsigned destination)
{ (void)origin; (void)slot; (void)destination; CHECK(0); return -1; }
int sched_ap_work_stop(void) { CHECK(0); return -1; }
void pci_log_devices(void) { }
void setup_autostart(const shz_bootinfo_t *bi) { (void)bi; ++setup_calls; ++fixture_sequence; }
unsigned k64_desktop(void) { ++desktop_calls; ++fixture_sequence; return 0; }
void ntdrv_selftest(void) { ++ntdrv_calls; ++fixture_sequence; }
void k64_autorun(void) { ++autorun_calls; ++fixture_sequence; }
void k64_autorun_observe(void) { }
int k64_cmdline_has(const char *text)
{
    return strstr(k64_boot_cmdline(), text) != NULL;
}
void ipc64_init(const shz_bootinfo_t *bi)
{
    CHECK(bi->channel_count > 0 && bi->channel[0].peer_domain == SHZ_DOM_KERNEL32);
    ++ipc_calls; ipc_sequence = ++fixture_sequence;
}
int ipc64_run_tests(void) { ++qa_calls; ++fixture_sequence; return 0; }
void subsys64_start(const shz_bootinfo_t *bi)
{
    CHECK(bi->domain_id == SHZ_DOM_KERNEL64);
    ++service_calls; service_sequence = ++fixture_sequence;
}
#endif

static void command(const char *text)
{
    size_t length = strlen(text);
    CHECK(length < sizeof fixture.cmdline);
    memset(fixture.cmdline, 0, sizeof fixture.cmdline);
    memcpy(fixture.cmdline, text, length + 1);
    fixture.cmdline_size = (uint32_t)length;
}

static void reset(void)
{
    memset(&fixture, 0, sizeof fixture);
    fixture.magic = SHZ_BOOTINFO_MAGIC;
    fixture.abi_major = SHZ_ABI_MAJOR;
    fixture.abi_minor = SHZ_ABI_MINOR;
    fixture.size = sizeof fixture;
    fixture.generation = 1;
    fixture.ram_size = 64ull << 20;
    fixture.tsc_hz = 1000000000;
#if defined(TEST_KERNEL32)
    fixture.domain_id = SHZ_DOM_KERNEL32;
    fixture.channel_count = 1;
    fixture.channel[0].peer_domain = SHZ_DOM_KERNEL64;
#else
    fixture.domain_id = SHZ_DOM_KERNEL64;
    fixture.channel_count = 2;
    fixture.channel[0].peer_domain = SHZ_DOM_KERNEL32;
    fixture.channel[1].peer_domain = SHZ_DOM_WIN98;
    fixture.channel[1].channel_id = 2;
    fixture.channel[1].gpa = SHZ_IPC_GPA_BASE + 2ull * SHZ_IPC_REGION_SIZE;
    fixture.channel[1].size = SHZ_IPC_REGION_SIZE;
    fixture.initrd_gpa = (uintptr_t)archive;
    fixture.initrd_size = sizeof archive;
    memset(&bootinfo, 0, sizeof bootinfo); /* One real entry invocation per simulated boot. */
    initrd_files = -1;
#endif
    fixture.channel[0].channel_id = 0;
    fixture.channel[0].gpa = SHZ_IPC_GPA_BASE;
    fixture.channel[0].size = SHZ_IPC_REGION_SIZE;
    final_owner_state = SHZ_DS_EXITED;
    owner_hcall_status = SHZ_OK;
    exit_code = UINT32_MAX;
}

static void invoke(void)
{
    if (setjmp(return_to_test) == 0) {
#if defined(TEST_KERNEL32)
        production_kmain(&fixture);
#else
        production_kmain((uint64_t)(uintptr_t)&fixture - K64_VIRT_BASE);
#endif
        CHECK(0); /* A real entry must exit or remain in its runtime worker. */
    }
}

static void normal_initialization(void)
{
    CHECK(arch_calls == 1 && mem_calls == 1 && sched_calls == 1);
    CHECK(timer_calls == 1 && sti_calls == 1 && ipc_calls == 1);
#if defined(TEST_KERNEL32)
    CHECK(thread_calls == 1);
    CHECK(fs_calls == 0 && archive_calls == 0 && random_calls == 0 && ds_calls == 0 && disk_calls == 0 && control_calls == 0 && service_sequence == 0);
#else
    CHECK(fs_calls == 1 && archive_calls == 1 && random_calls == 1 && ds_calls == 1 && disk_calls == 1);
    CHECK(bringup_prepare_calls == 1 && bringup_verify_calls == 1);
    CHECK(bringup_prepare_sequence < bringup_verify_sequence);
    CHECK(initrd_files == 7);
#endif
}

int main(int argc, char **argv)
{
    int malformed = 0, diagnostic = 0, old_service = 0;
    unsigned wanted_exit = 0;
    CHECK(argc == 2);
    reset(); command("shz.foundation=win98");
    if (strcmp(argv[1], "foundation-exited") == 0) { }
    else if (strcmp(argv[1], "foundation-failed") == 0) {
        final_owner_state = SHZ_DS_FAILED;
        wanted_exit = 1;
    }
    else if (strcmp(argv[1], "foundation-owner-running") == 0) { final_owner_state = SHZ_DS_RUNNABLE; }
    else if (strcmp(argv[1], "foundation-owner-waiting") == 0) { final_owner_state = SHZ_DS_WAITING; }
    else if (strcmp(argv[1], "foundation-owner-invalid") == 0) {
        final_owner_state = SHZ_DS_UNUSED; wanted_exit = 98;
    }
    else if (strcmp(argv[1], "foundation-owner-hcall-failed") == 0) {
        owner_hcall_status = SHZ_E_NOENT; wanted_exit = 98;
    }
    else if (strcmp(argv[1], "legacy-k32-service") == 0) {
        command("shz.k32-service=win98"); old_service = 1;
    }
    else if (strcmp(argv[1], "diagnostic") == 0) { command(""); diagnostic = 1; }
    else if (strcmp(argv[1], "legacy-tail") == 0) {
        fixture.size = 176; fixture.abi_minor = 0; diagnostic = 1;
    }
    else if (strcmp(argv[1], "malformed-nul") == 0) {
        memset(fixture.cmdline, 'a', sizeof fixture.cmdline);
        fixture.cmdline_size = 255; malformed = 1;
    }
    else if (strcmp(argv[1], "partial-tail") == 0) { fixture.size = 471; malformed = 1; }
    else if (strcmp(argv[1], "mixed-profile") == 0) {
        command("shz.foundation=win98 shz.desktop"); malformed = 1;
    }
    else if (strcmp(argv[1], "invalid-channel") == 0) { fixture.channel[0].gpa++; malformed = 1; }
    else if (strcmp(argv[1], "duplicate-profile") == 0) {
        command("shz.foundation=win98 shz.foundation=win98"); malformed = 1;
    }
    else CHECK(0);
#ifdef SHZ_STANDALONE
    if (!diagnostic && !old_service) malformed = 1;
#endif
    (void)old_service;
    invoke();
    if (malformed) {
        CHECK(exit_code == 97);
        CHECK(arch_calls == 0 && mem_calls == 0 && sched_calls == 0 && timer_calls == 0 && sti_calls == 0);
        CHECK(qa_calls == 0 && service_calls == 0 && thread_calls == 0 && ipc_calls == 0);
#if defined(TEST_KERNEL64)
        CHECK(bringup_prepare_calls == 0 && bringup_verify_calls == 0);
#endif
    } else {
        CHECK(exit_code == wanted_exit);
        normal_initialization();
        if (diagnostic) {
            CHECK(report_calls == 1 && qa_calls > 0);
#if defined(TEST_KERNEL64)
            CHECK(setup_calls == 1 && ntdrv_calls == 1 && autorun_calls == 1 && service_calls == 1 && control_calls == 1);
            CHECK(owner_calls == 0);
#endif
        } else {
            CHECK(qa_calls == 0 && report_calls == 0 && setup_calls == 0 && ntdrv_calls == 0 && autorun_calls == 0 && desktop_calls == 0);
#if defined(TEST_KERNEL32)
            CHECK(simulated_ms >= 30000); /* Both RUNNABLE and WAITING persisted beyond the old20s QA limit. */
#else
            CHECK(control_calls == 0 && service_calls == 1 && owner_calls == 1);
            CHECK(bringup_verify_sequence < service_sequence);
            CHECK(ipc_sequence < service_sequence);
#endif
        }
    }
    printf("PASS %u actual production entry boundary checks (%s), simulated=%llu ms; no VM executed\n",
           checks, argv[1], (unsigned long long)simulated_ms);
    return 0;
}
