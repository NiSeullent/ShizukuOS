/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 entry (C): bring up CPU tables, memory, scheduler, timer and IPC; run the
 * self-tests; keep serving other domains until the peer ends its session.
 */
#include "k32.h"
#include "smp_native.h"
#include "service_policy.h"
#include "../boot_profile/win98_foundation.h"

extern volatile uint32_t ipc_session_end;
extern void report_final(void);
extern unsigned tests_failed(void);

void kmain(const shz_bootinfo_t *bi)
{
    thread_t *server = 0;
    uint64_t waited_ms = 0;
    int service_mode;
    if (bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR || bi->domain_id != SHZ_DOM_KERNEL32)
        shz_exit(97);
    unsigned native_count=0;
    const int native_policy=k32_ap_policy(bi,&native_count);
    if(native_policy<0 || (native_policy && k32_ap_snapshot(bi,native_count)))shz_exit(97);
    service_mode = native_policy ? 0 : k32_boot_runtime_service_mode(bi);
    if (service_mode < 0)
        shz_exit(97);
    arch_init();
    kprintf("%s: Protected Mode kernel starting, %u MiB RAM, tsc %u kHz\n", KVER, (uint32_t)(bi->ram_size >> 20),
            (uint32_t)(bi->tsc_hz / 1000));
    mem_init(bi);
    sched_init();
    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);
    if(native_count) {
        const int native_result=k32_ap_run();
        shz_exit(native_result==1?0:98);
    }
    sti();
    if (bi->channel_count) {
        ipc_init(bi);
        server = thread_create("ipc-server", ipc_server_thread, 0);
        KASSERT(server);
    }
    if (service_mode) {
        KASSERT(server);
        kprintf("%s: native Win98 component service active; QA session limits disabled\n", KVER);
        for (;;) {
            hcreg_t state = SHZ_DS_UNUSED;
            const long status = shz_hcall(SHZ_HC_DOMAIN_STATE, SHZ_DOM_WIN98, 0, &state);
            if (status != SHZ_OK)
                shz_exit(98);
            if (state == SHZ_DS_EXITED) {
                kprintf("%s: Win98 owner exited; component service stopping\n", KVER);
                shz_exit(0);
            }
            if (state == SHZ_DS_FAILED)
                shz_exit(1);
            if (state != SHZ_DS_RUNNABLE && state != SHZ_DS_WAITING)
                shz_exit(98);
            thread_sleep_ms(100);
        }
    }
    run_self_tests(bi);
    if (server) {
        /* stay alive as a service until the peer signals the end of its session */
        while (!ipc_session_end && waited_ms < 20000) {
            thread_sleep_ms(10);
            waited_ms += 10;
        }
        thread_sleep_ms(20);                    /* let the reply for SESSION_END reach the peer */
    }
    report_final();
    kprintf("%s: done, %u self-test failure(s), %u IPC requests served\n", KVER, tests_failed(),
            (uint32_t)ipc_requests_served());
    shz_exit(tests_failed() ? 1 : 0);
}
