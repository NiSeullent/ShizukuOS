/* SPDX-License-Identifier: GPL-2.0-only
 * Executes the actual native subsys64 pump_slot body and real channel framing.
 * Scheduler, proc_wait and privileged operations are host boundaries. No VM.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../kernel64/proc_internal.h"
#include "../../abi/shz_ipc.h"

static unsigned checks, reap_calls, unfinished_waits, sleeps, notifications;
static uint64_t simulated_ticks;
static int reap_status, reap_faulted;
static int64_t reap_code;
static process_t test_process;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL native worker reap boundary: line=%u %s calls=%u unfinished=%u teardown=%d ticks=%llu\n", \
            (unsigned)__LINE__, #expression, reap_calls, unfinished_waits, test_process.teardown, \
            (unsigned long long)simulated_ticks); exit(1); \
} } while (0)

static uint64_t mock_irq_save(void) { return 0; }
static void mock_irq_restore(uint64_t flags) { (void)flags; }
static long mock_notify(unsigned domain, uint32_t mask)
{
    CHECK(domain == SHZ_DOM_WIN98 && mask == 1);
    ++notifications;
    return SHZ_OK;
}
#define irq_save mock_irq_save
#define irq_restore mock_irq_restore
#define shz_notify mock_notify
#include "../../kernel64/subsys64.c"
#undef irq_save
#undef irq_restore
#undef shz_notify

uint64_t ticks_now(void) { return simulated_ticks; }
void thread_sleep_ms(uint64_t milliseconds)
{
    ++sleeps;
    simulated_ticks += milliseconds;
}
void sem_init(ksem_t *sem, int count) { sem->count = count; sem->waiters = NULL; }
void kprintf(const char *format, ...) { (void)format; }
void kpanic(const char *format, ...)
{
    fprintf(stderr, "unexpected production panic: %s\n", format);
    exit(2);
}
int proc_wait(int pid, int64_t *code, int *faulted)
{
    CHECK(pid == test_process.pid && code != NULL && faulted != NULL);
    ++reap_calls;
    /* The real proc_wait blocks at this boundary until teardown completes.
     * Record that forbidden attempt instead of hanging the host test. */
    if (!test_process.terminated || test_process.threads_alive || test_process.teardown != 2) {
        ++unfinished_waits;
        return -1;
    }
    *code = reap_code;
    *faulted = reap_faulted;
    return reap_status;
}

static uint8_t test_channel[SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
static w64_slot_t *fixture(int teardown, int terminated, int threads_alive)
{
    memset(slots, 0, sizeof slots);
    memset(&test_process, 0, sizeof test_process);
    test_process.pid = 41;
    test_process.teardown = teardown;
    test_process.terminated = terminated;
    test_process.threads_alive = threads_alive;
    reap_calls = unfinished_waits = sleeps = notifications = 0;
    simulated_ticks = 0;
    reap_status = reap_faulted = 0;
    reap_code = 0x1234;
    CHECK(shz_channel_init(test_channel, sizeof test_channel, 2,
                           SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 7) == SHZ_OK);
    bind_channel(test_channel, sizeof test_channel, SHZ_DOM_WIN98);
    shutdown_requested = 1;
    shutdown_deadline = W64_SHUTDOWN_WAIT_MS;
    w64_slot_t *slot = &slots[0];
    slot->used = 1;
    slot->pid = test_process.pid;
    slot->proc = &test_process;
    slot->state = SHZ_W64_PS_STARTED;
    return slot;
}

static void pending(w64_slot_t *slot)
{
    const unsigned before = reap_calls;
    CHECK(pump_slot(slot) == 0);
    CHECK(reap_calls == before && unfinished_waits == 0);
    CHECK(slot->proc == &test_process && !slot->reaped && !slot->exited_sent);
    CHECK(slot->state == SHZ_W64_PS_STARTED && notifications == 0 && sleeps == 0);
}
static void completed(w64_slot_t *slot, uint32_t expected_state)
{
    shz_msg_hdr_t message;
    shz_w64_event_t event_data;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int reason = 0;
    CHECK(pump_slot(slot) == 1);
    CHECK(reap_calls == 1 && unfinished_waits == 0 && sleeps == 0);
    CHECK(slot->reaped && slot->proc == NULL && slot->exited_sent);
    CHECK(slot->state == expected_state && slot->exit_code == reap_code);
    CHECK(slot->fault_status == (reap_faulted ? (uint32_t)reap_code : 0));
    CHECK(notifications == 1);
    shz_ring_hdr_t *client_rx = shz_channel_ring_rx(test_channel, chan, SHZ_DOM_WIN98);
    CHECK(shz_ring_pop(client_rx, &message, payload, sizeof payload, &reason) == SHZ_OK);
    CHECK(message.opcode == SHZ_OP_W64_PROCESS_EXITED && message.generation == 7);
    CHECK(message.src_domain == SHZ_DOM_KERNEL64 && message.dst_domain == SHZ_DOM_WIN98);
    CHECK(message.flags == SHZ_MSGF_ONEWAY && message.payload_length == sizeof event_data);
    memcpy(&event_data, payload, sizeof event_data);
    CHECK(event_data.pid == 41 && event_data.state == expected_state);
    CHECK(event_data.exit_code == reap_code && event_data.fault_status == slot->fault_status);
    CHECK(pump_slot(slot) == 0 && reap_calls == 1 && notifications == 1);
    CHECK(shz_ring_pop(client_rx, &message, payload, sizeof payload, &reason) == SHZ_E_NOENT);
}

static void cancellation_while_reap_pending(void)
{
    w64_slot_t *slot = fixture(1, 1, 0);
    pending(slot);
    shz_pma_request_t request;
    shz_msg_hdr_t message, received, filler;
    shz_pma_completion_t completion;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int reason = 0;
    memset(&request, 0, sizeof request);
    request.magic = SHZ_PMA_MAGIC;
    request.abi_major = SHZ_PMA_ABI_MAJOR;
    request.abi_minor = SHZ_PMA_ABI_MINOR;
    request.size = sizeof request;
    request.domain = SHZ_DOM_WIN98;
    request.pid = 41;
    request.tid = 3;
    request.owner_generation = request.thread_generation = 1;
    memset(&message, 0, sizeof message);
    message.magic = SHZ_MSG_MAGIC;
    message.abi_major = SHZ_ABI_MAJOR;
    message.abi_minor = SHZ_ABI_MINOR;
    message.header_size = sizeof message;
    message.message_size = sizeof message + sizeof request;
    message.opcode = SHZ_OP_PMA_EVENT_CREATE;
    message.src_domain = SHZ_DOM_WIN98;
    message.dst_domain = SHZ_DOM_KERNEL64;
    message.generation = 7;
    message.request_id = 1;
    message.payload_offset = sizeof message;
    message.payload_length = sizeof request;
    CHECK(shz_pma_service_dispatch(&pma_service, &message, &request, 0) == SHZ_OK);
    CHECK(pma_pump() == 1);
    shz_ring_hdr_t *client_rx = shz_channel_ring_rx(test_channel, chan, SHZ_DOM_WIN98);
    CHECK(shz_ring_pop(client_rx, &received, payload, sizeof payload, &reason) == SHZ_OK);
    CHECK(received.opcode == SHZ_OP_PMA_EVENT_CREATE && received.status == SHZ_OK);
    memcpy(&completion, payload, sizeof completion);
    CHECK(completion.object != 0);
    request.object = completion.object;
    request.deadline_ns = UINT64_MAX;
    message.opcode = SHZ_OP_PMA_EVENT_WAIT;
    message.request_id = 2;
    CHECK(shz_pma_service_dispatch(&pma_service, &message, &request, 0) == SHZ_OK);
    CHECK(!shz_pma_service_peek(&pma_service));
    CHECK(shz_pma_service_shutdown(&pma_service) == SHZ_OK);
    memset(&filler, 0, sizeof filler);
    filler.flags = SHZ_MSGF_ONEWAY;
    filler.opcode = SHZ_OP_W64_QUERY;
    filler.src_domain = SHZ_DOM_KERNEL64;
    filler.dst_domain = SHZ_DOM_WIN98;
    filler.generation = 7;
    for (unsigned index = 0; index < 32; ++index)
        CHECK(shz_ring_push(tx, &filler, NULL) == SHZ_OK);
    const uint64_t retry_before = pma_full_ring_retries;
    CHECK(pma_pump() == 0 && pma_full_ring_retries == retry_before + 1);
    const shz_pma_frame_t *retained = shz_pma_service_peek(&pma_service);
    CHECK(retained && retained->header.request_id == 2 && retained->header.status == SHZ_E_CANCELLED);
    CHECK(pump_slot(slot) == 0 && reap_calls == 0 && unfinished_waits == 0);
    CHECK(slot->proc == &test_process && !slot->reaped);
    for (unsigned index = 0; index < 32; ++index) {
        CHECK(shz_ring_pop(client_rx, &received, payload, sizeof payload, &reason) == SHZ_OK);
        CHECK(received.opcode == SHZ_OP_W64_QUERY);
    }
    CHECK(pma_pump() == 1 && !shz_pma_service_peek(&pma_service));
    CHECK(shz_ring_pop(client_rx, &received, payload, sizeof payload, &reason) == SHZ_OK);
    memcpy(&completion, payload, sizeof completion);
    CHECK(received.opcode == SHZ_OP_PMA_EVENT_WAIT && received.request_id == 2 && received.status == SHZ_E_CANCELLED);
    CHECK(received.generation == 7 && completion.sequence == 2 && completion.status == SHZ_E_CANCELLED);
    CHECK(pma_pump() == 0 && reap_calls == 0 && notifications == 2 && sleeps == 0);
    CHECK(shz_ring_pop(client_rx, &received, payload, sizeof payload, &reason) == SHZ_E_NOENT);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "teardown-not-started") || !strcmp(argv[1], "teardown-in-progress")) {
        w64_slot_t *slot = fixture(!strcmp(argv[1], "teardown-in-progress"), 1, 0);
        /* Repeated shutdown pumps must never enter a reap wait, even across
         * the outer drain's deadline. Pending state stays owned and intact. */
        for (unsigned iteration = 0; iteration <= W64_SHUTDOWN_WAIT_MS; ++iteration) {
            simulated_ticks = iteration;
            pending(slot);
        }
        CHECK(simulated_ticks == shutdown_deadline && reap_calls == 0);
    } else if (!strcmp(argv[1], "threads-still-alive")) {
        pending(fixture(2, 1, 1));
    } else if (!strcmp(argv[1], "process-still-running")) {
        pending(fixture(2, 0, 0));
    } else if (!strcmp(argv[1], "teardown-complete")) {
        completed(fixture(2, 1, 0), SHZ_W64_PS_EXITED);
    } else if (!strcmp(argv[1], "killed-process-complete")) {
        w64_slot_t *slot = fixture(2, 1, 0);
        slot->state = SHZ_W64_PS_KILLED;
        reap_code = -9;
        reap_faulted = 1;
        completed(slot, SHZ_W64_PS_KILLED);
    } else if (!strcmp(argv[1], "teardown-progresses")) {
        w64_slot_t *slot = fixture(1, 1, 0);
        pending(slot);
        test_process.teardown = 2;
        completed(slot, SHZ_W64_PS_EXITED);
    } else if (!strcmp(argv[1], "PMA-cancellation-pending-reap")) {
        cancellation_while_reap_pending();
    } else {
        fprintf(stderr, "unknown case\n");
        return 2;
    }
    printf("PASS %u actual native worker reap checks (%s); scheduler/reap/IRQ boundaries modeled; no VM\n",
           checks, argv[1]);
    return 0;
}
