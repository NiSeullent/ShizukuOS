/* SPDX-License-Identifier: GPL-2.0-only
 * Independent transport checks use the production service and ABI ring code.
 * One thread owns service state; each ring has exactly one producer/consumer.
 * Host execution is not evidence of an actual Windows 98 VMM connection. */
#include "service.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks;
#define CHECK(x) do { __atomic_fetch_add(&checks, 1ul, __ATOMIC_RELAXED); \
    if (!(x)) { fprintf(stderr, "FAIL %s:%u: %s\n", __FILE__, (unsigned)__LINE__, #x); exit(1); } } while (0)
static uint8_t memory[1u << 20] __attribute__((aligned(4096)));
static shz_pma_service_t service;
static shz_ring_hdr_t *client_tx, *client_rx, *server_tx;
static shz_msg_hdr_t pending_header;
static uint8_t pending_payload[SHZ_MSG_MAX_INLINE];
static int pending, last_rejection;
static uint64_t sequence, now_ns;
static uint32_t epoch;
static FILE *samples;

static void setup(uint32_t slots)
{
    shz_channel_hdr_t *channel = (shz_channel_hdr_t *)memory;
    epoch = 7;
    CHECK(shz_channel_init(memory, sizeof memory, 2, SHZ_DOM_WIN98,
                           SHZ_DOM_KERNEL64, slots, epoch) == SHZ_OK);
    CHECK(shz_pma_service_init(&service, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, epoch) == SHZ_OK);
    client_tx = shz_channel_ring_tx(memory, channel, SHZ_DOM_WIN98);
    client_rx = server_tx = shz_channel_ring_rx(memory, channel, SHZ_DOM_WIN98);
    sequence = 0; now_ns = 100; pending = 0; last_rejection = SHZ_OK;
}

static shz_pma_request_t identity(uint32_t pid, uint32_t tid)
{
    shz_pma_request_t request;
    memset(&request, 0, sizeof request);
    request.magic = SHZ_PMA_MAGIC;
    request.abi_major = SHZ_PMA_ABI_MAJOR;
    request.abi_minor = SHZ_PMA_ABI_MINOR;
    request.size = sizeof request;
    request.domain = SHZ_DOM_WIN98;
    request.pid = pid; request.tid = tid;
    request.owner_generation = request.thread_generation = 1;
    return request;
}

static int enqueue(uint32_t op, uint64_t id, const shz_pma_request_t *request, uint32_t generation)
{
    shz_msg_hdr_t header;
    memset(&header, 0, sizeof header);
    header.opcode = op; header.request_id = id;
    header.src_domain = SHZ_DOM_WIN98; header.dst_domain = SHZ_DOM_KERNEL64;
    header.generation = generation; header.payload_length = sizeof *request;
    return shz_ring_push(client_tx, &header, request);
}

static uint64_t send(uint32_t op, const shz_pma_request_t *request)
{
    ++sequence;
    CHECK(enqueue(op, sequence, request, epoch) == SHZ_OK);
    return sequence;
}

/* Retain a completion until the real ring accepts it, and retain a request if
 * the production service says its completion reservation is full. */
static unsigned flush(void)
{
    const shz_pma_frame_t *frame;
    unsigned count = 0;
    while ((frame = shz_pma_service_peek(&service)) != NULL) {
        shz_msg_hdr_t header = frame->header;
        int rc = shz_ring_push(server_tx, &header, frame->payload);
        if (rc == SHZ_E_QUEUE_FULL) break;
        CHECK(rc == SHZ_OK);
        CHECK(shz_pma_service_ack(&service, header.request_id) == SHZ_OK);
        ++count;
    }
    return count;
}

static void pump(void)
{
    int reason, rc;
    shz_pma_service_tick(&service, now_ns);
    flush();
    for (;;) {
        if (!pending) {
            rc = shz_ring_pop(client_tx, &pending_header, pending_payload, sizeof pending_payload, &reason);
            if (rc == SHZ_E_NOENT) break;
            if (rc != SHZ_OK) { CHECK(rc == SHZ_E_PROTO); last_rejection = rc; continue; }
            pending = 1;
        }
        rc = shz_pma_service_dispatch(&service, &pending_header, pending_payload, now_ns);
        if (rc == SHZ_E_QUEUE_FULL) break;
        pending = 0;
        if (rc != SHZ_OK) last_rejection = rc;
        flush();
    }
    flush();
}

static shz_pma_completion_t receive(uint64_t id, int32_t status)
{
    shz_msg_hdr_t header;
    shz_pma_completion_t completion;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int reason;
    if (samples) {
        CHECK(shz_ring_count(client_rx) != 0);
        CHECK(fwrite(shz_ring_slot(client_rx, client_rx->tail), 1, SHZ_MSG_SLOT_SIZE, samples) == SHZ_MSG_SLOT_SIZE);
    }
    CHECK(shz_ring_pop(client_rx, &header, payload, sizeof payload, &reason) == SHZ_OK);
    CHECK(header.flags == SHZ_MSGF_REPLY && header.request_id == id && header.status == status);
    CHECK(header.src_domain == SHZ_DOM_KERNEL64 && header.dst_domain == SHZ_DOM_WIN98 && header.generation == epoch);
    CHECK(header.payload_length == sizeof completion);
    memcpy(&completion, payload, sizeof completion);
    CHECK(completion.magic == SHZ_PMA_MAGIC && completion.size == sizeof completion);
    CHECK(completion.sequence == id && completion.status == status);
    return completion;
}

static void receive_query(uint64_t id)
{
    shz_msg_hdr_t header;
    shz_pma_info_t info;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int reason;
    if (samples) {
        CHECK(shz_ring_count(client_rx) != 0);
        CHECK(fwrite(shz_ring_slot(client_rx, client_rx->tail), 1, SHZ_MSG_SLOT_SIZE, samples) == SHZ_MSG_SLOT_SIZE);
    }
    CHECK(shz_ring_pop(client_rx, &header, payload, sizeof payload, &reason) == SHZ_OK);
    CHECK(header.opcode == SHZ_OP_PMA_QUERY && header.request_id == id && header.status == SHZ_OK);
    CHECK(header.flags == SHZ_MSGF_REPLY && header.payload_length == sizeof info);
    memcpy(&info, payload, sizeof info);
    CHECK(info.magic == SHZ_PMA_MAGIC && info.size == sizeof info && info.features == SHZ_PMA_FEATURES);
    CHECK(info.generation == epoch && info.self_domain == SHZ_DOM_KERNEL64 && info.peer_domain == SHZ_DOM_WIN98);
    CHECK(info.now_ns == now_ns && info.max_completions == SHZ_PMA_MAX_COMPLETIONS);
}

static void empty(void)
{
    shz_msg_hdr_t header;
    uint8_t payload[SHZ_MSG_MAX_INLINE];
    int reason;
    CHECK(shz_ring_pop(client_rx, &header, payload, sizeof payload, &reason) == SHZ_E_NOENT);
}

static uint32_t create(uint32_t flags)
{
    shz_pma_request_t request = identity(41, 1);
    uint64_t id;
    request.flags = flags; id = send(SHZ_OP_PMA_EVENT_CREATE, &request); pump();
    return receive(id, SHZ_OK).object;
}

static uint64_t wait_event(uint32_t object, uint32_t tid, uint64_t deadline)
{
    shz_pma_request_t request = identity(41, tid);
    request.object = object; request.deadline_ns = deadline;
    return send(SHZ_OP_PMA_EVENT_WAIT, &request);
}

static uint64_t operation(uint32_t op, uint32_t object)
{
    shz_pma_request_t request = identity(41, 1);
    request.object = object;
    return send(op, &request);
}

static void test_wire_and_notification_idempotence(void)
{
    uint32_t object;
    uint64_t waiting, signal;
    shz_pma_request_t request;
    setup(8); object = create(0); CHECK(object != 0);
    waiting = wait_event(object, 2, UINT64_MAX); pump(); empty();
    signal = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump();
    receive(waiting, SHZ_OK); receive(signal, SHZ_OK);
    pump(); pump(); pump(); empty(); /* duplicate doorbells are advisory */
    request = identity(41, 1); request.object = object;
    CHECK(enqueue(SHZ_OP_PMA_EVENT_SIGNAL, signal, &request, epoch) == SHZ_OK);
    pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
    waiting = wait_event(object, 2, 0); pump(); receive(waiting, SHZ_E_TIMEOUT);
}

static void test_full_tx_retains_completion_exactly_once(void)
{
    shz_msg_hdr_t dummy;
    shz_pma_request_t request;
    uint32_t object;
    uint64_t waiting, signal;
    const shz_pma_frame_t *frame;
    setup(2); object = create(0);
    waiting = wait_event(object, 2, UINT64_MAX); pump();
    memset(&dummy, 0, sizeof dummy); dummy.opcode = 0xdead;
    CHECK(shz_ring_push(server_tx, &dummy, NULL) == SHZ_OK);
    CHECK(shz_ring_push(server_tx, &dummy, NULL) == SHZ_OK);
    signal = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump();
    frame = shz_pma_service_peek(&service);
    CHECK(frame && frame->header.request_id == waiting);
    CHECK(shz_pma_service_ack(&service, signal) == SHZ_E_NOENT);
    pump(); pump(); CHECK(shz_pma_service_peek(&service)->header.request_id == waiting);
    { shz_msg_hdr_t header; int reason;
      CHECK(shz_ring_pop(client_rx, &header, NULL, 0, &reason) == SHZ_OK && header.opcode == 0xdead);
      CHECK(shz_ring_pop(client_rx, &header, NULL, 0, &reason) == SHZ_OK && header.opcode == 0xdead); }
    pump(); receive(waiting, SHZ_OK); receive(signal, SHZ_OK); pump(); empty();
    request = identity(41, 1); request.object = object;
    CHECK(enqueue(SHZ_OP_PMA_EVENT_SIGNAL, signal, &request, epoch) == SHZ_OK);
    pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
}

static void test_owner_death_completion_survives_full_tx(void)
{
    shz_msg_hdr_t dummy, header;
    shz_pma_request_t request;
    uint32_t object;
    uint64_t waiting, death;
    int reason;
    setup(2); object = create(0);
    waiting = wait_event(object, 2, UINT64_MAX); pump();
    memset(&dummy, 0, sizeof dummy); dummy.opcode = 0xdead;
    CHECK(shz_ring_push(server_tx, &dummy, NULL) == SHZ_OK);
    CHECK(shz_ring_push(server_tx, &dummy, NULL) == SHZ_OK);
    request = identity(41, 1); death = send(SHZ_OP_PMA_PROCESS_EXIT, &request); pump();
    CHECK(shz_pma_service_peek(&service)->header.request_id == waiting);
    pump(); pump();
    CHECK(shz_ring_pop(client_rx, &header, NULL, 0, &reason) == SHZ_OK && header.opcode == 0xdead);
    CHECK(shz_ring_pop(client_rx, &header, NULL, 0, &reason) == SHZ_OK && header.opcode == 0xdead);
    pump(); receive(waiting, SHZ_E_CANCELLED); receive(death, SHZ_OK); pump(); empty();
    send(SHZ_OP_PMA_EVENT_CREATE, &request); pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
}

static void test_deadline_death_cancel_and_reuse(void)
{
    shz_pma_request_t request;
    uint32_t object, replacement;
    uint64_t waiting, op;
    setup(8); object = create(0);
    waiting = wait_event(object, 2, 200); pump();
    now_ns = 199; pump(); empty(); now_ns = 200; pump(); receive(waiting, SHZ_E_TIMEOUT);
    now_ns = 201; pump(); empty();
    waiting = wait_event(object, 2, UINT64_MAX); pump();
    request = identity(41, 2); request.target_sequence = waiting;
    op = send(SHZ_OP_PMA_CANCEL, &request); pump(); receive(waiting, SHZ_E_CANCELLED); receive(op, SHZ_OK);
    waiting = wait_event(object, 2, UINT64_MAX); pump();
    request.target_sequence = 0;
    op = send(SHZ_OP_PMA_THREAD_EXIT, &request); pump(); receive(waiting, SHZ_E_CANCELLED); receive(op, SHZ_OK);
    request.target_sequence = 0; request.object = object; request.deadline_ns = 0;
    send(SHZ_OP_PMA_EVENT_WAIT, &request); pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
    request.thread_generation = 2;
    op = send(SHZ_OP_PMA_EVENT_WAIT, &request); pump(); receive(op, SHZ_E_TIMEOUT);
    waiting = wait_event(object, 3, UINT64_MAX); pump();
    request = identity(41, 1); op = send(SHZ_OP_PMA_PROCESS_EXIT, &request); pump();
    receive(waiting, SHZ_E_CANCELLED); receive(op, SHZ_OK);
    send(SHZ_OP_PMA_EVENT_CREATE, &request); pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
    request.owner_generation = 2; op = send(SHZ_OP_PMA_EVENT_CREATE, &request); pump();
    replacement = receive(op, SHZ_OK).object; CHECK(replacement != object);
    request.object = object; op = send(SHZ_OP_PMA_EVENT_SIGNAL, &request); pump(); receive(op, SHZ_E_NOENT);
}

static void test_manual_reset_close_and_private_ownership(void)
{
    uint32_t object, replacement;
    uint64_t a, b, op;
    shz_pma_request_t request;
    setup(8); object = create(SHZ_PMA_EVENT_MANUAL_RESET);
    a = wait_event(object, 2, UINT64_MAX); b = wait_event(object, 3, UINT64_MAX); pump();
    op = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump(); receive(a, SHZ_OK); receive(b, SHZ_OK); receive(op, SHZ_OK);
    a = wait_event(object, 2, 0); pump(); receive(a, SHZ_OK);
    op = operation(SHZ_OP_PMA_EVENT_RESET, object); pump(); receive(op, SHZ_OK);
    a = wait_event(object, 2, 0); pump(); receive(a, SHZ_E_TIMEOUT);
    request = identity(42, 1); request.object = object;
    op = send(SHZ_OP_PMA_EVENT_SIGNAL, &request); pump(); receive(op, SHZ_E_DENIED);
    a = wait_event(object, 2, UINT64_MAX); pump();
    op = operation(SHZ_OP_PMA_EVENT_CLOSE, object); pump(); receive(a, SHZ_E_CANCELLED); receive(op, SHZ_OK);
    replacement = create(0); CHECK(replacement != object);
    op = operation(SHZ_OP_PMA_EVENT_WAIT, object); pump(); receive(op, SHZ_E_NOENT);
}

static void test_hostile_frames_and_epoch_restart(void)
{
    shz_pma_request_t request;
    uint32_t object;
    uint64_t waiting, op;
    setup(8); object = create(0);
    request = identity(41, 1); request.object = object;
    CHECK(enqueue(SHZ_OP_PMA_EVENT_SIGNAL, ++sequence, &request, epoch - 1) == SHZ_OK);
    pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
    request.domain = SHZ_DOM_KERNEL32;
    send(SHZ_OP_PMA_EVENT_SIGNAL, &request); pump(); CHECK(last_rejection == SHZ_E_DENIED); empty();
    request = identity(41, 1); request.required_features = UINT64_C(1) << 63;
    send(SHZ_OP_PMA_QUERY, &request); pump(); CHECK(last_rejection == SHZ_E_UNSUPPORTED); empty();
    request.required_features = 0; request.magic ^= 1;
    send(SHZ_OP_PMA_QUERY, &request); pump(); CHECK(last_rejection != SHZ_OK); empty();
    request = identity(41, 1); send(SHZ_OP_PMA_QUERY, &request);
    shz_ring_slot(client_tx, client_tx->head - 1)[80] ^= 1;
    pump(); CHECK(last_rejection == SHZ_E_PROTO); empty();
    waiting = wait_event(object, 2, 0); pump(); receive(waiting, SHZ_E_TIMEOUT);
    waiting = wait_event(object, 2, UINT64_MAX); pump();
    CHECK(shz_pma_service_restart(&service, epoch - 1) == SHZ_E_INVALID);
    CHECK(shz_pma_service_restart(&service, epoch) == SHZ_E_INVALID);
    CHECK(shz_pma_service_restart(&service, ++epoch) == SHZ_OK);
    ((shz_channel_hdr_t *)memory)->generation = epoch;
    request = identity(41, 1); request.object = object;
    CHECK(enqueue(SHZ_OP_PMA_EVENT_SIGNAL, ++sequence, &request, epoch - 1) == SHZ_OK);
    pump(); CHECK(last_rejection == SHZ_E_STALE); empty();
    op = send(SHZ_OP_PMA_EVENT_SIGNAL, &request); pump(); receive(op, SHZ_E_NOENT);
    pump(); empty(); (void)waiting;
}

static void test_reserved_timeout_under_total_completion_pressure(void)
{
    shz_msg_hdr_t dummy;
    shz_msg_hdr_t header;
    uint32_t object;
    uint64_t waiting, first, blocked;
    unsigned i;
    int reason;
    setup(2); object = create(0);
    waiting = wait_event(object, 2, 200); pump();
    memset(&dummy, 0, sizeof dummy); dummy.opcode = 0xdead;
    CHECK(shz_ring_push(server_tx, &dummy, NULL) == SHZ_OK);
    CHECK(shz_ring_push(server_tx, &dummy, NULL) == SHZ_OK);
    first = sequence + 1;
    for (i = 1; i < SHZ_PMA_MAX_COMPLETIONS; ++i) {
        operation(SHZ_OP_PMA_EVENT_RESET, object); pump();
    }
    blocked = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump();
    CHECK(pending && pending_header.request_id == blocked);
    now_ns = 200; pump();
    CHECK(pending && shz_pma_service_peek(&service)->header.request_id == first);
    CHECK(shz_ring_pop(client_rx, &header, NULL, 0, &reason) == SHZ_OK && header.opcode == 0xdead);
    CHECK(shz_ring_pop(client_rx, &header, NULL, 0, &reason) == SHZ_OK && header.opcode == 0xdead);
    for (i = 1; i < SHZ_PMA_MAX_COMPLETIONS; ++i) {
        pump(); receive(first + i - 1, SHZ_OK);
    }
    pump(); receive(waiting, SHZ_E_TIMEOUT);
    pump(); receive(blocked, SHZ_OK);
    CHECK(!pending && !shz_pma_service_peek(&service)); pump(); empty();
}

static void test_automatic_token_is_not_counting(void)
{
    uint32_t object;
    uint64_t a, b, op;
    setup(8); object = create(0);
    op = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump(); receive(op, SHZ_OK);
    op = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump(); receive(op, SHZ_OK);
    a = wait_event(object, 2, 0); b = wait_event(object, 3, 0); pump(); receive(a, SHZ_OK); receive(b, SHZ_E_TIMEOUT);
    a = wait_event(object, 2, UINT64_MAX); b = wait_event(object, 3, UINT64_MAX); pump();
    op = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump(); receive(a, SHZ_OK); receive(op, SHZ_OK); empty();
    op = operation(SHZ_OP_PMA_EVENT_CLOSE, object); pump(); receive(b, SHZ_E_CANCELLED); receive(op, SHZ_OK);
}

static void test_version_negotiation_and_initial_token(void)
{
    shz_pma_request_t request;
    uint32_t object;
    uint64_t op;
    setup(8);
    request = identity(41, 1); request.abi_minor = UINT16_MAX;
    request.required_features = SHZ_PMA_FEATURES;
    op = send(SHZ_OP_PMA_QUERY, &request); pump(); receive_query(op);
    request.abi_major = 2;
    send(SHZ_OP_PMA_QUERY, &request); pump(); CHECK(last_rejection == SHZ_E_UNSUPPORTED); empty();
    request = identity(41, 1); request.flags = SHZ_PMA_EVENT_SIGNALED;
    op = send(SHZ_OP_PMA_EVENT_CREATE, &request); pump(); object = receive(op, SHZ_OK).object;
    op = wait_event(object, 2, 0); pump(); receive(op, SHZ_OK);
    op = wait_event(object, 3, 0); pump(); receive(op, SHZ_E_TIMEOUT);
}

static int worker_stop;
static void *server_worker(void *unused)
{
    (void)unused;
    while (!__atomic_load_n(&worker_stop, __ATOMIC_ACQUIRE)) { pump(); sched_yield(); }
    pump(); return NULL;
}

static void threaded_send(uint32_t op, uint64_t id, const shz_pma_request_t *request)
{
    int rc;
    while ((rc = enqueue(op, id, request, epoch)) == SHZ_E_QUEUE_FULL) sched_yield();
    CHECK(rc == SHZ_OK);
}

static void threaded_receive(uint64_t id)
{
    while (!shz_ring_count(client_rx)) sched_yield();
    receive(id, SHZ_OK);
}

static void test_threaded_production_exchange(void)
{
    pthread_t server;
    shz_pma_request_t request;
    uint32_t object;
    unsigned i;
    setup(4); object = create(0);
    __atomic_store_n(&worker_stop, 0, __ATOMIC_RELEASE);
    CHECK(pthread_create(&server, NULL, server_worker, NULL) == 0);
    for (i = 0; i < 2000; ++i) {
        uint64_t wait_id = ++sequence, signal_id = ++sequence;
        request = identity(41, 2); request.object = object; request.deadline_ns = UINT64_MAX;
        threaded_send(SHZ_OP_PMA_EVENT_WAIT, wait_id, &request);
        request = identity(41, 1); request.object = object;
        threaded_send(SHZ_OP_PMA_EVENT_SIGNAL, signal_id, &request);
        threaded_receive(wait_id); threaded_receive(signal_id);
    }
    __atomic_store_n(&worker_stop, 1, __ATOMIC_RELEASE);
    CHECK(pthread_join(server, NULL) == 0);
    CHECK(last_rejection == SHZ_OK && !pending && !shz_pma_service_peek(&service)); empty();
}

static void write_wire_samples(const char *path)
{
    uint32_t object;
    uint64_t a, signal;
    shz_pma_request_t request;
    setup(8); samples = fopen(path, "wb"); CHECK(samples != NULL);
    object = create(0);
    a = wait_event(object, 2, UINT64_MAX); pump();
    signal = operation(SHZ_OP_PMA_EVENT_SIGNAL, object); pump(); receive(a, SHZ_OK); receive(signal, SHZ_OK);
    now_ns = UINT64_C(0x123456789abcdef);
    request = identity(41, 1); a = send(SHZ_OP_PMA_QUERY, &request); pump(); receive_query(a);
    CHECK(fclose(samples) == 0); samples = NULL;
}

int main(int argc, char **argv)
{
    test_wire_and_notification_idempotence();
    test_full_tx_retains_completion_exactly_once();
    test_owner_death_completion_survives_full_tx();
    test_deadline_death_cancel_and_reuse();
    test_manual_reset_close_and_private_ownership();
    test_hostile_frames_and_epoch_restart();
    test_reserved_timeout_under_total_completion_pressure();
    test_automatic_token_is_not_counting();
    test_version_negotiation_and_initial_token();
    test_threaded_production_exchange();
    if (argc > 1) write_wire_samples(argv[1]);
    printf("PASS: PMA production service over ABI rings (%lu checks; 2000 threaded WAIT/SIGNAL exchanges)\n", checks);
    return 0;
}
