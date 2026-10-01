/* SPDX-License-Identifier: GPL-2.0-only -- independently authored service tests. */
#include "../service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "line %u: %s\n", (unsigned)__LINE__, #x); exit(1); } } while (0)
static shz_pma_service_t service;
static uint64_t sequence;
static shz_pma_request_t request;
static shz_msg_hdr_t message;

static void setup(void)
{
    CHECK(shz_pma_service_init(&service, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 7) == SHZ_OK);
    sequence = 0;
}

static void prepare(uint32_t opcode, uint32_t pid, uint32_t tid)
{
    memset(&request, 0, sizeof request);
    request.magic = SHZ_PMA_MAGIC;
    request.abi_major = SHZ_PMA_ABI_MAJOR;
    request.abi_minor = SHZ_PMA_ABI_MINOR;
    request.size = sizeof request;
    request.domain = SHZ_DOM_WIN98;
    request.pid = pid;
    request.tid = tid;
    request.owner_generation = request.thread_generation = 1;
    memset(&message, 0, sizeof message);
    message.magic = SHZ_MSG_MAGIC;
    message.abi_major = SHZ_ABI_MAJOR;
    message.abi_minor = SHZ_ABI_MINOR;
    message.header_size = sizeof message;
    message.message_size = sizeof message + sizeof request;
    message.opcode = opcode;
    message.src_domain = SHZ_DOM_WIN98;
    message.dst_domain = SHZ_DOM_KERNEL64;
    message.generation = 7;
    message.request_id = ++sequence;
    message.payload_offset = sizeof message;
    message.payload_length = sizeof request;
}

static shz_pma_completion_t take(uint64_t id, int32_t status)
{
    const shz_pma_frame_t *frame = shz_pma_service_peek(&service);
    shz_pma_completion_t result;
    CHECK(frame && frame->header.request_id == id && frame->header.status == status);
    CHECK(frame->header.flags == SHZ_MSGF_REPLY && frame->header.generation == 7);
    CHECK(frame->header.src_domain == SHZ_DOM_KERNEL64 && frame->header.dst_domain == SHZ_DOM_WIN98);
    memcpy(&result, frame->payload, sizeof result);
    CHECK(result.magic == SHZ_PMA_MAGIC && result.size == sizeof result);
    CHECK(result.sequence == id && result.status == status);
    CHECK(shz_pma_service_ack(&service, id) == SHZ_OK);
    return result;
}

static uint32_t create(uint32_t flags)
{
    shz_pma_completion_t result;
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11);
    request.flags = flags;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    result = take(sequence, SHZ_OK);
    CHECK(result.object != 0);
    return result.object;
}

static uint64_t wait_event(uint32_t handle, uint32_t tid, uint64_t deadline)
{
    prepare(SHZ_OP_PMA_EVENT_WAIT, 10, tid);
    request.object = handle;
    request.deadline_ns = deadline;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    return sequence;
}

static uint64_t event_op(uint32_t opcode, uint32_t handle)
{
    prepare(opcode, 10, 11);
    request.object = handle;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    return sequence;
}

static void test_auto_event_retains_one_token_and_wakes_oldest(void)
{
    uint32_t object;
    uint64_t a, b, signal;
    setup(); object = create(0);
    a = wait_event(object, 11, UINT64_MAX);
    b = wait_event(object, 12, UINT64_MAX);
    CHECK(!shz_pma_service_peek(&service));
    signal = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object);
    take(a, SHZ_OK); take(signal, SHZ_OK);
    CHECK(!shz_pma_service_peek(&service));
    signal = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object);
    take(b, SHZ_OK); take(signal, SHZ_OK);
    signal = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object); take(signal, SHZ_OK);
    signal = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object); take(signal, SHZ_OK);
    a = wait_event(object, 11, 0); take(a, SHZ_OK);
    b = wait_event(object, 11, 0); take(b, SHZ_E_TIMEOUT);
}

static void test_manual_event_reset_close_and_handle_generation(void)
{
    uint32_t object, replacement;
    uint64_t a, b, op;
    setup(); object = create(SHZ_PMA_EVENT_MANUAL_RESET);
    a = wait_event(object, 11, UINT64_MAX); b = wait_event(object, 12, UINT64_MAX);
    op = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object);
    take(a, SHZ_OK); take(b, SHZ_OK); take(op, SHZ_OK);
    a = wait_event(object, 11, 0); take(a, SHZ_OK);
    op = event_op(SHZ_OP_PMA_EVENT_RESET, object); take(op, SHZ_OK);
    a = wait_event(object, 11, 0); take(a, SHZ_E_TIMEOUT);
    a = wait_event(object, 11, UINT64_MAX);
    op = event_op(SHZ_OP_PMA_EVENT_CLOSE, object); take(a, SHZ_E_CANCELLED); take(op, SHZ_OK);
    replacement = create(0); CHECK(replacement != object);
    op = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object); take(op, SHZ_E_NOENT);
}

static void test_timeout_cancellation_and_thread_death(void)
{
    uint32_t object;
    uint64_t a, op;
    setup(); object = create(0);
    a = wait_event(object, 11, 200);
    CHECK(shz_pma_service_tick(&service, 199) == 0);
    CHECK(shz_pma_service_tick(&service, 200) == 1); take(a, SHZ_E_TIMEOUT);
    a = wait_event(object, 12, UINT64_MAX);
    prepare(SHZ_OP_PMA_CANCEL, 10, 12); request.target_sequence = a;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 200) == SHZ_OK);
    op = sequence; take(a, SHZ_E_CANCELLED); take(op, SHZ_OK);
    a = wait_event(object, 12, UINT64_MAX);
    prepare(SHZ_OP_PMA_THREAD_EXIT, 10, 12);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 200) == SHZ_OK);
    op = sequence; take(a, SHZ_E_CANCELLED); take(op, SHZ_OK);
    prepare(SHZ_OP_PMA_EVENT_WAIT, 10, 12); request.object = object; request.deadline_ns = UINT64_MAX;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 200) == SHZ_E_STALE);
    request.thread_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 200) == SHZ_OK);
    CHECK(!shz_pma_service_peek(&service));
}

static void test_process_ownership_exit_and_epoch(void)
{
    uint32_t object;
    uint64_t a, op;
    setup(); object = create(0); a = wait_event(object, 12, UINT64_MAX);
    prepare(SHZ_OP_PMA_EVENT_SIGNAL, 20, 21); request.object = object;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_E_DENIED);
    prepare(SHZ_OP_PMA_PROCESS_EXIT, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    op = sequence; take(a, SHZ_E_CANCELLED); take(op, SHZ_OK);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    request.owner_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    CHECK(take(sequence, SHZ_OK).object != object);
}

static void test_protocol_and_duplicate_rejection_without_mutation(void)
{
    uint32_t object;
    uint64_t op;
    setup(); object = create(0);
    op = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    take(op, SHZ_OK);
    prepare(SHZ_OP_PMA_EVENT_RESET, 10, 11); request.object = object;
    message.generation = 6;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    message.generation = 7; request.required_features = UINT64_C(1) << 63;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_UNSUPPORTED);
    request.required_features = 0; request.domain = SHZ_DOM_KERNEL32;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_DENIED);
    request.domain = SHZ_DOM_WIN98; message.flags = SHZ_MSGF_ONEWAY;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_PROTO);
    CHECK(!shz_pma_service_peek(&service));
}

static void test_completion_backpressure_keeps_waits_and_retry_id(void)
{
    uint32_t object;
    unsigned i;
    uint64_t waiting, first, blocked;
    const shz_pma_frame_t *frame;
    setup(); object = create(0);
    waiting = wait_event(object, 11, 200);
    first = sequence + 1;
    for (i = 1; i < SHZ_PMA_MAX_COMPLETIONS; ++i) {
        prepare(SHZ_OP_PMA_QUERY, 10, 11);
        CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    }
    prepare(SHZ_OP_PMA_EVENT_SIGNAL, 10, 11); request.object = object; blocked = sequence;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_QUEUE_FULL);
    CHECK(shz_pma_service_tick(&service, 200) == 1);
    frame = shz_pma_service_peek(&service); CHECK(frame && frame->header.request_id == first);
    CHECK(shz_pma_service_ack(&service, blocked) == SHZ_E_NOENT);
    CHECK(shz_pma_service_ack(&service, first) == SHZ_OK);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 200) == SHZ_OK);
    for (i = 2; i < SHZ_PMA_MAX_COMPLETIONS; ++i) {
        frame = shz_pma_service_peek(&service); CHECK(frame && frame->header.request_id == first + i - 1);
        CHECK(shz_pma_service_ack(&service, frame->header.request_id) == SHZ_OK);
    }
    take(waiting, SHZ_E_TIMEOUT); take(blocked, SHZ_OK);
    CHECK(!shz_pma_service_peek(&service));
}

static void test_infinite_wait_saturation_preserves_control_headroom(void)
{
    uint32_t object;
    uint64_t first, overflow, signal;
    unsigned i;
    setup(); object = create(0); first = sequence + 1;
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i) wait_event(object, 11, UINT64_MAX);
    CHECK(!shz_pma_service_peek(&service));
    overflow = wait_event(object, 11, UINT64_MAX); take(overflow, SHZ_E_BUSY);
    signal = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object);
    take(first, SHZ_OK); take(signal, SHZ_OK);
    for (i = 1; i < SHZ_PMA_MAX_WAITS; ++i) {
        signal = event_op(SHZ_OP_PMA_EVENT_SIGNAL, object);
        take(first + i, SHZ_OK); take(signal, SHZ_OK);
    }
    CHECK(!shz_pma_service_peek(&service));
}

static void test_process_thread_tombstones_and_object_retirement_bounds(void)
{
    uint32_t objects[SHZ_PMA_MAX_OBJECTS], retired;
    unsigned i;
    setup();
    for (i = 0; i < SHZ_PMA_MAX_OBJECTS; ++i) objects[i] = create(0);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    CHECK(take(sequence, SHZ_E_NOMEM).object == 0);
    for (i = 0; i < SHZ_PMA_MAX_OBJECTS; ++i) {
        event_op(SHZ_OP_PMA_EVENT_CLOSE, objects[i]); take(sequence, SHZ_OK);
    }
    /* An exhausted 16-bit generation retires rather than resurrecting a handle. */
    service.objects[0].generation = 0xffffu;
    retired = create(0); CHECK((retired & 0xffffu) == 2);
    setup();
    for (i = 0; i < SHZ_PMA_MAX_OWNERS; ++i) {
        prepare(SHZ_OP_PMA_PROCESS_EXIT, 10 + i, 11);
        CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
        take(sequence, SHZ_OK);
    }
    prepare(SHZ_OP_PMA_QUERY, 100, 101);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_NOMEM);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11); request.owner_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_OK);
    setup();
    for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i) {
        prepare(SHZ_OP_PMA_THREAD_EXIT, 10, 11 + i);
        CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
        take(sequence, SHZ_OK);
    }
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 100);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_NOMEM);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11); request.thread_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_OK);
}

static void test_version_negotiation_identity_and_restart(void)
{
    const shz_pma_frame_t *frame;
    shz_pma_info_t info;
    uint64_t clock_snapshot;
    uint32_t object;
    setup(); prepare(SHZ_OP_PMA_QUERY, 10, 11); request.abi_minor = 65535;
    request.required_features = SHZ_PMA_FEATURE_EVENTS;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    frame = shz_pma_service_peek(&service); CHECK(frame && frame->header.opcode == SHZ_OP_PMA_QUERY);
    memcpy(&info, frame->payload, sizeof info);
    memcpy(&clock_snapshot, frame->payload + 40, sizeof clock_snapshot);
    CHECK(clock_snapshot == 100);
    CHECK(info.features == SHZ_PMA_FEATURES && SHZ_PMA_CLOCK_UNIT_NS == 1 && info.max_waits == SHZ_PMA_MAX_WAITS);
    CHECK(shz_pma_service_ack(&service, sequence) == SHZ_OK);
    object = create(0); wait_event(object, 11, UINT64_MAX);
    CHECK(shz_pma_service_restart(&service, 6) == SHZ_E_INVALID);
    CHECK(shz_pma_service_restart(&service, 7) == SHZ_E_INVALID);
    CHECK(shz_pma_service_restart(&service, 8) == SHZ_OK);
    CHECK(!shz_pma_service_peek(&service));
    prepare(SHZ_OP_PMA_EVENT_SIGNAL, 10, 11); request.object = object;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    setup(); prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11); message.request_id = UINT64_MAX;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK); take(UINT64_MAX, SHZ_OK);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
}

static void test_process_exit_after_last_thread_exit(void)
{
    uint32_t old_object, replacement;
    setup(); old_object = create(0);
    prepare(SHZ_OP_PMA_THREAD_EXIT, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_OK);
    prepare(SHZ_OP_PMA_PROCESS_EXIT, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_OK);
    CHECK(service.threads[0].state == 2); /* Rundown must not revive the dead thread. */
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    request.owner_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    replacement = take(sequence, SHZ_OK).object;
    CHECK((replacement & 0xffffu) == (old_object & 0xffffu) && replacement != old_object);
    prepare(SHZ_OP_PMA_EVENT_SIGNAL, 10, 11); request.owner_generation = 2; request.object = old_object;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_E_NOENT);
    prepare(SHZ_OP_PMA_PROCESS_EXIT, 10, 11); /* Original process epoch cannot kill its replacement. */
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    prepare(SHZ_OP_PMA_EVENT_SIGNAL, 10, 11); request.owner_generation = 2; request.object = replacement;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_OK);
}

static void test_process_exit_with_full_dead_thread_registry(void)
{
    uint32_t old_object;
    unsigned i;
    setup(); old_object = create(0);
    for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i) {
        prepare(SHZ_OP_PMA_THREAD_EXIT, 10, 11 + i);
        CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
        take(sequence, SHZ_OK);
    }
    prepare(SHZ_OP_PMA_PROCESS_EXIT, 10, 100); /* Notification does not need a new thread-table entry. */
    request.owner_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    request.owner_generation = 1;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_OK);
    for (i = 0; i < SHZ_PMA_MAX_THREADS; ++i) CHECK(service.threads[i].state == 2);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 100);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_STALE);
    request.owner_generation = 2;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    CHECK(take(sequence, SHZ_OK).object != old_object);
    prepare(SHZ_OP_PMA_EVENT_SIGNAL, 10, 100); request.owner_generation = 2; request.object = old_object;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    take(sequence, SHZ_E_NOENT);
}

static void test_shutdown_cancels_full_table_without_losing_ready_replies(void)
{
    uint32_t object;
    uint64_t first_wait, first_query;
    unsigned i;
    const shz_pma_frame_t *frame;
    shz_pma_completion_t c;
    setup(); object = create(0); first_wait = sequence + 1;
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i) wait_event(object, 11, UINT64_MAX);
    first_query = sequence + 1;
    for (i = 0; i < SHZ_PMA_MAX_COMPLETIONS - SHZ_PMA_MAX_WAITS; ++i) {
        prepare(SHZ_OP_PMA_QUERY, 10, 11);
        CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    }
    CHECK(shz_pma_service_shutdown(&service) == SHZ_OK);
    CHECK(shz_pma_service_shutdown(&service) == SHZ_OK);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11);
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_E_CANCELLED);
    for (i = 0; i < SHZ_PMA_MAX_COMPLETIONS - SHZ_PMA_MAX_WAITS; ++i) {
        frame = shz_pma_service_peek(&service);
        CHECK(frame && frame->header.request_id == first_query + i && frame->header.status == SHZ_OK);
        CHECK(shz_pma_service_ack(&service, frame->header.request_id) == SHZ_OK);
    }
    for (i = 0; i < SHZ_PMA_MAX_WAITS; ++i) take(first_wait + i, SHZ_E_CANCELLED);
    CHECK(!shz_pma_service_peek(&service));
    CHECK(shz_pma_service_tick(&service, UINT64_MAX) == 0);
    CHECK(shz_pma_service_shutdown(&service) == SHZ_OK && !shz_pma_service_peek(&service));
    CHECK(shz_pma_service_restart(&service, 8) == SHZ_OK);
    prepare(SHZ_OP_PMA_EVENT_CREATE, 10, 11); message.generation = 8; message.request_id = 1;
    CHECK(shz_pma_service_dispatch(&service, &message, &request, 100) == SHZ_OK);
    frame = shz_pma_service_peek(&service);
    CHECK(frame && frame->header.generation == 8 && frame->header.status == SHZ_OK);
    memcpy(&c, frame->payload, sizeof c);
    CHECK(c.object && c.sequence == 1);
    CHECK(shz_pma_service_ack(&service, 1) == SHZ_OK);
}

static void test_shutdown_preserves_terminal_success_and_invalid_state(void)
{
    uint32_t object;
    uint64_t complete, waiting;
    shz_pma_service_t uninitialized;
    memset(&uninitialized, 0, sizeof uninitialized);
    CHECK(shz_pma_service_shutdown(0) == SHZ_E_INVALID);
    CHECK(shz_pma_service_shutdown(&uninitialized) == SHZ_E_INVALID);
    setup(); object = create(SHZ_PMA_EVENT_SIGNALED);
    complete = wait_event(object, 11, 0);
    waiting = wait_event(object, 11, UINT64_MAX);
    CHECK(shz_pma_service_shutdown(&service) == SHZ_OK);
    take(complete, SHZ_OK); take(waiting, SHZ_E_CANCELLED);
    CHECK(!shz_pma_service_peek(&service));
}

int main(void)
{
    test_auto_event_retains_one_token_and_wakes_oldest();
    test_manual_event_reset_close_and_handle_generation();
    test_timeout_cancellation_and_thread_death();
    test_process_ownership_exit_and_epoch();
    test_protocol_and_duplicate_rejection_without_mutation();
    test_completion_backpressure_keeps_waits_and_retry_id();
    test_infinite_wait_saturation_preserves_control_headroom();
    test_process_thread_tombstones_and_object_retirement_bounds();
    test_version_negotiation_identity_and_restart();
    test_process_exit_with_full_dead_thread_registry();
    test_process_exit_after_last_thread_exit();
    test_shutdown_cancels_full_table_without_losing_ready_replies();
    test_shutdown_preserves_terminal_success_and_invalid_state();
    printf("PASS: PMA event service (%u checks)\n", checks);
    return 0;
}
