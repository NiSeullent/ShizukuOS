/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the complete production endpoint; only privileged hypercalls and
 * scheduler boundaries are replaced. A watchdog detects a missing boundary.
 */
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "../k32.h"
#include "../../abi/shz_ipc.h"

static uint64_t host_time_ns(void);
static long host_notify(unsigned domain, uint32_t mask);
static long host_set_vector(unsigned vector);
static uint32_t host_ack(void);
#define shz_time_ns host_time_ns
#define shz_notify host_notify
#define shz_set_doorbell_vector host_set_vector
#define shz_doorbell_ack host_ack
#include "../ipc.c"
#undef shz_time_ns
#undef shz_notify
#undef shz_set_doorbell_vector
#undef shz_doorbell_ack

static unsigned long checks;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
static uint8_t channel_storage[131072] __attribute__((aligned(4096)));
static uint8_t *channel_memory = channel_storage;
static size_t channel_bytes = sizeof channel_storage;
static unsigned fixture_service_mode;
static jmp_buf stop;
static unsigned waits, yields, acks, notifications, sleep_calls;
static unsigned pass_limit, refill;
static uint64_t next_request = 1;
static const uint64_t now_ns = UINT64_C(0x123456789abcdef0);

static void deadline(int sig)
{
    static const char message[] = "FAIL: production receive loop did not reach its next wait within 2 seconds\n";
    (void)sig;
    (void)write(STDERR_FILENO, message, sizeof message - 1);
    _Exit(124);
}

void kpanic(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void sem_init(ksem_t *s, int count) { s->count = count; s->waiters = NULL; }
void sem_post(ksem_t *s) { ++s->count; }
int sem_wait_timeout(ksem_t *s, uint32_t ms)
{
    CHECK(s == &doorbell_sem && ms == 20);
    if (++waits > pass_limit)
        longjmp(stop, 1);
    if (s->count > 0) {
        --s->count;                            /* queued doorbells make this wait return immediately */
        return 0;
    }
    return -1;
}
void thread_yield(void) { ++yields; }
void thread_sleep_ms(uint32_t ms) { CHECK(ms == 1); ++sleep_calls; }
static long host_set_vector(unsigned vector) { CHECK(vector == VEC_DOORBELL); return 0; }
static uint64_t host_time_ns(void) { return now_ns; }
static uint32_t host_ack(void) { ++acks; return 1; }

static void enqueue(uint32_t opcode, const void *payload, uint16_t length)
{
    shz_msg_hdr_t h = {0};
    h.opcode = opcode;
    h.request_id = next_request++;
    h.src_domain = SHZ_DOM_KERNEL64;
    h.dst_domain = SHZ_DOM_KERNEL32;
    h.generation = 7;
    h.payload_length = length;
    h.capability_id = 0x1234;
    CHECK(shz_ring_push(rx, &h, payload) == SHZ_OK);
}

static long host_notify(unsigned domain, uint32_t mask)
{
    CHECK(domain == SHZ_DOM_KERNEL64 && mask == 1);
    ++notifications;
    if (refill) {
        shz_msg_hdr_t reply_header;
        uint8_t payload[SHZ_MSG_MAX_INLINE];
        int reason;
        /* Model the compliant peer consuming each real reply and publishing
         * another real request before the server resumes its receive loop. */
        CHECK(shz_ring_pop(tx, &reply_header, payload, sizeof payload, &reason) == SHZ_OK);
        CHECK(reply_header.opcode == OP_ECHO && reply_header.status == SHZ_OK);
        enqueue(OP_ECHO, "x", 1);
        ipc_doorbell_irq();
    }
    return SHZ_OK;
}

static void setup(void)
{
    shz_bootinfo_t bi = {0};
    bi.magic = SHZ_BOOTINFO_MAGIC;
    bi.abi_major = SHZ_ABI_MAJOR;
    bi.abi_minor = SHZ_ABI_MINOR;
    bi.size = sizeof bi;
    bi.domain_id = SHZ_DOM_KERNEL32;
    bi.generation = 7;
    if (fixture_service_mode) {
        channel_bytes = SHZ_IPC_REGION_SIZE;
        channel_memory = mmap((void *)(uintptr_t)SHZ_IPC_GPA_BASE, channel_bytes,
                              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        CHECK(channel_memory == (void *)(uintptr_t)SHZ_IPC_GPA_BASE);
        memcpy(bi.cmdline, K32_WIN98_SERVICE_CMDLINE, sizeof K32_WIN98_SERVICE_CMDLINE);
        bi.cmdline_size = sizeof K32_WIN98_SERVICE_CMDLINE - 1;
    }
    CHECK(shz_channel_init(channel_memory, channel_bytes, 0,
                          SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64, 8, 7) == SHZ_OK);
    bi.channel_count = 1;
    bi.channel[0].gpa = (uintptr_t)channel_memory;
    bi.channel[0].size = channel_bytes;
    bi.channel[0].peer_domain = SHZ_DOM_KERNEL64;
    CHECK(k32_boot_service_mode(&bi) == (int)fixture_service_mode);
    ipc_init(&bi);
    CHECK(persistent_service == (int)fixture_service_mode);
    served = proto_errors = refused_buffers = stale_msgs = doorbells = ipc_session_end = 0;
    waits = yields = acks = notifications = sleep_calls = refill = 0;
    next_request = 1;
}

static void run_passes(unsigned count)
{
    pass_limit = count;
    alarm(2);
    if (!setjmp(stop))
        ipc_server_thread(NULL);
    alarm(0);
    CHECK(waits == count + 1 && acks == count);
    CHECK(sleep_calls == 0);
}

static shz_msg_hdr_t receive_reply(void *payload, size_t capacity)
{
    shz_msg_hdr_t h;
    int reason;
    CHECK(shz_ring_pop(tx, &h, payload, capacity, &reason) == SHZ_OK);
    CHECK(reason == SHZ_PR_NONE && h.flags == SHZ_MSGF_REPLY);
    CHECK(h.src_domain == SHZ_DOM_KERNEL32 && h.dst_domain == SHZ_DOM_KERNEL64);
    CHECK(h.generation == 7 && h.capability_id == 0x1234);
    return h;
}

static void test_unconsumed_head(void)
{
    setup();
    rx->head = 9;                            /* eight slots, no legal ninth outstanding frame */
    run_passes(1);
    CHECK(rx->tail == 0 && rx->head == 9);
    CHECK(ipc_protocol_errors() == 1 && ipc_requests_served() == 0);
    CHECK(notifications == 0 && yields == 1);
}

static void test_invalid_metadata(const char *field)
{
    setup();
    enqueue(OP_ECHO, "abc", 3);
    if (!strcmp(field, "magic")) rx->magic = 0;
    else if (!strcmp(field, "slots")) rx->slot_count = 0;
    else rx->slot_size = 64;
    run_passes(1);
    CHECK(rx->tail == 0 && rx->head == 1);
    CHECK(ipc_protocol_errors() == 1 && ipc_requests_served() == 0);
    CHECK(notifications == 0 && yields == 1);
}

static void test_malformed_then_valid(void)
{
    char payload[3];
    shz_msg_hdr_t h;
    setup();
    enqueue(OP_ECHO, "bad", 3);
    shz_ring_slot(rx, 0)[0] ^= 1;             /* first slot is consumed, without a reply */
    enqueue(OP_ECHO, "abc", 3);
    run_passes(1);
    CHECK(rx->tail == 2 && rx->head == 2);
    CHECK(ipc_protocol_errors() == 1 && ipc_requests_served() == 1);
    h = receive_reply(payload, sizeof payload);
    CHECK(h.opcode == OP_ECHO && h.request_id == 2 && h.status == SHZ_OK);
    CHECK(h.payload_length == 3 && !memcmp(payload, "abc", 3));
    CHECK(notifications == 1);
}

static void test_refill_bound(void)
{
    setup();
    enqueue(OP_ECHO, "x", 1);
    refill = 1;
    run_passes(2);
    CHECK(ipc_requests_served() == 64);
    CHECK(rx->head - rx->tail == 1);
    CHECK(notifications == ipc_requests_served() && yields == 2);
    CHECK(ipc_protocol_errors() == 0 && tx->head == tx->tail);
    CHECK(ipc_doorbells() == notifications && doorbell_sem.count > 0);
}

static void test_normal(void)
{
    char echo[3];
    uint64_t time;
    shz_msg_hdr_t h;
    int reason;
    setup();
    enqueue(OP_ECHO, "abc", 3);
    enqueue(OP_TIME, NULL, 0);
    enqueue(OP_SESSION_END, NULL, 0);
    run_passes(1);
    CHECK(ipc_requests_served() == 3 && ipc_protocol_errors() == 0 && ipc_session_end == 1);
    h = receive_reply(echo, sizeof echo);
    CHECK(h.opcode == OP_ECHO && h.request_id == 1 && h.status == SHZ_OK);
    CHECK(h.payload_length == 3 && !memcmp(echo, "abc", 3));
    h = receive_reply(&time, sizeof time);
    CHECK(h.opcode == OP_TIME && h.request_id == 2 && h.status == SHZ_OK);
    CHECK(h.payload_length == sizeof time && time == UINT64_C(0x123456789abcdef0));
    h = receive_reply(NULL, 0);
    CHECK(h.opcode == OP_SESSION_END && h.request_id == 3 && h.status == SHZ_OK && h.payload_length == 0);
    CHECK(shz_ring_pop(tx, &h, NULL, 0, &reason) == SHZ_E_NOENT);
    CHECK(notifications == 3 && rx->tail == 3);
}

static void test_persistent_live(void)
{
    char payload[3];
    shz_msg_hdr_t h;
    setup();
    enqueue(OP_SESSION_END, NULL, 0);
    enqueue(OP_ECHO, "abc", 3);
    run_passes(1);
    CHECK(ipc_session_end == 0 && ipc_requests_served() == 2 && ipc_protocol_errors() == 0);
    h = receive_reply(NULL, 0);
    CHECK(h.opcode == OP_SESSION_END && h.request_id == 1 && h.status == SHZ_E_UNSUPPORTED);
    h = receive_reply(payload, sizeof payload);
    CHECK(h.opcode == OP_ECHO && h.request_id == 2 && h.status == SHZ_OK);
    CHECK(h.payload_length == 3 && !memcmp(payload, "abc", 3));
    CHECK(yields == 1 && notifications == 2 && rx->tail == 2);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    signal(SIGALRM, deadline);
    if (!strncmp(argv[1], "persistent-", 11)) { fixture_service_mode = 1; argv[1] += 11; }
    if (!strcmp(argv[1], "head")) test_unconsumed_head();
    else if (!strcmp(argv[1], "magic") || !strcmp(argv[1], "slots") || !strcmp(argv[1], "size"))
        test_invalid_metadata(argv[1]);
    else if (!strcmp(argv[1], "malformed")) test_malformed_then_valid();
    else if (!strcmp(argv[1], "refill")) test_refill_bound();
    else if (!strcmp(argv[1], "normal")) test_normal();
    else if (!strcmp(argv[1], "live")) test_persistent_live();
    else { fprintf(stderr, "unknown case: %s\n", argv[1]); return 2; }
    printf("Kernel32 IPC %s: %lu checks passed\n", argv[1], checks);
    return 0;
}
