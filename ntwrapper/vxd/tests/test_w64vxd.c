/* SPDX-License-Identifier: GPL-2.0-only -- original host tests for the VxD's WIN64 subsystem bridge.
 * The VMM page services, the Supervisor hypercalls and the physical mapping are bounded mocks; the
 * channel the VxD maps is a real shz_channel_init() region, so every frame it pushes is checked with
 * the very library Kernel64 uses (shizukudos/abi/shz_ipc.h) as the peer would. */
#include "../bridge.h"
#include "../../../shizukudos/abi/shz_ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, step, failure, locked, unlocks, writes, reads, protected_now, notifies, acks, abi_calls, chan_calls;
static void (*unlock_interleave)(void);
static uint32_t held_alias[3], held_pages[3], unlock_fail_mask, bad_alias, all_locks, all_checks, all_pin_calls;
static uint32_t last_unlocked[64], permission = 7, physical_xor, doorbell_pending = 0x5, hv_present = 1, abi_reply = (1u << 16) | 1u;
static uint32_t channel_gpa = 0xe0200000u, channel_peer = 4, map_fail;
static unsigned reenter_notify;
static uint32_t reenter_result;
static unsigned char buffers[3][8192];          /* user pages 0x500.. (output), 0x600.. (returned), 0x700.. (input) */
static uint8_t channel[SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "line %u: %s\n", (unsigned)__LINE__, #x); exit(1); } } while (0)
static int fail(void) { return ++step == failure; }
static uintptr_t enter(void *p) { (void)p; CHECK(!protected_now); protected_now = 1; return 0x202; }
static void leave(void *p, uintptr_t saved) { (void)p; CHECK(protected_now && saved == 0x202); protected_now = 0; }
static unsigned which_buffer(uint32_t page)
{
    if (page == 0x500 || page == 0xc1000) return 0;
    if (page == 0x600 || page == 0xc2000) return 1;
    CHECK(page == 0x700 || page == 0xc3000);
    return 2;
}
static uint32_t check_range(uint32_t page, uint32_t count, uint32_t flags)
{ CHECK(!protected_now && flags == 0 && count >= 1 && count <= 2); (void)which_buffer(page);++all_checks; return fail() ? count - 1 : count; }
static uint32_t lock_range(uint32_t page, uint32_t count, uint32_t flags)
{ CHECK(!protected_now && flags == NTWV_MAP_GLOBAL && count >= 1 && count <= 2); ++all_pin_calls; if (fail()) return 0; unsigned b=which_buffer(page); CHECK(!held_alias[b]); held_alias[b]=1;held_pages[b]=count; ++locked; ++all_locks; return 0xc1000000u + 0x1000000u * b + bad_alias; }
static uint32_t unlock_range(uint32_t page, uint32_t count, uint32_t flags)
{ unsigned b=which_buffer(page); CHECK(!protected_now && flags == NTWV_MAP_GLOBAL && locked > 0 && unlocks < 64 && held_alias[b] && held_pages[b]==count); last_unlocked[unlocks++] = page; if(unlock_interleave){void (*hook)(void)=unlock_interleave;unlock_interleave=0;hook();} int failed=fail(); if(failed || (unlock_fail_mask&(1u<<b)))return 0; --locked;held_alias[b]=0;return 1; }
static uint32_t ptes(uint32_t page, uint32_t count, uint32_t *out, uint32_t flags)
{
    unsigned i, b = which_buffer(page);
    CHECK(protected_now && flags == 0 && count >= 1 && count <= 2);
    if (fail()) return 0;
    for (i = 0; i < count; ++i) out[i] = 0x00100000u * (b + 1) + i * 4096u + (b == 2 ? (permission & 5u) : permission);
    if (page >= 0xc0000) out[0] ^= physical_xor;
    return 1;
}
static void write_alias(uint32_t address, const void *source, uint32_t bytes)
{ unsigned b = which_buffer(address >> 12); CHECK(protected_now && (address & 0xffff) + bytes <= 8192); ++writes; memcpy(buffers[b] + (address & 0xffff), source, bytes); }
static void read_alias(void *destination, uint32_t address, uint32_t bytes)
{ unsigned b = which_buffer(address >> 12); CHECK(protected_now && b == 2 && (address & 0xffff) + bytes <= 8192); ++reads; memcpy(destination, buffers[b] + (address & 0xffff), bytes); }
static int hypervisor_present(void) { return (int)hv_present; }
static void try_reenter(void);
static int32_t hcall(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx, uint32_t *ecx)
{
    CHECK(!protected_now);                      /* hypercalls never run inside the pinned-copy interval */
    switch (op) {
    case SHZ_HC_ABI_VERSION: ++abi_calls; if (ebx) *ebx = abi_reply; return SHZ_OK;
    case SHZ_HC_CHANNEL_INFO: ++chan_calls; if (a != 2) return SHZ_E_NOENT; if (ebx) *ebx = channel_gpa; if (ecx) *ecx = channel_peer; return SHZ_OK;
    case SHZ_HC_NOTIFY: CHECK(a == SHZ_DOM_KERNEL64 && b == 1); ++notifies; if (reenter_notify) try_reenter(); return SHZ_OK;
    case SHZ_HC_DOORBELL_ACK: ++acks; if (ebx) *ebx = doorbell_pending; doorbell_pending = 0; return SHZ_OK;
    default: return SHZ_E_UNSUPPORTED;
    }
}
static void *map_phys(uint32_t phys, uint32_t bytes)
{ CHECK(phys == channel_gpa && bytes == SHZ_IPC_REGION_SIZE); return map_fail ? 0 : channel; }
static const struct ntwv_pages ops = { check_range, lock_range, unlock_range, ptes, enter, leave, write_alias, read_alias };
static const struct ntwv_hv hv = { hypervisor_present, hcall, map_phys, 0 };
static void try_reenter(void)
{
    const struct ntwv_dioc nested = { .code = NTWV_IOCTL_W64_OPEN,
        .output = 0x00500ff0, .output_bytes = 64, .returned = 0x00600ffe };
    reenter_notify = 0;
    reenter_result = ntwv_dioc_ex(&nested, &ops, &hv);
    CHECK(reenter_result == NTWV_ERROR_BUSY);
}
static void reset(void)
{ CHECK(!locked); step = failure = unlocks = writes = reads = protected_now = 0; permission = 7; physical_xor = 0; memset(buffers, 0xa5, sizeof buffers); }

static shz_channel_hdr_t *chdr(void) { return (shz_channel_hdr_t *)channel; }
static shz_ring_hdr_t *k64_rx(void) { return shz_channel_ring_rx(channel, chdr(), SHZ_DOM_KERNEL64); }
static shz_ring_hdr_t *k64_tx(void) { return shz_channel_ring_tx(channel, chdr(), SHZ_DOM_KERNEL64); }

/* One DeviceIoControl as VWIN32 would deliver it: input at user 0x00700ff0.., output at 0x00500ff0, count at 0x00600ffe. */
static uint32_t dioc(uint32_t code, const void *in, uint32_t in_bytes, uint32_t out_bytes, void *out, uint32_t *returned)
{
    struct ntwv_dioc request = { 0 };
    uint32_t result;
    step = unlocks = writes = reads = protected_now = 0;    /* per-call counters; `failure` etc. stay */
    request.code = code;
    request.output = 0x00500ff0; request.output_bytes = out_bytes; request.returned = 0x00600ffe;
    if (in_bytes) {                             /* an oversize count is rejected before any byte is read */
        request.input = 0x00700ff0; request.input_bytes = in_bytes;
        memcpy(buffers[2] + 0xff0, in, in_bytes > NTWV_W64_SEND_MAX ? NTWV_W64_SEND_MAX : in_bytes);
    }
    result = ntwv_dioc_ex(&request, &ops, &hv);
    if (out) memcpy(out, buffers[0] + 0xff0, out_bytes);
    if (returned) memcpy(returned, buffers[1] + 0xffe, 4);
    return result;
}

static void k64_reply(uint64_t request_id, uint32_t opcode, int32_t status, const void *payload, uint16_t len)
{
    shz_msg_hdr_t h;
    memset(&h, 0, sizeof h);
    h.flags = SHZ_MSGF_REPLY; h.opcode = opcode; h.request_id = request_id; h.src_domain = SHZ_DOM_KERNEL64;
    h.dst_domain = SHZ_DOM_WIN98; h.generation = chdr()->generation; h.status = status; h.payload_length = len;
    CHECK(shz_ring_push(k64_tx(), &h, payload) == SHZ_OK);
}

static void regression_begin(void)
{
    const struct ntw_lock_ops locks = { enter, leave, 0 };
    ntwv_w64_reset();
    reset();
    hv_present = 1; abi_reply = (1u << 16) | 1u; channel_peer = SHZ_DOM_KERNEL64; map_fail = 0;
    reenter_notify = 0; reenter_result = 0;
    CHECK(shz_channel_init(channel, sizeof channel, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    CHECK(ntwv_initialize(&locks));
}

static void regression_open(void)
{
    struct ntwv_w64_open info;
    reset();
    CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == 0);
}

static shz_msg_hdr_t regression_pool_request(void)
{
    shz_msg_hdr_t request = { 0 }, received;
    uint8_t frame[65], payload[SHZ_MSG_MAX_INLINE];
    int32_t status;
    int reason;
    request.opcode = SHZ_OP_W64_CREATE_PROCESS; request.request_id = 0x123456;
    memcpy(frame, &request, sizeof request); frame[64] = 'x';
    reset();
    CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, sizeof frame, 4, &status, 0) == 0);
    CHECK(shz_ring_pop(k64_rx(), &received, payload, sizeof payload, &reason) == SHZ_OK);
    CHECK(shz_pool_check(channel, chdr(), &received, SHZ_DOM_WIN98) == SHZ_OK);
    return received;
}

static void regression(const char *name)
{
    uint8_t slot[SHZ_MSG_SLOT_SIZE];
    struct ntwv_w64_open info;
    shz_msg_hdr_t request, response = { 0 };
    regression_begin();
    if (!strcmp(name, "layout")) {
        const shz_channel_hdr_t saved = *chdr();
        const shz_ring_hdr_t saved_tx = *k64_tx(), saved_rx = *k64_rx();
        unsigned i;
        for (i = 0; i < 10; ++i) {
            *chdr() = saved;
            *k64_tx() = saved_tx;
            *k64_rx() = saved_rx;
            switch (i) {
            case 0: chdr()->channel_id = 1; break;
            case 1: chdr()->generation = 0; break;
            case 2: chdr()->ring_ba_offset = chdr()->ring_ab_offset; break;
            case 3: chdr()->pool_offset = chdr()->ring_ab_offset; break;
            case 4: chdr()->slot_count = 64; break; /* disagrees with actual rings */
            case 5: chdr()->pool_size = SHZ_IPC_REGION_SIZE; break;
            case 6: chdr()->ring_ab_offset = 64; break; /* overlaps header/owner table */
            case 7: chdr()->pool_size -= 1; break;
            case 8: k64_tx()->magic = 0; break; /* actual mapped ring, not the header snapshot */
            default: k64_rx()->slot_size = SHZ_MSG_SLOT_SIZE / 2; break;
            }
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == NTWV_ERROR_GEN_FAILURE);
            CHECK(writes == 0 && !locked);
            ntwv_w64_reset();
        }
        *chdr() = saved;
        *k64_tx() = saved_tx;
        *k64_rx() = saved_rx;
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == 0);
    } else {
        regression_open();
        if (!strcmp(name, "reentrant")) {
            uint8_t frame[64];
            int32_t status;
            response.opcode = SHZ_OP_W64_QUERY; response.request_id = 1;
            memcpy(frame, &response, sizeof response);
            reenter_notify = 1;
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, sizeof frame, 4, &status, 0) == 0);
            CHECK(reenter_result == NTWV_ERROR_BUSY);
            CHECK(!locked && !protected_now);
            regression_open(); /* ownership was released on success */
        } else if (!strcmp(name, "epoch")) {
            request = regression_pool_request();
            chdr()->generation = 2;
            k64_reply(request.request_id, request.opcode, SHZ_OK, 0, 0);
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot, 0) == NTWV_ERROR_DEV_NOT_EXIST);
            CHECK(!writes && shz_ring_count(k64_tx()) == 1);
            CHECK(shz_pool_check(channel, chdr(), &request, SHZ_DOM_WIN98) == SHZ_OK);
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == NTWV_ERROR_DEV_NOT_EXIST);
            ntwv_w64_reset(); /* never releases a buffer from the new epoch */
            CHECK(shz_pool_check(channel, chdr(), &request, SHZ_DOM_WIN98) == SHZ_OK);
            regression_open();
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == 0 && info.generation == 2);
        } else if (!strcmp(name, "live-layout")) {
            const uint64_t saved = chdr()->ring_ab_offset;
            chdr()->ring_ab_offset += 64; /* still in range, but no longer the opened layout */
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot, 0) == NTWV_ERROR_GEN_FAILURE);
            CHECK(!writes);
            chdr()->ring_ab_offset = saved;
        } else if (!strcmp(name, "duplicate")) {
            uint8_t frame[65];
            int32_t status;
            request = regression_pool_request();
            response.opcode = request.opcode; response.request_id = request.request_id;
            memcpy(frame, &response, sizeof response); frame[64] = 'y';
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, sizeof frame, 4, &status, 0) == NTWV_ERROR_BUSY);
            CHECK(shz_ring_count(k64_rx()) == 0 && !writes);
        } else if (!strcmp(name, "corrupt-head")) {
            shz_ring_hdr_t *ring = k64_tx();
            ring->head = ring->tail + ring->slot_count + 1;
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot, 0) == NTWV_ERROR_GEN_FAILURE);
            CHECK(!writes && !locked);
        } else if (!strcmp(name, "corrupt-ring")) {
            k64_tx()->slot_count = 0x80000000u;
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot, 0) == NTWV_ERROR_GEN_FAILURE);
            CHECK(!writes && !locked);
        } else if (!strcmp(name, "responses")) {
            unsigned i;
            request = regression_pool_request();
            for (i = 0; i < 7; ++i) {
                memset(&response, 0, sizeof response);
                response.flags = SHZ_MSGF_REPLY; response.opcode = request.opcode;
                response.request_id = request.request_id; response.generation = 1;
                response.src_domain = SHZ_DOM_KERNEL64; response.dst_domain = SHZ_DOM_WIN98;
                switch (i) {
                case 0: response.generation = 2; break;
                case 1: response.src_domain = SHZ_DOM_KERNEL32; break;
                case 2: response.dst_domain = SHZ_DOM_KERNEL32; break;
                case 3: response.opcode = SHZ_OP_W64_QUERY; break;
                case 4: response.flags |= SHZ_MSGF_ONEWAY; break;
                case 5: response.flags |= SHZ_MSGF_CANCEL; break;
                default: response.flags |= SHZ_MSGF_BUFFER; response.buffer_length = 1; response.buffer_offset = request.buffer_offset; break;
                }
                CHECK(shz_ring_push(k64_tx(), &response, 0) == SHZ_OK);
                reset();
                CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot, 0) == NTWV_ERROR_NO_MORE_ITEMS);
                CHECK(!writes && shz_pool_check(channel, chdr(), &request, SHZ_DOM_WIN98) == SHZ_OK);
                reset();
                CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == 0 && info.pending_pool == 1);
            }
            k64_reply(request.request_id, request.opcode, SHZ_OK, 0, 0);
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, sizeof slot, slot, 0) == 0);
            CHECK(shz_pool_check(channel, chdr(), &request, SHZ_DOM_WIN98) == SHZ_E_DENIED);
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, 0) == 0 && info.pending_pool == 0 && info.proto_errors == 7);
        } else {
            CHECK(!"unknown regression");
        }
    }
    ntwv_w64_reset();
    CHECK(ntwv_shutdown());
    printf("PASS: VxD WIN64 regression %s %u assertions\n", name, checks);
}

int main(int argc, char **argv)
{
    const struct ntw_lock_ops locks = { enter, leave, 0 };
    struct ntwv_w64_open info;
    uint32_t returned, total;
    uint8_t frame[NTWV_W64_SEND_MAX], slot[SHZ_MSG_SLOT_SIZE];
    shz_msg_hdr_t h, got;
    uint8_t pl[SHZ_MSG_MAX_INLINE];
    int32_t status;
    int reason;

    if (argc == 2) { regression(argv[1]); return 0; }

    CHECK(shz_channel_init(channel, sizeof channel, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    CHECK(ntwv_initialize(&locks));
    reset();
    /* 1. OPEN maps the channel the Supervisor names and reports it */
    CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == 0);
    CHECK(returned == sizeof info && info.magic == NTWV_W64_MAGIC && info.size == 64 && info.abi_major == 1 && info.abi_minor == 1);
    CHECK(info.channel_id == 2 && info.self_domain == SHZ_DOM_WIN98 && info.peer_domain == SHZ_DOM_KERNEL64 && info.generation == 1);
    CHECK(info.slot_count == 32 && info.pool_bytes == chdr()->pool_size && info.sent == 0 && info.received == 0 && info.pending_pool == 0);
    CHECK(abi_calls == 1 && chan_calls == 3 && !locked && unlocks == 2 && writes == 2 && !reads);
    reset();
    CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == 0 && abi_calls == 1);   /* idempotent */
    CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info - 1, 0, 0) == NTWV_ERROR_INSUFFICIENT_BUFFER);

    /* 2. SEND a QUERY: the VxD owns src/dst/generation, pushes a CRC-valid slot, rings the doorbell */
    memset(&h, 0, sizeof h);
    h.opcode = SHZ_OP_W64_QUERY; h.request_id = 0x1234; h.src_domain = 99; h.dst_domain = 99; h.generation = 77;
    h.flags = SHZ_MSGF_BUFFER; h.buffer_offset = 0xdead; h.buffer_length = 5;   /* spoof attempt: stripped */
    memcpy(frame, &h, sizeof h);
    reset();
    CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 64, 4, &status, &returned) == 0 && status == SHZ_OK && returned == 4);
    CHECK(reads == 1 && writes == 2 && notifies == 1 && !locked && unlocks == 3);
    CHECK(last_unlocked[0] == 0xc2000 && last_unlocked[1] == 0xc1000 && last_unlocked[2] == 0xc3000);   /* reverse order */
    CHECK(shz_ring_pop(k64_rx(), &got, pl, sizeof pl, &reason) == SHZ_OK);
    CHECK(got.opcode == SHZ_OP_W64_QUERY && got.request_id == 0x1234 && got.src_domain == SHZ_DOM_WIN98 &&
          got.dst_domain == SHZ_DOM_KERNEL64 && got.generation == 1 && !(got.flags & SHZ_MSGF_BUFFER) &&
          got.buffer_length == 0 && got.buffer_offset == 0 && got.abi_minor == 1);

    /* 3. RECV: empty ring, then the reply, then empty again */
    reset();
    CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == NTWV_ERROR_NO_MORE_ITEMS && writes == 0);
    {
        shz_w64_info_t wi;
        memset(&wi, 0, sizeof wi);
        wi.abi_major = 1; wi.abi_minor = 1; wi.max_processes = 4;
        k64_reply(0x1234, SHZ_OP_W64_QUERY, SHZ_OK, &wi, sizeof wi);
    }
    reset();
    CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == 0 && returned == SHZ_MSG_SLOT_SIZE);
    memcpy(&got, slot, sizeof got);
    CHECK(got.opcode == SHZ_OP_W64_QUERY && got.request_id == 0x1234 && (got.flags & SHZ_MSGF_REPLY) && got.payload_length == sizeof(shz_w64_info_t));
    CHECK(((shz_w64_info_t *)(slot + 64))->max_processes == 4 && slot[255] == 0);
    CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == NTWV_ERROR_NO_MORE_ITEMS);

    /* 4. SEND with inline payload and trailing pool data: block allocated to WIN98, freed by the reply */
    {
        shz_w64_create_t ch;
        uint16_t block[1000];
        unsigned i;
        for (i = 0; i < 1000; ++i) block[i] = (uint16_t)('a' + i % 26);
        memset(&ch, 0, sizeof ch);
        ch.path_chars = 10; ch.cmdline_chars = 990; ch.block_bytes = 2000;
        memset(&h, 0, sizeof h);
        h.opcode = SHZ_OP_W64_CREATE_PROCESS; h.request_id = 0x2222; h.payload_length = sizeof ch;
        memcpy(frame, &h, sizeof h); memcpy(frame + 64, &ch, sizeof ch); memcpy(frame + 64 + sizeof ch, block, 2000);
        total = 64 + (uint32_t)sizeof ch + 2000;
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, total, 4, &status, &returned) == 0 && status == SHZ_OK);
        CHECK(shz_ring_pop(k64_rx(), &got, pl, sizeof pl, &reason) == SHZ_OK);
        CHECK((got.flags & SHZ_MSGF_BUFFER) && got.buffer_length == 2000 && got.payload_length == sizeof ch);
        {
            shz_w64_create_t seen;
            const uint16_t *blk;
            CHECK(shz_w64_create_check(&got, pl, chdr(), channel, &seen, &blk) == SHZ_OK);   /* exactly what Kernel64 runs */
            CHECK(seen.cmdline_chars == 990 && !memcmp(blk, block, 2000));
            CHECK(shz_pool_check(channel, chdr(), &got, SHZ_DOM_WIN98) == SHZ_OK);
        }
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == 0 && info.pending_pool == 1 && info.sent == 2);
        k64_reply(0x2222, SHZ_OP_W64_CREATE_PROCESS, SHZ_OK, 0, 0);
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == 0);
        CHECK(shz_pool_check(channel, chdr(), &got, SHZ_DOM_WIN98) == SHZ_E_DENIED);      /* released: no longer owned */
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == 0 && info.pending_pool == 0 && info.received == 2);
        /* four outstanding pool blocks are the limit; a one-way frame may not carry pool data */
        for (i = 0; i < NTWV_W64_PENDING_POOL; ++i) {
            h.request_id = 0x3000 + i; memcpy(frame, &h, sizeof h);
            reset();
            CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, total, 4, &status, &returned) == 0);
        }
        h.request_id = 0x3999; memcpy(frame, &h, sizeof h);
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, total, 4, &status, &returned) == NTWV_ERROR_BUSY);
        h.flags = SHZ_MSGF_ONEWAY; memcpy(frame, &h, sizeof h);
        for (i = 0; i < NTWV_W64_PENDING_POOL; ++i) k64_reply(0x3000 + i, SHZ_OP_W64_CREATE_PROCESS, SHZ_OK, 0, 0);
        for (i = 0; i < NTWV_W64_PENDING_POOL; ++i) { reset(); CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == 0); }
        while (shz_ring_pop(k64_rx(), &got, pl, sizeof pl, &reason) != SHZ_E_NOENT) { }
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, total, 4, &status, &returned) == NTWV_ERROR_BUSY);
        h.flags = 0;
    }

    /* 5. malformed SEND input never reaches the ring */
    memset(&h, 0, sizeof h);
    h.opcode = SHZ_OP_W64_QUERY; h.request_id = 5; h.payload_length = SHZ_MSG_MAX_INLINE + 1;
    memcpy(frame, &h, sizeof h);
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 64 + 193, 4, &status, &returned) == NTWV_ERROR_INVALID_PARAMETER && notifies == 1 + 5);
    h.payload_length = 40; memcpy(frame, &h, sizeof h);
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 64 + 20, 4, &status, &returned) == NTWV_ERROR_INVALID_PARAMETER);   /* shorter than declared */
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 63, 4, &status, &returned) == NTWV_ERROR_INVALID_PARAMETER && !step);
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, NTWV_W64_SEND_MAX + 1, 4, &status, &returned) == NTWV_ERROR_INVALID_PARAMETER && !step);
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 64, 3, &status, &returned) == NTWV_ERROR_INSUFFICIENT_BUFFER && !step);
    CHECK(shz_ring_count(k64_rx()) == 0);

    /* 6. RECV drops malformed slots (counted) and returns the next good frame */
    {
        shz_ring_hdr_t *r = k64_tx();
        uint8_t *bad;
        k64_reply(0x77, SHZ_OP_W64_QUERY, SHZ_OK, 0, 0);
        bad = shz_ring_slot(r, r->head - 1);
        bad[0x18] ^= 1;                                      /* request id bit flip: CRC mismatch */
        k64_reply(0x78, SHZ_OP_W64_QUERY, SHZ_OK, 0, 0);
        bad = shz_ring_slot(r, r->head - 1);
        *(uint16_t *)(bad + 4) = 9;                          /* foreign ABI major */
        k64_reply(0x79, SHZ_OP_W64_QUERY, SHZ_E_STALE, 0, 0);
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == 0);
        memcpy(&got, slot, sizeof got);
        CHECK(got.request_id == 0x79 && got.status == SHZ_E_STALE);
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == 0 && info.proto_errors == 2);
    }

    /* 7. WAIT acknowledges the doorbell and reports the mask; a full transmit ring is BUSY */
    {
        uint32_t mask = 0, i;
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_WAIT, &(uint32_t){100}, 4, 4, &mask, &returned) == 0 && mask == 5 && acks == 1 && returned == 4);
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_WAIT, &(uint32_t){100}, 4, 4, &mask, &returned) == 0 && mask == 0);
        reset(); CHECK(dioc(NTWV_IOCTL_W64_WAIT, &(uint32_t){100}, 3, 4, &mask, &returned) == NTWV_ERROR_INVALID_PARAMETER);
        memset(&h, 0, sizeof h);
        h.opcode = SHZ_OP_W64_QUERY;
        for (i = 0; i < 32; ++i) { h.request_id = 100 + i; memcpy(frame, &h, sizeof h); reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 64, 4, &status, &returned) == 0); }
        reset();
        CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 64, 4, &status, &returned) == NTWV_ERROR_BUSY);
        for (i = 0; i < 32; ++i) CHECK(shz_ring_pop(k64_rx(), &got, pl, sizeof pl, &reason) == SHZ_OK && got.request_id == 100 + i);
    }

    /* 8. buffer policy for the new codes */
    {
        struct ntwv_dioc request = { 0 };
        request.code = NTWV_IOCTL_W64_SEND; request.input = 0x00700ff0; request.input_bytes = 64;
        request.output = 0x00500ff0; request.output_bytes = 4; request.returned = 0x00600ffe;
        reset(); request.overlapped = 1; CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_INVALID_PARAMETER && !step); request.overlapped = 0;
        reset(); request.returned = request.output + 2; CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_INVALID_PARAMETER && !step); request.returned = 0x00600ffe;
        reset(); request.input = request.output - 60; CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_INVALID_PARAMETER && !step); request.input = 0x00700ff0;
        reset(); request.input = 0x00300000; CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_INVALID_PARAMETER && !step); request.input = 0x00700ff0;
        reset(); request.output = 0x80000000; CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_INVALID_PARAMETER && !step); request.output = 0x00500ff0;
        reset(); request.code = NTWV_IOCTL_W64_OPEN; request.input_bytes = 0; CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_INVALID_PARAMETER && !step);   /* input pointer without bytes */
        request.input = 0; request.output_bytes = 64;
        reset(); CHECK(ntwv_dioc_ex(&request, &ops, 0) == NTWV_ERROR_NOT_SUPPORTED);       /* no hypervisor services bound */
        CHECK(ntwv_dioc(&request, &ops) == NTWV_ERROR_NOT_SUPPORTED);
        reset(); CHECK(ntwv_dioc_ex(&request, 0, &hv) == NTWV_ERROR_NOT_SUPPORTED);
        request.code = NTWV_IOCTL_W64_WAIT + 1;
        reset(); CHECK(ntwv_dioc_ex(&request, &ops, &hv) == NTWV_ERROR_NOT_SUPPORTED);
    }

    /* 9. Failures keep every acquired alias owned until real release; a
     * failed unlock drains before the next admitted safe-copy request. */
    memset(&h, 0, sizeof h);
    h.opcode = SHZ_OP_W64_QUERY; h.request_id = 0x4444; h.payload_length = 8;
    memcpy(frame, &h, sizeof h); memcpy(frame + 64, "payload!", 8);
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 72, 4, &status, &returned) == 0); total = step;
    CHECK(shz_ring_pop(k64_rx(), &got, pl, sizeof pl, &reason) == SHZ_OK && got.payload_length == 8 && !memcmp(pl, "payload!", 8));
    {
        unsigned w;
        const uint32_t before = shz_ring_count(k64_rx());
        for (w = 1; w <= total; ++w) {
            reset(); failure = w;
            CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 72, 4, &status, &returned) == NTWV_ERROR_NOACCESS);
            CHECK(!protected_now);
            if (w <= 12) CHECK(writes == 0 && reads == 0);   /* 3 x (check, lock) + 6 PTE lookups precede the copy */
            if(locked) {failure=0;CHECK(dioc(NTWV_IOCTL_QUERY,0,0,32,0,0)==0 && !locked);}
        }
        /* 3 x (check, lock) + 6 PTE lookups precede the send; the 4 reply-side PTE lookups and 3 unlocks follow it, so
         * exactly those 7 failures leave a frame on the ring while still reporting NOACCESS (the error is authoritative) */
        CHECK(total == 19 && shz_ring_count(k64_rx()) - before == 7);
        while (shz_ring_pop(k64_rx(), &got, pl, sizeof pl, &reason) != SHZ_E_NOENT) { }
    }
    reset(); permission = 5; CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 72, 4, &status, &returned) == NTWV_ERROR_NOACCESS && !reads && !locked);
    reset(); physical_xor = 0x1000; CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 72, 4, &status, &returned) == NTWV_ERROR_NOACCESS && !reads && !locked);
    CHECK(shz_ring_count(k64_rx()) == 0);

    /* 10. OPEN refusals: no hypervisor, wrong ABI major, no channel, mapping failure, foreign channel */
    ntwv_w64_reset();
    reset(); hv_present = 0; CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_NOT_SUPPORTED && writes == 0); hv_present = 1;
    reset(); abi_reply = 2u << 16; CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_REVISION_MISMATCH); abi_reply = (1u << 16) | 1u;
    reset(); channel_peer = SHZ_DOM_KERNEL32; CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_DEV_NOT_EXIST); channel_peer = SHZ_DOM_KERNEL64;
    reset(); map_fail = 1; CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_NOT_ENOUGH_MEMORY); map_fail = 0;
    chdr()->domain_b = SHZ_DOM_KERNEL32;
    reset(); CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_GEN_FAILURE);
    chdr()->domain_b = SHZ_DOM_WIN98;
    chdr()->magic ^= 1;
    reset(); CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_GEN_FAILURE);
    chdr()->magic ^= 1;
    reset(); CHECK(dioc(NTWV_IOCTL_W64_SEND, frame, 72, 4, &status, &returned) == NTWV_ERROR_NOT_READY);   /* not open */
    reset(); CHECK(dioc(NTWV_IOCTL_W64_RECV, 0, 0, SHZ_MSG_SLOT_SIZE, slot, &returned) == NTWV_ERROR_NOT_READY);
    reset(); CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == 0 && info.sent == 0);
    CHECK(ntwv_shutdown());
    reset(); CHECK(dioc(NTWV_IOCTL_W64_OPEN, 0, 0, sizeof info, &info, &returned) == NTWV_ERROR_NOT_READY);
    printf("PASS: VxD WIN64 bridge %u assertions; frames validated with the Kernel64 library; failed aliases retained until real release\n", checks);
    return 0;
}
