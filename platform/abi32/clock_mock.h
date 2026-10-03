/* SPDX-License-Identifier: GPL-2.0-only -- bounded native clock page/IO model.
 * Explicit MEMORY_BASIC_INFORMATION32: seven DWORDs, no Win64 PartitionId.
 * These are host models, not native Win98 VirtualQuery execution or pinning. */
#include "../../ntwrapper/vxd/bridge.h"
#include "../../shizukudos/abi/shz_clock.h"

struct clock_mbi32 {
    uint32_t base, allocation, allocation_protect, region_bytes, state, protect, type;
};
_Static_assert(sizeof(struct clock_mbi32) == 28, "native 32-bit memory query ABI");
_Static_assert(offsetof(struct clock_mbi32, region_bytes) == 12, "native RegionSize offset");
_Static_assert(offsetof(struct clock_mbi32, protect) == 20, "native Protect offset");
__attribute__((aligned(4096))) static unsigned char clock_storage[3 * 4096];
static uint32_t clock_testing, clock_owned, clock_open_calls, clock_io_calls, clock_close_calls, clock_vq_calls;
static uint32_t clock_open_error, clock_io_error, clock_close_error, clock_reply_mode, clock_mbi_mode;
static uint32_t clock_protect[3], clock_post_protect;
static uintptr_t clock_handle;
static uint64_t clock_sample = UINT64_C(0x100000040);

static uintptr_t clock_open(uint32_t access, uint32_t share, void *security,
                            uint32_t disposition, uint32_t flags, uintptr_t template_file)
{
    CHECK(clock_testing && !clock_owned);
    CHECK(!access && !share && !security && disposition == 3 && flags == UINT32_C(0x04000000) && !template_file);
    ++clock_open_calls;
    if (clock_open_error) { last_error = clock_open_error; return UINT32_MAX; }
    clock_owned = 1;
    return clock_handle; /* zero is a valid owned handle in this model */
}
static int clock_close(uintptr_t handle)
{
    CHECK(clock_testing && clock_owned && handle == clock_handle);
    ++clock_close_calls;
    if (clock_close_error) { last_error = clock_close_error; return 0; }
    clock_owned = 0;
    last_error = 0x5656;
    return 1;
}
static uint32_t STDCALL mock_VirtualQuery(const void *address, struct clock_mbi32 *info, uint32_t bytes)
{
    const uintptr_t cursor = (uintptr_t)address, start = (uintptr_t)clock_storage;
    uint32_t page;
    CHECK(clock_testing && info && bytes == sizeof(*info));
    ++clock_vq_calls;
    last_error = 0x5151;
    if (cursor < start || cursor >= start + sizeof(clock_storage) || clock_mbi_mode == 1) return 0;
    page = (uint32_t)(cursor - start) / 4096u;
    info->base = (uint32_t)start + page * 4096u;
    info->allocation = (uint32_t)start;
    info->allocation_protect = 4;
    info->region_bytes = 4096;
    info->state = clock_mbi_mode == 3 ? 0x2000u : clock_mbi_mode == 4 ? 0x10000u : 0x1000u;
    info->protect = clock_io_calls && clock_post_protect ? clock_post_protect : clock_protect[page];
    info->type = 0x20000;
    if (clock_mbi_mode == 5) info->region_bytes = 0;
    if (clock_mbi_mode == 6) info->base = (uint32_t)cursor + 4;
    if (clock_mbi_mode == 7) info->region_bytes = UINT32_MAX;
    return clock_mbi_mode == 2 ? sizeof(*info) - 4u : sizeof(*info);
}
static uint32_t clock_device_io(uintptr_t device, uint32_t code, void *input, uint32_t input_bytes,
    void *output, uint32_t output_bytes, uint32_t *returned, void *overlapped)
{
    shz_clock_reply_t *reply = output;
    CHECK(clock_testing && clock_owned && device == clock_handle);
    CHECK(code == NTWV_IOCTL_CLOCK && !input && !input_bytes && reply && output_bytes == sizeof(*reply) && returned && !overlapped);
    ++clock_io_calls;
    if (clock_io_error) { last_error = clock_io_error; return 0; }
    reply->magic = SHZ_CLOCK_MAGIC;
    reply->size = sizeof(*reply);
    reply->version = SHZ_CLOCK_VERSION;
    reply->reserved = 0;
    reply->counter = clock_sample;
    reply->frequency = SHZ_CLOCK_FREQUENCY;
    *returned = sizeof(*reply);
    if (clock_reply_mode == 1) *returned -= 4;
    if (clock_reply_mode == 2) ++reply->magic;
    if (clock_reply_mode == 3) ++reply->size;
    if (clock_reply_mode == 4) ++reply->version;
    if (clock_reply_mode == 5) reply->reserved = 1;
    if (clock_reply_mode == 6) ++reply->frequency;
    if (clock_reply_mode == 7) reply->counter = UINT64_MAX;
    return 1;
}
