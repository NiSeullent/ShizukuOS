/* SPDX-License-Identifier: GPL-2.0-only
 * Host-side fault injection tests. These prove contracts, not firmware support.
 */
#include "boot.h"
#include "display.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static struct {
    unsigned allocations, frees, exits, map_calls, resize_once, stale, fail_alloc;
    unsigned invalid_descriptor, oversized, fail_exit, overflow_after_exit;
    size_t key;
} state;

static EFI_STATUS EFIAPI mock_map(size_t *bytes, EFI_MEMORY_DESCRIPTOR *map,
                                  size_t *key, size_t *stride, uint32_t *version)
{
    EFI_MEMORY_DESCRIPTOR d = {0};
    ++state.map_calls;
    *stride = 48;
    *version = 1;
    if (!map || (state.resize_once && state.allocations == 1 && !state.exits) ||
        (state.overflow_after_exit && state.exits)) {
        *bytes = state.oversized ? SD_MAP_LIMIT + 1 :
            (state.allocations ? *bytes + 48 : 96);
        return EFI_BUFFER_TOO_SMALL;
    }
    CHECK(*bytes >= 96);
    memset(map, 0, 96);
    d.type = 7; d.physical_start = 0x100000; d.pages = 32;
    memcpy(map, &d, sizeof(d));
    d.type = 6; d.physical_start = 0x200000; d.pages = 8;
    memcpy((unsigned char *)map + 48, &d, sizeof(d));
    *bytes = state.invalid_descriptor ? 95 : 96;
    *key = ++state.key;
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI mock_allocate(uint32_t type, size_t bytes, void **out)
{
    CHECK(type == EFI_LOADER_DATA);
    CHECK(!state.exits);
    ++state.allocations;
    if (state.fail_alloc) return EFI_OUT_OF_RESOURCES;
    *out = malloc(bytes);
    CHECK(*out != NULL);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI mock_free(void *p)
{
    CHECK(!state.exits);
    ++state.frees;
    free(p);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI mock_exit(EFI_HANDLE image, size_t key)
{
    CHECK(image == (EFI_HANDLE)(uintptr_t)0x1234);
    CHECK(key == state.key);
    ++state.exits;
    if (state.fail_exit) return EFI_DEVICE_ERROR;
    if (state.exits <= state.stale) return EFI_INVALID_PARAMETER;
    return EFI_SUCCESS;
}

static EFI_BOOT_SERVICES services = {
    .get_memory_map = mock_map, .allocate_pool = mock_allocate,
    .free_pool = mock_free, .exit_boot_services = mock_exit
};

static void exit_tests(void)
{
    SD_HANDOFF h = {0};
    EFI_STATUS status;
    memset(&state, 0, sizeof(state));
    status = sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h);
    CHECK(status == EFI_SUCCESS && h.boot_services_exited && h.exit_calls == 1);
    CHECK(h.conventional_pages == 32 && h.descriptor_size == 48);
    free(h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.stale = 1;
    status = sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h);
    CHECK(status == EFI_SUCCESS && h.exit_calls == 2 && state.allocations == 1);
    CHECK(state.map_calls == 3 && state.frees == 0);
    free(h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.resize_once = 1;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_SUCCESS);
    CHECK(state.allocations == 2 && state.frees == 1);
    free(h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.stale = 100;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_ABORTED);
    CHECK(h.exit_attempted && !h.boot_services_exited && h.exit_calls == SD_EXIT_ATTEMPTS);
    CHECK(state.allocations == 1 && state.frees == 0);
    free(h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.invalid_descriptor = 1;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_INVALID_PARAMETER);
    CHECK(!h.exit_attempted && !state.exits);
    free(h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.fail_alloc = 1;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_OUT_OF_RESOURCES);
    CHECK(!h.exit_attempted && !h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.oversized = 1;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_OUT_OF_RESOURCES);
    CHECK(!state.allocations && !state.exits);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state)); state.fail_exit = 1;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_DEVICE_ERROR);
    CHECK(h.exit_attempted && !h.boot_services_exited && h.exit_calls == 1);
    free(h.memory_map);

    h = (SD_HANDOFF){0}; memset(&state, 0, sizeof(state));
    state.stale = 1; state.overflow_after_exit = 1;
    CHECK(sd_exit_boot_services(&services, (void *)(uintptr_t)0x1234, &h) == EFI_BUFFER_TOO_SMALL);
    CHECK(h.exit_attempted && !h.boot_services_exited && state.allocations == 1);
    free(h.memory_map);
}

static void map_tests(void)
{
    EFI_MEMORY_DESCRIPTOR d = {.type = 7, .physical_start = 0x100000, .pages = 10};
    SD_HANDOFF h = {.memory_map = &d, .map_size = sizeof(d), .map_capacity = sizeof(d),
                    .descriptor_size = sizeof(d), .descriptor_version = 1};
    CHECK(sd_validate_map(&h) == EFI_SUCCESS && h.conventional_pages == 10);
    h.map_capacity = 1; CHECK(sd_validate_map(&h) == EFI_INVALID_PARAMETER); h.map_capacity = sizeof(d);
    h.descriptor_size = 32; CHECK(sd_validate_map(&h) == EFI_INVALID_PARAMETER); h.descriptor_size = sizeof(d);
    h.descriptor_version = 2; CHECK(sd_validate_map(&h) == EFI_INVALID_PARAMETER); h.descriptor_version = 1;
    d.physical_start++; CHECK(sd_validate_map(&h) == EFI_INVALID_PARAMETER); d.physical_start--;
    d.pages = UINT64_MAX; CHECK(sd_validate_map(&h) == EFI_INVALID_PARAMETER);
    d.pages = 0; CHECK(sd_validate_map(&h) == EFI_INVALID_PARAMETER);
}

static void framebuffer_tests(void)
{
    _Alignas(16) uint8_t arena[64 * 1024];
    size_t count = 336u * 240u, i;
    uint32_t *pixels = calloc(count + 2, sizeof(*pixels));
    EFI_GOP_INFO info = {.width = 320, .height = 240, .pixels_per_scan_line = 336, .pixel_format = 1};
    EFI_GOP_MODE mode = {.info = &info, .info_size = sizeof(info),
                        .framebuffer_base = (uintptr_t)(pixels + 1), .framebuffer_size = count * 4};
    SD_HANDOFF h = {0};
    CHECK(pixels != NULL);
    pixels[0] = pixels[count + 1] = 0xfefefefe;
    CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_SUCCESS);
    sd_framebuffer_result(&h, 1);
    CHECK(pixels[1 + 32 * 336 + 32] == 0x20d080);
    CHECK(pixels[1 + 32 * 336 + 112] == 0x7040e0);
    CHECK(sd_ntwddm_demo(&h.framebuffer, arena, sizeof(arena)) == 1);
    CHECK(pixels[1 + 32 * 336 + 192] == 0xffffb020);
    CHECK(sd_ntwddm_demo(&h.framebuffer, arena, 16) == 0);
    CHECK(pixels[0] == 0xfefefefe && pixels[count + 1] == 0xfefefefe);
    for (i = 0; i < 240; ++i) CHECK(pixels[1 + i * 336 + 320] == 0);
    info.pixel_format = 0;
    CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_SUCCESS);
    sd_framebuffer_result(&h, 0);
    CHECK(pixels[1 + 32 * 336 + 32] == 0x4040e0);
    CHECK(sd_ntwddm_demo(&h.framebuffer, arena, sizeof(arena)) == 1);
    CHECK(pixels[1 + 32 * 336 + 192] == 0xff20b0ff);
    info.pixel_format = 2; CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_UNSUPPORTED);
    info.pixel_format = 3; CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_UNSUPPORTED);
    info.pixel_format = 1; mode.framebuffer_size = 1;
    CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_INVALID_PARAMETER);
    mode.framebuffer_size = count * 4; info.pixels_per_scan_line = 319;
    CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_INVALID_PARAMETER);
    info.pixels_per_scan_line = 336; mode.framebuffer_base = UINT64_MAX - 3;
    CHECK(sd_framebuffer_snapshot(&mode, &h.framebuffer) == EFI_INVALID_PARAMETER);
    free(pixels);
}

int main(void)
{
    exit_tests(); map_tests(); framebuffer_tests();
    printf("PASS: %u UEFI handoff, fault injection, framebuffer and bounds checks\n", checks);
    return 0;
}
