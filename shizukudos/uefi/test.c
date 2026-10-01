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

/* Only the firmware boundary is simulated: the real selector reads these
 * independently constructed mode/EDID records, sets the mode and snapshots it. */
static struct {
    EFI_GOP_INFO infos[12];
    EFI_GOP_MODE mode;
    EFI_GOP gop, unrelated;
    EFI_EDID_ACTIVE active;
    uint8_t edid[256];
    unsigned queries, sets, allocations, frees, fail_query, fail_set;
    unsigned bad_size, undersized, changed_on_error, restore_fails, unrelated_edid;
    unsigned locate_error, query_alloc_error;
    unsigned wrong_original;
    unsigned physical_mode, physical_only_error;
} display;

static EFI_STATUS EFIAPI display_free(void *p)
{
    ++display.frees;
    free(p);
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI display_query(EFI_GOP *gop, uint32_t index,
                                       size_t *bytes, EFI_GOP_INFO **out)
{
    CHECK(gop == &display.gop && index < gop->mode->max_mode);
    ++display.queries;
    *out = malloc(sizeof(**out));
    CHECK(*out != NULL);
    ++display.allocations;
    **out = display.infos[index];
    if (display.wrong_original && !index) **out = display.infos[2];
    *bytes = display.bad_size == index + 1 ? sizeof(**out) - 1 : sizeof(**out);
    if (display.query_alloc_error == index + 1) return EFI_DEVICE_ERROR;
    if (display.fail_query == index + 1) {
        display_free(*out); *out = NULL;
        return EFI_DEVICE_ERROR;
    }
    return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI display_set(EFI_GOP *gop, uint32_t index)
{
    CHECK(gop == &display.gop && index < gop->mode->max_mode);
    ++display.sets;
    /* Hardware may change while the published GOP Mode structure stays old. */
    if (display.fail_set == index + 1 && display.physical_only_error) {
        display.physical_mode = index;
        return EFI_DEVICE_ERROR;
    }
    if ((display.restore_fails && index == 0) ||
        (display.fail_set == index + 1 && !display.changed_on_error))
        return EFI_DEVICE_ERROR;
    display.physical_mode = index;
    display.mode.mode = index;
    display.mode.info = &display.infos[index];
    display.mode.framebuffer_base = 0x10000000;
    display.mode.framebuffer_size = display.undersized == index + 1 ? 4096 : 64u * 1024 * 1024;
    return display.fail_set == index + 1 ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS EFIAPI display_handles(uint32_t search, EFI_GUID *guid, void *key,
                                         size_t *count, EFI_HANDLE **handles)
{
    CHECK(search == 2 && key == NULL && guid->a == 0x9042a9de);
    *count = 2;
    *handles = malloc(2 * sizeof(**handles));
    CHECK(*handles != NULL);
    ++display.allocations;
    (*handles)[0] = (EFI_HANDLE)(uintptr_t)1;
    (*handles)[1] = (EFI_HANDLE)(uintptr_t)2;
    return display.locate_error ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS EFIAPI display_protocol(EFI_HANDLE handle, EFI_GUID *guid, void **out)
{
    if (guid->a == 0x9042a9de) {
        *out = handle == (EFI_HANDLE)(uintptr_t)2 ? &display.gop : &display.unrelated;
        return EFI_SUCCESS;
    }
    CHECK(guid->a == 0xbd8c1056);
    if (handle == (EFI_HANDLE)(uintptr_t)(display.unrelated_edid ? 1 : 2) && display.active.size) {
        *out = &display.active;
        return EFI_SUCCESS;
    }
    *out = NULL;
    return EFI_NOT_FOUND;
}

static EFI_BOOT_SERVICES display_services = {
    .free_pool = display_free, .handle_protocol = display_protocol,
    .locate_handle_buffer = display_handles,
};

static void display_reset(void)
{
    memset(&display, 0, sizeof(display));
    display.infos[0] = (EFI_GOP_INFO){.width=800, .height=600, .pixel_format=1, .pixels_per_scan_line=832};
    display.infos[1] = (EFI_GOP_INFO){.width=1920, .height=1080, .pixel_format=1, .pixels_per_scan_line=2048};
    display.infos[2] = (EFI_GOP_INFO){.width=3840, .height=2160, .pixel_format=0, .pixels_per_scan_line=3840};
    display.infos[3] = (EFI_GOP_INFO){.width=1366, .height=768, .pixel_format=1, .pixels_per_scan_line=1408};
    display.mode = (EFI_GOP_MODE){.max_mode=4, .mode=0, .info=&display.infos[0],
        .info_size=sizeof(EFI_GOP_INFO), .framebuffer_base=0x10000000, .framebuffer_size=64u*1024*1024};
    display.gop = (EFI_GOP){.query_mode=display_query, .set_mode=display_set, .mode=&display.mode};
}

static void edid_checksum(unsigned block)
{
    unsigned i, sum = 0;
    uint8_t *bytes = display.edid + block * 128;
    bytes[127] = 0;
    for (i=0; i<127; ++i) sum += bytes[i];
    bytes[127] = (uint8_t)(0u-sum);
}

static void preferred_edid(void)
{
    static const uint8_t header[8] = {0,255,255,255,255,255,255,0};
    memcpy(display.edid, header, 8);
    display.edid[18]=1; display.edid[19]=4; display.edid[24]=2;
    /* 1366 active + 426 blank horizontal; 768 active + 30 blank vertical. */
    display.edid[54]=0x64; display.edid[55]=0x19;
    display.edid[56]=0x56; display.edid[57]=0xaa; display.edid[58]=0x51;
    display.edid[59]=0; display.edid[60]=30; display.edid[61]=0x30;
    edid_checksum(0);
    display.active = (EFI_EDID_ACTIVE){128, display.edid};
}

static SD_FRAMEBUFFER select_display(uint32_t mode, unsigned edid, unsigned fallback)
{
    SD_FRAMEBUFFER fb = {0}; SD_GOP_SELECTION choice = {0};
    CHECK(sd_gop_select(&display_services, &display.gop, &fb, &choice) == EFI_SUCCESS);
    CHECK(display.mode.mode == mode && choice.selected_mode == mode && choice.original_mode == 0);
    CHECK(display.physical_mode == mode);
    CHECK(choice.edid_preferred == edid && choice.used_fallback == fallback);
    CHECK(fb.width == display.infos[mode].width && fb.height == display.infos[mode].height);
    CHECK(fb.pitch_pixels == display.infos[mode].pixels_per_scan_line);
    CHECK(display.allocations == display.frees);
    return fb;
}

static void gop_selection_tests(void)
{
    SD_FRAMEBUFFER fb = {0}; SD_GOP_SELECTION choice = {0};
    display_reset(); fb=select_display(2,0,0);
    CHECK(display.queries == 4 && display.sets == 1 && fb.pixel_format == 0);
    display_reset(); preferred_edid(); fb=select_display(3,1,0);
    CHECK(fb.width == 1366 && fb.height == 768);
    display_reset(); preferred_edid(); display.unrelated_edid=1; select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[127]^=1; select_display(2,0,0);
    display_reset(); preferred_edid(); display.active.size=127; select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[0]=1; edid_checksum(0); select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[19]=5; edid_checksum(0); select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[19]=3; display.edid[24]=0;
    edid_checksum(0); select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[71]=128; edid_checksum(0); select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[54]=display.edid[55]=0;
    edid_checksum(0); select_display(2,0,0);
    display_reset(); preferred_edid(); display.edid[126]=1;
    edid_checksum(0); select_display(2,0,0); /* Advertised extension missing. */
    display_reset(); preferred_edid(); display.edid[126]=1; display.active.size=256;
    display.edid[128]=2; edid_checksum(0); edid_checksum(1); select_display(3,1,0);
    display_reset(); preferred_edid(); display.edid[126]=1; display.active.size=256;
    edid_checksum(0); display.edid[128]=1; select_display(2,0,0);
    display_reset(); preferred_edid(); display.locate_error=1; select_display(2,0,0);
    display_reset(); display.infos[2].pixels_per_scan_line=3840-1; select_display(1,0,0);
    display_reset(); display.infos[2].pixels_per_scan_line=UINT32_MAX; select_display(1,0,0);
    display_reset(); display.infos[2].pixels_per_scan_line=8192; select_display(1,0,0);
    display_reset(); display.infos[2].pixel_format=3; select_display(1,0,0);
    display_reset(); display.infos[2].pixel_format=2; select_display(1,0,0);
    display_reset(); display.infos[2].pixel_format=2;
    display.infos[2].red_mask=0xff0000; display.infos[2].green_mask=0xff00;
    display.infos[2].blue_mask=0xff; display.infos[2].reserved_mask=0xff000000;
    fb=select_display(2,0,0); CHECK(fb.pixel_format == 1);
    display_reset(); display.bad_size=3; select_display(1,0,0);
    display_reset(); display.fail_query=3; select_display(1,0,0);
    display_reset(); display.query_alloc_error=3; select_display(1,0,0);
    display_reset(); display.wrong_original=1; select_display(2,0,0);
    display_reset(); display.fail_set=3; select_display(1,0,0);
    display_reset(); display.undersized=3; select_display(1,0,0);
    display_reset(); display.fail_set=3; display.changed_on_error=1; select_display(1,0,0);
    display_reset(); display.fail_set=3; display.changed_on_error=1; display.restore_fails=1;
    CHECK(sd_gop_select(&display_services,&display.gop,&fb,&choice) == EFI_DEVICE_ERROR);
    CHECK(display.allocations == display.frees);
    display_reset(); display.mode.max_mode=1; select_display(0,0,1); CHECK(display.sets == 0);
    display_reset(); display.gop.query_mode=NULL; select_display(0,0,1);
    display_reset(); display.mode.max_mode=1025; select_display(0,0,1); CHECK(display.queries == 0);
    display_reset(); display.mode.framebuffer_size=4096;
    CHECK(sd_gop_select(&display_services,&display.gop,&fb,&choice) == EFI_INVALID_PARAMETER);
    CHECK(display.sets == 0); /* A safe original is mandatory before attempting a mode change. */

    /* F1: a rejected switch must restore hardware even if Mode is unchanged.
     * Here 800x600 is not in the ladder and no second candidate can hide it. */
    display_reset(); display.mode.max_mode=2; display.fail_set=2; display.physical_only_error=1;
    select_display(0,0,1); CHECK(display.sets == 2);
    /* Also protect the existing-current ladder shortcut after a higher mode failed. */
    display_reset(); display.mode.max_mode=2; display.fail_set=2; display.physical_only_error=1;
    display.infos[0].width=1024; display.infos[0].height=768; display.infos[0].pixels_per_scan_line=1024;
    select_display(0,0,0); CHECK(display.sets == 2);
    display_reset(); display.mode.max_mode=2; display.fail_set=2;
    display.physical_only_error=1; display.restore_fails=1;
    CHECK(sd_gop_select(&display_services,&display.gop,&fb,&choice) == EFI_DEVICE_ERROR);
    CHECK(display.mode.mode == 0 && display.physical_mode == 1 && display.sets == 2);
    CHECK(display.allocations == display.frees);
}

int main(void)
{
    exit_tests(); map_tests(); framebuffer_tests(); gop_selection_tests();
    printf("PASS: %u UEFI handoff, fault injection, framebuffer and bounds checks\n", checks);
    return 0;
}
