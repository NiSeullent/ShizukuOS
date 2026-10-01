/* SPDX-License-Identifier: GPL-2.0-only
 * The runner supplies verbatim loader.c entry/boot/release/GOP-stage bodies.
 * Only EFI services, selector and physical boot preparation are simulated.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shizukudos/supervisor/loader/efi_ext.h"
#include "shizukudos/supervisor/loader/bootini.h"
#include "shizukudos/uefi/boot.h"
#include "shizukudos/abi/shz_abi.h"
#include "shizukudos/kernel64/standalone/memholes.h"
#include "shizukudos/supervisor/include/shz_info.h"
#include "shizukudos/supervisor/src/caps.h"
#include "shizukudos/supervisor/native_win98/config.h"
#include "gop_auto_state.inc"

static EFI_SYSTEM_TABLE *g_st;
static SD_HANDOFF g_handoff;
static shz_blob_t g_blobs[SHZ_MAX_BLOBS];
static bootini_policy_t g_policy;
static uint64_t g_k32_ram, g_k64_ram, g_ipc;
static EFI_GUID gop_guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static const EFI_GUID acpi2_guid = {0x8868e871,0xe4f1,0x11d3,{0xbc,0x22,0x00,0x80,0xc7,0x3c,0x88,0x81}};
static const uint8_t payload_image[] = {0};
static EFI_GOP mock_gop;
static unsigned checks;

#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #c); exit(1); \
} } while (0)

static struct {
    int mode, auto_kernel64, image_present, gop_present, long_mode;
    unsigned vendor, svm_usable;
    EFI_STATUS preparation, selection, launch;
    unsigned image_calls, prepare_calls, launch_calls, select_calls, csm_calls, frees;
} test;

static void zero(void *, size_t);
static EFI_STATUS prepare_display_stage(EFI_BOOT_SERVICES *);
static EFI_STATUS k64_refuse(const char *, EFI_STATUS);

static void say(const char *text) { (void)text; }
static void say_status(EFI_STATUS status) { (void)status; }
static void say_dec(uint64_t value) { (void)value; }
static void say_hex(uint64_t value) { (void)value; }

/* Unused entry paths must stop before touching physical RAM or privileges. */
static EFI_STATUS forbidden(void)
{
    CHECK(0 && "unexpected firmware/physical boot boundary");
    return EFI_ABORTED;
}

static EFI_STATUS EFIAPI mock_allocate_pages(uint32_t a, uint32_t b, size_t c, uint64_t *d)
{
    (void)a; (void)b; (void)c; (void)d;
    return forbidden();
}
static EFI_STATUS EFIAPI mock_free_pages(uint64_t address, size_t pages)
{
    CHECK((address == K64_LOW_PA && pages == K64_LOW_PAGES) ||
          (address == K64_KERNEL_PA && pages == (K64_KERNEL_WINDOW >> 12)));
    ++test.frees;
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI mock_allocate_pool(uint32_t a, size_t b, void **c)
{
    (void)a; (void)b; (void)c;
    return forbidden();
}
static EFI_STATUS EFIAPI mock_handle_protocol(EFI_HANDLE a, EFI_GUID *b, void **c)
{
    (void)a; (void)b; (void)c;
    return forbidden();
}
static EFI_STATUS EFIAPI mock_stall(size_t time)
{
    (void)time;
    return forbidden();
}
static EFI_STATUS EFIAPI mock_watchdog(size_t a, uint64_t b, size_t c, CHAR16 *d)
{
    CHECK(a == 0 && b == 0 && c == 0 && d == NULL);
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI mock_locate(EFI_GUID *guid, void *key, void **out)
{
    CHECK(guid->a == gop_guid.a && key == NULL && out != NULL);
    *out = test.gop_present ? &mock_gop : NULL;
    return test.gop_present ? EFI_SUCCESS : EFI_NOT_FOUND;
}
static EFI_BOOT_SERVICES services = {
    .header.signature = EFI_BOOT_SERVICES_SIGNATURE,
    .allocate_pages = (void *)mock_allocate_pages,
    .free_pages = (void *)mock_free_pages,
    .allocate_pool = mock_allocate_pool,
    .handle_protocol = mock_handle_protocol,
    .stall = (void *)mock_stall,
    .set_watchdog_timer = mock_watchdog,
    .locate_protocol = mock_locate,
};
static EFI_SYSTEM_TABLE system_table = {
    .header.signature = EFI_SYSTEM_TABLE_SIGNATURE,
    .boot_services = &services,
};

EFI_STATUS sd_gop_select(EFI_BOOT_SERVICES *bs, EFI_GOP *gop, SD_FRAMEBUFFER *fb,
                         SD_GOP_SELECTION *choice)
{
    CHECK(bs == &services && gop == &mock_gop && fb != NULL && choice != NULL);
    ++test.select_calls;
    if (EFI_ERROR(test.selection)) return test.selection;
    *fb = (SD_FRAMEBUFFER){.base=0x10000000, .size=4u*1024*1024,
        .width=1024, .height=768, .pitch_pixels=1024, .pixel_format=1};
    *choice = (SD_GOP_SELECTION){.original_mode=0, .selected_mode=0, .used_fallback=1};
    return EFI_SUCCESS;
}
EFI_STATUS sd_exit_boot_services(EFI_BOOT_SERVICES *bs, EFI_HANDLE image, SD_HANDOFF *h)
{
    (void)bs; (void)image; (void)h;
    return forbidden();
}
void shz_probe_caps(shz_caps_t *caps)
{
    memset(caps, 0, sizeof(*caps));
    caps->long_mode = (uint32_t)test.long_mode;
    caps->vendor = test.vendor;
    caps->svm_usable = test.svm_usable;
    strcpy(caps->vmx_why, "fixture has no VMX backend");
    strcpy(caps->svm_why, "fixture has no SVM backend");
}
static EFI_STATUS load_boot_policy(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, bootini_policy_t *policy)
{
    CHECK(image == (EFI_HANDLE)(uintptr_t)7 && bs == &services);
    memset(policy, 0, sizeof(*policy));
    policy->mode = test.mode;
    policy->auto_kernel64 = test.auto_kernel64;
    return EFI_SUCCESS;
}
static void boot_menu(bootini_policy_t *policy) { (void)policy; (void)forbidden(); }
static int k64_image_present(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    CHECK(image == (EFI_HANDLE)(uintptr_t)7 && bs == &services);
    ++test.image_calls;
    return test.image_present;
}
static EFI_STATUS csm_boot(EFI_HANDLE image, EFI_BOOT_SERVICES *bs,
                           const bootini_policy_t *policy, const char *why)
{
    CHECK(image == (EFI_HANDLE)(uintptr_t)7 && bs == &services && policy == &g_policy && why != NULL);
    ++test.csm_calls;
    return EFI_ABORTED; /* Distinct observable return from entering the CSM boundary. */
}
static EFI_STATUS k64_prepare(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    CHECK(image == (EFI_HANDLE)(uintptr_t)7 && bs == &services);
    ++test.prepare_calls;
#include "gop_auto_reset.inc"
    if (EFI_ERROR(test.preparation)) return test.preparation;
    g_k64.low_alloc = g_k64.kernel_alloc = 1;
    return prepare_display_stage(bs);
}
static EFI_STATUS k64_launch(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    CHECK(image == (EFI_HANDLE)(uintptr_t)7 && bs == &services);
    ++test.launch_calls;
    return test.launch; /* Simulated pre-ExitBootServices preparation failure. */
}
static EFI_STATUS load_file(EFI_HANDLE a, EFI_BOOT_SERVICES *b, const char *c,
                            uint64_t *d, uint64_t *e, uint64_t f)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    return forbidden();
}
static EFI_STATUS alloc_guest_ram(EFI_BOOT_SERVICES *a, unsigned b, uint64_t *c)
{
    (void)a; (void)b; (void)c;
    return forbidden();
}
static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}
static uint64_t rdtsc_now(void) { (void)forbidden(); return 0; }

#include "gop_auto_production.inc"

static void reset(void)
{
    memset(&test, 0, sizeof(test));
    test.mode = BOOT_MODE_AUTO;
    test.auto_kernel64 = test.image_present = test.gop_present = test.long_mode = 1;
    test.vendor = SHZ_VENDOR_AMD;
    test.launch = EFI_LOAD_ERROR;
}
static void run_case(const char *name, EFI_STATUS want, unsigned csm, unsigned prepare, unsigned select)
{
    EFI_STATUS got = efi_main((EFI_HANDLE)(uintptr_t)7, &system_table);
    if (got != want || test.csm_calls != csm)
        fprintf(stderr, "%s: returned %llx (wanted %llx), CSM calls %u (wanted %u)\n",
                name, (unsigned long long)got, (unsigned long long)want, test.csm_calls, csm);
    CHECK(test.csm_calls == csm);
    CHECK(got == want);
    CHECK(test.prepare_calls == prepare);
    CHECK(test.select_calls == select);
    CHECK(g_k64.low_alloc == 0 && g_k64.kernel_alloc == 0 && g_k64.initrd_alloc == 0);
    if (prepare && !EFI_ERROR(test.preparation)) CHECK(test.frees == 2);
    printf("PASS %s\n", name);
}

int main(void)
{
    reset(); test.selection=EFI_DEVICE_ERROR;
    run_case("AUTO refuses CSM after failed GOP restoration", EFI_DEVICE_ERROR,0,1,1);
    /* The next attempt must reset the previous fatal display outcome. */
    reset(); test.preparation=EFI_OUT_OF_RESOURCES;
    run_case("unplaceable Kernel64 retains CSM fallback after prior fatal display",EFI_ABORTED,1,1,0);
    reset(); test.selection=EFI_INVALID_PARAMETER;
    run_case("invalid available GOP refuses AUTO CSM",EFI_INVALID_PARAMETER,0,1,1);
    reset(); test.selection=EFI_UNSUPPORTED;
    run_case("unsupported available GOP refuses AUTO CSM",EFI_UNSUPPORTED,0,1,1);
    reset(); test.vendor=SHZ_VENDOR_INTEL; test.selection=EFI_DEVICE_ERROR;
    run_case("Intel AUTO without usable VMX refuses unsafe display fallback",EFI_DEVICE_ERROR,0,1,1);
    reset(); test.svm_usable=1; test.selection=EFI_DEVICE_ERROR;
    run_case("AMD usable SVM still refuses unsafe display fallback",EFI_DEVICE_ERROR,0,1,1);
    reset();
    run_case("validated original display retains ordinary pre-exit CSM fallback",EFI_ABORTED,1,1,1);
    reset(); test.gop_present=0;
    run_case("absent GOP retains ordinary CSM fallback",EFI_ABORTED,1,1,0);
    reset(); test.preparation=EFI_LOAD_ERROR;
    run_case("unreadable Kernel64 retains CSM fallback",EFI_ABORTED,1,1,0);
    reset(); test.image_present=0;
    run_case("absent Kernel64 image retains CSM fallback",EFI_ABORTED,1,0,0);
    reset(); test.auto_kernel64=0;
    run_case("AUTO without Kernel64 option retains CSM fallback",EFI_ABORTED,1,0,0);
    reset(); test.mode=BOOT_MODE_KERNEL64; test.selection=EFI_DEVICE_ERROR;
    run_case("explicit Kernel64 returns restoration failure",EFI_DEVICE_ERROR,0,1,1);
    reset(); test.mode=BOOT_MODE_INSTALL; test.selection=EFI_DEVICE_ERROR;
    run_case("explicit installer returns restoration failure",EFI_DEVICE_ERROR,0,1,1);
    reset(); test.mode=BOOT_MODE_CSM;
    run_case("explicit CSM remains selected by policy",EFI_ABORTED,1,0,0);
    reset(); test.long_mode=0;
    run_case("CPU rejection occurs before any backend attempt",EFI_UNSUPPORTED,0,0,0);
    CHECK(test.launch_calls == 0);
    printf("PASS %u actual-loader entry, GOP-stage and release checks\n",checks);
    return 0;
}
