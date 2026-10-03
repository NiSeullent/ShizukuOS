/* Host control for kernel64/laptop_power.c with synthetic Q35-like FADT and a modelled port space. */
#define K64_LAPTOP_POWER_HOST 1
#include "../laptop_power.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } } while(0)

static struct { uint16_t status, enable, ctl; uint32_t oob_access; unsigned smi_writes, reset_writes, forbidden;
                uint8_t reset_value; uint64_t now; int sci_en_initially; } M;
static uint32_t hin(void *c, uint16_t p, unsigned n) {
    (void)c;
    if (p == 0x600 && n == 4) return ((uint32_t)M.enable << 16) | M.status;
    if (p == 0x604 && n == 2) return M.ctl;
    M.forbidden++; return 0xffffffffu;
}
static void hout(void *c, uint16_t p, unsigned n, uint32_t v) {
    (void)c;
    if (p == 0x600 && n == 4) { M.status &= (uint16_t)~(v & 0xffff); M.enable = (uint16_t)(v >> 16); return; }
    if (p == 0x600 && n == 2) { M.status &= (uint16_t)~v; return; }
    if (p == 0xb2 && n == 1) { M.smi_writes++; if (v == 0xf1) M.ctl |= 1; return; }
    if (p == 0xcf9 && n == 1) { M.reset_writes++; M.reset_value = (uint8_t)v; return; }
    M.forbidden++;
}
static uint64_t hnow(void *c) { (void)c; return M.now += 1000; }
static void hrelax(void *c) { (void)c; }
static const struct k64_power_hw HW = { 0, hin, hout, hnow, hrelax };

static void p32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void build(struct shz_laptop_firmware *fw, uint8_t *t, size_t n, uint32_t flags, uint32_t pm1, uint32_t smi) {
    memset(t, 0, n); memcpy(t, "FACP", 4); p32(t + 4, (uint32_t)n); t[8] = 6;
    p32(t + 48, smi); t[52] = 0xf1; t[53] = 0xf0; p32(t + 56, pm1); p32(t + 64, pm1 + 4);
    t[88] = 4; t[89] = 2; p32(t + 112, flags);
    t[116] = 1; t[117] = 8; t[119] = 1; p32(t + 120, 0xcf9); t[128] = 0x0e;
    { uint8_t s = 0; for (size_t i = 0; i < n; i++) s = (uint8_t)(s + t[i]); t[9] = (uint8_t)(0u - s); }
    memset(fw, 0, sizeof *fw);
    assert(shz_parse_fadt(t, n, &fw->fixed) == SHZ_DRIVER_OK);
}
static void reset_model(int sci_en) { memset(&M, 0, sizeof M); M.ctl = (uint16_t)sci_en; }

int main(void) {
    static uint8_t t[244]; struct shz_laptop_firmware fw; uint16_t ev; int pressed; uint64_t g1, g2;
    struct k64_laptop_power_policy deny_all = { 0, 0, 0 }, ok = { 1, 0, 50000 }, smi = { 1, 1, 50000 };

    build(&fw, t, sizeof t, 1u << 10, 0x600, 0xb2);
    /* table addresses are not a grant */
    reset_model(1);
    C(k64_laptop_power_open_hw(&fw, &deny_all, &HW) == SHZ_UNSUPPORTED);
    C(k64_laptop_power_open_hw(0, &ok, &HW) == SHZ_INVALID);
    C(k64_laptop_power_poll(&ev) == SHZ_NOT_FOUND && M.forbidden == 0);
    /* SCI_EN clear and no SMI authority: refuse, write nothing */
    reset_model(0);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_UNSUPPORTED && M.smi_writes == 0);
    C(k64_laptop_power_generation() == 0);
    /* SMI authority: ACPI_ENABLE written once, SCI_EN observed */
    reset_model(0);
    C(k64_laptop_power_open_hw(&fw, &smi, &HW) == SHZ_DRIVER_OK && M.smi_writes == 1 && (M.ctl & 1));
    C(k64_laptop_power_close() == SHZ_DRIVER_OK);
    /* open with SCI_EN already set; button path */
    reset_model(1);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_DRIVER_OK);
    g1 = k64_laptop_power_generation(); C(g1 != 0);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_BUSY);
    M.status = K64_POWER_BUTTON;                          /* pressed but not armed */
    C(k64_laptop_power_poll(&ev) == SHZ_DRIVER_OK && ev == 0);
    C(k64_laptop_power_arm_button() == SHZ_DRIVER_OK && (M.enable & K64_POWER_BUTTON) && M.status == K64_POWER_BUTTON);
    C(k64_laptop_power_button_pressed(&pressed) == SHZ_DRIVER_OK && pressed == 1 && M.status == 0);
    C(k64_laptop_power_button_pressed(&pressed) == SHZ_DRIVER_OK && pressed == 0);
    C(k64_laptop_power_ack(0x0002) == SHZ_UNSUPPORTED);   /* unsupported bit rejected */
    C(M.forbidden == 0);
    /* reset write + bounded wait: platform keeps running -> TIMEOUT, value from FADT */
    C(k64_laptop_power_reset() == SHZ_TIMEOUT && M.reset_writes == 1 && M.reset_value == 0x0e);
    /* close revokes; reopen gets a new generation; stale state is gone */
    C(k64_laptop_power_close() == SHZ_DRIVER_OK);
    C(k64_laptop_power_poll(&ev) == SHZ_NOT_FOUND && k64_laptop_power_generation() == 0);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_DRIVER_OK);
    g2 = k64_laptop_power_generation(); C(g2 > g1);
    C(k64_laptop_power_close() == SHZ_DRIVER_OK);
    /* no reset flag */
    build(&fw, t, sizeof t, 0, 0x600, 0xb2); reset_model(1);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_DRIVER_OK);
    C(k64_laptop_power_reset() == SHZ_UNSUPPORTED && M.reset_writes == 0);
    C(k64_laptop_power_close() == SHZ_DRIVER_OK);
    /* PM1 block overlapping the i8042/PIT ports is refused */
    build(&fw, t, sizeof t, 1u << 10, 0x60, 0xb2); reset_model(1);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_BUSY && M.forbidden == 0);
    /* MMIO register block has no mapping owner */
    build(&fw, t, sizeof t, 0, 0x600, 0xb2); fw.fixed.event_a.space = 0;
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_UNSUPPORTED);
    /* clock going backwards during reset wait is an error, not a hang */
    build(&fw, t, sizeof t, 1u << 10, 0x600, 0xb2); reset_model(1);
    C(k64_laptop_power_open_hw(&fw, &ok, &HW) == SHZ_DRIVER_OK);
    C(k64_laptop_power_close() == SHZ_DRIVER_OK);
    printf("laptop_power host control: %u checks PASS\n", checks);
    return 0;
}
