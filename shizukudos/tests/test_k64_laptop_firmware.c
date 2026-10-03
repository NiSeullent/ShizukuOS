/* SPDX-License-Identifier: GPL-2.0-only
 * Production laptop bootstrap and parser; only the firmware owner boundary
 * is modeled. No register access or privileged CPU instruction is executed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/laptop_firmware.h"
#include "../kernel64/cpu_firmware.h"
#include "../kernel64/smp_acpi.h"

#define RSDP_PA 0x100u
#define ROOT_PA 0x200u
#define FADT_PA 0x400u
static unsigned checks;
static int prepare_result, scan_result, finish_result;
static unsigned prepares, scans, finishes, reads;
static int reader_denied;
static uint64_t scan_pa;
static shz_cpu_firmware_t *prepared_owner;
static const shz_bootinfo_t *prepared_boot;
static unsigned char firmware[4096];
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr,"FAIL %s:%u: %s\n",__FILE__,(unsigned)__LINE__,#x); exit(1); } } while (0)

static void put32(unsigned char *p,uint32_t v)
{ for (unsigned i=0;i<4;++i) p[i]=(unsigned char)(v>>(i*8)); }
static void seal(unsigned char *p,size_t n,size_t check)
{
    unsigned char sum=0; p[check]=0;
    for (size_t i=0;i<n;++i) sum=(unsigned char)(sum+p[i]);
    p[check]=(unsigned char)(0u-sum);
}
static void reset(void)
{
    memset(firmware,0,sizeof firmware);
    prepare_result=1; scan_result=0; finish_result=0; reader_denied=0;
    scan_pa=RSDP_PA;
    prepares=scans=finishes=reads=0; prepared_owner=0; prepared_boot=0;
    memcpy(firmware+RSDP_PA,"RSD PTR ",8);
    put32(firmware+RSDP_PA+16,ROOT_PA); seal(firmware+RSDP_PA,20,8);
    memcpy(firmware+ROOT_PA,"RSDT",4); put32(firmware+ROOT_PA+4,40);
    put32(firmware+ROOT_PA+36,FADT_PA); seal(firmware+ROOT_PA,40,9);
    memcpy(firmware+FADT_PA,"FACP",4); put32(firmware+FADT_PA+4,116);
    firmware[FADT_PA+46]=9; put32(firmware+FADT_PA+56,0x600);
    put32(firmware+FADT_PA+64,0x604);
    firmware[FADT_PA+88]=4; firmware[FADT_PA+89]=2;
    seal(firmware+FADT_PA,116,9);
}
int shz_cpu_firmware_prepare(const shz_bootinfo_t *bi,shz_cpu_firmware_t *f)
{
    ++prepares; prepared_owner=f; prepared_boot=bi;
    if (prepare_result==1) { memset(f,0,sizeof *f); f->ready=1; f->discovery=1; }
    return prepare_result;
}
int shz_cpu_firmware_read(void *ctx,uint64_t pa,void *out,size_t n)
{
    ++reads; CHECK(ctx==prepared_owner);
    if (reader_denied || pa>sizeof firmware || n>sizeof firmware-(size_t)pa) return -1;
    memcpy(out,firmware+(size_t)pa,n); return 0;
}
int shz_smp_acpi_find_bios(shz_smp_phys_read_fn read,void *ctx,uint64_t *out)
{
    ++scans; CHECK(ctx==prepared_owner); CHECK(read!=0);
    if (!scan_result) *out=scan_pa;
    return scan_result;
}
int shz_cpu_firmware_finish_discovery(shz_cpu_firmware_t *f,uint64_t pa)
{
    ++finishes; CHECK(f==prepared_owner); CHECK(pa==RSDP_PA);
    if (!finish_result) { f->discovery=0; f->rsdp=pa; f->rsdp_bytes=20; }
    return finish_result;
}
int main(void)
{
    shz_bootinfo_t bi={0}; const struct shz_laptop_firmware *s;
    reset(); CHECK(k64_laptop_firmware_snapshot()==0);
    CHECK(k64_laptop_firmware_init(0)==SHZ_INVALID);
    CHECK(prepares==0 && scans==0 && reads==0);
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_OK);
    CHECK(prepares==1 && prepared_boot==&bi && scans==1 && finishes==1 && reads>0);
    s=k64_laptop_firmware_snapshot(); CHECK(s!=0);
    CHECK(s->rsdp_pa==RSDP_PA && s->root_pa==ROOT_PA && s->fadt_pa==FADT_PA);
    CHECK(s->fixed.control_a.address==0x604 && s->fixed.event_a.address==0x600);
    CHECK(s->fixed.sci==9 && !s->has_ecdt);
    CHECK(!prepared_owner->ready && !prepared_owner->discovery && !prepared_owner->rsdp);

    reset(); prepare_result=0;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_UNSUPPORTED);
    CHECK(!k64_laptop_firmware_snapshot() && prepares==1 && scans==0 && reads==0);
    reset(); prepare_result=-1;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_REVOKED);
    CHECK(!k64_laptop_firmware_snapshot() && scans==0 && reads==0);
    reset(); scan_result=SHZ_SMP_ACPI_NOT_FOUND;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_NOT_FOUND);
    CHECK(!k64_laptop_firmware_snapshot() && scans==1 && finishes==0 && reads==0);
    reset(); scan_result=SHZ_SMP_ACPI_INVALID;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_MALFORMED);
    CHECK(!k64_laptop_firmware_snapshot() && finishes==0 && reads==0);
    CHECK(!prepared_owner->ready && !prepared_owner->discovery);
    reset(); scan_result=SHZ_SMP_ACPI_UNSUPPORTED;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_UNSUPPORTED);
    CHECK(!k64_laptop_firmware_snapshot() && finishes==0 && reads==0);
    reset(); scan_result=SHZ_SMP_ACPI_LIMIT;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_CAPACITY);
    CHECK(!k64_laptop_firmware_snapshot() && finishes==0 && reads==0);
    reset(); scan_result=1;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_IO);
    CHECK(!k64_laptop_firmware_snapshot() && finishes==0 && reads==0);
    reset(); scan_pa=0;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_MALFORMED);
    CHECK(!k64_laptop_firmware_snapshot() && finishes==0 && reads==0);
    reset(); finish_result=-1;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_REVOKED);
    CHECK(!k64_laptop_firmware_snapshot() && finishes==1 && reads==0);
    reset(); reader_denied=1;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_REVOKED);
    CHECK(!k64_laptop_firmware_snapshot() && reads==1);
    CHECK(!prepared_owner->ready && !prepared_owner->discovery && !prepared_owner->rsdp);
    reset(); firmware[FADT_PA+50]^=1;
    CHECK(k64_laptop_firmware_init(&bi)==SHZ_MALFORMED);
    CHECK(!k64_laptop_firmware_snapshot());
    reset(); CHECK(k64_laptop_firmware_init(&bi)==SHZ_OK);
    CHECK(k64_laptop_firmware_snapshot()!=0);
    CHECK(k64_laptop_firmware_init(0)==SHZ_INVALID);
    CHECK(!k64_laptop_firmware_snapshot());
    printf("PASS production laptop firmware boot adapter: %u assertions\n",checks);
    return 0;
}
