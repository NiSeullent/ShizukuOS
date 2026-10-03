/* SPDX-License-Identifier: GPL-2.0-only
 * BSP-only firmware discovery through the existing retained-memory authority.
 * Parsed addresses describe firmware; they never grant register access.
 */
#include "laptop_firmware.h"
#include "cpu_firmware.h"
#include "smp_acpi.h"

static shz_cpu_firmware_t firmware_owner;
static struct shz_laptop_firmware firmware_snapshot;
static unsigned snapshot_ready;

static int laptop_read(void *owner,uint64_t address,void *out,size_t bytes)
{
    return shz_cpu_firmware_read(owner,address,out,bytes) ? SHZ_REVOKED:SHZ_DRIVER_OK;
}

int k64_laptop_firmware_init(const shz_bootinfo_t *bi)
{
    uint64_t rsdp=0;
    int result;
    /* No stale snapshot or broad BIOS-discovery grant survives any retry. */
    snapshot_ready=0;
    memset(&firmware_snapshot,0,sizeof firmware_snapshot);
    memset(&firmware_owner,0,sizeof firmware_owner);
    if(!bi) return SHZ_INVALID;
    result=shz_cpu_firmware_prepare(bi,&firmware_owner);
    if(result!=1) {
        result=result==0 ? SHZ_UNSUPPORTED:SHZ_REVOKED;
        goto done;
    }
    result=shz_smp_acpi_find_bios(shz_cpu_firmware_read,&firmware_owner,&rsdp);
    switch(result) {
    case SHZ_SMP_ACPI_OK: break;
    case SHZ_SMP_ACPI_NOT_FOUND: result=SHZ_NOT_FOUND; goto done;
    case SHZ_SMP_ACPI_INVALID: result=SHZ_MALFORMED; goto done;
    case SHZ_SMP_ACPI_UNSUPPORTED: result=SHZ_UNSUPPORTED; goto done;
    case SHZ_SMP_ACPI_LIMIT: result=SHZ_CAPACITY; goto done;
    default: result=SHZ_IO; goto done;
    }
    if(!rsdp) { result=SHZ_MALFORMED; goto done; }
    if(shz_cpu_firmware_finish_discovery(&firmware_owner,rsdp)) {
        result=SHZ_REVOKED;
        goto done;
    }
    result=shz_laptop_firmware_probe(laptop_read,&firmware_owner,rsdp,&firmware_snapshot);
    if(result==SHZ_DRIVER_OK) snapshot_ready=1;
done:
    /* Discovery is finished. Keep only copied descriptors, no callable owner. */
    memset(&firmware_owner,0,sizeof firmware_owner);
    return result;
}

const struct shz_laptop_firmware *k64_laptop_firmware_snapshot(void)
{
    return snapshot_ready ? &firmware_snapshot:0;
}
