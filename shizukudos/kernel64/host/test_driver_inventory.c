/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for kernel64/driver_inventory.c pure helpers (built with -DDRVINV_HOST): status folding (a catalogue
 * match alone is never "working"), operation selection per catalogue service, query sizing and the user ABI layout.
 * Host-only evidence: no PCI device, block device or display is touched here.
 * Build: cc -std=gnu11 -Wall -Wextra -Werror -DDRVINV_HOST -I.. test_driver_inventory.c ../driver_inventory.c
 *        ../ntdrv_catalog.c
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../driver_inventory.h"

static int failures;
#define CHECK(c) do { if (!(c)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

int main(void)
{
    unsigned i;
    /* folding: nothing below BOUND can become WORKING, whatever the operation status claims */
    CHECK(drvinv_fold(SHZ_BIND_NO_DRIVER, 1, 0) == DRVINV_UNSUPPORTED);
    CHECK(drvinv_fold(SHZ_BIND_MATCHED_NOT_STARTED, 1, 0) == DRVINV_NOT_ATTACHED);
    CHECK(drvinv_fold(SHZ_BIND_MATCHED_NOT_STARTED, 0, DRVINV_OP_NOT_RUN) == DRVINV_NOT_ATTACHED);
    CHECK(drvinv_fold((enum shz_drvcat_binding)99, 1, 0) == DRVINV_UNSUPPORTED);
    CHECK(drvinv_fold(SHZ_BIND_BOUND, 0, 0) == DRVINV_BOUND_UNVERIFIED);
    CHECK(drvinv_fold(SHZ_BIND_BOUND, 1, DRVINV_OP_NOT_RUN) == DRVINV_BOUND_UNVERIFIED);
    CHECK(drvinv_fold(SHZ_BIND_BOUND, 1, 0) == DRVINV_WORKING);
    CHECK(drvinv_fold(SHZ_BIND_BOUND, 1, (int32_t)0xC0000185) == DRVINV_FAILED);
    CHECK(drvinv_fold(SHZ_BIND_BOUND_HOSTED, 1, 0) == DRVINV_WORKING);
    CHECK(drvinv_fold(SHZ_BIND_BOUND_HOSTED, 1, (int32_t)0xC00000A3) == DRVINV_FAILED);
    CHECK(drvinv_fold(SHZ_BIND_BOUND_UNLISTED, 0, DRVINV_OP_NOT_RUN) == DRVINV_BOUND_UNVERIFIED);

    /* every catalogue service maps to the operation of its backend family; unknown services get none */
    for (i = 0; i < shz_k64_catalog_count; ++i)
        CHECK(drvinv_op_for_service(shz_k64_catalog[i].service) != DRVINV_OP_NONE);
    CHECK(drvinv_op_for_service("ahci_blk") == DRVINV_OP_STORAGE_READ0);
    CHECK(drvinv_op_for_service("nvme") == DRVINV_OP_STORAGE_READ0);
    CHECK(drvinv_op_for_service("sdhci") == DRVINV_OP_STORAGE_READ0);
    CHECK(drvinv_op_for_service("shzgop") == DRVINV_OP_DISPLAY_MODE);
    CHECK(drvinv_op_for_service("gfx_virtio") == DRVINV_OP_DISPLAY_MODE);
    CHECK(drvinv_op_for_service("gfx_bga") == DRVINV_OP_DISPLAY_MODE);
    CHECK(drvinv_op_for_service("net_rtl8139") == DRVINV_OP_NIC_LINK);
    CHECK(drvinv_op_for_service("ahci") == DRVINV_OP_NONE);
    CHECK(drvinv_op_for_service("") == DRVINV_OP_NONE);
    CHECK(drvinv_op_for_service(NULL) == DRVINV_OP_NONE);

    /* query sizing and ABI */
    CHECK(drvinv_query_size(0) == sizeof(drvinv_header_t));
    CHECK(drvinv_query_size(DRVINV_MAX_ROWS) == sizeof(drvinv_header_t) + DRVINV_MAX_ROWS * sizeof(drvinv_row_t));
    CHECK(drvinv_query_size(DRVINV_MAX_ROWS + 1) == 0);
    CHECK(drvinv_query_size(0xffffffffu) == 0);
    CHECK(sizeof(drvinv_row_t) == 220 && sizeof(drvinv_header_t) == 96);
    CHECK(offsetof(drvinv_row_t, init_status) == 20 && offsetof(drvinv_row_t, service) == 44);
    CHECK(offsetof(drvinv_header_t, gop_base) == 40 && offsetof(drvinv_header_t, active_backend) == 64);
    CHECK(strcmp(drvinv_status_name(DRVINV_WORKING), "bound, operation verified") == 0);
    CHECK(strcmp(drvinv_status_name((enum drvinv_status)42), "invalid") == 0);
    if (failures) { fprintf(stderr, "test_driver_inventory: %d failure(s)\n", failures); return 1; }
    puts("test_driver_inventory: PASS");
    return 0;
}
