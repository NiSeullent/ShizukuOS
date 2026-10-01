/* SPDX-License-Identifier: GPL-2.0-only
 * Private registered-PnP catalog, not an inventory of unregistered hardware.
 * Original fixed-width shared ABI; snapshots contain no kernel pointers.
 */
#ifndef SHZ_PNP_CATALOG_H
#define SHZ_PNP_CATALOG_H
#include <stdint.h>
#define SHZ_PNP_CATALOG_CLASS 0x103u
#define SHZ_PNP_CATALOG_VERSION 1u
#define SHZ_PNP_NODE 1u
#define SHZ_PNP_INTERFACE 2u
typedef struct { uint32_t version, row_size, count, reserved; } shz_pnp_catalog_t;
typedef struct {
    uint32_t kind, node_id, enabled, started;
    uint16_t instance[128], class_guid[40], driver_key[80];
    uint16_t description[128], manufacturer[128], link[160];
    uint8_t interface_guid[16];
    char service[64];
} shz_pnp_row_t;
_Static_assert(sizeof(shz_pnp_catalog_t)==16,"catalog header ABI");
_Static_assert(sizeof(shz_pnp_row_t)==1424,"catalog row ABI");
#endif
