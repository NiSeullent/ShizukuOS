/* SPDX-License-Identifier: GPL-2.0-only
 * Original private ownership adapter for genuine upstream DXBC parsing.
 */
#ifndef WP_DXBC_CONTAINER_H
#define WP_DXBC_CONTAINER_H
#include <stddef.h>
#include <stdint.h>
struct wp_dxbc;
enum { WP_DXBC_MAX_BYTES = 8 * 1024 * 1024 };
/* Returns the genuine vkd3d_result domain. The input is copied and owned;
 * section pointers remain valid until close. This parses a DXBC container,
 * not shader instructions, device features, or executable rendering support.
 */
int wp_dxbc_open(const void *bytes, size_t size, struct wp_dxbc **out);
size_t wp_dxbc_sections(const struct wp_dxbc *p);
int wp_dxbc_section(const struct wp_dxbc *p, size_t index,
        uint32_t *tag, const void **bytes, size_t *size);
void wp_dxbc_close(struct wp_dxbc *p);
#endif
