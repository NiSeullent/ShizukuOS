/* SPDX-License-Identifier: GPL-2.0-only */
#include "container.h"
#include "vkd3d_shader.h"
#include <stdlib.h>
#include <string.h>
struct wp_dxbc { void *bytes; struct vkd3d_shader_dxbc_desc desc; };
int wp_dxbc_open(const void *bytes, size_t size, struct wp_dxbc **out)
{
    struct wp_dxbc *p;
    struct vkd3d_shader_code code;
    int ret;
    if (!out) return VKD3D_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    if (!bytes || size < 32 || size > WP_DXBC_MAX_BYTES)
        return VKD3D_ERROR_INVALID_ARGUMENT;
    if (!(p = calloc(1, sizeof(*p)))) return VKD3D_ERROR_OUT_OF_MEMORY;
    if (!(p->bytes = malloc(size))) { free(p); return VKD3D_ERROR_OUT_OF_MEMORY; }
    memcpy(p->bytes, bytes, size);
    code.code = p->bytes; code.size = size;
    ret = vkd3d_shader_parse_dxbc(&code, 0, &p->desc, NULL);
    if (ret < 0) { free(p->bytes); free(p); return ret; }
    *out = p;
    return ret;
}
size_t wp_dxbc_sections(const struct wp_dxbc *p) { return p ? p->desc.section_count : 0; }
int wp_dxbc_section(const struct wp_dxbc *p, size_t index,
        uint32_t *tag, const void **bytes, size_t *size)
{
    if (tag) *tag = 0;
    if (bytes) *bytes = NULL;
    if (size) *size = 0;
    if (!p || index >= p->desc.section_count || !tag || !bytes || !size)
        return VKD3D_ERROR_INVALID_ARGUMENT;
    *tag = p->desc.sections[index].tag;
    *bytes = p->desc.sections[index].data.code;
    *size = p->desc.sections[index].data.size;
    return VKD3D_OK;
}
void wp_dxbc_close(struct wp_dxbc *p)
{
    if (!p) return;
    vkd3d_shader_free_dxbc(&p->desc);
    free(p->bytes);
    free(p);
}
