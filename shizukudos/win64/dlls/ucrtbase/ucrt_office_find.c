/* SPDX-License-Identifier: GPL-2.0-only
 * Actual existing lowio.c directory enumerator supplies owned FindFirstFileW
 * handles, absolute path/code-page conversion, metadata and errno semantics.
 * Narrow output conversion follows MSVC's distinct 64i32 ABI and the low32
 * size used by pinned Wine11 db11d0fe6a169c457e23d007e20404643d067aa8
 * dlls/msvcrt/dir.c. Original project adapter; no upstream code copied.
 */
#include "crtint.h"
#include "ucrt_office_find.h"

intptr_t CRTAPI _findfirst64(const char *, struct crt_finddata64 *);
int CRTAPI _findnext64(intptr_t, struct crt_finddata64 *);

static void copy_find64i32(struct crt_finddata64i32 *out, const struct crt_finddata64 *data)
{
    out->attrib = data->attrib;
    out->time_create = data->time_create;
    out->time_access = data->time_access;
    out->time_write = data->time_write;
    out->size = (uint32_t)data->size;
    crt_memcpy(out->name, data->name, sizeof out->name);
}

DLLAPI intptr_t CRTAPI _findfirst64i32(const char *spec, struct crt_finddata64i32 *out)
{
    struct crt_finddata64 data = {0};
    intptr_t handle;
    CRT_VALIDATE(spec != 0 && out != 0, CRT_EINVAL, -1);
    handle = _findfirst64(spec, &data);
    if (handle != -1) copy_find64i32(out, &data);
    return handle;
}

DLLAPI int CRTAPI _findnext64i32(intptr_t handle, struct crt_finddata64i32 *out)
{
    struct crt_finddata64 data = {0};
    CRT_VALIDATE(out != 0, CRT_EINVAL, -1);
    if (_findnext64(handle, &data)) return -1;
    copy_find64i32(out, &data);
    return 0;
}
