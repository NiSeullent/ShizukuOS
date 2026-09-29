/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: the PE side of Wine's Unix-library call mechanism (include/wine/unixlib.h).
 *
 * A Wine DLL with a Unix half reaches it through __wine_unix_call_dispatcher(handle, code, args). Shizuku has no Unix
 * side. This file is compiled once per module:
 *   - default: there is no Unix half; __wine_init_unix_call succeeds (so DllMain continues) and every call returns
 *     STATUS_NOT_SUPPORTED, which the Wine callers treat as "the host facility is unavailable";
 *   - with SHZW_UNIX_INPROC: the module's former Unix sources were ported to PE and linked into the same DLL (see the
 *     module's patches); calls go straight to their __wine_unix_call_funcs table, in process.
 */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/unixlib.h"

unixlib_handle_t __wine_unixlib_handle = 0;

#ifdef SHZW_UNIX_INPROC
typedef NTSTATUS (*shzw_unix_entry)(void *args);
extern const shzw_unix_entry __wine_unix_call_funcs[];
extern const unsigned int shzw_unix_call_count;

static NTSTATUS WINAPI inproc_dispatcher(unixlib_handle_t handle, unsigned int code, void *args)
{
    if (code >= shzw_unix_call_count) return STATUS_INVALID_PARAMETER;
    return __wine_unix_call_funcs[code](args);
}
NTSTATUS (WINAPI *__wine_unix_call_dispatcher)(unixlib_handle_t, unsigned int, void *) = inproc_dispatcher;
NTSTATUS WINAPI __wine_init_unix_call(void) { __wine_unixlib_handle = 1; return STATUS_SUCCESS; }
#else
static NTSTATUS WINAPI no_unix_dispatcher(unixlib_handle_t handle, unsigned int code, void *args)
{
    return STATUS_NOT_SUPPORTED;
}
NTSTATUS (WINAPI *__wine_unix_call_dispatcher)(unixlib_handle_t, unsigned int, void *) = no_unix_dispatcher;
NTSTATUS WINAPI __wine_init_unix_call(void) { return STATUS_SUCCESS; }
#endif
