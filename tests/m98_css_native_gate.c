/* SPDX-License-Identifier: GPL-2.0-only
 * DLL entry only. No initialization, registration, threads or global state.
 * This build component is not an MSHTML style/paint adapter or guest probe. */
int __attribute__((stdcall)) m98_css_dll_entry(void *instance,unsigned reason,void *reserved)
{
    (void)instance; (void)reason; (void)reserved;
    return 1;
}
