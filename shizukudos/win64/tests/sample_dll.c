/* SPDX-License-Identifier: GPL-2.0-only
 * Sample AMD64 DLL used to exercise the PE parser (exports, forwarder, TLS, relocations). */
#include <stdint.h>
__declspec(dllexport) int shz_add(int a, int b) { return a + b; }
__declspec(dllexport) int shz_value = 1234;
int __stdcall DllMain(void *h, unsigned long reason, void *r) { (void)h; (void)reason; (void)r; return 1; }
int shz_ord_fn(void) { return 77; }
