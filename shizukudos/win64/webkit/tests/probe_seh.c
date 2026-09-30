/* SPDX-License-Identifier: GPL-2.0-only
 * Toolchain probe: does `__try/__except` work with clang --target=x86_64-w64-windows-gnu? (It compiles, but clang 18 emits
 * no handler for it on this target: the fault is not caught; WEBKIT.md records the run.) */
#include <windows.h>
#include <stdio.h>
int main(){int r=0; __try { *(volatile int*)0=1; } __except(EXCEPTION_EXECUTE_HANDLER) { r=1; } printf("SEH r=%d\n",r); return !r;}
