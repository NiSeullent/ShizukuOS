/* SPDX-License-Identifier: GPL-2.0-only: test-only mapped callback state. */
#ifndef SHZ_LOADER_FIXTURE_H
#define SHZ_LOADER_FIXTURE_H
#include <windows.h>
typedef struct {
    volatile ULONG count, order[16], reserved_nonnull, dependency_value, recursive_free_succeeded;
} loader_fixture_trace;
#endif
