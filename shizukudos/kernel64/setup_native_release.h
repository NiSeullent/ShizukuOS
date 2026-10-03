/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_NATIVE_RELEASE_H
#define SHZ_SETUP_NATIVE_RELEASE_H
#include "archive_source.h"
/* Kernel build owner only. Runtime users cannot install admission records.
 * Bytes/SHA from sealed custody do not establish a trusted DOS/Windows producer. */
int setup_native_release_available(void);
int setup_native_release_source(const archive_source_info_t *,unsigned manifest_or_sim);
int setup_native_release_pair(const archive_source_info_t manifest_and_sim[2]);
#endif
