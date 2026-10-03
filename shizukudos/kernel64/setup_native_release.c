/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_release.h"
/* No actual independently validated Windows98 native producer output exists
 * in the public tree. A caller receipt/hash, synthetic fixture, or successful
 * RAM snapshot must never supply this authority. Future build-owned release
 * records must be emitted by the real producer under held final-byte custody,
 * authenticate BOTH manifest and encoded SIM, and enter source/tool receipts.
 * Until that independent constructor exists, every target claim refuses. */
int setup_native_release_available(void) { return 0; }
int setup_native_release_source(const archive_source_info_t *source,unsigned role)
{ (void)source;(void)role;return -1; }
int setup_native_release_pair(const archive_source_info_t pair[2])
{ (void)pair; return -1; }
