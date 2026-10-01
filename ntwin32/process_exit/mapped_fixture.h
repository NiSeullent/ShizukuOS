/* SPDX-License-Identifier: GPL-2.0-only -- shared own diagnostic observations */
#ifndef MX_FIXTURE_H
#define MX_FIXTURE_H
#include <stdint.h>
typedef struct mx_fixture_observation {
 uint32_t tls_process_attach,dll_process_attach,tls_thread_attach,dll_thread_attach;
 uint32_t tls_process_detach,dll_process_detach,tls_word,dll_word;
 uint32_t tls_reserved_nonnull,dll_reserved_nonnull,failures;
} mx_fixture_observation;
#endif
