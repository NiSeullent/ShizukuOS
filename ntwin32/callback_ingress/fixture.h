/* SPDX-License-Identifier: GPL-2.0-only -- own zero-import fixture observations */
#ifndef CI_FIXTURE_H
#define CI_FIXTURE_H
#include <stdint.h>
typedef struct ci_observation {
    uint32_t process_attach, process_detach;
    uint32_t tls_attach, dll_attach, tls_detach, dll_detach, failures;
    uint32_t retired_word[2];
} ci_observation;
#endif
