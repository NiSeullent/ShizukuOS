/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_START_H
#define NTW_START_H
#include "map.h"
#include "../tls/tls.h"
int ntw_loader_start(uint8_t *image, const ntw_placed *placed, ntwtls_process *process,
                     ntwtls_thread *thread, const ntwtls_services *services, int execute,
                     void **slot_out);
#endif
