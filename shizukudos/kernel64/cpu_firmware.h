/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_FIRMWARE_H
#define SHZ_CPU_FIRMWARE_H
#include "k64.h"
#include "standalone/qemu_firmware.h"
typedef struct {
    shz_native_firmware_t native;
    shz_qemu_firmware_t qemu;
    uint64_t rsdp, rsdp_bytes, ebda;
    unsigned discovery, ready;
} shz_cpu_firmware_t;
int shz_cpu_firmware_prepare(const shz_bootinfo_t *, shz_cpu_firmware_t *);
int shz_cpu_firmware_read(void *, uint64_t, void *, size_t);
int shz_cpu_firmware_finish_discovery(shz_cpu_firmware_t *, uint64_t);
#endif
