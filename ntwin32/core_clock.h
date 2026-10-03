/* SPDX-License-Identifier: GPL-2.0-only -- explicit Core provider, no routing. */
#ifndef NTW_CORE_CLOCK_H
#define NTW_CORE_CLOCK_H
#include <stdint.h>
#include "../shizukudos/abi/shz_clock.h"

struct ntw_core_clock_ops {
    void *opaque;
    uint32_t (*open)(void *opaque, uintptr_t *handle);
    uint32_t (*query)(void *opaque, uintptr_t handle, shz_clock_reply_t *reply, uint32_t *returned);
    uint32_t (*close)(void *opaque, uintptr_t handle);
    uint32_t (*writable)(void *opaque, const int64_t *output);
};
/* Only one synchronous caller owns the device at a time. A failed close
 * remains owned and must actually succeed before another open is admitted. */
struct ntw_core_clock_client {
    uint32_t admitted, stopped, held;
    uintptr_t retained;
    void *retained_opaque;
    uint32_t (*retained_close)(void *opaque, uintptr_t handle);
};
uint32_t ntw_core_clock_query(struct ntw_core_clock_client *client,
    const struct ntw_core_clock_ops *ops, int64_t *counter, int64_t *frequency);
int32_t ntw_core_clock_ntquery(struct ntw_core_clock_client *client,
    const struct ntw_core_clock_ops *ops, int64_t *counter, int64_t *frequency);
uint32_t ntw_core_clock_stop(struct ntw_core_clock_client *client);
/* Native DLL detach stops admission only. No device open/query/close or other
 * I/O occurs under the loader lock. Normal calls drain failed closes first. */
void ntw_core_clock_native_stop(void);
#endif
