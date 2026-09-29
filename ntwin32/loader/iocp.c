/* SPDX-License-Identifier: GPL-2.0-only */
#include "iocp.h"
#define NTW_IOCP_SLOTS 8u
#define NTW_IOCP_PACKETS 64u
#define NTW_IOCP_BASE 0x4600u
#define NTW_INVALID_FILE 0xffffffffu
struct ntw_packet {
    uint32_t bytes;
    uint32_t key;
    uint32_t overlapped;
};
static struct ntw_port {
    int live;
    uint32_t threads;
    volatile int lock;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    struct ntw_packet packets[NTW_IOCP_PACKETS];
} ports[NTW_IOCP_SLOTS];
static ntw_iocp_pause pause_fn;
void ntw_iocp_set_pause(ntw_iocp_pause pause) { pause_fn = pause; }
static void lock_port(struct ntw_port *port) {
    while (__sync_lock_test_and_set(&port->lock, 1)) {
        if (pause_fn) pause_fn();
    }
}
static void unlock_port(struct ntw_port *port) { __sync_lock_release(&port->lock); }
static int port_slot(uint32_t handle) {
    uint32_t slot = handle - NTW_IOCP_BASE;
    if (handle < NTW_IOCP_BASE || slot >= NTW_IOCP_SLOTS || !ports[slot].live) return -1;
    return (int)slot;
}
int ntw_iocp_owns(uint32_t handle) { return port_slot(handle) >= 0; }
int ntw_iocp_create(uint32_t file, uint32_t existing, uint32_t key, uint32_t threads,
                    int (*valid_file)(uint32_t file), uint32_t *handle, uint32_t *error) {
    uint32_t slot;
    (void)key;
    if (!error || !handle) return 0;
    *handle = 0;
    if (file == NTW_INVALID_FILE) {
        if (existing) { *error = 87; return 0; }
    } else {
        if (!file || !valid_file || !valid_file(file)) { *error = 6; return 0; }
        if (existing && port_slot(existing) < 0) { *error = 6; return 0; }
    }
    if (existing) { *handle = existing; *error = 0; return 1; }
    for (slot = 0; slot < NTW_IOCP_SLOTS; ++slot) if (!ports[slot].live) break;
    if (slot == NTW_IOCP_SLOTS) { *error = 8; return 0; }
    ports[slot].live = 1;
    ports[slot].threads = threads;
    ports[slot].lock = 0;
    ports[slot].head = 0;
    ports[slot].tail = 0;
    ports[slot].count = 0;
    *handle = NTW_IOCP_BASE + slot;
    *error = 0;
    return 1;
}
int ntw_iocp_post(uint32_t port, uint32_t bytes, uint32_t key, uint32_t overlapped, uint32_t *error) {
    int slot = port_slot(port);
    struct ntw_port *item;
    if (!error) return 0;
    if (slot < 0) { *error = 6; return 0; }
    item = &ports[slot];
    lock_port(item);
    if (item->count >= NTW_IOCP_PACKETS) { unlock_port(item); *error = 8; return 0; }
    item->packets[item->tail].bytes = bytes;
    item->packets[item->tail].key = key;
    item->packets[item->tail].overlapped = overlapped;
    item->tail = (item->tail + 1u) % NTW_IOCP_PACKETS;
    item->count++;
    unlock_port(item);
    *error = 0;
    return 1;
}
int ntw_iocp_get(uint32_t port, uint32_t *bytes, uint32_t *key, uint32_t *overlapped, uint32_t timeout,
                 uint32_t *error) {
    int slot = port_slot(port);
    struct ntw_port *item;
    uint32_t waited = 0;
    if (!error || !bytes || !key || !overlapped) { if (error) *error = 87; return 0; }
    if (slot < 0) { *error = 6; return 0; }
    item = &ports[slot];
    for (;;) {
        lock_port(item);
        if (item->count) {
            *bytes = item->packets[item->head].bytes;
            *key = item->packets[item->head].key;
            *overlapped = item->packets[item->head].overlapped;
            item->head = (item->head + 1u) % NTW_IOCP_PACKETS;
            item->count--;
            unlock_port(item);
            *error = 0;
            return 1;
        }
        unlock_port(item);
        if (timeout == 0 || (timeout != 0xffffffffu && waited >= timeout)) { *error = 258; return 0; }
        if (!pause_fn) { *error = 258; return 0; }
        pause_fn();
        if (timeout != 0xffffffffu) waited++;
    }
}
int ntw_iocp_close(uint32_t handle, uint32_t *error) {
    int slot = port_slot(handle);
    if (!error || slot < 0) { if (error) *error = 6; return 0; }
    ports[slot].live = 0;
    ports[slot].count = 0;
    *error = 0;
    return 1;
}
