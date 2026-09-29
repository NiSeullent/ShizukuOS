/* SPDX-License-Identifier: GPL-2.0-only */
#include "fileio.h"
static uint32_t std_value[3] = { 1u, 2u, 3u };
static const int std_fd[3] = { 0, 1, 2 };
static const int std_can_read[3] = { 1, 0, 0 };
static const int std_can_write[3] = { 0, 1, 1 };
static ntw_file_transfer transfer_fn;
static void *transfer_user;
void ntw_file_set_transfer(ntw_file_transfer transfer, void *user) {
    transfer_fn = transfer;
    transfer_user = user;
}
static int slot_for_kind(uint32_t kind) {
    if (kind == NTW_STD_INPUT) return 0;
    if (kind == NTW_STD_OUTPUT) return 1;
    if (kind == NTW_STD_ERROR) return 2;
    return -1;
}
uint32_t ntw_file_get_std(uint32_t kind) {
    int slot = slot_for_kind(kind);
    return slot < 0 ? 0xffffffffu : std_value[slot];
}
int ntw_file_set_std(uint32_t kind, uint32_t handle) {
    int slot = slot_for_kind(kind);
    if (slot < 0 || !handle) return 0;
    std_value[slot] = handle;
    return 1;
}
static int find_slot(uint32_t handle) {
    int slot;
    for (slot = 0; slot < 3; ++slot) if (std_value[slot] == handle) return slot;
    return -1;
}
static int begin(uint32_t *count, const void *overlapped, const void *buffer, uint32_t bytes, uint32_t *error) {
    if (count) *count = 0;
    if (overlapped || !count || (bytes && !buffer)) {
        *error = 87;
        return 0;
    }
    return 1;
}
int ntw_file_write(uint32_t handle, const void *buffer, uint32_t bytes, uint32_t *written, const void *overlapped, uint32_t *error) {
    int slot, moved;
    if (!error) return 0;
    if (!begin(written, overlapped, buffer, bytes, error)) return 0;
    slot = find_slot(handle);
    if (slot < 0) { *error = 6; return 0; }
    if (!std_can_write[slot]) { *error = 5; return 0; }
    if (!bytes) { *error = 0; return 1; }
    if (!transfer_fn) { *error = 1; return 0; }
    moved = transfer_fn(transfer_user, std_fd[slot], (void *)buffer, bytes, 1);
    if (moved < 0) { *error = 5; return 0; }
    *written = (uint32_t)moved;
    *error = 0;
    return 1;
}
int ntw_file_read(uint32_t handle, void *buffer, uint32_t bytes, uint32_t *read_count, const void *overlapped, uint32_t *error) {
    int slot, moved;
    if (!error) return 0;
    if (!begin(read_count, overlapped, buffer, bytes, error)) return 0;
    slot = find_slot(handle);
    if (slot < 0) { *error = 6; return 0; }
    if (!std_can_read[slot]) { *error = 5; return 0; }
    if (!bytes) { *error = 0; return 1; }
    if (!transfer_fn) { *error = 1; return 0; }
    moved = transfer_fn(transfer_user, std_fd[slot], buffer, bytes, 0);
    if (moved < 0) { *error = 5; return 0; }
    *read_count = (uint32_t)moved;
    *error = 0;
    return 1;
}
uint32_t ntw_file_type(uint32_t handle, uint32_t *error) {
    if (find_slot(handle) < 0) {
        if (error) *error = 6;
        return NTW_FILE_TYPE_UNKNOWN;
    }
    if (error) *error = 0;
    return NTW_FILE_TYPE_CHAR;
}
