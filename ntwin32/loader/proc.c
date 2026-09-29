/* SPDX-License-Identifier: GPL-2.0-only
 * Windows process creation contract. The parent stores a pid only after the
 * spawn callback returns one. Compared with CreateProcessW, not copied from Wine.
 */
#include "proc.h"
#define PROC_SLOTS 8u
#define PROC_BASE 0x4300u
#define PROC_THREAD 0x4400u
static ntw_proc_ops proc_ops;
static int (*proc_waitpid)(void *user, uint32_t pid, uint32_t *status, int block);
static int (*proc_kill)(void *user, uint32_t pid);
static void *proc_wait_user;
static char command_copy[1024];
static struct {
    int live;
    int refs;
    uint32_t pid;
    int reaped;
    uint32_t exit_code;
} kids[PROC_SLOTS];

void ntw_proc_set_ops(const ntw_proc_ops *ops) {
    if (ops) proc_ops = *ops;
}
void ntw_proc_set_wait(int (*waitpid)(void *user, uint32_t pid, uint32_t *status, int block), void *user) {
    proc_waitpid = waitpid;
    proc_wait_user = user;
}
void ntw_proc_set_kill(int (*kill)(void *user, uint32_t pid)) {
    proc_kill = kill;
}
static int map_errno(int rc) {
    if (rc == -2) return 2;
    if (rc == -8) return 193;
    if (rc == -13 || rc == -1) return 5;
    if (rc == -22) return 87;
    return 31;
}
static int find_slot(uint32_t handle, int *is_thread) {
    uint32_t slot;
    if (handle >= PROC_BASE && handle < PROC_BASE + PROC_SLOTS) {
        slot = handle - PROC_BASE;
        if (!kids[slot].live) return -1;
        if (is_thread) *is_thread = 0;
        return (int)slot;
    }
    if (handle >= PROC_THREAD && handle < PROC_THREAD + PROC_SLOTS) {
        slot = handle - PROC_THREAD;
        if (!kids[slot].live) return -1;
        if (is_thread) *is_thread = 1;
        return (int)slot;
    }
    return -1;
}
int ntw_proc_owns(uint32_t handle) { return find_slot(handle, 0) >= 0; }
static int copy_token(const uint16_t **pp, char *out, uint32_t cap) {
    const uint16_t *p = *pp;
    uint32_t n = 0;
    int quoted = 0;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) { *pp = p; return 0; }
    if (*p == '"') { quoted = 1; p++; }
    while (*p && (quoted ? *p != '"' : (*p != ' ' && *p != '\t'))) {
        uint16_t ch = *p++;
        if (ch > 127 || n + 1 >= cap) return -1;
        out[n++] = (char)(ch == '\\' ? '/' : ch);
    }
    if (quoted && *p == '"') p++;
    out[n] = 0;
    *pp = p;
    return n ? 1 : 0;
}
int ntw_proc_create(const uint16_t *application, const uint16_t *command, uint32_t flags, uint32_t environment,
                    uint32_t *process, uint32_t *thread, uint32_t *pid, uint32_t *tid, uint32_t *error) {
    char path[260], tokens[12][160];
    char *argv[12];
    const uint16_t *cursor = command;
    int count = 0, taken, slot, existed, rc;
    uint32_t i, n = 0;
    (void)environment;
    if (!error || !process || !pid) return 0;
    *process = 0;
    *pid = 0;
    command_copy[0] = 0;
    if (command) {
        while (command[n] && n + 1 < sizeof command_copy) {
            command_copy[n] = (command[n] >= 32 && command[n] < 127) ? (char)command[n] : '?';
            n++;
        }
        command_copy[n] = 0;
    } else if (application) {
        while (application[n] && n + 1 < sizeof command_copy) {
            command_copy[n] = (application[n] >= 32 && application[n] < 127) ? (char)application[n] : '?';
            n++;
        }
        command_copy[n] = 0;
    }
    if (flags & 4u) { *error = 87; return 0; }
    if (!proc_ops.exists || !proc_ops.spawn || !proc_waitpid) { *error = 87; return 0; }
    path[0] = 0;
    if (application && application[0]) {
        const uint16_t *app = application;
        if (copy_token(&app, path, sizeof path) != 1) { *error = 87; return 0; }
    }
    if (cursor) {
        while (count < 12) {
            taken = copy_token(&cursor, tokens[count], 160);
            if (taken == 0) break;
            if (taken < 0) { *error = 3; return 0; }
            count++;
        }
    }
    if (!path[0]) {
        if (count < 1) { *error = 87; return 0; }
        for (i = 0; tokens[0][i] && i < 259; ++i) path[i] = tokens[0][i];
        path[i] = 0;
    }
    if (!path[0]) { *error = 87; return 0; }
    existed = proc_ops.exists(proc_ops.user, path);
    if (existed <= 0) { *error = 2; return 0; }
    argv[0] = path;
    i = path[0] ? 1u : 0u;
    {
        int start = (count > 0) ? 1 : 0;
        int t;
        for (t = start; t < count && i < 12; ++t) argv[i++] = tokens[t];
    }
    for (slot = 0; slot < (int)PROC_SLOTS; ++slot) if (!kids[slot].live) break;
    if (slot == (int)PROC_SLOTS) { *error = 4; return 0; }
    {
        uint32_t child = 0;
        rc = proc_ops.spawn(proc_ops.user, path, (int)i, argv, &child);
        if (rc < 0 || !child) { *error = (uint32_t)map_errno(rc); return 0; }
        kids[slot].live = 1;
        kids[slot].refs = 2;
        kids[slot].pid = child;
        kids[slot].reaped = 0;
        kids[slot].exit_code = 259;
        *process = PROC_BASE + (uint32_t)slot;
        if (thread) *thread = PROC_THREAD + (uint32_t)slot;
        *pid = child;
        if (tid) *tid = child;
        *error = 0;
        return 1;
    }
}
static int reap(int slot, int block, uint32_t *error) {
    uint32_t status = 0;
    int rc;
    if (kids[slot].reaped) return 1;
    rc = proc_waitpid(proc_wait_user, kids[slot].pid, &status, block);
    if (rc == 0) return 0;
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return -1; }
    kids[slot].reaped = 1;
    if ((status & 0x7fu) == 0) kids[slot].exit_code = (status >> 8) & 0xffu;
    else kids[slot].exit_code = 0xC0000000u | (status & 0x7fu);
    return 1;
}
int ntw_proc_wait(uint32_t handle, int block, uint32_t *wait_result, uint32_t *error) {
    int slot = find_slot(handle, 0);
    int got;
    if (!error || !wait_result) return 0;
    if (slot < 0) { *error = 6; return 0; }
    got = reap(slot, block, error);
    if (got < 0) return 0;
    *wait_result = got ? 0u : 258u;
    *error = 0;
    return 1;
}
int ntw_proc_exit_code(uint32_t handle, uint32_t *code, uint32_t *error) {
    int slot = find_slot(handle, 0);
    int got;
    if (!error || !code) return 0;
    if (slot < 0) { *error = 6; return 0; }
    got = reap(slot, 0, error);
    if (got < 0) return 0;
    *code = kids[slot].reaped ? kids[slot].exit_code : 259u;
    *error = 0;
    return 1;
}
int ntw_proc_terminate(uint32_t handle, uint32_t code, uint32_t *error) {
    int slot = find_slot(handle, 0);
    int got;
    if (!error || slot < 0) { if (error) *error = 6; return 0; }
    if (!kids[slot].reaped) {
        if (!proc_kill) { *error = 87; return 0; }
        if (proc_kill(proc_wait_user, kids[slot].pid) < 0) { *error = 5; return 0; }
        got = reap(slot, 1, error);
        if (got < 0) return 0;
        kids[slot].reaped = 1;
        kids[slot].exit_code = code;
    }
    *error = 0;
    return 1;
}
int ntw_proc_close(uint32_t handle, uint32_t *error) {
    int slot = find_slot(handle, 0);
    if (!error || slot < 0) { if (error) *error = 6; return 0; }
    if (kids[slot].refs > 0) kids[slot].refs--;
    if (kids[slot].refs == 0) {
        reap(slot, 0, error);
        kids[slot].live = 0;
    }
    *error = 0;
    return 1;
}
int ntw_proc_command(char *out, uint32_t cap) {
    uint32_t i = 0;
    if (!out || cap < 2) return 0;
    while (command_copy[i] && i + 1 < cap) { out[i] = command_copy[i]; i++; }
    out[i] = 0;
    return 1;
}
int ntw_proc_pid(uint32_t handle, uint32_t *pid) {
    int slot = find_slot(handle, 0);
    if (!pid || slot < 0 || !kids[slot].live) return 0;
    *pid = kids[slot].pid;
    return 1;
}
