/* SPDX-License-Identifier: GPL-2.0-only
 * CreateProcessW. A missing image returns 2. A successful return has a
 * running process id that can be waited on. No Wine body is copied.
 */
#ifndef NTW_PROC_H
#define NTW_PROC_H
#include <stdint.h>
typedef struct ntw_proc_ops {
    void *user;
    int (*exists)(void *user, const char *path);
    int (*spawn)(void *user, const char *image, int argc, char **argv, uint32_t *pid);
} ntw_proc_ops;
void ntw_proc_set_ops(const ntw_proc_ops *ops);
void ntw_proc_set_wait(int (*waitpid)(void *user, uint32_t pid, uint32_t *status, int block), void *user);
int ntw_proc_owns(uint32_t handle);
int ntw_proc_create(const uint16_t *application, const uint16_t *command, uint32_t flags, uint32_t environment,
                    uint32_t *process, uint32_t *thread, uint32_t *pid, uint32_t *tid, uint32_t *error);
int ntw_proc_wait(uint32_t handle, int block, uint32_t *wait_result, uint32_t *error);
int ntw_proc_exit_code(uint32_t handle, uint32_t *code, uint32_t *error);
void ntw_proc_set_kill(int (*kill)(void *user, uint32_t pid));
int ntw_proc_terminate(uint32_t handle, uint32_t code, uint32_t *error);
int ntw_proc_close(uint32_t handle, uint32_t *error);
int ntw_proc_command(char *out, uint32_t cap);
int ntw_proc_pid(uint32_t handle, uint32_t *pid);
#endif
