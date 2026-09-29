/* SPDX-License-Identifier: GPL-2.0-only
 * CreateFileW path and access-mask contract. Missing files fail. Creation
 * dispositions create or refuse. No Wine body is copied.
 */
#ifndef NTW_WINFILE_H
#define NTW_WINFILE_H
#include <stdint.h>
typedef struct ntw_disk_ops {
    void *user;
    int (*open)(void *user, const char *path, int flags, int mode);
    int (*close)(void *user, int fd);
    int (*read)(void *user, int fd, void *buf, uint32_t bytes);
    int (*write)(void *user, int fd, const void *buf, uint32_t bytes);
    int (*seek)(void *user, int fd, uint32_t off_lo, uint32_t off_hi, int whence, uint32_t *new_lo, uint32_t *new_hi);
    int (*exists)(void *user, const char *path);
    int (*unlink)(void *user, const char *path);
    int (*mkdir)(void *user, const char *path, int mode);
    int (*pipe_bind)(void *user, const char *path);
    int (*pipe_connect)(void *user, const char *path);
    int (*pipe_accept)(void *user, int listen_fd);
} ntw_disk_ops;
void ntw_winfile_set_ops(const ntw_disk_ops *ops);
void ntw_winfile_set_root(const char *root);
int ntw_winfile_mkdirs(const uint16_t *name, uint32_t *error);
uint32_t ntw_winfile_inherit_text(char *out, uint32_t cap);
int ntw_winfile_adopt_listen(uint32_t handle, int fd);
const char *ntw_winfile_last_path(void);
const char *ntw_winfile_drive_root(void);
int ntw_winfile_path_exists(const char *path);
int ntw_winfile_path_mkdir(const char *path);
int ntw_winfile_owns(uint32_t handle);
int ntw_winfile_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags);
int ntw_winfile_create(const uint16_t *name, uint32_t access, uint32_t share, uint32_t disposition,
                       uint32_t flags, uint32_t template_file, uint32_t *handle, uint32_t *error);
int ntw_winfile_read(uint32_t handle, void *buffer, uint32_t bytes, uint32_t *count, const void *overlapped, uint32_t *error);
int ntw_winfile_write(uint32_t handle, const void *buffer, uint32_t bytes, uint32_t *count, const void *overlapped, uint32_t *error);
int ntw_winfile_close(uint32_t handle, uint32_t *error);
int ntw_winfile_seek(uint32_t handle, uint32_t lo, uint32_t hi, uint32_t *new_lo, uint32_t *new_hi, uint32_t method, uint32_t *error);
int ntw_winfile_size(uint32_t handle, uint32_t *lo, uint32_t *hi, uint32_t *error);
int ntw_winfile_path(uint32_t handle, char *out, uint32_t cap);
int ntw_pipe_create(const uint16_t *name, uint32_t open_mode, uint32_t pipe_mode, uint32_t instances,
                    uint32_t *handle, uint32_t *error);
int ntw_pipe_connect(uint32_t handle, const void *overlapped, uint32_t *error);
int ntw_pipe_set_state(uint32_t handle, const uint32_t *mode, const uint32_t *collect, const uint32_t *timeout, uint32_t *error);
int ntw_pipe_transact(uint32_t handle, const void *in_buf, uint32_t in_len, void *out_buf, uint32_t out_cap,
                      uint32_t *read_count, const void *overlapped, uint32_t *error);
int ntw_winfile_attributes(const uint16_t *name, uint32_t *attrs, uint32_t *error);
typedef struct ntw_file_meta {
    uint32_t attrs;
    uint32_t nlink;
    uint32_t size_lo, size_hi;
    uint32_t c_lo, c_hi;
    uint32_t a_lo, a_hi;
    uint32_t m_lo, m_hi;
    uint32_t ch_lo, ch_hi;
} ntw_file_meta;
void ntw_winfile_set_meta(int (*fn)(int fd, ntw_file_meta *out));
int ntw_winfile_info(uint32_t handle, uint32_t klass, void *buffer, uint32_t bytes, uint32_t *error);
typedef int (*ntw_lock_fn)(int fd, int exclusive, int wait, uint32_t start_lo, uint32_t start_hi, uint32_t len_lo, uint32_t len_hi);
void ntw_winfile_set_lock(ntw_lock_fn fn);
int ntw_winfile_lock(uint32_t handle, uint32_t flags, uint32_t reserved, uint32_t len_lo, uint32_t len_hi, const uint32_t *overlapped, uint32_t *error);
int ntw_winfile_unlock(uint32_t handle, uint32_t reserved, uint32_t len_lo, uint32_t len_hi, const uint32_t *overlapped, uint32_t *error);
int ntw_winfile_longpath(const uint16_t *name, uint16_t *out, uint32_t cap, uint32_t *needed, uint32_t *error);
typedef int (*ntw_trunc_fn)(int fd, uint32_t lo, uint32_t hi);
void ntw_winfile_set_trunc(ntw_trunc_fn fn);
int ntw_winfile_set_end(uint32_t handle, uint32_t *error);
int ntw_winfile_delete(const uint16_t *name, uint32_t *error);
int ntw_event_owns(uint32_t handle);
int ntw_event_create(int manual, int initial, const uint16_t *name, uint32_t *handle, uint32_t *error);
int ntw_event_set(uint32_t handle, uint32_t *error);
int ntw_event_reset(uint32_t handle, uint32_t *error);
int ntw_event_close(uint32_t handle, uint32_t *error);
int ntw_event_wait(uint32_t handle, uint32_t *result);
int ntw_event_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags);
int ntw_sem_owns(uint32_t handle);
int ntw_sem_create(int32_t initial, int32_t maximum, const uint16_t *name, uint32_t *handle, uint32_t *error);
int ntw_sem_release(uint32_t handle, int32_t count, int32_t *previous, uint32_t *error);
int ntw_sem_wait(uint32_t handle, uint32_t *result);
int ntw_sem_close(uint32_t handle, uint32_t *error);
int ntw_sem_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags);
typedef int (*ntw_dir_next)(void *user, const char *directory, uint32_t index, char *name, uint32_t cap, int *is_dir, uint32_t *size_lo);
void ntw_winfile_set_dir(ntw_dir_next fn, void *user);
int ntw_find_first(const uint16_t *pattern, uint32_t level, uint32_t search, uint32_t filter, uint32_t extra, void *data, uint32_t data_bytes, uint32_t *handle, uint32_t *error);
int ntw_find_next(uint32_t handle, void *data, uint32_t data_bytes, uint32_t *error);
int ntw_find_close(uint32_t handle, uint32_t *error);
int ntw_find_owns(uint32_t handle);
#endif
