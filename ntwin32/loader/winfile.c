/* SPDX-License-Identifier: GPL-2.0-only
 * Disk files for CreateFileW. Layout of the path and disposition arguments
 * follows the public CreateFileW contract. Share mode is not enforced.
 */
#include "winfile.h"
#define WIN_SLOTS 48u
#define WIN_BASE 0x4100u
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 64
#define O_EXCL 128
#define O_TRUNC 512
#define O_APPEND 1024
#define GENERIC_ALL 0x10000000u
#define GENERIC_EXECUTE 0x20000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_READ 0x80000000u
#define FILE_READ_DATA 0x1u
#define FILE_WRITE_DATA 0x2u
#define FILE_APPEND_DATA 0x4u
#define FILE_READ_ATTRIBUTES 0x80u
#define FILE_WRITE_ATTRIBUTES 0x100u
#define FILE_FLAG_OVERLAPPED 0x40000000u
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000u

static ntw_disk_ops disk;
static char drive_root[260];
static char last_unix[260];
static struct {
    int live;
    int fd;
    int can_read;
    int can_write;
    int overlapped;
    int delete_on_close;
    uint32_t handle_flags;
    int is_pipe;
    int pipe_nowait;
    int listen_fd;
    uint32_t share;
    char path[260];
} files[WIN_SLOTS];

void ntw_winfile_set_ops(const ntw_disk_ops *ops) {
    if (!ops) return;
    disk = *ops;
}
void ntw_winfile_set_root(const char *root) {
    uint32_t i = 0;
    drive_root[0] = 0;
    if (!root) return;
    while (root[i] && i + 1 < sizeof drive_root) { drive_root[i] = root[i]; i++; }
    drive_root[i] = 0;
    while (i > 1 && drive_root[i - 1] == '/') { drive_root[--i] = 0; }
}
const char *ntw_winfile_last_path(void) { return last_unix; }
const char *ntw_winfile_drive_root(void) { return drive_root; }
int ntw_winfile_path_exists(const char *path) {
    return path && disk.exists && disk.exists(disk.user, path) == 1;
}
int ntw_winfile_path_mkdir(const char *path) {
    if (!path || !disk.mkdir) return -1;
    if (ntw_winfile_path_exists(path)) return 0;
    return disk.mkdir(disk.user, path, 0755);
}
int ntw_winfile_owns(uint32_t handle) {
    uint32_t slot = handle - WIN_BASE;
    return handle >= WIN_BASE && slot < WIN_SLOTS && files[slot].live;
}
int ntw_winfile_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags) {
    uint32_t slot = handle - WIN_BASE;
    if (!ntw_winfile_owns(handle)) return 0;
    if (change) files[slot].handle_flags = (files[slot].handle_flags & ~mask) | (value & mask);
    if (flags) *flags = files[slot].handle_flags;
    return 1;
}
static int map_errno(int rc) {
    if (rc == -2) return 2;
    if (rc == -17) return 80;
    if (rc == -13 || rc == -1 || rc == -21) return 5;
    if (rc == -20) return 3;
    if (rc == -28) return 112;
    if (rc == -22) return 87;
    return 31;
}
static int to_path(const uint16_t *name, char *out, uint32_t *error) {
    uint32_t i = 0, j = 0, start = 0;
    if (!name || !name[0]) { *error = 87; return 0; }
    if (name[0] == '\\' && name[1] == '\\' && name[2] == '?' && name[3] == '\\') name += 4;
    if (name[0] == '\\' && name[1] == '\\') { *error = 3; return 0; }
    if (name[0] && name[1] == ':') {
        if (!((name[0] == 'C' || name[0] == 'c') && (name[2] == '\\' || name[2] == '/' || !name[2]))) {
            *error = 3;
            return 0;
        }
        name += 2;
    }
    if (name[0] == '\\') {
        if (!drive_root[0]) { *error = 3; return 0; }
        while (drive_root[j] && j + 1 < 260) { out[j] = drive_root[j]; j++; }
        if (j && out[j - 1] != '/') out[j++] = '/';
        start = 1;
    }
    for (i = start; name[i]; ++i) {
        uint16_t ch = name[i];
        if (ch > 127 || j + 1 >= 260) { *error = 3; return 0; }
        if (ch == '\\' || ch == '/') {
            if (j && out[j - 1] == '/') continue;
            out[j++] = '/';
            continue;
        }
        if (ch == '.' && (name[i + 1] == '.' ) && (name[i + 2] == '\\' || name[i + 2] == '/' || !name[i + 2])) {
            *error = 3;
            return 0;
        }
        out[j++] = (char)ch;
    }
    out[j] = 0;
    if (!j || (j == 1 && out[0] == '/')) { *error = 3; return 0; }
    return 1;
}
static int ensure_parents(const char *path, uint32_t *error) {
    char partial[260];
    uint32_t i = 0, n = 0;
    if (!disk.mkdir) return 1;
    while (path[n]) n++;
    for (i = 1; i < n; ++i) {
        uint32_t k;
        if (path[i] != '/') continue;
        for (k = 0; k < i && k + 1 < sizeof partial; ++k) partial[k] = path[k];
        partial[k] = 0;
        if (disk.exists && disk.exists(disk.user, partial) == 1) continue;
        if (disk.mkdir(disk.user, partial, 0755) < 0 && !(disk.exists && disk.exists(disk.user, partial) == 1)) {
            *error = 3;
            return 0;
        }
    }
    return 1;
}
static void access_bits(uint32_t access, int *read, int *write, int *append) {
    *write = (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA)) != 0;
    *read = (access & (GENERIC_READ | GENERIC_ALL | GENERIC_EXECUTE | FILE_READ_DATA | FILE_READ_ATTRIBUTES)) != 0;
    *append = (access & FILE_APPEND_DATA) && !(access & (GENERIC_WRITE | FILE_WRITE_DATA | GENERIC_ALL));
    if (!*read && !*write) *read = 1;
}
int ntw_winfile_create(const uint16_t *name, uint32_t access, uint32_t share, uint32_t disposition,
                       uint32_t flags, uint32_t template_file, uint32_t *handle, uint32_t *error) {
    char path[260];
    int can_read = 0, can_write = 0, append = 0, existed = 0, oflags = 0, fd, slot;
    uint32_t i;
    (void)share;
    if (!error || !handle) return 0;
    *handle = 0;
    if (!disk.open || !disk.close || !disk.seek || template_file) { *error = 87; return 0; }
    if (disposition < 1 || disposition > 5) { *error = 87; return 0; }
    if (name && name[0] == '\\' && name[1] == '\\' && (name[2] == '.' || name[2] == '?')) {
        static const char pipe[] = "pipe\\";
        uint32_t p = 4;
        uint32_t k;
        for (k = 0; pipe[k]; ++k) {
            uint16_t ch = name[p + k];
            char want = pipe[k];
            if (ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch - 'A' + 'a');
            if (want >= 'A' && want <= 'Z') want = (char)(want - 'A' + 'a');
            if (ch != (uint16_t)(unsigned char)want) break;
        }
        if (!pipe[k]) {
            int client = -1, slot;
            char socket_path[260];
            if (!name[p + k]) { *error = 2; return 0; }
            if (drive_root[0] && disk.pipe_connect) {
                uint32_t n = 0, s = 0;
                while (drive_root[n] && s + 8 < sizeof socket_path) { socket_path[s++] = drive_root[n++]; }
                socket_path[s++] = '/';
                socket_path[s++] = 'p'; socket_path[s++] = 'i'; socket_path[s++] = 'p'; socket_path[s++] = 'e'; socket_path[s++] = 's'; socket_path[s++] = '/';
                while (name[p + k] && s + 1 < sizeof socket_path) {
                    uint16_t ch = name[p + k++];
                    if (ch == '\\' || ch == '/') ch = '_';
                    if (ch > 127) { *error = 3; return 0; }
                    socket_path[s++] = (char)ch;
                }
                socket_path[s] = 0;
                for (n = 0; socket_path[n] && n + 1 < sizeof last_unix; ++n) last_unix[n] = socket_path[n];
                last_unix[n] = 0;
                client = disk.pipe_connect(disk.user, socket_path);
                if (client < 0) { *error = 2; return 0; }
                for (slot = 0; slot < (int)WIN_SLOTS; ++slot) if (!files[slot].live) break;
                if (slot == (int)WIN_SLOTS) { disk.close(disk.user, client); *error = 4; return 0; }
                files[slot].live = 1;
                files[slot].fd = client;
                files[slot].listen_fd = -1;
                files[slot].can_read = 1;
                files[slot].can_write = 1;
                files[slot].overlapped = 0;
                files[slot].delete_on_close = 0;
                files[slot].handle_flags = 0;
                files[slot].is_pipe = 1;
                files[slot].pipe_nowait = 0;
                files[slot].share = 0;
                for (n = 0; n < 260; ++n) files[slot].path[n] = 0;
                *handle = WIN_BASE + (uint32_t)slot;
                *error = 0;
                return 1;
            }
            *error = 2;
            return 0;
        }
    }
    if (!to_path(name, path, error)) return 0;
    for (i = 0; path[i] && i + 1 < sizeof last_unix; ++i) last_unix[i] = path[i];
    last_unix[i] = 0;
    access_bits(access, &can_read, &can_write, &append);
    if (disposition == 5 && !can_write) { *error = 87; return 0; }
    if ((disposition == 1 || disposition == 2 || disposition == 4) && !ensure_parents(path, error)) return 0;
    if (can_read && can_write) oflags = O_RDWR;
    else if (can_write) oflags = O_WRONLY;
    if (append) oflags |= O_APPEND;
    if (disk.exists) existed = disk.exists(disk.user, path) == 1;
    if (disposition == 1) oflags |= O_CREAT | O_EXCL;
    else if (disposition == 2) oflags |= O_CREAT | O_TRUNC;
    else if (disposition == 4) oflags |= O_CREAT;
    else if (disposition == 5) oflags |= O_TRUNC;
    else if (disposition == 3 && disk.exists && !existed) { *error = 2; return 0; }
    for (slot = 0; slot < (int)WIN_SLOTS; ++slot) if (!files[slot].live) break;
    if (slot == (int)WIN_SLOTS) { *error = 4; return 0; }
    fd = disk.open(disk.user, path, oflags, 0644);
    if (fd < 0) { *error = (uint32_t)map_errno(fd); return 0; }
    files[slot].live = 1;
    files[slot].fd = fd;
    files[slot].can_read = can_read;
    files[slot].can_write = can_write;
    files[slot].overlapped = (flags & FILE_FLAG_OVERLAPPED) != 0;
    files[slot].delete_on_close = (flags & FILE_FLAG_DELETE_ON_CLOSE) != 0;
    files[slot].handle_flags = 0;
    files[slot].is_pipe = 0;
    files[slot].pipe_nowait = 0;
    files[slot].listen_fd = -1;
    files[slot].share = share;
    for (i = 0; i < 260; ++i) files[slot].path[i] = 0;
    for (i = 0; path[i] && i < 259; ++i) files[slot].path[i] = path[i];
    *handle = WIN_BASE + (uint32_t)slot;
    *error = ((disposition == 2 || disposition == 4) && existed) ? 183u : 0u;
    return 1;
}
static int begin_io(uint32_t handle, const void *buffer, uint32_t bytes, uint32_t *count, const void *overlapped, uint32_t *error, int writing) {
    uint32_t slot = handle - WIN_BASE;
    if (count) *count = 0;
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    if (!count || overlapped || (bytes && !buffer)) { *error = 87; return 0; }
    if (files[slot].overlapped) { *error = 87; return 0; }
    if (writing && !files[slot].can_write) { *error = 5; return 0; }
    if (!writing && !files[slot].can_read) { *error = 5; return 0; }
    return 1;
}
int ntw_winfile_read(uint32_t handle, void *buffer, uint32_t bytes, uint32_t *count, const void *overlapped, uint32_t *error) {
    int moved;
    if (!error || !begin_io(handle, buffer, bytes, count, overlapped, error, 0)) return 0;
    if (!bytes) { *error = 0; return 1; }
    if (files[handle - WIN_BASE].is_pipe && files[handle - WIN_BASE].fd < 0) { *error = 233; return 0; }
    moved = disk.read(disk.user, files[handle - WIN_BASE].fd, buffer, bytes);
    if (moved < 0) { *error = 5; return 0; }
    *count = (uint32_t)moved;
    *error = 0;
    return 1;
}
int ntw_winfile_write(uint32_t handle, const void *buffer, uint32_t bytes, uint32_t *count, const void *overlapped, uint32_t *error) {
    int moved;
    if (!error || !begin_io(handle, buffer, bytes, count, overlapped, error, 1)) return 0;
    if (!bytes) { *error = 0; return 1; }
    if (files[handle - WIN_BASE].is_pipe && files[handle - WIN_BASE].fd < 0) { *error = 233; return 0; }
    moved = disk.write(disk.user, files[handle - WIN_BASE].fd, buffer, bytes);
    if (moved < 0) { *error = 5; return 0; }
    *count = (uint32_t)moved;
    *error = 0;
    return 1;
}
int ntw_winfile_close(uint32_t handle, uint32_t *error) {
    uint32_t slot = handle - WIN_BASE;
    int rc;
    if (!error || !ntw_winfile_owns(handle)) { if (error) *error = 6; return 0; }
    if (files[slot].handle_flags & 2u) { *error = 6; return 0; }
    rc = files[slot].fd >= 0 ? disk.close(disk.user, files[slot].fd) : 0;
    files[slot].live = 0;
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return 0; }
    if (!files[slot].is_pipe && files[slot].delete_on_close && disk.unlink && disk.unlink(disk.user, files[slot].path) < 0) {
        *error = 5;
        return 0;
    }
    *error = 0;
    return 1;
}
int ntw_winfile_seek(uint32_t handle, uint32_t lo, uint32_t hi, uint32_t *new_lo, uint32_t *new_hi, uint32_t method, uint32_t *error) {
    uint32_t got_lo = 0, got_hi = 0;
    int rc;
    if (!error) return 0;
    if (method > 2) { *error = 87; return 0; }
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    if (method == 0 && (int32_t)hi < 0) { *error = 131; return 0; }
    rc = disk.seek(disk.user, files[handle - WIN_BASE].fd, lo, hi, (int)method, &got_lo, &got_hi);
    if (rc < 0) { *error = rc == -22 ? 131u : (uint32_t)map_errno(rc); return 0; }
    if (new_lo) *new_lo = got_lo;
    if (new_hi) *new_hi = got_hi;
    *error = 0;
    return 1;
}
int ntw_winfile_size(uint32_t handle, uint32_t *lo, uint32_t *hi, uint32_t *error) {
    uint32_t cur_lo = 0, cur_hi = 0, end_lo = 0, end_hi = 0;
    if (!error || !lo || !hi) { if (error) *error = 87; return 0; }
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    if (!ntw_winfile_seek(handle, 0, 0, &cur_lo, &cur_hi, 1, error)) return 0;
    if (!ntw_winfile_seek(handle, 0, 0, &end_lo, &end_hi, 2, error)) return 0;
    if (!ntw_winfile_seek(handle, cur_lo, cur_hi, 0, 0, 0, error)) return 0;
    *lo = end_lo;
    *hi = end_hi;
    *error = 0;
    return 1;
}
int ntw_winfile_path(uint32_t handle, char *out, uint32_t cap) {
    uint32_t i = 0, slot = handle - WIN_BASE;
    if (!out || cap < 2 || !ntw_winfile_owns(handle)) return 0;
    while (files[slot].path[i] && i + 1 < cap) { out[i] = files[slot].path[i]; i++; }
    out[i] = 0;
    return 1;
}

static int same_pipe(const char *left, const char *right) {
    uint32_t i = 0;
    while (left[i] && right[i]) {
        char a = left[i], b = right[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
        i++;
    }
    return left[i] == right[i];
}
int ntw_pipe_create(const uint16_t *name, uint32_t open_mode, uint32_t pipe_mode, uint32_t instances,
                    uint32_t *handle, uint32_t *error) {
    static const char prefix[] = "\\\\.\\pipe\\";
    char path[260];
    uint32_t i, access;
    int slot;
    if (!error || !handle) return 0;
    *handle = 0;
    if (!name || !name[0] || instances == 0 || instances > 255u) { *error = 87; return 0; }
    for (i = 0; prefix[i]; ++i) {
        uint16_t ch = name[i];
        char want = prefix[i];
        if (ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch - 'A' + 'a');
        if (want >= 'A' && want <= 'Z') want = (char)(want - 'A' + 'a');
        if (!ch || ch != (uint16_t)(unsigned char)want) { *error = 123; return 0; }
    }
    if (!name[i]) { *error = 123; return 0; }
    path[0] = 0;
    for (i = 0; name[i] && i < 259; ++i) {
        uint16_t ch = name[i];
        if (ch > 127) { *error = 123; return 0; }
        path[i] = (char)ch;
    }
    path[i] = 0;
    access = open_mode & 3u;
    if (access == 0) { *error = 87; return 0; }
    if ((pipe_mode & 4u) == 0 && (pipe_mode & 2u)) { *error = 87; return 0; }
    for (slot = 0; slot < (int)WIN_SLOTS; ++slot) {
        if (files[slot].live && files[slot].is_pipe && same_pipe(files[slot].path, path)) {
            *error = (open_mode & 0x80000u) ? 183u : 231u;
            return 0;
        }
    }
    for (slot = 0; slot < (int)WIN_SLOTS; ++slot) if (!files[slot].live) break;
    if (slot == (int)WIN_SLOTS) { *error = 4; return 0; }
    files[slot].live = 1;
    files[slot].fd = -1;
    files[slot].can_read = access == 1 || access == 3;
    files[slot].can_write = access == 2 || access == 3;
    files[slot].overlapped = (open_mode & FILE_FLAG_OVERLAPPED) != 0;
    files[slot].delete_on_close = 0;
    files[slot].is_pipe = 1;
    files[slot].pipe_nowait = (pipe_mode & 1u) != 0;
    files[slot].listen_fd = -1;
    files[slot].share = 0;
    files[slot].handle_flags = 0;
    files[slot].fd = -1;
    if (drive_root[0] && disk.pipe_bind && disk.mkdir) {
        char socket_path[260];
        uint32_t s = 0, n = 0;
        int bound;
        while (drive_root[n] && s + 16 < sizeof socket_path) socket_path[s++] = drive_root[n++];
        socket_path[s++] = '/';
        socket_path[s++] = 'p'; socket_path[s++] = 'i'; socket_path[s++] = 'p'; socket_path[s++] = 'e'; socket_path[s++] = 's';
        socket_path[s] = 0;
        disk.mkdir(disk.user, socket_path, 0755);
        socket_path[s++] = '/';
        for (n = 9; path[n] && s + 1 < sizeof socket_path; ++n) {
            char ch = path[n];
            if (ch == '\\' || ch == '/') ch = '_';
            socket_path[s++] = ch;
        }
        socket_path[s] = 0;
        if (disk.unlink) disk.unlink(disk.user, socket_path);
        bound = disk.pipe_bind(disk.user, socket_path);
        if (bound < 0) { files[slot].live = 0; *error = 5; return 0; }
        files[slot].listen_fd = bound;
        files[slot].fd = bound;
    }
    for (i = 0; i < 260; ++i) files[slot].path[i] = path[i];
    *handle = WIN_BASE + (uint32_t)slot;
    *error = 0;
    return 1;
}
int ntw_pipe_connect(uint32_t handle, const void *overlapped, uint32_t *error) {
    uint32_t slot = handle - WIN_BASE;
    int accepted;
    if (!error || !ntw_winfile_owns(handle) || !files[slot].is_pipe) { if (error) *error = 6; return 0; }
    if (overlapped || files[slot].overlapped) { *error = 87; return 0; }
    if (files[slot].listen_fd >= 0 && disk.pipe_accept) {
        accepted = disk.pipe_accept(disk.user, files[slot].listen_fd);
        if (accepted < 0) { *error = files[slot].pipe_nowait ? 536u : 1460u; return 0; }
        if (files[slot].fd >= 0 && files[slot].fd != files[slot].listen_fd) disk.close(disk.user, files[slot].fd);
        files[slot].fd = accepted;
        *error = 0;
        return 1;
    }
    *error = files[slot].pipe_nowait ? 536u : 1460u;
    return 0;
}
int ntw_pipe_set_state(uint32_t handle, const uint32_t *mode, const uint32_t *collect, const uint32_t *timeout, uint32_t *error) {
    uint32_t slot = handle - WIN_BASE;
    if (!error || !ntw_winfile_owns(handle) || !files[slot].is_pipe) { if (error) *error = 6; return 0; }
    if (!mode && !collect && !timeout) { *error = 87; return 0; }
    if (mode) {
        uint32_t bits = *mode;
        if (bits & ~0x7u) { *error = 87; return 0; }
        files[slot].pipe_nowait = (bits & 1u) != 0;
    }
    *error = 0;
    return 1;
}
int ntw_pipe_transact(uint32_t handle, const void *in_buf, uint32_t in_len, void *out_buf, uint32_t out_cap,
                      uint32_t *read_count, const void *overlapped, uint32_t *error) {
    uint32_t slot = handle - WIN_BASE;
    uint32_t sent = 0, got = 0;
    if (read_count) *read_count = 0;
    if (!error || overlapped || (in_len && !in_buf) || (out_cap && !out_buf) || !read_count) {
        if (error) *error = 87;
        return 0;
    }
    if (!ntw_winfile_owns(handle) || !files[slot].is_pipe) { *error = 6; return 0; }
    if (files[slot].fd < 0 || (files[slot].listen_fd >= 0 && files[slot].fd == files[slot].listen_fd)) {
        *error = 233;
        return 0;
    }
    while (sent < in_len) {
        int wrote = disk.write(disk.user, files[slot].fd, (const uint8_t *)in_buf + sent, in_len - sent);
        if (wrote <= 0) { *error = 109; return 0; }
        sent += (uint32_t)wrote;
    }
    if (!out_cap) { *error = 0; return 1; }
    {
        int got_now = disk.read(disk.user, files[slot].fd, out_buf, out_cap);
        if (got_now < 0) { *error = 233; return 0; }
        got = (uint32_t)got_now;
    }
    *read_count = got;
    *error = 0;
    return 1;
}
static int (*meta_fn)(int fd, ntw_file_meta *out);
void ntw_winfile_set_meta(int (*fn)(int fd, ntw_file_meta *out)) { meta_fn = fn; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put64(uint8_t *p, uint32_t lo, uint32_t hi) { put32(p, lo); put32(p + 4, hi); }
static void zero_bytes(uint8_t *p, uint32_t n) { uint32_t i; for (i = 0; i < n; ++i) p[i] = 0; }
int ntw_winfile_info(uint32_t handle, uint32_t klass, void *buffer, uint32_t bytes, uint32_t *error) {
    ntw_file_meta meta;
    uint8_t *out = buffer;
    uint32_t slot, links, alloc_lo, alloc_hi, i, name_bytes = 0;
    uint64_t size, alloc;
    int rc;
    if (!error) return 0;
    if (!buffer) { *error = 87; return 0; }
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    slot = handle - WIN_BASE;
    if (files[slot].is_pipe || files[slot].fd < 0 || !meta_fn) { *error = 1; return 0; }
    rc = meta_fn(files[slot].fd, &meta);
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return 0; }
    if (klass == 0) {
        if (bytes < 40) { *error = 122; return 0; }
        zero_bytes(out, 40);
        put64(out, meta.c_lo, meta.c_hi);
        put64(out + 8, meta.a_lo, meta.a_hi);
        put64(out + 16, meta.m_lo, meta.m_hi);
        put64(out + 24, meta.ch_lo, meta.ch_hi);
        put32(out + 32, meta.attrs);
        *error = 0;
        return 1;
    }
    if (klass == 1) {
        if (bytes < 24) { *error = 122; return 0; }
        size = ((uint64_t)meta.size_hi << 32) | meta.size_lo;
        alloc = size ? (size + 4095ull) & ~4095ull : 0ull;
        alloc_lo = (uint32_t)alloc;
        alloc_hi = (uint32_t)(alloc >> 32);
        links = meta.nlink ? meta.nlink : 1u;
        zero_bytes(out, 24);
        put64(out, alloc_lo, alloc_hi);
        put64(out + 8, meta.size_lo, meta.size_hi);
        put32(out + 16, links);
        out[20] = files[slot].delete_on_close ? 1 : 0;
        out[21] = (meta.attrs & 0x10u) ? 1 : 0;
        *error = 0;
        return 1;
    }
    if (klass == 2) {
        while (files[slot].path[name_bytes]) name_bytes++;
        name_bytes *= 2u;
        if (bytes < 4) { *error = 122; return 0; }
        zero_bytes(out, bytes < 4u + name_bytes ? bytes : 4u + name_bytes);
        put32(out, name_bytes);
        if (bytes < 4u + name_bytes) { *error = 122; return 0; }
        for (i = 0; i < name_bytes / 2u; ++i) out[4 + i * 2u] = (uint8_t)files[slot].path[i];
        *error = 0;
        return 1;
    }
    if (klass == 9) {
        if (bytes < 8) { *error = 122; return 0; }
        zero_bytes(out, 8);
        put32(out, meta.attrs);
        *error = 0;
        return 1;
    }
    *error = 87;
    return 0;
}
static ntw_lock_fn lock_fn;
void ntw_winfile_set_lock(ntw_lock_fn fn) { lock_fn = fn; }
int ntw_winfile_lock(uint32_t handle, uint32_t flags, uint32_t reserved, uint32_t len_lo, uint32_t len_hi, const uint32_t *overlapped, uint32_t *error) {
    uint32_t slot, start_lo = 0, start_hi = 0;
    int rc;
    if (!error) return 0;
    if (reserved || !overlapped || (flags & ~3u)) { *error = 87; return 0; }
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    slot = handle - WIN_BASE;
    if (files[slot].is_pipe || files[slot].fd < 0 || !lock_fn) { *error = 1; return 0; }
    start_lo = overlapped[2];
    start_hi = overlapped[3];
    if (len_lo == 0xffffffffu && len_hi == 0xffffffffu) { len_lo = 0; len_hi = 0; }
    rc = lock_fn(files[slot].fd, (flags & 2u) ? 1 : 0, (flags & 1u) ? 0 : 1, start_lo, start_hi, len_lo, len_hi);
    if (rc == -11 || rc == -13) { *error = 33; return 0; }
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return 0; }
    *error = 0;
    return 1;
}
int ntw_winfile_unlock(uint32_t handle, uint32_t reserved, uint32_t len_lo, uint32_t len_hi, const uint32_t *overlapped, uint32_t *error) {
    uint32_t slot, start_lo, start_hi;
    int rc;
    if (!error) return 0;
    if (reserved || !overlapped) { *error = 87; return 0; }
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    slot = handle - WIN_BASE;
    if (files[slot].is_pipe || files[slot].fd < 0 || !lock_fn) { *error = 1; return 0; }
    start_lo = overlapped[2];
    start_hi = overlapped[3];
    if (len_lo == 0xffffffffu && len_hi == 0xffffffffu) { len_lo = 0; len_hi = 0; }
    rc = lock_fn(files[slot].fd, 2, 0, start_lo, start_hi, len_lo, len_hi);
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return 0; }
    *error = 0;
    return 1;
}
int ntw_winfile_longpath(const uint16_t *name, uint16_t *out, uint32_t cap, uint32_t *needed, uint32_t *error) {
    char path[260];
    uint32_t n = 0, i;
    if (!error || !needed) return 0;
    *needed = 0;
    if (!to_path(name, path, error)) return 0;
    if (!disk.exists || disk.exists(disk.user, path) != 1) { *error = 2; return 0; }
    while (name[n]) n++;
    if (!out || cap < n + 1u) { *needed = n + 1u; *error = 122; return 0; }
    for (i = 0; i < n; ++i) out[i] = name[i];
    out[n] = 0;
    *needed = n;
    *error = 0;
    return 1;
}
static ntw_trunc_fn trunc_fn;
void ntw_winfile_set_trunc(ntw_trunc_fn fn) { trunc_fn = fn; }
int ntw_winfile_set_end(uint32_t handle, uint32_t *error) {
    uint32_t lo = 0, hi = 0;
    int rc;
    if (!error) return 0;
    if (!ntw_winfile_owns(handle)) { *error = 6; return 0; }
    if (files[handle - WIN_BASE].is_pipe || !trunc_fn) { *error = 1; return 0; }
    if (!ntw_winfile_seek(handle, 0, 0, &lo, &hi, 1, error)) return 0;
    rc = trunc_fn(files[handle - WIN_BASE].fd, lo, hi);
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return 0; }
    *error = 0;
    return 1;
}
int ntw_winfile_delete(const uint16_t *name, uint32_t *error) {
    char path[260];
    uint32_t slot;
    int rc;
    if (!error) return 0;
    if (!to_path(name, path, error)) return 0;
    for (slot = 0; slot < WIN_SLOTS; ++slot) {
        uint32_t i = 0;
        if (!files[slot].live || files[slot].is_pipe) continue;
        while (path[i] && files[slot].path[i] && path[i] == files[slot].path[i]) i++;
        if (path[i] == files[slot].path[i] && (files[slot].share & 4u) == 0) { *error = 32; return 0; }
    }
    if (!disk.exists || disk.exists(disk.user, path) != 1) { *error = 2; return 0; }
    if (!disk.unlink) { *error = 87; return 0; }
    rc = disk.unlink(disk.user, path);
    if (rc < 0) { *error = (uint32_t)map_errno(rc); return 0; }
    *error = 0;
    return 1;
}
int ntw_winfile_attributes(const uint16_t *name, uint32_t *attrs, uint32_t *error) {
    char path[260];
    int fd, got;
    uint8_t byte;
    if (!error || !attrs) return 0;
    if (!to_path(name, path, error)) return 0;
    if (!disk.open || !disk.read || !disk.close) { *error = 87; return 0; }
    fd = disk.open(disk.user, path, 0, 0);
    if (fd < 0) { *error = (uint32_t)map_errno(fd); return 0; }
    got = disk.read(disk.user, fd, &byte, 1);
    disk.close(disk.user, fd);
    if (got == -21) *attrs = 0x10u;
    else if (got < 0) { *error = 5; return 0; }
    else *attrs = 0x20u;
    *error = 0;
    return 1;
}
int ntw_winfile_mkdirs(const uint16_t *name, uint32_t *error) {
    char path[260];
    uint32_t n = 0;
    if (!error) return 0;
    if (!to_path(name, path, error)) return 0;
    for (n = 0; path[n] && n + 1 < sizeof last_unix; ++n) last_unix[n] = path[n];
    last_unix[n] = 0;
    if (disk.exists && disk.exists(disk.user, path) == 1) { *error = 183; return 0; }
    if (!ensure_parents(path, error)) return 0;
    if (!disk.mkdir || disk.mkdir(disk.user, path, 0755) < 0) { *error = 3; return 0; }
    for (n = 0; path[n] && n + 1 < sizeof last_unix; ++n) last_unix[n] = path[n];
    last_unix[n] = 0;
    *error = 0;
    return 1;
}
uint32_t ntw_winfile_inherit_text(char *out, uint32_t cap) {
    uint32_t used = 0, slot;
    if (!out || cap < 4) return 0;
    out[0] = 0;
    for (slot = 0; slot < WIN_SLOTS; ++slot) {
        char line[40];
        uint32_t n = 0, handle, fd, i, m = 0;
        char num[16];
        if (!files[slot].live || !files[slot].is_pipe || files[slot].listen_fd < 0) continue;
        if ((files[slot].handle_flags & 1u) == 0) continue;
        handle = WIN_BASE + slot;
        fd = (uint32_t)files[slot].listen_fd;
        for (i = 0; i < 8; ++i) {
            uint32_t nib = (handle >> (28 - i * 4)) & 0xfu;
            line[n++] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
        }
        line[n++] = ' ';
        if (!fd) num[m++] = '0';
        while (fd) { num[m++] = (char)('0' + (fd % 10)); fd /= 10; }
        while (m) line[n++] = num[--m];
        line[n++] = '\n';
        line[n] = 0;
        for (i = 0; line[i] && used + 1 < cap; ++i) out[used++] = line[i];
    }
    out[used] = 0;
    return used;
}
int ntw_winfile_adopt_listen(uint32_t handle, int fd) {
    uint32_t slot = handle - WIN_BASE;
    if (handle < WIN_BASE || slot >= WIN_SLOTS || fd < 0) return 0;
    files[slot].live = 1;
    files[slot].fd = fd;
    files[slot].listen_fd = fd;
    files[slot].can_read = 1;
    files[slot].can_write = 1;
    files[slot].is_pipe = 1;
    files[slot].overlapped = 0;
    files[slot].pipe_nowait = 0;
    files[slot].delete_on_close = 0;
    files[slot].share = 0;
    files[slot].handle_flags = 1u;
    return 1;
}

#define EVENT_SLOTS 32u
#define EVENT_BASE 0x4200u
static struct {
    int live;
    int manual;
    int signaled;
    uint32_t handle_flags;
    char name[128];
} events[EVENT_SLOTS];

static int event_slot(uint32_t handle) {
    uint32_t slot = handle - EVENT_BASE;
    if (handle < EVENT_BASE || slot >= EVENT_SLOTS || !events[slot].live) return -1;
    return (int)slot;
}
int ntw_event_owns(uint32_t handle) { return event_slot(handle) >= 0; }
int ntw_event_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags) {
    int slot = event_slot(handle);
    if (slot < 0) return 0;
    if (change) events[slot].handle_flags = (events[slot].handle_flags & ~mask) | (value & mask);
    if (flags) *flags = events[slot].handle_flags;
    return 1;
}
int ntw_event_create(int manual, int initial, const uint16_t *name, uint32_t *handle, uint32_t *error) {
    char ascii[128];
    int slot, found = -1;
    uint32_t i = 0;
    if (!error || !handle) return 0;
    *handle = 0;
    ascii[0] = 0;
    if (name && name[0]) {
        while (name[i] && i + 1 < sizeof ascii) {
            if (name[i] > 127) { *error = 123; return 0; }
            ascii[i] = (char)name[i];
            i++;
        }
        if (name[i]) { *error = 123; return 0; }
        ascii[i] = 0;
        for (slot = 0; slot < (int)EVENT_SLOTS; ++slot) {
            if (!events[slot].live || !events[slot].name[0]) continue;
            if (same_pipe(events[slot].name, ascii)) { found = slot; break; }
        }
        if (found >= 0) {
            *handle = EVENT_BASE + (uint32_t)found;
            *error = 183;
            return 1;
        }
    }
    for (slot = 0; slot < (int)EVENT_SLOTS; ++slot) if (!events[slot].live) break;
    if (slot == (int)EVENT_SLOTS) { *error = 4; return 0; }
    events[slot].live = 1;
    events[slot].manual = manual ? 1 : 0;
    events[slot].signaled = initial ? 1 : 0;
    events[slot].handle_flags = 0;
    for (i = 0; i < sizeof ascii; ++i) events[slot].name[i] = ascii[i];
    *handle = EVENT_BASE + (uint32_t)slot;
    *error = 0;
    return 1;
}
int ntw_event_set(uint32_t handle, uint32_t *error) {
    int slot = event_slot(handle);
    if (slot < 0) { if (error) *error = 6; return 0; }
    events[slot].signaled = 1;
    if (error) *error = 0;
    return 1;
}
int ntw_event_reset(uint32_t handle, uint32_t *error) {
    int slot = event_slot(handle);
    if (slot < 0) { if (error) *error = 6; return 0; }
    events[slot].signaled = 0;
    if (error) *error = 0;
    return 1;
}
int ntw_event_close(uint32_t handle, uint32_t *error) {
    int slot = event_slot(handle);
    if (slot < 0) { if (error) *error = 6; return 0; }
    if (events[slot].handle_flags & 2u) { if (error) *error = 6; return 0; }
    events[slot].live = 0;
    events[slot].name[0] = 0;
    if (error) *error = 0;
    return 1;
}
int ntw_event_wait(uint32_t handle, uint32_t *result) {
    int slot = event_slot(handle);
    if (!result) return 0;
    if (slot < 0) { *result = 0xffffffffu; return 0; }
    if (!events[slot].signaled) { *result = 258u; return 1; }
    if (!events[slot].manual) events[slot].signaled = 0;
    *result = 0;
    return 1;
}

#define SEM_SLOTS 32u
#define SEM_BASE 0x4300u
static struct {
    int live;
    int32_t count;
    int32_t maximum;
    uint32_t handle_flags;
    char name[128];
} sems[SEM_SLOTS];
static int sem_slot(uint32_t handle) {
    uint32_t slot = handle - SEM_BASE;
    if (handle < SEM_BASE || slot >= SEM_SLOTS || !sems[slot].live) return -1;
    return (int)slot;
}
int ntw_sem_owns(uint32_t handle) { return sem_slot(handle) >= 0; }
int ntw_sem_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags) {
    int slot = sem_slot(handle);
    if (slot < 0) return 0;
    if (change) sems[slot].handle_flags = (sems[slot].handle_flags & ~mask) | (value & mask);
    if (flags) *flags = sems[slot].handle_flags;
    return 1;
}
int ntw_sem_create(int32_t initial, int32_t maximum, const uint16_t *name, uint32_t *handle, uint32_t *error) {
    char ascii[128];
    int slot, found = -1;
    uint32_t i = 0;
    if (!error || !handle) return 0;
    *handle = 0;
    if (maximum < 1 || initial < 0 || initial > maximum) { *error = 87; return 0; }
    ascii[0] = 0;
    if (name && name[0]) {
        while (name[i] && i + 1 < sizeof ascii) {
            if (name[i] > 127) { *error = 123; return 0; }
            ascii[i] = (char)name[i];
            i++;
        }
        if (name[i]) { *error = 123; return 0; }
        ascii[i] = 0;
        for (slot = 0; slot < (int)SEM_SLOTS; ++slot) {
            if (sems[slot].live && sems[slot].name[0] && same_pipe(sems[slot].name, ascii)) { found = slot; break; }
        }
        if (found >= 0) {
            *handle = SEM_BASE + (uint32_t)found;
            *error = 183;
            return 1;
        }
    }
    for (slot = 0; slot < (int)SEM_SLOTS; ++slot) if (!sems[slot].live) break;
    if (slot == (int)SEM_SLOTS) { *error = 4; return 0; }
    sems[slot].live = 1;
    sems[slot].count = initial;
    sems[slot].maximum = maximum;
    sems[slot].handle_flags = 0;
    for (i = 0; i < sizeof ascii; ++i) sems[slot].name[i] = ascii[i];
    *handle = SEM_BASE + (uint32_t)slot;
    *error = 0;
    return 1;
}
int ntw_sem_release(uint32_t handle, int32_t count, int32_t *previous, uint32_t *error) {
    int slot = sem_slot(handle);
    if (!error) return 0;
    if (slot < 0) { *error = 6; return 0; }
    if (count < 1) { *error = 87; return 0; }
    if (sems[slot].count > sems[slot].maximum - count) { *error = 298; return 0; }
    if (previous) *previous = sems[slot].count;
    sems[slot].count += count;
    *error = 0;
    return 1;
}
int ntw_sem_wait(uint32_t handle, uint32_t *result) {
    int slot = sem_slot(handle);
    if (!result) return 0;
    if (slot < 0) { *result = 0xffffffffu; return 0; }
    if (sems[slot].count < 1) { *result = 258u; return 1; }
    sems[slot].count -= 1;
    *result = 0;
    return 1;
}
int ntw_sem_close(uint32_t handle, uint32_t *error) {
    int slot = sem_slot(handle);
    if (slot < 0) { if (error) *error = 6; return 0; }
    if (sems[slot].handle_flags & 2u) { if (error) *error = 6; return 0; }
    sems[slot].live = 0;
    sems[slot].name[0] = 0;
    if (error) *error = 0;
    return 1;
}

static ntw_dir_next dir_next;
static void *dir_user;
void ntw_winfile_set_dir(ntw_dir_next fn, void *user) { dir_next = fn; dir_user = user; }
#define FIND_SLOTS 16u
#define FIND_BASE 0x4400u
#define FIND_DATA_BYTES 592u
static struct {
    int live;
    char directory[260];
    char pattern[128];
    uint32_t index;
} finds[FIND_SLOTS];
static int wild_match(const char *pat, const char *name) {
    while (*pat) {
        if (*pat == '*') {
            pat++;
            if (!*pat) return 1;
            while (*name) { if (wild_match(pat, name)) return 1; name++; }
            return wild_match(pat, name);
        }
        if (!*name) return 0;
        if (*pat != '?' ) {
            char a = *pat, b = *name;
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) return 0;
        }
        pat++;
        name++;
    }
    return *name == 0;
}
static void write_find_data(uint8_t *data, const char *name, int is_dir, uint32_t size_lo) {
    uint32_t i, n = 0;
    for (i = 0; i < FIND_DATA_BYTES; ++i) data[i] = 0;
    *(uint32_t *)data = is_dir ? 0x10u : 0x20u;
    *(uint32_t *)(data + 32) = size_lo;
    while (name[n] && n < 259) {
        data[44 + n * 2] = (uint8_t)name[n];
        data[45 + n * 2] = 0;
        n++;
    }
}
static int find_one(char *directory, char *pattern, uint32_t *index, uint8_t *data) {
    char name[256];
    int is_dir = 0;
    uint32_t size_lo = 0;
    if (!dir_next) return 0;
    while (*index < 4096u) {
        uint32_t at = (*index)++;
        if (!dir_next(dir_user, directory, at, name, sizeof name, &is_dir, &size_lo)) return 0;
        if (!name[0]) continue;
        if (name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2]))) continue;
        if (!wild_match(pattern, name)) continue;
        write_find_data(data, name, is_dir, size_lo);
        return 1;
    }
    return 0;
}
int ntw_find_first(const uint16_t *pattern, uint32_t level, uint32_t search, uint32_t filter, uint32_t extra,
                   void *data, uint32_t data_bytes, uint32_t *handle, uint32_t *error) {
    char path[260];
    uint32_t i, slash = 0, slot;
    if (!error || !handle) return 0;
    *handle = 0xffffffffu;
    if (!data || data_bytes < FIND_DATA_BYTES || (level > 1u) || search != 0 || filter || (extra & ~3u)) {
        *error = 87;
        return 0;
    }
    if (!to_path(pattern, path, error)) return 0;
    for (i = 0; path[i]; ++i) if (path[i] == '/') slash = i;
    if (!slash) { *error = 3; return 0; }
    for (slot = 0; slot < FIND_SLOTS; ++slot) if (!finds[slot].live) break;
    if (slot == FIND_SLOTS) { *error = 4; return 0; }
    for (i = 0; i < slash && i + 1 < sizeof finds[slot].directory; ++i) finds[slot].directory[i] = path[i];
    finds[slot].directory[i] = 0;
    for (i = 0; path[slash + 1 + i] && i + 1 < sizeof finds[slot].pattern; ++i)
        finds[slot].pattern[i] = path[slash + 1 + i];
    finds[slot].pattern[i] = 0;
    if (!finds[slot].pattern[0]) { *error = 3; return 0; }
    if (!disk.exists || disk.exists(disk.user, finds[slot].directory) != 1) { *error = 3; return 0; }
    finds[slot].index = 0;
    finds[slot].live = 1;
    if (!find_one(finds[slot].directory, finds[slot].pattern, &finds[slot].index, data)) {
        finds[slot].live = 0;
        *error = 2;
        return 0;
    }
    *handle = FIND_BASE + slot;
    *error = 0;
    return 1;
}
int ntw_find_next(uint32_t handle, void *data, uint32_t data_bytes, uint32_t *error) {
    uint32_t slot = handle - FIND_BASE;
    if (!error) return 0;
    if (handle < FIND_BASE || slot >= FIND_SLOTS || !finds[slot].live || !data || data_bytes < FIND_DATA_BYTES) {
        *error = 6;
        return 0;
    }
    if (!find_one(finds[slot].directory, finds[slot].pattern, &finds[slot].index, data)) { *error = 18; return 0; }
    *error = 0;
    return 1;
}
int ntw_find_owns(uint32_t handle) {
    uint32_t slot = handle - FIND_BASE;
    return handle >= FIND_BASE && slot < FIND_SLOTS && finds[slot].live;
}
int ntw_find_close(uint32_t handle, uint32_t *error) {
    uint32_t slot = handle - FIND_BASE;
    if (handle < FIND_BASE || slot >= FIND_SLOTS || !finds[slot].live) { if (error) *error = 6; return 0; }
    finds[slot].live = 0;
    if (error) *error = 0;
    return 1;
}
