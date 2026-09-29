/* SPDX-License-Identifier: GPL-2.0-only
 * Freestanding i386 loader. It maps a PE32, keeps the subsystem version, and
 * calls static TLS PROCESS_ATTACH callbacks through ntw_loader_start.
 */
#include "start.h"
#include "critsec.h"
#include "fls.h"
#include "fileio.h"
#include "prng.h"
#include "raise.h"
#include "filemap.h"
#include "verinfo.h"
#include "sddl.h"
#include "winfile.h"
#include "shell.h"
#include "user32.h"
#include "proc.h"
#include "shutdown.h"
#include "thread.h"
#include "iocp.h"
#include "initonce.h"
#include "strcmp.h"
#include "meminfo.h"
#include "token.h"
#include "job.h"
#include "trustee.h"
#include "../sync.h"
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define O_TRUNC 512
#define PROT_RWX 7
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
extern int ntw_open(const char *path, int flags, int mode);
extern int ntw_read(int fd, void *buf, unsigned len);
extern int ntw_write(int fd, const void *buf, unsigned len);
extern int ntw_close(int fd);
extern int ntw_lseek(int fd, int off, int whence);
extern int ntw_llseek(int fd, unsigned off_hi, unsigned off_lo, uint32_t *result, int whence);
extern int ntw_unlink(const char *path);
extern int ntw_fork(void);
extern int ntw_execve(const char *path, char *const *argv, char *const *envp);
extern int ntw_waitpid(int pid, uint32_t *status, int options);
extern int ntw_dup2(int oldfd, int newfd);
extern int ntw_getpid(void);
extern int ntw_kill(int pid, int sig);
extern int ntw_readlink(const char *path, char *buf, unsigned size);
extern int ntw_mkdir(const char *path, int mode);
extern int ntw_fstat64(int fd, void *stat64);
extern int ntw_fcntl(int fd, int cmd, void *arg);
extern int ntw_ftruncate64(int fd, uint32_t pad, uint32_t length_lo, uint32_t length_hi);
extern int ntw_times(unsigned *times);
extern int ntw_clone(unsigned flags, void *stack, void *parent_tid, void *tls, void *child_tid);
extern void *ntw_mmap2(void *addr, unsigned len, int prot, int flags, int fd, unsigned pgoff);
extern int ntw_munmap(void *addr, unsigned len);
extern int ntw_set_thread_area(void *desc);
extern void ntw_load_fs(unsigned selector);
extern int ntw_clock_gettime(int clock, void *spec);
extern int ntw_syscall0(int number);
extern int ntw_getrandom(void *buffer, unsigned bytes, unsigned flags);
extern int ntw_getdents64(int fd, void *dirp, unsigned count);
extern int ntw_mprotect(void *addr, unsigned len, int prot);
extern int ntw_nanosleep(const void *request, void *remain);
extern void ntw_exit(uint32_t code);
extern void ntw_exit_group(uint32_t code);
extern int ntw_rt_sigaction(int sig, const void *act, void *old, uint32_t mask_bytes);
extern int ntw_sigaltstack(const void *stack, void *old);
extern void ntw_sigreturn(void);
static uint8_t *g_image;
static uint32_t g_image_bytes, image_size, image_entry;
static char image_path[260];
static uint8_t *dep_image;
static uint32_t dep_size, dep_entry;
static char dep_path[260];
static ntw_placed dep_placed;
static uint8_t *process_heap;
static char **host_environ;
void ntw_cs_yield(void);
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentProcessId(void);
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentThreadId(void);
void __attribute__((stdcall)) ntw_imp_Sleep(uint32_t milliseconds);
uint32_t __attribute__((stdcall)) ntw_imp_CreateFileMappingW(uint32_t file, uint32_t security, uint32_t protect,
                                                            uint32_t size_high, uint32_t size_low, uint32_t name);
uint32_t __attribute__((stdcall)) ntw_imp_MapViewOfFile(uint32_t mapping, uint32_t access, uint32_t offset_high,
                                                       uint32_t offset_low, uint32_t bytes);
uint32_t __attribute__((stdcall)) ntw_imp_UnmapViewOfFile(uint32_t address);
uint32_t __attribute__((stdcall)) ntw_imp_VirtualQuery(uint32_t address, uint32_t *info, uint32_t length);
uint32_t __attribute__((stdcall)) ntw_imp_DuplicateHandle(uint32_t source_process, uint32_t source, uint32_t target_process,
                                                         uint32_t *out, uint32_t access, uint32_t inherit, uint32_t options);
struct ntw_user_desc {
    unsigned entry_number, base_addr, limit;
    unsigned seg_32bit : 1;
    unsigned contents : 2;
    unsigned read_exec_only : 1;
    unsigned limit_in_pages : 1;
    unsigned seg_not_present : 1;
    unsigned useable : 1;
};
static unsigned log_len;
static char logbuf[65536];
static void append(const char *text);
static void append_hex(unsigned value);
static void flush_log_now(void);
static int fs_ready;
static int install_tls_fs(uint32_t slot, uint32_t index) {
    static unsigned teb[1024];
    static unsigned vector[64];
    static unsigned peb[128];
    static unsigned process_params[32];
    static unsigned process_slot[8];
    struct ntw_user_desc desc;
    unsigned i, selector, tid;
    int status;
    if (index >= 64) return -1;
    if (!fs_ready) {
        for (i = 0; i < 1024; ++i) teb[i] = 0;
        for (i = 0; i < 64; ++i) vector[i] = 0;
        for (i = 0; i < 128; ++i) peb[i] = 0;
        for (i = 0; i < 8; ++i) process_slot[i] = 0;
        tid = ntw_imp_GetCurrentThreadId();
        teb[0] = 0xffffffffu;
        teb[6] = (unsigned)(unsigned long)teb;
        teb[8] = ntw_imp_GetCurrentProcessId();
        teb[9] = tid;
        teb[11] = (unsigned)(unsigned long)vector;
        teb[12] = (unsigned)(unsigned long)peb;
        for (i = 0; i < 32; ++i) process_params[i] = 0;
        process_params[0] = 32u * 4u;
        process_params[1] = 32u * 4u;
        process_params[2] = 1u;
        process_params[6] = 0xfffffff6u;
        process_params[7] = 0xfffffff5u;
        process_params[8] = 0xfffffff4u;
        peb[2] = (unsigned)(unsigned long)g_image;
        peb[4] = (unsigned)(unsigned long)process_params;
        peb[6] = 1u;
        peb[0x28] = (unsigned)(unsigned long)process_slot;
        process_slot[1] = 0xffffffffu;
        for (i = 0; i < sizeof desc / 4; ++i) ((unsigned *)&desc)[i] = 0;
        desc.entry_number = 0xffffffffu;
        desc.base_addr = (unsigned)(unsigned long)teb;
        desc.limit = 0xfff;
        desc.seg_32bit = 1;
        desc.contents = 0;
        desc.read_exec_only = 0;
        desc.limit_in_pages = 0;
        desc.seg_not_present = 0;
        desc.useable = 1;
        status = ntw_set_thread_area(&desc);
        append("set_thread_area "); append_hex((unsigned)status); append(" entry ");
        append_hex(desc.entry_number); append("\n");
        if (status < 0) return status;
        selector = (desc.entry_number << 3) | 3u;
        ntw_load_fs(selector);
        fs_ready = 1;
    }
    if (g_image) peb[2] = (unsigned)(unsigned long)g_image;
    vector[index] = slot;
    return 0;
}
static void append(const char *text) {
    while (*text && log_len + 1 < sizeof logbuf) logbuf[log_len++] = *text++;
}
static void append_hex(unsigned value) {
    char tmp[9];
    int i;
    tmp[8] = 0;
    for (i = 7; i >= 0; --i) {
        unsigned nibble = value & 0xfu;
        tmp[i] = (char)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);
        value >>= 4;
    }
    append(tmp);
}
static void *bump_alloc(void *user, size_t bytes) {
    unsigned char **cursor = user;
    unsigned char *block;
    unsigned long aligned = ((unsigned long)*cursor + 15) & ~(unsigned long)15;
    if (!bytes || aligned + bytes < aligned) return 0;
    block = (unsigned char *)aligned;
    *cursor = block + bytes;
    return block;
}
static void bump_release(void *user, void *memory, size_t bytes) {
    (void)user; (void)memory; (void)bytes;
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16); p[3] = (uint8_t)(value >> 24);
}
static int same_name(const char *left, const char *right) {
    while (*left && *right) {
        char a = *left++, b = *right++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return *left == *right;
}
static uint32_t last_error, pointer_cookie;
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentProcess(void) { return 0xffffffffu; }
uint32_t __attribute__((stdcall)) ntw_imp_IsWow64Process(uint32_t process, uint32_t *wow64) {
    if (!wow64) { last_error = 87; return 0; }
    if (process != 0xffffffffu && process != 0x2000u) { last_error = 6; return 0; }
    *wow64 = 0;
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsWow64Process2(uint32_t process, uint16_t *process_machine, uint16_t *native_machine) {
    if (!process_machine && !native_machine) { last_error = 87; return 0; }
    if (process != 0xffffffffu && process != 0x2000u) { last_error = 6; return 0; }
    if (process_machine) *process_machine = 0;
    if (native_machine) *native_machine = 0x014cu;
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_InitializeProcThreadAttributeList(uint32_t list, uint32_t count, uint32_t flags, uint32_t *size) {
    uint32_t need;
    if (flags || !size || count == 0 || count > 8u) { last_error = 87; return 0; }
    need = 16u + count * 24u;
    if (!list || *size < need) { *size = need; last_error = 122; return 0; }
    ((uint32_t *)(unsigned long)list)[0] = 0x41545452u;
    ((uint32_t *)(unsigned long)list)[1] = count;
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_UpdateProcThreadAttribute(uint32_t list, uint32_t flags, uint32_t attribute, uint32_t value,
                                                                  uint32_t bytes, uint32_t previous, uint32_t returned) {
    if (flags || !list || previous || returned) { last_error = 87; return 0; }
    if (*(uint32_t *)(unsigned long)list != 0x41545452u) { last_error = 6; return 0; }
    if (attribute != 0x00020002u || !value || (bytes & 3u) || bytes < 4u) { last_error = 87; return 0; }
    last_error = 0;
    return 1;
}
void __attribute__((stdcall)) ntw_imp_DeleteProcThreadAttributeList(uint32_t list) {
    if (list && *(uint32_t *)(unsigned long)list == 0x41545452u) *(uint32_t *)(unsigned long)list = 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetProcessTimes(uint32_t process, uint32_t *created, uint32_t *exited, uint32_t *kernel, uint32_t *user) {
    unsigned times[4];
    int rc;
    if (!created || !exited || !kernel || !user) { last_error = 87; return 0; }
    if (process != 0xffffffffu && process != 0x2000u) { last_error = 6; return 0; }
    created[0] = 0; created[1] = 0;
    exited[0] = 0; exited[1] = 0;
    rc = ntw_times(times);
    if (rc < 0) { last_error = 5; return 0; }
    user[0] = times[0] * 100000u; user[1] = 0;
    kernel[0] = times[1] * 100000u; kernel[1] = 0;
    last_error = 0;
    return 1;
}
static int wide_is(const uint16_t *text, const char *ascii) {
    uint32_t i = 0;
    if (!text) return 0;
    for (; ascii[i]; ++i) {
        uint16_t c = text[i];
        char a = ascii[i];
        if (c >= 'A' && c <= 'Z') c = (uint16_t)(c - 'A' + 'a');
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (c != (unsigned char)a) return 0;
    }
    return text[i] == 0;
}
static int tracer_present(void) {
    char buffer[768];
    int fd, n, i;
    fd = ntw_open("/proc/self/status", 0, 0);
    if (fd < 0) return 0;
    n = ntw_read(fd, buffer, sizeof buffer - 1);
    ntw_close(fd);
    if (n < 12) return 0;
    buffer[n] = 0;
    for (i = 0; i + 11 < n; ++i) {
        if (buffer[i] == 'T' && buffer[i + 1] == 'r' && buffer[i + 2] == 'a' && buffer[i + 3] == 'c'
            && buffer[i + 4] == 'e' && buffer[i + 5] == 'r' && buffer[i + 6] == 'P' && buffer[i + 7] == 'i'
            && buffer[i + 8] == 'd' && buffer[i + 9] == ':') {
            i += 10;
            while (buffer[i] == ' ' || buffer[i] == '\t') i++;
            return buffer[i] >= '1' && buffer[i] <= '9';
        }
    }
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsDebuggerPresent(void) { return tracer_present() ? 1u : 0u; }
static void write_system_info(uint32_t *info) {
    uint32_t i;
    for (i = 0; i < 9; ++i) info[i] = 0;
    info[0] = 0;
    info[1] = 4096;
    info[2] = 0x10000u;
    info[3] = 0x7ffeffffu;
    info[4] = 1;
    info[5] = 1;
    info[6] = 586;
    info[7] = 65536;
    ((uint16_t *)info)[16] = 6;
}
void __attribute__((stdcall)) ntw_imp_GetSystemInfo(void *info) { if (info) write_system_info(info); }
void __attribute__((stdcall)) ntw_imp_GetNativeSystemInfo(void *info) { if (info) write_system_info(info); }
void __attribute__((stdcall)) ntw_imp_InitializeSListHead(void *head) {
    uint32_t *words = head;
    words[0] = 0;
    words[1] = 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_InterlockedFlushSList(void *head) {
    uint32_t *words = head;
    uint32_t next = words[0];
    words[0] = 0;
    words[1] = 0;
    return next;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetTickCount(void) {
    unsigned spec[2];
    static unsigned long long boot_ns;
    static int ready;
    unsigned long long now;
    if (ntw_clock_gettime(1, spec) < 0) return 0;
    now = (unsigned long long)spec[0] * 1000000000ull + spec[1];
    if (!ready) { boot_ns = now; ready = 1; }
    return (uint32_t)((now - boot_ns) / 1000000ull);
}
void __attribute__((stdcall)) ntw_imp_Sleep(uint32_t milliseconds) {
    unsigned spec[2];
    if (!milliseconds) { ntw_cs_yield(); return; }
    spec[0] = milliseconds / 1000u;
    spec[1] = (milliseconds % 1000u) * 1000000u;
    (void)ntw_nanosleep(spec, 0);
}
uint32_t __attribute__((stdcall)) ntw_imp_SleepEx(uint32_t milliseconds, uint32_t alertable) {
    (void)alertable;
    ntw_imp_Sleep(milliseconds);
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetModuleHandleA(const char *name) {
    if (!name) return g_image ? (uint32_t)(unsigned long)g_image : 0;
    if (same_name(name, "kernel32.dll") || same_name(name, "kernel32") || same_name(name, "kernelbase.dll") || same_name(name, "kernelbase")) return 0x1000u;
    if (same_name(name, "bcryptprimitives.dll")) return 0x1001u;
    if (dep_image && (same_name(name, "chrome_elf.dll") || same_name(name, "chrome_elf"))) return (uint32_t)(unsigned long)dep_image;
    if (same_name(name, "advapi32.dll") || same_name(name, "advapi32")) return 0x1002u;
    if (same_name(name, "shell32.dll") || same_name(name, "shell32")) return 0x1003u;
    if (same_name(name, "dbghelp.dll") || same_name(name, "dbghelp")) return 0x1004u;
    if (name[0] == 'a' || name[0] == 'A') {
        const char *p = name;
        const char *pre = "api-ms-win-appmodel-runtime";
        uint32_t i = 0;
        int match = 1;
        while (pre[i]) {
            char a = name[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (a != pre[i]) { match = 0; break; }
            i++;
        }
        if (match) return 0x1005u;
        (void)p;
    }
    append("modmissa ");
    append(name);
    {
        uint32_t frame = 0, ret = 0, image;
        __asm__ volatile("mov %%ebp, %0" : "=r"(frame));
        if (frame > 0x10000u && frame < 0xffff0000u) ret = *(uint32_t *)(unsigned long)(frame + 4u);
        image = (uint32_t)(unsigned long)g_image;
        append(" from ");
        if (image && ret >= image && ret - image < image_size) append_hex(ret - image);
        else append_hex(ret);
    }
    append("\n");
    flush_log_now();
    last_error = 126;
    return 0;
}
static uint8_t *extra_image;
static uint32_t extra_size;
uint32_t __attribute__((stdcall)) ntw_imp_GetModuleHandleExW(uint32_t flags, const uint16_t *name, uint32_t *out) {
    uint32_t address;
    if (!out) { last_error = 87; return 0; }
    if (flags & ~7u) { last_error = 87; return 0; }
    if (flags & 4u) {
        address = (uint32_t)(unsigned long)name;
        if (dep_image && address >= (uint32_t)(unsigned long)dep_image &&
            address - (uint32_t)(unsigned long)dep_image < dep_size) {
            *out = (uint32_t)(unsigned long)dep_image;
            last_error = 0;
            return 1;
        }
        if (extra_image && address >= (uint32_t)(unsigned long)extra_image &&
            address - (uint32_t)(unsigned long)extra_image < extra_size) {
            *out = (uint32_t)(unsigned long)extra_image;
            last_error = 0;
            return 1;
        }
        if (!g_image || address < (uint32_t)(unsigned long)g_image ||
            address - (uint32_t)(unsigned long)g_image >= image_size) {
            last_error = 126;
            append("modaddr ");
            append_hex(address);
            append("\n");
            flush_log_now();
            return 0;
        }
        *out = (uint32_t)(unsigned long)g_image;
        last_error = 0;
        return 1;
    }
    if (!name) {
        if (!g_image) { last_error = 6; return 0; }
        *out = (uint32_t)(unsigned long)g_image;
        return 1;
    }
    if (wide_is(name, "kernel32.dll")) { *out = 0x1000u; return 1; }
    if (wide_is(name, "bcryptprimitives.dll")) { *out = 0x1001u; return 1; }
    if (dep_image && wide_is(name, "chrome_elf.dll")) { *out = (uint32_t)(unsigned long)dep_image; return 1; }
    if (wide_is(name, "advapi32.dll")) { *out = 0x1002u; return 1; }
    append("modmiss ");
    {
        char shown[96];
        uint32_t n = 0;
        while (name[n] && n + 1 < sizeof shown) {
            shown[n] = (name[n] >= 32 && name[n] < 127) ? (char)name[n] : '?';
            n++;
        }
        shown[n] = 0;
        append(shown);
    }
    append("\n");
    flush_log_now();
    last_error = 126;
    return 0;
}
static uint32_t copy_ascii_wide(const char *path, uint16_t *buffer, uint32_t chars) {
    uint32_t n = 0;
    if (!buffer || !chars) { last_error = 122; return 0; }
    while (path[n] && n + 1 < chars) { buffer[n] = (unsigned char)path[n]; n++; }
    buffer[n] = 0;
    if (path[n]) { last_error = 122; return chars; }
    return n;
}
static char extra_path[260];
static ntwtls_process *live_tls_process;
static ntwtls_thread *live_tls_thread;
uint32_t __attribute__((stdcall)) ntw_imp_GetModuleFileNameW(uint32_t module, uint16_t *buffer, uint32_t chars) {
    const char *path = image_path;
    if (module == 0x1000u) path = "kernel32.dll";
    else if (module == 0x1001u) path = "bcryptprimitives.dll";
    else if (extra_image && module == (uint32_t)(unsigned long)extra_image) path = extra_path;
    else if (dep_image && module == (uint32_t)(unsigned long)dep_image) path = dep_path;
    else if (module && (!g_image || module != (uint32_t)(unsigned long)g_image)) {
        append("modfile ");
        append_hex(module);
        append("\n");
        flush_log_now();
        last_error = 126;
        return 0;
    }
    return copy_ascii_wide(path, buffer, chars);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetCommandLineA(void) { return (uint32_t)(unsigned long)image_path; }
static uint16_t command_line_w[1024];
static int command_line_ready;
uint32_t __attribute__((stdcall)) ntw_imp_GetCommandLineW(void) {
    uint32_t i;
    if (!command_line_ready) {
        for (i = 0; image_path[i] && i < 259; ++i) command_line_w[i] = (unsigned char)image_path[i];
        command_line_w[i] = 0;
        command_line_ready = 1;
    }
    return (uint32_t)(unsigned long)command_line_w;
}
void __attribute__((stdcall)) ntw_imp_GetStartupInfoW(void *info) {
    uint8_t *bytes = info;
    uint32_t i;
    if (!info) { last_error = 87; return; }
    for (i = 0; i < 68; ++i) bytes[i] = 0;
    *(uint32_t *)bytes = 68;
    *(uint32_t *)(bytes + 56) = NTW_STD_INPUT;
    *(uint32_t *)(bytes + 60) = NTW_STD_OUTPUT;
    *(uint32_t *)(bytes + 64) = NTW_STD_ERROR;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetACP(void) { return 1252; }
uint32_t __attribute__((stdcall)) ntw_imp_GetOEMCP(void) { return 437; }
uint32_t __attribute__((stdcall)) ntw_imp_IsValidCodePage(uint32_t page) {
    return page == 437 || page == 1252 || page == 65001 || page == 1200 ||
           page == 949 || page == 932 || page == 936 || page == 950;
}
static const uint16_t cp1252_high[32] = {
    0x20ac, 0, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
    0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017d, 0,
    0, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0, 0x017e, 0x0178
};
uint32_t __attribute__((stdcall)) ntw_imp_GetCPInfo(uint32_t page, uint8_t *info) {
    uint32_t i;
    if (!info || !ntw_imp_IsValidCodePage(page)) { last_error = 87; return 0; }
    for (i = 0; i < 18; ++i) info[i] = 0;
    if (page == 65001) info[0] = 4;
    else if (page == 1200 || page == 949 || page == 932 || page == 936 || page == 950) info[0] = 2;
    else info[0] = 1;
    info[4] = 0x3f;
    if (info[0] == 2 && page != 1200) { info[6] = 0x81; info[7] = 0xfe; }
    return 1;
}
static uint32_t counted_bytes(const char *text, int32_t length) {
    uint32_t n = 0;
    if (length < 0) {
        if (!text) return 0;
        while (text[n]) n++;
        return n + 1;
    }
    return (uint32_t)length;
}
static int cp1252_to_wide(unsigned char byte, uint16_t *out) {
    if (byte < 0x80 || byte >= 0xa0) { *out = byte; return 1; }
    if (!cp1252_high[byte - 0x80]) return 0;
    *out = cp1252_high[byte - 0x80];
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_MultiByteToWideChar(uint32_t page, uint32_t flags, const char *src,
                                                           int32_t src_len, uint16_t *dst, int32_t dst_len) {
    uint32_t count = 0, i = 0, need, bytes;
    if (!ntw_imp_IsValidCodePage(page) || (flags & ~0x8u) || src_len < -1 || dst_len < 0 || (dst_len && !dst) || !src) {
        last_error = 87;
        return 0;
    }
    if (page == 1200 || page == 949 || page == 932 || page == 936 || page == 950) { last_error = 87; return 0; }
    bytes = counted_bytes(src, src_len);
    if (src_len < 0 && !bytes) { last_error = 87; return 0; }
    if (page == 65001) {
        while (i < bytes) {
            unsigned char c = (unsigned char)src[i];
            uint32_t cp, need_bytes = 1;
            if (c < 0x80) cp = c;
            else if ((c & 0xe0) == 0xc0) { need_bytes = 2; cp = c & 0x1f; }
            else if ((c & 0xf0) == 0xe0) { need_bytes = 3; cp = c & 0x0f; }
            else if ((c & 0xf8) == 0xf0) { need_bytes = 4; cp = c & 0x07; }
            else { last_error = 1113; return 0; }
            if (i + need_bytes > bytes) { last_error = 1113; return 0; }
            for (need = 1; need < need_bytes; ++need) {
                unsigned char n = (unsigned char)src[i + need];
                if ((n & 0xc0) != 0x80) { last_error = 1113; return 0; }
                cp = (cp << 6) | (n & 0x3f);
            }
            if ((need_bytes == 2 && cp < 0x80) || (need_bytes == 3 && cp < 0x800) || (need_bytes == 4 && cp < 0x10000) || cp > 0x10ffff) {
                last_error = 1113;
                return 0;
            }
            if (dst_len && count + (cp > 0xffff ? 2u : 1u) > (uint32_t)dst_len) { last_error = 122; return 0; }
            if (dst) {
                if (cp > 0xffff) {
                    cp -= 0x10000;
                    dst[count++] = (uint16_t)(0xd800 + (cp >> 10));
                    dst[count++] = (uint16_t)(0xdc00 + (cp & 0x3ff));
                } else dst[count++] = (uint16_t)cp;
            } else count += cp > 0xffff ? 2u : 1u;
            i += need_bytes;
        }
        return count;
    }
    for (i = 0; i < bytes; ++i) {
        uint16_t wide = 0;
        if (!cp1252_to_wide((unsigned char)src[i], &wide)) {
            if (flags & 8u) { last_error = 1113; return 0; }
            wide = (unsigned char)src[i];
        }
        if (dst_len && count + 1 > (uint32_t)dst_len) { last_error = 122; return 0; }
        if (dst) dst[count] = wide;
        count++;
    }
    return count;
}
static int wide_to_1252(uint16_t wide, unsigned char *out) {
    uint32_t i;
    if (wide < 0x80 || (wide >= 0xa0 && wide <= 0xff)) { *out = (unsigned char)wide; return 1; }
    for (i = 0; i < 32; ++i) if (cp1252_high[i] == wide) { *out = (unsigned char)(0x80 + i); return 1; }
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_WideCharToMultiByte(uint32_t page, uint32_t flags, const uint16_t *src,
                                                            int32_t src_len, char *dst, int32_t dst_len,
                                                            const char *fallback, uint32_t *used_default) {
    uint32_t count = 0, i, chars = 0, n, b;
    unsigned char replacement = 0x3f;
    if (used_default) *used_default = 0;
    if (!ntw_imp_IsValidCodePage(page) || src_len < -1 || dst_len < 0 || (dst_len && !dst) || !src ||
        (flags & ~(0x400u | 0x80u))) {
        last_error = 87;
        return 0;
    }
    if (page == 1200 || page == 949 || page == 932 || page == 936 || page == 950) { last_error = 87; return 0; }
    if (fallback && fallback[0]) replacement = (unsigned char)fallback[0];
    if (src_len < 0) { while (src[chars]) chars++; chars++; }
    else chars = (uint32_t)src_len;
    for (i = 0; i < chars; ++i) {
        unsigned char bytes[4];
        uint32_t code = src[i];
        n = 1;
        if (page == 65001) {
            if (code >= 0xd800 && code <= 0xdbff && i + 1 < chars && src[i + 1] >= 0xdc00 && src[i + 1] <= 0xdfff)
                code = 0x10000u + ((code - 0xd800u) << 10) + (src[++i] - 0xdc00u);
            if (code < 0x80) bytes[0] = (unsigned char)code;
            else if (code < 0x800) {
                bytes[0] = (unsigned char)(0xc0 | (code >> 6));
                bytes[1] = (unsigned char)(0x80 | (code & 0x3f));
                n = 2;
            } else if (code < 0x10000) {
                bytes[0] = (unsigned char)(0xe0 | (code >> 12));
                bytes[1] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
                bytes[2] = (unsigned char)(0x80 | (code & 0x3f));
                n = 3;
            } else {
                bytes[0] = (unsigned char)(0xf0 | (code >> 18));
                bytes[1] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
                bytes[2] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
                bytes[3] = (unsigned char)(0x80 | (code & 0x3f));
                n = 4;
            }
        } else if (!wide_to_1252((uint16_t)code, &bytes[0])) {
            if (flags & 0x80u) { last_error = 1113; return 0; }
            bytes[0] = replacement;
            if (used_default) *used_default = 1;
        }
        if (dst_len && count + n > (uint32_t)dst_len) { last_error = 122; return 0; }
        if (dst) for (b = 0; b < n; ++b) dst[count + b] = (char)bytes[b];
        count += n;
    }
    return count;
}
static uint16_t *environment_block;
static uint32_t environment_bytes;
static uint32_t build_environment(void) {
    uint32_t chars = 1, used = 0, i;
    char **env = host_environ;
    if (environment_block) return 1;
    if (env) while (env[used]) {
        uint32_t n = 0;
        while (env[used][n]) n++;
        chars += n + 1;
        used++;
    }
    environment_bytes = chars * 2u;
    environment_block = ntw_mmap2(0, (environment_bytes + 4095u) & ~4095u, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)environment_block > 0xfffff000u) { environment_block = 0; last_error = 8; return 0; }
    i = 0;
    if (env) for (used = 0; env[used]; ++used) {
        uint32_t n = 0;
        while (env[used][n]) { environment_block[i++] = (unsigned char)env[used][n]; n++; }
        environment_block[i++] = 0;
    }
    environment_block[i] = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetEnvironmentStringsW(void) {
    if (!build_environment()) return 0;
    return (uint32_t)(unsigned long)environment_block;
}
uint32_t __attribute__((stdcall)) ntw_imp_FreeEnvironmentStringsW(uint32_t block) {
    if (!environment_block || block != (uint32_t)(unsigned long)environment_block) { last_error = 87; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetEnvironmentVariableW(const uint16_t *name, uint16_t *buffer, uint32_t chars) {
    uint32_t i = 0, name_len = 0, value = 0, n = 0, k;
    if (!name || !name[0] || !build_environment()) { last_error = 87; return 0; }
    while (name[name_len]) name_len++;
    while (environment_block[i]) {
        uint32_t start = i, eq = 0;
        int match = 1;
        while (environment_block[i]) i++;
        for (k = start; k < i; ++k) if (environment_block[k] == '=') { eq = k; break; }
        if (eq && eq - start == name_len) {
            for (k = 0; k < name_len; ++k) {
                uint16_t a = environment_block[start + k], b = name[k];
                if (a >= 'A' && a <= 'Z') a = (uint16_t)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (uint16_t)(b - 'A' + 'a');
                if (a != b) match = 0;
            }
            if (match) { value = eq + 1; n = i - value; break; }
        }
        i++;
    }
    if (!value && !n) { last_error = 203; return 0; }
    if (!buffer || chars <= n) return n + 1;
    for (k = 0; k < n; ++k) buffer[k] = environment_block[value + k];
    buffer[n] = 0;
    return n;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetProcessId(uint32_t process) {
    if (process != 0xffffffffu && process != 0x2000u) { last_error = 6; return 0; }
    return ntw_imp_GetCurrentProcessId();
}
uint32_t __attribute__((stdcall)) ntw_imp_GetThreadId(uint32_t thread) {
    if (thread != 0xfffffffeu) { last_error = 6; return 0; }
    return ntw_imp_GetCurrentThreadId();
}
uint32_t __attribute__((stdcall)) ntw_imp_GetUserDefaultLangID(void) { return 0x0409u; }
uint32_t __attribute__((stdcall)) ntw_imp_GetSystemDefaultLangID(void) { return 0x0409u; }
uint32_t __attribute__((stdcall)) ntw_imp_GetUserDefaultLCID(void) { return 0x0409u; }
uint32_t __attribute__((stdcall)) ntw_imp_GetSystemDefaultLCID(void) { return 0x0409u; }
static void unix_civil(uint32_t seconds, uint16_t *out) {
    uint32_t days = seconds / 86400u;
    uint32_t tod = seconds % 86400u;
    uint32_t z = days + 719468u;
    uint32_t era = z / 146097u;
    uint32_t doe = z - era * 146097u;
    uint32_t yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    uint32_t yday = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    uint32_t mp = (5u * yday + 2u) / 153u;
    uint32_t day = yday - (153u * mp + 2u) / 5u + 1u;
    uint32_t month = mp + (mp < 10u ? 3u : (uint32_t)-9);
    uint32_t year = yoe + era * 400u + (month <= 2u);
    out[0] = (uint16_t)year;
    out[1] = (uint16_t)month;
    out[2] = (uint16_t)((days + 4u) % 7u);
    out[3] = (uint16_t)day;
    out[4] = (uint16_t)(tod / 3600u);
    out[5] = (uint16_t)((tod / 60u) % 60u);
    out[6] = (uint16_t)(tod % 60u);
    out[7] = 0;
}
void __attribute__((stdcall)) ntw_imp_GetSystemTime(uint16_t *out) {
    unsigned spec[2];
    if (!out) return;
    if (ntw_clock_gettime(0, spec) < 0) { unix_civil(0, out); return; }
    unix_civil((uint32_t)spec[0], out);
}
void __attribute__((stdcall)) ntw_imp_GetLocalTime(uint16_t *out) { ntw_imp_GetSystemTime(out); }
static int wide_ascii_equal(const uint16_t *wide, const char *ascii) {
    while (*ascii) {
        uint16_t ch = *wide++;
        char plain = *ascii++;
        if (ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch - 'A' + 'a');
        if (plain >= 'A' && plain <= 'Z') plain = (char)(plain - 'A' + 'a');
        if (ch != (uint16_t)(unsigned char)plain) return 0;
    }
    return wide && *wide == 0;
}
static uint32_t write_locale(const char *text, uint16_t *out, uint32_t chars) {
    uint32_t n = 0, i;
    while (text[n]) n++;
    if (!out || chars < n + 1u) { last_error = 122; return 0; }
    for (i = 0; i < n; ++i) out[i] = (unsigned char)text[i];
    out[n] = 0;
    return n + 1u;
}
static const char *locale_info(uint32_t kind) {
    if (kind == 1) return "0409";
    if (kind == 0x59) return "en";
    if (kind == 0x5a) return "US";
    if (kind == 0x5c) return "en-US";
    if (kind == 0x1001) return "English";
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetUserDefaultLocaleName(uint16_t *out, uint32_t chars) {
    return write_locale("en-US", out, chars);
}
uint32_t __attribute__((stdcall)) ntw_imp_IsValidLocaleName(const uint16_t *name) {
    if (!name) { last_error = 87; return 0; }
    return wide_ascii_equal(name, "en-US") ? 1u : 0u;
}
uint32_t __attribute__((stdcall)) ntw_imp_LocaleNameToLCID(const uint16_t *name, uint32_t flags) {
    (void)flags;
    if (!name || !ntw_imp_IsValidLocaleName(name)) { last_error = 87; return 0; }
    return 0x0409u;
}
uint32_t __attribute__((stdcall)) ntw_imp_LCIDToLocaleName(uint32_t lcid, uint16_t *out, uint32_t chars, uint32_t flags) {
    (void)flags;
    if (lcid != 0x0409u) { last_error = 87; return 0; }
    return write_locale("en-US", out, chars);
}
uint32_t __attribute__((stdcall)) ntw_imp_LCMapStringEx(const uint16_t *locale, uint32_t flags, const uint16_t *src, uint32_t src_chars,
                                                       uint16_t *dest, uint32_t dest_chars, uint32_t version, uint32_t reserved, uint32_t sort) {
    uint32_t n = 0, i;
    (void)locale; (void)version; (void)reserved; (void)sort;
    if (!src || (flags & 0x400u) || (flags & ~(0x100u | 0x200u))) { last_error = 87; return 0; }
    if (src_chars == 0xffffffffu) { while (src[n]) n++; }
    else n = src_chars;
    if (!dest || dest_chars < n) { last_error = dest ? 122 : 87; return dest ? 0 : n; }
    for (i = 0; i < n; ++i) {
        uint16_t ch = src[i];
        if ((flags & 0x100u) && ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch - 'A' + 'a');
        if ((flags & 0x200u) && ch >= 'a' && ch <= 'z') ch = (uint16_t)(ch - 'a' + 'A');
        dest[i] = ch;
    }
    return n;
}
uint32_t __attribute__((stdcall)) ntw_imp_CompareStringEx(const uint16_t *locale, uint32_t flags, const uint16_t *left, uint32_t left_chars,
                                                         const uint16_t *right, uint32_t right_chars, uint32_t version, uint32_t reserved, uint32_t param) {
    uint32_t i = 0;
    (void)locale; (void)version; (void)reserved; (void)param;
    if (!left || !right) { last_error = 87; return 0; }
    if (left_chars == 0xffffffffu) { left_chars = 0; while (left[left_chars]) left_chars++; }
    if (right_chars == 0xffffffffu) { right_chars = 0; while (right[right_chars]) right_chars++; }
    while (i < left_chars && i < right_chars) {
        uint16_t a = left[i], b = right[i];
        if (flags & 1u) {
            if (a >= 'A' && a <= 'Z') a = (uint16_t)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (uint16_t)(b - 'A' + 'a');
        }
        if (a < b) return 1;
        if (a > b) return 3;
        i++;
    }
    if (left_chars < right_chars) return 1;
    if (left_chars > right_chars) return 3;
    return 2;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetLocaleInfoEx(const uint16_t *locale, uint32_t kind, uint16_t *out, uint32_t chars) {
    const char *text;
    if (locale && locale[0] && !wide_ascii_equal(locale, "en-US")) { last_error = 87; return 0; }
    text = locale_info(kind);
    if (!text) { last_error = 87; return 0; }
    if (!chars) return write_locale(text, (uint16_t *)0, 0) ? 0 : 0;
    return write_locale(text, out, chars);
}
static uint32_t format_two(uint16_t *out, uint32_t chars, uint16_t a, uint16_t b, uint16_t c, int three) {
    char text[16];
    uint32_t n = 0;
    text[n++] = (char)('0' + (a / 10) % 10); text[n++] = (char)('0' + a % 10); text[n++] = '/';
    text[n++] = (char)('0' + (b / 10) % 10); text[n++] = (char)('0' + b % 10);
    if (three) { text[n++] = '/'; text[n++] = (char)('0' + (c / 1000) % 10); text[n++] = (char)('0' + (c / 100) % 10); text[n++] = (char)('0' + (c / 10) % 10); text[n++] = (char)('0' + c % 10); }
    text[n] = 0;
    return write_locale(text, out, chars);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetDateFormatEx(const uint16_t *locale, uint32_t flags, uint16_t *time, const uint16_t *format,
                                                         uint16_t *out, uint32_t chars, const uint16_t *calendar) {
    uint16_t now[8];
    (void)locale; (void)flags; (void)format; (void)calendar;
    if (time) { now[0] = time[0]; now[1] = time[1]; now[3] = time[3]; }
    else ntw_imp_GetSystemTime(now);
    return format_two(out, chars, now[1], now[3], now[0], 1);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetTimeFormatEx(const uint16_t *locale, uint32_t flags, uint16_t *time, const uint16_t *format,
                                                         uint16_t *out, uint32_t chars) {
    uint16_t now[8];
    char text[16];
    (void)locale; (void)flags; (void)format;
    if (time) { now[4] = time[4]; now[5] = time[5]; now[6] = time[6]; }
    else ntw_imp_GetSystemTime(now);
    text[0] = (char)('0' + (now[4] / 10) % 10); text[1] = (char)('0' + now[4] % 10); text[2] = ':';
    text[3] = (char)('0' + (now[5] / 10) % 10); text[4] = (char)('0' + now[5] % 10); text[5] = ':';
    text[6] = (char)('0' + (now[6] / 10) % 10); text[7] = (char)('0' + now[6] % 10); text[8] = 0;
    return write_locale(text, out, chars);
}
uint32_t __attribute__((stdcall)) ntw_imp_EnumSystemLocalesEx(uint32_t callback, uint32_t flags, uint32_t param, uint32_t reserved) {
    static uint16_t name[] = {'e','n','-','U','S', 0};
    uint32_t ok;
    (void)flags; (void)reserved;
    if (!callback) { last_error = 87; return 0; }
    ok = ((uint32_t __attribute__((stdcall)) (*)(uint16_t *, uint32_t, uint32_t))(unsigned long)callback)(name, 0, param);
    return ok ? 1u : 0u;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetProductInfo(uint32_t major, uint32_t minor, uint32_t sp_major, uint32_t sp_minor, uint32_t *product) {
    (void)major;
    (void)minor;
    (void)sp_major;
    (void)sp_minor;
    if (!product) { last_error = 87; return 0; }
    *product = 0x30u;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetVersionExW(uint8_t *info) {
    uint32_t size, i;
    if (!info) { last_error = 87; return 0; }
    size = *(uint32_t *)info;
    if (size != 276 && size != 284) { last_error = 87; return 0; }
    for (i = 4; i < size; ++i) info[i] = 0;
    *(uint32_t *)(info + 4) = 10;
    *(uint32_t *)(info + 8) = 0;
    *(uint32_t *)(info + 12) = 19041;
    *(uint32_t *)(info + 16) = 2;
    if (size == 284) info[282] = 1;
    return 1;
}
uint64_t __attribute__((stdcall)) ntw_imp_VerSetConditionMask(uint64_t mask, uint32_t type, uint8_t condition) {
    uint32_t bit;
    for (bit = 0; bit < 8; ++bit) if (type & (1u << bit)) {
        mask &= ~((uint64_t)7 << (bit * 3));
        mask |= (uint64_t)(condition & 7u) << (bit * 3);
    }
    return mask;
}
static int version_compare(uint32_t have, uint32_t want, uint32_t condition) {
    if (condition == 1) return have == want;
    if (condition == 2) return have > want;
    if (condition == 3) return have >= want;
    if (condition == 4) return have < want;
    if (condition == 5) return have <= want;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_VerifyVersionInfoW(uint8_t *info, uint32_t type, uint64_t mask) {
    static const uint32_t have_number[4] = {0, 10, 19041, 2};
    uint32_t bit;
    if (!info || *(uint32_t *)info != 284) { last_error = 87; return 0; }
    for (bit = 0; bit < 8; ++bit) {
        uint32_t condition = (uint32_t)((mask >> (bit * 3)) & 7u);
        uint32_t want, have;
        int ok;
        if (!(type & (1u << bit)) || !condition) continue;
        if (bit < 4) {
            want = *(uint32_t *)(info + 4 + bit * 4);
            if (bit == 0) want = *(uint32_t *)(info + 8);
            if (bit == 1) want = *(uint32_t *)(info + 4);
            have = have_number[bit == 0 ? 0 : bit];
            ok = version_compare(have, want, condition);
        } else if (bit == 4) {
            ok = version_compare(0, *(uint16_t *)(info + 278), condition);
        } else if (bit == 5) {
            ok = version_compare(0, *(uint16_t *)(info + 276), condition);
        } else if (bit == 6) {
            uint32_t suite = *(uint16_t *)(info + 280);
            ok = condition == 6 ? (0 & suite) == suite : condition == 7 && (0 & suite) != 0;
        } else {
            ok = condition == 1 && info[282] == 1;
        }
        if (!ok) { last_error = 1150; return 0; }
    }
    return 1;
}
void __attribute__((stdcall)) ntw_imp_ExitProcess(uint32_t code) {
    uint32_t frame = 0, image, depth;
    append("exit process ");
    append_hex(code);
    append(" lasterr ");
    append_hex(last_error);
    image = (uint32_t)(unsigned long)g_image;
    __asm__ volatile("mov %%ebp, %0" : "=r"(frame));
    for (depth = 0; depth < 12u && frame > 0x10000u && frame < 0xffff0000u; ++depth) {
        uint32_t ret = *(uint32_t *)(unsigned long)(frame + 4u);
        uint32_t next = *(uint32_t *)(unsigned long)frame;
        append(" ");
        if (image && ret >= image && ret - image < image_size) append_hex(ret - image);
        else append_hex(ret);
        if (next <= frame) break;
        frame = next;
    }
    append("\n");
    flush_log_now();
    ntw_exit(code);
}
static uint32_t unhandled_filter;
typedef struct ntw_fiber {
    uint32_t parameter;
    uint32_t start;
    uint32_t stack;
    uint32_t stack_bytes;
    uint32_t flags;
    uint32_t live;
    uint32_t esp;
    uint32_t ebp_saved;
    uint32_t exception_list;
    uint32_t ebx_saved;
    uint32_t esi_saved;
    uint32_t edi_saved;
} ntw_fiber;
static ntw_fiber fibers[32];
static ntw_fiber *current_fiber;
extern void ntw_fiber_switch(ntw_fiber *from, ntw_fiber *to);
extern void ntw_fiber_bootstrap(void);
extern int ntw_chdir(const char *path);
extern int ntw_getcwd(char *buffer, unsigned size);
static char current_directory[260];
static uint16_t current_directory_w[260];
static int directory_ready;
static int refresh_directory(void) {
    uint32_t i;
    if (ntw_getcwd(current_directory, sizeof current_directory) < 0) return 0;
    for (i = 0; current_directory[i] && i < 259; ++i) current_directory_w[i] = (unsigned char)current_directory[i];
    current_directory_w[i] = 0;
    directory_ready = 1;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetCurrentDirectoryW(const uint16_t *path) {
    char narrow[260];
    uint32_t i;
    if (!path || !path[0]) { last_error = 3; return 0; }
    for (i = 0; path[i] && i < 259; ++i) {
        if (path[i] > 0x7f) { last_error = 3; return 0; }
        narrow[i] = (char)path[i];
    }
    narrow[i] = 0;
    if (ntw_chdir(narrow) < 0) { last_error = 3; return 0; }
    directory_ready = 0;
    if (!refresh_directory()) { last_error = 3; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentDirectoryW(uint32_t chars, uint16_t *buffer) {
    uint32_t n = 0;
    if (!directory_ready && !refresh_directory()) { last_error = 3; return 0; }
    while (current_directory_w[n]) n++;
    if (!buffer || chars <= n) return n + 1;
    for (n = 0; current_directory_w[n]; ++n) buffer[n] = current_directory_w[n];
    buffer[n] = 0;
    return n;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetTempPathW(uint32_t chars, uint16_t *buffer) {
    static const char path[] = "/tmp/";
    uint32_t n = 0, i;
    while (path[n]) n++;
    if (!buffer || chars <= n) return n + 1;
    for (i = 0; i < n; ++i) buffer[i] = (unsigned char)path[i];
    buffer[n] = 0;
    return n;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFullPathNameW(const uint16_t *name, uint32_t chars, uint16_t *buffer,
                                                         uint32_t *file_part) {
    uint16_t norm[520];
    uint32_t n = 0, i, slash = 0, mark[64], marks = 0;
    int drive = 0;
    const uint16_t *cursor = name;
    if (!name || !name[0]) { last_error = 3; return 0; }
    if (name[0] == '\\' && name[1] == '\\') { last_error = 3; return 0; }
    if (name[1] == ':') {
        if (!(name[0] == 'C' || name[0] == 'c')) { last_error = 3; return 0; }
        cursor = name + 2;
        drive = 1;
    }
    if (!drive && cursor[0] != '/' && cursor[0] != '\\') {
        if (!directory_ready && !refresh_directory()) { last_error = 3; return 0; }
        while (current_directory_w[n] && n < 400) { norm[n] = current_directory_w[n]; n++; }
        if (n && norm[n - 1] != '/' && norm[n - 1] != '\\') norm[n++] = '/';
    }
    for (i = 0; cursor[i] && n < 519; ++i) {
        uint16_t ch = cursor[i];
        if (ch == '\\') ch = '/';
        if (ch == '/' && n && norm[n - 1] == '/') continue;
        norm[n++] = ch;
    }
    norm[n] = 0;
    if (!n) { last_error = 3; return 0; }
    {
        uint32_t out_n = drive ? 3u : 0u;
        uint16_t out[520];
        if (drive) { out[0] = 'C'; out[1] = ':'; out[2] = '\\'; }
        i = 0;
        if (norm[0] == '/') i = 1;
        while (norm[i]) {
            uint32_t start = i, len;
            while (norm[i] && norm[i] != '/') i++;
            len = i - start;
            if (norm[i] == '/') i++;
            if (!len || (len == 1 && norm[start] == '.')) continue;
            if (len == 2 && norm[start] == '.' && norm[start + 1] == '.') {
                if (!marks) { last_error = 3; return 0; }
                out_n = mark[--marks];
                continue;
            }
            if (out_n && out[out_n - 1] != '\\') out[out_n++] = drive ? '\\' : '/';
            if (marks < 64) mark[marks++] = out_n;
            while (len && out_n < 519) { out[out_n++] = norm[start++]; len--; }
        }
        out[out_n] = 0;
        slash = 0;
        for (i = 0; i < out_n; ++i) if (out[i] == '\\' || out[i] == '/') slash = i + 1;
        if (!buffer || chars <= out_n) return out_n + 1;
        for (i = 0; i < out_n; ++i) buffer[i] = out[i];
        buffer[out_n] = 0;
        if (file_part) *file_part = (uint32_t)(unsigned long)(buffer + slash);
        return out_n;
    }
}
static int claim_fiber(uint32_t flags, uint32_t *index) {
    uint32_t i;
    if (flags & ~1u) { last_error = 87; return 0; }
    for (i = 0; i < 32; ++i) if (!fibers[i].live) { *index = i; return 1; }
    last_error = 8;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsThreadAFiber(void) {
    append("isfiber ");
    append_hex(current_fiber ? 1u : 0u);
    append("\n");
    flush_log_now();
    return current_fiber ? 1u : 0u;
}
uint32_t __attribute__((stdcall)) ntw_imp_ConvertThreadToFiberEx(uint32_t parameter, uint32_t flags) {
    uint32_t index;
    if (current_fiber) { last_error = 0x80; return 0; }
    if (!claim_fiber(flags, &index)) return 0;
    append("convert fiber flags ");
    append_hex(flags);
    append("\n");
    flush_log_now();
    fibers[index].parameter = parameter;
    fibers[index].flags = flags;
    fibers[index].live = 1;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(fibers[index].exception_list));
    current_fiber = &fibers[index];
    return (uint32_t)(unsigned long)current_fiber;
}
uint32_t __attribute__((stdcall)) ntw_imp_ConvertThreadToFiber(uint32_t parameter) {
    return ntw_imp_ConvertThreadToFiberEx(parameter, 0);
}
uint32_t __attribute__((stdcall)) ntw_imp_ConvertFiberToThread(void) {
    if (!current_fiber) { last_error = 87; return 0; }
    current_fiber->live = 0;
    current_fiber = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateFiberEx(uint32_t commit, uint32_t reserve, uint32_t flags,
                                                      uint32_t start, uint32_t parameter) {
    uint32_t bytes, index;
    uint32_t *stack_top;
    void *stack;
    if (!start) { last_error = 87; return 0; }
    if (!claim_fiber(flags, &index)) return 0;
    if (!reserve) reserve = 1024u * 1024u;
    if (commit > reserve) commit = reserve;
    bytes = (reserve + 4095u) & ~4095u;
    if (bytes < 4096u || bytes > 16u * 1024u * 1024u) { last_error = 8; return 0; }
    (void)commit;
    stack = ntw_mmap2(0, bytes, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)stack > 0xfffff000u) { last_error = 8; return 0; }
    stack_top = (uint32_t *)(((uintptr_t)stack + bytes) & ~(uintptr_t)15u);
    stack_top -= 4;
    stack_top[0] = (uint32_t)(unsigned long)ntw_fiber_bootstrap;
    stack_top[1] = start;
    stack_top[2] = parameter;
    fibers[index].parameter = parameter;
    fibers[index].start = start;
    fibers[index].stack = (uint32_t)(unsigned long)stack;
    fibers[index].stack_bytes = bytes;
    fibers[index].flags = flags;
    fibers[index].live = 1;
    fibers[index].esp = (uint32_t)(unsigned long)stack_top;
    fibers[index].ebp_saved = 0;
    fibers[index].exception_list = NTW_EX_CHAIN_END;
    fibers[index].ebx_saved = 0;
    fibers[index].esi_saved = 0;
    fibers[index].edi_saved = 0;
    return (uint32_t)(unsigned long)&fibers[index];
}
uint32_t __attribute__((stdcall)) ntw_imp_DeleteFiber(uint32_t fiber) {
    ntw_fiber *slot = (ntw_fiber *)(unsigned long)fiber;
    uint32_t i;
    if (slot == current_fiber) { last_error = 87; return 0; }
    for (i = 0; i < 32; ++i) if (fibers[i].live && &fibers[i] == slot) {
        if (slot->stack) ntw_munmap((void *)(unsigned long)slot->stack, slot->stack_bytes);
        slot->live = 0;
        return 0;
    }
    last_error = 6;
    return 0;
}
void __attribute__((stdcall)) ntw_imp_SwitchToFiber(uint32_t fiber) {
    ntw_fiber *target = (ntw_fiber *)(unsigned long)fiber;
    ntw_fiber *from = current_fiber;
    if (!from || !target || !target->live || !target->esp) return;
    current_fiber = target;
    ntw_fiber_switch(from, target);
}
uint32_t __attribute__((stdcall)) ntw_imp_SetUnhandledExceptionFilter(uint32_t filter) {
    uint32_t previous = unhandled_filter;
    unhandled_filter = filter;
    return previous;
}
uint32_t __attribute__((stdcall)) ntw_imp_UnhandledExceptionFilter(uint32_t pointers) {
    typedef uint32_t __attribute__((stdcall)) (*filter_fn)(uint32_t);
    if (unhandled_filter) return ((filter_fn)(unsigned long)unhandled_filter)(pointers);
    if (tracer_present()) return 0;
    return 1;
}
extern void ntw_resume(uint32_t eip, uint32_t esp, uint32_t ebp, uint32_t eax);
static uint32_t raise_esp;
static int raise_frame_ok(uint32_t frame, void *user) {
    (void)user;
    return frame > 0x10000u && frame < 0xffff0000u;
}
static int32_t raise_top_filter(ntw_ex_pointers *pointers, void *user) {
    (void)user;
    if (!unhandled_filter) return tracer_present() ? NTW_EX_CONTINUE_SEARCH : NTW_EX_EXECUTE_HANDLER;
    return (int32_t)ntw_imp_UnhandledExceptionFilter((uint32_t)(unsigned long)pointers);
}
static void flush_log_now(void) {
    int out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
    ntw_write(1, logbuf, log_len);
}
static void user_log(const char *text) {
    append(text);
    flush_log_now();
}
static int fastfail_once;
static void fastfail_signal(int sig, uint32_t info, uint32_t context) {
    uint32_t *uc = (uint32_t *)(unsigned long)context;
    uint32_t *si = (uint32_t *)(unsigned long)info;
    uint32_t ecx = 0, edx = 0, eax = 0, ebx = 0, eip = 0, esp = 0, ebp = 0, caller = 0, image;
    uint32_t fault = 0, code = 0;
    if (fastfail_once) ntw_exit_group(41);
    fastfail_once = 1;
    if (si) {
        code = si[2];
        fault = si[3];
    }
    if (uc) {
        ecx = uc[15];
        edx = uc[14];
        eax = uc[16];
        ebx = uc[13];
        eip = uc[19];
        esp = uc[12];
        ebp = uc[11];
    }
    append("sig "); append_hex((unsigned)sig);
    append(" code "); append_hex(code);
    append(" addr "); append_hex(fault);
    append(" ecx "); append_hex(ecx);
    append(" eax "); append_hex(eax);
    append(" ebx "); append_hex(ebx);
    append(" edx "); append_hex(edx);
    append(" eip "); append_hex(eip);
    image = (uint32_t)(unsigned long)g_image;
    if (image && eip >= image && eip - image < image_size) {
        append(" rva "); append_hex(eip - image);
    }
    if (extra_image && eip >= (uint32_t)(unsigned long)extra_image &&
        eip - (uint32_t)(unsigned long)extra_image < extra_size) {
        append(" dll-rva ");
        append_hex(eip - (uint32_t)(unsigned long)extra_image);
    }
    append(" esp "); append_hex(esp);
    append(" ebp "); append_hex(ebp);
    if (eip > 0x10000u && eip < 0xffff0000u) {
        uint8_t *opb = (uint8_t *)(unsigned long)eip;
        uint32_t n;
        append(" bytes");
        for (n = 0; n < 8; ++n) { append(" "); append_hex(opb[n]); }
        if (opb[0] == 0xcd && opb[1] == 0x29) append(" int29");
    }
    if (!fault || fault < 0x10000u) append(" kind null");
    else if (fault == eip) append(" kind fetch");
    else if (code == 2) append(" kind guard");
    else if (extra_image && fault >= (uint32_t)(unsigned long)extra_image &&
             fault - (uint32_t)(unsigned long)extra_image < extra_size) append(" kind dll");
    else append(" kind unmapped");
    if (esp > 0x10000u && esp < 0xffff0000u) {
        caller = *(uint32_t *)(unsigned long)esp;
        append(" caller "); append_hex(caller);
        if (extra_image && caller >= (uint32_t)(unsigned long)extra_image &&
            caller - (uint32_t)(unsigned long)extra_image < extra_size) {
            append(" dll-caller ");
            append_hex(caller - (uint32_t)(unsigned long)extra_image);
        }
        if (image && caller >= image && caller - image < image_size) {
            append(" exe-caller ");
            append_hex(caller - image);
        }
    }
    append("\n");
    flush_log_now();
    {
        struct { uint32_t handler, flags, restorer, mask0, mask1; } sa;
        sa.handler = 0;
        sa.flags = 0;
        sa.restorer = 0;
        sa.mask0 = 0;
        sa.mask1 = 0;
        ntw_rt_sigaction(11, &sa, 0, 8);
    }
}
static void install_fastfail_log(void) {
    struct { uint32_t handler, flags, restorer, mask0, mask1; } sa;
    int rc;
    {
        uint32_t alt[4];
        uint8_t *stack = ntw_mmap2(0, 16384, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        alt[0] = (uint32_t)(unsigned long)stack;
        alt[1] = 0;
        alt[2] = 16384;
        alt[3] = 0;
        if ((unsigned)stack <= 0xfffff000u) {
            int alt_rc = ntw_sigaltstack(alt, 0);
            append("altstack ");
            append_hex((unsigned)alt_rc);
            append("\n");
        }
    }
    sa.handler = (uint32_t)(unsigned long)fastfail_signal;
    sa.flags = 4u | 0x04000000u | 0x08000000u;
    sa.restorer = (uint32_t)(unsigned long)ntw_sigreturn;
    sa.mask0 = 0;
    sa.mask1 = 0;
    rc = ntw_rt_sigaction(11, &sa, 0, 8);
    append("fastfail watch "); append_hex((unsigned)rc); append("\n");
    flush_log_now();
}
void __attribute__((stdcall)) ntw_imp_RaiseException(uint32_t code, uint32_t flags, uint32_t count, uint32_t arguments) {
    ntw_ex_record record;
    ntw_context context;
    uint32_t seh = NTW_EX_CHAIN_END, final_code = 0, i;
    uint32_t *params = (uint32_t *)(unsigned long)arguments;
    uint8_t *bytes = (uint8_t *)&context;
    if (count > NTW_EX_MAXIMUM_PARAMETERS || (count && !arguments)) { last_error = 87; return; }
    for (i = 0; i < sizeof context; ++i) bytes[i] = 0;
    for (i = 0; i < sizeof record; ++i) ((uint8_t *)&record)[i] = 0;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(seh));
    __asm__ volatile("mov %%esp, %0" : "=r"(raise_esp));
    __asm__ volatile("mov %%ebp, %0" : "=r"(context.Ebp));
    context.Eip = (uint32_t)(unsigned long)__builtin_return_address(0);
    context.Esp = raise_esp;
    context.ContextFlags = 0x10007u;
    record.code = code;
    record.flags = flags;
    record.address = context.Eip;
    record.count = count;
    for (i = 0; i < count; ++i) record.info[i] = params[i];
    if (code != 0x406D1388u) {
        append("raise ");
        append_hex(code);
        append(" flags ");
        append_hex(flags);
        append(" params ");
        append_hex(count);
        append("\n");
        flush_log_now();
    }
    if (ntw_raise_software(&record, &context, seh, raise_frame_ok, 0, raise_top_filter, 0, &final_code) == NTW_RAISE_RESUME)
        return;
    if (code == 0x406D1388u) {
        append("thread name continued\n");
        flush_log_now();
        return;
    }
    append("unhandled exception "); append_hex(final_code);
    append(" seh "); append_hex(seh);
    append(" params "); append_hex(record.count);
    if (record.count) {
        uint32_t info = record.info[0];
        append(" info "); append_hex(info); append("\n");
        flush_log_now();
        if (info > 0x10000u && info < 0xffff0000u && (info & 3u) == 0) {
            uint32_t name = *(uint32_t *)(unsigned long)(info + 12u);
            append("nameptr "); append_hex(name); append("\n");
            flush_log_now();
            if (name > 0x10000u && name < 0xffff0000u) {
                const char *text = (const char *)(unsigned long)name;
                uint32_t n = 0;
                append("delay ");
                while (text[n] && n < 80 && (unsigned char)text[n] >= 32 && (unsigned char)text[n] < 127) {
                    char one[2];
                    one[0] = text[n];
                    one[1] = 0;
                    append(one);
                    n++;
                }
                append("\n");
            }
        }
    } else append("\n");
    if (record.count) {
        uint32_t info = record.info[0];
        uint32_t image = (uint32_t)(unsigned long)g_image;
        uint32_t dep = (uint32_t)(unsigned long)dep_image;
        int info_ok = (g_image && info >= image && info + 16u - image < 8u * 1024u * 1024u) ||
                      (dep_image && info >= dep && info + 16u - dep < 8u * 1024u * 1024u);
        if (info_ok) {
            uint32_t name = *(uint32_t *)(unsigned long)(info + 12u);
            int name_ok = (g_image && name >= image && name - image < 8u * 1024u * 1024u) ||
                          (dep_image && name >= dep && name - dep < 8u * 1024u * 1024u);
            if (name_ok) { append("delay "); append((const char *)(unsigned long)name); append("\n"); }
        }
    }
    flush_log_now();
    ntw_exit(final_code ? final_code : 1u);
}
void __attribute__((stdcall)) ntw_imp_RtlUnwind(uint32_t target, uint32_t target_ip, uint32_t record_ptr, uint32_t retval) {
    ntw_ex_record *record = (ntw_ex_record *)(unsigned long)record_ptr;
    ntw_context context;
    uint32_t head = NTW_EX_CHAIN_END, error = 0, i;
    uint8_t *bytes = (uint8_t *)&context;
    for (i = 0; i < sizeof context; ++i) bytes[i] = 0;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(head));
    __asm__ volatile("mov %%esp, %0" : "=r"(raise_esp));
    __asm__ volatile("mov %%ebp, %0" : "=r"(context.Ebp));
    context.Eip = target_ip;
    context.Esp = target ? target : raise_esp;
    if (!ntw_unwind_chain(&head, target, record, &context, raise_frame_ok, 0, &error) || !target_ip) {
        append("unwind failed "); append_hex(error); append("\n");
        flush_log_now();
        ntw_exit(record ? record->code : 1u);
    }
    __asm__ volatile("mov %0, %%fs:0" :: "r"(head) : "memory");
    ntw_resume(target_ip, context.Esp, context.Ebp, retval);
}
uint32_t __attribute__((stdcall)) ntw_imp_AddVectoredExceptionHandler(uint32_t first, uint32_t routine) {
    uint32_t handle = 0;
    if (!ntw_veh_add(first, (ntw_veh_routine)(unsigned long)routine, &handle, &last_error)) return 0;
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_RemoveVectoredExceptionHandler(uint32_t handle) {
    return ntw_veh_remove(handle, &last_error);
}
uint32_t __attribute__((stdcall)) ntw_imp_RtlFormatCurrentUserKeyPath(void *path) {
    uint32_t i;
    uint8_t *bytes = path;
    if (!path) return 0xC000000Du;
    for (i = 0; i < 8; ++i) bytes[i] = 0;
    last_error = 1008;
    return 0xC000007Cu;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentThread(void) { return 0xfffffffeu; }
void __attribute__((stdcall)) ntw_imp_GetCurrentThreadStackLimits(uint32_t *low, uint32_t *high) {
    uint32_t esp;
    if (!low || !high) return;
    if (current_fiber && current_fiber->stack && current_fiber->stack_bytes &&
        current_fiber->stack + current_fiber->stack_bytes > current_fiber->stack) {
        *low = current_fiber->stack;
        *high = current_fiber->stack + current_fiber->stack_bytes;
        return;
    }
    __asm__ volatile("mov %%esp, %0" : "=r"(esp));
    *low = esp & ~0xfffffu;
    if (*low >= esp) *low = esp > 0x100000u ? esp - 0x100000u : 0x10000u;
    *high = *low + 0x100000u;
    if (*high <= *low) *high = 0xffff0000u;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetLastError(void) { return last_error; }
void __attribute__((stdcall)) ntw_imp_SetLastError(uint32_t error) { last_error = error; }
static uint32_t rotl(uint32_t value, uint32_t bits) {
    if (!bits) return value;
    return (value << bits) | (value >> (32u - bits));
}
uint32_t __attribute__((stdcall)) ntw_imp_EncodePointer(uint32_t value) {
    return rotl(value ^ pointer_cookie, pointer_cookie & 31u);
}
uint32_t __attribute__((stdcall)) ntw_imp_DecodePointer(uint32_t value) {
    uint32_t bits = pointer_cookie & 31u;
    return (rotl(value, bits ? 32u - bits : 0) ^ pointer_cookie);
}
void __attribute__((stdcall)) ntw_imp_GetSystemTimeAsFileTime(uint32_t *out) {
    long spec[2];
    unsigned long long ticks;
    if (ntw_clock_gettime(0, spec) < 0) { spec[0] = 0; spec[1] = 0; }
    ticks = (unsigned long long)spec[0] * 10000000ull + 116444736000000000ull + (unsigned long long)(spec[1] / 100);
    if (out) { out[0] = (uint32_t)ticks; out[1] = (uint32_t)(ticks >> 32); }
}
void __attribute__((stdcall)) ntw_imp_GetSystemTimePreciseAsFileTime(uint32_t *out) { ntw_imp_GetSystemTimeAsFileTime(out); }
uint32_t __attribute__((stdcall)) ntw_imp_AreFileApisANSI(void) { return 1u; }
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentProcessId(void) {
    int id = ntw_syscall0(20);
    return id > 0 ? (uint32_t)id : 1u;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetCurrentThreadId(void) {
    int id = ntw_syscall0(224);
    return id > 0 ? (uint32_t)id : 1u;
}
uint32_t __attribute__((stdcall)) ntw_imp_QueryPerformanceCounter(uint32_t *out) {
    long spec[2];
    unsigned long long ticks;
    if (!out) return 0;
    if (ntw_clock_gettime(1, spec) < 0) return 0;
    ticks = (unsigned long long)spec[0] * 1000000000ull + (unsigned long long)spec[1];
    out[0] = (uint32_t)ticks;
    out[1] = (uint32_t)(ticks >> 32);
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_QueryPerformanceFrequency(uint32_t *out) {
    if (!out) return 0;
    out[0] = 1000000000u;
    out[1] = 0;
    return 1;
}
uint32_t ntw_cs_thread_id(void) { return ntw_imp_GetCurrentThreadId(); }
void ntw_cs_yield(void) { (void)ntw_syscall0(158); }
void __attribute__((stdcall)) ntw_imp_InitializeSRWLock(void *lock) { ntw_srw_init(lock); }
uint32_t __attribute__((stdcall)) ntw_imp_TryAcquireSRWLockExclusive(void *lock) {
    return (uint32_t)ntw_srw_try_exclusive(lock);
}
uint32_t __attribute__((stdcall)) ntw_imp_TryAcquireSRWLockShared(void *lock) {
    return (uint32_t)ntw_srw_try_shared(lock);
}
void __attribute__((stdcall)) ntw_imp_AcquireSRWLockExclusive(void *lock) {
    ntw_srw_acquire_exclusive(lock, ntw_cs_yield);
}
void __attribute__((stdcall)) ntw_imp_AcquireSRWLockShared(void *lock) {
    ntw_srw_acquire_shared(lock, ntw_cs_yield);
}
void __attribute__((stdcall)) ntw_imp_ReleaseSRWLockExclusive(void *lock) { ntw_srw_release_exclusive(lock); }
void __attribute__((stdcall)) ntw_imp_ReleaseSRWLockShared(void *lock) { ntw_srw_release_shared(lock); }
void __attribute__((stdcall)) ntw_imp_InitializeConditionVariable(uint32_t *variable) { if (variable) *variable = 0; }
void __attribute__((stdcall)) ntw_imp_WakeConditionVariable(uint32_t *variable) { if (variable) *variable += 1; }
void __attribute__((stdcall)) ntw_imp_WakeAllConditionVariable(uint32_t *variable) { if (variable) *variable += 1; }
uint32_t __attribute__((stdcall)) ntw_imp_SleepConditionVariableSRW(uint32_t *variable, void *lock,
                                                                  uint32_t milliseconds, uint32_t flags) {
    uint32_t seen, left;
    if (!variable || !lock || (flags & ~1u)) { last_error = 87; return 0; }
    seen = *variable;
    if (flags & 1u) ntw_srw_release_shared(lock);
    else ntw_srw_release_exclusive(lock);
    left = milliseconds;
    while (*variable == seen) {
        if (!left) {
            last_error = 258;
            if (flags & 1u) ntw_srw_acquire_shared(lock, ntw_cs_yield);
            else ntw_srw_acquire_exclusive(lock, ntw_cs_yield);
            return 0;
        }
        if (left == 0xffffffffu) ntw_imp_Sleep(50);
        else {
            uint32_t slice = left > 50u ? 50u : left;
            ntw_imp_Sleep(slice);
            left -= slice;
        }
    }
    if (flags & 1u) ntw_srw_acquire_shared(lock, ntw_cs_yield);
    else ntw_srw_acquire_exclusive(lock, ntw_cs_yield);
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_InitializeCriticalSectionEx(void *section, uint32_t spin, uint32_t flags) {
    if (!ntw_cs_initialize(section, spin, flags)) {
        last_error = ntw_cs_last_error();
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_InitializeCriticalSection(void *section) {
    return ntw_imp_InitializeCriticalSectionEx(section, 0, 0);
}
void __attribute__((stdcall)) ntw_imp_EnterCriticalSection(void *section) { ntw_cs_enter(section); }
void __attribute__((stdcall)) ntw_imp_LeaveCriticalSection(void *section) { ntw_cs_leave(section); }
uint32_t __attribute__((stdcall)) ntw_imp_TryEnterCriticalSection(void *section) {
    return (uint32_t)ntw_cs_try_enter(section);
}
void __attribute__((stdcall)) ntw_imp_DeleteCriticalSection(void *section) { ntw_cs_delete(section); }
uint32_t __attribute__((stdcall)) ntw_imp_FlsAlloc(void *callback) {
    uint32_t index = ntw_fls_alloc(callback);
    last_error = ntw_fls_last_error();
    return index;
}
uint32_t __attribute__((stdcall)) ntw_imp_FlsFree(uint32_t index) {
    uint32_t status = ntw_fls_free(index);
    last_error = ntw_fls_last_error();
    return status;
}
uint32_t __attribute__((stdcall)) ntw_imp_FlsGetValue(uint32_t index) {
    void *value = ntw_fls_get(index);
    last_error = ntw_fls_last_error();
    return (uint32_t)(unsigned long)value;
}
uint32_t __attribute__((stdcall)) ntw_imp_FlsSetValue(uint32_t index, uint32_t value) {
    uint32_t status = ntw_fls_set(index, (void *)(unsigned long)value);
    last_error = ntw_fls_last_error();
    return status;
}
static uint8_t page_state[2048];
static int linux_protect(uint32_t win, int *prot) {
    switch (win & 0xffu) {
    case 0x01: *prot = 0; break;
    case 0x02: *prot = 1; break;
    case 0x04: case 0x08: *prot = 3; break;
    case 0x10: *prot = 4; break;
    case 0x20: *prot = 5; break;
    case 0x40: case 0x80: *prot = 7; break;
    default: return 0;
    }
    return (win & ~0xffu) == 0;
}
#define NTW_MEM_COMMIT 0x1000u
#define NTW_MEM_RESERVE 0x2000u
#define NTW_MEM_DECOMMIT 0x4000u
#define NTW_MEM_RELEASE 0x8000u
#define NTW_MEM_RESET 0x80000u
#define NTW_MEM_TOP_DOWN 0x100000u
static uint32_t alloc_addr[128], alloc_size[128];
static uint32_t page_cover(uint32_t address, uint32_t size, uint32_t *start) {
    uint32_t end;
    *start = address & ~4095u;
    if (size > 0xffffffffu - address) return 0;
    end = (address + size + 4095u) & ~4095u;
    return end > *start ? end - *start : 0;
}
static int span_holding(uint32_t start, uint32_t bytes) {
    uint32_t i;
    if (!bytes || bytes > 0xffffffffu - start) return -1;
    for (i = 0; i < 128; ++i) if (alloc_addr[i] && start >= alloc_addr[i] &&
                                  start + bytes <= alloc_addr[i] + alloc_size[i]) return (int)i;
    return -1;
}
static int range_busy(uint32_t address, uint32_t bytes) {
    uint32_t i, end, env_bytes;
    if (!bytes || address < 0x10000u || address + bytes < address) return 1;
    end = address + bytes;
    if (g_image && address < (uint32_t)(unsigned long)g_image + 8u * 1024u * 1024u &&
        (uint32_t)(unsigned long)g_image < end) return 1;
    if (dep_image && address < (uint32_t)(unsigned long)dep_image + 8u * 1024u * 1024u &&
        (uint32_t)(unsigned long)dep_image < end) return 1;
    if (process_heap && address < (uint32_t)(unsigned long)process_heap + 8u * 1024u * 1024u &&
        (uint32_t)(unsigned long)process_heap < end) return 1;
    if (environment_block) {
        env_bytes = (environment_bytes + 4095u) & ~4095u;
        if (address < (uint32_t)(unsigned long)environment_block + env_bytes &&
            (uint32_t)(unsigned long)environment_block < end) return 1;
    }
    for (i = 0; i < 128; ++i) if (alloc_addr[i] && address < alloc_addr[i] + alloc_size[i] && alloc_addr[i] < end)
        return 1;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_VirtualAlloc(uint32_t address, uint32_t size, uint32_t kind, uint32_t protect) {
    uint32_t bytes, start, i, action;
    int prot = 0, slot;
    void *memory;
    action = kind & ~(NTW_MEM_TOP_DOWN | NTW_MEM_RESET);
    if (!size || (action & ~(NTW_MEM_COMMIT | NTW_MEM_RESERVE))) { last_error = 87; return 0; }
    bytes = page_cover(address, size, &start);
    if (!bytes) { last_error = 87; return 0; }
    if ((action & NTW_MEM_COMMIT) && address) {
        slot = span_holding(start, bytes);
        if (slot >= 0) {
            if (!linux_protect(protect ? protect : 0x04u, &prot)) { last_error = 87; return 0; }
            if (ntw_mprotect((void *)(unsigned long)start, bytes, prot) < 0) { last_error = 487; return 0; }
            return address;
        }
        if (!(action & NTW_MEM_RESERVE)) { last_error = 487; return 0; }
    }
    if (action & NTW_MEM_COMMIT) {
        if (!linux_protect(protect ? protect : 0x04u, &prot)) { last_error = 87; return 0; }
    }
    if (!address && bytes >= 65536u) {
        uint32_t align = bytes >= 0x200000u ? 0x200000u : 65536u;
        uint32_t span = bytes + align;
        uint32_t base, aligned, tail;
        void *wide = ntw_mmap2(0, span, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((unsigned)wide > 0xfffff000u) { last_error = 8; return 0; }
        base = (uint32_t)(unsigned long)wide;
        aligned = (base + align - 1u) & ~(align - 1u);
        if (aligned != base) ntw_munmap((void *)(unsigned long)base, aligned - base);
        tail = aligned + bytes;
        if (base + span > tail) ntw_munmap((void *)(unsigned long)tail, base + span - tail);
        memory = (void *)(unsigned long)aligned;
    } else memory = ntw_mmap2(address ? (void *)(unsigned long)address : 0, bytes, prot,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)memory > 0xfffff000u) { last_error = 8; return 0; }
    if (address && (uint32_t)(unsigned long)memory != address) {
        ntw_munmap(memory, bytes);
        if (range_busy(address, bytes)) { last_error = 487; return 0; }
        memory = ntw_mmap2((void *)(unsigned long)address, bytes, prot,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if ((unsigned)memory > 0xfffff000u || (uint32_t)(unsigned long)memory != address) {
            last_error = 487;
            return 0;
        }
    }
    for (i = 0; i < 128; ++i) if (!alloc_addr[i]) {
        alloc_addr[i] = (uint32_t)(unsigned long)memory;
        alloc_size[i] = bytes;
        return alloc_addr[i];
    }
    ntw_munmap(memory, bytes);
    last_error = 8;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_VirtualFree(uint32_t address, uint32_t size, uint32_t kind) {
    uint32_t i, start, bytes;
    if (kind == NTW_MEM_DECOMMIT) {
        if (!address || !size) { last_error = 87; return 0; }
        bytes = page_cover(address, size, &start);
        if (!bytes || span_holding(start, bytes) < 0) { last_error = 487; return 0; }
        if (ntw_mprotect((void *)(unsigned long)start, bytes, 0) < 0) { last_error = 487; return 0; }
        return 1;
    }
    if (kind != NTW_MEM_RELEASE || size || !address) { last_error = 87; return 0; }
    for (i = 0; i < 128; ++i) if (alloc_addr[i] == address) {
        if (ntw_munmap((void *)(unsigned long)address, alloc_size[i]) < 0) { last_error = 87; return 0; }
        alloc_addr[i] = 0;
        return 1;
    }
    last_error = 487;
    return 0;
}
#define NTW_TLS_SLOTS 1088u
#define NTW_TLS_OUT_OF_INDEXES 0xffffffffu
static uint32_t tls_value[NTW_TLS_SLOTS];
static uint8_t tls_live[NTW_TLS_SLOTS];
uint32_t __attribute__((stdcall)) ntw_imp_TlsAlloc(void) {
    uint32_t i;
    for (i = 0; i < NTW_TLS_SLOTS; ++i) if (!tls_live[i]) {
        tls_live[i] = 1;
        tls_value[i] = 0;
        last_error = 0;
        return i;
    }
    last_error = 259;
    return NTW_TLS_OUT_OF_INDEXES;
}
uint32_t __attribute__((stdcall)) ntw_imp_TlsFree(uint32_t index) {
    if (index >= NTW_TLS_SLOTS || !tls_live[index]) { last_error = 87; return 0; }
    tls_live[index] = 0;
    tls_value[index] = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_TlsGetValue(uint32_t index) {
    if (index >= NTW_TLS_SLOTS || !tls_live[index]) { last_error = 87; return 0; }
    last_error = 0;
    return tls_value[index];
}
uint32_t __attribute__((stdcall)) ntw_imp_TlsSetValue(uint32_t index, uint32_t value) {
    if (index >= NTW_TLS_SLOTS || !tls_live[index]) { last_error = 87; return 0; }
    tls_value[index] = value;
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_VirtualProtect(uint32_t address, uint32_t size,
                                                       uint32_t requested, uint32_t *old_protect) {
    uint32_t start, end, page, base, index;
    int prot;
    if (!address || !size || !old_protect || !g_image) { last_error = 87; return 0; }
    base = (uint32_t)(unsigned long)g_image;
    if (address < base || address - base >= g_image_bytes || size > g_image_bytes - (address - base)) {
        if (extra_image && address >= (uint32_t)(unsigned long)extra_image &&
            address - (uint32_t)(unsigned long)extra_image < extra_size &&
            size <= extra_size - (address - (uint32_t)(unsigned long)extra_image)) {
            if (!linux_protect(requested, &prot)) { last_error = 87; return 0; }
            start = address & ~4095u;
            end = (address + size + 4095u) & ~4095u;
            *old_protect = 0x40u;
            if (ntw_mprotect((void *)(unsigned long)start, end - start, prot) < 0) { last_error = 487; return 0; }
            return 1;
        }
        if (dep_image && address >= (uint32_t)(unsigned long)dep_image &&
            address - (uint32_t)(unsigned long)dep_image < 8u * 1024u * 1024u &&
            size <= 8u * 1024u * 1024u - (address - (uint32_t)(unsigned long)dep_image)) {
            if (!linux_protect(requested, &prot)) { last_error = 87; return 0; }
            start = address & ~4095u;
            end = (address + size + 4095u) & ~4095u;
            *old_protect = 0x40u;
            if (ntw_mprotect((void *)(unsigned long)start, end - start, prot) < 0) { last_error = 487; return 0; }
            return 1;
        }
        last_error = 487;
        return 0;
    }
    if (!linux_protect(requested, &prot)) { last_error = 87; return 0; }
    start = address & ~4095u;
    end = (address + size + 4095u) & ~4095u;
    index = (start - base) >> 12;
    *old_protect = page_state[index] ? page_state[index] : 0x40u;
    if (ntw_mprotect((void *)(unsigned long)start, end - start, prot) < 0) {
        last_error = 487;
        return 0;
    }
    for (page = start; page < end; page += 4096u) {
        uint32_t slot = (page - base) >> 12;
        if (slot < 2048) page_state[slot] = (uint8_t)(requested & 0xffu);
    }
    return 1;
}
#define NTW_HEAP_HANDLE 1u
#define NTW_HEAP_ZERO 0x8u
#define NTW_HEAP_NOSERIALIZE 0x1u
static uint32_t process_heap_used;
static int heap_ready(void) {
    if (process_heap) return 1;
    process_heap = ntw_mmap2(0, 8u * 1024u * 1024u, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)process_heap > 0xfffff000u) { process_heap = 0; return 0; }
    return 1;
}
static uint32_t heap_compatibility;
static int heap_terminate_on_corruption;
uint32_t __attribute__((stdcall)) ntw_imp_HeapSetInformation(uint32_t heap, uint32_t klass, uint32_t info, uint32_t bytes) {
    uint32_t value;
    if (heap && heap != NTW_HEAP_HANDLE) { last_error = 6; return 0; }
    if (klass == 1u) {
        if (info || bytes) { last_error = 87; return 0; }
        heap_terminate_on_corruption = 1;
        return 1;
    }
    if (klass == 0u) {
        if (!info || bytes != 4u) { last_error = 87; return 0; }
        value = *(uint32_t *)(unsigned long)info;
        if (value > 2u) { last_error = 87; return 0; }
        heap_compatibility = value;
        return 1;
    }
    last_error = 87;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_HeapQueryInformation(uint32_t heap, uint32_t klass, uint32_t info, uint32_t bytes, uint32_t *needed) {
    if (heap && heap != NTW_HEAP_HANDLE) { last_error = 6; return 0; }
    if (klass != 0u) { last_error = 87; return 0; }
    if (needed) *needed = 4u;
    if (bytes < 4u) { last_error = 122; return 0; }
    if (!info) { last_error = 87; return 0; }
    *(uint32_t *)(unsigned long)info = heap_compatibility;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetProcessHeap(void) {
    if (!heap_ready()) { last_error = 8; return 0; }
    return NTW_HEAP_HANDLE;
}
uint32_t __attribute__((stdcall)) ntw_imp_HeapAlloc(uint32_t heap, uint32_t flags, uint32_t bytes) {
    uint32_t total, i;
    uint8_t *block;
    if (heap != NTW_HEAP_HANDLE || (flags & ~(NTW_HEAP_ZERO | NTW_HEAP_NOSERIALIZE))) {
        last_error = 6;
        return 0;
    }
    if (!bytes) bytes = 1;
    if (!heap_ready()) { last_error = 8; return 0; }
    total = (bytes + 8u + 7u) & ~7u;
    if (process_heap_used + total < process_heap_used || process_heap_used + total > 8u * 1024u * 1024u) {
        last_error = 8;
        return 0;
    }
    block = process_heap + process_heap_used;
    process_heap_used += total;
    wr32(block, bytes);
    wr32(block + 4, 0x48503121u);
    block += 8;
    if (flags & NTW_HEAP_ZERO) for (i = 0; i < bytes; ++i) block[i] = 0;
    return (uint32_t)(unsigned long)block;
}
uint32_t __attribute__((stdcall)) ntw_imp_HeapFree(uint32_t heap, uint32_t flags, uint32_t pointer) {
    if (flags & ~NTW_HEAP_NOSERIALIZE) { last_error = 87; return 0; }
    if (!pointer) return 1;
    if (heap != NTW_HEAP_HANDLE || !process_heap) { last_error = 6; return 0; }
    if (rd32((uint8_t *)(unsigned long)(pointer - 4)) != 0x48503121u) { last_error = 87; return 0; }
    wr32((uint8_t *)(unsigned long)(pointer - 4), 0);
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_LocalAlloc(uint32_t flags, uint32_t bytes) {
    uint32_t heap_flags = 0;
    if (flags & ~0x40u) { last_error = 87; return 0; }
    if (flags & 0x40u) heap_flags = NTW_HEAP_ZERO;
    return ntw_imp_HeapAlloc(NTW_HEAP_HANDLE, heap_flags, bytes ? bytes : 1u);
}
uint32_t __attribute__((stdcall)) ntw_imp_LocalFree(uint32_t pointer) {
    if (!pointer) return 0;
    if (!ntw_imp_HeapFree(NTW_HEAP_HANDLE, 0, pointer)) return pointer;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_HeapSize(uint32_t heap, uint32_t flags, uint32_t pointer) {
    if (flags & ~NTW_HEAP_NOSERIALIZE) { last_error = 87; return 0xffffffffu; }
    if (heap != NTW_HEAP_HANDLE || !pointer || rd32((uint8_t *)(unsigned long)(pointer - 4)) != 0x48503121u) {
        last_error = 6;
        return 0xffffffffu;
    }
    return rd32((uint8_t *)(unsigned long)(pointer - 8));
}
uint32_t __attribute__((stdcall)) ntw_imp_IsProcessorFeaturePresent(uint32_t feature) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    switch (feature) {
    case 0: return 0; /* precision errata */
    case 1: return 0; /* floating-point emulation */
    case 2: return (edx >> 8) & 1u; /* CMPXCHG8B */
    case 3: return (edx >> 23) & 1u; /* MMX */
    case 6: return (edx >> 25) & 1u; /* SSE */
    case 7: return (edx >> 0) & 0u;
    case 8: return (edx >> 11) & 1u; /* SEP */
    case 10: return (edx >> 26) & 1u; /* SSE2 */
    case 13: return ecx & 1u; /* SSE3 */
    default: return 0;
    }
}
void ntw_import_fault(const char *name) {
    int out;
    append("first unresolved import ");
    append(name ? name : "?");
    append("\n");
    out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
    ntw_write(1, logbuf, log_len);
    __asm__ volatile("ud2");
}
static uint32_t make_fault_stub(uint8_t *code, const char *name) {
    uint32_t target = (uint32_t)(unsigned long)ntw_import_fault;
    uint32_t next = (uint32_t)(unsigned long)(code + 10);
    code[0] = 0x68;
    wr32(code + 1, (uint32_t)(unsigned long)name);
    code[5] = 0xE8;
    wr32(code + 6, target - next);
    return (uint32_t)(unsigned long)code;
}
static uint32_t known_import(const char *dll, const char *name);
static int loader_transfer(void *user, int fd, void *buffer, uint32_t bytes, int writing) {
    (void)user;
    if (writing) return ntw_write(fd, buffer, bytes);
    return ntw_read(fd, buffer, bytes);
}
static int disk_dir(void *user, const char *directory, uint32_t index, char *name, uint32_t cap, int *is_dir, uint32_t *size_lo) {
    uint8_t buf[1024];
    uint32_t seen = 0;
    int fd, n;
    (void)user;
    if (!directory || !name || cap < 2) return 0;
    fd = ntw_open(directory, 0, 0);
    if (fd < 0) return 0;
    for (;;) {
        int off = 0;
        n = ntw_getdents64(fd, buf, sizeof buf);
        if (n <= 0) { ntw_close(fd); return 0; }
        while (off + 19 < n) {
            unsigned reclen = *(unsigned short *)(buf + off + 16);
            const char *ent;
            uint32_t k = 0;
            if (reclen < 19 || off + (int)reclen > n) { ntw_close(fd); return 0; }
            if (seen == index) {
                ent = (const char *)(buf + off + 19);
                while (ent[k] && k + 1 < cap) { name[k] = ent[k]; k++; }
                name[k] = 0;
                if (is_dir) *is_dir = buf[off + 18] == 4;
                if (size_lo) *size_lo = 0;
                ntw_close(fd);
                return 1;
            }
            seen++;
            off += (int)reclen;
        }
    }
}
static int disk_open(void *user, const char *path, int flags, int mode) {
    (void)user;
    return ntw_open(path, flags, mode);
}
static int disk_close(void *user, int fd) {
    (void)user;
    return ntw_close(fd);
}
static int disk_read(void *user, int fd, void *buf, uint32_t bytes) {
    (void)user;
    return ntw_read(fd, buf, bytes);
}
static int disk_write(void *user, int fd, const void *buf, uint32_t bytes) {
    (void)user;
    return ntw_write(fd, buf, bytes);
}
static int disk_seek(void *user, int fd, uint32_t lo, uint32_t hi, int whence, uint32_t *new_lo, uint32_t *new_hi) {
    uint32_t result[2];
    int rc;
    (void)user;
    rc = ntw_llseek(fd, hi, lo, result, whence);
    if (rc < 0) return rc;
    if (new_lo) *new_lo = result[0];
    if (new_hi) *new_hi = result[1];
    return 0;
}
static int disk_exists(void *user, const char *path) {
    int fd;
    (void)user;
    fd = ntw_open(path, 0, 0);
    if (fd < 0) return 0;
    ntw_close(fd);
    return 1;
}
static int disk_unlink(void *user, const char *path) {
    (void)user;
    return ntw_unlink(path);
}
static int disk_mkdir(void *user, const char *path, int mode) {
    (void)user;
    return ntw_mkdir(path, mode);
}
extern int ntw_socketcall(int call, unsigned *args);
static int unix_socket(void) {
    unsigned args[3];
    args[0] = 1;
    args[1] = 1;
    args[2] = 0;
    return ntw_socketcall(1, args);
}
static int fill_addr(uint8_t *addr, const char *path, uint32_t *len) {
    uint32_t n = 0;
    addr[0] = 1;
    addr[1] = 0;
    while (path[n] && n < 104) { addr[2 + n] = (uint8_t)path[n]; n++; }
    if (path[n]) return 0;
    addr[2 + n] = 0;
    *len = 3 + n;
    return 1;
}
static int disk_pipe_bind(void *user, const char *path) {
    unsigned args[3];
    uint8_t addr[112];
    uint32_t len = 0;
    int fd;
    (void)user;
    if (!fill_addr(addr, path, &len)) return -22;
    fd = unix_socket();
    if (fd < 0) return fd;
    args[0] = (unsigned)fd;
    args[1] = (unsigned)(unsigned long)addr;
    args[2] = len;
    if (ntw_socketcall(2, args) < 0) { ntw_close(fd); return -5; }
    args[0] = (unsigned)fd;
    args[1] = 8;
    if (ntw_socketcall(4, args) < 0) { ntw_close(fd); return -5; }
    return fd;
}
static int disk_pipe_connect(void *user, const char *path) {
    unsigned args[3];
    uint8_t addr[112];
    uint32_t len = 0;
    int fd;
    (void)user;
    if (!fill_addr(addr, path, &len)) return -22;
    fd = unix_socket();
    if (fd < 0) return fd;
    args[0] = (unsigned)fd;
    args[1] = (unsigned)(unsigned long)addr;
    args[2] = len;
    if (ntw_socketcall(3, args) < 0) { ntw_close(fd); return -2; }
    return fd;
}
static int disk_pipe_accept(void *user, int listen_fd) {
    unsigned args[3];
    (void)user;
    args[0] = (unsigned)listen_fd;
    args[1] = 0;
    args[2] = 0;
    return ntw_socketcall(5, args);
}
static char loader_path[260];
static int proc_depth;
static int path_ends(const char *path, const char *tail) {
    uint32_t n = 0, t = 0, i;
    while (path[n]) n++;
    while (tail[t]) t++;
    if (n < t) return 0;
    for (i = 0; i < t; ++i) {
        char a = path[n - t + i], b = tail[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}
static int loader_spawn(void *user, const char *image, int argc, char **argv, uint32_t *pid) {
    char magic[2];
    char *child_argv[16];
    char *envp[1];
    int fd, child, out, n, k = 0;
    (void)user;
    if (proc_depth && path_ends(image, "chrome.exe")) return -13;
    fd = ntw_open(image, O_RDONLY, 0);
    if (fd < 0) return -2;
    if (ntw_read(fd, magic, 2) != 2 || magic[0] != 'M' || magic[1] != 'Z') { ntw_close(fd); return -8; }
    ntw_close(fd);
    if (!loader_path[0]) return -2;
    {
        char command[1024], inherited[512];
        int outfd;
        uint32_t bytes;
        command[0] = 0;
        ntw_proc_command(command, sizeof command);
        outfd = ntw_open("child-cmdline.txt", 1 | 64 | 512, 0644);
        bytes = 0;
        while (command[bytes]) bytes++;
        if (outfd >= 0) { if (bytes) ntw_write(outfd, command, bytes); ntw_close(outfd); }
        bytes = ntw_winfile_inherit_text(inherited, sizeof inherited);
        outfd = ntw_open("child-inherit.txt", 1 | 64 | 512, 0644);
        if (outfd >= 0) { if (bytes) ntw_write(outfd, inherited, bytes); ntw_close(outfd); }
    }
    child = ntw_fork();
    if (child < 0) return child;
    if (child == 0) {
        child_argv[k++] = loader_path;
        for (n = 0; n < argc && k < 12; ++n) child_argv[k++] = argv[n];
        child_argv[k++] = "exe";
        child_argv[k++] = "ntw-depth-1";
        child_argv[k] = 0;
        envp[0] = 0;
        out = ntw_open("child-proc.stdout", 1 | 64 | 512, 0644);
        if (out >= 0) { ntw_dup2(out, 1); ntw_dup2(out, 2); }
        ntw_execve(loader_path, child_argv, envp);
        ntw_exit(127);
    }
    *pid = (uint32_t)child;
    return 0;
}
static int loader_proc_wait(void *user, uint32_t pid, uint32_t *status, int block) {
    int rc;
    (void)user;
    rc = ntw_waitpid((int)pid, status, block ? 0 : 1);
    if (rc == 0) return 0;
    if (rc < 0) return rc;
    return 1;
}
static int loader_proc_kill(void *user, uint32_t pid) {
    (void)user;
    return ntw_kill((int)pid, 9);
}
static void log_file_wide(const uint16_t *text) {
    char shown[160];
    uint32_t n = 0;
    append("file ");
    if (!text) { append("(null)\n"); return; }
    while (text[n] && n + 1 < sizeof shown) {
        shown[n] = (text[n] >= 32 && text[n] < 127) ? (char)text[n] : '?';
        n += 1u;
    }
    shown[n] = 0;
    append(shown);
    append("\n");
    flush_log_now();
}
uint32_t __attribute__((stdcall)) ntw_imp_WriteFile(uint32_t handle, uint32_t buffer, uint32_t bytes,
                                                   uint32_t *written, uint32_t overlapped) {
    uint32_t error = 0;
    int ok;
    if (ntw_winfile_owns(handle))
        ok = ntw_winfile_write(handle, (const void *)(unsigned long)buffer, bytes, written,
                               overlapped ? (const void *)(unsigned long)overlapped : 0, &error);
    else
        ok = ntw_file_write(handle, (const void *)(unsigned long)buffer, bytes, written,
                            overlapped ? (const void *)(unsigned long)overlapped : 0, &error);
    if (!ok) last_error = error;
    return (uint32_t)ok;
}
uint32_t __attribute__((stdcall)) ntw_imp_ReadFile(uint32_t handle, uint32_t buffer, uint32_t bytes,
                                                  uint32_t *read_count, uint32_t overlapped) {
    uint32_t error = 0;
    int ok;
    if (ntw_winfile_owns(handle))
        ok = ntw_winfile_read(handle, (void *)(unsigned long)buffer, bytes, read_count,
                              overlapped ? (void *)(unsigned long)overlapped : 0, &error);
    else
        ok = ntw_file_read(handle, (void *)(unsigned long)buffer, bytes, read_count,
                           overlapped ? (void *)(unsigned long)overlapped : 0, &error);
    if (!ok) last_error = error;
    return (uint32_t)ok;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileType(uint32_t handle) {
    uint32_t error = 0, kind;
    if (ntw_winfile_owns(handle)) return 1;
    kind = ntw_file_type(handle, &error);
    if (error) last_error = error;
    return kind;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateFileW(const uint16_t *name, uint32_t access, uint32_t share,
                                                     uint32_t security, uint32_t disposition, uint32_t flags,
                                                     uint32_t template_file) {
    uint32_t handle = 0, error = 0;
    (void)security;
    log_file_wide(name);
    append(" share ");
    append_hex(share);
    append(" access ");
    append_hex(access);
    append(" disp ");
    append_hex(disposition);
    append("\n");
    flush_log_now();
    if (!ntw_winfile_create(name, access, share, disposition, flags, template_file, &handle, &error)) {
        append(" openfail ");
        append(ntw_winfile_last_path());
        append(" ");
        append_hex(error ? error : 87u);
        append("\n");
        flush_log_now();
        last_error = error ? error : 87u;
        return 0xffffffffu;
    }
    if (error) last_error = error;
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateDirectoryW(const uint16_t *name, uint32_t security) {
    uint32_t error = 0;
    (void)security;
    log_file_wide(name);
    if (!ntw_winfile_mkdirs(name, &error)) {
        append(" dirfail ");
        append(ntw_winfile_last_path());
        append(" ");
        append_hex(error ? error : 3u);
        append("\n");
        flush_log_now();
        last_error = error ? error : 3u;
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetFilePointerEx(uint32_t handle, uint32_t lo, uint32_t hi,
                                                          uint32_t *newoff, uint32_t method) {
    uint32_t error = 0, new_lo = 0, new_hi = 0;
    if (!ntw_winfile_seek(handle, lo, hi, &new_lo, &new_hi, method, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    if (newoff) { newoff[0] = new_lo; newoff[1] = new_hi; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileSizeEx(uint32_t handle, uint32_t *size) {
    uint32_t error = 0, lo = 0, hi = 0;
    if (!size) { last_error = 87; return 0; }
    if (!ntw_winfile_size(handle, &lo, &hi, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    size[0] = lo;
    size[1] = hi;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateNamedPipeW(const uint16_t *name, uint32_t open_mode, uint32_t pipe_mode,
                                                          uint32_t instances, uint32_t out_bytes, uint32_t in_bytes,
                                                          uint32_t timeout, uint32_t security) {
    uint32_t handle = 0, error = 0;
    (void)out_bytes; (void)in_bytes; (void)timeout; (void)security;
    log_file_wide(name);
    if (!ntw_pipe_create(name, open_mode, pipe_mode, instances, &handle, &error)) {
        last_error = error ? error : 87u;
        return 0xffffffffu;
    }
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_ConnectNamedPipe(uint32_t handle, uint32_t overlapped) {
    uint32_t error = 0;
    if (!ntw_pipe_connect(handle, overlapped ? (const void *)(unsigned long)overlapped : 0, &error)) {
        last_error = error ? error : 6u;
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetNamedPipeHandleState(uint32_t handle, uint32_t *mode, uint32_t *collect, uint32_t *timeout) {
    uint32_t error = 0;
    if (!ntw_pipe_set_state(handle, mode, collect, timeout, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_TransactNamedPipe(uint32_t handle, uint32_t in_buf, uint32_t in_len,
                                                           uint32_t out_buf, uint32_t out_cap, uint32_t *read_count,
                                                           uint32_t overlapped) {
    uint32_t error = 0;
    if (!ntw_pipe_transact(handle, in_buf ? (const void *)(unsigned long)in_buf : 0, in_len,
                           out_buf ? (void *)(unsigned long)out_buf : 0, out_cap, read_count,
                           overlapped ? (const void *)(unsigned long)overlapped : 0, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetProcessShutdownParameters(uint32_t level, uint32_t flags) {
    uint32_t error = 0;
    if (!ntw_shutdown_set(level, flags, &error)) { last_error = error ? error : 87u; return 0; }
    append("shutdown stored ");
    append_hex(level);
    append(" ");
    append_hex(flags);
    append(" order unchanged\n");
    flush_log_now();
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetProcessShutdownParameters(uint32_t *level, uint32_t *flags) {
    uint32_t error = 0;
    if (!ntw_shutdown_get(level, flags, &error)) { last_error = error ? error : 87u; return 0; }
    return 1;
}
static void unix_filetime(uint32_t sec, uint32_t nsec, uint32_t *lo, uint32_t *hi) {
    uint64_t ticks = (uint64_t)sec * 10000000ull + 116444736000000000ull + (uint64_t)(nsec / 100u);
    *lo = (uint32_t)ticks;
    *hi = (uint32_t)(ticks >> 32);
}
static int disk_meta(int fd, ntw_file_meta *out) {
    uint8_t st[96];
    uint32_t mode, i;
    int rc = ntw_fstat64(fd, st);
    if (rc < 0 || !out) return rc < 0 ? rc : -22;
    for (i = 0; i < sizeof(ntw_file_meta) / 4; ++i) ((uint32_t *)out)[i] = 0;
    mode = (uint32_t)st[16] | ((uint32_t)st[17] << 8) | ((uint32_t)st[18] << 16) | ((uint32_t)st[19] << 24);
    out->attrs = ((mode & 0xf000u) == 0x4000u) ? 0x10u : 0x20u;
    out->nlink = (uint32_t)st[20] | ((uint32_t)st[21] << 8) | ((uint32_t)st[22] << 16) | ((uint32_t)st[23] << 24);
    out->size_lo = (uint32_t)st[44] | ((uint32_t)st[45] << 8) | ((uint32_t)st[46] << 16) | ((uint32_t)st[47] << 24);
    out->size_hi = (uint32_t)st[48] | ((uint32_t)st[49] << 8) | ((uint32_t)st[50] << 16) | ((uint32_t)st[51] << 24);
    unix_filetime((uint32_t)st[64] | ((uint32_t)st[65] << 8) | ((uint32_t)st[66] << 16) | ((uint32_t)st[67] << 24),
                  (uint32_t)st[68] | ((uint32_t)st[69] << 8) | ((uint32_t)st[70] << 16) | ((uint32_t)st[71] << 24),
                  &out->a_lo, &out->a_hi);
    unix_filetime((uint32_t)st[72] | ((uint32_t)st[73] << 8) | ((uint32_t)st[74] << 16) | ((uint32_t)st[75] << 24),
                  (uint32_t)st[76] | ((uint32_t)st[77] << 8) | ((uint32_t)st[78] << 16) | ((uint32_t)st[79] << 24),
                  &out->m_lo, &out->m_hi);
    unix_filetime((uint32_t)st[80] | ((uint32_t)st[81] << 8) | ((uint32_t)st[82] << 16) | ((uint32_t)st[83] << 24),
                  (uint32_t)st[84] | ((uint32_t)st[85] << 8) | ((uint32_t)st[86] << 16) | ((uint32_t)st[87] << 24),
                  &out->c_lo, &out->c_hi);
    out->ch_lo = out->c_lo;
    out->ch_hi = out->c_hi;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileInformationByHandleEx(uint32_t handle, uint32_t klass, void *info, uint32_t bytes) {
    uint32_t error = 0;
    if (!ntw_winfile_info(handle, klass, info, bytes, &error)) {
        last_error = error ? error : 87u;
        append("fileinfo ");
        append_hex(klass);
        append(" ");
        append_hex(last_error);
        append("\n");
        flush_log_now();
        return 0;
    }
    return 1;
}
static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static int disk_lock(int fd, int exclusive, int wait, uint32_t start_lo, uint32_t start_hi, uint32_t len_lo, uint32_t len_hi) {
    uint8_t fl[24];
    uint32_t i;
    for (i = 0; i < sizeof fl; ++i) fl[i] = 0;
    fl[0] = exclusive == 2 ? 2 : (exclusive ? 1 : 0);
    put_le32(fl + 4, start_lo);
    put_le32(fl + 8, start_hi);
    put_le32(fl + 12, len_lo);
    put_le32(fl + 16, len_hi);
    return ntw_fcntl(fd, wait ? 14 : 13, fl);
}
static int disk_trunc(int fd, uint32_t lo, uint32_t hi) {
    return ntw_ftruncate64(fd, 0, lo, hi);
}
uint32_t __attribute__((stdcall)) ntw_imp_SetEndOfFile(uint32_t handle) {
    uint32_t error = 0;
    if (!ntw_winfile_set_end(handle, &error)) { last_error = error ? error : 87u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_LockFileEx(uint32_t handle, uint32_t flags, uint32_t reserved, uint32_t len_lo, uint32_t len_hi, uint32_t overlapped) {
    uint32_t error = 0;
    if (!ntw_winfile_lock(handle, flags, reserved, len_lo, len_hi, overlapped ? (const uint32_t *)(unsigned long)overlapped : 0, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_UnlockFileEx(uint32_t handle, uint32_t reserved, uint32_t len_lo, uint32_t len_hi, uint32_t overlapped) {
    uint32_t error = 0;
    if (!ntw_winfile_unlock(handle, reserved, len_lo, len_hi, overlapped ? (const uint32_t *)(unsigned long)overlapped : 0, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetLongPathNameW(const uint16_t *name, uint16_t *out, uint32_t cap) {
    uint32_t needed = 0, error = 0;
    if (!ntw_winfile_longpath(name, out, cap, &needed, &error)) {
        if (error == 122) return needed;
        last_error = error ? error : 87u;
        return 0;
    }
    return needed;
}
uint32_t __attribute__((stdcall)) ntw_imp_DeleteFileW(const uint16_t *name) {
    uint32_t error = 0;
    if (!ntw_winfile_delete(name, &error)) { last_error = error ? error : 87u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileAttributesW(const uint16_t *name) {
    uint32_t attrs = 0, error = 0;
    log_file_wide(name);
    if (!ntw_winfile_attributes(name, &attrs, &error)) {
        last_error = error ? error : 2u;
        return 0xffffffffu;
    }
    return attrs;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateEventW(uint32_t security, uint32_t manual, uint32_t initial, const uint16_t *name) {
    uint32_t handle = 0, error = 0;
    (void)security;
    if (name && name[0]) log_file_wide(name);
    if (!ntw_event_create(manual ? 1 : 0, initial ? 1 : 0, name, &handle, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    if (error) last_error = error;
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetEvent(uint32_t handle) {
    uint32_t error = 0;
    if (!ntw_event_set(handle, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_ResetEvent(uint32_t handle) {
    uint32_t error = 0;
    if (!ntw_event_reset(handle, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
static unsigned worker_tebs[8][256];
static unsigned worker_tls[8][64];
static int loader_thread_spawn(void *user, ntw_thread_body body, void *slot) {
    unsigned size = 1024u * 1024u;
    uint8_t *stack;
    uint32_t *top;
    int tid;
    (void)user;
    stack = ntw_mmap2(0, size, 3, 2 | 0x20, -1, 0);
    if ((unsigned)stack > 0xfffff000u) return -12;
    top = (uint32_t *)(((unsigned long)stack + size) & ~(unsigned long)15);
    top -= 4;
    top[0] = (uint32_t)(unsigned long)body;
    top[1] = (uint32_t)(unsigned long)slot;
    tid = ntw_clone(0x100u | 0x200u | 0x400u | 0x800u | 0x10000u | 0x40000u, top, 0, 0, 0);
    if (tid < 0) { ntw_munmap(stack, size); return tid; }
    return 0;
}
static void loader_thread_enter(uint32_t index, uint32_t handle) {
    unsigned *teb, parent = 0, i, selector;
    struct ntw_user_desc desc;
    if (index >= 8) return;
    teb = worker_tebs[index];
    __asm__ volatile("mov %%fs:0x18, %0" : "=r"(parent));
    for (i = 0; i < 256; ++i) teb[i] = 0;
    teb[0] = 0xffffffffu;
    teb[6] = (unsigned)(unsigned long)teb;
    if (parent) {
        teb[8] = *(unsigned *)(parent + 0x20);
        teb[12] = *(unsigned *)(parent + 0x30);
    }
    teb[9] = ntw_syscall0(224) > 0 ? (unsigned)ntw_syscall0(224) : 1u;
    teb[11] = (unsigned)(unsigned long)worker_tls[index];
    if (parent && *(unsigned *)(parent + 0x2c)) {
        unsigned *src = (unsigned *)(unsigned long)*(unsigned *)(parent + 0x2c);
        for (i = 0; i < 64; ++i) worker_tls[index][i] = src[i];
    }
    teb[16] = handle;
    for (i = 0; i < sizeof desc / 4; ++i) ((unsigned *)&desc)[i] = 0;
    desc.entry_number = 0xffffffffu;
    desc.base_addr = (unsigned)(unsigned long)teb;
    desc.limit = 0xfff;
    desc.seg_32bit = 1;
    desc.useable = 1;
    if (ntw_set_thread_area(&desc) == 0) {
        selector = (desc.entry_number << 3) | 3u;
        ntw_load_fs(selector);
    }
}
static void loader_thread_pause(void) {
    unsigned request[2];
    request[0] = 0;
    request[1] = 1000000u;
    ntw_nanosleep(request, 0);
}
static uint32_t loader_thread_tid(void) {
    int id = ntw_syscall0(224);
    return id > 0 ? (uint32_t)id : 1u;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateThread(uint32_t security, uint32_t stack, uint32_t start, uint32_t param,
                                                      uint32_t flags, uint32_t *tid_out) {
    uint32_t handle = 0, tid = 0, error = 0;
    (void)security;
    (void)stack;
    if (!start || !ntw_thread_flags_ok(flags)) { last_error = 87; return 0; }
    append("thread\n");
    flush_log_now();
    if (!ntw_thread_create((ntw_thread_start)(unsigned long)start, (void *)(unsigned long)param, (flags & 4u) != 0,
                           &handle, &tid, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    if (tid_out) *tid_out = tid;
    return handle;
}
void __attribute__((stdcall)) ntw_imp_ExitThread(uint32_t code) {
    unsigned teb = 0, handle = 0;
    __asm__ volatile("mov %%fs:0x18, %0" : "=r"(teb));
    if (teb) handle = *(unsigned *)(teb + 0x40);
    if (handle) ntw_thread_complete(handle, code);
    ntw_exit(code);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetExitCodeThread(uint32_t thread, uint32_t *code) {
    uint32_t error = 0;
    if (!code) { last_error = 87; return 0; }
    if (thread == 0xfffffffeu) { *code = 259; return 1; }
    if (!ntw_thread_exit_code(thread, code, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
static struct { uint32_t handle; uint32_t flags; int live; } extra_handle_flags[64];
static int known_kernel_handle(uint32_t handle) {
    return handle == 0xffffffffu || handle == 0xfffffffeu || handle == 0x2000u || handle == 0x1000u
        || handle == NTW_STD_INPUT || handle == NTW_STD_OUTPUT || handle == NTW_STD_ERROR
        || ntw_thread_owns(handle) || ntw_proc_owns(handle) || ntw_iocp_owns(handle)
        || ntw_event_owns(handle) || ntw_winfile_owns(handle) || ntw_sem_owns(handle)
        || ntw_token_owns(handle);
}
static int extra_flags(uint32_t handle, int change, uint32_t mask, uint32_t value, uint32_t *flags) {
    uint32_t i, free_slot = 64;
    for (i = 0; i < 64; ++i) {
        if (!extra_handle_flags[i].live) { if (free_slot == 64) free_slot = i; continue; }
        if (extra_handle_flags[i].handle != handle) continue;
        if (change) extra_handle_flags[i].flags = (extra_handle_flags[i].flags & ~mask) | (value & mask);
        if (flags) *flags = extra_handle_flags[i].flags;
        return 1;
    }
    if (!change) { if (flags) *flags = 0; return 1; }
    if (free_slot == 64) return 0;
    extra_handle_flags[free_slot].live = 1;
    extra_handle_flags[free_slot].handle = handle;
    extra_handle_flags[free_slot].flags = value & mask;
    if (flags) *flags = extra_handle_flags[free_slot].flags;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetHandleInformation(uint32_t handle, uint32_t *flags) {
    uint32_t stored = 0;
    if (!flags) { last_error = 87; return 0; }
    if (!handle) { last_error = 6; return 0; }
    if (ntw_winfile_flags(handle, 0, 0, 0, &stored) || ntw_event_flags(handle, 0, 0, 0, &stored)
        || ntw_sem_flags(handle, 0, 0, 0, &stored)) {
        *flags = stored;
        last_error = 0;
        return 1;
    }
    if (!known_kernel_handle(handle)) { last_error = 6; return 0; }
    extra_flags(handle, 0, 0, 0, &stored);
    *flags = stored;
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetHandleInformation(uint32_t handle, uint32_t mask, uint32_t flags) {
    if ((mask & ~3u) || (flags & ~mask)) { last_error = 87; return 0; }
    if (!handle) { last_error = 6; return 0; }
    append("sethandle ");
    append_hex(handle);
    append(" ");
    append_hex(mask);
    append(" ");
    append_hex(flags);
    append("\n");
    flush_log_now();
    if (ntw_winfile_flags(handle, 1, mask, flags, 0) || ntw_event_flags(handle, 1, mask, flags, 0)
        || ntw_sem_flags(handle, 1, mask, flags, 0)) {
        last_error = 0;
        return 1;
    }
    if (!known_kernel_handle(handle) || !extra_flags(handle, 1, mask, flags, 0)) { last_error = 6; return 0; }
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetThreadDescription(uint32_t thread, const uint16_t *text) {
    if (!thread || !text) return 0x80070057u;
    if (thread != 0xfffffffeu && thread != 0xffffffffu && !ntw_thread_owns(thread)) return 0x80070006u;
    last_error = 0;
    return 0;
}
static uint32_t console_handlers[8];
static uint32_t console_handler_count;
uint32_t __attribute__((stdcall)) ntw_imp_SetConsoleCtrlHandler(uint32_t routine, uint32_t add) {
    uint32_t i;
    if (!add) {
        for (i = 0; i < console_handler_count; ++i) {
            if (console_handlers[i] != routine) continue;
            console_handlers[i] = console_handlers[--console_handler_count];
            last_error = 0;
            return 1;
        }
        last_error = 87;
        return 0;
    }
    if (console_handler_count >= 8u) { last_error = 8; return 0; }
    console_handlers[console_handler_count++] = routine;
    last_error = 0;
    return 1;
}
void __attribute__((stdcall)) ntw_imp_OutputDebugStringA(const char *text) {
    uint32_t n = 0;
    if (!text) return;
    while (text[n]) n++;
    if (n) ntw_write(2, text, n);
}
void __attribute__((stdcall)) ntw_imp_OutputDebugStringW(const uint16_t *text) {
    char narrow[240];
    uint32_t n = 0;
    if (!text) return;
    while (text[n] && n + 1 < sizeof narrow) {
        narrow[n] = (text[n] >= 32 && text[n] < 127) ? (char)text[n] : '?';
        n++;
    }
    if (n) ntw_imp_OutputDebugStringA(narrow);
}
uint32_t __attribute__((stdcall)) ntw_imp_ResumeThread(uint32_t thread) {
    uint32_t previous = 0, error = 0;
    if (!ntw_thread_resume(thread, &previous, &error)) { last_error = error ? error : 6u; return 0xffffffffu; }
    return previous;
}
static int iocp_file(uint32_t file) {
    return file == 0xffffffffu || file == 0xfffffffeu || file == 0x2000u || ntw_winfile_owns(file)
        || ntw_thread_owns(file) || ntw_event_owns(file) || ntw_proc_owns(file);
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateIoCompletionPort(uint32_t file, uint32_t existing, uint32_t key, uint32_t threads) {
    uint32_t handle = 0, error = 0;
    if (!ntw_iocp_create(file, existing, key, threads, iocp_file, &handle, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_PostQueuedCompletionStatus(uint32_t port, uint32_t bytes, uint32_t key, uint32_t overlapped) {
    uint32_t error = 0;
    if (!ntw_iocp_post(port, bytes, key, overlapped, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetQueuedCompletionStatus(uint32_t port, uint32_t *bytes, uint32_t *key, uint32_t *overlapped, uint32_t timeout) {
    uint32_t error = 0, got_bytes = 0, got_key = 0, got_overlapped = 0;
    if (!bytes || !key || !overlapped) { last_error = 87; return 0; }
    if (!ntw_iocp_get(port, &got_bytes, &got_key, &got_overlapped, timeout, &error)) {
        *overlapped = 0;
        last_error = error ? error : 258u;
        return 0;
    }
    *bytes = got_bytes;
    *key = got_key;
    *overlapped = got_overlapped;
    return 1;
}
int32_t __attribute__((stdcall)) ntw_imp_lstrcmpiA(const uint8_t *left, const uint8_t *right) {
    return ntw_lstrcmpi_a(left, right);
}
static int read_statm(const char *path, uint32_t *size_pages, uint32_t *resident) {
    char text[96];
    int fd, n;
    fd = ntw_open(path, 0, 0);
    if (fd < 0) return 0;
    n = ntw_read(fd, text, sizeof text - 1u);
    ntw_close(fd);
    if (n <= 0) return 0;
    text[n] = 0;
    return ntw_mem_parse_statm(text, size_pages, resident);
}
static int proc_statm_path(uint32_t pid, char *path, uint32_t cap) {
    char digits[12];
    uint32_t n = 0, count = 0, value = pid;
    const char *prefix = "/proc/";
    const char *suffix = "/statm";
    if (!path || cap < 20) return 0;
    if (!value) value = 0;
    do { digits[count++] = (char)('0' + (value % 10u)); value /= 10u; } while (value && count < sizeof digits);
    while (prefix[n]) { path[n] = prefix[n]; n++; }
    while (count && n + 8 < cap) path[n++] = digits[--count];
    count = 0;
    while (suffix[count] && n + 1 < cap) path[n++] = suffix[count++];
    path[n] = 0;
    return suffix[count] == 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_K32GetProcessMemoryInfo(uint32_t process, void *buffer, uint32_t bytes) {
    uint32_t error = 0, size_pages = 0, resident = 0, pid = 0, working, pagefile;
    char path[32];
    int ok;
    if (process == 0xffffffffu || process == 0x2000u) ok = read_statm("/proc/self/statm", &size_pages, &resident);
    else if (ntw_proc_pid(process, &pid) && proc_statm_path(pid, path, sizeof path))
        ok = read_statm(path, &size_pages, &resident);
    else { last_error = 6; return 0; }
    if (!ok) { last_error = 5; return 0; }
    working = (uint32_t)((uint64_t)resident * 4096u);
    pagefile = (uint32_t)((uint64_t)size_pages * 4096u);
    if (!ntw_mem_store(buffer, bytes, 0, working, pagefile, pagefile, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    return 1;
}
static int read_text(const char *path, char *text, uint32_t cap) {
    int fd, n;
    if (!text || cap < 2) return 0;
    fd = ntw_open(path, 0, 0);
    if (fd < 0) return 0;
    n = ntw_read(fd, text, cap - 1u);
    ntw_close(fd);
    if (n <= 0) return 0;
    text[n] = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_K32GetPerformanceInfo(void *buffer, uint32_t bytes) {
    char text[1536];
    uint32_t error = 0, total = 0, avail = 0, committed = 0, limit = 0;
    if (!read_text("/proc/meminfo", text, sizeof text)) { last_error = 5; return 0; }
    if (!ntw_perf_parse(text, &total, &avail, &committed, &limit)) { last_error = 31; return 0; }
    if (!ntw_perf_store(buffer, bytes, (uint32_t)((uint64_t)committed * 1024u), (uint32_t)((uint64_t)limit * 1024u),
                        (uint32_t)((uint64_t)total * 1024u), (uint32_t)((uint64_t)avail * 1024u), &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_InitOnceExecuteOnce(uint32_t *once, uint32_t fn, uint32_t param, uint32_t *context) {
    uint32_t error = 0;
    if (!ntw_init_execute(once, (ntw_init_fn)(unsigned long)fn, param, context, &error)) {
        last_error = error;
        return 0;
    }
    return 1;
}
static int dep_policy_set;
uint32_t __attribute__((stdcall)) ntw_imp_SetProcessDEPPolicy(uint32_t flags) {
    if (flags & ~3u) { last_error = 87; return 0; }
    if (dep_policy_set) { last_error = 5; return 0; }
    dep_policy_set = 1;
    append("dep policy ");
    append_hex(flags);
    append("\n");
    flush_log_now();
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_FindFirstFileExW(const uint16_t *name, uint32_t level, void *data, uint32_t search,
                                                         uint32_t filter, uint32_t extra) {
    uint32_t handle = 0xffffffffu, error = 0;
    if (!ntw_find_first(name, level, search, filter, extra, data, 592, &handle, &error)) {
        last_error = error ? error : 87u;
        append("find fail ");
        append_hex(last_error);
        append("\n");
        flush_log_now();
        return 0xffffffffu;
    }
    append("find ");
    append_hex(handle);
    append("\n");
    flush_log_now();
    last_error = 0;
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_FindNextFileW(uint32_t handle, void *data) {
    uint32_t error = 0;
    if (!ntw_find_next(handle, data, 592, &error)) { last_error = error ? error : 18u; return 0; }
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_FindClose(uint32_t handle) {
    uint32_t error = 0;
    if (!ntw_find_close(handle, &error)) { last_error = error ? error : 6u; return 0; }
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateSemaphoreW(uint32_t security, int32_t initial, int32_t maximum, const uint16_t *name) {
    uint32_t handle = 0, error = 0;
    (void)security;
    if (!ntw_sem_create(initial, maximum, name, &handle, &error)) { last_error = error ? error : 87u; return 0; }
    append("semaphore ");
    append_hex((uint32_t)initial);
    append(" ");
    append_hex((uint32_t)maximum);
    append("\n");
    flush_log_now();
    if (error) last_error = error;
    else last_error = 0;
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateSemaphoreA(uint32_t security, int32_t initial, int32_t maximum, const char *name) {
    uint16_t wide[128];
    uint32_t i = 0;
    if (!name) return ntw_imp_CreateSemaphoreW(security, initial, maximum, 0);
    while (name[i] && i + 1 < 128) { wide[i] = (unsigned char)name[i]; i++; }
    if (name[i]) { last_error = 123; return 0; }
    wide[i] = 0;
    return ntw_imp_CreateSemaphoreW(security, initial, maximum, wide);
}
uint32_t __attribute__((stdcall)) ntw_imp_ReleaseSemaphore(uint32_t handle, int32_t count, int32_t *previous) {
    uint32_t error = 0;
    if (!ntw_sem_release(handle, count, previous, &error)) { last_error = error ? error : 6u; return 0; }
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_WaitForSingleObject(uint32_t handle, uint32_t timeout) {
    uint32_t result = 0, error = 0;
    if (ntw_proc_owns(handle)) {
        if (!ntw_proc_wait(handle, timeout == 0xffffffffu, &result, &error)) {
            last_error = error ? error : 6u;
            return 0xffffffffu;
        }
        return result;
    }
    if (ntw_thread_owns(handle)) {
        if (!ntw_thread_wait(handle, timeout == 0xffffffffu, &result, &error)) {
            last_error = error ? error : 6u;
            return 0xffffffffu;
        }
        return result;
    }
    if (ntw_sem_owns(handle)) {
        if (!ntw_sem_wait(handle, &result)) { last_error = 6; return 0xffffffffu; }
        return result;
    }
    if (!ntw_event_wait(handle, &result)) { last_error = 6; return 0xffffffffu; }
    (void)timeout;
    return result;
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateProcessW(const uint16_t *application, uint16_t *command, uint32_t process_attr,
                                                        uint32_t thread_attr, uint32_t inherit, uint32_t flags,
                                                        uint32_t environment, const uint16_t *directory, uint32_t startup,
                                                        uint32_t *info) {
    uint32_t process = 0, thread = 0, pid = 0, tid = 0, error = 0;
    char shown[180];
    uint32_t n = 0;
    const uint16_t *text = command ? command : application;
    (void)process_attr; (void)thread_attr; (void)inherit; (void)directory; (void)startup;
    append("proc ");
    if (!text) append("(null)");
    else {
        while (text[n] && n + 1 < sizeof shown) {
            shown[n] = (text[n] >= 32 && text[n] < 127) ? (char)text[n] : '?';
            n++;
        }
        shown[n] = 0;
        append(shown);
    }
    append("\n");
    flush_log_now();
    if (!info) { last_error = 87; return 0; }
    if (!ntw_proc_create(application, command, flags, environment, &process, &thread, &pid, &tid, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    info[0] = process;
    info[1] = thread;
    info[2] = pid;
    info[3] = tid;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetExitCodeProcess(uint32_t process, uint32_t *code) {
    uint32_t error = 0;
    if (!ntw_proc_exit_code(process, code, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_TerminateProcess(uint32_t process, uint32_t code) {
    uint32_t error = 0;
    append("terminate ");
    append_hex(process);
    append(" ");
    append_hex(code);
    append("\n");
    flush_log_now();
    if (process == 0xffffffffu || process == 0x2000u) ntw_exit(code);
    if (!ntw_proc_terminate(process, code, &error)) { last_error = error ? error : 6u; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_ProcessPrng(uint32_t buffer, uint32_t bytes);
static int wide_equal(const uint16_t *wide, const char *ascii) {
    while (*ascii) {
        uint16_t ch = *wide++;
        char plain = *ascii++;
        if (ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch - 'A' + 'a');
        if (plain >= 'A' && plain <= 'Z') plain = (char)(plain - 'A' + 'a');
        if (ch != (uint16_t)(uint8_t)plain) return 0;
    }
    return *wide == 0;
}
static int wide_starts(const uint16_t *wide, const char *ascii) {
    if (!wide) return 0;
    while (*ascii) {
        uint16_t ch = *wide++;
        char plain = *ascii++;
        if (ch >= 'A' && ch <= 'Z') ch = (uint16_t)(ch - 'A' + 'a');
        if (plain >= 'A' && plain <= 'Z') plain = (char)(plain - 'A' + 'a');
        if (ch != (uint16_t)(uint8_t)plain) return 0;
    }
    return 1;
}
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t pe_export(uint8_t *image, uint32_t limit, const char *name) {
    uint32_t pe, opt, dir, count, funcs, names, ords, i;
    if (!image || !name || limit < 0x80) return 0;
    pe = rd32(image + 0x3c);
    if (pe + 120 > limit) return 0;
    opt = pe + 24;
    dir = rd32(image + opt + 96);
    if (!dir || dir + 40 > limit) return 0;
    count = rd32(image + dir + 24);
    funcs = rd32(image + dir + 28);
    names = rd32(image + dir + 32);
    ords = rd32(image + dir + 36);
    if (count > 200000u) return 0;
    for (i = 0; i < count; ++i) {
        uint32_t name_rva, rva;
        uint16_t ordinal;
        if (names + i * 4 + 4 > limit || ords + i * 2 + 2 > limit) return 0;
        name_rva = rd32(image + names + i * 4);
        if (!name_rva || name_rva >= limit) continue;
        if (!same_name((const char *)(image + name_rva), name)) continue;
        ordinal = rd16(image + ords + i * 2);
        if (funcs + (uint32_t)ordinal * 4 + 4 > limit) return 0;
        rva = rd32(image + funcs + (uint32_t)ordinal * 4);
        if (!rva || rva >= limit) return 0;
        return (uint32_t)(unsigned long)(image + rva);
    }
    return 0;
}
static uint32_t dep_export(const char *name) {
    return pe_export(dep_image, dep_placed.size_of_image, name);
}
static int register_one(uint8_t *image, const ntw_placed *placed, ntwtls_process *process, uint32_t *index);
static void call_tls(uint8_t *image, const ntw_placed *placed);
static uint32_t map_sibling_dll(const uint16_t *name);
uint32_t __attribute__((stdcall)) ntw_imp_InitializeAcl(void *acl, uint32_t length, uint32_t revision) {
    uint8_t *bytes = acl;
    if (!acl || length < 8u || (revision != 2u && revision != 4u)) { last_error = 87; return 0; }
    bytes[0] = (uint8_t)revision;
    bytes[1] = 0;
    bytes[2] = (uint8_t)length;
    bytes[3] = (uint8_t)(length >> 8);
    bytes[4] = 0;
    bytes[5] = 0;
    bytes[6] = 0;
    bytes[7] = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsValidAcl(void *acl) {
    uint8_t *bytes = acl;
    uint32_t size, count, offset, i;
    if (!acl || (uint32_t)(unsigned long)acl < 0x10000u) return 0;
    if (bytes[0] != 2 && bytes[0] != 4) return 0;
    size = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8);
    count = (uint32_t)bytes[4] | ((uint32_t)bytes[5] << 8);
    if (size < 8u) return 0;
    offset = 8;
    for (i = 0; i < count; ++i) {
        uint32_t ace_size;
        if (offset + 4 > size) return 0;
        ace_size = (uint32_t)bytes[offset + 2] | ((uint32_t)bytes[offset + 3] << 8);
        if (ace_size < 4u || offset + ace_size > size) return 0;
        offset += ace_size;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetAce(void *acl, uint32_t index, uint32_t *ace) {
    uint8_t *bytes = acl;
    uint32_t count, offset, i, size;
    if (!acl || !ace || !ntw_imp_IsValidAcl(acl)) { last_error = 87; return 0; }
    count = (uint32_t)bytes[4] | ((uint32_t)bytes[5] << 8);
    size = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8);
    if (index >= count) { last_error = 87; return 0; }
    offset = 8;
    for (i = 0; i < index; ++i) {
        uint32_t ace_size = (uint32_t)bytes[offset + 2] | ((uint32_t)bytes[offset + 3] << 8);
        if (ace_size < 4u || offset + ace_size > size) { last_error = 87; return 0; }
        offset += ace_size;
    }
    *ace = (uint32_t)(unsigned long)(bytes + offset);
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_InitializeSecurityDescriptor(void *descriptor, uint32_t revision) {
    uint8_t *bytes = descriptor;
    uint32_t i;
    if (!descriptor || revision != 1u) { last_error = 87; return 0; }
    for (i = 0; i < 20; ++i) bytes[i] = 0;
    bytes[0] = 1;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsValidSecurityDescriptor(void *descriptor) {
    uint8_t *bytes = descriptor;
    return descriptor && bytes[0] == 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSecurityDescriptorControl(void *descriptor, uint32_t *control, uint32_t *revision) {
    uint8_t *bytes = descriptor;
    if (!ntw_imp_IsValidSecurityDescriptor(descriptor) || !control || !revision) { last_error = 87; return 0; }
    *control = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8);
    *revision = bytes[0];
    return 1;
}
static uint32_t security_pointer(void *descriptor, uint32_t present_bit, uint32_t offset, uint32_t *present, uint32_t *pointer, uint32_t *defaulted) {
    uint8_t *bytes = descriptor;
    uint32_t control;
    if (!ntw_imp_IsValidSecurityDescriptor(descriptor) || !present || !pointer || !defaulted) { last_error = 87; return 0; }
    control = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8);
    *defaulted = (control & (present_bit << 1)) ? 1u : 0u;
    if (control & present_bit) {
        *present = 1;
        *pointer = *(uint32_t *)(bytes + offset);
    } else {
        *present = 0;
        *pointer = 0;
    }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSecurityDescriptorDacl(void *descriptor, uint32_t *present, uint32_t *acl, uint32_t *defaulted) {
    return security_pointer(descriptor, 0x4u, 16, present, acl, defaulted);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSecurityDescriptorSacl(void *descriptor, uint32_t *present, uint32_t *acl, uint32_t *defaulted) {
    return security_pointer(descriptor, 0x10u, 12, present, acl, defaulted);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSecurityDescriptorOwner(void *descriptor, uint32_t *owner, uint32_t *defaulted) {
    uint8_t *bytes = descriptor;
    if (!ntw_imp_IsValidSecurityDescriptor(descriptor) || !owner || !defaulted) { last_error = 87; return 0; }
    *owner = *(uint32_t *)(bytes + 4);
    *defaulted = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSecurityDescriptorGroup(void *descriptor, uint32_t *group, uint32_t *defaulted) {
    uint8_t *bytes = descriptor;
    if (!ntw_imp_IsValidSecurityDescriptor(descriptor) || !group || !defaulted) { last_error = 87; return 0; }
    *group = *(uint32_t *)(bytes + 8);
    *defaulted = 0;
    return 1;
}
static uint32_t set_security_acl(void *descriptor, uint32_t present_bit, uint32_t offset, uint32_t present, void *acl, uint32_t defaulted) {
    uint8_t *bytes = descriptor;
    uint32_t control;
    if (!ntw_imp_IsValidSecurityDescriptor(descriptor)) { last_error = 87; return 0; }
    if (present && acl && !ntw_imp_IsValidAcl(acl)) { last_error = 87; return 0; }
    control = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8);
    control &= ~(present_bit | (present_bit << 1));
    if (present) control |= present_bit;
    if (present && defaulted) control |= present_bit << 1;
    bytes[2] = (uint8_t)control;
    bytes[3] = (uint8_t)(control >> 8);
    *(uint32_t *)(bytes + offset) = present ? (uint32_t)(unsigned long)acl : 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetSecurityDescriptorDacl(void *descriptor, uint32_t present, void *acl, uint32_t defaulted) {
    return set_security_acl(descriptor, 0x4u, 16, present, acl, defaulted);
}
uint32_t __attribute__((stdcall)) ntw_imp_SetSecurityDescriptorSacl(void *descriptor, uint32_t present, void *acl, uint32_t defaulted) {
    return set_security_acl(descriptor, 0x10u, 12, present, acl, defaulted);
}
uint32_t __attribute__((stdcall)) ntw_imp_RegOpenKeyExW(uint32_t key, const uint16_t *subkey, uint32_t options,
                                                      uint32_t access, uint32_t *result) {
    (void)key; (void)subkey; (void)options; (void)access;
    if (!result) { last_error = 87; return 87; }
    *result = 0;
    last_error = 2;
    return 2;
}
uint32_t __attribute__((stdcall)) ntw_imp_RegCloseKey(uint32_t key) {
    (void)key;
    last_error = 6;
    return 6;
}
uint32_t __attribute__((stdcall)) ntw_imp_RegQueryValueExW(uint32_t key, const uint16_t *name, uint32_t *reserved,
                                                         uint32_t *type, uint8_t *data, uint32_t *bytes) {
    (void)key; (void)name; (void)reserved; (void)type; (void)data; (void)bytes;
    last_error = 2;
    return 2;
}
uint32_t __attribute__((stdcall)) ntw_imp_RegQueryValueExA(uint32_t key, const char *name, uint32_t *reserved,
                                                         uint32_t *type, uint8_t *data, uint32_t *bytes) {
    (void)key; (void)name; (void)reserved; (void)type; (void)data; (void)bytes;
    last_error = 2;
    return 2;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileVersionInfoSizeW(const uint16_t *filename, uint32_t *handle) {
    char path[260];
    uint8_t *image = 0;
    uint32_t i = 0, file_size = 0, offset = 0, bytes = 0, error = 0;
    int fd, length;
    if (handle) *handle = 0;
    if (!filename || !filename[0]) { last_error = 87; return 0; }
    while (filename[i]) {
        if (filename[i] > 127 || i + 1 >= sizeof path) { last_error = 1812; return 0; }
        path[i] = (char)filename[i];
        i++;
    }
    path[i] = 0;
    fd = ntw_open(path, O_RDONLY, 0);
    if (fd < 0) { last_error = 1812; return 0; }
    length = ntw_lseek(fd, 0, 2);
    if (length < 64 || length > 8 * 1024 * 1024) { ntw_close(fd); last_error = 1812; return 0; }
    ntw_lseek(fd, 0, 0);
    image = ntw_mmap2(0, (unsigned)length, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)image > 0xfffff000u || ntw_read(fd, image, (unsigned)length) != length) {
        ntw_close(fd);
        last_error = 1812;
        return 0;
    }
    ntw_close(fd);
    file_size = (uint32_t)length;
    if (!ntw_ver_find(image, file_size, &offset, &bytes, &error)) {
        ntw_munmap(image, (unsigned)length);
        last_error = error ? error : 1812;
        return 0;
    }
    ntw_munmap(image, (unsigned)length);
    return bytes;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileVersionInfoW(const uint16_t *filename, uint32_t handle, uint32_t bytes, void *data) {
    char path[260];
    uint8_t *image = 0;
    uint32_t i = 0, file_size = 0, offset = 0, found = 0, error = 0;
    int fd, length;
    (void)handle;
    if (!filename || !filename[0] || !data) { last_error = 87; return 0; }
    while (filename[i]) {
        if (filename[i] > 127 || i + 1 >= sizeof path) { last_error = 1812; return 0; }
        path[i] = (char)filename[i];
        i++;
    }
    path[i] = 0;
    fd = ntw_open(path, O_RDONLY, 0);
    if (fd < 0) { last_error = 1812; return 0; }
    length = ntw_lseek(fd, 0, 2);
    if (length < 64 || length > 8 * 1024 * 1024) { ntw_close(fd); last_error = 1812; return 0; }
    ntw_lseek(fd, 0, 0);
    image = ntw_mmap2(0, (unsigned)length, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)image > 0xfffff000u || ntw_read(fd, image, (unsigned)length) != length) {
        ntw_close(fd);
        last_error = 1812;
        return 0;
    }
    ntw_close(fd);
    file_size = (uint32_t)length;
    if (!ntw_ver_find(image, file_size, &offset, &found, &error)) {
        ntw_munmap(image, (unsigned)length);
        last_error = error ? error : 1812;
        return 0;
    }
    if (bytes < found) {
        ntw_munmap(image, (unsigned)length);
        last_error = 122;
        return 0;
    }
    for (i = 0; i < found; ++i) ((uint8_t *)data)[i] = image[offset + i];
    ntw_munmap(image, (unsigned)length);
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_VerQueryValueW(const void *block, const uint16_t *sub, uint32_t *buffer, uint32_t *length) {
    const void *value = 0;
    uint32_t bytes = 0, error = 0, block_size;
    if (!block || !sub || !buffer || !length) { last_error = 87; return 0; }
    block_size = ((const uint8_t *)block)[0] | ((uint32_t)((const uint8_t *)block)[1] << 8);
    if (!ntw_ver_query(block, block_size, sub, &value, &bytes, &error) || !value) {
        last_error = error ? error : 1812;
        return 0;
    }
    *buffer = (uint32_t)(unsigned long)value;
    *length = bytes;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_ConvertStringSecurityDescriptorToSecurityDescriptorW(
        const uint16_t *text, uint32_t revision, uint32_t *descriptor, uint32_t *descriptor_bytes) {
    uint8_t blob[1536];
    uint8_t *dest;
    char shown[180];
    uint32_t bytes = 0, error = 0, i, n = 0, copy;
    if (text) {
        while (text[n] && n + 1 < sizeof shown) {
            shown[n] = (text[n] >= 32 && text[n] < 127) ? (char)text[n] : '?';
            n += 1u;
        }
        shown[n] = 0;
        append("sddl ");
        append(shown);
        append("\n");
        flush_log_now();
    }
    if (!descriptor || !ntw_sddl_build(text, revision, blob, sizeof blob, &bytes, &error)) {
        last_error = error ? error : 87u;
        return 0;
    }
    copy = ntw_imp_LocalAlloc(0x40u, bytes);
    if (!copy) return 0;
    dest = (uint8_t *)(unsigned long)copy;
    for (i = 0; i < bytes; ++i) dest[i] = blob[i];
    *descriptor = copy;
    if (descriptor_bytes) *descriptor_bytes = bytes;
    return 1;
}
void __attribute__((stdcall)) ntw_imp_BuildExplicitAccessWithNameW(uint8_t *access, const uint16_t *name,
                                                                   uint32_t perms, uint32_t mode, uint32_t inherit) {
    char shown[96];
    uint32_t error = 0, n = 0;
    if (name) {
        while (name[n] && n + 1 < sizeof shown) {
            shown[n] = (name[n] >= 32 && name[n] < 127) ? (char)name[n] : '?';
            n += 1u;
        }
        shown[n] = 0;
        append("trustee ");
        append(shown);
        append("\n");
        flush_log_now();
    }
    if (!ntw_explicit_access(access, name, perms, mode, inherit, &error)) last_error = error ? error : 87u;
}
uint32_t __attribute__((stdcall)) ntw_imp_BuildSecurityDescriptorW(uint32_t owner, uint32_t group, uint32_t count,
                                                                  uint8_t *list, uint32_t audit_count, uint32_t audits,
                                                                  uint8_t *old_sd, uint32_t *out_size, uint32_t *out_sd) {
    uint8_t blob[1536], *dest;
    uint32_t perms, mode, inherit, form, name_bits, bytes = 0, error = 0, copy, old_bytes, i;
    const uint16_t *name;
    (void)audits;
    if (owner || group || audit_count || !out_sd || count != 1u || !list || !old_sd) {
        last_error = 87;
        return 87;
    }
    perms = rd32(list);
    mode = rd32(list + 4);
    inherit = rd32(list + 8);
    form = rd32(list + 20);
    name_bits = rd32(list + 28);
    if (mode != 1u || form != 1u || !name_bits) { last_error = 87; return 87; }
    name = (const uint16_t *)(unsigned long)name_bits;
    old_bytes = ntw_imp_HeapSize(NTW_HEAP_HANDLE, 0, (uint32_t)(unsigned long)old_sd);
    if (old_bytes == 0xffffffffu || old_bytes < 20u) { last_error = 87; return 87; }
    if (!ntw_merge_grant(old_sd, old_bytes, name, perms, inherit, blob, sizeof blob, &bytes, &error)) {
        last_error = error ? error : 87u;
        return last_error;
    }
    copy = ntw_imp_LocalAlloc(0x40u, bytes);
    if (!copy) return last_error ? last_error : 8u;
    dest = (uint8_t *)(unsigned long)copy;
    for (i = 0; i < bytes; ++i) dest[i] = blob[i];
    *out_sd = copy;
    if (out_size) *out_size = bytes;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsValidSid(uint32_t sid);
uint32_t __attribute__((stdcall)) ntw_imp_GetLengthSid(uint32_t sid);
uint32_t __attribute__((stdcall)) ntw_imp_GetSidSubAuthorityCount(uint32_t sid) {
    if (!ntw_imp_IsValidSid(sid)) return 0;
    return sid + 1u;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSidSubAuthority(uint32_t sid, uint32_t index) {
    uint8_t *bytes = (uint8_t *)(unsigned long)sid;
    if (!ntw_imp_IsValidSid(sid) || index >= bytes[1]) return 0;
    return sid + 8u + index * 4u;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSidIdentifierAuthority(uint32_t sid) {
    if (!ntw_imp_IsValidSid(sid)) return 0;
    return sid + 2u;
}
uint32_t __attribute__((stdcall)) ntw_imp_CopySid(uint32_t length, uint32_t dest, uint32_t source) {
    uint8_t *to = (uint8_t *)(unsigned long)dest;
    uint8_t *from = (uint8_t *)(unsigned long)source;
    uint32_t need, i;
    need = ntw_imp_GetLengthSid(source);
    if (!dest || !need) { last_error = 87; return 0; }
    if (length < need) { last_error = 122; return 0; }
    for (i = 0; i < need; ++i) to[i] = from[i];
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_EqualSid(uint32_t left, uint32_t right) {
    uint8_t *a = (uint8_t *)(unsigned long)left;
    uint8_t *b = (uint8_t *)(unsigned long)right;
    uint32_t na, nb, i;
    na = ntw_imp_GetLengthSid(left);
    nb = ntw_imp_GetLengthSid(right);
    if (!na || na != nb) return 0;
    for (i = 0; i < na; ++i) if (a[i] != b[i]) return 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetLengthSid(uint32_t sid) {
    uint8_t *bytes = (uint8_t *)(unsigned long)sid;
    if (!ntw_imp_IsValidSid(sid)) return 0;
    return 8u + 4u * bytes[1];
}
uint32_t __attribute__((stdcall)) ntw_imp_IsValidSid(uint32_t sid) {
    uint8_t *bytes = (uint8_t *)(unsigned long)sid;
    if (!sid || sid < 0x10000u) return 0;
    if (bytes[0] != 1 || bytes[1] > 15) return 0;
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetFileTime(uint32_t handle, uint32_t *created, uint32_t *accessed, uint32_t *written) {
    uint8_t info[40];
    uint32_t error = 0, i;
    if (!ntw_winfile_info(handle, 0, info, 40, &error)) { last_error = error ? error : 6u; return 0; }
    if (created) for (i = 0; i < 2; ++i) created[i] = *(uint32_t *)(info + i * 4);
    if (accessed) for (i = 0; i < 2; ++i) accessed[i] = *(uint32_t *)(info + 8 + i * 4);
    if (written) for (i = 0; i < 2; ++i) written[i] = *(uint32_t *)(info + 16 + i * 4);
    last_error = 0;
    return 1;
}
void __attribute__((stdcall)) ntw_imp_BuildTrusteeWithSidW(uint32_t trustee, uint32_t sid) {
    ntw_trustee_with_sid((void *)(unsigned long)trustee, (void *)(unsigned long)sid, ntw_imp_IsValidSid(sid), &last_error);
}
static void *acl_alloc(unsigned bytes) {
    return (void *)(unsigned long)ntw_imp_LocalAlloc(0x40u, bytes);
}
uint32_t __attribute__((stdcall)) ntw_imp_SetEntriesInAclW(uint32_t count, uint32_t entries, uint32_t old_acl, uint32_t *out) {
    (void)old_acl;
    return ntw_acl_set_entries(count, (void *)(unsigned long)entries, (void **)(unsigned long)out, acl_alloc);
}
uint32_t __attribute__((stdcall)) ntw_imp_SetSecurityInfo(uint32_t handle, uint32_t object_type, uint32_t owner, uint32_t group,
                                                         uint32_t dacl, uint32_t sacl) {
    (void)owner; (void)group; (void)dacl; (void)sacl;
    if (object_type > 7u) { last_error = 87; return 87; }
    if (!handle || (!known_kernel_handle(handle) && !ntw_find_owns(handle) && !ntw_user_owns(handle))) {
        last_error = 6;
        return 6;
    }
    last_error = 0;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetSecurityInfo(uint32_t handle, uint32_t object_type, uint32_t info,
                                                         uint32_t *owner, uint32_t *group, uint32_t *dacl, uint32_t *sacl,
                                                         uint32_t *descriptor) {
    static const uint8_t blob[] = {
        1, 0, 0x04, 0x00,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
        2, 0, 8, 0, 0, 0, 0, 0
    };
    uint32_t copy, i;
    uint8_t *dest;
    (void)info;
    if (!descriptor || object_type > 7u) { last_error = 87; return 87; }
    if (!handle || (!known_kernel_handle(handle) && !ntw_find_owns(handle) && !ntw_user_owns(handle))) {
        last_error = 6;
        return 6;
    }
    copy = ntw_imp_LocalAlloc(0x40u, sizeof blob);
    if (!copy) return last_error ? last_error : 8u;
    dest = (uint8_t *)(unsigned long)copy;
    for (i = 0; i < sizeof blob; ++i) dest[i] = blob[i];
    *(uint32_t *)(dest + 4) = copy + 20u;
    *(uint32_t *)(dest + 8) = copy + 20u;
    *(uint32_t *)(dest + 16) = copy + 32u;
    if (owner) *owner = copy + 20u;
    if (group) *group = copy + 20u;
    if (dacl) *dacl = copy + 32u;
    if (sacl) *sacl = 0;
    *descriptor = copy;
    append("securityinfo ");
    append_hex(object_type);
    append("\n");
    flush_log_now();
    last_error = 0;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_OpenProcessToken(uint32_t process, uint32_t access, uint32_t *token) {
    uint32_t error = 0;
    if (!token) { last_error = 87; return 0; }
    if (process != 0xffffffffu && process != 0x2000u && !ntw_proc_owns(process)) { last_error = 6; return 0; }
    if (!ntw_token_open(access, token, &error)) { last_error = error ? error : 5u; return 0; }
    append("token ");
    append_hex(access);
    append("\n");
    flush_log_now();
    last_error = 0;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetTokenInformation(uint32_t token, uint32_t klass, uint32_t buffer,
                                                             uint32_t bytes, uint32_t *needed) {
    uint32_t error = 0;
    if (!ntw_token_info(token, klass, (void *)(unsigned long)buffer, bytes, needed, &error)) {
        append("tokeninfo ");
        append_hex(klass);
        append(" ");
        append_hex(error);
        append("\n");
        flush_log_now();
        last_error = error ? error : 6u;
        return 0;
    }
    last_error = 0;
    return 1;
}
static uint32_t advapi_export(const char *name) {
    if (same_name(name, "InitializeAcl")) return (uint32_t)(unsigned long)ntw_imp_InitializeAcl;
    if (same_name(name, "IsValidAcl")) return (uint32_t)(unsigned long)ntw_imp_IsValidAcl;
    if (same_name(name, "GetAce")) return (uint32_t)(unsigned long)ntw_imp_GetAce;
    if (same_name(name, "InitializeSecurityDescriptor")) return (uint32_t)(unsigned long)ntw_imp_InitializeSecurityDescriptor;
    if (same_name(name, "IsValidSecurityDescriptor")) return (uint32_t)(unsigned long)ntw_imp_IsValidSecurityDescriptor;
    if (same_name(name, "GetSecurityDescriptorControl")) return (uint32_t)(unsigned long)ntw_imp_GetSecurityDescriptorControl;
    if (same_name(name, "GetSecurityDescriptorDacl")) return (uint32_t)(unsigned long)ntw_imp_GetSecurityDescriptorDacl;
    if (same_name(name, "GetSecurityDescriptorSacl")) return (uint32_t)(unsigned long)ntw_imp_GetSecurityDescriptorSacl;
    if (same_name(name, "GetSecurityDescriptorOwner")) return (uint32_t)(unsigned long)ntw_imp_GetSecurityDescriptorOwner;
    if (same_name(name, "GetSecurityDescriptorGroup")) return (uint32_t)(unsigned long)ntw_imp_GetSecurityDescriptorGroup;
    if (same_name(name, "SetSecurityDescriptorDacl")) return (uint32_t)(unsigned long)ntw_imp_SetSecurityDescriptorDacl;
    if (same_name(name, "SetSecurityDescriptorSacl")) return (uint32_t)(unsigned long)ntw_imp_SetSecurityDescriptorSacl;
    if (same_name(name, "RegOpenKeyExW")) return (uint32_t)(unsigned long)ntw_imp_RegOpenKeyExW;
    if (same_name(name, "RegCloseKey")) return (uint32_t)(unsigned long)ntw_imp_RegCloseKey;
    if (same_name(name, "RegQueryValueExW")) return (uint32_t)(unsigned long)ntw_imp_RegQueryValueExW;
    if (same_name(name, "RegQueryValueExA")) return (uint32_t)(unsigned long)ntw_imp_RegQueryValueExA;
    if (same_name(name, "ConvertStringSecurityDescriptorToSecurityDescriptorW"))
        return (uint32_t)(unsigned long)ntw_imp_ConvertStringSecurityDescriptorToSecurityDescriptorW;
    if (same_name(name, "BuildExplicitAccessWithNameW"))
        return (uint32_t)(unsigned long)ntw_imp_BuildExplicitAccessWithNameW;
    if (same_name(name, "BuildSecurityDescriptorW"))
        return (uint32_t)(unsigned long)ntw_imp_BuildSecurityDescriptorW;
    if (same_name(name, "IsValidSid")) return (uint32_t)(unsigned long)ntw_imp_IsValidSid;
    if (same_name(name, "GetLengthSid")) return (uint32_t)(unsigned long)ntw_imp_GetLengthSid;
    if (same_name(name, "CopySid")) return (uint32_t)(unsigned long)ntw_imp_CopySid;
    if (same_name(name, "EqualSid")) return (uint32_t)(unsigned long)ntw_imp_EqualSid;
    if (same_name(name, "GetSidSubAuthorityCount")) return (uint32_t)(unsigned long)ntw_imp_GetSidSubAuthorityCount;
    if (same_name(name, "GetSidSubAuthority")) return (uint32_t)(unsigned long)ntw_imp_GetSidSubAuthority;
    if (same_name(name, "GetSidIdentifierAuthority")) return (uint32_t)(unsigned long)ntw_imp_GetSidIdentifierAuthority;
    if (same_name(name, "GetSecurityInfo")) return (uint32_t)(unsigned long)ntw_imp_GetSecurityInfo;
    if (same_name(name, "BuildTrusteeWithSidW")) return (uint32_t)(unsigned long)ntw_imp_BuildTrusteeWithSidW;
    if (same_name(name, "SetEntriesInAclW")) return (uint32_t)(unsigned long)ntw_imp_SetEntriesInAclW;
    if (same_name(name, "SetSecurityInfo")) return (uint32_t)(unsigned long)ntw_imp_SetSecurityInfo;
    if (same_name(name, "OpenProcessToken")) return (uint32_t)(unsigned long)ntw_imp_OpenProcessToken;
    if (same_name(name, "GetTokenInformation")) return (uint32_t)(unsigned long)ntw_imp_GetTokenInformation;
    return 0;
}
static int shell_exists(void *user, const char *path) {
    (void)user;
    return ntw_winfile_path_exists(path) ? 1 : 0;
}
static int shell_mkdir(void *user, const char *path) {
    (void)user;
    return ntw_winfile_path_mkdir(path);
}
uint32_t __attribute__((stdcall)) ntw_imp_CommandLineToArgvW(const uint16_t *cmd, uint32_t *count) {
    uint8_t *block;
    uint16_t *words;
    uint32_t offsets[64], error = 0, i;
    int argc = 0;
    if (!count) { last_error = 87; return 0; }
    block = (uint8_t *)(unsigned long)ntw_imp_LocalAlloc(0x40u, 64u * 4u + 4096u);
    if (!block) return 0;
    words = (uint16_t *)(block + 64u * 4u);
    if (!ntw_shell_argv(cmd, words, 2048, offsets, 64, &argc, &error)) {
        ntw_imp_LocalFree((uint32_t)(unsigned long)block);
        last_error = error ? error : 87u;
        return 0;
    }
    for (i = 0; i < (uint32_t)argc; ++i) ((uint32_t *)block)[i] = (uint32_t)(unsigned long)(words + offsets[i]);
    *count = (uint32_t)argc;
    return (uint32_t)(unsigned long)block;
}
uint32_t __attribute__((stdcall)) ntw_imp_SHGetFolderPathW(uint32_t hwnd, uint32_t csidl, uint32_t token, uint32_t kind, uint16_t *path) {
    uint32_t hr = 0;
    (void)hwnd; (void)token; (void)kind;
    append("shell SHGetFolderPathW "); append_hex(csidl); append("\n"); flush_log_now();
    if (!ntw_shell_folder(csidl, ntw_winfile_drive_root(), shell_exists, shell_mkdir, 0, path, 260, &hr)) {
        last_error = hr == 0x80070005u ? 5u : (hr == NTW_SHELL_MISSING) ? 2u : 87u;
        return hr ? hr : NTW_SHELL_INVALID;
    }
    log_file_wide(path);
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SHGetKnownFolderPath(const uint8_t *guid, uint32_t flags, uint32_t token, uint32_t *out_path) {
    uint16_t path[260];
    uint32_t hr = 0, n = 0, bytes, copy, i;
    uint8_t *block;
    (void)token;
    append("shell SHGetKnownFolderPath\n"); flush_log_now();
    if (!out_path) return NTW_SHELL_INVALID;
    *out_path = 0;
    if (!ntw_shell_known(guid, flags, ntw_winfile_drive_root(), shell_exists, shell_mkdir, 0, path, 260, &hr)) {
        last_error = (hr == NTW_SHELL_MISSING) ? 2u : 87u;
        return hr ? hr : NTW_SHELL_INVALID;
    }
    while (path[n]) n++;
    bytes = (n + 1u) * 2u;
    copy = ntw_imp_LocalAlloc(0x40u, bytes);
    if (!copy) return 0x8007000Eu;
    block = (uint8_t *)(unsigned long)copy;
    for (i = 0; i < bytes; ++i) block[i] = ((uint8_t *)path)[i];
    *out_path = copy;
    return 0;
}
static uint32_t shell_export(const char *name) {
    if (same_name(name, "CommandLineToArgvW")) return (uint32_t)(unsigned long)ntw_imp_CommandLineToArgvW;
    if (same_name(name, "SHGetFolderPathW")) return (uint32_t)(unsigned long)ntw_imp_SHGetFolderPathW;
    if (same_name(name, "SHGetKnownFolderPath")) return (uint32_t)(unsigned long)ntw_imp_SHGetKnownFolderPath;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_MiniDumpWriteDump(uint32_t process, uint32_t pid, uint32_t file, uint32_t kind,
                                                          uint32_t exception, uint32_t streams, uint32_t callback) {
    (void)process; (void)pid; (void)file; (void)kind; (void)streams; (void)callback;
    append("dbghelp MiniDumpWriteDump refused");
    append(" ex ");
    append_hex(exception);
    append("\n");
    flush_log_now();
    last_error = 120;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SymCleanup(uint32_t process) { (void)process; last_error = 120; return 0; }
uint32_t __attribute__((stdcall)) ntw_imp_SymFromAddr(uint32_t process, uint32_t addr_lo, uint32_t addr_hi, uint32_t disp, uint32_t symbol) {
    (void)process; (void)addr_lo; (void)addr_hi; (void)disp; (void)symbol; last_error = 120; return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SymGetLineFromAddr64(uint32_t process, uint32_t addr_lo, uint32_t addr_hi, uint32_t disp, uint32_t line) {
    (void)process; (void)addr_lo; (void)addr_hi; (void)disp; (void)line; last_error = 120; return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SymGetModuleInfo64(uint32_t process, uint32_t addr_lo, uint32_t addr_hi, uint32_t info) {
    (void)process; (void)addr_lo; (void)addr_hi; (void)info; last_error = 120; return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SymGetSearchPathW(uint32_t process, uint32_t path, uint32_t chars) {
    (void)process; (void)path; (void)chars; last_error = 120; return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SymInitialize(uint32_t process, uint32_t path, uint32_t invade) {
    (void)process; (void)path; (void)invade; last_error = 120; return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_SymSetOptions(uint32_t options) { (void)options; last_error = 120; return 0; }
uint32_t __attribute__((stdcall)) ntw_imp_SymSetSearchPathW(uint32_t process, uint32_t path) {
    (void)process; (void)path; last_error = 120; return 0;
}
static uint32_t dbghelp_export(const char *name) {
    if (same_name(name, "MiniDumpWriteDump")) return (uint32_t)(unsigned long)ntw_imp_MiniDumpWriteDump;
    if (same_name(name, "SymCleanup")) return (uint32_t)(unsigned long)ntw_imp_SymCleanup;
    if (same_name(name, "SymFromAddr")) return (uint32_t)(unsigned long)ntw_imp_SymFromAddr;
    if (same_name(name, "SymGetLineFromAddr64")) return (uint32_t)(unsigned long)ntw_imp_SymGetLineFromAddr64;
    if (same_name(name, "SymGetModuleInfo64")) return (uint32_t)(unsigned long)ntw_imp_SymGetModuleInfo64;
    if (same_name(name, "SymGetSearchPathW")) return (uint32_t)(unsigned long)ntw_imp_SymGetSearchPathW;
    if (same_name(name, "SymInitialize")) return (uint32_t)(unsigned long)ntw_imp_SymInitialize;
    if (same_name(name, "SymSetOptions")) return (uint32_t)(unsigned long)ntw_imp_SymSetOptions;
    if (same_name(name, "SymSetSearchPathW")) return (uint32_t)(unsigned long)ntw_imp_SymSetSearchPathW;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_AppPolicyGetProcessTerminationMethod(uint32_t token, uint32_t *policy);
uint32_t __attribute__((stdcall)) ntw_imp_GetProcAddress(uint32_t module, uint32_t name) {
    const char *text;
    uint32_t found;
    /* MSDN: an ordinal has a zero high-order word. A mapped pointer above 2GB is still a name. */
    if ((name >> 16) == 0) { last_error = name ? 127 : 87; return 0; }
    text = (const char *)(unsigned long)name;
    if (dep_image && module == (uint32_t)(unsigned long)dep_image) {
        found = dep_export(text);
        if (!found) { last_error = 127; return 0; }
        return found;
    }
    if (extra_image && module == (uint32_t)(unsigned long)extra_image) {
        found = pe_export(extra_image, extra_size, text);
        if (!found) { last_error = 127; return 0; }
        return found;
    }
    if (module == 0x1002u) {
        uint32_t found = advapi_export(text);
        if (found) return found;
        append("advapi "); append(text); append("\n");
        flush_log_now();
        last_error = 127;
        return 0;
    }
    if (module == 0x1003u) {
        found = shell_export(text);
        if (found) return found;
        append("shell "); append(text); append("\n");
        flush_log_now();
        last_error = 127;
        return 0;
    }
    if (module == 0x1004u) {
        found = dbghelp_export(text);
        if (found) return found;
        append("dbghelp "); append(text); append("\n");
        flush_log_now();
        last_error = 127;
        return 0;
    }
    if (module == 0x1006u) {
        found = ntw_user_export(text);
        if (found) return found;
        append("user32 "); append(text); append("\n");
        flush_log_now();
        last_error = 127;
        return 0;
    }
    if (module == 0x1005u) {
        if (same_name(text, "AppPolicyGetProcessTerminationMethod"))
            return (uint32_t)(unsigned long)ntw_imp_AppPolicyGetProcessTerminationMethod;
        append("appmodel "); append(text); append("\n");
        flush_log_now();
        last_error = 127;
        return 0;
    }
    if (module != 0x1000u && module != 0x1001u) { last_error = 6; return 0; }
    if (module == 0x1001u) {
        if (same_name(text, "ProcessPrng")) return (uint32_t)(unsigned long)ntw_imp_ProcessPrng;
        last_error = 127;
        return 0;
    }
    found = known_import("kernel32.dll", text);
    if (!found) {
        append("missing ");
        append(text);
        append("\n");
        flush_log_now();
        last_error = 127;
        return 0;
    }
    return found;
}
static int kernel_entropy(void *user, uint8_t *buffer, uint32_t bytes) {
    (void)user;
    return ntw_getrandom(buffer, bytes, 0);
}
uint32_t __attribute__((stdcall)) ntw_imp_ProcessPrng(uint32_t buffer, uint32_t bytes) {
    uint32_t error = 0;
    int ok = ntw_process_prng((void *)(unsigned long)buffer, bytes, kernel_entropy, 0, &error);
    if (!ok) last_error = error;
    return (uint32_t)ok;
}
uint32_t __attribute__((stdcall)) ntw_imp_AppPolicyGetProcessTerminationMethod(uint32_t token, uint32_t *policy) {
    (void)token;
    if (!policy) return 87;
    *policy = 0;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_LoadLibraryExW(uint32_t name, uint32_t file, uint32_t flags) {
    const uint16_t *text = (const uint16_t *)(unsigned long)name;
    (void)file;
    (void)flags;
    if (!name) { last_error = 87; return 0; }
    if (wide_equal(text, "kernel32.dll") || wide_equal(text, "kernel32")) return 0x1000u;
    if (wide_equal(text, "bcryptprimitives.dll")) return 0x1001u;
    if (dep_image && (wide_equal(text, "chrome_elf.dll") || wide_equal(text, "chrome_elf")))
        return (uint32_t)(unsigned long)dep_image;
    if (wide_equal(text, "advapi32.dll") || wide_equal(text, "advapi32")) return 0x1002u;
    if (wide_equal(text, "shell32.dll") || wide_equal(text, "shell32")) return 0x1003u;
    if (wide_equal(text, "user32.dll") || wide_equal(text, "user32")) return 0x1006u;
    if (wide_equal(text, "dbghelp.dll") || wide_equal(text, "dbghelp")) return 0x1004u;
    if (wide_starts(text, "api-ms-win-appmodel-runtime")) return 0x1005u;
    if (wide_starts(text, "api-ms-win-downlevel-shell32")) return 0x1003u;
    if (wide_equal(text, "kernelbase.dll") || wide_equal(text, "kernelbase")) return 0x1000u;
    if (wide_starts(text, "api-ms-win-core-")) return 0x1000u;
    {
        uint32_t mapped = map_sibling_dll(text);
        if (mapped) return mapped;
        if (last_error == 1114u) return 0;
    }
    append("dll ");
    {
        char shown[96];
        uint32_t n = 0;
        while (text[n] && n + 1 < sizeof shown) {
            shown[n] = (text[n] >= 32 && text[n] < 127) ? (char)text[n] : '?';
            n++;
        }
        shown[n] = 0;
        append(shown);
    }
    append("\n");
    flush_log_now();
    last_error = 126;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_LoadLibraryW(uint32_t name) {
    return ntw_imp_LoadLibraryExW(name, 0, 0);
}
uint32_t __attribute__((stdcall)) ntw_imp_LoadLibraryExA(uint32_t name, uint32_t file, uint32_t flags) {
    const char *text = (const char *)(unsigned long)name;
    uint16_t wide[260];
    uint32_t i = 0;
    if (!text) { last_error = 87; return 0; }
    while (text[i] && i < 259) { wide[i] = (unsigned char)text[i]; i++; }
    wide[i] = 0;
    return ntw_imp_LoadLibraryExW((uint32_t)(unsigned long)wide, file, flags);
}
uint32_t __attribute__((stdcall)) ntw_imp_LoadLibraryA(uint32_t name) {
    return ntw_imp_LoadLibraryExA(name, 0, 0);
}
uint32_t __attribute__((stdcall)) ntw_imp_GetModuleHandleW(uint32_t name) {
    const uint16_t *text;
    if (!name) return (uint32_t)(unsigned long)g_image;
    text = (const uint16_t *)(unsigned long)name;
    if (wide_equal(text, "kernel32.dll") || wide_equal(text, "kernel32")) return 0x1000u;
    if (wide_equal(text, "bcryptprimitives.dll")) return 0x1001u;
    if (dep_image && (wide_equal(text, "chrome_elf.dll") || wide_equal(text, "chrome_elf")))
        return (uint32_t)(unsigned long)dep_image;
    if (extra_image && (wide_equal(text, "chrome.dll") || wide_equal(text, "chrome")))
        return (uint32_t)(unsigned long)extra_image;
    if (wide_equal(text, "advapi32.dll") || wide_equal(text, "advapi32")) return 0x1002u;
    if (wide_equal(text, "shell32.dll") || wide_equal(text, "shell32")) return 0x1003u;
    if (wide_equal(text, "user32.dll") || wide_equal(text, "user32")) return 0x1006u;
    if (wide_equal(text, "dbghelp.dll") || wide_equal(text, "dbghelp")) return 0x1004u;
    if (wide_starts(text, "api-ms-win-appmodel-runtime")) return 0x1005u;
    if (wide_starts(text, "api-ms-win-downlevel-shell32")) return 0x1003u;
    if (wide_equal(text, "kernelbase.dll") || wide_equal(text, "kernelbase")) return 0x1000u;
    if (wide_starts(text, "api-ms-win-core-")) return 0x1000u;
    append("modmiss ");
    {
        char shown[96];
        uint32_t n = 0;
        while (text[n] && n + 1 < sizeof shown) {
            shown[n] = (text[n] >= 32 && text[n] < 127) ? (char)text[n] : '?';
            n++;
        }
        shown[n] = 0;
        append(shown);
    }
    append("\n");
    flush_log_now();
    last_error = 126;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_FreeLibrary(uint32_t module) {
    if (module == 0x1000u || module == 0x1001u || module == 0x1002u || module == 0x1003u || module == 0x1004u ||
        module == 0x1005u || module == 0x1006u) return 1;
    if (dep_image && module == (uint32_t)(unsigned long)dep_image) return 1;
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_lstrlenA(uint32_t text) {
    const char *cursor = (const char *)(unsigned long)text;
    uint32_t count = 0;
    if (!text) return 0;
    while (cursor[count]) count++;
    return count;
}
uint32_t __attribute__((stdcall)) ntw_imp_lstrlenW(uint32_t text) {
    const uint16_t *cursor = (const uint16_t *)(unsigned long)text;
    uint32_t count = 0;
    if (!text) return 0;
    while (cursor[count]) count++;
    return count;
}
uint32_t __attribute__((stdcall)) ntw_imp_GetStdHandle(uint32_t kind) {
    uint32_t handle = ntw_file_get_std(kind);
    if (handle == 0xffffffffu) last_error = 6;
    return handle;
}
uint32_t __attribute__((stdcall)) ntw_imp_SetStdHandle(uint32_t kind, uint32_t handle) {
    if (!ntw_file_set_std(kind, handle)) { last_error = 6; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_RtlCaptureStackBackTrace(uint32_t skip, uint32_t count,
                                                                 uint32_t *frames, uint32_t *hash) {
    uint32_t frame_addr, stack, seen = 0, stored = 0, sum = 0;
    if (!frames || !count) return 0;
    __asm__ volatile("mov %%ebp, %0" : "=r"(frame_addr));
    __asm__ volatile("mov %%esp, %0" : "=r"(stack));
    while (stored < count && seen < 48) {
        uint32_t next, retaddr;
        uint32_t *frame;
        if (!frame_addr || frame_addr < stack || frame_addr - stack > 0x200000u || (frame_addr & 3u)) break;
        frame = (uint32_t *)(unsigned long)frame_addr;
        next = frame[0];
        retaddr = frame[1];
        if (seen >= skip) {
            frames[stored++] = retaddr;
            sum += retaddr;
        }
        seen++;
        if (next <= frame_addr) break;
        frame_addr = next;
    }
    if (hash) *hash = sum;
    return stored;
}
uint32_t __attribute__((stdcall)) ntw_imp_IsProcessInJob(uint32_t process, uint32_t job, uint32_t *result) {
    int valid = process == 0xffffffffu || process == 0x2000u || ntw_proc_owns(process);
    return ntw_job_is_process(process, job, result, &last_error, valid);
}
uint32_t __attribute__((stdcall)) ntw_imp_OpenProcess(uint32_t access, uint32_t inherit, uint32_t pid) {
    (void)inherit;
    if (!access) { last_error = 5; return 0; }
    if (pid != ntw_imp_GetCurrentProcessId()) { last_error = 87; return 0; }
    return 0x2000u;
}
uint32_t __attribute__((stdcall)) ntw_imp_CloseHandle(uint32_t handle) {
    uint32_t bits = 0;
    if (extra_flags(handle, 0, 0, 0, &bits) && (bits & 2u) && known_kernel_handle(handle)
        && !ntw_winfile_owns(handle) && !ntw_event_owns(handle)) {
        last_error = 6;
        return 0;
    }
    if (ntw_token_owns(handle)) return ntw_token_close(handle, &last_error) ? 1u : 0u;
    if (ntw_sem_owns(handle)) return ntw_sem_close(handle, &last_error) ? 1u : 0u;
    if (ntw_iocp_owns(handle)) return ntw_iocp_close(handle, &last_error) ? 1u : 0u;
    if (ntw_thread_owns(handle)) return ntw_thread_close(handle, &last_error) ? 1u : 0u;
    if (ntw_proc_owns(handle)) return ntw_proc_close(handle, &last_error) ? 1u : 0u;
    if (ntw_event_owns(handle)) return ntw_event_close(handle, &last_error) ? 1u : 0u;
    if (ntw_winfile_owns(handle)) return ntw_winfile_close(handle, &last_error) ? 1u : 0u;
    if (ntw_filemap_close(handle, &last_error)) return 1;
    if (handle == 0x2000u || handle == 0x1000u) return 1;
    last_error = 6;
    return 0;
}
static int self_process(uint32_t process) {
    return process == 0xffffffffu || process == 0x2000u;
}
uint32_t __attribute__((stdcall)) ntw_imp_DuplicateHandle(uint32_t source_process, uint32_t source, uint32_t target_process,
                                                         uint32_t *out, uint32_t access, uint32_t inherit, uint32_t options) {
    (void)access;
    (void)inherit;
    if (!out || (options & ~3u) || !self_process(source_process) || !self_process(target_process)) {
        last_error = 87;
        return 0;
    }
    if (ntw_filemap_duplicate(source, options & 1u, out, &last_error)) return 1;
    if (source == 0xfffffffeu || ntw_thread_owns(source)) {
        if (!ntw_thread_duplicate(source, out, &last_error)) return 0;
        return 1;
    }
    if (source == 0xffffffffu || source == 0x2000u || source == NTW_STD_INPUT || source == NTW_STD_OUTPUT || source == NTW_STD_ERROR) {
        if (options & 1u) { last_error = 87; return 0; }
        *out = source;
        return 1;
    }
    last_error = 6;
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_K32EnumProcessModules(uint32_t process, uint32_t *modules,
                                                              uint32_t bytes, uint32_t *needed) {
    if (!needed) { last_error = 87; return 0; }
    if (!self_process(process)) { last_error = 5; return 0; }
    *needed = dep_image ? 8u : 4u;
    if (!g_image) { last_error = 6; return 0; }
    if (bytes < 4 || !modules) { last_error = 122; return 0; }
    modules[0] = (uint32_t)(unsigned long)g_image;
    if (dep_image && bytes >= 8) modules[1] = (uint32_t)(unsigned long)dep_image;
    if (dep_image && bytes < 8) { last_error = 122; return 0; }
    return 1;
}
uint32_t __attribute__((stdcall)) ntw_imp_K32GetModuleInformation(uint32_t process, uint32_t module,
                                                                uint32_t *info, uint32_t bytes) {
    if (!self_process(process) || !info || bytes < 12) { last_error = 87; return 0; }
    if (dep_image && module == (uint32_t)(unsigned long)dep_image) {
        info[0] = module;
        info[1] = dep_size;
        info[2] = module + dep_entry;
        return 1;
    }
    if (!g_image || (module && module != (uint32_t)(unsigned long)g_image)) {
        append("modinfo ");
        append_hex(module);
        append("\n");
        flush_log_now();
        last_error = 126;
        return 0;
    }
    info[0] = (uint32_t)(unsigned long)g_image;
    info[1] = image_size;
    info[2] = (uint32_t)(unsigned long)g_image + image_entry;
    return 1;
}
static uint32_t copy_path(uint32_t buffer, uint32_t chars, int wide) {
    uint32_t n = 0;
    if (!buffer || !chars) { last_error = 122; return 0; }
    while (image_path[n] && n + 1 < chars) {
        if (wide) ((uint16_t *)(unsigned long)buffer)[n] = (uint8_t)image_path[n];
        else ((char *)(unsigned long)buffer)[n] = image_path[n];
        n++;
    }
    if (wide) ((uint16_t *)(unsigned long)buffer)[n] = 0;
    else ((char *)(unsigned long)buffer)[n] = 0;
    return n;
}
uint32_t __attribute__((stdcall)) ntw_imp_K32GetModuleFileNameExA(uint32_t process, uint32_t module,
                                                                 uint32_t buffer, uint32_t chars) {
    if (!self_process(process)) { last_error = 5; return 0; }
    if (module && g_image && module != (uint32_t)(unsigned long)g_image) {
        append("modexa ");
        append_hex(module);
        append("\n");
        flush_log_now();
        last_error = 126;
        return 0;
    }
    return copy_path(buffer, chars, 0);
}
uint32_t __attribute__((stdcall)) ntw_imp_K32GetModuleFileNameExW(uint32_t process, uint32_t module,
                                                                 uint32_t buffer, uint32_t chars) {
    if (!self_process(process)) { last_error = 5; return 0; }
    if (module && g_image && module != (uint32_t)(unsigned long)g_image) {
        append("modexw ");
        append_hex(module);
        append("\n");
        flush_log_now();
        last_error = 126;
        return 0;
    }
    return copy_path(buffer, chars, 1);
}
static const char *system_message(uint32_t code) {
    if (code == 2) return "The system cannot find the file specified.";
    if (code == 5) return "Access is denied.";
    if (code == 6) return "The handle is invalid.";
    if (code == 8) return "Not enough memory resources are available to process this command.";
    if (code == 32) return "The process cannot access the file because it is being used by another process.";
    if (code == 87) return "The parameter is incorrect.";
    if (code == 122) return "The data area passed to a system call is too small.";
    if (code == 127) return "The specified procedure could not be found.";
    if (code == 183) return "Cannot create a file when that file already exists.";
    if (code == 1332) return "No mapping between account names and security IDs was done.";
    if (code == 1812) return "The specified image file did not contain a resource section.";
    return 0;
}
uint32_t __attribute__((stdcall)) ntw_imp_FormatMessageW(uint32_t flags, uint32_t source, uint32_t code,
                                                        uint32_t language, uint32_t buffer, uint32_t size,
                                                        uint32_t args) {
    const char *text;
    uint32_t chars, i, out_ptr;
    uint16_t *dest;
    (void)language;
    (void)args;
    if (flags & ~0x3f00u) { last_error = 87; return 0; }
    if (!(flags & 0x200u) && args) { last_error = 87; return 0; }
    if ((flags & 0x1400u) == 0) { last_error = 87; return 0; }
    if (flags & 0x400u) { last_error = 317; return 0; }
    if (!(flags & 0x1000u)) { last_error = 87; return 0; }
    (void)source;
    text = system_message(code);
    if (!text) { last_error = 317; return 0; }
    chars = 0;
    while (text[chars]) chars += 1u;
    if (flags & 0x100u) {
        if (!buffer) { last_error = 87; return 0; }
        out_ptr = ntw_imp_LocalAlloc(0x40u, (chars + 1u) * 2u);
        if (!out_ptr) return 0;
        *(uint32_t *)(unsigned long)buffer = out_ptr;
        dest = (uint16_t *)(unsigned long)out_ptr;
    } else {
        if (!buffer || size < chars + 1u) { last_error = 122; return 0; }
        dest = (uint16_t *)(unsigned long)buffer;
    }
    for (i = 0; i < chars; ++i) dest[i] = (uint16_t)(unsigned char)text[i];
    dest[chars] = 0;
    return chars;
}
static uint32_t known_import(const char *dll, const char *name) {
    if (same_name(dll, "ntdll.dll")) {
        if (same_name(name, "RtlFormatCurrentUserKeyPath"))
            return (uint32_t)(unsigned long)ntw_imp_RtlFormatCurrentUserKeyPath;
        return 0;
    }
    if (!same_name(dll, "kernel32.dll")) return 0;
    if (same_name(name, "GetCurrentProcess")) return (uint32_t)(unsigned long)ntw_imp_GetCurrentProcess;
    if (same_name(name, "IsWow64Process")) return (uint32_t)(unsigned long)ntw_imp_IsWow64Process;
    if (same_name(name, "IsWow64Process2")) return (uint32_t)(unsigned long)ntw_imp_IsWow64Process2;
    if (same_name(name, "InitializeProcThreadAttributeList")) return (uint32_t)(unsigned long)ntw_imp_InitializeProcThreadAttributeList;
    if (same_name(name, "UpdateProcThreadAttribute")) return (uint32_t)(unsigned long)ntw_imp_UpdateProcThreadAttribute;
    if (same_name(name, "DeleteProcThreadAttributeList")) return (uint32_t)(unsigned long)ntw_imp_DeleteProcThreadAttributeList;
    if (same_name(name, "GetProcessTimes")) return (uint32_t)(unsigned long)ntw_imp_GetProcessTimes;
    if (same_name(name, "IsDebuggerPresent")) return (uint32_t)(unsigned long)ntw_imp_IsDebuggerPresent;
    if (same_name(name, "GetSystemInfo")) return (uint32_t)(unsigned long)ntw_imp_GetSystemInfo;
    if (same_name(name, "GetNativeSystemInfo")) return (uint32_t)(unsigned long)ntw_imp_GetNativeSystemInfo;
    if (same_name(name, "InitializeSListHead")) return (uint32_t)(unsigned long)ntw_imp_InitializeSListHead;
    if (same_name(name, "InterlockedFlushSList")) return (uint32_t)(unsigned long)ntw_imp_InterlockedFlushSList;
    if (same_name(name, "GetTickCount")) return (uint32_t)(unsigned long)ntw_imp_GetTickCount;
    if (same_name(name, "Sleep")) return (uint32_t)(unsigned long)ntw_imp_Sleep;
    if (same_name(name, "SleepEx")) return (uint32_t)(unsigned long)ntw_imp_SleepEx;
    if (same_name(name, "GetModuleHandleA")) return (uint32_t)(unsigned long)ntw_imp_GetModuleHandleA;
    if (same_name(name, "GetModuleHandleExW")) return (uint32_t)(unsigned long)ntw_imp_GetModuleHandleExW;
    if (same_name(name, "GetModuleFileNameW")) return (uint32_t)(unsigned long)ntw_imp_GetModuleFileNameW;
    if (same_name(name, "GetCommandLineA")) return (uint32_t)(unsigned long)ntw_imp_GetCommandLineA;
    if (same_name(name, "GetCommandLineW")) return (uint32_t)(unsigned long)ntw_imp_GetCommandLineW;
    if (same_name(name, "GetStartupInfoW")) return (uint32_t)(unsigned long)ntw_imp_GetStartupInfoW;
    if (same_name(name, "GetACP")) return (uint32_t)(unsigned long)ntw_imp_GetACP;
    if (same_name(name, "GetOEMCP")) return (uint32_t)(unsigned long)ntw_imp_GetOEMCP;
    if (same_name(name, "IsValidCodePage")) return (uint32_t)(unsigned long)ntw_imp_IsValidCodePage;
    if (same_name(name, "GetCPInfo")) return (uint32_t)(unsigned long)ntw_imp_GetCPInfo;
    if (same_name(name, "MultiByteToWideChar")) return (uint32_t)(unsigned long)ntw_imp_MultiByteToWideChar;
    if (same_name(name, "WideCharToMultiByte")) return (uint32_t)(unsigned long)ntw_imp_WideCharToMultiByte;
    if (same_name(name, "GetEnvironmentStringsW")) return (uint32_t)(unsigned long)ntw_imp_GetEnvironmentStringsW;
    if (same_name(name, "FreeEnvironmentStringsW")) return (uint32_t)(unsigned long)ntw_imp_FreeEnvironmentStringsW;
    if (same_name(name, "GetEnvironmentVariableW")) return (uint32_t)(unsigned long)ntw_imp_GetEnvironmentVariableW;
    if (same_name(name, "GetProcessId")) return (uint32_t)(unsigned long)ntw_imp_GetProcessId;
    if (same_name(name, "GetThreadId")) return (uint32_t)(unsigned long)ntw_imp_GetThreadId;
    if (same_name(name, "GetVersionExW")) return (uint32_t)(unsigned long)ntw_imp_GetVersionExW;
    if (same_name(name, "GetProductInfo")) return (uint32_t)(unsigned long)ntw_imp_GetProductInfo;
    if (same_name(name, "GetUserDefaultLangID")) return (uint32_t)(unsigned long)ntw_imp_GetUserDefaultLangID;
    if (same_name(name, "GetUserDefaultLocaleName")) return (uint32_t)(unsigned long)ntw_imp_GetUserDefaultLocaleName;
    if (same_name(name, "IsValidLocaleName")) return (uint32_t)(unsigned long)ntw_imp_IsValidLocaleName;
    if (same_name(name, "LocaleNameToLCID")) return (uint32_t)(unsigned long)ntw_imp_LocaleNameToLCID;
    if (same_name(name, "LCIDToLocaleName")) return (uint32_t)(unsigned long)ntw_imp_LCIDToLocaleName;
    if (same_name(name, "LCMapStringEx")) return (uint32_t)(unsigned long)ntw_imp_LCMapStringEx;
    if (same_name(name, "CompareStringEx")) return (uint32_t)(unsigned long)ntw_imp_CompareStringEx;
    if (same_name(name, "GetLocaleInfoEx")) return (uint32_t)(unsigned long)ntw_imp_GetLocaleInfoEx;
    if (same_name(name, "GetDateFormatEx")) return (uint32_t)(unsigned long)ntw_imp_GetDateFormatEx;
    if (same_name(name, "GetTimeFormatEx")) return (uint32_t)(unsigned long)ntw_imp_GetTimeFormatEx;
    if (same_name(name, "EnumSystemLocalesEx")) return (uint32_t)(unsigned long)ntw_imp_EnumSystemLocalesEx;
    if (same_name(name, "GetSystemTimePreciseAsFileTime")) return (uint32_t)(unsigned long)ntw_imp_GetSystemTimePreciseAsFileTime;
    if (same_name(name, "AreFileApisANSI")) return (uint32_t)(unsigned long)ntw_imp_AreFileApisANSI;
    if (same_name(name, "GetSystemDefaultLangID")) return (uint32_t)(unsigned long)ntw_imp_GetSystemDefaultLangID;
    if (same_name(name, "GetUserDefaultLCID")) return (uint32_t)(unsigned long)ntw_imp_GetUserDefaultLCID;
    if (same_name(name, "GetSystemDefaultLCID")) return (uint32_t)(unsigned long)ntw_imp_GetSystemDefaultLCID;
    if (same_name(name, "GetLocalTime")) return (uint32_t)(unsigned long)ntw_imp_GetLocalTime;
    if (same_name(name, "GetSystemTime")) return (uint32_t)(unsigned long)ntw_imp_GetSystemTime;
    if (same_name(name, "VerSetConditionMask")) return (uint32_t)(unsigned long)ntw_imp_VerSetConditionMask;
    if (same_name(name, "VerifyVersionInfoW")) return (uint32_t)(unsigned long)ntw_imp_VerifyVersionInfoW;
    if (same_name(name, "ExitProcess")) return (uint32_t)(unsigned long)ntw_imp_ExitProcess;
    if (same_name(name, "SetUnhandledExceptionFilter")) return (uint32_t)(unsigned long)ntw_imp_SetUnhandledExceptionFilter;
    if (same_name(name, "UnhandledExceptionFilter")) return (uint32_t)(unsigned long)ntw_imp_UnhandledExceptionFilter;
    if (same_name(name, "RaiseException")) return (uint32_t)(unsigned long)ntw_imp_RaiseException;
    if (same_name(name, "RtlUnwind")) return (uint32_t)(unsigned long)ntw_imp_RtlUnwind;
    if (same_name(name, "AddVectoredExceptionHandler")) return (uint32_t)(unsigned long)ntw_imp_AddVectoredExceptionHandler;
    if (same_name(name, "RemoveVectoredExceptionHandler")) return (uint32_t)(unsigned long)ntw_imp_RemoveVectoredExceptionHandler;
    if (same_name(name, "IsThreadAFiber")) return (uint32_t)(unsigned long)ntw_imp_IsThreadAFiber;
    if (same_name(name, "ConvertThreadToFiber")) return (uint32_t)(unsigned long)ntw_imp_ConvertThreadToFiber;
    if (same_name(name, "ConvertThreadToFiberEx")) return (uint32_t)(unsigned long)ntw_imp_ConvertThreadToFiberEx;
    if (same_name(name, "ConvertFiberToThread")) return (uint32_t)(unsigned long)ntw_imp_ConvertFiberToThread;
    if (same_name(name, "CreateFiberEx")) return (uint32_t)(unsigned long)ntw_imp_CreateFiberEx;
    if (same_name(name, "DeleteFiber")) return (uint32_t)(unsigned long)ntw_imp_DeleteFiber;
    if (same_name(name, "SwitchToFiber")) return (uint32_t)(unsigned long)ntw_imp_SwitchToFiber;
    if (same_name(name, "SetCurrentDirectoryW")) return (uint32_t)(unsigned long)ntw_imp_SetCurrentDirectoryW;
    if (same_name(name, "GetCurrentDirectoryW")) return (uint32_t)(unsigned long)ntw_imp_GetCurrentDirectoryW;
    if (same_name(name, "GetTempPathW")) return (uint32_t)(unsigned long)ntw_imp_GetTempPathW;
    if (same_name(name, "GetFullPathNameW")) return (uint32_t)(unsigned long)ntw_imp_GetFullPathNameW;
    if (same_name(name, "CreateFileMappingW")) return (uint32_t)(unsigned long)ntw_imp_CreateFileMappingW;
    if (same_name(name, "CreateFileW")) return (uint32_t)(unsigned long)ntw_imp_CreateFileW;
    if (same_name(name, "CreateDirectoryW")) return (uint32_t)(unsigned long)ntw_imp_CreateDirectoryW;
    if (same_name(name, "CreateNamedPipeW")) return (uint32_t)(unsigned long)ntw_imp_CreateNamedPipeW;
    if (same_name(name, "ConnectNamedPipe")) return (uint32_t)(unsigned long)ntw_imp_ConnectNamedPipe;
    if (same_name(name, "TransactNamedPipe")) return (uint32_t)(unsigned long)ntw_imp_TransactNamedPipe;
    if (same_name(name, "SetProcessShutdownParameters")) return (uint32_t)(unsigned long)ntw_imp_SetProcessShutdownParameters;
    if (same_name(name, "GetProcessShutdownParameters")) return (uint32_t)(unsigned long)ntw_imp_GetProcessShutdownParameters;
    if (same_name(name, "GetFileAttributesW")) return (uint32_t)(unsigned long)ntw_imp_GetFileAttributesW;
    if (same_name(name, "GetFileInformationByHandleEx")) return (uint32_t)(unsigned long)ntw_imp_GetFileInformationByHandleEx;
    if (same_name(name, "LockFileEx")) return (uint32_t)(unsigned long)ntw_imp_LockFileEx;
    if (same_name(name, "GetLongPathNameW")) return (uint32_t)(unsigned long)ntw_imp_GetLongPathNameW;
    if (same_name(name, "SetEndOfFile")) return (uint32_t)(unsigned long)ntw_imp_SetEndOfFile;
    if (same_name(name, "UnlockFileEx")) return (uint32_t)(unsigned long)ntw_imp_UnlockFileEx;
    if (same_name(name, "DeleteFileW")) return (uint32_t)(unsigned long)ntw_imp_DeleteFileW;
    if (same_name(name, "SetNamedPipeHandleState")) return (uint32_t)(unsigned long)ntw_imp_SetNamedPipeHandleState;
    if (same_name(name, "CreateEventW")) return (uint32_t)(unsigned long)ntw_imp_CreateEventW;
    if (same_name(name, "SetEvent")) return (uint32_t)(unsigned long)ntw_imp_SetEvent;
    if (same_name(name, "ResetEvent")) return (uint32_t)(unsigned long)ntw_imp_ResetEvent;
    if (same_name(name, "WaitForSingleObject")) return (uint32_t)(unsigned long)ntw_imp_WaitForSingleObject;
    if (same_name(name, "CreateThread")) return (uint32_t)(unsigned long)ntw_imp_CreateThread;
    if (same_name(name, "ExitThread")) return (uint32_t)(unsigned long)ntw_imp_ExitThread;
    if (same_name(name, "GetExitCodeThread")) return (uint32_t)(unsigned long)ntw_imp_GetExitCodeThread;
    if (same_name(name, "GetHandleInformation")) return (uint32_t)(unsigned long)ntw_imp_GetHandleInformation;
    if (same_name(name, "SetHandleInformation")) return (uint32_t)(unsigned long)ntw_imp_SetHandleInformation;
    if (same_name(name, "SetThreadDescription")) return (uint32_t)(unsigned long)ntw_imp_SetThreadDescription;
    if (same_name(name, "SetConsoleCtrlHandler")) return (uint32_t)(unsigned long)ntw_imp_SetConsoleCtrlHandler;
    if (same_name(name, "OutputDebugStringA")) return (uint32_t)(unsigned long)ntw_imp_OutputDebugStringA;
    if (same_name(name, "OutputDebugStringW")) return (uint32_t)(unsigned long)ntw_imp_OutputDebugStringW;
    if (same_name(name, "ResumeThread")) return (uint32_t)(unsigned long)ntw_imp_ResumeThread;
    if (same_name(name, "SetProcessDEPPolicy")) return (uint32_t)(unsigned long)ntw_imp_SetProcessDEPPolicy;
    if (same_name(name, "FindFirstFileExW")) return (uint32_t)(unsigned long)ntw_imp_FindFirstFileExW;
    if (same_name(name, "FindNextFileW")) return (uint32_t)(unsigned long)ntw_imp_FindNextFileW;
    if (same_name(name, "FindClose")) return (uint32_t)(unsigned long)ntw_imp_FindClose;
    if (same_name(name, "GetFileTime")) return (uint32_t)(unsigned long)ntw_imp_GetFileTime;
    if (same_name(name, "CreateSemaphoreW")) return (uint32_t)(unsigned long)ntw_imp_CreateSemaphoreW;
    if (same_name(name, "CreateSemaphoreA")) return (uint32_t)(unsigned long)ntw_imp_CreateSemaphoreA;
    if (same_name(name, "ReleaseSemaphore")) return (uint32_t)(unsigned long)ntw_imp_ReleaseSemaphore;
    if (same_name(name, "CreateIoCompletionPort")) return (uint32_t)(unsigned long)ntw_imp_CreateIoCompletionPort;
    if (same_name(name, "GetQueuedCompletionStatus")) return (uint32_t)(unsigned long)ntw_imp_GetQueuedCompletionStatus;
    if (same_name(name, "PostQueuedCompletionStatus")) return (uint32_t)(unsigned long)ntw_imp_PostQueuedCompletionStatus;
    if (same_name(name, "InitOnceExecuteOnce")) return (uint32_t)(unsigned long)ntw_imp_InitOnceExecuteOnce;
    if (same_name(name, "lstrcmpiA")) return (uint32_t)(unsigned long)ntw_imp_lstrcmpiA;
    if (same_name(name, "K32GetProcessMemoryInfo")) return (uint32_t)(unsigned long)ntw_imp_K32GetProcessMemoryInfo;
    if (same_name(name, "K32GetPerformanceInfo")) return (uint32_t)(unsigned long)ntw_imp_K32GetPerformanceInfo;
    if (same_name(name, "CreateProcessW")) return (uint32_t)(unsigned long)ntw_imp_CreateProcessW;
    if (same_name(name, "GetExitCodeProcess")) return (uint32_t)(unsigned long)ntw_imp_GetExitCodeProcess;
    if (same_name(name, "TerminateProcess")) return (uint32_t)(unsigned long)ntw_imp_TerminateProcess;
    if (same_name(name, "SetFilePointerEx")) return (uint32_t)(unsigned long)ntw_imp_SetFilePointerEx;
    if (same_name(name, "GetFileSizeEx")) return (uint32_t)(unsigned long)ntw_imp_GetFileSizeEx;
    if (same_name(name, "MapViewOfFile")) return (uint32_t)(unsigned long)ntw_imp_MapViewOfFile;
    if (same_name(name, "UnmapViewOfFile")) return (uint32_t)(unsigned long)ntw_imp_UnmapViewOfFile;
    if (same_name(name, "VirtualQuery")) return (uint32_t)(unsigned long)ntw_imp_VirtualQuery;
    if (same_name(name, "DuplicateHandle")) return (uint32_t)(unsigned long)ntw_imp_DuplicateHandle;
    if (same_name(name, "GetCurrentThread")) return (uint32_t)(unsigned long)ntw_imp_GetCurrentThread;
    if (same_name(name, "GetCurrentThreadStackLimits")) return (uint32_t)(unsigned long)ntw_imp_GetCurrentThreadStackLimits;
    if (same_name(name, "GetLastError")) return (uint32_t)(unsigned long)ntw_imp_GetLastError;
    if (same_name(name, "SetLastError")) return (uint32_t)(unsigned long)ntw_imp_SetLastError;
    if (same_name(name, "FormatMessageW")) return (uint32_t)(unsigned long)ntw_imp_FormatMessageW;
    if (same_name(name, "EncodePointer")) return (uint32_t)(unsigned long)ntw_imp_EncodePointer;
    if (same_name(name, "DecodePointer")) return (uint32_t)(unsigned long)ntw_imp_DecodePointer;
    if (same_name(name, "GetSystemTimeAsFileTime")) return (uint32_t)(unsigned long)ntw_imp_GetSystemTimeAsFileTime;
    if (same_name(name, "GetCurrentProcessId")) return (uint32_t)(unsigned long)ntw_imp_GetCurrentProcessId;
    if (same_name(name, "GetCurrentThreadId")) return (uint32_t)(unsigned long)ntw_imp_GetCurrentThreadId;
    if (same_name(name, "QueryPerformanceCounter")) return (uint32_t)(unsigned long)ntw_imp_QueryPerformanceCounter;
    if (same_name(name, "QueryPerformanceFrequency")) return (uint32_t)(unsigned long)ntw_imp_QueryPerformanceFrequency;
    if (same_name(name, "IsProcessorFeaturePresent")) return (uint32_t)(unsigned long)ntw_imp_IsProcessorFeaturePresent;
    if (same_name(name, "TryAcquireSRWLockExclusive")) return (uint32_t)(unsigned long)ntw_imp_TryAcquireSRWLockExclusive;
    if (same_name(name, "TryAcquireSRWLockShared")) return (uint32_t)(unsigned long)ntw_imp_TryAcquireSRWLockShared;
    if (same_name(name, "AcquireSRWLockExclusive")) return (uint32_t)(unsigned long)ntw_imp_AcquireSRWLockExclusive;
    if (same_name(name, "AcquireSRWLockShared")) return (uint32_t)(unsigned long)ntw_imp_AcquireSRWLockShared;
    if (same_name(name, "ReleaseSRWLockExclusive")) return (uint32_t)(unsigned long)ntw_imp_ReleaseSRWLockExclusive;
    if (same_name(name, "ReleaseSRWLockShared")) return (uint32_t)(unsigned long)ntw_imp_ReleaseSRWLockShared;
    if (same_name(name, "InitializeSRWLock")) return (uint32_t)(unsigned long)ntw_imp_InitializeSRWLock;
    if (same_name(name, "InitializeConditionVariable")) return (uint32_t)(unsigned long)ntw_imp_InitializeConditionVariable;
    if (same_name(name, "WakeConditionVariable")) return (uint32_t)(unsigned long)ntw_imp_WakeConditionVariable;
    if (same_name(name, "WakeAllConditionVariable")) return (uint32_t)(unsigned long)ntw_imp_WakeAllConditionVariable;
    if (same_name(name, "SleepConditionVariableSRW")) return (uint32_t)(unsigned long)ntw_imp_SleepConditionVariableSRW;
    if (same_name(name, "InitializeCriticalSectionEx")) return (uint32_t)(unsigned long)ntw_imp_InitializeCriticalSectionEx;
    if (same_name(name, "InitializeCriticalSection")) return (uint32_t)(unsigned long)ntw_imp_InitializeCriticalSection;
    if (same_name(name, "EnterCriticalSection")) return (uint32_t)(unsigned long)ntw_imp_EnterCriticalSection;
    if (same_name(name, "LeaveCriticalSection")) return (uint32_t)(unsigned long)ntw_imp_LeaveCriticalSection;
    if (same_name(name, "TryEnterCriticalSection")) return (uint32_t)(unsigned long)ntw_imp_TryEnterCriticalSection;
    if (same_name(name, "DeleteCriticalSection")) return (uint32_t)(unsigned long)ntw_imp_DeleteCriticalSection;
    if (same_name(name, "FlsAlloc")) return (uint32_t)(unsigned long)ntw_imp_FlsAlloc;
    if (same_name(name, "FlsFree")) return (uint32_t)(unsigned long)ntw_imp_FlsFree;
    if (same_name(name, "FlsGetValue")) return (uint32_t)(unsigned long)ntw_imp_FlsGetValue;
    if (same_name(name, "FlsGetValue2")) return (uint32_t)(unsigned long)ntw_imp_FlsGetValue;
    if (same_name(name, "FlsSetValue")) return (uint32_t)(unsigned long)ntw_imp_FlsSetValue;
    if (same_name(name, "TlsAlloc")) return (uint32_t)(unsigned long)ntw_imp_TlsAlloc;
    if (same_name(name, "TlsFree")) return (uint32_t)(unsigned long)ntw_imp_TlsFree;
    if (same_name(name, "TlsGetValue")) return (uint32_t)(unsigned long)ntw_imp_TlsGetValue;
    if (same_name(name, "TlsSetValue")) return (uint32_t)(unsigned long)ntw_imp_TlsSetValue;
    if (same_name(name, "VirtualProtect")) return (uint32_t)(unsigned long)ntw_imp_VirtualProtect;
    if (same_name(name, "VirtualAlloc")) return (uint32_t)(unsigned long)ntw_imp_VirtualAlloc;
    if (same_name(name, "VirtualFree")) return (uint32_t)(unsigned long)ntw_imp_VirtualFree;
    if (same_name(name, "GetProcessHeap")) return (uint32_t)(unsigned long)ntw_imp_GetProcessHeap;
    if (same_name(name, "HeapSetInformation")) return (uint32_t)(unsigned long)ntw_imp_HeapSetInformation;
    if (same_name(name, "HeapQueryInformation")) return (uint32_t)(unsigned long)ntw_imp_HeapQueryInformation;
    if (same_name(name, "HeapAlloc")) return (uint32_t)(unsigned long)ntw_imp_HeapAlloc;
    if (same_name(name, "HeapFree")) return (uint32_t)(unsigned long)ntw_imp_HeapFree;
    if (same_name(name, "HeapSize")) return (uint32_t)(unsigned long)ntw_imp_HeapSize;
    if (same_name(name, "LocalAlloc")) return (uint32_t)(unsigned long)ntw_imp_LocalAlloc;
    if (same_name(name, "LocalFree")) return (uint32_t)(unsigned long)ntw_imp_LocalFree;
    if (same_name(name, "LoadLibraryExW")) return (uint32_t)(unsigned long)ntw_imp_LoadLibraryExW;
    if (same_name(name, "LoadLibraryW")) return (uint32_t)(unsigned long)ntw_imp_LoadLibraryW;
    if (same_name(name, "LoadLibraryA")) return (uint32_t)(unsigned long)ntw_imp_LoadLibraryA;
    if (same_name(name, "LoadLibraryExA")) return (uint32_t)(unsigned long)ntw_imp_LoadLibraryExA;
    if (same_name(name, "GetModuleHandleW")) return (uint32_t)(unsigned long)ntw_imp_GetModuleHandleW;
    if (same_name(name, "GetProcAddress")) return (uint32_t)(unsigned long)ntw_imp_GetProcAddress;
    if (same_name(name, "FreeLibrary")) return (uint32_t)(unsigned long)ntw_imp_FreeLibrary;
    if (same_name(name, "lstrlenA")) return (uint32_t)(unsigned long)ntw_imp_lstrlenA;
    if (same_name(name, "lstrlenW")) return (uint32_t)(unsigned long)ntw_imp_lstrlenW;
    if (same_name(name, "GetStdHandle")) return (uint32_t)(unsigned long)ntw_imp_GetStdHandle;
    if (same_name(name, "SetStdHandle")) return (uint32_t)(unsigned long)ntw_imp_SetStdHandle;
    if (same_name(name, "WriteFile")) return (uint32_t)(unsigned long)ntw_imp_WriteFile;
    if (same_name(name, "ReadFile")) return (uint32_t)(unsigned long)ntw_imp_ReadFile;
    if (same_name(name, "GetFileType")) return (uint32_t)(unsigned long)ntw_imp_GetFileType;
    if (same_name(name, "RtlCaptureStackBackTrace")) return (uint32_t)(unsigned long)ntw_imp_RtlCaptureStackBackTrace;
    if (same_name(name, "OpenProcess")) return (uint32_t)(unsigned long)ntw_imp_OpenProcess;
    if (same_name(name, "IsProcessInJob")) return (uint32_t)(unsigned long)ntw_imp_IsProcessInJob;
    if (same_name(name, "CloseHandle")) return (uint32_t)(unsigned long)ntw_imp_CloseHandle;
    if (same_name(name, "K32EnumProcessModules")) return (uint32_t)(unsigned long)ntw_imp_K32EnumProcessModules;
    if (same_name(name, "K32GetModuleInformation")) return (uint32_t)(unsigned long)ntw_imp_K32GetModuleInformation;
    if (same_name(name, "K32GetModuleFileNameExA")) return (uint32_t)(unsigned long)ntw_imp_K32GetModuleFileNameExA;
    if (same_name(name, "K32GetModuleFileNameExW")) return (uint32_t)(unsigned long)ntw_imp_K32GetModuleFileNameExW;
    return 0;
}
static int bind_imports(const uint8_t *file, uint32_t file_len, uint8_t *image, uint8_t **stubs) {
    uint32_t pe, opt, dir, size, desc, bound = 0, unresolved = 0;
    if (file_len < 0x40) return NTW_MAP_INVALID;
    pe = rd32(file + 0x3c);
    opt = pe + 24;
    if (opt + 104 > file_len) return NTW_MAP_INVALID;
    dir = rd32(file + opt + 96 + 8);
    size = rd32(file + opt + 96 + 12);
    if (!dir || !size) return NTW_MAP_OK;
    {
        uint32_t image_limit = rd32(file + opt + 56);
        if (image_limit < 0x1000u) return NTW_MAP_INVALID;
    for (desc = 0; desc < 4096; ++desc) {
        uint32_t off, oft, name_rva, iat, slot;
        const char *dll;
        if (ntw_rva_span(file, file_len, dir + desc * 20, 20, &off) != NTW_MAP_OK) return NTW_MAP_INVALID;
        oft = rd32(file + off);
        name_rva = rd32(file + off + 12);
        iat = rd32(file + off + 16);
        if (!oft && !name_rva && !iat) break;
        if (!name_rva || !iat) return NTW_MAP_INVALID;
        if (!oft) oft = iat;
        if (ntw_rva_span(file, file_len, name_rva, 1, &off) != NTW_MAP_OK) return NTW_MAP_INVALID;
        dll = (const char *)(file + off);
        for (slot = 0; slot < 65536; ++slot) {
            uint32_t thunk, iat_off, value, fn;
            const char *symbol;
            if (ntw_rva_span(file, file_len, oft + slot * 4, 4, &off) != NTW_MAP_OK) return NTW_MAP_INVALID;
            thunk = rd32(file + off);
            if (!thunk) break;
            if (iat + slot * 4 + 4 > image_limit) return NTW_MAP_LIMIT;
            iat_off = iat + slot * 4;
            if (thunk & 0x80000000u) symbol = "ordinal";
            else {
                if (ntw_rva_span(file, file_len, (thunk & 0x7fffffffu) + 2, 1, &off) != NTW_MAP_OK)
                    return NTW_MAP_INVALID;
                symbol = (const char *)(file + off);
            }
            fn = known_import(dll, symbol);
            if (!fn && dep_image && same_name(dll, "chrome_elf.dll")) fn = dep_export(symbol);
            if (!fn && same_name(dll, "version.dll")) {
                if (same_name(symbol, "GetFileVersionInfoSizeW")) fn = (uint32_t)(unsigned long)ntw_imp_GetFileVersionInfoSizeW;
                else if (same_name(symbol, "GetFileVersionInfoW")) fn = (uint32_t)(unsigned long)ntw_imp_GetFileVersionInfoW;
                else if (same_name(symbol, "VerQueryValueW")) fn = (uint32_t)(unsigned long)ntw_imp_VerQueryValueW;
            }
            if (!fn) {
                fn = make_fault_stub(*stubs, symbol);
                *stubs += 16;
                ++unresolved;
            } else ++bound;
            wr32(image + iat_off, fn);
            (void)value;
        }
    }
    append("imports bound "); append_hex(bound); append(" unresolved "); append_hex(unresolved); append("\n");
    return NTW_MAP_OK;
    }
}
static uint32_t map_sibling_dll(const uint16_t *name) {
    char path[260], leaf[96];
    uint32_t n = 0, slash = 0, i, leaf_n = 0, start = 0, dir = 0, bytes;
    int fd, size, status;
    uint8_t *file, *mapped, *cursor;
    ntw_placed placed;
    uint32_t image_limit, pe, opt;
    typedef uint32_t (__attribute__((stdcall)) *dllmain_fn)(uint32_t, uint32_t, uint32_t);
    if (!name || !name[0]) return 0;
    while (name[n]) {
        if (name[n] == '\\' || name[n] == '/') slash = n + 1;
        n++;
    }
    while (name[slash + leaf_n] && leaf_n + 1 < sizeof leaf) {
        uint16_t ch = name[slash + leaf_n];
        if (ch > 127) return 0;
        leaf[leaf_n] = (char)ch;
        leaf_n++;
    }
    leaf[leaf_n] = 0;
    if (!same_name(leaf, "chrome.dll")) return 0;
    if (extra_image) return (uint32_t)(unsigned long)extra_image;
    while (image_path[start] && start < 240) {
        if (image_path[start] == '/') dir = start + 1;
        start++;
    }
    if (dir + leaf_n + 1 > sizeof path) return 0;
    for (i = 0; i < dir; ++i) path[i] = image_path[i];
    for (i = 0; i < leaf_n; ++i) path[dir + i] = leaf[i];
    path[dir + leaf_n] = 0;
    fd = ntw_open(path, O_RDONLY, 0);
    if (fd < 0) return 0;
    size = ntw_lseek(fd, 0, 2);
    if (size < 64 || size > 400 * 1024 * 1024) { ntw_close(fd); return 0; }
    ntw_lseek(fd, 0, 0);
    file = ntw_mmap2(0, (unsigned)size, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)file > 0xfffff000u) { ntw_close(fd); return 0; }
    bytes = 0;
    while ((int)bytes < size) {
        int got = ntw_read(fd, file + bytes, (unsigned)size - bytes);
        if (got <= 0) { ntw_close(fd); return 0; }
        bytes += (uint32_t)got;
    }
    ntw_close(fd);
    pe = rd32(file + 0x3c);
    if (pe + 96 > (uint32_t)size) return 0;
    opt = pe + 24;
    image_limit = rd32(file + opt + 56);
    if (image_limit < 0x1000u || image_limit > 400u * 1024u * 1024u) return 0;
    {
        uint32_t preferred = rd32(file + opt + 28);
        mapped = ntw_mmap2((void *)(unsigned long)preferred, image_limit + 1024u * 1024u, PROT_RWX,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if ((uint32_t)(unsigned long)mapped != preferred)
            mapped = ntw_mmap2(0, image_limit + 1024u * 1024u, PROT_RWX, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if ((unsigned)mapped > 0xfffff000u) return 0;
    status = ntw_place_pe32(file, (unsigned)size, mapped, image_limit, (unsigned)mapped, &placed);
    append("dll place ");
    append_hex((unsigned)status);
    append("\n");
    flush_log_now();
    if (status != NTW_MAP_OK) return 0;
    if ((uint32_t)(unsigned long)mapped != rd32(file + opt + 28)) {
        uint32_t base = (uint32_t)(unsigned long)mapped;
        mapped[opt + 28] = (uint8_t)base;
        mapped[opt + 29] = (uint8_t)(base >> 8);
        mapped[opt + 30] = (uint8_t)(base >> 16);
        mapped[opt + 31] = (uint8_t)(base >> 24);
    }
    cursor = mapped + placed.size_of_image;
    status = bind_imports(file, (unsigned)size, mapped, &cursor);
    append("dll bind ");
    append_hex((unsigned)status);
    append("\n");
    flush_log_now();
    if (status != NTW_MAP_OK) return 0;
    extra_image = mapped;
    extra_size = placed.size_of_image;
    for (i = 0; path[i] && i + 1 < sizeof extra_path; ++i) extra_path[i] = path[i];
    extra_path[i] = 0;
    append("dll image ");
    append_hex((unsigned)mapped);
    append(" entry ");
    append_hex(placed.entry_rva);
    append(" tls ");
    append_hex(placed.tls.callback_count);
    append("\n");
    flush_log_now();
    if (live_tls_process && placed.tls.present && placed.tls.callback_count < 32u) {
        uint32_t index = 0;
        int tls_status = register_one(mapped, &placed, live_tls_process, &index);
        if (tls_status == NTWTLS_BUSY) {
            ntwtls_image info;
            ntwtls_callback callbacks[32];
            uint32_t n;
            for (n = 0; n < placed.tls.callback_count; ++n)
                callbacks[n] = (ntwtls_callback)(void *)(mapped + (placed.tls.callback_vas[n] - placed.actual_base));
            callbacks[placed.tls.callback_count] = 0;
            info.module = mapped;
            info.raw = placed.tls.raw;
            info.raw_bytes = placed.tls.raw_bytes;
            info.zero_fill = placed.tls.zero_fill;
            info.index_slot = placed.tls.index_slot;
            info.callbacks = callbacks;
            info.characteristics = placed.tls.characteristics;
            tls_status = ntwtls_register_late(live_tls_process, &info, &index);
            if (tls_status == NTWTLS_OK && live_tls_thread)
                tls_status = ntwtls_thread_extend(live_tls_process, live_tls_thread);
            if (tls_status == NTWTLS_OK) {
                void *slot = ntwtls_slot(live_tls_thread, index);
                if (slot) install_tls_fs((uint32_t)(unsigned long)slot, index);
            }
        }
        append("dll tls ");
        append_hex((unsigned)tls_status);
        append("\n");
        flush_log_now();
        if (tls_status == NTWTLS_OK) call_tls(mapped, &placed);
    }
    if (placed.entry_rva && placed.entry_rva < placed.size_of_image) {
        install_fastfail_log();
        append("calling dll\n");
        flush_log_now();
        dllmain_fn entry = (dllmain_fn)(void *)(mapped + placed.entry_rva);
        uint32_t ok = entry((uint32_t)(unsigned long)mapped, 1, 0);
        append("dllmain ");
        append_hex(ok);
        append("\n");
        flush_log_now();
        if (!ok) { last_error = 1114; return 0; }
    }
    return (uint32_t)(unsigned long)mapped;
}
static int imports_dll(const uint8_t *file, uint32_t file_len, const char *want) {
    uint32_t pe, opt, dir, desc;
    if (file_len < 0x80) return 0;
    pe = rd32(file + 0x3c);
    opt = pe + 24;
    if (opt + 104 > file_len) return 0;
    dir = rd32(file + opt + 96 + 8);
    if (!dir) return 0;
    for (desc = 0; desc < 64; ++desc) {
        uint32_t off, name_rva;
        if (ntw_rva_span(file, file_len, dir + desc * 20, 20, &off) != NTW_MAP_OK) return 0;
        name_rva = rd32(file + off + 12);
        if (!rd32(file + off) && !name_rva && !rd32(file + off + 16)) break;
        if (!name_rva || ntw_rva_span(file, file_len, name_rva, 1, &off) != NTW_MAP_OK) return 0;
        if (same_name((const char *)(file + off), want)) return 1;
    }
    return 0;
}
static int map_dependency(void) {
    char path[260];
    const char *dll = "chrome_elf.dll";
    uint32_t n = 0, slash = 0, i, len = 0;
    int fd, bytes, status;
    uint8_t *file, *mapped, *cursor;
    while (image_path[n]) {
        if (image_path[n] == '/') slash = n + 1;
        n++;
    }
    while (dll[len]) len++;
    if (slash + len + 1 > sizeof path) return -1;
    for (i = 0; i < slash; ++i) path[i] = image_path[i];
    for (i = 0; i < len; ++i) path[slash + i] = dll[i];
    path[slash + len] = 0;
    fd = ntw_open(path, O_RDONLY, 0);
    if (fd < 0) return -1;
    bytes = ntw_lseek(fd, 0, 2);
    if (bytes < 64 || bytes > 8 * 1024 * 1024) { ntw_close(fd); return -1; }
    ntw_lseek(fd, 0, 0);
    file = ntw_mmap2(0, (unsigned)bytes, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mapped = ntw_mmap2(0, 8 * 1024 * 1024, PROT_RWX, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)file > 0xfffff000u || (unsigned)mapped > 0xfffff000u) { ntw_close(fd); return -1; }
    if (ntw_read(fd, file, (unsigned)bytes) != bytes) { ntw_close(fd); return -1; }
    ntw_close(fd);
    status = ntw_place_pe32(file, (unsigned)bytes, mapped, 8 * 1024 * 1024, (unsigned)mapped, &dep_placed);
    append("dep place "); append_hex((unsigned)status); append("\n");
    if (status != NTW_MAP_OK) return status;
    dep_image = mapped;
    dep_size = dep_placed.size_of_image;
    dep_entry = dep_placed.entry_rva;
    for (i = 0; i < slash + len && i + 1 < sizeof dep_path; ++i) dep_path[i] = path[i];
    dep_path[i] = 0;
    cursor = mapped + dep_placed.size_of_image;
    status = bind_imports(file, (unsigned)bytes, mapped, &cursor);
    append("dep image "); append_hex((unsigned)mapped); append("\n");
    return status;
}
static int register_one(uint8_t *image, const ntw_placed *placed, ntwtls_process *process, uint32_t *index) {
    ntwtls_callback callbacks[32];
    ntwtls_image info;
    uint32_t n;
    if (!placed->tls.present || placed->tls.callback_count >= 32u) return NTWTLS_INVALID;
    for (n = 0; n < placed->tls.callback_count; ++n) {
        uint32_t va = placed->tls.callback_vas[n];
        if (va < placed->actual_base || va - placed->actual_base >= placed->size_of_image) return NTWTLS_INVALID;
        callbacks[n] = (ntwtls_callback)(void *)(image + (va - placed->actual_base));
    }
    callbacks[n] = 0;
    info.module = image;
    info.raw = placed->tls.raw;
    info.raw_bytes = placed->tls.raw_bytes;
    info.zero_fill = placed->tls.zero_fill;
    info.index_slot = placed->tls.index_slot;
    info.callbacks = placed->tls.callback_count ? callbacks : 0;
    info.characteristics = placed->tls.characteristics;
    return ntwtls_register(process, &info, index);
}
static void call_tls(uint8_t *image, const ntw_placed *placed) {
    uint32_t n;
    for (n = 0; n < placed->tls.callback_count; ++n) {
        uint32_t va = placed->tls.callback_vas[n];
        ntwtls_callback callback;
        if (va < placed->actual_base || va - placed->actual_base >= placed->size_of_image) continue;
        callback = (ntwtls_callback)(void *)(image + (va - placed->actual_base));
        callback(image, NTWTLS_PROCESS_ATTACH, 0);
    }
}
static void *loader_map_place(void *user, void *addr, uint32_t length, int prot, int flags) {
    void *memory;
    (void)user;
    memory = ntw_mmap2(addr, length, prot, flags, -1, 0);
    if ((unsigned)memory > 0xfffff000u) return 0;
    return memory;
}
static int loader_map_remove(void *user, void *addr, uint32_t length) {
    (void)user;
    return ntw_munmap(addr, length);
}
static int loader_map_protect(void *user, void *addr, uint32_t length, int prot) {
    (void)user;
    return ntw_mprotect(addr, length, prot);
}
uint32_t __attribute__((stdcall)) ntw_imp_CreateFileMappingW(uint32_t file, uint32_t security, uint32_t protect,
                                                            uint32_t size_high, uint32_t size_low, uint32_t name) {
    (void)security;
    return ntw_filemap_create(file, protect, size_high, size_low, (const uint16_t *)(unsigned long)name, &last_error);
}
uint32_t __attribute__((stdcall)) ntw_imp_MapViewOfFile(uint32_t mapping, uint32_t access, uint32_t offset_high,
                                                       uint32_t offset_low, uint32_t bytes) {
    return (uint32_t)ntw_filemap_view(mapping, access, offset_high, offset_low, bytes, &last_error);
}
uint32_t __attribute__((stdcall)) ntw_imp_UnmapViewOfFile(uint32_t address) {
    return ntw_filemap_unmap(address, &last_error);
}
uint32_t __attribute__((stdcall)) ntw_imp_VirtualQuery(uint32_t address, uint32_t *info, uint32_t length) {
    uint32_t i, base = address & ~4095u, allocation = 0, allocation_protect = 1, region = 65536, state = 0x10000u, protect = 1;
    if (!info || length < 28u) { last_error = 87; return 0; }
    if (ntw_filemap_query(address, &base, &allocation, &allocation_protect, &region, &state, &protect)) {
    } else if (g_image && address >= (uint32_t)(unsigned long)g_image &&
               address - (uint32_t)(unsigned long)g_image < image_size) {
        allocation = (uint32_t)(unsigned long)g_image;
        allocation_protect = 0x40u;
        region = image_size - (base - allocation);
        state = 0x1000u;
        protect = 0x40u;
    } else if (dep_image && address >= (uint32_t)(unsigned long)dep_image &&
               address - (uint32_t)(unsigned long)dep_image < dep_size) {
        allocation = (uint32_t)(unsigned long)dep_image;
        allocation_protect = 0x40u;
        region = dep_size - (base - allocation);
        state = 0x1000u;
        protect = 0x40u;
    } else if (process_heap && address >= (uint32_t)(unsigned long)process_heap &&
               address - (uint32_t)(unsigned long)process_heap < 8u * 1024u * 1024u) {
        allocation = (uint32_t)(unsigned long)process_heap;
        allocation_protect = 0x04u;
        region = 8u * 1024u * 1024u - (base - allocation);
        state = 0x1000u;
        protect = 0x04u;
    }
    for (i = 0; i < 7; ++i) info[i] = 0;
    info[0] = base;
    info[1] = allocation;
    info[2] = allocation_protect;
    info[3] = region;
    info[4] = state;
    info[5] = protect;
    info[6] = state == 0x10000u ? 0u : 0x20000u;
    return 28;
}
static void load_child_files(void) {
    char buf[1024];
    int fd, n, i;
    fd = ntw_open("child-cmdline.txt", O_RDONLY, 0);
    if (fd >= 0) {
        n = ntw_read(fd, buf, sizeof buf - 1);
        ntw_close(fd);
        if (n > 0) {
            buf[n] = 0;
            for (i = 0; buf[i] && i + 1 < 1024; ++i) command_line_w[i] = (unsigned char)buf[i];
            command_line_w[i] = 0;
            command_line_ready = 1;
        }
    }
    fd = ntw_open("child-inherit.txt", O_RDONLY, 0);
    if (fd < 0) return;
    n = ntw_read(fd, buf, sizeof buf - 1);
    ntw_close(fd);
    if (n <= 0) return;
    buf[n] = 0;
    i = 0;
    while (buf[i]) {
        uint32_t handle = 0, fdn = 0;
        int k;
        for (k = 0; k < 8 && buf[i]; ++k, ++i) {
            char c = buf[i];
            uint32_t nib = (c >= 'a' && c <= 'f') ? (uint32_t)(c - 'a' + 10) : (uint32_t)(c - '0');
            handle = (handle << 4) | nib;
        }
        if (buf[i] == ' ') i++;
        while (buf[i] >= '0' && buf[i] <= '9') { fdn = fdn * 10u + (uint32_t)(buf[i] - '0'); i++; }
        if (buf[i] == '\n') i++;
        if (handle) ntw_winfile_adopt_listen(handle, (int)fdn);
    }
}
int ntw_loader_main(int argc, char **argv) {
    int fd = -1, size = 0, out, status = 1, i, is_dll = 0;
    const char entered[] = "entered\n";
    unsigned char *file = 0, *image = 0, *arena = 0, *cursor;
    ntw_placed placed;
    ntwtls_process *process;
    ntwtls_thread *thread;
    ntwtls_services services;
    void *slot = 0;
    for (i = 0; i < (int)sizeof placed; ++i) ((unsigned char *)&placed)[i] = 0;
    ntw_user_bind(&last_error);
    ntw_user_set_log(user_log);
    ntw_write(1, entered, sizeof entered - 1);
    install_fastfail_log();
    ntw_file_set_transfer(loader_transfer, 0);
    ntw_thread_set_spawn(loader_thread_spawn, loader_thread_enter, 0, loader_thread_pause, loader_thread_tid, 0);
    ntw_iocp_set_pause(loader_thread_pause);
    ntw_init_set_pause(loader_thread_pause);
    {
        ntw_disk_ops disk_ops;
        disk_ops.user = 0;
        disk_ops.open = disk_open;
        disk_ops.close = disk_close;
        disk_ops.read = disk_read;
        disk_ops.write = disk_write;
        disk_ops.seek = disk_seek;
        disk_ops.exists = disk_exists;
        disk_ops.unlink = disk_unlink;
        disk_ops.mkdir = disk_mkdir;
        disk_ops.pipe_bind = disk_pipe_bind;
        disk_ops.pipe_connect = disk_pipe_connect;
        disk_ops.pipe_accept = disk_pipe_accept;
        ntw_winfile_set_ops(&disk_ops);
        ntw_winfile_set_dir(disk_dir, 0);
        ntw_winfile_set_meta(disk_meta);
        ntw_winfile_set_lock(disk_lock);
        ntw_winfile_set_trunc(disk_trunc);
    }
    {
        char cwd[200], root[220];
        int got = ntw_getcwd(cwd, sizeof cwd - 8);
        uint32_t n = 0;
        if (got >= 0) {
            while (cwd[n] && n + 8 < sizeof root) { root[n] = cwd[n]; n++; }
            root[n++] = '/'; root[n++] = 'd'; root[n++] = 'r'; root[n++] = 'i'; root[n++] = 'v'; root[n++] = 'e';
            root[n] = 0;
            ntw_mkdir(root, 0755);
            ntw_winfile_set_root(root);
        }
    }
    {
        ntw_proc_ops spawned;
        int link;
        spawned.user = 0;
        spawned.exists = disk_exists;
        spawned.spawn = loader_spawn;
        ntw_proc_set_ops(&spawned);
        ntw_proc_set_wait(loader_proc_wait, 0);
        ntw_proc_set_kill(loader_proc_kill);
        link = ntw_readlink("/proc/self/exe", loader_path, 259);
        if (link > 0) loader_path[link] = 0;
        else loader_path[0] = 0;
    }
    ntw_filemap_set_ops(loader_map_place, loader_map_remove, loader_map_protect, 0);
    host_environ = argv + argc + 1;
    if (argc >= 2 && argv[1]) {
        unsigned n = 0;
        while (argv[1][n] && n + 1 < sizeof image_path) { image_path[n] = argv[1][n]; n++; }
        image_path[n] = 0;
    }
    for (i = 0; i < argc; ++i) {
        const char *mark = "ntw-depth-1";
        unsigned n = 0;
        if (!argv[i]) continue;
        while (mark[n] && argv[i][n] == mark[n]) n++;
        if (!mark[n] && !argv[i][n]) proc_depth = 1;
    }
    /* child-cmdline.txt is the command line of the most recently spawned
       child. The browser process must not adopt it, or chrome.exe starts as
       --type=fallback-handler and returns 2 before loading the main DLL. */
    if (proc_depth) {
        load_child_files();
        append("cmdline child\n");
    } else append("cmdline browser\n");
    flush_log_now();
    if (argc < 2) { append("usage: ntwload32 <pe>\n"); goto done; }
    fd = ntw_open(argv[1], O_RDONLY, 0);
    if (fd < 0) { append("open failed\n"); goto done; }
    size = ntw_lseek(fd, 0, 2);
    if (size < 64 || size > 8 * 1024 * 1024) { append("size rejected\n"); goto done; }
    ntw_lseek(fd, 0, 0);
    file = ntw_mmap2(0, (unsigned)size, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    image = ntw_mmap2(0, 8 * 1024 * 1024, PROT_RWX, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_image = image;
    g_image_bytes = 8u * 1024u * 1024u;
    arena = ntw_mmap2(0, 2 * 1024 * 1024, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned)file > 0xfffff000u || (unsigned)image > 0xfffff000u || (unsigned)arena > 0xfffff000u) {
        append("mmap failed\n"); goto done;
    }
    if (ntw_read(fd, file, (unsigned)size) != size) { append("read failed\n"); goto done; }
    ntw_close(fd); fd = -1;
    status = ntw_place_pe32(file, (unsigned)size, image, 8 * 1024 * 1024, (unsigned)image, &placed);
    append("place "); append_hex((unsigned)status); append("\n");
    append("subsystem "); append_hex(placed.subsystem_major); append(".");
    append_hex(placed.subsystem_minor); append("\n");
    append("preferred "); append_hex(placed.preferred_base); append("\n");
    append("image "); append_hex((unsigned)image); append("\n");
    append("relocs "); append_hex((unsigned)placed.relocations_applied); append("\n");
    if (status != NTW_MAP_OK) goto done;
    image_size = placed.size_of_image;
    image_entry = placed.entry_rva;
    append("tls "); append_hex((unsigned)placed.tls.present); append(" raw ");
    append_hex(placed.tls.raw_bytes); append(" align "); append_hex(placed.tls.alignment);
    append(" callbacks "); append_hex(placed.tls.callback_count); append(" chars ");
    append_hex(placed.tls.characteristics); append("\n");
    for (i = 0; i < (int)placed.tls.callback_count; ++i) {
        append("callback "); append_hex((unsigned)i); append(" ");
        append_hex(placed.tls.callback_vas[i]); append("\n");
    }
    pointer_cookie = ((uint32_t)(unsigned long)&pointer_cookie << 1) | 1u;
    is_dll = (rd16(image + rd32(image + 0x3c) + 22) & 0x2000) != 0;
    if (!is_dll && imports_dll(file, (uint32_t)size, "chrome_elf.dll")) {
        int dep_status = map_dependency();
        append("dep status "); append_hex((unsigned)dep_status); append("\n");
        if (dep_status != NTW_MAP_OK) goto done;
    }
    cursor = image + placed.size_of_image;
    status = bind_imports(file, (uint32_t)size, image, &cursor);
    append("bind "); append_hex((unsigned)status); append("\n");
    if (status != NTW_MAP_OK) goto done;
    cursor = arena;
    process = bump_alloc(&cursor, ntwtls_process_size());
    thread = bump_alloc(&cursor, ntwtls_thread_size());
    services.user = &cursor;
    services.allocate = bump_alloc;
    services.release = bump_release;
    if (!is_dll && dep_image) {
        uint32_t elf_index = 0, exe_index = 0;
        void *elf_slot, *exe_slot;
        typedef int __attribute__((stdcall)) (*dllmain_t)(void *, unsigned, void *);
        typedef int (*exe_entry_t)(void);
        dllmain_t elf_entry;
        exe_entry_t exe_entry;
        int elf_result;
        append("two modules\n");
        if (ntwtls_process_init(process, &services) != NTWTLS_OK) goto done;
        if (register_one(dep_image, &dep_placed, process, &elf_index) != NTWTLS_OK) goto done;
        if (register_one(image, &placed, process, &exe_index) != NTWTLS_OK) goto done;
        if (ntwtls_thread_init(process, thread) != NTWTLS_OK) goto done;
        elf_slot = ntwtls_slot(thread, elf_index);
        exe_slot = ntwtls_slot(thread, exe_index);
        if (!elf_slot || !exe_slot) goto done;
        if (install_tls_fs((uint32_t)(unsigned long)elf_slot, elf_index) < 0) goto done;
        if (install_tls_fs((uint32_t)(unsigned long)exe_slot, exe_index) < 0) goto done;
        append("elf tls\n");
        call_tls(dep_image, &dep_placed);
        elf_entry = (dllmain_t)(void *)(dep_image + dep_entry);
        append("calling elf "); append_hex(dep_entry); append("\n");
        out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
        ntw_write(1, logbuf, log_len);
        elf_result = elf_entry(dep_image, 1, 0);
        append("elf entry "); append_hex((unsigned)elf_result); append("\n");
        if (!elf_result) { status = 1; goto done; }
        append("exe tls\n");
        call_tls(image, &placed);
        if (argc > 2) {
            exe_entry = (exe_entry_t)(void *)(image + placed.entry_rva);
            live_tls_process = process;
        live_tls_thread = thread;
        append("calling exe "); append_hex(placed.entry_rva); append("\n");
            out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
            ntw_write(1, logbuf, log_len);
            status = exe_entry();
            append("exe "); append_hex((unsigned)status); append("\n");
            status = 0;
        } else status = 0;
        goto done;
    }
    append("slot init then PROCESS_ATTACH\n");
    out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
    ntw_write(1, logbuf, log_len);
    status = ntw_loader_start(image, &placed, process, thread, &services, 0, &slot);
    append("slot "); append_hex((unsigned)status); append("\n");
    if (status == 0 && slot && placed.tls.index_slot)
        install_tls_fs((uint32_t)(unsigned long)slot, *placed.tls.index_slot);
    out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
    ntw_write(1, logbuf, log_len);
    if (status == 0)
        status = ntwtls_call(process, thread, NTWTLS_PROCESS_ATTACH);
    append("start "); append_hex((unsigned)status); append("\n");
    if (slot && placed.tls.raw_bytes >= 4) {
        append("slot0 ");
        append_hex(((unsigned char *)slot)[0]); append(" ");
        append_hex(((unsigned char *)slot)[1]); append(" ");
        append_hex(((unsigned char *)slot)[2]); append(" ");
        append_hex(((unsigned char *)slot)[3]); append("\n");
    }
    if (placed.size_of_image >= 0x2204) {
        append("word_2200 "); append_hex(*(unsigned *)(image + 0x2200)); append("\n");
    }
    if (status == 0 && argc > 2 && argv[2][0] == 'e') {
        typedef int __attribute__((stdcall)) (*dllmain_t)(void *, unsigned, void *);
        dllmain_t entry = (dllmain_t)(void *)(image + placed.entry_rva);
        append("calling entry "); append_hex(placed.entry_rva); append("\n");
        out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
        ntw_write(1, logbuf, log_len);
        status = entry(image, 1, 0);
        append("entry "); append_hex((unsigned)status); append("\n");
        status = status ? 0 : 1;
    }
done:
    out = ntw_open("ntwload.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) { ntw_write(out, logbuf, log_len); ntw_close(out); }
    ntw_write(1, logbuf, log_len);
    return status == 0 ? 0 : 1;
}
