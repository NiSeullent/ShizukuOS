/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "proc.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static int failures;
static int spawned;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void wide(const char *ascii, uint16_t *out) {
    while (*ascii) *out++ = (uint16_t)(unsigned char)*ascii++;
    *out = 0;
}
static int host_exists(void *user, const char *path) {
    (void)user;
    return access(path, F_OK) == 0 ? 1 : 0;
}
static int host_spawn(void *user, const char *image, int argc, char **argv, uint32_t *pid) {
    pid_t child;
    (void)user;
    spawned++;
    child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        char *list[16];
        int i;
        for (i = 0; i < argc && i < 15; ++i) list[i] = argv[i];
        list[i] = 0;
        execv(image, list);
        _exit(127);
    }
    *pid = (uint32_t)child;
    return 0;
}
static int host_wait(void *user, uint32_t pid, uint32_t *status, int block) {
    int st = 0;
    pid_t got;
    (void)user;
    got = waitpid((pid_t)pid, &st, block ? 0 : WNOHANG);
    if (got == 0) return 0;
    if (got < 0) return -errno;
    *status = (uint32_t)st;
    return 1;
}
static int host_kill(void *user, uint32_t pid) {
    (void)user;
    return kill((pid_t)pid, SIGKILL) == 0 ? 0 : -errno;
}
int main(void) {
    ntw_proc_ops ops = { 0, host_exists, host_spawn };
    uint16_t name[160], missing[80], command[200];
    uint32_t process = 0, thread = 0, pid = 0, tid = 0, error = 0, wait_result = 9, code = 0;
    ntw_proc_set_ops(&ops);
    ntw_proc_set_wait(host_wait, 0);
    wide("/tmp/ntw-no-such-proc.exe", missing);
    C(ntw_proc_create(missing, 0, 0, 0, &process, &thread, &pid, &tid, &error) == 0 && error == 2 && pid == 0 && spawned == 0);
    wide("/tmp/ntw-exit42", name);
    C(ntw_proc_create(name, 0, 4, 0, &process, &thread, &pid, &tid, &error) == 0 && error == 87 && spawned == 0);
    C(ntw_proc_create(name, 0, 0, 0, &process, &thread, &pid, &tid, &error) == 1);
    C(pid > 1 && process != 0 && thread != process && tid == pid);
    C(ntw_proc_exit_code(process, &code, &error) == 1);
    C(ntw_proc_wait(process, 1, &wait_result, &error) == 1 && wait_result == 0);
    C(ntw_proc_exit_code(process, &code, &error) == 1 && code == 42);
    C(ntw_proc_close(process, &error) == 1);
    C(ntw_proc_close(thread, &error) == 1);
    C(ntw_proc_exit_code(process, &code, &error) == 0 && error == 6);
    wide("/tmp/ntw-exit42 extra", command);
    C(ntw_proc_create(0, command, 0, 0, &process, &thread, &pid, &tid, &error) == 1 && pid > 1);
    C(ntw_proc_wait(process, 1, &wait_result, &error) == 1 && wait_result == 0);
    C(ntw_proc_exit_code(thread, &code, &error) == 1 && code == 42);
    C(ntw_proc_close(process, &error) == 1 && ntw_proc_close(thread, &error) == 1);
    ntw_proc_set_kill(host_kill);
    wide("/bin/sleep", name);
    spawned = 0;
    C(ntw_proc_create(name, 0, 0, 0, &process, &thread, &pid, &tid, &error) == 1 && pid > 1);
    C(ntw_proc_terminate(process, 7, &error) == 1);
    C(ntw_proc_exit_code(process, &code, &error) == 1 && code == 7);
    C(ntw_proc_close(process, &error) == 1 && ntw_proc_close(thread, &error) == 1);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"proc\":true}\n");
    return 0;
}
