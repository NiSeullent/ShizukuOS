/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 application autorun: `shz.autorun=<path>` on the kernel command line names a control file (usually on a
 * disk volume, e.g. D:\K64RUN.TXT) that describes one Win64 program to start after the boot self-tests; used by
 * tests/run_k64_chromium.py to start chrome.exe from the Chromium disk. `shz.noapps` skips the T_*.EXE self-checking
 * programs of \SHZ\TESTS (tests.c), so such a run spends its time on the program under test.
 *
 * Control file (ASCII, one "key=value" per line, CR/LF tolerated, unknown keys ignored):
 *   image=D:\chrome-win\chrome.exe          executable (required)
 *   cmdline=chrome.exe --headless ...        command line (default: the image path)
 *   cwd=D:\chrome-win                        current directory (default: the image's directory)
 *   timeout=900                              seconds before the process is terminated (default 600)
 * The kernel prints "K64 autorun: ..." lines (start, periodic heartbeat with the process' CPU and memory counters, and the
 * final exit code / fault / timeout) that the host runner parses. Nothing here decides success: the runner checks the
 * program's own output.
 */
#include "fs.h"
#include "net.h"
#include "vfs_mounts.h"

extern void k64_dump_threads(process_t *p);
extern process_t *process_slot(unsigned i);
extern int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                  process_t **out_proc, thread_t **out_thread);

int k64_cmdline_has(const char *word)
{
    const char *p = k64_boot_cmdline();
    const size_t n = strlen(word);
    while (p && *p) {
        while (*p == ' ') ++p;
        if (!strncmp(p, word, n) && (p[n] == ' ' || p[n] == 0 || p[n] == '=')) return 1;
        while (*p && *p != ' ') ++p;
    }
    return 0;
}

/* Value of `key=` on the command line (up to the next space) into out; 0 = found. */
static int cmdline_value(const char *key, char *out, size_t cap)
{
    const char *p = k64_boot_cmdline();
    const size_t n = strlen(key);
    while (p && *p) {
        while (*p == ' ') ++p;
        if (!strncmp(p, key, n) && p[n] == '=') {
            size_t i = 0;
            p += n + 1;
            while (*p && *p != ' ' && i + 1 < cap) out[i++] = *p++;
            out[i] = 0;
            return 0;
        }
        while (*p && *p != ' ') ++p;
    }
    return -1;
}

static void copy_value(char *dst, size_t cap, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = 0;
}

/* Production boot profile: keep the real Win64 shell alive until it exits. A
 * kernel-created process retains its creation reference until proc_wait(), which
 * yields to its threads and safely reaps it. Do not use the QA autorun timeout. */
unsigned k64_desktop(void)
{
    const char *image = "C:\\SHZ\\SYS64\\SHZDESK.EXE";
    process_t *p = 0;
    thread_t *t = 0;
    int64_t code = -1;
    int faulted = 1, pid, reaped, flush;
    int32_t st;
    kprintf("K64 desktop: production profile (self-tests not run)\n");
    if (net_ensure_init()) {
        kprintf("K64 desktop: result network-init-failed\n");
        return 1;
    }
    /* Display, compositor and input use their normal, lazy initialisation when
     * the shell calls the graphics syscalls. Only the shell can report GUI ready. */
    kprintf("K64 desktop: starting %s\n", image);
    st = ldr_create_process(0, image, image, "C:\\SHZ", &p, &t);
    if (st) {
        kprintf("K64 desktop: result start-failed status=%x\n", (uint32_t)st);
        return 1;
    }
    pid = p->pid;
    kprintf("K64 desktop: started pid %d\n", pid);
    reaped = proc_wait(pid, &code, &faulted);
    /* proc_wait may release the process slot; p and t are no longer usable. */
    if (reaped) {
        kprintf("K64 desktop: result wait-failed pid=%d rc=%d\n", pid, reaped);
        return 1;
    }
    kprintf("K64 desktop: result exited exit=%x faulted=%d reaped=%d\n",
            (uint32_t)code, faulted, reaped);
    flush = vfs_flush_all();
    kprintf("K64 desktop: volume flush rc %d\n", flush);
    return code != 0 || faulted || flush != 0 ? 1 : 0;
}

void k64_autorun(void)
{
    char ctl[128], image[200], cmdline[512], cwd[160];
    uint8_t *text;
    fsnode_t *n;
    uint64_t got = 0, timeout_s = 600, waited = 0, i = 0, next_beat = 10000;
    process_t *p = 0;
    thread_t *t = 0;
    int64_t code = -1;
    int faulted = 1, reaped = -1;
    int32_t st;
    if (cmdline_value("shz.autorun", ctl, sizeof ctl)) return;
    image[0] = cmdline[0] = cwd[0] = 0;
    n = fs_lookup(ctl);
    if (!n || n->is_dir || n->size == 0 || n->size > 4096) {
        kprintf("K64 autorun: control file %s not found or unusable\n", ctl);
        return;
    }
    text = kzalloc(n->size + 1);
    if (!text) return;
    if (fs_read(n, 0, text, n->size, &got) || got != n->size) {
        kprintf("K64 autorun: cannot read %s\n", ctl);
        kfree(text);
        return;
    }
    while (i < got) {
        uint64_t e = i, eq;
        while (e < got && text[e] != '\n' && text[e] != '\r') ++e;
        for (eq = i; eq < e && text[eq] != '='; ++eq) { }
        if (eq < e) {
            const char *k = (const char *)text + i, *v = (const char *)text + eq + 1;
            const size_t kl = eq - i, vl = e - eq - 1;
            if (kl == 5 && !strncmp(k, "image", 5)) copy_value(image, sizeof image, v, vl);
            else if (kl == 7 && !strncmp(k, "cmdline", 7)) copy_value(cmdline, sizeof cmdline, v, vl);
            else if (kl == 3 && !strncmp(k, "cwd", 3)) copy_value(cwd, sizeof cwd, v, vl);
            else if (kl == 7 && !strncmp(k, "timeout", 7)) {
                uint64_t s = 0, j;
                for (j = 0; j < vl && v[j] >= '0' && v[j] <= '9'; ++j) s = s * 10 + (uint64_t)(v[j] - '0');
                if (s) timeout_s = s;
            }
        }
        i = e + 1;
    }
    kfree(text);
    if (!image[0]) { kprintf("K64 autorun: %s has no image= line\n", ctl); return; }
    if (!cwd[0]) {
        size_t cut = strlen(image);
        while (cut && image[cut - 1] != '\\') --cut;
        copy_value(cwd, sizeof cwd, image, cut > 3 ? cut - 1 : cut);
    }
    kprintf("K64 autorun: starting %s (cwd %s, timeout %u s)\n", image, cwd, (unsigned)timeout_s);
    kprintf("K64 autorun: command line: %s\n", cmdline[0] ? cmdline : image);
    st = ldr_create_process(0, image, cmdline[0] ? cmdline : image, cwd, &p, &t);
    if (st) {
        kprintf("K64 autorun: process creation failed, status %x\n", (uint32_t)st);
        kprintf("K64 autorun: result start-failed status=%x\n", (uint32_t)st);
        return;
    }
    kprintf("K64 autorun: started pid %d\n", p->pid);
    while (!(p->terminated && p->threads_alive == 0) && waited < timeout_s * 1000) {
        thread_sleep_ms(10);
        waited += 10;
        if (waited >= next_beat) {
            next_beat += 30000;
            kprintf("K64 autorun: heartbeat %u s: pid %d threads %d, %u free pages, kernel heap %u KiB used\n",
                    (unsigned)(waited / 1000), p->pid, p->threads_alive, (unsigned)pmm_free_count(),
                    (unsigned)(kheap_used() >> 10));
        }
    }
    if (!p->terminated || p->threads_alive) {
        uint64_t grace = 0;
        const int timed_out = !p->terminated;
        if (timed_out) {
            unsigned k;
            process_t *q;
            kprintf("K64 autorun: timeout after %u s; thread report of the live processes:\n", (unsigned)timeout_s);
            for (k = 1; (q = process_slot(k)) != 0; ++k) {
                if (!q->used || !q->pml4 || q->threads_alive <= 0) continue;
                kprintf("K64: process pid %d (%s), %d thread(s)%s\n", q->pid, q->name, q->threads_alive, q->terminated ? ", terminating" : "");
                k64_dump_threads(q);
            }
            kprintf("K64 autorun: terminating pid %d\n", p->pid);
            process_terminate(p, 0x102, 1);
        }
        while (p->threads_alive > 0 && grace < 10000) { thread_sleep_ms(10); grace += 10; }
        if (p->threads_alive > 0) {                 /* a thread that never leaves the kernel: do not block the boot on it */
            kprintf("K64 autorun: result %s exit=%x faulted=%d reaped=0 (%d thread(s) still alive) after %u ms\n",
                    timed_out ? "timeout" : "exited", (uint32_t)p->exit_code, p->faulted, p->threads_alive, (unsigned)waited);
            return;
        }
    }
    reaped = proc_wait(p->pid, &code, &faulted);
    kprintf("K64 autorun: result %s exit=%x faulted=%d reaped=%d after %u ms\n", waited >= timeout_s * 1000 ? "timeout" : "exited",
            (uint32_t)code, faulted, reaped, (unsigned)waited);
}
