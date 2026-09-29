/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 Windows process model: process exit ordering (NtTerminateProcess(NULL)), and - as the subsystem grows -
 * process creation, handle inheritance and duplication, cross-process memory access and jobs.
 */
#include "ipc.h"

/* ---------------------------------------------------------------- NtTerminateProcess(NULL, status) */
/* First half of RtlExitUserProcess (ExitProcess): every thread of the calling process except the caller ends, and the call
 * returns only once they are all gone, so DLL_PROCESS_DETACH then runs with no other thread alive, as on Windows. The
 * caller becomes the process's exit owner: from now on no new thread starts in the process, and a second thread that also
 * tries to exit the process is simply one of the victims. Threads blocked in interruptible waits (object waits, delays,
 * alert-by-thread-id, I/O and port waits) are woken to die; threads spinning in user mode die at the next timer tick;
 * threads inside a kernel-internal wait (a kernel mutex or semaphore) die when that wait ends and they leave the kernel. */
int32_t process_terminate_others(process_t *p)
{
    thread_t *me = thread_current();
    uint64_t f = irq_save();
    if (p->exit_owner && p->exit_owner != me) {         /* another thread is already exiting the process: we are a victim */
        irq_restore(f);
        return STATUS_THREAD_IS_TERMINATING;            /* check_kill() ends this thread on the way out */
    }
    p->exit_owner = me;
    irq_restore(f);
    while (p->threads_alive > 1 && !p->terminated) {
        ipc_process_terminating(p);                     /* repeated: a victim may block again before it notices */
        thread_sleep_ms(1);
    }
    return STATUS_SUCCESS;
}

/* NtTerminateProcess(handle, status): the caller's own process (NtCurrentProcess() or a handle to it) ends at once, with
 * the caller; another process is terminated asynchronously (its threads die as described above; wait on its handle for
 * the end). A process that has already ended reports STATUS_PROCESS_IS_TERMINATING (Win32: ERROR_ACCESS_DENIED). */
int32_t process_terminate_handle(process_t *p, uint64_t h, int32_t code)
{
    process_t *t;
    kobject_t *o;
    int32_t st = ipc_ref_process(p, h, PROCESS_TERMINATE, &t, &o);
    if (st) return st;
    if (t != p && (t->terminated || t->teardown)) { ob_deref(o); return STATUS_PROCESS_IS_TERMINATING; }
    process_terminate(t, (int64_t)code, 0);
    ob_deref(o);
    if (t == p) {
        process_thread_gone(p);
        thread_exit(code);
    }
    return STATUS_SUCCESS;
}

/* placeholders of the parts not brought up yet */
void job_handle_closed(kobject_t *o) { (void)o; }
void job_free(kobject_t *o) { (void)o; }
void job_process_exited(process_t *p) { (void)p; }
int32_t ipc_proc_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int *handled)
{ (void)p; (void)r; (void)num; (void)a1; (void)a2; (void)a3; (void)a4; *handled = 0; return 0; }
