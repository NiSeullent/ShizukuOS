/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 IPC and Windows process model: shared definitions of ipc_core.c (routing, lifetimes, handles, APCs),
 * ipc_io.c (IRPs, completion, I/O completion ports, overlapped file I/O), ipc_section.c (sections and views),
 * ipc_proc.c (process creation, handle inheritance and duplication, jobs) and npfs.c (named pipe file system).
 *
 * Concurrency model: Kernel64 is uniprocessor and preemptible, so every IPC data structure is changed with interrupts
 * disabled (irq_save/irq_restore). Nothing in this subsystem sleeps while holding that "lock" except through
 * thread_block_current(), which is the documented way to wait with interrupts off.
 */
#ifndef K64_IPC_H
#define K64_IPC_H
#include "fs.h"

/* NTSTATUS values used by this subsystem (same numeric values as ntstatus.h). */
#define STATUS_OBJECT_NAME_EXISTS ((int32_t)0x40000000)
#define STATUS_PROCESS_NOT_IN_JOB ((int32_t)0x00000123)
#define STATUS_PROCESS_IN_JOB ((int32_t)0x00000124)
#define STATUS_PARTIAL_COPY ((int32_t)0x8000000D)
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010)
#define STATUS_NOT_MAPPED_VIEW ((int32_t)0xC0000019)
#define STATUS_UNABLE_TO_DELETE_SECTION ((int32_t)0xC000001B)
#define STATUS_INVALID_VIEW_SIZE ((int32_t)0xC000001F)
#define STATUS_INVALID_PARAMETER_MIX ((int32_t)0xC0000030)
#define STATUS_SECTION_TOO_BIG ((int32_t)0xC0000040)
#define STATUS_INVALID_PAGE_PROTECTION ((int32_t)0xC0000045)
#define STATUS_INSTANCE_NOT_AVAILABLE ((int32_t)0xC00000AB)
#define STATUS_PIPE_NOT_AVAILABLE ((int32_t)0xC00000AC)
#define STATUS_INVALID_PIPE_STATE ((int32_t)0xC00000AD)
#define STATUS_PIPE_BUSY ((int32_t)0xC00000AE)
#define STATUS_ILLEGAL_FUNCTION ((int32_t)0xC00000AF)
#define STATUS_PIPE_DISCONNECTED ((int32_t)0xC00000B0)
#define STATUS_PIPE_CLOSING ((int32_t)0xC00000B1)
#define STATUS_PIPE_CONNECTED ((int32_t)0xC00000B2)
#define STATUS_PIPE_LISTENING ((int32_t)0xC00000B3)
#define STATUS_INVALID_READ_MODE ((int32_t)0xC00000B4)
#define STATUS_IO_TIMEOUT ((int32_t)0xC00000B5)
#define STATUS_PIPE_EMPTY ((int32_t)0xC00000D9)
#define STATUS_MAPPED_FILE_SIZE_ZERO ((int32_t)0xC000011E)
#define STATUS_PIPE_BROKEN ((int32_t)0xC000014B)
#define STATUS_MAPPED_ALIGNMENT ((int32_t)0xC0000220)
#define STATUS_NOT_FOUND ((int32_t)0xC0000225)
#define STATUS_HANDLE_NOT_CLOSABLE ((int32_t)0xC0000235)
#define STATUS_FRAME_REWRITTEN ((int32_t)0x7fff0001)          /* syscall.c: leave through IRETQ with the edited frame */

/* Access rights checked here. */
#define PROCESS_TERMINATE 0x0001u
#define PROCESS_VM_OPERATION 0x0008u
#define PROCESS_VM_READ 0x0010u
#define PROCESS_VM_WRITE 0x0020u
#define PROCESS_DUP_HANDLE 0x0040u
#define PROCESS_SET_QUOTA 0x0100u
#define PROCESS_QUERY_INFORMATION 0x0400u
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define PROCESS_ALL_ACCESS 0x1fffffu
#define THREAD_ALL_ACCESS 0x1fffffu
#define THREAD_SUSPEND_RESUME 0x0002u
#define THREAD_SET_CONTEXT 0x0010u
#define SECTION_QUERY 0x0001u
#define SECTION_MAP_WRITE 0x0002u
#define SECTION_MAP_READ 0x0004u
#define SECTION_MAP_EXECUTE 0x0008u
#define SECTION_ALL_ACCESS 0xf001fu
#define GENERIC_READ_ACCESS 0x80000000u
#define GENERIC_WRITE_ACCESS 0x40000000u
#define GENERIC_EXECUTE_ACCESS 0x20000000u
#define GENERIC_ALL_ACCESS 0x10000000u
#define FILE_READ_DATA_ACCESS 0x0001u
#define FILE_WRITE_DATA_ACCESS 0x0002u
#define FILE_APPEND_DATA_ACCESS 0x0004u
#define OBJ_INHERIT_ATTR 0x00000002u
#define HANDLE_FLAG_INHERIT_BIT 1u          /* handle_entry_t.inherit bit 0 */
#define HANDLE_FLAG_PROTECT_BIT 2u          /* handle_entry_t.inherit bit 1: HANDLE_FLAG_PROTECT_FROM_CLOSE */

/* Native structures (Windows x64 layouts). */
struct ipc_ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };
struct ipc_objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };
struct ipc_iosb { uint64_t status; uint64_t information; };

/* ---------------------------------------------------------------- per-process / per-thread state */
typedef struct view view_t;
typedef struct job job_t;
typedef struct {
    view_t *views;                      /* mapped section views of this process */
    job_t *job;                         /* job the process belongs to (reference held) */
    uint64_t apc_dispatcher;            /* ntdll!KiUserApcDispatcher, resolved on first use */
} ipc_proc_t;

typedef struct apc {
    struct apc *next;
    uint64_t routine, arg1, arg2, arg3;
} apc_t;

typedef struct {
    apc_t *apc_head, *apc_tail;         /* user-mode APC queue (NtQueueApcThread, I/O completion routines) */
    int alertable;                      /* blocked in an alertable wait: queuing an APC wakes it */
    int waiting;                        /* blocked in an IPC wait (sync I/O, port, pipe wait): a kill wakes it */
} ipc_thread_t;

ipc_proc_t *ipc_proc(process_t *p, int create);
void ipc_process_terminating(process_t *p);    /* wakes the process's blocked threads (except the caller) so they die */
void ipc_reap(void);
void ipc_wake_to_die(thread_t *t);               /* interrupts off */
ipc_thread_t *ipc_thread(thread_t *t, int create);

/* ---------------------------------------------------------------- handles and objects */
int32_t ipc_name_from_oa(process_t *p, uint64_t oa_va, char *out, size_t cap, uint32_t *attributes);
int32_t ipc_read_ustr16(process_t *p, uint64_t ustr_va, uint16_t *out, uint32_t cap_chars, uint32_t *chars);
/* Inserts `o` (the caller's reference is kept by the handle table on success, dropped on failure) and writes the handle
 * value to user memory. `inherit` sets the handle's inheritance flag. */
int32_t ipc_give_handle(process_t *p, kobject_t *o, uint32_t access, int inherit, uint64_t user_ptr, uint32_t *h_out);
/* Handle -> referenced object (pseudo handles -1 / -2 included, low tag bits ignored). */
int32_t ipc_ref_handle(process_t *p, uint64_t h, uint32_t type, kobject_t **out, uint32_t *access);
int32_t ipc_ref_process(process_t *cur, uint64_t h, uint32_t need_access, process_t **out, kobject_t **obj);
void ipc_handle_opened(kobject_t *o);   /* counts handles of IPC objects (pipe ends, ports, jobs) */

/* ---------------------------------------------------------------- IRPs and completion (ipc_io.c) */
enum { IRP_READ = 1, IRP_WRITE, IRP_LISTEN, IRP_TRANSCEIVE, IRP_FLUSH };

typedef struct irp irp_t;
struct irp {
    irp_t *next;                        /* queue of the object that owns the pending IRP */
    irp_t *all_next;                    /* every pending IRP (cancellation, teardown) */
    process_t *proc;                    /* issuer (holds a reference on proc->object) */
    thread_t *thread;                   /* issuing thread (APC target, CancelIo) */
    kobject_t *fobj;                    /* file object the I/O was issued on (referenced) */
    uint32_t major, flags;
    uint64_t buf, len, done;            /* user buffer in the issuer's address space; bytes moved so far */
    uint64_t obuf, olen;                /* TransactNamedPipe: reply buffer */
    uint64_t iosb;                      /* IO_STATUS_BLOCK in the issuer's address space (0: none) */
    kobject_t *event;                   /* referenced event, signaled on completion */
    uint64_t apc_routine, apc_context;
    kobject_t *port;                    /* completion port captured at issue (referenced), with its key */
    uint64_t key;
    int sync;                           /* the issuer waits inside the system call */
    int completed, pended;
    int32_t status;
    uint64_t info;
    void *owner;                        /* object whose queue holds the IRP, for cancellation */
    void (*cancel)(irp_t *irp);         /* unlinks the IRP from its owner's queue (interrupts off) */
    uint32_t read_mode;                 /* pipe reads: FILE_PIPE_MESSAGE_MODE captured at issue */
    int transceive_phase;               /* 0 writing the request, 1 reading the reply */
};
#define IRPF_NO_EVENT_ON_HANDLE 1       /* FILE_SKIP_SET_EVENT_ON_HANDLE */

typedef struct {
    kobject_t *port;                    /* referenced completion port */
    uint64_t key;
    uint32_t notify;                    /* FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 1 | FILE_SKIP_SET_EVENT_ON_HANDLE 2 */
    int sync;                           /* FILE_SYNCHRONOUS_IO_*: the object has a current position, I/O waits */
} ioctx_t;

ioctx_t *ipc_ioctx(kobject_t *fobj, int create);
/* Builds an IRP from the NtReadFile-style arguments (event, APC routine/context, IOSB). */
int32_t irp_prepare(process_t *p, kobject_t *fobj, uint64_t event_h, uint64_t apc_routine, uint64_t apc_context,
                    uint64_t iosb, uint32_t major, irp_t **out);
void irp_free(irp_t *irp);
/* Queues the IRP as pending on its owner (the caller linked it into its owner's queue and set irp->cancel). */
void irp_mark_pending(irp_t *irp);
/* Completes an IRP (interrupts off): IOSB, event, file object, APC or completion packet, sync waiter. */
void irp_complete(irp_t *irp, int32_t status, uint64_t info);
/* After issuing: waits for a synchronous IRP, or returns STATUS_PENDING / the final status of an asynchronous one. */
int32_t irp_finish(irp_t *irp);
void irp_cancel_matching(process_t *p, thread_t *t, kobject_t *fobj, uint64_t iosb, int *found);
void ipc_io_teardown(process_t *p);
void ipc_io_thread_exit(thread_t *t);
/* Posts a completion packet to a port (interrupts off). */
int32_t iocp_post(kobject_t *port, uint64_t key, uint64_t apc_context, int32_t status, uint64_t info);
void iocp_handle_closed(kobject_t *o);
void iocp_free(kobject_t *o);
void ioctx_free(kobject_t *o);

/* APCs */
int apc_pending(thread_t *t);
void apc_queue(thread_t *t, uint64_t routine, uint64_t a1, uint64_t a2, uint64_t a3);
int32_t apc_deliver(process_t *p, struct regs *r, int32_t status);       /* STATUS_FRAME_REWRITTEN or `status` */
void apc_free_all(thread_t *t);

/* ---------------------------------------------------------------- dispatch entry points of each file */
int32_t ipc_io_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                       int *handled);
int32_t ipc_section_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                            uint64_t a4, int *handled);
int32_t ipc_proc_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int *handled);
int32_t npfs_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                     int *handled);

/* sections */
void section_free(kobject_t *o);
void views_teardown(process_t *p);

/* named pipes */
int npfs_is_pipe_path(const uint16_t *name, uint32_t chars);
void npfs_handle_closed(kobject_t *o);
void npfs_free(kobject_t *o);

/* jobs */
void job_handle_closed(kobject_t *o);
void job_free(kobject_t *o);
void job_process_exited(process_t *p);
int32_t job_inherit(process_t *parent, process_t *child);

/* counters for NtShzQueryKernelStats */
extern uint32_t ipc_stat_sections, ipc_stat_views, ipc_stat_pipes, ipc_stat_irps, ipc_stat_packets, ipc_stat_jobs;

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
extern int32_t user_exception_continue(process_t *p, struct regs *r, uint64_t context_va, uint64_t record_va, int is_raise);
extern int32_t sysfile_dispatch(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                                uint64_t a4, int *handled);
#endif
