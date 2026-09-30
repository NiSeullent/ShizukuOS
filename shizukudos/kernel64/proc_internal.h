/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 internal process, VAD and object structures.
 */
#ifndef K64_PROC_INTERNAL_H
#define K64_PROC_INTERNAL_H
#include "k64.h"
#include "ntsys.h"

/* ---- virtual address descriptors ---- */
enum { VAD_FREE = 0, VAD_RESERVED = 1, VAD_COMMITTED = 2 };
enum { VK_PRIVATE = 0, VK_IMAGE = 1, VK_STACK = 2, VK_TEB = 3, VK_SECTION = 4 };   /* VK_SECTION: a mapped view (section.c), img = view */
typedef struct {
    uint64_t start, end;                /* [start, end), page aligned */
    uint32_t state;                     /* VAD_RESERVED / VAD_COMMITTED */
    uint32_t prot;                      /* PAGE_* of committed pages; initial protect for reserved */
    uint32_t kind;
    uint32_t alloc_prot;                /* protection at reservation (AllocationProtect) */
    uint64_t alloc_base;                /* AllocationBase */
    void *img;                          /* VK_IMAGE backed lazily by a file (ldr.c image_map_t), else NULL */
} vad_t;

typedef struct {
    vad_t *v;
    unsigned count, cap;
} vad_set_t;

/* ---- kernel objects ---- */
enum { OB_NONE = 0, OB_EVENT = 1, OB_MUTANT = 2, OB_SEMAPHORE = 3, OB_THREAD = 4, OB_PROCESS = 5, OB_FILE = 6,
       OB_TIMER = 7, OB_DIRECTORY = 8 };
enum { OB_KEY = 0x10 };                 /* registry key (registry.c); a separate enum so other subsystems can add their own types */
#define OB_SOCKET 0x40                  /* socket handle (u.net.sock); closed through net_socket_handle_closing() */
/* kernel32 support objects (kernel64/section.c, iocp.c, npfs.c, sysk32_obj.c) */
#define OB_SECTION 0x20                 /* section (file mapping): u.section.s = section_t * */
#define OB_IOCP 0x21                    /* I/O completion port: u.iocp.q; signalled while packets are queued */
#define OB_JOB 0x22                     /* job object: u.job.j */
#define OB_TOKEN 0x23                   /* access token: u.token.t */
#define OB_NAME_MAX 128                 /* named objects: bytes of the UTF-8 name including the terminator */
struct waitblock;
struct kobject {
    uint32_t type, refs;
    int signaled;                       /* event/thread/process/timer state, semaphore count > 0 */
    struct waitblock *waiters;
    char name[OB_NAME_MAX];
    struct kobject *next_named;
    void *sd;                           /* self-relative security descriptor set with NtShzSecurityObject (stored, not enforced) */
    uint32_t sd_len;
    uint32_t handle_count;              /* handles referring to the object (handle_insert / handle_close) */
    union {
        struct { int manual; } event;
        struct { thread_t *owner; int recursion; int abandoned; } mutant;
        struct { int count, max; } sem;
        /* t is 0 once the exited thread was reclaimed (sched.c); the other fields then answer queries */
        struct { thread_t *t; int64_t exit_code; uint64_t tid; uint64_t pid;
                 uint64_t create_tick, exit_tick, user_ticks, kernel_ticks, cycles; } thr;
        struct { void *sock; } net;         /* OB_SOCKET: sock_t * (net_sock.c) */
        struct { process_t *p; } proc;
        struct { void *file; uint32_t access; } file;
        struct { uint64_t due_tick, period_ms; int manual; int armed; struct kobject *next_timer; } timer;   /* objects.c timer list */
        struct { void *node; } key;             /* registry key node (registry.c); the node's refs count these objects */
        struct { void *s; } section;            /* OB_SECTION: section_t * (section.c) */
        struct { void *q; } iocp;               /* OB_IOCP: iocp_t * (iocp.c) */
        struct { void *j; } job;                /* OB_JOB: job_t * (sysk32_obj.c) */
        struct { void *t; } token;              /* OB_TOKEN: token_t * (sysk32_obj.c) */
    } u;
};

typedef struct waitblock {
    thread_t *thread;
    struct waitblock *next_all;         /* all waits of one thread */
    struct waitblock *next;             /* per-object list */
    kobject_t *obj;
    unsigned index;
} waitblock_t;

#define MAX_HANDLES 512
typedef struct {
    kobject_t *obj;
    uint32_t access;
    uint32_t inherit;
} handle_entry_t;

struct process {
    int used, pid;
    uint64_t pml4;
    vad_set_t vads;
    handle_entry_t *handles;
    unsigned handle_count;
    int64_t exit_code;
    int faulted, terminated, threads_alive;
    thread_t *main_thread;
    ksem_t exited;
    char name[32];
    kobject_t *object;
    uint64_t image_base, entry;
    uint64_t peb;
    uint64_t next_tid;
    void *loaded_modules;
    uint64_t heap_hint;
    uint64_t cwd_len;
    char cwd[128];
    void *env;
    uint64_t env_size;
    uint64_t stack_hint;
    uint64_t mmap_hint;                 /* allocation hint for NULL-base requests */
    uint64_t parent_pid;
    uint64_t create_tick;
    char cmdline[256];
    /* loader state */
    void *modules;                      /* module_t list, see ldr.c */
    unsigned tls_slots;                 /* TLS indices handed out to loaded modules */
    kmutex_t ldr_lock;                  /* serialises runtime loads and TLS array (re)building (ldr.c) */
    uint64_t ntdll_process_start, ntdll_thread_start, ntdll_exception_dispatcher;
    uint64_t ldr_va;                    /* PEB_LDR_DATA */
    uint64_t params_va;                 /* RTL_USER_PROCESS_PARAMETERS */
    /* kernel32 support (sysk32.c): CPU time of the threads that have exited, exit tick, settings and memory statistics */
    uint64_t dead_user_ticks, dead_kernel_ticks, dead_cycles, exit_tick;
    uint32_t priority_class;            /* PROCESS_PRIORITY_CLASS value (GetPriorityClass); 0 = never set: NORMAL */
    uint64_t page_faults;               /* user-mode page faults taken (demand-zero and access faults) */
    uint64_t peak_ws_pages, peak_commit;        /* maxima measured before each unmap and at each query (sysk32.c) */
    uint32_t mem_priority, power_control, power_state;  /* SetProcessInformation settings (0 priority = never set: 5) */
    /* WIN64 subsystem bridge (subsys64.c): console sink the standard handles are relayed to, inherited from the
     * parent at creation; 0 = the Supervisor/serial console. `console_sink_gen` guards against a recycled slot. */
    void *console_sink;
    uint32_t console_sink_gen;
    /* kernel32 support (sysk32_obj.c): the job the process belongs to and its primary access token (both referenced) */
    kobject_t *job;
    kobject_t *token;
    /* reaper (proc.c): a process created by another process is never proc_wait()ed by the kernel; once its last thread is
     * gone the reaper closes its handles and frees its address space, keeping the slot for exit-code queries. */
    int reap_pending, mem_released;
};

/* vad.c */
int32_t vad_insert_fixed(process_t *p, uint64_t start, uint64_t size, uint32_t state, uint32_t prot, uint32_t kind,
                         uint64_t alloc_base);
/* A committed VK_IMAGE descriptor whose pages are produced on first touch by ldr_image_fault(img). */
int32_t vad_insert_image(process_t *p, uint64_t start, uint64_t size, uint32_t prot, uint64_t alloc_base, void *img);
/* The loader's only access path to process memory (vad.c): pages are produced like a fault (lazy image pages read and
 * relocated, others demand-zero) and accessed whatever their protection. */
uint8_t *image_kpage(process_t *p, uint64_t va);                              /* kernel address of the page, or NULL */
int image_poke(process_t *p, uint64_t va, const void *src, uint64_t n);       /* write; 0 = ok */
int image_peek(process_t *p, uint64_t va, void *dst, uint64_t n);             /* read; 0 = ok */
int vad_range_is_free(process_t *p, uint64_t start, uint64_t size);
void vad_init(process_t *p);
void vad_destroy(process_t *p);
vad_t *vad_find(process_t *p, uint64_t addr);
int32_t vad_alloc(process_t *p, uint64_t *base, uint64_t *size, uint32_t type, uint32_t prot, uint32_t kind);
int32_t vad_free(process_t *p, uint64_t *base, uint64_t *size, uint32_t type);
int32_t vad_protect(process_t *p, uint64_t *base, uint64_t *size, uint32_t new_prot, uint32_t *old_prot);
int32_t vad_query(process_t *p, uint64_t addr, uint64_t *base, uint64_t *alloc_base, uint32_t *alloc_prot,
                  uint64_t *size, uint32_t *state, uint32_t *prot, uint32_t *type);
uint64_t prot_to_ptflags(uint32_t prot);                  /* PT_* flags (with PT_U) for a PAGE_* value */
int user_fault_in(process_t *p, uint64_t addr, int write, int exec);   /* demand-zero commit; 0 = ok */
int copy_from_user(process_t *p, void *dst, uint64_t uva, uint64_t n);
int copy_to_user(process_t *p, uint64_t uva, const void *src, uint64_t n);
int user_string_len(process_t *p, uint64_t uva, uint64_t max, uint64_t *len);

/* ldr.c */
/* Options of a process creation beyond image, command line and directory (NtCreateProcessEx's extension block, sysx.c). */
typedef struct ldr_proc_opts {
    int suspended;                      /* the main thread waits for NtResumeThread */
    const uint16_t *env;                /* UTF-16 environment block (double-NUL terminated), NULL = the default one */
    uint64_t env_chars;
    int inherit;                        /* copy the parent's inheritable handles to the same values */
    const uint64_t *handle_list;        /* only these (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), NULL = every inheritable handle */
    unsigned handle_count;
    int use_std;                        /* STARTF_USESTDHANDLES: std[] are the child's standard handles */
    uint64_t std[3];
    int breakaway;                      /* CREATE_BREAKAWAY_FROM_JOB */
} ldr_proc_opts_t;
int32_t ldr_create_process_ex(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                              const ldr_proc_opts_t *opts, process_t **out_proc, thread_t **out_thread);
int ldr_image_fault(process_t *p, vad_t *v, uint64_t addr);          /* page-in of a lazily mapped image page; 0 = ok */
void ldr_release_modules(process_t *p);                             /* frees the loader's per-process records */

/* proc.c */
process_t *current_process(void);
process_t *process_by_pid(int pid);
process_t *process_slot(unsigned i);            /* process table slot i (1-based; check ->used), 0 past the end */
void process_terminate(process_t *p, int64_t code, int faulted);
process_t *process_create_empty(const char *name);
int process_start_thread(process_t *p, uint64_t rip, uint64_t rsp, uint64_t arg, thread_t **out);
/* Starts a user thread at `rip` with RCX = rcx, RDX = rdx on a fresh stack of `stack_size` bytes. */
int process_start_thread2(process_t *p, uint64_t rip, uint64_t rcx, uint64_t rdx, uint64_t stack_size, thread_t **out);
void proc_alloc_peb(process_t *p);
void thread_user_tls_init(process_t *p, thread_t *t);
void process_thread_gone(process_t *p);
uint64_t proc_alloc_teb(process_t *p, uint64_t stack_base, uint64_t stack_limit);

/* objects.c */
kobject_t *ob_create(uint32_t type, const char *name);
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
kobject_t *ob_find_named(uint32_t type, const char *name);
int32_t handle_insert(process_t *p, kobject_t *o, uint32_t access, uint32_t *h_out);
kobject_t *handle_lookup(process_t *p, uint64_t handle, uint32_t type);
/* Looks the handle up and takes a reference on the object in one irq-atomic step (the caller ob_deref()s it). Reports
 * STATUS_INVALID_HANDLE / STATUS_OBJECT_TYPE_MISMATCH; `access` (optional) receives the handle's granted access. */
int32_t handle_ref(process_t *p, uint64_t handle, uint32_t type, kobject_t **out, uint32_t *access);
int32_t handle_close(process_t *p, uint64_t handle);
void handles_close_all(process_t *p);
int32_t ob_wait(process_t *p, kobject_t **objs, unsigned n, int wait_all, int64_t timeout_100ns, int alertable);
void ob_signal_event(kobject_t *o);
void ob_reset_event(kobject_t *o);
void ob_release_check(kobject_t *o);

#define CURRENT_PROCESS_HANDLE ((uint64_t)-1)
#define CURRENT_THREAD_HANDLE ((uint64_t)-2)
#endif
