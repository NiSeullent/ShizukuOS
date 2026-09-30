/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: internal interfaces shared by the kernel image loader
 * (ntdrv_ldr.c), the WDM provider core (ntdrv_io/ke/mm/rtl/zw.c), the export tables
 * (ntdrv_prov.c) and the self-test (ntdrv_test.c). See docs/shizukudos10/NTDRV.md.
 *
 * A loaded .sys is an unmodified Windows x64 kernel image. It runs in ring 0 in the kernel
 * address space and calls the provider functions through their import table. Because the
 * kernel is built System-V and the driver is built Microsoft-x64, every function whose
 * address the driver can reach carries NTAPI (ms_abi); the boundary is honoured on both
 * directions of every call.
 */
#ifndef K64_NTDRV_H
#define K64_NTDRV_H
#include "proc_internal.h"
#include "ntddk.h"

/* NTSTATUS values the driver ABI needs beyond ntsys.h's set (same numeric values as Windows). */
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010)
#define STATUS_NO_SUCH_DEVICE ((int32_t)0xC000000E)
#define STATUS_DEVICE_NOT_READY ((int32_t)0xC00000A3)
#define STATUS_PROCEDURE_NOT_FOUND ((int32_t)0xC000007A)
#define STATUS_INVALID_DEVICE_STATE ((int32_t)0xC0000184)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((int32_t)0xC0000182)
#define STATUS_MORE_PROCESSING_REQUIRED ((int32_t)0xC0000016)
#define STATUS_IMAGE_ALREADY_LOADED ((int32_t)0xC000010E)

/* Driver image VA window (kernel half, above the direct map, below the image alias). Each
 * loaded .sys gets a naturally sized, page-granular slice; images are mapped, relocated and
 * import-resolved here, never in any user address space. */
#define NTDRV_VA_END  (NTDRV_VA_BASE + 0x40000000ull)   /* 1 GiB of driver image space; NTDRV_VA_BASE is in k64.h */

/* ---- provider export tables (ntdrv_prov.c) ---- */
typedef struct { const char *name; void *fn; } ntdrv_export_t;
extern const ntdrv_export_t ntdrv_ntoskrnl_exports[];
extern const ntdrv_export_t ntdrv_hal_exports[];
extern const unsigned ntdrv_ntoskrnl_export_count, ntdrv_hal_export_count;
/* Resolve `symbol` in the module named `dll` ("ntoskrnl.exe" / "hal.dll"); 0 if absent. */
void *ntdrv_resolve_export(const char *dll, const char *symbol);

/* ---- loaded driver / device namespace (ntdrv_io.c, ntdrv_ldr.c) ---- */
typedef struct ntdrv_driver {
    struct ntdrv_driver *next;
    char name[64];                      /* service name, e.g. "echo" */
    uint64_t image_base, image_size;    /* kernel VA of the mapped image */
    DRIVER_OBJECT *drv;                 /* the DRIVER_OBJECT passed to DriverEntry */
    UNICODE_STRING regpath;             /* \Registry\Machine\System\...\Services\<name> */
    WCHAR regpath_buf[160];
    int started;                        /* DriverEntry returned STATUS_SUCCESS */
    char claim[72];                     /* "ntdrv:<service>": pci_claim() owner string for functions it drives */
} ntdrv_driver_t;

/* device object bookkeeping kept beside the Windows DEVICE_OBJECT the driver sees */
typedef struct ntdrv_devnode {
    struct ntdrv_devnode *next;
    DEVICE_OBJECT *dev;
    char name[96];                      /* "\Device\Echo" */
    ntdrv_driver_t *owner;
} ntdrv_devnode_t;

typedef struct ntdrv_symlink {
    struct ntdrv_symlink *next;
    char link[96];                      /* "\DosDevices\Echo" / "\??\Echo" */
    char target[96];                    /* "\Device\Echo" */
} ntdrv_symlink_t;

DEVICE_OBJECT *ntdrv_find_device(const char *device_name);        /* "\Device\X" */
DEVICE_OBJECT *ntdrv_resolve_symlink(const char *dosname);        /* "\??\X" or "\DosDevices\X" -> device */
void ntdrv_register_device(DEVICE_OBJECT *dev, ntdrv_driver_t *owner);
ntdrv_driver_t *ntdrv_current_driver(void);                       /* the driver whose DriverEntry is running */
void ntdrv_set_current_driver(ntdrv_driver_t *d);

/* ---- loader (ntdrv_ldr.c) ---- */
/* Loads a .sys from `image`/`size` at a kernel VA, relocates, resolves ntoskrnl/hal imports,
 * builds a DRIVER_OBJECT and calls DriverEntry(DriverObject, RegistryPath). One diagnostic
 * line is printed per unresolved import. `service` names the Services key (for RegistryPath
 * and the driver record). *out receives the driver record. */
int32_t ntdrv_load_image(const uint8_t *image, uint64_t size, const char *service, ntdrv_driver_t **out);
int32_t ntdrv_unload(ntdrv_driver_t *d);
ntdrv_driver_t *ntdrv_find_driver(const char *service);           /* a started driver of that service, or NULL */
ntdrv_driver_t *ntdrv_driver_by_address(uint64_t va);            /* the loaded image containing va, or NULL */
struct fsnode;
int32_t ntdrv_load_node(struct fsnode *n, const char *service, ntdrv_driver_t **out);   /* RAM or disk-backed file */
uint64_t ntdrv_alloc_image_va(uint64_t bytes);                    /* reserve a slice of the driver VA window */

/* ---- PCI ownership (ntdrv_io.c): MmMapIoSpace inside a function's memory BAR claims it for the current driver ---- */
void ntdrv_pci_note_mmio(uint64_t pa, uint64_t size);

/* ---- IRP engine (ntdrv_io.c) ---- */
/* Synchronous device control entirely on kernel buffers: builds an IRP, IoCallDriver()s the
 * device's driver stack, waits for completion (honouring a pended IRP), returns the driver's
 * NTSTATUS and *info = IoStatus.Information. Used by both the user syscall path and the
 * kernel self-test. `internal` selects IRP_MJ_INTERNAL_DEVICE_CONTROL. */
int32_t ntdrv_device_control(DEVICE_OBJECT *dev, uint32_t ioctl, const void *in, uint32_t inlen,
                             void *out, uint32_t outlen, int internal, uint64_t *info);
/* Synchronous read/write (IRP_MJ_READ / IRP_MJ_WRITE) on kernel buffers. */
int32_t ntdrv_read_write(DEVICE_OBJECT *dev, int write, void *buf, uint32_t len, uint64_t offset, uint64_t *info);
/* IRP_MJ_CREATE / IRP_MJ_CLOSE against a device (returns the driver's status). */
int32_t ntdrv_open_close_device(DEVICE_OBJECT *dev, int close);

/* ---- Ke/Ex runtime services used across provider files (ntdrv_ke.c/mm.c) ---- */
void ntdrv_ke_init(void);                                         /* DPC worker + timer thread */
uint8_t ntdrv_current_irql(void);
void ntdrv_kuser_init(void);                                      /* ntdrv_kuser.c */
void ntdrv_kuser_tick(void);
uint64_t ntdrv_gs_enter(void);                                    /* GS base := this thread's KPCR; returns the old base */
uint64_t ntdrv_gs_enter_isr(void);                                /* same, for interrupt context (no allocation) */
void ntdrv_gs_leave(uint64_t previous);
void ntdrv_dpc_queue_flush(void);
void NTAPI KeAcquireSpinLock(KSPIN_LOCK *l, uint8_t *old);
void NTAPI KeReleaseSpinLock(KSPIN_LOCK *l, uint8_t old);
void NTAPI KeInitializeEvent(KEVENT *e, uint32_t type, uint8_t state);
LONG NTAPI KeSetEvent(KEVENT *e, LONG boost, uint8_t wait);
int32_t NTAPI KeWaitForSingleObject(void *obj, uint32_t reason, uint8_t mode, uint8_t alertable, int64_t *timeout);
MDL *NTAPI IoAllocateMdl(void *va, uint32_t len, uint8_t secondary, uint8_t charge, IRP *irp);

/* ---- self-test (ntdrv_test.c), invoked once from kmain when \SHZ\DRIVERS exists ---- */
void ntdrv_selftest(void);

/* Shared string helpers. */
int ntdrv_ascii_to_wide(const char *s, WCHAR *out, unsigned cap);
int ntdrv_wide_to_ascii(const WCHAR *s, unsigned chars, char *out, unsigned cap);

/* Kernel-mode handle table (ntdrv_zw.c): a small namespace for the handles a driver holds --
 * registry keys (ZwOpenKey), files (ZwCreateFile) and system threads (PsCreateSystemThread).
 * Separate from the per-process user handle tables. */
enum { KH_NONE = 0, KH_KEY = 1, KH_FILE = 2, KH_THREAD = 3, KH_EVENT = 4, KH_DEVICE = 5, KH_DRIVER = 6, KH_PROCESS = 7,
       KH_SEMAPHORE = 8, KH_DIR = 9, KH_SECTION = 10 };
uint64_t ntdrv_kh_alloc(int kind, void *ptr);
void *ntdrv_kh_get(uint64_t handle, int kind);
int ntdrv_kh_free(uint64_t handle);

#endif
