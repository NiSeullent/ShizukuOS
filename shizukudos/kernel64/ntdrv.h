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
#include "pci.h"
#include "registry.h"

/* NTSTATUS values the driver ABI needs beyond ntsys.h's set (same numeric values as Windows). */
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010)
#define STATUS_NO_SUCH_DEVICE ((int32_t)0xC000000E)
#define STATUS_DEVICE_NOT_READY ((int32_t)0xC00000A3)
#define STATUS_PROCEDURE_NOT_FOUND ((int32_t)0xC000007A)
#define STATUS_INVALID_DEVICE_STATE ((int32_t)0xC0000184)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((int32_t)0xC0000182)
#define STATUS_MORE_PROCESSING_REQUIRED ((int32_t)0xC0000016)
#define STATUS_IMAGE_ALREADY_LOADED ((int32_t)0xC000010E)
#define STATUS_CONNECTION_IN_USE ((int32_t)0xC0000108)
#define STATUS_OBJECT_NAME_COLLISION ((int32_t)0xC0000035)
#define STATUS_NO_MORE_ENTRIES ((int32_t)0x8000001A)

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
#define NTDRV_MAX_DEPS 8u              /* one capacity for import collection and retained references */
typedef struct ntdrv_driver {
    struct ntdrv_driver *next;
    char name[64];                      /* service name, e.g. "echo" */
    uint64_t image_base, image_size;    /* kernel VA of the mapped image */
    DRIVER_OBJECT *drv;                 /* the DRIVER_OBJECT passed to DriverEntry */
    UNICODE_STRING regpath;             /* \Registry\Machine\System\...\Services\<name> */
    WCHAR regpath_buf[160];
    int started;                        /* DriverEntry returned STATUS_SUCCESS */
    char claim[72];                     /* "ntdrv:<service>": pci_claim() owner string for functions it drives */
    uint32_t export_rva, export_size;   /* the image's export directory (an export driver such as ndis.sys) */
    unsigned users;                     /* loaded images whose imports were resolved against this one */
    int dependency;                     /* loaded because an image imports it, not by a Services-key request */
    struct ntdrv_driver *deps[NTDRV_MAX_DEPS]; /* modules this image imports from (their `users` count it) */
    unsigned ndeps;
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
/* NtUnloadDriver's work: STATUS_OBJECT_NAME_NOT_FOUND (not loaded), STATUS_CONNECTION_IN_USE (another loaded image
 * imports from it), STATUS_INVALID_DEVICE_REQUEST (the driver has no DriverUnload routine: it stays loaded, as on
 * Windows), else DriverUnload runs, its PCI claims are released and the record is marked not started. */
int32_t ntdrv_unload_service(const char *service);
ntdrv_driver_t *ntdrv_find_driver(const char *service);           /* a started driver of that service, or NULL */
ntdrv_driver_t *ntdrv_drivers(void);                              /* every record (started or not), newest first */
/* Export drivers: a loaded image another driver imports from ("ndis.sys" -> the record named "ndis"). The loader
 * resolves a non-ntoskrnl/hal import by loading \SHZ\SYS64\DRIVERS\<dll> on demand (its DriverEntry runs, as a
 * boot-start service's would) and looking the symbol up in that image's export directory. */
ntdrv_driver_t *ntdrv_find_module(const char *dllname);
void *ntdrv_module_export(ntdrv_driver_t *m, const char *symbol);
ntdrv_driver_t *ntdrv_driver_by_address(uint64_t va);            /* the loaded image containing va, or NULL */
struct fsnode;
int32_t ntdrv_load_node(struct fsnode *n, const char *service, ntdrv_driver_t **out);   /* RAM or disk-backed file */
uint64_t ntdrv_alloc_image_va(uint64_t bytes);                    /* reserve a slice of the driver VA window */

/* ---- PCI ownership (ntdrv_io.c): MmMapIoSpace inside a function's memory BAR claims it for the current driver ---- */
void ntdrv_pci_note_mmio(uint64_t pa, uint64_t size);
/* Claim every PCI function whose Enum key (HKLM\SYSTEM\CurrentControlSet\Enum\PCI\<hwid>\B<bus>D<dev>F<fn>,
 * written by shzpnp add-driver --install) names this service in `Service`: the devnode -> function-driver binding. */
void ntdrv_bind_enum(ntdrv_driver_t *d);
void ntdrv_release_claims(ntdrv_driver_t *d);                     /* drop every pci_claim made for d */
unsigned ntdrv_claimed_functions(ntdrv_driver_t *d, pci_dev_t *out, unsigned max);
ntdrv_devnode_t *ntdrv_devnodes(void);                            /* named device objects, newest first */

/* ---- PnP root (ntdrv_pnp.c): one PDO per Enum\PCI devnode bound to a hosted driver ---- */
typedef struct ntdrv_pdo ntdrv_pdo_t;
/* Called under the registry lock for each Enum\PCI\<hwid>\B..D..F.. key whose Service names d: records the devnode
 * (its Driver, DeviceDesc, ClassGUID, HardwareID values) and creates its PDO on the host's PnP root driver. */
void ntdrv_pnp_add(ntdrv_driver_t *d, const pci_dev_t *dev, regkey_t *inst_key, const char *instance_path);
/* AddDevice(DriverObject, PDO) + IRP_MN_START_DEVICE (with the function's BARs and interrupt as CM_RESOURCE_LIST)
 * for every PDO recorded for d and not yet started; a driver without AddDevice keeps its claim and gets no IRP. */
void ntdrv_pnp_start_pending(ntdrv_driver_t *d);
void ntdrv_pnp_driver_unloading(ntdrv_driver_t *d);              /* drop the PDOs whose function driver is going away */
/* IRP_MN_QUERY_REMOVE_DEVICE + IRP_MN_REMOVE_DEVICE down every started stack of d; a refused query returns its status. */
int32_t ntdrv_pnp_remove_devices(ntdrv_driver_t *d);
ntdrv_pdo_t *ntdrv_pdo_from_device(DEVICE_OBJECT *dev);
/* IofCallDriver + wait for completion (a pended IRP included) + IoFreeIrp; returns IoStatus.Status (ntdrv_io.c). */
int32_t ntdrv_send_irp_sync(DEVICE_OBJECT *dev, IRP *irp, uint64_t *info);

/* ---- boot-time driver bring-up (ntdrv_pnp.c): enumeration -> catalog match -> existing init owners -> report ----
 * shz_driver_bringup_init(bootinfo, SHZ_BRINGUP_PHASE_EARLY|DEVICES, flags) is the single Core64 boot entry; the row
 * and report layouts live in drivers/common/shz_bringup.h (fixed width, no kernel pointers). */
#include "../../drivers/common/shz_bringup.h"
/* ntdrv_catalog.c: installed driver catalog v2 importer (drivers/common/shz_catalog.h). Import once before DEVICES loads
 * services: 0 imported, 1 absent, < 0 rejected as a whole. */
int ntdrv_catalog_import(void);
void ntdrv_catalog_report(shz_bringup_report_t *r);
uint64_t ntdrv_install_generation(void);           /* k64_install_generation() when install_identity.h exists, else 0 */
/* NtLoadDriver's kernel core (ntdrv_io.c): load the Services\<name> image, bind its Enum\PCI devnodes, AddDevice and
 * IRP_MN_START_DEVICE. `w` is the "\Registry\Machine\System\CurrentControlSet\Services\<name>" object path. */
int32_t ntdrv_load_service_path(const uint16_t *w, unsigned chars);
void ntdrv_send_shutdown(void);                                   /* ntdrv_dev.c: IRP_MJ_SHUTDOWN to registered devices */

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
