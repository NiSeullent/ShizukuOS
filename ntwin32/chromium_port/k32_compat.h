/* SPDX-License-Identifier: GPL-2.0-only
 * Portable cores for M98K32CE.DLL, the Win98-native KERNEL32 provider for the
 * NT6+ names imported by Chromium 157 x86 chrome_elf.dll. The Win98 binding
 * lives in k32_native.c; the host test binds the same cores to pthreads.
 *
 * Behavioural references (no code copied): Wine dlls/ntdll/sync.c and
 * dlls/ntdll/version.c (RtlVerifyVersionInfo, VerSetConditionMask),
 * ReactOS sdk/lib/rtl/srw.c and condvar.c, Microsoft SDK documentation.
 */
#ifndef M98_CHROMIUM_K32_COMPAT_H
#define M98_CHROMIUM_K32_COMPAT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* ---- Slim reader/writer locks and condition variables ----------------- */
/* The SRWLOCK word (one pointer, zero == SRWLOCK_INIT): bit 0 exclusive
 * owner, bit 1 "queued waiters exist", bits 2.. shared owner count. Waiters
 * live on their own stacks in one global queue keyed by object address (the
 * NT keyed-event model), so statically initialised locks need no destroy.
 * Release hands ownership directly to queued waiters (FIFO; consecutive
 * shared waiters are granted together), so a waiter never races a newcomer. */
#define K32_SRW_EXCLUSIVE 1u
#define K32_SRW_WAITERS   2u
#define K32_SRW_SHARED    4u

/* Platform services supplied by the linking unit. */
void k32p_lock(void);
void k32p_unlock(void);
void *k32p_thread_event(void);          /* per-thread auto-reset event or NULL */
int k32p_wait(void *event, uint32_t ms);/* 0 signalled, 1 timeout, -1 failed */
void k32p_signal(void *event);
void k32p_yield(void);
uint32_t k32p_ticks(void);
#define K32_INFINITE 0xffffffffu

void k32_srw_acquire(volatile uint32_t *lock, int exclusive);
int k32_srw_try_acquire(volatile uint32_t *lock, int exclusive);
void k32_srw_release(volatile uint32_t *lock, int exclusive);

/* Release/reacquire the caller's lock around a condition wait. */
typedef void (*k32_lock_fn)(void *lock, int shared);
/* Returns 0 woken, 1 timeout, 2 no wait event (lock never released),
 * 3 wait failure. The caller's lock is held again on every return. */
int k32_cv_sleep(volatile uint32_t *cv, void *lock, int shared, uint32_t ms,
                 k32_lock_fn release, k32_lock_fn acquire);
void k32_cv_wake(volatile uint32_t *cv, int all);
/* Number of queued waiters (diagnostic/test only, takes the global lock). */
unsigned k32_queue_depth(void);

/* ---- VerifyVersionInfo / VerSetConditionMask -------------------------- */
enum { K32_VER_MINOR = 0x1, K32_VER_MAJOR = 0x2, K32_VER_BUILD = 0x4,
       K32_VER_PLATFORM = 0x8, K32_VER_SPMINOR = 0x10, K32_VER_SPMAJOR = 0x20,
       K32_VER_SUITE = 0x40, K32_VER_PRODUCT = 0x80 };
enum { K32_VER_EQUAL = 1, K32_VER_GREATER, K32_VER_GREATER_EQUAL, K32_VER_LESS,
       K32_VER_LESS_EQUAL, K32_VER_AND, K32_VER_OR };
enum { K32_VERIFY_OK = 0, K32_VERIFY_MISMATCH = 1, K32_VERIFY_BADARG = 2 };
typedef struct k32_osver {
    uint32_t major, minor, build, platform;
    uint16_t sp_major, sp_minor, suite;
    uint8_t product;
} k32_osver;
uint64_t k32_ver_set_condition_mask(uint64_t mask, uint32_t type, uint8_t condition);
int k32_verify_version(const k32_osver *current, const k32_osver *wanted,
                       uint32_t type, uint64_t conditions);

/* ---- EncodePointer / DecodePointer ------------------------------------ */
uint32_t k32_encode(uint32_t value, uint32_t cookie);
uint32_t k32_decode(uint32_t value, uint32_t cookie);

/* ---- Batch 3: chrome_elf remaining KERNEL32 names ------------------------
 * Vectored exception handlers. Win98 has no first-chance vectored dispatch;
 * the native binding consults this list from its top-level (last-chance)
 * unhandled-exception filter only. Handles are pool node addresses; a
 * removed node stays linked while a dispatch holds a reference. */
#define K32_VEH_MAX 64u
typedef long (*k32_veh_invoke)(void *handler, void *pointers);
void *k32_veh_add(int first, void *handler);
int k32_veh_remove(void *handle);
long k32_veh_dispatch(void *pointers, k32_veh_invoke invoke); /* -1 continue execution, 0 search */
unsigned k32_veh_count(void);

/* Frame-pointer walk bounded to [low, high); each frame is {saved fp, return}.
 * Stops at the first misaligned, out-of-range, non-increasing or zero frame. */
unsigned k32_walk_frames(uintptr_t fp, uintptr_t low, uintptr_t high, unsigned skip,
                         unsigned count, void **out, uint32_t *hash);

/* SYSTEM_LOGICAL_PROCESSOR_INFORMATION (x86 layout, 24 bytes per entry) from
 * the real active processor mask: one core per bit, one package, NUMA node 0.
 * No cache entries: Win98 has no cache descriptor source. */
#define K32_LPI_ENTRY 24u
enum { K32_LPI_OK = 0, K32_LPI_SHORT = 1, K32_LPI_BADARG = 2 };
int k32_logical_processor_info(uint32_t active_mask, uint8_t *buffer, uint32_t *length);

/* COMPUTER_NAME_FORMAT 0..7 composed from real NetBIOS name and MSTCP host and
 * domain. Returns length, -1 bad format/arg, -2 output too small (needed+1 in *need). */
int k32_compose_computer_name(unsigned format, const char *netbios, const char *dns_host,
                              const char *dns_domain, char *out, unsigned cap, unsigned *need);

/* Images mapped by the NTWPE32 private loader (not Win98 modules). */
#define K32_IMAGE_MAX 32u
#define K32_IMAGE_PATH 260u
int k32_image_register(uintptr_t base, uint32_t size, const char *path);
int k32_image_unregister(uintptr_t base);
int k32_image_find(uintptr_t address, uintptr_t *base, uint32_t *size, char *path, unsigned cap);
int k32_image_by_name(const char *name, uintptr_t *base);
unsigned k32_image_list(uintptr_t *bases, unsigned cap);

#ifdef __cplusplus
}
#endif
#endif
