/* SPDX-License-Identifier: GPL-2.0-only
 * Domains: one guest kernel instance each, with its own vCPU (VMCS), EPT, RAM and
 * VMX-exit policy. The Supervisor time-slices them on the boot CPU. A failure inside
 * one domain marks only that domain FAILED; the others keep running.
 */
#ifndef SHZ_DOMAIN_H
#define SHZ_DOMAIN_H
#include <stdarg.h>
#include <stdint.h>
#include "caps.h"
#include "ept.h"
#include "vmx.h"
#include "../include/shz_info.h"
#include "../../abi/shz_abi.h"

typedef enum { DK_DOS16 = 0, DK_KERNEL32 = 1, DK_KERNEL64 = 2, DK_WIN98 = 3 } dom_kind_t;

typedef struct domain {
    uint32_t id;
    const char *name;
    dom_kind_t kind;
    uint32_t state;                     /* enum shz_domain_state */
    uint32_t generation;
    vcpu_t vc;
    ept_t ept;
    uint64_t guest_cr2;                 /* opt-in mixed Win98/K64 fault context */
    uint64_t ram_base, ram_size;        /* private RAM: guest-physical [0, ram_size) */
    uint8_t *io_bitmap_a, *io_bitmap_b, *msr_bitmap;
    /* paravirtual timer and doorbell (Kernel32/Kernel64) */
    uint64_t timer_next, timer_period;  /* TSC ticks */
    uint8_t timer_vector;
    uint8_t doorbell_vector;
    uint32_t doorbell_pending;
    uint8_t doorbell_signaled;
    uint64_t wake_hint;
    uint64_t last_snapshot_tsc;
    uint8_t fx[512] __attribute__((aligned(16)));
    /* shared IPC windows mapped into this domain */
    struct { uint64_t hpa; uint32_t peer; uint8_t mapped; } chan[SHZ_MAX_CHANNELS];
} domain_t;

extern domain_t g_dom[SHZ_MAX_DOMAINS];
extern shz_info_t *g_info;
extern uint64_t g_tsc_hz;

/* Creation (each returns 0 or -1 with info->last_error set). */
int dos_domain_create(shz_info_t *info, const shz_caps_t *caps, const uint8_t *vbios, unsigned vbios_len);
int kernel_domain_create(shz_info_t *info, const shz_caps_t *caps, dom_kind_t kind);
int ipc_channels_create(shz_info_t *info);

void vmx_snapshot(shz_vmcs_snapshot_t *dst);
int vmx_hw_init(shz_info_t *info, const shz_caps_t *caps);
int vmx_vcpu_init(vcpu_t *vc, shz_info_t *info, const shz_caps_t *caps, const vmx_cfg_t *cfg);
void vmx_set_interrupt_window(vcpu_t *vc, int on);
void vmx_inject_external(uint8_t vector);
void vmx_inject_exception(uint8_t vector, int has_error, uint32_t error);
int vmx_guest_interruptible(void);

/* Scheduler. Returns when no domain can run any more. */
int sched_run(shz_info_t *info);

/* Common helpers used by the per-kind exit handlers. */
void dom_fail(domain_t *d, const char *fmt, ...);
void dom_exit(domain_t *d, uint32_t code);
uint8_t *dom_gpa_ptr(domain_t *d, uint64_t gpa, uint64_t len);
void dom_advance_rip(void);
void dom_console(domain_t *d, const uint8_t *data, unsigned len);
int hcall_vmcall(domain_t *d);                  /* SHZ_HC_* dispatcher */

/* DOS16-specific exit handling (dos.c). */
int dos_handle_exit(domain_t *d, uint32_t reason);   /* 1 = handled, 0 = not a DOS-specific exit */
int dos_ready(domain_t *d, uint64_t now);
void dos_housekeeping(void);
uint64_t dos_next_event_tsc(void);
#endif
