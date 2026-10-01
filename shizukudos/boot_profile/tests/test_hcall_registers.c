/* SPDX-License-Identifier: GPL-2.0-only
 * Real production VMCALL instructions, trapped only at the privileged boundary.
 * C caller values must survive dispatcher RCX replies under optimization.
 * No Supervisor, VM or Windows is executed by this host fixture.
 */
#ifndef SHZ_HCALL_COMPILE_ONLY
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#endif
#include "../../kcommon/khc.h"

__attribute__((noinline))
long hcall_register_probe(hcreg_t opcode, hcreg_t argument,
                         hcreg_t live_d, hcreg_t live_c, hcreg_t observed[3])
{
    hcreg_t value = 0;
    const long status = shz_hcall(opcode, argument, live_c, &value);
    observed[0] = live_c;
    observed[1] = live_d;
    observed[2] = value;
    return status;
}

__attribute__((noinline))
long hcall_null_result_probe(hcreg_t opcode, hcreg_t argument,
                            hcreg_t live_d, hcreg_t live_c, hcreg_t observed[3])
{
    const long status = shz_hcall(opcode, argument, live_c, NULL);
    observed[0] = live_c;
    observed[1] = live_d;
    observed[2] = 0;
    return status;
}

#ifndef SHZ_HCALL_COMPILE_ONLY
#if !defined(__x86_64__) || defined(SHZ_STANDALONE)
#error Host trap fixture requires Linux x86-64 native hypercall branch
#endif

static volatile sig_atomic_t traps, bad_inputs;
static hcreg_t expected_opcode, expected_argument, expected_c;
static hcreg_t reply_value, reply_c;
static long reply_status;
static int change_c;

static void vmcall_boundary(int signal_number, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    greg_t *r = uc->uc_mcontext.gregs;
    const unsigned char *ip = (const unsigned char *)(uintptr_t)r[REG_RIP];
    (void)info;
    if ((signal_number != SIGILL && signal_number != SIGSEGV) ||
        ip[0] != 0x0f || ip[1] != 0x01 || ip[2] != 0xc1)
        _exit(90);
    if ((hcreg_t)r[REG_RAX] != expected_opcode ||
        (hcreg_t)r[REG_RBX] != expected_argument ||
        (hcreg_t)r[REG_RCX] != expected_c)
        bad_inputs = 1;
    ++traps;
    r[REG_RAX] = (greg_t)reply_status;
    r[REG_RBX] = (greg_t)reply_value;
    if (change_c)
        r[REG_RCX] = (greg_t)reply_c;
    /* Current hcall_vmcall preserves RDX and every other general register. */
    r[REG_RIP] += 3;
}

int main(int argc, char **argv)
{
    struct sigaction action;
    hcreg_t observed[3] = {0, 0, 0};
    const hcreg_t live_d = UINT64_C(0x713579bd2468ace0);
    const hcreg_t live_c = UINT64_C(0x13579bdf2468ace0);
    long status;
    int null_result = 0;
    if (argc != 2)
        return 89;
    expected_c = live_c;
    reply_status = SHZ_OK;
    change_c = 1;
    if (!strcmp(argv[1], "domain-state")) {
        expected_opcode = SHZ_HC_DOMAIN_STATE;
        expected_argument = SHZ_DOM_WIN98;
        reply_value = SHZ_DS_WAITING;
        reply_c = 17;
    } else if (!strcmp(argv[1], "channel-info")) {
        expected_opcode = SHZ_HC_CHANNEL_INFO;
        expected_argument = 2;
        reply_value = UINT64_C(0xe0200000);
        reply_c = SHZ_DOM_KERNEL64;
    } else if (!strcmp(argv[1], "domain-error")) {
        expected_opcode = SHZ_HC_DOMAIN_STATE;
        expected_argument = SHZ_DOM_MAX;
        reply_status = SHZ_E_NOENT;
        reply_value = expected_argument;
        change_c = 0;
    } else if (!strcmp(argv[1], "time-64")) {
        expected_opcode = SHZ_HC_TIME;
        expected_argument = 0;
        reply_value = UINT64_C(0x123456789abcdef0);
        change_c = 0;
    } else if (!strcmp(argv[1], "null-result")) {
        expected_opcode = SHZ_HC_DOMAIN_STATE;
        expected_argument = SHZ_DOM_WIN98;
        reply_value = SHZ_DS_EXITED;
        reply_c = 99;
        null_result = 1;
    } else {
        return 88;
    }
    memset(&action, 0, sizeof action);
    action.sa_sigaction = vmcall_boundary;
    action.sa_flags = SA_SIGINFO;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGILL, &action, NULL) ||
        sigaction(SIGSEGV, &action, NULL))
        return 87;
    status = null_result ? hcall_null_result_probe(expected_opcode, expected_argument,
                                                  live_d, live_c, observed) :
                           hcall_register_probe(expected_opcode, expected_argument,
                                                live_d, live_c, observed);
    if (traps != 1 || bad_inputs || status != reply_status ||
        observed[0] != live_c || observed[1] != live_d ||
        observed[2] != (null_result ? 0 : reply_value)) {
        fprintf(stderr, "FAIL %s: traps=%d inputs=%d status=%ld/%ld live_c=%llx/%llx live_d=%llx/%llx result=%llx/%llx; host VMCALL boundary only\n",
                argv[1], (int)traps, (int)bad_inputs, status, reply_status,
                (unsigned long long)observed[0], (unsigned long long)live_c,
                (unsigned long long)observed[1], (unsigned long long)live_d,
                (unsigned long long)observed[2],
                (unsigned long long)(null_result ? 0 : reply_value));
        return 1;
    }
    printf("PASS %s: 6 real-helper checks, dispatcher register replies modeled; no VM executed\n", argv[1]);
    return 0;
}
#endif
