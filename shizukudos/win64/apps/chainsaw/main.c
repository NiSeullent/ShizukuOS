/* SPDX-License-Identifier: GPL-2.0-only
 * Native ShizukuOS process teardown companion. Detection and all mutations
 * come from NtShzSaw; compatible Win32 termination APIs remain untouched.
 * RM/PSP/other kernel contexts are never invented for a native PE64 process.
 */
#include "nt.h"
#include "shzcrt.h"
#include "args.h"
#include "reply.h"
#include <string.h>
NTSTATUS NTAPI NtShzSaw(ULONG_PTR request, ULONG_PTR request_bytes, ULONG_PTR reply, ULONG_PTR reply_bytes);
static shz_saw_reply snapshot, result;

static void warning(void)
{
    printf("==================================================\nCHARBOMBA: DESTRUCTIVE FORCED TEARDOWN\n==================================================\n");
    printf("Root Mode / CLOSED AIR DEFENSE state is normally protected.\nForced teardown can cause immediate kernel panic, invalid references,\ndeadlocks, memory corruption, filesystem/data loss and forced reboot.\nYour computer may be trashed.\n");
    printf("No automatic escalation. To acknowledge this exact target use:\n  /charbomba --ack-destructive=PID:GENERATION\nInspect the current generation with CHAINSAW /list /verbose first.\n");
}
static void usage(void)
{
    printf("CHAINSAW.exe: ShizukuOS ZOMBIE DETECTOR\nCHAINSAW [/zombies | /list] [/verbose]\nCHAINSAW SAW <PID | exact-name.exe> [/verbose]\nCHAINSAW SAW <target> /nuke [/verbose]\nCHAINSAW SAW <target> /charbomba --ack-destructive=PID:GENERATION [/verbose]\n");
    printf("SAW is also accepted in the desktop Run dialog. A name must match\none exact process name, case-insensitively. Waiting, suspended and\nsleeping processes are not zombies without a teardown contradiction.\nCHARBOMBA has no implicit /force or automatic retry.\n");
}
static const char *class_name(uint32_t c)
{
    switch (c) { case SHZ_SAW_ZOMBIE: return "ZOMBIE"; case SHZ_SAW_ADMISSED: return "ADMISSED ZOMBIE";
    case SHZ_SAW_ARMORED: return "ARMORED ZOMBIE"; default: return "NORMAL"; }
}
static const char *life_name(uint32_t l)
{
    switch (l) { case SHZ_SAW_EXIT_PENDING: return "exit pending"; case SHZ_SAW_EXITED: return "exited";
    case SHZ_SAW_RUNNING: return "running"; default: return "unavailable"; }
}
static void reasons(uint32_t r)
{
    if (r & SHZ_SAW_REASON_WAIT_REFS) printf("  reason: exited process object intentionally retained by wait/handle references\n");
    if (r & SHZ_SAW_REASON_EXIT_PENDING) printf("  reason: process termination requested; execution remains\n");
    if (r & SHZ_SAW_REASON_NO_TEARDOWN) printf("  reason: no live threads but resource teardown incomplete\n");
    if (r & SHZ_SAW_REASON_LIVE_AFTER_SIGNAL) printf("  reason: live execution after process exit signal\n");
    if (r & SHZ_SAW_REASON_RESOURCES_AFTER_TEARDOWN) printf("  reason: resources remain after completed teardown\n");
    if (r & SHZ_SAW_REASON_KERNEL_WAIT) printf("  reason: thread has not left its kernel wait safely\n");
    if (r & SHZ_SAW_REASON_ROOT_BOUNDARY) printf("  boundary: CLOSED AIR DEFENSE / Root Mode or critical owner\n");
    if (r & SHZ_SAW_REASON_IDENTITY) printf("  refusal: PID/generation identity changed; rerun detector\n");
    if (r & SHZ_SAW_REASON_ACCESS) printf("  refusal: access/privilege boundary\n");
    if (r & SHZ_SAW_REASON_TEARDOWN_BUSY) printf("  reason: teardown in progress; unsafe to reclaim concurrently\n");
    if (r & SHZ_SAW_REASON_ANCESTRY) printf("  refusal: process-tree ownership could not be established safely\n");
    if (r & SHZ_SAW_REASON_FORCE_ACK) printf("  refusal: destructive acknowledgement or force-privilege policy rejected\n");
    if (r & SHZ_SAW_REASON_SELF) printf("  refusal: target includes this CHAINSAW process\n");
    if (r & SHZ_SAW_REASON_THREAD_ACCOUNTING) printf("  reason: live thread accounting contradicts scheduler state\n");
}
static void row_print(const shz_saw_row *p, unsigned verbose)
{
    char display[32]; unsigned i;
    if (!p->pid) {
        printf("[INACCESSIBLE] Process-tree descendant details withheld by account boundary.\n");
        reasons(p->reasons); return;
    }
    if (!p->lifecycle) {
        printf("[REQUEST REJECTED] PID %llu requested generation=%llu status=%08x\n",
               (unsigned long long)p->pid, (unsigned long long)p->generation, (unsigned)p->status);
        reasons(p->reasons); return; /* no observed state: do not invent a NORMAL classification */
    }
    for (i = 0; i + 1 < sizeof display && p->name[i]; ++i) {
        unsigned c = (unsigned char)p->name[i]; display[i] = c >= 32 && c < 127 ? (char)c : '?';
    }
    display[i] = 0;
    printf("[%s] PID %llu %s\n", class_name(p->classification), (unsigned long long)p->pid, display);
    if (p->protection & SHZ_SAW_PROTECT_ROOT) printf("  protection: CLOSED AIR DEFENSE (Root Mode)\n");
    if (p->protection & SHZ_SAW_PROTECT_CRITICAL) printf("  protection: critical system owner\n");
    if (verbose) {
        printf("  generation=%llu parent=%llu lifecycle=%s status=%08x\n", (unsigned long long)p->generation,
               (unsigned long long)p->parent_pid, life_name(p->lifecycle), (unsigned)p->status);
        printf("  threads=%u references=%u handles=%u vads=%u\n", (unsigned)p->threads,
               (unsigned)p->references, (unsigned)p->handles, (unsigned)p->vads);
        if (p->contexts & SHZ_SAW_CONTEXT_KERNEL64) printf("  context: ShizukuOS Kernel64 native task\n");
        if (p->contexts & SHZ_SAW_CONTEXT_ADDRESS_SPACE) printf("  context: native address space\n");
        if (p->contexts & SHZ_SAW_CONTEXT_HANDLES) printf("  context: native handle table\n");
        if (p->contexts & SHZ_SAW_CONTEXT_IPC) printf("  context: native IPC ownership\n");
    }
    if (verbose || p->classification != SHZ_SAW_NORMAL || p->status) reasons(p->reasons);
    if (p->classification == SHZ_SAW_ADMISSED) printf("  Status: continued existence explicitly permitted by retained object policy.\n  Action: ignored.\n");
}
static NTSTATUS call(shz_saw_request *q, shz_saw_reply *r)
{
    memset(r, 0, sizeof *r);
    return NtShzSaw((ULONG_PTR)q, sizeof *q, (ULONG_PTR)r, sizeof *r);
}
static int detect(const cs_args *a)
{
    unsigned i, shown = 0;
    printf("CHAINSAW ZOMBIE DETECTOR\n");
    for (i = 0; i < snapshot.count; ++i) {
        const shz_saw_row *p = &snapshot.rows[i];
        if (a->action != CS_LIST && p->classification == SHZ_SAW_NORMAL) continue;
        row_print(p, a->verbose); ++shown;
    }
    printf("Examined %u process(es); displayed %u. No idle/wait heuristic is used.\n", (unsigned)snapshot.count, shown);
    return 0;
}
static void steps(const shz_saw_row *p)
{
    if (p->steps & SHZ_SAW_STEP_TERMINATION_REQUESTED) printf("[SHIZUKU] PID %llu termination requested.\n", (unsigned long long)p->pid);
    if (p->steps & SHZ_SAW_STEP_THREADS_QUIESCENT) printf("[SHIZUKU] PID %llu native threads quiescent.\n", (unsigned long long)p->pid);
    if (p->steps & SHZ_SAW_STEP_MEMORY_RELEASED) printf("[MEM] PID %llu native address space released.\n", (unsigned long long)p->pid);
    if (p->steps & SHZ_SAW_STEP_HANDLES_CLOSED) printf("[HANDLE] PID %llu native handle table closed.\n", (unsigned long long)p->pid);
    if (p->steps & SHZ_SAW_STEP_IPC_RELEASED) printf("[IPC] PID %llu native IPC references detached.\n", (unsigned long long)p->pid);
}
int main(int argc, char **argv)
{
    cs_args a; const char *error; shz_saw_request q;
    const shz_saw_row *target = 0; unsigned i, matches = 0; NTSTATUS st;
    if (!cs_parse(argc, argv, &a, &error)) {
        if (a.action == CS_CHARBOMBA) warning();
        printf("CHAINSAW: %s\n", error); usage(); return 2;
    }
    if (a.action == CS_HELP) { usage(); return 0; }
    memset(&q, 0, sizeof q); q.version = SHZ_SAW_VERSION; q.size = sizeof q; q.operation = SHZ_SAW_QUERY;
    st = call(&q, &snapshot);
    if (st) { printf("CHAINSAW backend unavailable/refused: %08x\n", (unsigned)st); return 1; }
    if (!cs_reply_valid(&snapshot) || snapshot.status) { printf("CHAINSAW snapshot rejected: invalid/error kernel reply.\n"); return 1; }
    for (i = 0; i < snapshot.count; ++i) if (snapshot.rows[i].status || !snapshot.rows[i].generation ||
        snapshot.rows[i].lifecycle < SHZ_SAW_RUNNING) { printf("CHAINSAW snapshot rejected: incomplete process identity.\n"); return 1; }
    if (a.action == CS_LIST || a.action == CS_DETECT) return detect(&a);
    for (i = 0; i < snapshot.count; ++i) {
        const shz_saw_row *p = &snapshot.rows[i];
        if (a.numeric ? p->pid == a.pid : cs_name_equal(p->name, a.name)) { target = p; ++matches; }
    }
    if (matches != 1) {
        printf("CHAINSAW: target %s; no teardown performed.\n", matches ? "name is ambiguous" : "not found or not accessible");
        if (matches) for (i = 0; i < snapshot.count; ++i) if (cs_name_equal(snapshot.rows[i].name, a.name)) row_print(&snapshot.rows[i], 1);
        return 2;
    }
    row_print(target, a.verbose);
    if (a.action == CS_CHARBOMBA) {
        warning();
        if (!cs_ack_matches(&a, (uint32_t)target->pid, target->generation)) {
            printf("CHARBOMBA cancelled: acknowledgement does not match this PID/generation.\n"); return 2;
        }
        printf("Explicit destructive acknowledgement accepted for PID %llu generation %llu.\n",
               (unsigned long long)target->pid, (unsigned long long)target->generation);
        q.acknowledgement = SHZ_SAW_DESTRUCTIVE_ACK;
    }
    q.pid = target->pid; q.generation = target->generation; q.wait_ms = SHZ_SAW_MAX_WAIT_MS;
    q.operation = a.action == CS_NUKE ? SHZ_SAW_NUKE : a.action == CS_CHARBOMBA ? SHZ_SAW_CHARBOMBA : SHZ_SAW_SINGLE;
    printf("\xEC\x8D\xA8\xEB\x8A\x94 \xEC\xA4\x91... PID %llu generation %llu\n", (unsigned long long)q.pid, (unsigned long long)q.generation); /* 써는 중... */
    st = call(&q, &result);
    if (!cs_reply_valid(&result) || result.status != (int32_t)st) {
        if (st) printf("SAW backend refused: NTSTATUS=%08x; no valid diagnostic reply. No automatic escalation.\n", (unsigned)st);
        else printf("SAW result rejected: invalid kernel reply; completion unconfirmed.\n");
        return 1;
    }
    matches = 0;
    for (i = 0; i < result.count; ++i) if (result.rows[i].pid == q.pid &&
        result.rows[i].generation == q.generation) ++matches;
    if (!result.status && matches != 1) {
        printf("SAW result rejected: requested PID/generation missing; completion unconfirmed.\n"); return 1;
    }
    if (a.action == CS_NUKE) printf("[NUKE]\nRoot PID: %llu\nDescendants acquired: %u\nTargets acquired: %u\n",
        (unsigned long long)q.pid, result.targets ? (unsigned)result.targets - 1u : 0u, (unsigned)result.targets);
    for (i = 0; i < result.count; ++i) { row_print(&result.rows[i], a.verbose); steps(&result.rows[i]); }
    if (cs_reply_sawed(&result)) {
        printf(a.action == CS_NUKE ? "PROCESS TREE SAWED.\n" : "SAWED.\n"); return 0;
    }
    if (result.flags & SHZ_SAW_REPLY_PROTECTED) {
        printf(a.action == CS_NUKE ? "[NUKE FAILED]\n" : "[SAW REFUSED]\n");
        printf("CLOSED AIR DEFENSE / critical ownership boundary. No automatic escalation.\n");
    }
    if (result.flags & SHZ_SAW_REPLY_PENDING) printf("SAW PENDING: kernel execution has not quiesced; resources retained safely.\n");
    if (result.flags & SHZ_SAW_REPLY_ADMITTED) printf("ADMITTED residual state retained by policy; not removed.\n");
    if (result.status) printf("SAW status=%08x\n", (unsigned)result.status);
    printf("\xEC\x95\x88 \xEC\x8D\xB0\xEB\xA6\xB0\xEB\x8B\xA4. Completion unconfirmed.\n"); /* 안 썰린다. */
    return (result.flags & (SHZ_SAW_REPLY_PENDING | SHZ_SAW_REPLY_ADMITTED)) ? 3 : 1;
}
