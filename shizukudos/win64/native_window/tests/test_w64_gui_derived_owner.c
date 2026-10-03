/* SPDX-License-Identifier: GPL-2.0-only
 * Host protocol test for the derived-owner GUI route: the real NTWRAP9X identity code (ntwrapper/vxd/w64_owner.c)
 * stamps headers, and the real K64 authority predicate (shz_w64_gui_subject_authorized, used by
 * kernel64/w64_gui_service.c) decides. A second Win98 process presenting the first one's pid and capability_id is
 * refused. Host-only: no VxD load, no VWIN32, no K64, no VM. */
#include <stdio.h>
#include <string.h>
#include "../../../../ntwrapper/vxd/w64_owner.h"
#include "../../../../ntwrapper/vxd/bridge.h"
static int fails, checks;
#define CHECK(c) do { ++checks; if (!(c)) { ++fails; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
#define SYS_VM 0xc1000000u
#define DOS_VM 0xc2000000u
#define PROC_A 0x81a00010u
#define PROC_B 0x81b00020u
#define GEN 5u
#define PROC_C 0x81c00030u
static int lock_depth;
static uintptr_t model_enter(void *o) { (void)o; return (uintptr_t)lock_depth++; }
static void model_leave(void *o, uintptr_t saved) { (void)o; lock_depth = (int)saved; }

/* A user W64 SEND as the VxD forwards it: app bytes, then the VxD stamp. */
static uint32_t user_send(uint32_t vm, uint32_t process, uint32_t gen, uint32_t app_cap, uint32_t pid_in_payload,
                          uint32_t *derive_rc)
{
    shz_msg_hdr_t h;
    uint32_t cap = 0;
    memset(&h, 0, sizeof h);
    h.capability_id = app_cap;
    h.opcode = SHZ_OP_W64_GUI_FRAME_ACQUIRE;
    (void)pid_in_payload;                       /* selects the slot only; never identity */
    *derive_rc = ntwv_w64_owner_derive(vm, process, gen, &cap);
    if (*derive_rc) return 0xffffffffu;         /* not sent */
    ntwv_w64_owner_stamp(&h, 1, cap);
    return h.capability_id;
}

int main(void)
{
    uint32_t rc, cap_a, cap_a2, cap_b, slot_owner_a, got, i, issued_before;
    shz_msg_hdr_t h;

    /* Unbound system VM: nothing derivable. */
    CHECK(ntwv_w64_owner_derive(SYS_VM, PROC_A, GEN, &cap_a) != 0 && cap_a == 0);
    ntwv_w64_owner_bind_system_vm(SYS_VM);
    /* No interrupt lock bound: an open cannot be recorded, so no identity is derivable. */
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_A) == NTWV_ERROR_ACCESS_DENIED);
    CHECK(user_send(SYS_VM, PROC_A, GEN, 0, 0, &rc) == 0xffffffffu && rc == NTWV_ERROR_ACCESS_DENIED);
    ntwv_w64_owner_bind_lock(model_enter, model_leave);
    /* Only a process with a recorded live NTWRAP9X handle (DIOC_OPEN) has an identity. */
    CHECK(user_send(SYS_VM, PROC_A, GEN, 0, 0, &rc) == 0xffffffffu && rc == NTWV_ERROR_ACCESS_DENIED);
    CHECK(ntwv_w64_owner_handle_open(DOS_VM, PROC_A) == NTWV_ERROR_ACCESS_DENIED);
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, 0) == NTWV_ERROR_ACCESS_DENIED);
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_A) == 0 && ntwv_w64_owner_handle_open(SYS_VM, PROC_B) == 0);
    CHECK(ntwv_w64_owner_handles(PROC_A) == 1 && lock_depth == 0);

    /* A creates the W64 process: subsys64 records owner_cap from the stamped CREATE header (app said 0x1234). */
    slot_owner_a = user_send(SYS_VM, PROC_A, GEN, 0x1234u, 0, &rc);
    CHECK(rc == 0 && shz_w64_owner_cap_derived(slot_owner_a) && slot_owner_a != 0x1234u);
    cap_a = user_send(SYS_VM, PROC_A, GEN, 0, 77, &rc);
    CHECK(rc == 0 && cap_a == slot_owner_a);                              /* stable for the same tagProcess */
    CHECK(shz_w64_gui_subject_authorized(slot_owner_a, cap_a, 1));

    /* B spoofs A's capability_id and A's pid: the VxD replaces the identity, K64 refuses. */
    cap_b = user_send(SYS_VM, PROC_B, GEN, slot_owner_a, 77, &rc);
    CHECK(rc == 0 && shz_w64_owner_cap_derived(cap_b) && cap_b != slot_owner_a);
    CHECK(!shz_w64_gui_subject_authorized(slot_owner_a, cap_b, 1));
    /* B forging the DERIVED bit with an arbitrary token is overwritten too. */
    got = user_send(SYS_VM, PROC_B, GEN, SHZ_W64_OWNER_CAP_DERIVED | 1u, 77, &rc);
    CHECK(rc == 0 && got == cap_b);

    /* Trusted in-VxD endpoint path (stamp=0) can never carry the DERIVED bit. */
    memset(&h, 0, sizeof h); h.capability_id = slot_owner_a;
    ntwv_w64_owner_stamp(&h, 0, 0);
    CHECK(!shz_w64_owner_cap_derived(h.capability_id) && !shz_w64_gui_subject_authorized(slot_owner_a, h.capability_id, 1));
    /* A stamped send whose derivation produced no capability forwards 0, not the app value. */
    memset(&h, 0, sizeof h); h.capability_id = slot_owner_a;
    ntwv_w64_owner_stamp(&h, 1, 0);
    CHECK(h.capability_id == 0);

    /* Callers outside the system VM, process tag 0, generation 0: denied, no capability. */
    CHECK(user_send(DOS_VM, PROC_A, GEN, 0, 0, &rc) == 0xffffffffu && rc != 0);
    CHECK(user_send(SYS_VM, 0, GEN, 0, 0, &rc) == 0xffffffffu && rc != 0);
    CHECK(user_send(SYS_VM, PROC_A, 0, 0, 0, &rc) == 0xffffffffu && rc != 0);

    /* Standalone (derived not required) still demands creator identity equality; anonymous 0 != derived owner. */
    CHECK(shz_w64_gui_subject_authorized(0, 0, 0) && !shz_w64_gui_subject_authorized(0, 0, 1));
    CHECK(!shz_w64_gui_subject_authorized(slot_owner_a, 0, 0));

    /* DIOC_CLOSEHANDLE of A (deferred, applied at next derive): a recycled tag gets a fresh identity. */
    ntwv_w64_owner_departed(PROC_A);
    cap_a2 = user_send(SYS_VM, PROC_A, GEN, slot_owner_a, 0, &rc);
    CHECK(rc == 0 && cap_a2 != slot_owner_a && !shz_w64_gui_subject_authorized(slot_owner_a, cap_a2, 1));
    /* Channel generation change: the old identity is dead. */
    got = user_send(SYS_VM, PROC_A, GEN + 1, 0, 0, &rc);
    CHECK(rc == 0 && got != cap_a2 && got != slot_owner_a);

    /* Deferred-list overflow retires everyone (fail closed). */
    for (i = 0; i < NTWV_W64_OWNER_DEFERRED + 1u; ++i) ntwv_w64_owner_departed(0x90000000u + i);
    issued_before = ntwv_w64_owner_issued();
    got = user_send(SYS_VM, PROC_B, GEN, 0, 0, &rc);
    CHECK(rc == 0 && got != cap_b && ntwv_w64_owner_live() == 1 && ntwv_w64_owner_issued() == issued_before + 1);

    /* Table capacity: the 17th distinct live process is BUSY, nothing granted. */
    for (i = 1; i < NTWV_W64_OWNER_SLOTS; ++i) {
        CHECK(ntwv_w64_owner_handle_open(SYS_VM, 0x70000000u + i) == 0);
        CHECK(user_send(SYS_VM, 0x70000000u + i, GEN, 0, 0, &rc) != 0xffffffffu);
    }
    CHECK(ntwv_w64_owner_handle_open(SYS_VM, 0x7f000000u) == 0);
    CHECK(user_send(SYS_VM, 0x7f000000u, GEN, 0, 0, &rc) == 0xffffffffu && rc == NTWV_ERROR_BUSY);

    /* Channel reset retires every identity; tokens are never reissued afterwards. */
    issued_before = ntwv_w64_owner_issued();
    ntwv_w64_owner_reset_locked();
    CHECK(ntwv_w64_owner_live() == 0);
    got = user_send(SYS_VM, PROC_B, GEN, 0, 0, &rc);
    CHECK(rc == 0 && (got & SHZ_W64_OWNER_CAP_TOKEN) == issued_before + 1u);

    /* Per-process handle refcount (batch 5): closing one of two handles keeps the identity; the last close retires it. */
    {
        uint32_t c1, c2, c3, opened = 0;
        CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_C) == 0 && ntwv_w64_owner_handle_open(SYS_VM, PROC_C) == 0);
        CHECK(ntwv_w64_owner_handles(PROC_C) == 2);
        c1 = user_send(SYS_VM, PROC_C, GEN, 0, 0, &rc);
        CHECK(rc == 0 && shz_w64_owner_cap_derived(c1) && ntwv_w64_owner_cap_live(c1));
        ntwv_w64_owner_handle_close(PROC_C);                 /* e.g. the PMA client handle closes */
        c2 = user_send(SYS_VM, PROC_C, GEN, 0, 0, &rc);
        CHECK(rc == 0 && c2 == c1 && ntwv_w64_owner_handles(PROC_C) == 1 && ntwv_w64_owner_cap_live(c1));
        ntwv_w64_owner_handle_close(PROC_C);                 /* last handle */
        CHECK(ntwv_w64_owner_handles(PROC_C) == 0 && !ntwv_w64_owner_cap_live(c1));
        CHECK(user_send(SYS_VM, PROC_C, GEN, c1, 0, &rc) == 0xffffffffu && rc == NTWV_ERROR_ACCESS_DENIED);
        /* Recycled tagProcess with a new handle: fresh identity, the old slot owner is refused. */
        CHECK(ntwv_w64_owner_handle_open(SYS_VM, PROC_C) == 0);
        c3 = user_send(SYS_VM, PROC_C, GEN, c1, 0, &rc);
        CHECK(rc == 0 && c3 != c1 && !shz_w64_gui_subject_authorized(c1, c3, 1));
        /* An unrecorded close (never counted) retires conservatively and never underflows another process. */
        ntwv_w64_owner_handle_close(0x6f000000u);
        CHECK(ntwv_w64_owner_handles(PROC_C) == 1 && ntwv_w64_owner_cap_live(c3));
        /* Handle table capacity: an unrecordable open leaves that process without identity (fail closed). */
        for (i = 0; i < 2u * NTWV_W64_OWNER_HANDLE_PROCS; ++i)
            if (ntwv_w64_owner_handle_open(SYS_VM, 0x60000000u + i) == 0) ++opened; else break;
        CHECK(opened < NTWV_W64_OWNER_HANDLE_PROCS && ntwv_w64_owner_handle_open(SYS_VM, 0x6e000000u) == NTWV_ERROR_BUSY);
        CHECK(user_send(SYS_VM, 0x6e000000u, GEN, 0, 0, &rc) == 0xffffffffu && rc == NTWV_ERROR_ACCESS_DENIED);
        /* Non-derived caps are never live owners. */
        CHECK(!ntwv_w64_owner_cap_live(0) && !ntwv_w64_owner_cap_live(c3 & SHZ_W64_OWNER_CAP_TOKEN));
        CHECK(lock_depth == 0);
    }

    /* Display requirement used by NTW32 NtwQueryGui64 and the presenter. */
    CHECK(!shz_w64_gui_display_valid(0) && shz_w64_gui_display_valid(SHZ_W64_GUI_DISPLAY_SCANOUT) &&
          shz_w64_gui_display_valid(SHZ_W64_GUI_DISPLAY_HOSTED_PRIVATE) && !shz_w64_gui_display_valid(3));
    CHECK(sizeof(shz_w64_gui_view_t) == 64 && offsetof(shz_w64_gui_view_t, display_backend) == 52);

    printf("test_w64_gui_derived_owner: %d checks, %d failures\n", checks, fails);
    return fails != 0;
}
