/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 system calls 0x9d-0x9e for advapi32 (routed by sysk32.c):
 *
 *  - access tokens (NtShzToken): one primary token per process (medium integrity, session 1, a fresh LUID) and duplicates
 *    of it; advapi32 renders the Windows information classes from shz_token_info. Thread impersonation records which
 *    token a thread impersonates (OpenThreadToken reports it). Token queries require the handle's TOKEN_QUERY right;
 *    token operations enforce handle rights, but descriptor-based identity checks remain incomplete;
 *  - security descriptors (NtShzSecurityObject): stored per object as the self-relative blob advapi32 composes (not
 *    token-aware DACL evaluation is incomplete), returned by queries admitted by READ_CONTROL.
 *    Descriptor replacement requires WRITE_DAC; owner/SACL authorization remains separate work.
 */
#include "fs.h"
#include "../abi/shz_token_ops.h"
#include "auth_policy.h"

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

#define STATUS_NO_TOKEN ((int32_t)0xC000007C)
#define STATUS_NOT_FOUND ((int32_t)0xC0000225)

static process_t *proc_ref_of(process_t *cur, uint64_t h, kobject_t **ref, uint32_t *access, int32_t *status)
{
    kobject_t *o;
    process_t *t;
    *ref = 0;
    *status = STATUS_SUCCESS;
    if (h == CURRENT_PROCESS_HANDLE) { *access = 0x1fffffu; if (!cur) *status = STATUS_INVALID_HANDLE; return cur; }
    *status = handle_ref(cur, h, OB_PROCESS, &o, access);
    if (*status) return 0;
    t = o->u.proc.p;
    if (!t || !t->used || t->object != o || t->teardown) { ob_deref(o); *status = STATUS_INVALID_HANDLE; return 0; }   /* gone: the slot may be reused */
    *ref = o;
    return t;
}

static void proc_unref(kobject_t *ref) { if (ref) ob_deref(ref); }

/* Inserts `o` (the caller's reference is consumed) and writes the handle to user memory. */
static int32_t give_handle(process_t *p, kobject_t *o, uint64_t user_ptr, uint32_t access)
{
    uint32_t h;
    uint64_t v;
    int32_t st = handle_insert(p, o, access, &h);
    ob_deref(o);
    if (st) return st;
    v = h;
    if (copy_to_user(p, user_ptr, &v, 8)) { handle_close(p, h); return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- tokens */
typedef struct shz_token_info {
    uint32_t type, imp_level, integrity_rid, flags;
    uint64_t id, modified_id, auth_id;
    uint32_t session, elevation_type;
    uint64_t owner_pid;
} shz_token_info;

static uint64_t next_luid = 0x10000;

void token_object_free(kobject_t *o)
{
    if (o->u.token.t) { kfree(o->u.token.t); o->u.token.t = 0; }
}

static kobject_t *token_new(const shz_token_info *from, uint64_t owner_pid)
{
    shz_token_info *t = kzalloc(sizeof *t);
    kobject_t *o = t ? ob_create(OB_TOKEN, 0) : 0;
    if (!o) { kfree(t); return 0; }
    if (from) *t = *from;
    else {
        t->type = 1;                                                        /* TokenPrimary */
        t->integrity_rid = 0x2000;                                          /* SECURITY_MANDATORY_MEDIUM_RID */
        t->session = 1;
        t->elevation_type = 1;                                              /* TokenElevationTypeDefault */
        t->auth_id = 0x3e7 + 0x100;                                         /* the interactive logon session */
    }
    t->id = ++next_luid;
    t->modified_id = t->id;
    t->owner_pid = owner_pid;
    o->u.token.t = t;
    return o;
}

static kobject_t *process_token(process_t *t)
{
    if (!t->token) t->token = token_new(0, (uint64_t)t->pid);
    return t->token;
}

/* Account policy uses the lower of its immutable ceiling and the public token
 * label. Reading policy never creates a lazy token or trusts privilege flags. */
uint32_t shz_token_integrity(process_t *p, uint32_t fallback)
{
    const uint64_t f = irq_save();
    if (p && p->token) {
        const shz_token_info *t = p->token->u.token.t;
        if (t && t->integrity_rid < fallback) fallback = t->integrity_rid;
    }
    irq_restore(f);
    return fallback;
}

/* Trusted account authority only: bind before a fresh child's first token use.
 * Public metadata setters cannot call this, and existing identities cannot be
 * switched in place while old token handles might remain alive. */
int32_t shz_token_bind_subject(process_t *p, uint64_t auth_id, uint32_t session, uint32_t integrity)
{
    kobject_t *tok;
    kobject_t *object;
    shz_token_info *t;
    uint64_t pid;
    uint64_t f;
    if (!p || !auth_id) return STATUS_INVALID_PARAMETER;
    f = irq_save();
    if (!p->used || p->teardown || !p->object) { irq_restore(f); return STATUS_INVALID_HANDLE; }
    if (p->token) { irq_restore(f); return STATUS_ACCESS_DENIED; }
    object = p->object; pid = (uint64_t)p->pid;
    ob_ref(object);
    irq_restore(f);
    tok = token_new(0, pid);
    if (!tok) { ob_deref(object); return STATUS_NO_MEMORY; }
    t = tok->u.token.t;
    t->auth_id = auth_id; t->session = session; t->integrity_rid = integrity;
    t->elevation_type = integrity == 0x3000u ? 2u : 1u;
    t->flags = 0;
    f = irq_save();
    if (!p->used || p->teardown || p->object != object || (uint64_t)p->pid != pid || p->token) {
        irq_restore(f); ob_deref(tok); ob_deref(object); return STATUS_ACCESS_DENIED;
    }
    p->token = tok;
    irq_restore(f);
    ob_deref(object);
    return STATUS_SUCCESS;
}

/* Registry account authorization is based on the immutable primary subject.
 * Support impersonation only when it describes that same identity and label;
 * reject differing contexts even for callers using native syscalls directly. */
int shz_token_registry_context(process_t *p)
{
    int allowed=1;
    const uint64_t f=irq_save();
    thread_t *th=thread_current();
    if(th&&th->proc==p&&th->impersonation){
        const kobject_t *primary=p->token,*imp=th->impersonation;
        const shz_token_info *a=primary?primary->u.token.t:0,*b=imp->u.token.t;
        allowed=primary&&primary->type==OB_TOKEN&&imp->type==OB_TOKEN&&a&&b&&
            a->type==1&&b->type==2&&b->imp_level>=2&&b->imp_level<=3&&
            a->auth_id==b->auth_id&&a->session==b->session&&a->integrity_rid==b->integrity_rid;
    }
    irq_restore(f);
    return allowed;
}

static int32_t sys_token(process_t *p, struct regs *r, uint64_t op, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r;
    switch (op) {
    case SHZ_TOK_OPEN_PROCESS: {
        kobject_t *pref, *tok;
        uint32_t granted, desired;
        int32_t st;
        process_t *t = proc_ref_of(p, a2, &pref, &granted, &st);
        if (!t) return st;
        if (!(granted & (0x0400u | 0x1000u))) { proc_unref(pref); return STATUS_ACCESS_DENIED; }
        if (!shz_auth_process_access(p, t)) { proc_unref(pref); return STATUS_ACCESS_DENIED; }
        if (a3 >> 32 || !shz_token_map_access((uint32_t)a3, SHZ_TOKEN_ALL_ACCESS, &desired)) {
            proc_unref(pref); return STATUS_ACCESS_DENIED;
        }
        tok = process_token(t);
        if (!tok) { proc_unref(pref); return STATUS_NO_MEMORY; }
        ob_ref(tok);
        st = give_handle(p, tok, a4, desired);
        proc_unref(pref);
        return st;
    }
    case SHZ_TOK_OPEN_THREAD: {
        thread_t *t = 0;
        kobject_t *to = 0, *tok;
        uint32_t granted = 0x1fffffu, desired;
        uint64_t f;
        if (a2 == CURRENT_THREAD_HANDLE) t = thread_current();
        else {
            int32_t st = handle_ref(p, a2, OB_THREAD, &to, &granted);
            if (st) return st;
        }
        if (!(granted & (0x0040u | 0x0800u))) { if (to) ob_deref(to); return STATUS_ACCESS_DENIED; }
        if (a3 >> 32 || !shz_token_map_access((uint32_t)a3, SHZ_TOKEN_ALL_ACCESS, &desired)) {
            if (to) ob_deref(to);
            return STATUS_ACCESS_DENIED;
        }
        f = irq_save();
        if (to) t = to->u.thr.t;
        if (t && !shz_auth_process_access(p, t->proc)) {
            irq_restore(f); if (to) ob_deref(to); return STATUS_ACCESS_DENIED;
        }
        tok = t ? t->impersonation : 0;
        if (tok) ob_ref(tok);
        irq_restore(f);
        if (to) ob_deref(to);
        if (!tok) return STATUS_NO_TOKEN;
        return give_handle(p, tok, a4, desired);
    }
    case SHZ_TOK_QUERY: {
        kobject_t *tok;
        uint32_t access;
        int32_t st = handle_ref(p, a2, OB_TOKEN, &tok, &access);
        if (st) return st;
        if (!(access & 0x0008u)) st = STATUS_ACCESS_DENIED;                /* TOKEN_QUERY, from this actual handle */
        else if (a4 < sizeof(shz_token_info)) st = STATUS_INFO_LENGTH_MISMATCH;
        else {
            shz_token_info snapshot;
            const uint64_t f = irq_save();
            snapshot = *(const shz_token_info *)tok->u.token.t;
            irq_restore(f);
            if (copy_to_user(p, a3, &snapshot, sizeof snapshot)) st = STATUS_ACCESS_VIOLATION;
        }
        ob_deref(tok);
        return st;
    }
    case SHZ_TOK_SET: {
        kobject_t *tok;
        shz_token_info *t;
        uint32_t granted, required;
        int32_t st = handle_ref(p, a2, OB_TOKEN, &tok, &granted);
        if (st) return st;
        if (a3 == SHZ_TOKF_INTEGRITY) required = SHZ_TOKEN_ADJUST_DEFAULT;
        else if (a3 == SHZ_TOKF_SESSION) required = SHZ_TOKEN_ADJUST_SESSIONID;
        else if (a3 == SHZ_TOKF_PRIVS) required = SHZ_TOKEN_ADJUST_PRIVILEGES;
        else { ob_deref(tok); return STATUS_INVALID_INFO_CLASS; }
        if (!(granted & required)) { ob_deref(tok); return STATUS_ACCESS_DENIED; }
        const uint64_t f = irq_save();
        t = tok->u.token.t;
        if (a3 == SHZ_TOKF_INTEGRITY) {
            if (a4 > t->integrity_rid) st = STATUS_ACCESS_DENIED;          /* integrity can only be lowered (no privilege to raise it) */
            else { t->integrity_rid = (uint32_t)a4; t->modified_id = ++next_luid; }
        } else if (a3 == SHZ_TOKF_SESSION) {
            if (a4 != t->session) st = STATUS_ACCESS_DENIED;               /* needs SeTcbPrivilege, which nobody holds here */
        } else if (a3 == SHZ_TOKF_PRIVS) {
            if (a4 & ~0x1full) st = STATUS_INVALID_PARAMETER;
            else { t->flags = (uint32_t)a4; t->modified_id = ++next_luid; }
        } else {
            st = STATUS_INVALID_INFO_CLASS;
        }
        irq_restore(f);
        ob_deref(tok);
        return st;
    }
    case SHZ_TOK_DUPLICATE:
    case SHZ_TOKEN_OP_DUPLICATE_EX: {
        kobject_t *tok, *nt;
        shz_token_info copy;
        uint32_t granted, desired, type, level;
        if (op == SHZ_TOKEN_OP_DUPLICATE_EX) {
            if (a3 >> 48) return STATUS_INVALID_PARAMETER;
            type = (uint32_t)(a3 >> 32) & 0xff; level = (uint32_t)(a3 >> 40) & 0xff;
            if ((type != 1 && type != 2) || level > 3) return STATUS_INVALID_PARAMETER;
        } else {
            if (a3 >> 16) return STATUS_INVALID_PARAMETER;
            type = (uint32_t)a3 & 0xff; level = (uint32_t)(a3 >> 8) & 0xff;
            if (type > 2 || level > 3) return STATUS_INVALID_PARAMETER;
        }
        int32_t st = handle_ref(p, a2, OB_TOKEN, &tok, &granted);
        if (st) return st;
        if (!(granted & SHZ_TOKEN_DUPLICATE)) { ob_deref(tok); return STATUS_ACCESS_DENIED; }
        desired = granted;
        if (op == SHZ_TOKEN_OP_DUPLICATE_EX && (uint32_t)a3 &&
            !shz_token_map_access((uint32_t)a3, granted, &desired)) {
            ob_deref(tok); return STATUS_ACCESS_DENIED;
        }
        const uint64_t f = irq_save();
        copy = *(shz_token_info *)tok->u.token.t;
        irq_restore(f);
        ob_deref(tok);
        if (copy.type == 2 && level > copy.imp_level) return STATUS_ACCESS_DENIED;
        copy.type = type ? type : copy.type;
        copy.imp_level = level;
        if (copy.type != 1 && copy.type != 2) return STATUS_INVALID_PARAMETER;
        nt = token_new(&copy, copy.owner_pid);
        if (!nt) return STATUS_NO_MEMORY;
        return give_handle(p, nt, a4, desired);
    }
    case SHZ_TOK_IMPERSONATE: {
        thread_t *t = 0;
        kobject_t *to = 0, *tok = 0, *old;
        uint32_t granted;
        uint64_t f;
        if (a3) {
            int32_t st = handle_ref(p, a3, OB_TOKEN, &tok, &granted);
            if (st) return st;
            if (!(granted & SHZ_TOKEN_IMPERSONATE)) { ob_deref(tok); return STATUS_ACCESS_DENIED; }
            if (((shz_token_info *)tok->u.token.t)->type != 2) { ob_deref(tok); return (int32_t)0xC000005C; }   /* STATUS_BAD_TOKEN_TYPE */
        }
        if (!a2 || a2 == CURRENT_THREAD_HANDLE) t = thread_current();
        else {
            int32_t st = handle_ref(p, a2, OB_THREAD, &to, &granted);
            if (st) { if (tok) ob_deref(tok); return st; }
            if (!(granted & 0x0080u)) { ob_deref(to); if (tok) ob_deref(tok); return STATUS_ACCESS_DENIED; }
        }
        f = irq_save();
        if (to) t = to->u.thr.t;
        if (!t) { irq_restore(f); if (to) ob_deref(to); if (tok) ob_deref(tok); return STATUS_THREAD_IS_TERMINATING; }
        if (!shz_auth_process_access(p, t->proc)) {
            irq_restore(f); if (to) ob_deref(to); if (tok) ob_deref(tok); return STATUS_ACCESS_DENIED;
        }
        old = t->impersonation;
        t->impersonation = tok;                                             /* the reference moves to the thread */
        irq_restore(f);
        if (old) ob_deref(old);
        if (to) ob_deref(to);
        return STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- security descriptors */
static int32_t sys_security(process_t *p, struct regs *r, uint64_t op, uint64_t h, uint64_t buf, uint64_t len)
{
    kobject_t *o;
    uint32_t granted = 0x1fffffu;
    int32_t st;
    if (h == CURRENT_PROCESS_HANDLE) { o = p->object; ob_ref(o); }
    else if (h == CURRENT_THREAD_HANDLE) { o = thread_current()->object; ob_ref(o); }
    else if ((st = handle_ref(p, h, 0, &o, &granted))) return st;
    if ((op == SHZ_SOB_QUERY && !(granted & SHZ_TOKEN_READ_CONTROL)) ||
        (op == SHZ_SOB_SET && !(granted & SHZ_TOKEN_WRITE_DAC))) {
        ob_deref(o); return STATUS_ACCESS_DENIED;
    }
    if (op == SHZ_SOB_QUERY) {
        const uint64_t pneed = (uint64_t)stack_arg(p, r, 5);
        void *sd;
        uint32_t n;
        const uint64_t f = irq_save();
        sd = o->sd;
        n = o->sd_len;
        irq_restore(f);
        if (!sd) st = STATUS_NOT_FOUND;                                     /* never set: advapi32 reports the default */
        else {
            uint8_t *copy = kmalloc(n);
            if (!copy) st = STATUS_NO_MEMORY;
            else {
                const uint64_t f2 = irq_save();
                if (o->sd && o->sd_len == n) memcpy(copy, o->sd, n); else n = 0;
                irq_restore(f2);
                if (pneed && copy_to_user(p, pneed, &n, 4)) st = STATUS_ACCESS_VIOLATION;
                else if (!n) st = STATUS_NOT_FOUND;
                else if (len < n) st = STATUS_BUFFER_TOO_SMALL;
                else st = copy_to_user(p, buf, copy, n) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
                kfree(copy);
            }
        }
    } else if (op == SHZ_SOB_SET) {
        uint8_t *copy;
        void *old;
        if (len < 20 || len > 65536) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
        copy = kmalloc(len);
        if (!copy) st = STATUS_NO_MEMORY;
        else if (copy_from_user(p, copy, buf, len)) { kfree(copy); st = STATUS_ACCESS_VIOLATION; }
        else {
            const uint64_t f = irq_save();
            old = o->sd;
            o->sd = copy;
            o->sd_len = (uint32_t)len;
            irq_restore(f);
            kfree(old);
            st = STATUS_SUCCESS;
        }
    } else {
        st = STATUS_INVALID_PARAMETER;
    }
    ob_deref(o);
    return st;
}

/* ---------------------------------------------------------------- dispatch */
int32_t sys_ext_k32_obj(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    if (num == SYS_NtShzToken && a1 >= 0x200 && a1 <= 0x20f) {
        extern int32_t shz_auth_syscall(process_t *, uint64_t, uint64_t, uint64_t, uint64_t);
        return shz_auth_syscall(p, a1, a2, a3, a4);
    }
    switch (num) {
    case SYS_NtShzToken: return sys_token(p, r, a1, a2, a3, a4);
    case SYS_NtShzSecurityObject: return sys_security(p, r, a1, a2, a3, a4);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
