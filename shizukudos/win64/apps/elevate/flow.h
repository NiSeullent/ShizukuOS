/* SPDX-License-Identifier: GPL-2.0-only
 * elevate client outcome policy: consent expiry and kernel status -> exit code.
 * Header-only so both the PE64 build and the host controls use the same text.
 * The kernel (sysk32_auth.c, 74b0) remains the only authority; this file never
 * turns a refusal into success and never infers why authentication failed
 * beyond the status the kernel returned (wrong password and lockout are both
 * STATUS_ACCESS_DENIED there, so they are reported together). */
#ifndef SHZ_ELEVATE_FLOW_H
#define SHZ_ELEVATE_FLOW_H
#include <stdint.h>
#include "../../../abi/shz_auth.h"

/* Consent is bound to one displayed request. After this many milliseconds the
 * displayed request is stale; entry is discarded and no IPC is issued. */
#define SHZ_ELEVATE_CONSENT_MS 120000u

enum {
 SHZ_PROMPT_UNAVAILABLE=0, /* consent could not be displayed/read: no IPC */
 SHZ_PROMPT_ACCEPTED=1,
 SHZ_PROMPT_CANCELED=2,    /* Esc, Cancel, close: no IPC */
 SHZ_PROMPT_EXPIRED=3      /* deadline passed before acceptance: no IPC */
};

enum {
 SHZ_ELEVATE_EXIT_OK=0,
 SHZ_ELEVATE_EXIT_REFUSED=1,     /* kernel refused (bad credential, lockout, policy) */
 SHZ_ELEVATE_EXIT_USAGE=2,
 SHZ_ELEVATE_EXIT_CANCELED=3,
 SHZ_ELEVATE_EXIT_EXPIRED=4,
 SHZ_ELEVATE_EXIT_UNDISPLAYABLE=5,
 SHZ_ELEVATE_EXIT_INCONSISTENT=6 /* kernel reported success with an impossible reply */
};

#define SHZ_ELEVATE_INTEGRITY_HIGH 0x3000u
#define SHZ_ELEVATE_INTEGRITY_MEDIUM 0x2000u

/* Wraparound-safe 32-bit millisecond tick comparison (GetTickCount clock). */
static inline int shz_consent_expired(uint32_t start,uint32_t now,uint32_t limit)
{ return (uint32_t)(now-start)>=limit; }

/* Exit status as reported by the boot enrollment caller. */
static inline const char *shz_elevate_exit_name(int64_t code)
{
 return code==SHZ_ELEVATE_EXIT_OK?"enrolled":code==SHZ_ELEVATE_EXIT_REFUSED?"refused":
        code==SHZ_ELEVATE_EXIT_USAGE?"usage":code==SHZ_ELEVATE_EXIT_CANCELED?"cancelled":
        code==SHZ_ELEVATE_EXIT_EXPIRED?"expired":code==SHZ_ELEVATE_EXIT_UNDISPLAYABLE?"undisplayable":
        code==SHZ_ELEVATE_EXIT_INCONSISTENT?"inconsistent":"unknown";
}

/* Boot enrollment caller policy (kernel64/autorun.c, shz.accounts=setup runs
 * "ELEVATE.EXE --enroll admin" with the bootstrap authority). A dialog the operator
 * cancelled or let expire never reached the kernel, so it is offered again, at most
 * SHZ_ELEVATE_ENROLL_ATTEMPTS times in total. A kernel refusal, an undisplayable
 * dialog, a usage error, a fault or any unknown status ends enrollment: the desktop
 * is not started without an enrolled administrator. Returns 1 enrolled, 0 offer
 * again, -1 stop. `attempt` counts finished attempts starting at 1. */
#define SHZ_ELEVATE_ENROLL_ATTEMPTS 3u
static inline int shz_enroll_next(int64_t code,int faulted,unsigned attempt)
{
 if(faulted)return -1;
 if(code==SHZ_ELEVATE_EXIT_OK)return 1;
 if((code==SHZ_ELEVATE_EXIT_CANCELED||code==SHZ_ELEVATE_EXIT_EXPIRED)&&attempt<SHZ_ELEVATE_ENROLL_ATTEMPTS)return 0;
 return -1;
}

static inline int shz_prompt_exit(int outcome)
{
 return outcome==SHZ_PROMPT_CANCELED?SHZ_ELEVATE_EXIT_CANCELED:
        outcome==SHZ_PROMPT_EXPIRED?SHZ_ELEVATE_EXIT_EXPIRED:SHZ_ELEVATE_EXIT_UNDISPLAYABLE;
}

static inline const char *shz_prompt_message(int outcome)
{
 return outcome==SHZ_PROMPT_CANCELED?"Authentication cancelled; nothing was started.":
        outcome==SHZ_PROMPT_EXPIRED?"Authentication request expired; nothing was started. Run the command again.":
        "Authentication request could not be displayed; nothing was started.";
}

/* Kernel NTSTATUS values produced by sysk32_auth.c auth_status()/validation. */
static inline const char *shz_refusal_message(uint32_t st)
{
 switch(st){
 case 0xc0000022u:return "Access denied: wrong credential, account locked, not an administrator, or image not permitted.";
 case 0xc000000du:return "Request rejected as invalid by the account backend.";
 case 0xc0000017u:return "Account backend out of sessions or memory.";
 case 0xc0000005u:return "Request or reply buffer was not accessible.";
 default:return "Account backend unavailable or refused the operation.";
 }
}

/* A launch reply must describe a fresh child whose authority is the
 * authenticated one, never the caller's own session. `parent` is the caller's
 * subject queried after the launch: it must not have acquired the child's
 * session/authentication or (for elevation) high integrity. */
static inline int shz_launch_reply_consistent(uint32_t op,const shz_auth_reply *r,const shz_subject *parent)
{
 if(!r||!parent||r->version!=1u||!r->child_pid)return 0;
 if(op==SHZ_AUTH_ELEVATE_LAUNCH){
  if(r->subject.integrity!=SHZ_ELEVATE_INTEGRITY_HIGH||r->subject.roles!=SHZ_ROLE_ADMIN)return 0;
 } else if(op==SHZ_AUTH_LOGIN_LAUNCH){
  if(r->subject.integrity!=SHZ_ELEVATE_INTEGRITY_MEDIUM)return 0;
 } else if(op==SHZ_AUTH_SANDBOX_LAUNCH){
  if(!(r->subject.flags&SHZ_SUBJECT_SANDBOX)||r->subject.roles)return 0;
  /* Sandbox inherits the caller's uid/session at low integrity. */
  return r->subject.integrity==0x1000u&&r->subject.uid==parent->uid&&
         r->subject.integrity<=parent->integrity;
 } else return 0;
 /* Fresh authenticated session distinct from the caller's. */
 if(!r->subject.session||r->subject.session==parent->session||
    r->subject.auth_id==parent->auth_id)return 0;
 return 1;
}
#endif
