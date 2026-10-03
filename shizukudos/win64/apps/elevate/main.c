/* SPDX-License-Identifier: GPL-2.0-only */
#include "nt.h"
#include "shzcrt.h"
#include "prompt.h"
#include "consent.h"
#include "flow.h"
#include "../../../abi/shz_auth.h"
#include <string.h>
static int copy(char *d,size_t cap,const char *s){size_t n=strlen(s);if(n>=cap)return -1;memcpy(d,s,n+1);return 0;}
int main(int argc,char **argv) {
 shz_auth_request req={0};shz_auth_reply reply={0};char consent[SHZ_ELEVATE_CONSENT_BYTES];unsigned op=SHZ_AUTH_ELEVATE_LAUNCH;int i=1;NTSTATUS st;
 req.version=1;
 if(argc==2&&!strcmp(argv[1],"--status")) {
  st=NtShzToken(SHZ_AUTH_QUERY,0,sizeof reply,(ULONG_PTR)&reply);
  if(st){printf("Account backend unavailable or refused: %08x\n",(unsigned)st);return 1;}
  printf("uid=%u session=%u integrity=%x accounts=%u volatile=%u\n",reply.subject.uid,reply.subject.session,reply.subject.integrity,reply.accounts,reply.flags&SHZ_AUTH_VOLATILE);return 0;
 }
 if(argc>1&&(!strcmp(argv[1],"--enroll")||!strcmp(argv[1],"--register"))) {op=SHZ_AUTH_REGISTER;req.roles=!strcmp(argv[1],"--enroll")?SHZ_ROLE_ADMIN:0;i++;}
 else if(argc>1&&!strcmp(argv[1],"--login")){op=SHZ_AUTH_LOGIN_LAUNCH;i++;}
 else if(argc>1&&!strcmp(argv[1],"--sandbox")){op=SHZ_AUTH_SANDBOX_LAUNCH;i++;}
 if(op!=SHZ_AUTH_SANDBOX_LAUNCH) {if(i>=argc||copy(req.user,sizeof req.user,argv[i++]))goto usage;}
 if(op!=SHZ_AUTH_REGISTER) {
  if(i>=argc||copy(req.image,sizeof req.image,argv[i++]))goto usage;
  if(i<argc){if(i+1!=argc||copy(req.command,sizeof req.command,argv[i]))goto usage;}else if(copy(req.command,sizeof req.command,req.image))goto usage;
 } else if(i!=argc)goto usage;
 if(op!=SHZ_AUTH_SANDBOX_LAUNCH) {
  int n,why;
  if(!shz_elevate_consent(op,&req,consent,sizeof consent)){SecureZeroMemory(&req,sizeof req);goto usage;}
  n=shz_password_prompt_ex(req.user,consent,req.password,sizeof req.password,SHZ_ELEVATE_CONSENT_MS,&why);
  SecureZeroMemory(consent,sizeof consent);
  /* Canceled, expired and undisplayable requests never reach the kernel. */
  if(!n){SecureZeroMemory(&req,sizeof req);printf("%s\n",shz_prompt_message(why));return shz_prompt_exit(why);}
  req.password_bytes=(uint32_t)n;
 }
 st=NtShzToken(op,(ULONG_PTR)&req,sizeof req,(ULONG_PTR)&reply);SecureZeroMemory(&req,sizeof req);
 if(st){printf("Account operation refused: %08x\n%s\n",(unsigned)st,shz_refusal_message((uint32_t)st));return SHZ_ELEVATE_EXIT_REFUSED;}
 if(op==SHZ_AUTH_REGISTER){printf("Credential registered in volatile kernel account store.\n");return 0;}
 {
  /* The child holds the authenticated authority; this process must not.
   * Re-read our own subject from the kernel rather than trusting the reply. */
  shz_auth_reply self={0};
  st=NtShzToken(SHZ_AUTH_QUERY,0,sizeof self,(ULONG_PTR)&self);
  if(st||!shz_launch_reply_consistent(op,&reply,&self.subject)) {
   printf("Launch reply inconsistent with caller authority (query %08x); child pid=%llu not trusted.\n",(unsigned)st,(unsigned long long)reply.child_pid);
   return SHZ_ELEVATE_EXIT_INCONSISTENT;
  }
  printf("Started pid=%llu uid=%u session=%u integrity=%x; caller unchanged uid=%u session=%u integrity=%x\n",(unsigned long long)reply.child_pid,reply.subject.uid,reply.subject.session,reply.subject.integrity,self.subject.uid,self.subject.session,self.subject.integrity);
 }
 return 0;
usage:
 printf("elevate --status\nelevate --enroll USER | --register USER\nelevate --login USER IMAGE [COMMAND]\nelevate USER IMAGE [COMMAND]\nelevate --sandbox IMAGE [COMMAND]\nPasswords are entered in the masked dialog, never as arguments.\nExit: 0 started, 1 refused, 2 usage, 3 cancelled, 4 expired, 5 not displayable, 6 inconsistent reply.\n");return SHZ_ELEVATE_EXIT_USAGE;
}
