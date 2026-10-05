/* SPDX-License-Identifier: GPL-2.0-only */
#include "nt.h"
#include "shzcrt.h"
#include "prompt.h"
#include "../../../abi/shz_auth.h"
#include <string.h>
static int copy(char *d,size_t cap,const char *s){size_t n=strlen(s);if(n>=cap)return -1;memcpy(d,s,n+1);return 0;}
/* Reject any reply that is not exactly the current ABI; success is never shown otherwise. */
static int reply_valid(const shz_auth_reply *r){return r->version==SHZ_AUTH_VERSION&&!r->reserved&&!(r->flags&~SHZ_AUTH_VOLATILE);}
static const char *store_text(const shz_auth_reply *r){return (r->flags&SHZ_AUTH_VOLATILE)?"volatile (lost at reboot)":"durable";}
int main(int argc,char **argv) {
 shz_auth_request req={0};shz_auth_reply reply={0};unsigned op=SHZ_AUTH_ELEVATE_LAUNCH;int i=1;NTSTATUS st;
 req.version=1;
 if(argc==2&&!strcmp(argv[1],"--status")) {
  st=NtShzToken(SHZ_AUTH_QUERY,0,sizeof reply,(ULONG_PTR)&reply);
  if(st){printf("Account backend unavailable or refused: %08x\n",(unsigned)st);return 1;}
  if(!reply_valid(&reply)){printf("Account backend returned an invalid reply.\n");return 1;}
  printf("uid=%u session=%u integrity=%x accounts=%u store=%s\n",reply.subject.uid,reply.subject.session,reply.subject.integrity,reply.accounts,store_text(&reply));return 0;
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
  int n=shz_password_prompt(req.user,op==SHZ_AUTH_REGISTER?"Register an account credential":req.image,req.password,sizeof req.password);
  if(!n){SecureZeroMemory(&req,sizeof req);printf("Authentication cancelled.\n");return 1;}req.password_bytes=(uint32_t)n;
 }
 memset(&reply,0,sizeof reply);
 st=NtShzToken(op,(ULONG_PTR)&req,sizeof req,(ULONG_PTR)&reply);SecureZeroMemory(&req,sizeof req);
 if(st){SecureZeroMemory(&reply,sizeof reply);printf("Account operation refused: %08x\n",(unsigned)st);return 1;}
 if(!reply_valid(&reply)){SecureZeroMemory(&reply,sizeof reply);printf("Account operation result rejected: invalid kernel reply.\n");return 1;}
 if(op==SHZ_AUTH_REGISTER)printf("Credential registered; account store is %s.\n",store_text(&reply));
 else printf("Started pid=%llu uid=%u session=%u integrity=%x\n",(unsigned long long)reply.child_pid,reply.subject.uid,reply.subject.session,reply.subject.integrity);
 return 0;
usage:
 printf("elevate --status\nelevate --enroll USER | --register USER\nelevate --login USER IMAGE [COMMAND]\nelevate USER IMAGE [COMMAND]\nelevate --sandbox IMAGE [COMMAND]\nPasswords are entered in the masked dialog, never as arguments.\n");return 2;
}
