/* SPDX-License-Identifier: GPL-2.0-only */
#include "consent.h"
#include <string.h>
static int literal(const char *s,size_t capacity) {
 size_t i=0;
 while(i<capacity) {
  uint32_t c=(unsigned char)s[i++],minimum=0;unsigned need=0;
  if(!c)return 1;
  if(c>=0xc2&&c<=0xdf){need=1;minimum=0x80;c&=0x1f;}
  else if(c>=0xe0&&c<=0xef){need=2;minimum=0x800;c&=0x0f;}
  else if(c>=0xf0&&c<=0xf4){need=3;minimum=0x10000;c&=0x07;}
  else if(c>=0x80)return 0;
  while(need--) {
   unsigned char next;
   if(i>=capacity)return 0;
   next=(unsigned char)s[i++];if((next&0xc0)!=0x80)return 0;
   c=(c<<6)|(next&0x3f);
  }
  if(c<minimum||c>0x10ffff||(c>=0xd800&&c<=0xdfff))return 0;
  /* Caller text must not forge field lines or reorder executable/arguments.
   * Keep ordinary Unicode filenames, including Korean, unchanged. */
  if(c<32||(c>=127&&c<=159)||c==0x061c||c==0x200e||c==0x200f||
     (c>=0x2028&&c<=0x202e)||(c>=0x2066&&c<=0x2069))return 0;
 }
 return 0;
}
static int append(char *out,size_t capacity,size_t *used,const char *s) {
 size_t n=strlen(s);
 if(*used>=capacity||n>=capacity-*used)return 0;
 memcpy(out+*used,s,n+1);*used+=n;return 1;
}
int shz_elevate_consent(uint32_t op,const shz_auth_request *req,char *out,size_t capacity) {
 const char *action;size_t used=0;
 if(!out||!capacity)return 0;
 out[0]=0;
 if(!req||!literal(req->user,sizeof req->user)||!literal(req->image,sizeof req->image)||
    !literal(req->command,sizeof req->command))return 0;
 if(op==SHZ_AUTH_REGISTER) {
  if(req->roles&~SHZ_ROLE_ADMIN||req->image[0]||req->command[0])return 0;
  action=req->roles?"Enroll administrator (volatile store)":"Register account (volatile store)";
 } else if(op==SHZ_AUTH_ELEVATE_LAUNCH)action="Run as administrator";
 else if(op==SHZ_AUTH_LOGIN_LAUNCH)action="Sign in and run";
 else return 0;
 if(!append(out,capacity,&used,"Operation: ")||!append(out,capacity,&used,action))goto refuse;
 if(op!=SHZ_AUTH_REGISTER) {
  if(!req->image[0]||!req->command[0])goto refuse;
  if(!append(out,capacity,&used,"\nSelected executable: ")||!append(out,capacity,&used,req->image)||
     !append(out,capacity,&used,"\nCommand line: ")||!append(out,capacity,&used,req->command))goto refuse;
 }
 return 1;
refuse:
 out[0]=0;return 0;
}
