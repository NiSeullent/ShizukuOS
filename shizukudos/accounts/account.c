/* SPDX-License-Identifier: GPL-2.0-only */
#include "account.h"
#include "kdf.h"
#include <string.h>
static int name_copy(char out[32],const char *name) {
 unsigned i; if(!name)return -1;
 for(i=0;i<32;i++) {unsigned char c=(unsigned char)name[i];if(!c){out[i]=0;return i?0:-1;}if(c>='A'&&c<='Z')c+=32;if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-'))return -1;out[i]=(char)c;}return -1;
}
void shz_accounts_init(shz_accounts *d,shz_entropy e,void *c){memset(d,0,sizeof *d);d->entropy=e;d->entropy_ctx=c;d->next_session=1;}
int shz_account_register(shz_accounts *d,const shz_subject *who,int bootstrap,const char *name,const void *pw,size_t pn,uint32_t roles) {
 char n[32]; shz_account a;unsigned i;
 if(!d||!who||!pw||pn<8||pn>128||roles&~SHZ_ROLE_ADMIN||name_copy(n,name))return SHZ_AUTH_INVALID;
 if(!((!d->count&&bootstrap)||(d->count&&who->uid&&who->roles==SHZ_ROLE_ADMIN&&who->integrity>=0x3000&&!who->flags)))return SHZ_AUTH_DENIED;
 /* A first ordinary account would consume enrollment with no administrator
  * able to authorize later registrations. Refuse before entropy or mutation. */
 if(!d->count&&roles!=SHZ_ROLE_ADMIN)return SHZ_AUTH_DENIED;
 if(d->count>=SHZ_ACCOUNT_LIMIT)return SHZ_AUTH_FULL;
 for(i=0;i<d->count;i++)if(!strcmp(n,d->accounts[i].name))return SHZ_AUTH_DENIED;
 memset(&a,0,sizeof a);memcpy(a.name,n,sizeof n);a.uid=1000+d->count;a.roles=roles;
 if(!d->entropy||d->entropy(d->entropy_ctx,a.salt,32))return SHZ_AUTH_ENTROPY;
 if(shz_pbkdf2(pw,pn,a.salt,32,SHZ_KDF_ROUNDS,a.digest)){shz_secret_clear(&a,sizeof a);return SHZ_AUTH_INVALID;}
 d->accounts[d->count++]=a;shz_secret_clear(&a,sizeof a);return 0;
}
int shz_account_login(shz_accounts *d,const char *name,const void *pw,size_t pn,uint64_t now,shz_subject *out) {
 char n[32];shz_account *a=0;uint8_t digest[32],salt[32]={0};unsigned i,diff=0;shz_subject s={0};
 if(!d||!out||!pw||pn<8||pn>128||name_copy(n,name))return SHZ_AUTH_DENIED;
 for(i=0;i<d->count;i++)if(!strcmp(n,d->accounts[i].name))a=&d->accounts[i];
 if(a&&now<a->locked_until)return SHZ_AUTH_LOCKED;
 if(a)memcpy(salt,a->salt,32);
 shz_pbkdf2(pw,pn,salt,32,SHZ_KDF_ROUNDS,digest);
 for(i=0;i<32;i++)diff|=digest[i]^(a?a->digest[i]:0);
 shz_secret_clear(digest,32);shz_secret_clear(salt,32);
 if(!a||diff){if(a&&++a->failures>=5){a->locked_until=now>UINT64_MAX-30000?UINT64_MAX:now+30000;a->failures=0;}return SHZ_AUTH_DENIED;}
 if(!d->next_session)return SHZ_AUTH_FULL;
 a->failures=0;a->locked_until=0;s.uid=a->uid;s.roles=a->roles;s.integrity=0x2000;s.session=d->next_session++;
 s.auth_id=((uint64_t)s.uid<<32)|s.session;*out=s;return 0;
}
int shz_account_elevate(shz_accounts *d,const char *n,const void *p,size_t l,uint64_t now,shz_subject *out) {
 shz_subject s;int st=shz_account_login(d,n,p,l,now,&s);if(st)return st;if(s.roles!=SHZ_ROLE_ADMIN)return SHZ_AUTH_DENIED;s.integrity=0x3000;*out=s;return 0;
}
int shz_subject_access(const shz_subject *a,const shz_subject *b) {
 if(!a||!b)return 0;
 if(a->uid&&a->roles==SHZ_ROLE_ADMIN&&a->integrity>=0x3000&&!a->flags)return 1;
 return a->uid==b->uid&&a->session==b->session&&a->integrity>=b->integrity;
}
static unsigned lower(unsigned c){return c>='A'&&c<='Z'?c+32:c;}
int shz_subject_path(const shz_subject *s,const char *path,int write) {
 char p[300];unsigned n=0,i,begin;uint32_t uid=0;int profile=0;
 if(!s||!path)return 0;
 if(!strncmp(path,"\\??\\",4))path+=4;
 while(path[n]&&n<sizeof p-1){p[n]=(char)lower((unsigned char)path[n]);n++;}if(path[n]||n<3)return 0;p[n]=0;
 if(p[0]<'a'||p[0]>'z'||p[1]!=':'||p[2]!='\\')return 0;
 for(i=3,begin=3;i<=n;i++) {if(p[i]==':'||p[i]=='/'||((unsigned char)p[i]<32&&p[i]))return 0;if(p[i]=='\\'||!p[i]){if(i==begin||(i>begin&&(p[i-1]=='.'||p[i-1]==' ')))return 0;begin=i+1;}}
 if(n>=9&&!strncmp(p+3,"users\\",6)) {
  profile=1;i=9;begin=i;while(i<n&&p[i]>='0'&&p[i]<='9'){if(uid>(UINT32_MAX-9)/10)return 0;uid=uid*10+(unsigned)(p[i++]-'0');}
  if(i==begin||!uid||(i<n&&p[i]!='\\'))return 0;
 }
 if(s->uid&&s->roles==SHZ_ROLE_ADMIN&&s->integrity>=0x3000&&!s->flags)return 1;
 if(profile&&uid!=s->uid)return 0;
 if(write)return profile&&s->uid&&s->integrity>=0x2000&&!s->flags;
 return 1;
}
