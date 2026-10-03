/* SPDX-License-Identifier: GPL-2.0-only
 * Actual HKCU C bodies. Only Windows types, heap and syscall transport are host adapters.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <assert.h>
typedef uint8_t BYTE,UCHAR,BOOLEAN;
typedef uint16_t USHORT;
typedef uint32_t DWORD,ULONG,ACCESS_MASK,REGSAM,*PULONG,*LPDWORD;
typedef int32_t LONG,NTSTATUS;
typedef uint64_t ULONG64,ULONGLONG;
typedef int64_t LONGLONG;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef void VOID,*PVOID,*HANDLE,*HKEY,*PSID;
typedef HANDLE *PHANDLE;typedef HKEY *PHKEY;
typedef wchar_t WCHAR,*PWSTR,*LPWSTR;typedef const WCHAR *LPCWSTR,*PCWSTR;
typedef int BOOL;
typedef void *LPSECURITY_ATTRIBUTES;
typedef struct {USHORT Length,MaximumLength;WCHAR *Buffer;} SHZ_UNICODE_STRING;
typedef struct {ULONG Length;HANDLE RootDirectory;SHZ_UNICODE_STRING *ObjectName;ULONG Attributes;
 void *SecurityDescriptor,*SecurityQualityOfService;} SHZ_OBJECT_ATTRIBUTES;
typedef struct {ULONG_PTR Status,Information;} SHZ_IO_STATUS_BLOCK;
typedef struct {BYTE Value[6];} SID_IDENTIFIER_AUTHORITY;
typedef struct {BYTE Revision,SubAuthorityCount;SID_IDENTIFIER_AUTHORITY IdentifierAuthority;DWORD SubAuthority[1];} SID;
typedef struct {PSID Sid;DWORD Attributes;} SID_AND_ATTRIBUTES;
typedef struct {SID_AND_ATTRIBUTES User;} TOKEN_USER;
#define NTAPI
#define WINAPI
#define DLLAPI
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_NO_MEMORY ((NTSTATUS)0xc0000017)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xc0000008)
#define STATUS_NO_TOKEN ((NTSTATUS)0xc000007c)
#define STATUS_BAD_TOKEN_TYPE ((NTSTATUS)0xc000005c)
#define STATUS_BAD_IMPERSONATION_LEVEL ((NTSTATUS)0xc00000a5)
#define STATUS_INVALID_SID ((NTSTATUS)0xc0000078)
#define ERROR_SUCCESS 0
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_NOT_SUPPORTED 50
#define ERROR_INVALID_PARAMETER 87
#define ERROR_BAD_PATHNAME 161
#define ERROR_INVALID_SID 1337
#define ERROR_BAD_IMPERSONATION_LEVEL 1346
#define ERROR_BAD_TOKEN_TYPE 1349
#define REG_OPTION_OPEN_LINK 8
#define REG_OPTION_BACKUP_RESTORE 4
#define KEY_READ 0x20019u
#define KEY_ALL_ACCESS 0xf003fu
#define KEY_NOTIFY 0x10u
#define KEY_QUERY_VALUE 1u
#define TOKEN_QUERY 8u
#define SID_REVISION 1
#define SID_MAX_SUB_AUTHORITIES 15
#define SECURITY_MAX_SID_SIZE 68
#define MAXDWORD UINT32_MAX
#define CURRENT_PROCESS ((HANDLE)(intptr_t)-1)
#define CURRENT_THREAD ((HANDLE)(intptr_t)-2)
#define HKEY_CURRENT_USER ((HKEY)(intptr_t)(int32_t)0x80000001)
#define HKEY_LOCAL_MACHINE ((HKEY)(intptr_t)(int32_t)0x80000002)
#define SHZ_TOK_OPEN_PROCESS 1
#define SHZ_TOK_OPEN_THREAD 2
#define SHZ_TOK_QUERY 3
/* ACTUAL_TOKEN_RECORD */
/* ACTUAL_NTREG_HEADER */
static NTSTATUS NtShzToken(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
static shz_token_info primary,thread_token;
static NTSTATUS thread_open_status,process_open_status,query_status,auth_status,key_status;
static NTSTATUS close_status;
static HANDLE query_failure_target;
static unsigned token_opens,token_closes,queries,auth_queries,key_opens,key_closes;
static unsigned allocations,frees,fail_allocation,live_blocks,checks,failures;
static shz_auth_reply authority;
static void *blocks[64];
typedef struct {WCHAR path[512];BOOL used;} key_handle;
static key_handle handles[48];
static WCHAR observed[512];
static void *host_publish(void **,void *,void *);
static void (*publication_hook)(void **,void *);
#define __sync_val_compare_and_swap(ptr,old,value) host_publish((void **)(ptr),(void *)(old),(void *)(value))
static size_t host_wlen(const WCHAR *w){size_t n=0;while(w[n])n++;return n;}
static BOOL host_weq(const WCHAR *a,const WCHAR *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void host_wcopy(WCHAR *dst,const WCHAR *src,size_t n){memcpy(dst,src,n*sizeof *dst);dst[n]=0;}
static void *ShzProcessHeap(void){return (void *)(uintptr_t)0x1234;}
static void *RtlAllocateHeap(void *heap,ULONG flags,size_t size){
 assert(heap==ShzProcessHeap()&&!flags);allocations++;
 if(fail_allocation==allocations)return NULL;
 for(unsigned i=0;i<64;i++)if(!blocks[i]){blocks[i]=malloc(size);assert(blocks[i]);live_blocks++;return blocks[i];}
 abort();
}
static BOOLEAN RtlFreeHeap(void *heap,ULONG flags,void *ptr){
 assert(heap==ShzProcessHeap()&&!flags);
 for(unsigned i=0;i<64;i++)if(blocks[i]==ptr){free(ptr);blocks[i]=NULL;live_blocks--;frees++;return TRUE;}
 abort();
}
static DWORD RtlNtStatusToDosError(NTSTATUS st){
 switch(st){case STATUS_SUCCESS:return ERROR_SUCCESS;case STATUS_NO_MEMORY:return ERROR_NOT_ENOUGH_MEMORY;
 case STATUS_INVALID_HANDLE:return ERROR_INVALID_HANDLE;case STATUS_INVALID_PARAMETER:return ERROR_INVALID_PARAMETER;
 case STATUS_INVALID_SID:return ERROR_INVALID_SID;case STATUS_BAD_IMPERSONATION_LEVEL:return ERROR_BAD_IMPERSONATION_LEVEL;
 case STATUS_BAD_TOKEN_TYPE:return ERROR_BAD_TOKEN_TYPE;default:return ERROR_ACCESS_DENIED;}
}
static NTSTATUS shz_last_status(void){return 0;}
VOID NTAPI RtlInitUnicodeString(SHZ_UNICODE_STRING *us,PCWSTR w){
 us->Buffer=(WCHAR *)w;us->Length=(USHORT)(host_wlen(w)*sizeof(WCHAR));us->MaximumLength=us->Length+sizeof(WCHAR);
}
NTSTATUS NTAPI NtClose(HANDLE h){
 if(h==&primary||h==&thread_token){token_closes++;return close_status;}
 key_handle *k=h;assert(k>=handles&&k<handles+48&&k->used);k->used=FALSE;key_closes++;return 0;
}
static NTSTATUS NtShzToken(ULONG_PTR op,ULONG_PTR a2,ULONG_PTR a3,ULONG_PTR a4){
 if(op==SHZ_TOK_OPEN_PROCESS||op==SHZ_TOK_OPEN_THREAD){
  assert(a3==TOKEN_QUERY);assert((HANDLE)a2==(op==SHZ_TOK_OPEN_PROCESS?CURRENT_PROCESS:CURRENT_THREAD));
  NTSTATUS st=op==SHZ_TOK_OPEN_PROCESS?process_open_status:thread_open_status;
  if(st)return st;
  token_opens++;*(PHANDLE)a4=op==SHZ_TOK_OPEN_PROCESS?(HANDLE)&primary:(HANDLE)&thread_token;return 0;
 }
 if(op==SHZ_TOK_QUERY){queries++;assert(a4==sizeof(shz_token_info));assert((void *)a2==&primary||(void *)a2==&thread_token);
  if(query_status&&(!query_failure_target||(HANDLE)a2==query_failure_target))return query_status;
  memcpy((void *)a3,(void *)a2,(size_t)a4);return 0;}
 assert(op==SHZ_AUTH_QUERY&&!a2&&a3==sizeof(shz_auth_reply));auth_queries++;
 if(auth_status)return auth_status;
 memcpy((void *)a4,&authority,sizeof authority);return 0;
}
/* ACTUAL_TOKEN_WRAPPERS */
static DWORD GetLengthSid(PSID sid){return 8+4*((SID *)sid)->SubAuthorityCount;}
/* ACTUAL_TOKEN_USER_RENDERING */
static NTSTATUS open_native(PHANDLE out,ACCESS_MASK desired,SHZ_OBJECT_ATTRIBUTES *oa){
 (void)desired;key_opens++;assert(oa&&oa->ObjectName);
 host_wcopy(observed,oa->ObjectName->Buffer,oa->ObjectName->Length/sizeof(WCHAR));
 if(key_status)return key_status;
 for(unsigned i=0;i<48;i++)if(!handles[i].used){handles[i].used=TRUE;host_wcopy(handles[i].path,observed,host_wlen(observed));*out=&handles[i];return 0;}
 return STATUS_NO_MEMORY;
}
NTSTATUS NTAPI NtOpenKey(PHANDLE h,ACCESS_MASK a,SHZ_OBJECT_ATTRIBUTES *oa){return open_native(h,a,oa);}
NTSTATUS NTAPI NtOpenKeyEx(PHANDLE h,ACCESS_MASK a,SHZ_OBJECT_ATTRIBUTES *oa,ULONG options){(void)options;return open_native(h,a,oa);}
NTSTATUS NTAPI NtCreateKey(PHANDLE h,ACCESS_MASK a,SHZ_OBJECT_ATTRIBUTES *oa,ULONG title,SHZ_UNICODE_STRING *cls,ULONG options,PULONG disp){
 (void)title;(void)cls;(void)options;if(disp)*disp=1;return open_native(h,a,oa);
}
/* ACTUAL_RTLREG_UNIT */
/* ACTUAL_REGISTRY_FRONTEND */
/* ACTUAL_REG_CURRENT_USER_UNIT */
#define CHECK(c) do{checks++;if(!(c)){failures++;fprintf(stderr,"%s:%d: %s\n",__func__,__LINE__,#c);}}while(0)
static void setup(void){
 primary=(shz_token_info){.type=1,.auth_id=((uint64_t)1000<<32)|1,.session=1,.integrity_rid=0x2000};
 thread_token=(shz_token_info){.type=2,.imp_level=2,.auth_id=primary.auth_id,.session=1,.integrity_rid=0x2000};
 authority=(shz_auth_reply){.version=SHZ_AUTH_VERSION,.accounts=2};
 thread_open_status=STATUS_NO_TOKEN;process_open_status=query_status=auth_status=key_status=close_status=0;
 token_opens=token_closes=queries=auth_queries=key_opens=key_closes=allocations=frees=fail_allocation=0;
 observed[0]=0;publication_hook=NULL;query_failure_target=NULL;
}
static void expect_identity(DWORD uid){
 SHZ_UNICODE_STRING path={0};BYTE sid[SECURITY_MAX_SID_SIZE];WCHAR expected[100];
 token_user_sid(&primary,sid);SID *s=(SID *)sid;CHECK(s->SubAuthority[4]==uid);
 const char *prefix="\\Registry\\User\\S-1-5-21-2210311251-3305482031-1094512843-";
 char ascii[100];snprintf(ascii,sizeof ascii,"%s%u",prefix,uid);
 unsigned i;for(i=0;ascii[i];i++)expected[i]=(WCHAR)(unsigned char)ascii[i];expected[i]=0;
 CHECK(RtlFormatCurrentUserKeyPath(&path)==0);
 if(path.Buffer){CHECK(host_weq(path.Buffer,expected));CHECK(path.Length==host_wlen(expected)*sizeof(WCHAR));
  CHECK(path.MaximumLength==path.Length+sizeof(WCHAR));RtlFreeUnicodeString(&path);}
 HKEY h=NULL;CHECK(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Settings",0,KEY_READ,&h)==ERROR_SUCCESS);
 WCHAR child[120];host_wcopy(child,expected,host_wlen(expected));size_t n=host_wlen(child);
 host_wcopy(child+n,L"\\Software\\Settings",host_wlen(L"\\Software\\Settings"));CHECK(host_weq(observed,child));
 if(h)CHECK(RegCloseKey(h)==ERROR_SUCCESS);
 CHECK(RegOpenCurrentUser(KEY_READ,&h)==ERROR_SUCCESS);CHECK(host_weq(observed,expected));
 if(h)CHECK(RegCloseKey(h)==ERROR_SUCCESS);
 CHECK(token_opens==token_closes&&live_blocks==0);
}
static void actual_two_identities(void){
 setup();expect_identity(1000);primary.auth_id=((uint64_t)1001<<32)|2;primary.session=2;expect_identity(1001);
 primary.auth_id=((uint64_t)1015<<32)|3;primary.session=3;expect_identity(1015);
}
static void expect_failure(NTSTATUS expected){
 SHZ_UNICODE_STRING path={.Length=99,.MaximumLength=100,.Buffer=(WCHAR *)(uintptr_t)1};HKEY h=(HKEY)(uintptr_t)1;
 NTSTATUS st=RtlFormatCurrentUserKeyPath(&path);CHECK(st==expected);CHECK(!path.Buffer&&!path.Length&&!path.MaximumLength);
 if(!st)RtlFreeUnicodeString(&path); /* Keep an intentionally failing old source fixture independent. */
 LONG e=RegOpenCurrentUser(KEY_READ,&h);CHECK(e==(LONG)RtlNtStatusToDosError(expected));CHECK(!h);
 if(!e&&h)RegCloseKey(h);
 e=RegOpenKeyExW(HKEY_CURRENT_USER,L"Software",0,KEY_READ,&h);CHECK(e==(LONG)RtlNtStatusToDosError(expected));
 if(!e&&h)RegCloseKey(h);
 CHECK(key_opens==0&&token_opens==token_closes&&live_blocks==0);
}
static void actual_failure_and_cleanup(void){
 setup();thread_open_status=STATUS_ACCESS_DENIED;expect_failure(STATUS_ACCESS_DENIED);CHECK(!token_opens&&!queries);
 setup();process_open_status=STATUS_INVALID_HANDLE;expect_failure(STATUS_INVALID_HANDLE);CHECK(!token_opens);
 setup();query_status=STATUS_ACCESS_DENIED;expect_failure(STATUS_ACCESS_DENIED);CHECK(token_opens==3);
 setup();close_status=STATUS_INVALID_HANDLE;expect_failure(STATUS_INVALID_HANDLE);
 setup();primary.auth_id=((uint64_t)1016<<32)|1;expect_failure(STATUS_ACCESS_DENIED);
 setup();primary.auth_id=UINT64_MAX;expect_failure(STATUS_ACCESS_DENIED);
 setup();primary.auth_id=0;expect_failure(STATUS_ACCESS_DENIED);
 setup();primary.type=2;expect_failure(STATUS_BAD_TOKEN_TYPE);
 setup();fail_allocation=1;SHZ_UNICODE_STRING path={0};CHECK(RtlFormatCurrentUserKeyPath(&path)==STATUS_NO_MEMORY);
 CHECK(!path.Buffer&&token_opens==token_closes&&live_blocks==0);
 setup();key_status=STATUS_ACCESS_DENIED;HKEY h=(HKEY)(uintptr_t)1;
 CHECK(RegOpenCurrentUser(KEY_READ,&h)==ERROR_ACCESS_DENIED&&!h);CHECK(live_blocks==0&&token_opens==token_closes);
 setup();CHECK(RtlFormatCurrentUserKeyPath(NULL)==STATUS_INVALID_PARAMETER);CHECK(!token_opens&&!allocations);
 CHECK(RegOpenCurrentUser(KEY_READ,NULL)==ERROR_INVALID_PARAMETER);
}
static void actual_legacy_authority(void){
 setup();primary.auth_id=0x4e7;authority.accounts=0;expect_identity(1001);CHECK(auth_queries>0);
 setup();primary.auth_id=0x4e7;expect_failure(STATUS_ACCESS_DENIED);
 setup();primary.auth_id=0x4e7;authority.accounts=0;auth_status=STATUS_INVALID_HANDLE;expect_failure(STATUS_INVALID_HANDLE);
 setup();primary.auth_id=0x4e7;authority.accounts=0;authority.version++;expect_failure(STATUS_ACCESS_DENIED);
 setup();primary.auth_id=0x4e7;authority.accounts=0;authority.reserved=1;expect_failure(STATUS_ACCESS_DENIED);
}
static void actual_impersonation(void){
 setup();thread_open_status=0;expect_identity(1000);CHECK(token_opens==token_closes&&token_opens==6);
 setup();thread_open_status=0;thread_token.imp_level=3;expect_identity(1000);
 setup();thread_open_status=0;thread_token.auth_id=((uint64_t)1001<<32)|2;expect_failure(STATUS_ACCESS_DENIED);
 setup();thread_open_status=0;thread_token.integrity_rid=0x1000;expect_failure(STATUS_ACCESS_DENIED);
 setup();thread_open_status=0;thread_token.session++;expect_failure(STATUS_ACCESS_DENIED);
 setup();thread_open_status=0;thread_token.imp_level=1;expect_failure(STATUS_ACCESS_DENIED);
 setup();thread_open_status=0;thread_token.type=1;expect_failure(STATUS_BAD_TOKEN_TYPE);
 setup();thread_open_status=0;query_status=STATUS_INVALID_HANDLE;expect_failure(STATUS_INVALID_HANDLE);
 setup();thread_open_status=0;query_status=STATUS_INVALID_HANDLE;query_failure_target=&primary;expect_failure(STATUS_INVALID_HANDLE);
 CHECK(token_opens==6&&token_closes==6);
 setup();thread_open_status=0;process_open_status=STATUS_ACCESS_DENIED;expect_failure(STATUS_ACCESS_DENIED);
 setup();thread_open_status=0;close_status=STATUS_INVALID_HANDLE;expect_failure(STATUS_INVALID_HANDLE);
}
static void actual_long_subkey_cleanup(void){
 setup();WCHAR sub[220];for(unsigned i=0;i<219;i++)sub[i]='x';sub[219]=0;HKEY h=NULL;
 fail_allocation=2;CHECK(RegOpenKeyExW(HKEY_CURRENT_USER,sub,0,KEY_READ,&h)==ERROR_NOT_ENOUGH_MEMORY);
 CHECK(!h&&live_blocks==0&&key_opens==0&&token_opens==token_closes);
 setup();CHECK(RegCreateKeyExW(HKEY_CURRENT_USER,sub,0,NULL,0,KEY_ALL_ACCESS,NULL,&h,NULL)==0);
 CHECK(live_blocks==0&&token_opens==token_closes);if(h)RegCloseKey(h);
}
static void actual_notify_identity_cache(void){
 setup();HANDLE first=NULL,again=NULL,second=NULL;CHECK(notify_handle(HKEY_CURRENT_USER,&first)==0);
 unsigned before=queries;CHECK(notify_handle(HKEY_CURRENT_USER,&again)==0&&again==first);CHECK(queries>before);
 primary.auth_id=((uint64_t)1001<<32)|2;CHECK(notify_handle(HKEY_CURRENT_USER,&second)==0&&second!=first);
 if(first&&second)CHECK(!host_weq(((key_handle *)first)->path,((key_handle *)second)->path));
 query_status=STATUS_ACCESS_DENIED;before=key_opens;CHECK(notify_handle(HKEY_CURRENT_USER,&again)==ERROR_ACCESS_DENIED);CHECK(key_opens==before);
 CHECK(token_opens==token_closes);
}
static void *host_publish(void **slot,void *expected,void *value){
 if(publication_hook){void (*hook)(void **,void *)=publication_hook;publication_hook=NULL;hook(slot,value);}
 void *previous=*slot;if(previous==expected)*slot=value;return previous;
}
#ifdef HAS_BOUNDED_SID_FORMAT
static void actual_bounded_sid_format(void){
 setup();struct {TOKEN_USER user;BYTE sid[SECURITY_MAX_SID_SIZE];} buffer={0};
 SHZ_UNICODE_STRING out={0};buffer.user.User.Sid=buffer.sid;SID *sid=(SID *)buffer.sid;
 sid->Revision=1;sid->SubAuthorityCount=15;memset(sid->IdentifierAuthority.Value,255,6);
 for(unsigned i=0;i<15;i++){DWORD value=UINT32_MAX;memcpy(buffer.sid+8+4*i,&value,4);}
 CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==0);
 if(out.Buffer){CHECK(out.Length==398);CHECK(host_weq(out.Buffer,L"\\Registry\\User\\S-1-281474976710655-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295-4294967295"));RtlFreeUnicodeString(&out);}
 sid->SubAuthorityCount=16;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);
 sid->SubAuthorityCount=15;CHECK(format_user_sid(&out,&buffer.user,offsetof(__typeof__(buffer),sid)+SECURITY_MAX_SID_SIZE-1)==STATUS_INVALID_SID);
 sid->Revision=2;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);sid->Revision=1;
 buffer.user.User.Sid=NULL;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);
 buffer.user.User.Sid=(void *)(uintptr_t)1;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);
 buffer.user.User.Sid=&buffer.user;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);
 buffer.user.User.Sid=buffer.sid+SECURITY_MAX_SID_SIZE;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);
 buffer.user.User.Sid=(void *)UINTPTR_MAX;CHECK(format_user_sid(&out,&buffer.user,sizeof buffer)==STATUS_INVALID_SID);
 CHECK(format_user_sid(&out,NULL,0)==STATUS_INVALID_SID);
 CHECK(format_user_sid(&out,&buffer.user,sizeof(TOKEN_USER)-1)==STATUS_INVALID_SID);CHECK(live_blocks==0);
 CHECK(format_user_sid(&out,&buffer.user,SIZE_MAX)==STATUS_INVALID_SID);
}
#endif
static void release_notification_storage(void){
#ifdef HAS_USER_NOTIFY_CACHE
 for(unsigned i=0;i<sizeof g_notify_users/sizeof *g_notify_users;i++)if(g_notify_users[i]){
  NtClose(g_notify_users[i]->h);RtlFreeHeap(ShzProcessHeap(),0,g_notify_users[i]);g_notify_users[i]=NULL;
 }
#endif
 for(unsigned i=0;i<8;i++)if(g_notify_roots[i]){NtClose(g_notify_roots[i]);g_notify_roots[i]=NULL;}
}
#ifdef HAS_USER_NOTIFY_CACHE
/* Deterministically publish the same identity between production's acquire load
 * and CAS. This is the transport adapter boundary, not a copied cache algorithm. */
static void publish_notify_competitor(void **slot,void *value){
 user_notify_root *candidate=value,*winner=RtlAllocateHeap(ShzProcessHeap(),0,sizeof *winner);*winner=*candidate;
 SHZ_UNICODE_STRING us={winner->chars*sizeof(WCHAR),(winner->chars+1)*sizeof(WCHAR),winner->path};
 SHZ_OBJECT_ATTRIBUTES oa={.Length=sizeof oa,.ObjectName=&us};
 CHECK(NtOpenKey(&winner->h,KEY_NOTIFY|KEY_QUERY_VALUE,&oa)==0);*slot=winner;
}
static void actual_notify_failure_and_competition(void){
 release_notification_storage();CHECK(live_blocks==0);HANDLE h=NULL;
 setup();fail_allocation=1;CHECK(notify_handle(HKEY_CURRENT_USER,&h)==ERROR_NOT_ENOUGH_MEMORY);
 CHECK(live_blocks==0&&!key_opens&&token_opens==token_closes);
 setup();fail_allocation=2;CHECK(notify_handle(HKEY_CURRENT_USER,&h)==ERROR_NOT_ENOUGH_MEMORY);
 CHECK(live_blocks==0&&!key_opens&&token_opens==token_closes);
 setup();key_status=STATUS_ACCESS_DENIED;CHECK(notify_handle(HKEY_CURRENT_USER,&h)==ERROR_ACCESS_DENIED);
 CHECK(live_blocks==0&&key_opens==1&&token_opens==token_closes);
 setup();publication_hook=publish_notify_competitor;CHECK(notify_handle(HKEY_CURRENT_USER,&h)==0);
 CHECK(h==g_notify_users[0]->h&&key_opens==2&&key_closes==1&&live_blocks==1);
 CHECK(token_opens==token_closes);release_notification_storage();CHECK(live_blocks==0&&key_closes==2);
}
#endif
int main(void){
 actual_two_identities();actual_failure_and_cleanup();actual_legacy_authority();actual_impersonation();actual_long_subkey_cleanup();
#ifdef HAS_BOUNDED_SID_FORMAT
 actual_bounded_sid_format();
#endif
 actual_notify_identity_cache();release_notification_storage();CHECK(live_blocks==0);
#ifdef HAS_USER_NOTIFY_CACHE
 actual_notify_failure_and_competition();
#endif
 printf("HKCU actual frontend: %u assertions, %u failures; native Windows98 acceptance pending\n",checks,failures);return failures?1:0;
}
