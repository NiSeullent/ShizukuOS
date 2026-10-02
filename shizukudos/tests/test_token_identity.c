/* SPDX-License-Identifier: GPL-2.0-only
 * Exact token rendering, membership and AccessCheck production bodies.
 * Windows type declarations and native transport are explicit host boundaries.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t BYTE;typedef uint16_t WORD,WCHAR;typedef uint32_t DWORD,ULONG,*PDWORD,*LPDWORD;
typedef int32_t LONG,NTSTATUS;typedef uintptr_t ULONG_PTR;typedef int BOOL,*LPBOOL;
typedef uint64_t ULONG64;typedef BYTE *PUCHAR;typedef void VOID;
typedef void *PVOID,*LPVOID,*HANDLE,*PSID;typedef HANDLE *PHANDLE;
typedef const WCHAR *LPCWSTR;typedef WCHAR *LPWSTR;
typedef struct {DWORD nLength;void *lpSecurityDescriptor;BOOL bInheritHandle;} SECURITY_ATTRIBUTES,*LPSECURITY_ATTRIBUTES;
typedef struct host_startup *LPSTARTUPINFOW;typedef void *LPPROCESS_INFORMATION;
typedef struct {BYTE Value[6];} SID_IDENTIFIER_AUTHORITY;
typedef struct {BYTE Revision,SubAuthorityCount;SID_IDENTIFIER_AUTHORITY IdentifierAuthority;DWORD SubAuthority[1];} SID;
typedef struct {DWORD LowPart;LONG HighPart;} LUID;
typedef union {int64_t QuadPart;} LARGE_INTEGER;
typedef struct {PSID Sid;DWORD Attributes;} SID_AND_ATTRIBUTES;
typedef struct {SID_AND_ATTRIBUTES User;} TOKEN_USER;
typedef struct {DWORD GroupCount;SID_AND_ATTRIBUTES Groups[1];} TOKEN_GROUPS;
typedef struct {LUID Luid;DWORD Attributes;} LUID_AND_ATTRIBUTES;
typedef struct {DWORD PrivilegeCount;LUID_AND_ATTRIBUTES Privileges[1];} TOKEN_PRIVILEGES;
typedef struct {char SourceName[8];LUID SourceIdentifier;} TOKEN_SOURCE;
typedef int TOKEN_TYPE,SECURITY_IMPERSONATION_LEVEL;
typedef struct {LUID TokenId,AuthenticationId;LARGE_INTEGER ExpirationTime;TOKEN_TYPE TokenType;
 SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;DWORD DynamicCharged,DynamicAvailable,GroupCount,PrivilegeCount;LUID ModifiedId;} TOKEN_STATISTICS;
typedef struct {SID_AND_ATTRIBUTES Label;} TOKEN_MANDATORY_LABEL;
typedef struct {DWORD Policy;} TOKEN_MANDATORY_POLICY;
typedef struct {BYTE AclRevision,Sbz1;WORD AclSize,AceCount,Sbz2;} ACL,*PACL;
typedef struct {BYTE AceType,AceFlags;WORD AceSize;} ACE_HEADER;
typedef WORD SECURITY_DESCRIPTOR_CONTROL;
typedef struct {BYTE Revision,Sbz1;WORD Control;PSID Owner,Group;PACL Sacl,Dacl;} SECURITY_DESCRIPTOR;
typedef void *PSECURITY_DESCRIPTOR;
typedef struct {BYTE Revision,Sbz1;WORD Control;DWORD Owner,Group,Sacl,Dacl;} SECURITY_DESCRIPTOR_RELATIVE;
typedef struct {DWORD GenericRead,GenericWrite,GenericExecute,GenericAll;} GENERIC_MAPPING,*PGENERIC_MAPPING;
typedef struct {DWORD PrivilegeCount,Control;LUID_AND_ATTRIBUTES Privilege[1];} PRIVILEGE_SET,*PPRIVILEGE_SET;
typedef struct {WORD control;PSID owner,group;PACL dacl,sacl;} sec_parts_t;
typedef struct {BYTE revision,count;SID_IDENTIFIER_AUTHORITY authority;DWORD sub[5];} test_sid;
enum {TokenUser=1,TokenGroups,TokenPrivileges,TokenOwner,TokenPrimaryGroup,TokenDefaultDacl,TokenSource,
 TokenType,TokenImpersonationLevel,TokenStatistics,TokenRestrictedSids,TokenSessionId,TokenGroupsAndPrivileges,
 TokenSessionReference,TokenSandBoxInert,TokenAuditPolicy,TokenOrigin,TokenElevationType,TokenLinkedToken,
 TokenElevation,TokenHasRestrictions,TokenAccessInformation,TokenVirtualizationAllowed,TokenVirtualizationEnabled,
 TokenIntegrityLevel,TokenUIAccess,TokenMandatoryPolicy,TokenLogonSid,TokenIsAppContainer,TokenCapabilities,
 TokenAppContainerSid,TokenAppContainerNumber};
typedef int TOKEN_INFORMATION_CLASS;
#define WINAPI
#define DLLAPI
#define TRUE 1
#define FALSE 0
#define SECURITY_MAX_SID_SIZE 68
#define SID_MAX_SUB_AUTHORITIES 15
#define SID_REVISION 1
#define SID_HEADER 8u
#define ACL_REVISION 2
#define ACL_REVISION_DS 4
#define SECURITY_DESCRIPTOR_REVISION 1
#define SE_GROUP_MANDATORY 1
#define SE_GROUP_ENABLED_BY_DEFAULT 2
#define SE_GROUP_ENABLED 4
#define SE_GROUP_INTEGRITY 0x20
#define SE_GROUP_INTEGRITY_ENABLED 0x40
#define SE_GROUP_LOGON_ID 0xc0000000u
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 1
#define SE_PRIVILEGE_ENABLED 2
#define SE_DACL_PRESENT 4
#define SE_SACL_PRESENT 0x10
#define SE_SELF_RELATIVE 0x8000
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_EXECUTE 0x20000000u
#define GENERIC_ALL 0x10000000u
#define READ_CONTROL 0x20000
#define WRITE_DAC 0x40000
#define WRITE_OWNER 0x80000
#define DELETE 0x10000
#define STANDARD_RIGHTS_ALL 0x1f0000
#define ACCESS_SYSTEM_SECURITY 0x1000000
#define MAXIMUM_ALLOWED 0x2000000
#define ACCESS_ALLOWED_ACE_TYPE 0
#define ACCESS_DENIED_ACE_TYPE 1
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE 0x11
#define INHERIT_ONLY_ACE 8
#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP 1
#define SYSTEM_MANDATORY_LABEL_NO_READ_UP 2
#define SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP 4
#define TOKEN_MANDATORY_POLICY_NO_WRITE_UP 1
#define TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN 2
#define TokenIsRestricted 40
#define TokenPrimary 1
#define TokenImpersonation 2
#define MAXDWORD UINT32_MAX
#define TOKEN_QUERY 8
#define SHZ_TOK_QUERY 3
#define CURRENT_PROCESS ((HANDLE)(intptr_t)-1)
#define ERROR_NOACCESS 998
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INVALID_SID 1337
#define ERROR_ALLOTTED_SPACE_EXCEEDED 1344
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_NO_SUCH_LOGON_SESSION 1312
#define ERROR_INVALID_ACL 1336
#define ERROR_INVALID_SECURITY_DESCR 1338
#define ERROR_NO_IMPERSONATION_TOKEN 1309
#define ERROR_ACCESS_DENIED 5
#define ERROR_BAD_TOKEN_TYPE 1349
#define ERROR_NOT_SUPPORTED 50
/* @PRODUCTION_TOKEN_RECORD@ */
static DWORD error,accounts_count;
static int query_failure,open_failure,auth_failure,bad_auth_version;
static unsigned opens,closes,auth_queries,launches;
static shz_token_info caller,target;
static void shz_set_last_error(DWORD e){error=e;}
static DWORD RtlNtStatusToDosError(NTSTATUS st){(void)st;return ERROR_ACCESS_DENIED;}
static NTSTATUS NtOpenProcessToken(HANDLE p,DWORD rights,PHANDLE out){
 assert(p==CURRENT_PROCESS&&rights==TOKEN_QUERY);if(open_failure)return (NTSTATUS)0xc0000022;
 opens++;*out=&caller;return 0;
}
static NTSTATUS NtClose(HANDLE h){assert(h==&caller);closes++;return 0;}
static BOOL CreateProcessW(LPCWSTR app,LPWSTR cmd,LPSECURITY_ATTRIBUTES pa,LPSECURITY_ATTRIBUTES ta,
 BOOL inherit,DWORD flags,LPVOID env,LPCWSTR dir,LPSTARTUPINFOW si,LPPROCESS_INFORMATION pi){
 (void)app;(void)cmd;(void)pa;(void)ta;(void)inherit;(void)flags;(void)env;(void)dir;(void)si;(void)pi;
 launches++;return TRUE;
}
static NTSTATUS NtShzToken(ULONG_PTR op,ULONG_PTR a2,ULONG_PTR a3,ULONG_PTR a4){
 if(op==3){if(query_failure&&(query_failure==1||(void *)a2==&caller))return (NTSTATUS)0xc0000022;assert(a4==sizeof(shz_token_info));
  assert((void *)a2==&caller||(void *)a2==&target);memcpy((void *)a3,(void *)a2,(size_t)a4);return 0;}
 assert(op==SHZ_AUTH_QUERY&&!a2&&a3==sizeof(shz_auth_reply));auth_queries++;
 if(auth_failure)return (NTSTATUS)0xc0000022;
 shz_auth_reply r={0};r.version=bad_auth_version?2:1;r.accounts=accounts_count;memcpy((void *)a4,&r,sizeof r);return 0;
}
static BOOL sec_unsupported(const char *fn,const char *what,DWORD e){(void)fn;(void)what;error=e;return FALSE;}
/* Original fixed-SID initializer boundary, unused by the corrected source. */
static BOOL ConvertStringSidToSidW(const WCHAR *w,PSID *out){
 (void)w;test_sid *s=malloc(sizeof *s);assert(s);*s=(test_sid){1,5,{{0,0,0,0,0,5}},{21,2210311251u,3305482031u,1094512843u,1001}};*out=s;return TRUE;
}
static void LocalFree(void *p){free(p);}
/* @PRODUCTION_SID_FUNCTIONS@ */
/* @PRODUCTION_ACL_FUNCTIONS@ */
/* @PRODUCTION_TOKEN_RENDERING@ */

static unsigned checks,failures;
#define CHECK(c) do{checks++;if(!(c)){failures++;fprintf(stderr,"%s:%d: %s\n",__func__,__LINE__,#c);return;}}while(0)
static test_sid sid_for(DWORD rid){return (test_sid){1,5,{{0,0,0,0,0,5}},{21,2210311251u,3305482031u,1094512843u,rid}};}
static DWORD rid(PSID p){SID *s=p;assert(IsValidSid(p)&&s->SubAuthorityCount==5);return s->SubAuthority[4];}
static void setup(void){
 caller=(shz_token_info){.type=1,.auth_id=((uint64_t)1000<<32)|1,.integrity_rid=0x2000,.session=1};
 target=(shz_token_info){.type=2,.auth_id=((uint64_t)1001<<32)|2,.integrity_rid=0x2000,.session=2};
 accounts_count=2;query_failure=open_failure=auth_failure=bad_auth_version=0;error=0;opens=closes=auth_queries=launches=0;
}
typedef union {uint64_t aligned;BYTE bytes[512];} output_buffer;
static void target_information(void){
 output_buffer b;DWORD n=0;test_sid expected=sid_for(1001);
 CHECK(GetTokenInformation(&target,TokenUser,b.bytes,sizeof b.bytes,&n));
 CHECK(EqualSid(((TOKEN_USER *)b.bytes)->User.Sid,&expected));
 CHECK(GetTokenInformation(&target,TokenOwner,b.bytes,sizeof b.bytes,&n));CHECK(EqualSid(*(PSID *)b.bytes,&expected));
 CHECK(GetTokenInformation(&target,TokenDefaultDacl,b.bytes,sizeof b.bytes,&n));
 PACL acl=*(PACL *)b.bytes;CHECK(acl->AceCount==2);CHECK(EqualSid((BYTE *)(acl+1)+8,&expected));
 CHECK(rid(sec_user_sid())==1000&&opens==closes);
}
static void caller_independence(void){
 output_buffer b;DWORD n;target.auth_id=((uint64_t)1015<<32)|2;
 CHECK(GetTokenInformation(&target,TokenDefaultDacl,b.bytes,sizeof b.bytes,&n));
 CHECK(rid((BYTE *)(*(PACL *)b.bytes+1)+8)==1015);
 test_sid own=sid_for(1015),other=sid_for(1000),legacy=sid_for(1001);
 CHECK(token_has_sid(&target,&own));CHECK(!token_has_sid(&target,&other));CHECK(!token_has_sid(&target,&legacy));
 caller.auth_id=((uint64_t)1014<<32)|1;CHECK(token_has_sid(&target,&own));CHECK(!token_has_sid(&target,&other));
}
static void anonymous_collision(void){
 output_buffer b;DWORD n;target.auth_id=0x4e7;test_sid guest=sid_for(0),account=sid_for(1001);
 CHECK(GetTokenInformation(&target,TokenUser,b.bytes,sizeof b.bytes,&n));CHECK(EqualSid(((TOKEN_USER *)b.bytes)->User.Sid,&guest));
 CHECK(GetTokenInformation(&target,TokenOwner,b.bytes,sizeof b.bytes,&n));CHECK(EqualSid(*(PSID *)b.bytes,&guest));
 CHECK(GetTokenInformation(&target,TokenDefaultDacl,b.bytes,sizeof b.bytes,&n));CHECK(EqualSid((BYTE *)(*(PACL *)b.bytes+1)+8,&guest));
 CHECK(token_has_sid(&target,&guest));CHECK(!token_has_sid(&target,&account));
}
static void activation_and_immutable_storage(void){
 caller.auth_id=0x4e7;accounts_count=0;PSID before=sec_user_sid();CHECK(rid(before)==1001);
 accounts_count=2;PSID after=sec_user_sid();CHECK(rid(after)==0);CHECK(rid(before)==1001);
 caller.auth_id=((uint64_t)1000<<32)|1;PSID first=sec_user_sid();CHECK(rid(first)==1000);
 caller.auth_id=((uint64_t)1001<<32)|2;PSID second=sec_user_sid();CHECK(rid(second)==1001);CHECK(rid(first)==1000);
 CHECK(opens==closes);
}
static void bootstrap_identity(void){
 output_buffer b;DWORD n;target.auth_id=UINT64_MAX;caller.auth_id=UINT64_MAX;
 CHECK(GetTokenInformation(&target,TokenUser,b.bytes,sizeof b.bytes,&n));CHECK(rid(((TOKEN_USER *)b.bytes)->User.Sid)==UINT32_MAX);
 CHECK(GetTokenInformation(&target,TokenDefaultDacl,b.bytes,sizeof b.bytes,&n));CHECK(rid((BYTE *)(*(PACL *)b.bytes+1)+8)==UINT32_MAX);
 CHECK(rid(sec_user_sid())==UINT32_MAX&&opens==closes);
 test_sid admin={1,2,{{0,0,0,0,0,5}},{32,544,0,0,0}};CHECK(!token_has_sid(&target,&admin));
}
static void transport_denial(void){
 caller.auth_id=0x4e7;auth_failure=1;CHECK(rid(sec_user_sid())==0);auth_failure=0;bad_auth_version=1;
 CHECK(rid(sec_user_sid())==0);bad_auth_version=0;query_failure=1;CHECK(rid(sec_user_sid())==0&&opens==closes);
 query_failure=0;open_failure=1;CHECK(rid(sec_user_sid())==0&&opens==closes);
}
static void access_check_identity(void){
 BYTE aclbuf[128];PACL acl=(PACL)aclbuf;test_sid chosen=sid_for(1001);
 SECURITY_DESCRIPTOR sd={.Revision=1,.Control=SE_DACL_PRESENT,.Dacl=acl};
 GENERIC_MAPPING map={1,2,4,7};DWORD granted=0,len=sizeof(PRIVILEGE_SET);PRIVILEGE_SET privileges={0};BOOL okay=FALSE;
 CHECK(InitializeAcl(acl,sizeof aclbuf,ACL_REVISION));CHECK(sec_add_simple_ace(acl,ACCESS_ALLOWED_ACE_TYPE,0,1,&chosen,MAXDWORD));
 CHECK(AccessCheck(&sd,&target,1,&map,&privileges,&len,&granted,&okay)&&okay&&granted==1);
 target.auth_id=0x4e7;okay=TRUE;CHECK(AccessCheck(&sd,&target,1,&map,&privileges,&len,&granted,&okay)&&!okay&&!granted);
 target.auth_id=((uint64_t)1015<<32)|2;okay=TRUE;
 CHECK(AccessCheck(&sd,&target,1,&map,&privileges,&len,&granted,&okay)&&!okay&&!granted);
 chosen=sid_for(1015);CHECK(InitializeAcl(acl,sizeof aclbuf,ACL_REVISION));sd.Owner=&chosen;
 CHECK(AccessCheck(&sd,&target,WRITE_DAC,&map,&privileges,&len,&granted,&okay)&&okay&&granted==WRITE_DAC);
 target.auth_id=((uint64_t)1000<<32)|2;okay=TRUE;
 CHECK(AccessCheck(&sd,&target,WRITE_DAC,&map,&privileges,&len,&granted,&okay)&&!okay&&!granted);
}
static BOOL launch_as(HANDLE token){return CreateProcessAsUserW(token,0,0,0,0,FALSE,0,0,0,0,0);}
static void caller_launch_admission(void){
 target=caller;CHECK(launch_as(&target)&&launches==1);
 target.auth_id=((uint64_t)1001<<32)|1;CHECK(!launch_as(&target)&&launches==1&&error!=0);
 target=caller;target.integrity_rid=0x1000;CHECK(!launch_as(&target)&&launches==1);
 target=caller;target.session=2;CHECK(!launch_as(&target)&&launches==1);
 target=caller;target.flags=1;CHECK(!launch_as(&target)&&launches==1);
 caller.flags=target.flags=1;CHECK(!launch_as(&target)&&launches==1);caller.flags=0;
 target=caller;open_failure=1;CHECK(!launch_as(&target)&&launches==1&&error==ERROR_ACCESS_DENIED);open_failure=0;
 query_failure=2;CHECK(!launch_as(&target)&&launches==1&&error==ERROR_ACCESS_DENIED&&opens==closes);query_failure=0;
 target.type=TokenImpersonation;CHECK(!launch_as(&target)&&launches==1&&error==ERROR_BAD_TOKEN_TYPE);
 caller.session=2;caller.integrity_rid=0x1000;target=caller;
 CHECK(launch_as(&target)&&launches==2&&opens==closes);
 caller.auth_id=0x4e7;target=caller;CHECK(!launch_as(&target)&&launches==2);
}
int main(void){
 _Static_assert(sizeof(shz_token_info)==56,"unchanged token wire ABI");
 _Static_assert(sizeof(test_sid)==28&&sizeof(ACL)==8&&sizeof(SID_AND_ATTRIBUTES)==16,"public Win64 layout adapters");
 void (*cases[])(void)={target_information,caller_independence,anonymous_collision,activation_and_immutable_storage,bootstrap_identity,transport_denial,access_check_identity,caller_launch_admission};
 for(unsigned i=0;i<sizeof cases/sizeof *cases;i++){setup();cases[i]();}
 printf("token identity: %u cases, %u checks, %u failures; actual production rendering/ACL/AccessCheck\n",(unsigned)(sizeof cases/sizeof *cases),checks,failures);
 return failures?1:0;
}
