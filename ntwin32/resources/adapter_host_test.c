/* SPDX-License-Identifier: GPL-2.0-only -- host tests, no target code execution. */
#define _POSIX_C_SOURCE 200112L
#include "win32_adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern uint32_t NRA_CALL ResourceFixtureRun(void *,const nra_api *);
typedef struct host {uint32_t error;const uint8_t *deny;uint32_t deny_bytes;} host;
static host state;
static unsigned checks,cases;
static void check(int value,const char *text,unsigned line)
{checks++;if(!value){fprintf(stderr,"FAIL %u %s error=%u\n",line,text,state.error);exit(1);}}
#define CHECK(x) check(!!(x),#x,__LINE__)
#define CASE(s) do{cases++;printf("CASE %s\n",s);}while(0)
static const uint8_t *read_memory(void *opaque,const void *p,uint32_t n)
{
 host *s=opaque;uintptr_t at=(uintptr_t)p,deny=(uintptr_t)s->deny;
 /* Host valid C objects are live through each call. Deliberately bad query
  * pointers and explicitly denied live subranges are refused before a read. */
 if(!p||at<=65536u||at>UINTPTR_MAX-n)return 0;
 if(s->deny&&n&&s->deny_bytes&&(at>=deny?at-deny<s->deny_bytes:deny-at<n))return 0;
 return p;
}
static void last_error(void *opaque,uint32_t error){((host *)opaque)->error=error;}
static nra_api api={nra_FindResourceExA,nra_FindResourceExW,nra_FindResourceA,nra_FindResourceW,
 nra_LoadResource,nra_LockResource,nra_SizeofResource,nra_FreeResource};
static void put(uint8_t *p,uint32_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);}
static uint8_t *file_read(const char *path,uint32_t *bytes)
{
 FILE *s=fopen(path,"rb");long n;uint8_t *p;CHECK(s);CHECK(!fseek(s,0,SEEK_END));n=ftell(s);
 CHECK(n>0&&(unsigned long)n<=NP_LARGE_FILE_LIMIT);rewind(s);p=malloc((size_t)n);CHECK(p);
 CHECK(fread(p,1,(size_t)n,s)==(size_t)n);CHECK(!fclose(s));*bytes=(uint32_t)n;return p;
}
static uint8_t *map_resources(const nr_resources *r,int full)
{
 uint8_t *mapped=0;unsigned i;CHECK(!posix_memalign((void **)&mapped,65536,r->image.size));
 /* A host resource-only image layout is intentionally not executable. */
 memcpy(mapped,r->image.file,r->image.headers);
 if(full)for(i=0;i<r->image.sections;i++){const np_section *s=&r->image.section[i];
  if(s->bytes)memcpy(mapped+s->va,r->image.file+s->raw,s->bytes);
 }else{
  if(r->present)memcpy(mapped+r->directory_rva,np_raw(&r->image,r->directory_rva,r->directory_bytes),r->directory_bytes);
  for(i=0;i<r->count;i++){const nr_leaf *l=&r->leaf[i];if(l->bytes)memcpy(mapped+l->data_rva,np_raw(&r->image,l->data_rva,l->bytes),l->bytes);}
 }
 return mapped;
}
static void fixture(const char *path)
{
 uint32_t bytes;uint8_t *file=file_read(path,&bytes),*mapped,*second;np_image p;
 nr_resources *r=calloc(1,sizeof(*r)),*other=calloc(1,sizeof(*other));nra_adapter a,b;const char *error=0;
 void *info,*data;uint32_t payload_rva;unsigned i;
 CHECK(r&&other);CHECK(np_parse(&p,file,bytes,&error));CHECK(nr_parse(&p,r,&error));CHECK(r->count==4);
 mapped=map_resources(r,1);second=map_resources(r,1);CHECK(nr_parse(&p,other,&error));
 CASE("closed-fixture-identical-host-C-consumer-guest-stdcall-pending");
 CHECK(nra_init(&a,read_memory,last_error,&state));CHECK(nra_register(&a,r,mapped,p.size,1));CHECK(nra_bind(&a));
 CHECK(ResourceFixtureRun(mapped,&api)==23);
 CASE("Win32-last-error-type-name-language-distinction");
 CHECK(!nra_FindResourceExA(mapped,(const char *)(uintptr_t)999,(const char *)(uintptr_t)101,1033));CHECK(state.error==1813);
 CHECK(!nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,(const char *)(uintptr_t)999,1033));CHECK(state.error==1814);
 CHECK(!nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,1042));CHECK(state.error==120);
 CASE("explicit-unsupported-language-selection");
 CHECK(!nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,"MULTI",0));CHECK(state.error==120);
 CHECK(!nra_FindResourceA(mapped,"MULTI",(const char *)(uintptr_t)10));CHECK(state.error==120);
 CHECK(nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,"MULTI",1033));
 CHECK(nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,"MULTI",1042));
 CASE("current-module-is-only-explicit-root");
 info=nra_FindResourceExA(0,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,1033);CHECK(info);
 CHECK(info==nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,1033));
 CASE("successful-API-preserves-last-error-and-mapped-payload-identity");
 state.error=0x12345678;CHECK(nra_SizeofResource(mapped,info)==8&&state.error==0x12345678);
 data=nra_LoadResource(mapped,info);CHECK(data&&state.error==0x12345678);
 payload_rva=((const nr_leaf *)info)->data_rva;CHECK(data==mapped+payload_rva);
 CHECK(data!=np_raw(&p,payload_rva,8));CHECK(nra_LockResource(data)==data&&state.error==0x12345678);
 CHECK(!nra_FreeResource(data)&&state.error==0x12345678);CHECK(nra_LockResource(data)==data);
 CASE("named-find-trusted-read-callback-error-slot-preservation");
 state.error=0x51a2b3c4u;
 CHECK(nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,"named",1033)&&state.error==0x51a2b3c4u);
 {uint16_t query[]={'n','a','m','e','d',0};CHECK(nra_FindResourceW(mapped,query,(const uint16_t *)(uintptr_t)10)&&state.error==0x51a2b3c4u);}
 {const char query[]="NAMED";state.deny=(const uint8_t *)query;state.deny_bytes=sizeof(query);
  CHECK(!read_memory(&state,query,1)&&state.error==0x51a2b3c4u);state.deny=0;state.deny_bytes=0;}
 CASE("unknown-modules-never-dereferenced");
 CHECK(!nra_FindResourceExA((void *)(uintptr_t)1,"X","Y",1033)&&state.error==6);
 CHECK(!nra_LoadResource((void *)(uintptr_t)1,info)&&state.error==6);
 CHECK(!nra_SizeofResource((void *)(uintptr_t)1,info)&&state.error==6);
 CASE("forged-interior-foreign-and-unissued-info-handles");
 CHECK(nra_register(&a,other,second,p.size,0));
 {void *bad[]={0,(void *)(uintptr_t)1,(uint8_t *)info+1,&other->leaf[0]};
  for(i=0;i<sizeof(bad)/sizeof(bad[0]);i++){CHECK(!nra_LoadResource(mapped,bad[i])&&state.error==6);CHECK(!nra_SizeofResource(mapped,bad[i])&&state.error==6);}}
 CHECK(!nra_LoadResource(second,info)&&state.error==6);
 CASE("LockResource-rejects-info-global-memory-and-unloaded-payload");
 CHECK(!nra_LockResource(info)&&state.error==6);CHECK(!nra_LockResource(second+other->leaf[0].data_rva)&&state.error==6);
 CHECK(!nra_FreeResource((void *)(uintptr_t)1)&&state.error==6);
 CASE("bad-query-read-guard-with-no-dereference");
 CHECK(!nra_FindResourceA(mapped,(const char *)(uintptr_t)65536,(const char *)(uintptr_t)10)&&state.error==87);
 {const char query[]="NAMED";state.deny=(const uint8_t *)query;state.deny_bytes=sizeof(query);
  CHECK(!nra_FindResourceA(mapped,query,(const char *)(uintptr_t)10)&&state.error==87);state.deny=0;state.deny_bytes=0;}
 CASE("bounded-decimal-IDs-and-explicit-ACP-Unicode-folding-limits");
 {const char *invalid[]={"#","#-1","# 101","#65536","#9999999999999999999999","#101x"};
  for(i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++)CHECK(!nra_FindResourceA(mapped,invalid[i],(const char *)(uintptr_t)10)&&state.error==87);}
 CHECK(nra_FindResourceA(mapped,"#00101","#00010")==info);
 CHECK(!nra_FindResourceA(mapped,"\xc0",(const char *)(uintptr_t)10)&&state.error==120);
 {uint16_t non_ascii[]={0x212a,0};CHECK(!nra_FindResourceW(mapped,non_ascii,(const uint16_t *)(uintptr_t)10)&&state.error==120);}
 CASE("registration-denies-duplicates-overlap-and-invalid-bounds");
 CHECK(!nra_register(&a,r,mapped,p.size,0)&&state.error==87);
 CHECK(!nra_register(&a,r,mapped+1,p.size,0)&&state.error==87);
 CHECK(!nra_register(&a,r,mapped,p.size-1,0)&&state.error==87);
 CHECK(!nra_register(&a,r,file,p.size,0)&&state.error==87);
 CASE("foreign-facade-bind-and-copied-context");
 CHECK(nra_init(&b,read_memory,last_error,&state));CHECK(!nra_bind(&b));
 b=a;CHECK(!nra_register(&b,r,mapped,p.size,0));
 CASE("unregistration-invalidates-information-and-loaded-identity");
 CHECK(nra_unregister(&a,mapped));CHECK(!nra_LoadResource(mapped,info)&&state.error==6);
 CHECK(!nra_LockResource(data)&&state.error==6);CHECK(!nra_FindResourceA(0,"NAMED",(const char *)(uintptr_t)10)&&state.error==6);
 CHECK(nra_unregister(&a,second));nra_unbind(&a);
 CASE("registration-verifies-mapped-metadata-and-payload-contents");
 CHECK(nra_init(&a,read_memory,last_error,&state));mapped[payload_rva]^=1;
 CHECK(!nra_register(&a,r,mapped,p.size,1)&&state.error==193);mapped[payload_rva]^=1;
 mapped[r->directory_rva]^=1;CHECK(!nra_register(&a,r,mapped,p.size,1)&&state.error==193);mapped[r->directory_rva]^=1;
 mapped[0]^=1;CHECK(!nra_register(&a,r,mapped,p.size,1)&&state.error==193);mapped[0]^=1;
 state.deny=mapped+r->directory_rva;state.deny_bytes=r->directory_bytes;
 CHECK(!nra_register(&a,r,mapped,p.size,1)&&state.error==193);state.deny=0;state.deny_bytes=0;
 CHECK(nra_register(&a,r,mapped,p.size,1));CHECK(nra_unregister(&a,mapped));
 CASE("empty-counted-name-is-valid-key-not-invalid-query");
 CHECK(nra_register(&a,r,mapped,p.size,1));
 {nr_key type={NR_KEY_ID,10,0,0},empty={NR_KEY_NAME,0,0,0};
  CHECK(!nra_find_counted(&a,mapped,&type,&empty,1033)&&state.error==1815);}
 CHECK(nra_unregister(&a,mapped));
 CASE("malformed-original-metadata-does-not-publish-module");
 {uint8_t *bad=malloc(bytes);np_image malformed;nr_resources *invalid=calloc(1,sizeof(*invalid));
  CHECK(bad&&invalid);memcpy(bad,file,bytes);put(bad+(np_raw(&p,r->directory_rva,1)-file)+20,0x80000000u);
  CHECK(np_parse(&malformed,bad,bytes,&error));CHECK(!nr_parse(&malformed,invalid,&error));
  CHECK(!nra_register(&a,invalid,mapped,p.size,1)&&state.error==87);free(invalid);free(bad);}
 free(second);free(mapped);free(other);free(r);free(file);
}
static void changed_profiles(const char *path)
{
 uint32_t bytes,mode;uint8_t *original=file_read(path,&bytes);np_image p;nr_resources *source=calloc(1,sizeof(*source));const char *error=0;
 CHECK(source&&np_parse(&p,original,bytes,&error)&&nr_parse(&p,source,&error));
 for(mode=0;mode<4;mode++){
  uint8_t *file=malloc(bytes),*mapped;nr_resources *r=calloc(1,sizeof(*r));np_image changed;nra_adapter a;unsigned j;const nr_leaf *named=0,*numeric=0;
  CHECK(file&&r);memcpy(file,original,bytes);
  for(j=0;j<source->count;j++){const nr_leaf *l=&source->leaf[j];if(l->name.kind==NR_KEY_NAME&&l->name.units==5&&np_u16(l->name.utf16)=='N')named=l;
   if(l->name.kind==NR_KEY_ID&&l->name.id==101)numeric=l;}
  CHECK(named&&numeric);
  if(mode==0){const uint16_t text[5]={'N',0,0xd800,0x212a,'D'};uint32_t k,offset=(uint32_t)(named->name.utf16-original);
   CASE("actual-counted-UTF16-retains-NUL-and-unpaired-surrogate");for(k=0;k<5;k++){file[offset+k*2]=(uint8_t)text[k];file[offset+k*2+1]=(uint8_t)(text[k]>>8);}}
  else if(mode==1){uint32_t k,offset=(uint32_t)(named->name.utf16-original);const char text[]="multi";
   CASE("valid-PE-case-fold-ambiguity-is-unsupported-not-picked");for(k=0;k<5;k++){file[offset+k*2]=(uint8_t)text[k];file[offset+k*2+1]=0;}}
  else {uint32_t raw=(uint32_t)(np_raw(&p,source->directory_rva+named->entry_offset,16)-original);
   if(mode==2){CASE("legitimate-shared-payload-has-no-double-free-state");put(file+raw,numeric->data_rva);put(file+raw+4,numeric->bytes);}
   else {CASE("zero-size-zero-RVA-borrowed-mapped-resource");put(file+raw,0);put(file+raw+4,0);}}
  CHECK(np_parse(&changed,file,bytes,&error)&&nr_parse(&changed,r,&error));mapped=map_resources(r,1);
  CHECK(nra_init(&a,read_memory,last_error,&state)&&nra_register(&a,r,mapped,changed.size,1)&&nra_bind(&a));
  if(mode==0){const nr_leaf *l=0;void *info,*data;for(j=0;j<r->count;j++)if(r->leaf[j].name.kind==NR_KEY_NAME&&r->leaf[j].name.units==5&&np_u16(r->leaf[j].name.utf16)=='N')l=&r->leaf[j];
   CHECK(l);info=nra_find_counted(&a,mapped,&l->type,&l->name,l->language);CHECK(info==l);data=nra_load(&a,mapped,info);CHECK(data&&nra_lock(&a,data)==data);
   CHECK(!nra_FindResourceA(mapped,"NAMED",(const char *)(uintptr_t)10)&&state.error==120);}
  else if(mode==1){CHECK(!nra_FindResourceExA(mapped,(const char *)(uintptr_t)10,"multi",1033)&&state.error==120);}
  else {void *info=nra_FindResourceA(mapped,"NAMED",(const char *)(uintptr_t)10),*data;CHECK(info);data=nra_LoadResource(mapped,info);CHECK(data&&nra_LockResource(data)==data);
   if(mode==2){void *other=nra_FindResourceA(mapped,(const char *)(uintptr_t)101,(const char *)(uintptr_t)10);CHECK(other);CHECK(nra_LoadResource(mapped,other)==data);CHECK(!nra_FreeResource(data));CHECK(nra_LockResource(data)==data);}
   else {CHECK(nra_SizeofResource(mapped,info)==0);CHECK(data==mapped);CHECK(!nra_FreeResource(data));CHECK(nra_LockResource(data)==mapped);}}
  CHECK(nra_unregister(&a,mapped));nra_unbind(&a);free(mapped);free(r);free(file);
 }
 free(source);free(original);
}
static void original(const char *path,unsigned expected)
{
 uint32_t bytes,i;uint8_t *file=file_read(path,&bytes),*mapped;np_image p;nr_resources *r=calloc(1,sizeof(*r));
 nra_adapter a;const char *error=0;np_parse_limits limits={NP_LARGE_FILE_LIMIT,NP_LARGE_IMAGE_LIMIT,NP_LARGE_TOTAL_LIMIT};
 CASE("pinned-original-Chromium-actual-mapped-resource-consumption");CHECK(r);
 CHECK(np_parse_limited(&p,file,bytes,&limits,&error));CHECK(nr_parse(&p,r,&error));CHECK(r->count==expected);
 mapped=map_resources(r,0);CHECK(nra_init(&a,read_memory,last_error,&state));CHECK(nra_register(&a,r,mapped,p.size,1));
 for(i=0;i<r->count;i++){
  const nr_leaf *leaf=&r->leaf[i];void *info,*data;const uint8_t *raw;
  info=nra_find_counted(&a,mapped,&leaf->type,&leaf->name,leaf->language);CHECK(info==leaf);
  data=nra_load(&a,mapped,info);CHECK(data==mapped+leaf->data_rva);
  raw=np_raw(&p,leaf->data_rva,leaf->bytes);CHECK(!memcmp(data,raw,leaf->bytes));
  CHECK(nra_sizeof(&a,mapped,info)==leaf->bytes);CHECK(nra_lock(&a,data)==data);
  CHECK(!nra_free(&a,data));CHECK(nra_lock(&a,data)==data);
 }
 CHECK(!np_runtime_profile(&p,&error));CHECK(nra_unregister(&a,mapped));free(mapped);free(r);free(file);
 printf("ORIGINAL %u mapped-resource-consumption-only application_success=false\n",expected);
}
int main(int argc,char **argv)
{
 CHECK(argc==4);fixture(argv[1]);changed_profiles(argv[1]);original(argv[2],54);original(argv[3],105);
 printf("RESULT PASS cases=%u checks=%u closed_native_pending=true application_success=false\n",cases,checks);return 0;
}
