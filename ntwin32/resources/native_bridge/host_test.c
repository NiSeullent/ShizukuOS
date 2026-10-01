/* SPDX-License-Identifier: GPL-2.0-only -- host bridge lifetime controls. */
#define _POSIX_C_SOURCE 200112L
#include "bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,cases;static uint32_t last_error;
static void check(int yes,const char *what,unsigned line){checks++;if(!yes){fprintf(stderr,"FAIL %u %s error=%u\n",line,what,last_error);exit(1);}}
#define CHECK(x) check(!!(x),#x,__LINE__)
#define CASE(s) do{cases++;printf("CASE %s\n",s);}while(0)
static const uint8_t *readable(void *unused,const void *p,uint32_t bytes)
{(void)unused;if(!p||(uintptr_t)p>UINTPTR_MAX-bytes)return NULL;return p;}
static void error(void *unused,uint32_t value){(void)unused;last_error=value;}
typedef struct owned_module {np_image image;uint8_t *file,*mapped;uint32_t bytes;int state;} owned_module;
static void load(owned_module *m,const char *path)
{
 FILE *f=fopen(path,"rb");long n;const char *why=NULL;unsigned i;CHECK(f);CHECK(!fseek(f,0,SEEK_END));n=ftell(f);CHECK(n>0&&n<NP_FILE_LIMIT);rewind(f);
 m->file=malloc((size_t)n);CHECK(m->file);CHECK(fread(m->file,1,(size_t)n,f)==(size_t)n);CHECK(!fclose(f));m->bytes=(uint32_t)n;
 CHECK(np_parse(&m->image,m->file,m->bytes,&why));CHECK(np_runtime_profile(&m->image,&why));CHECK(!posix_memalign((void **)&m->mapped,65536,m->image.size));
 memcpy(m->mapped,m->file,m->image.headers);for(i=0;i<m->image.sections;i++){const np_section *s=&m->image.section[i];if(s->bytes)memcpy(m->mapped+s->va,m->file+s->raw,s->bytes);}m->state=2;
}
static void release(owned_module *m){free(m->mapped);free(m->file);}
int main(int argc,char **argv)
{
 owned_module app={0},dep={0};nrb_registry *r=calloc(1,sizeof(*r)),*copy=malloc(sizeof(*r));void *info,*data,*foreign;const char *why=NULL;
 CHECK(argc==3&&r&&copy);load(&app,argv[1]);load(&dep,argv[2]);
 CASE("exact-own-graph-pins-reject-altered-unknown-and-lengths");
 CHECK(nrb_verify_file("RBAPP.EXE",app.file,app.bytes));CHECK(nrb_verify_file("rbdata.dll",dep.file,dep.bytes));
 CHECK(!nrb_verify_file("chrome.exe",app.file,app.bytes));CHECK(!nrb_verify_file("RBAPP.EXE",app.file,app.bytes-1));app.file[0]^=1;CHECK(!nrb_verify_file("RBAPP.EXE",app.file,app.bytes));app.file[0]^=1;
 CASE("all-existing-nonresource-directory-gates-remain");
 {const unsigned blocked[]={3,7,10,11,13,14};unsigned j;for(j=0;j<sizeof(blocked)/sizeof(blocked[0]);j++){np_image bad=app.image;bad.directory[blocked[j]][0]=bad.headers-1;bad.directory[blocked[j]][1]=1;CHECK(!np_runtime_profile(&bad,&why));CHECK(!strcmp(why,"EXECUTION_RUNTIME_DIRECTORY"));}}
 CASE("real-base-owner-registration-before-publication");
 CHECK(nrb_init(r,readable,error,NULL));CHECK(nrb_add(r,&app,&app.image,app.mapped,1,&why));CHECK(nrb_add(r,&dep,&dep.image,dep.mapped,0,&why));
 CHECK(nrb_owned(r,&app,app.mapped));CHECK(!nrb_owned(r,&dep,app.mapped));CHECK(!nrb_owned(r,&app,(void *)(uintptr_t)1));
 CASE("duplicate-owner-base-and-copied-registry-refused");
 CHECK(!nrb_add(r,&app,&app.image,app.mapped,0,&why));*copy=*r;CHECK(!nrb_owned(copy,&app,app.mapped));CHECK(!nrb_publish(copy));CHECK(!nrb_remove(copy,&app));
 CHECK(nrb_publish(r));CHECK(!nrb_publish(r));CHECK(!nrb_add(r,&dep,&dep.image,dep.mapped,0,&why));
 CASE("application-NULL-module-root-is-real-mapping");
 info=nra_FindResourceExA(NULL,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,1033);CHECK(info);CHECK(info==nra_FindResourceExA(app.mapped,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,1033));
 data=nra_LoadResource(app.mapped,info);CHECK(data&&data==app.mapped+((const nr_leaf *)info)->data_rva);CHECK(nra_LockResource(data)==data);
 CASE("same-global-data-identity-no-free-ownership");CHECK(!nra_FreeResource(data));CHECK(!nra_FreeResource(data));CHECK(nra_LockResource(data)==data);
 CASE("foreign-module-and-information-handles-refused");
 foreign=nra_FindResourceExA(dep.mapped,(const char *)(uintptr_t)10,(const char *)(uintptr_t)301,1033);CHECK(foreign);CHECK(!nra_LoadResource(dep.mapped,info)&&last_error==6);CHECK(!nra_SizeofResource(app.mapped,foreign)&&last_error==6);
 CHECK(!nra_LoadResource(app.mapped,(uint8_t *)info+1)&&last_error==6);CHECK(!nra_LockResource(info)&&last_error==6);
 CASE("unregister-before-free-invalidates-live-owned-handles");CHECK(nrb_remove(r,&app));CHECK(!nrb_owned(r,&app,app.mapped));CHECK(!nra_LockResource(data)&&last_error==6);CHECK(!nra_LoadResource(app.mapped,info)&&last_error==6);CHECK(!nrb_remove(r,&app));
 CASE("retained-dependency-survives-other-module-unregister");data=nra_LoadResource(dep.mapped,foreign);CHECK(data&&nra_LockResource(data)==data);CHECK(nrb_dispose(r));CHECK(!nra_lock(&r->adapter,data)&&last_error==6);CHECK(nrb_dispose(r));
 CASE("mapped-content-failure-publishes-no-owner");CHECK(nrb_init(r,readable,error,NULL));dep.mapped[0]^=1;CHECK(!nrb_add(r,&dep,&dep.image,dep.mapped,0,&why));CHECK(!nrb_owned(r,&dep,dep.mapped));dep.mapped[0]^=1;CHECK(nrb_add(r,&dep,&dep.image,dep.mapped,0,&why));CHECK(nrb_dispose(r));
 CASE("malformed-directory-rollback-publishes-no-owner");
 {uint8_t saved[4],*at=app.file+(np_raw(&app.image,app.image.directory[2][0],24)-app.file)+20;memcpy(saved,at,4);at[0]=0;at[1]=0;at[2]=0;at[3]=0x80;
  CHECK(nrb_init(r,readable,error,NULL));CHECK(!nrb_add(r,&app,&app.image,app.mapped,1,&why));CHECK(why&&!nrb_owned(r,&app,app.mapped));memcpy(at,saved,4);CHECK(nrb_add(r,&app,&app.image,app.mapped,1,&why));CHECK(nrb_dispose(r));}
 CASE("DLL-root-has-no-synthetic-mapped-NULL-root");CHECK(nrb_init(r,readable,error,NULL));CHECK(nrb_add(r,&dep,&dep.image,dep.mapped,0,&why));CHECK(nrb_publish(r));CHECK(!nra_FindResourceA(NULL,(const char *)(uintptr_t)301,(const char *)(uintptr_t)10)&&last_error==6);CHECK(nrb_dispose(r));
 release(&dep);release(&app);free(copy);free(r);printf("RESULT PASS cases=%u checks=%u native_executed=false application_success=false\n",cases,checks);return 0;
}
