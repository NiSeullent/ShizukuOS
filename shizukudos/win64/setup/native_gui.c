/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_gui.h"
#include <string.h>
static int label(const char *p,size_t n)
{ for(size_t i=0;i<n;i++)if(!p[i])return i?0:-1;return -1; }
static int same(const native_setup_target_v1_t *a,const native_setup_target_v1_t *b)
{
 return a->index==b->index&&a->generation==b->generation&&
  !memcmp(a->whole_id,b->whole_id,16)&&!memcmp(&a->disk,&b->disk,sizeof a->disk);
}
int shz_native_gui_prepare(shz_native_gui *v,const plat_t *base)
{
 int rc;if(!v)return -1;
 for(size_t i=0;i<sizeof *v;i++)if(((const unsigned char *)v)[i])return -1;
 rc=shz_native_runtime_init(&v->runtime,base);if(rc)return rc;
 v->request.version=NATIVE_SETUP_VERSION;v->request.bytes=sizeof v->request;
 v->request.manifest_path=SHZ_NATIVE_GUI_MANIFEST;v->request.sim_path=SHZ_NATIVE_GUI_SIM;
 if(shz_native_runtime_preview(&v->runtime,v->request.manifest_path,v->request.sim_path,
                              v->request.admitted_manifest_sha256))return -1;
 v->prepared=1;return 0;
}
int shz_native_gui_close(shz_native_gui *v)
{
 int rc;if(!v)return -1;
 rc=shz_native_runtime_preview_close(&v->runtime);v->prepared=v->confirmed=v->reviewed=0;
 return rc;
}
int shz_native_gui_review(shz_native_gui *v,unsigned index,native_setup_target_v1_t *out)
{
 native_setup_ops_v1_t *a;void *sources[2];native_setup_target_v1_t actual;
 if(!v||!out||!v->prepared||v->started)return -1;
 a=&v->runtime.provider.backend.authority;
 sources[0]=&v->runtime.source[0];sources[1]=&v->runtime.source[1];
 if(a->check_source(a->ctx,sources[0])||a->check_source(a->ctx,sources[1])||
    a->review_target(a->ctx,index,sources,&actual))return -1;
 /* Geometry/label minimums match the actual native installer. Device role
  * exclusions and whole identity are decided by the kernel review, not these. */
 if(!actual.generation||actual.disk.flags||actual.disk.sector_size!=512||
    actual.disk.sectors<((2304ull<<20)/512)+8192||actual.disk.sectors>UINT64_MAX/512||
    label(actual.disk.name,sizeof actual.disk.name)||label(actual.disk.serial,sizeof actual.disk.serial))return -1;
 *out=actual;v->reviewed=1;return 0;
}
int shz_native_gui_confirm(shz_native_gui *v,const native_setup_target_v1_t *reviewed,const char *text)
{
 native_setup_target_v1_t current;
 if(!v||!reviewed||!text||strcmp(text,"ERASE")||!v->reviewed||v->confirmed||
    shz_native_gui_review(v,reviewed->index,&current)||!same(reviewed,&current))return -1;
 v->request.reviewed_target=current;v->request.confirmation="ERASE";v->confirmed=1;return 0;
}
void shz_native_gui_run(shz_native_gui *v,native_setup_result_v1_t *result)
{
 native_setup_target_v1_t current;
 if(!result)return;
 memset(result,0,sizeof *result);
 if(!v||!v->prepared||!v->confirmed||v->started||
    shz_native_gui_review(v,v->request.reviewed_target.index,&current)||
    !same(&current,&v->request.reviewed_target)){
  strcpy(result->reason,"native GUI source or target changed before installation");
  if(v)shz_native_gui_close(v);
  return;
 }
 v->started=1;
 shz_native_provider_run(&v->runtime.provider,&v->request,result);
 if(shz_native_gui_close(v)){
  result->ok=0;strcpy(result->reason,"native GUI mandatory source finalization failed");
 }
}
