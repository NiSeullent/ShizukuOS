/* SPDX-License-Identifier: GPL-2.0-only */
#include "mapped_snapshot.h"
enum mx_error mx_seal(mx_snapshot *out,const mx_spec *in,mx_code_guard guard,void *opaque)
{
 uint32_t i,j;
 if(!out||!in||!guard||out->sealed)return MX_BAD_STATE;
 if(!in->image_base||in->image_base&4095u||in->image_bytes<4096||in->image_bytes>1024u*1024u||
    in->image_base>UINTPTR_MAX-in->image_bytes)return MX_BAD_IMAGE;
 if(in->tls_slot>=64||!in->owner_count||in->owner_count>MX_OWNERS)return MX_BAD_TLS;
 if(in->dependencies!=MX_KERNEL32&&in->dependencies!=(MX_KERNEL32|MX_OWN_OBSERVER))return MX_DETACHED_DEPENDENCY;
 if(!in->entry_rva||in->entry_rva>=in->image_bytes||!guard(opaque,in->entry_rva)||
    !in->callback_count||in->callback_count>MX_CALLBACKS)return MX_BAD_CODE;
 for(i=0;i<in->callback_count;i++){
  if(!in->callbacks[i]||in->callbacks[i]>=in->image_bytes||!guard(opaque,in->callbacks[i]))return MX_BAD_CODE;
  for(j=0;j<i;j++)if(in->callbacks[i]==in->callbacks[j])return MX_BAD_CODE;
 }
 for(i=0;i<in->owner_count;i++){
  const mx_owner *o=&in->owners[i];
  if(!o->thread_id||!o->tls_data||o->tls_bytes<4||o->tls_bytes>1024u*1024u||o->tls_data>UINTPTR_MAX-o->tls_bytes)return MX_BAD_OWNER;
  for(j=0;j<i;j++)if(o->thread_id==in->owners[j].thread_id||o->tls_data==in->owners[j].tls_data)return MX_BAD_OWNER;
 }
 out->spec=*in;out->sealed=MX_MAGIC;return MX_OK;
}
enum mx_error mx_dispatch_guard(const mx_snapshot *s,uint32_t thread,uintptr_t data,uint32_t detached)
{
 uint32_t i;
 if(!s||s->sealed!=MX_MAGIC||!s->spec.owner_count||s->spec.owner_count>MX_OWNERS||
    !s->spec.callback_count||s->spec.callback_count>MX_CALLBACKS)return MX_BAD_STATE;
 if(s->spec.dependencies!=MX_KERNEL32&&s->spec.dependencies!=(MX_KERNEL32|MX_OWN_OBSERVER))return MX_DETACHED_DEPENDENCY;
 /* Every dependency must still be initialized. A retained mapping is not
  * enough. Refuse before reading/calling any own mapped target code. */
 if(s->spec.dependencies&detached)return MX_DETACHED_DEPENDENCY;
 if(!data)return MX_MISSING_TLS;
 for(i=0;i<s->spec.owner_count;i++)if(s->spec.owners[i].thread_id==thread)
  return s->spec.owners[i].tls_data==data?MX_OK:MX_BAD_OWNER;
 return MX_BAD_OWNER;
}
