/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored mapped resource adapter, no Wine implementation copy.
 * Compared Wine f7f1defb4f01f84d4fafc8f65d6bdef519595855 loader/resource.c and
 * loader/pe_resource.c (2001-01-12): PE HGLOBAL=data pointer, no PE free, ASCII
 * case-insensitive resource lookup; NE ownership/thunks are out of scope.
 * Microsoft public resource API contracts are pinned in adapter provenance.
 */
#include "win32_adapter.h"
static nra_adapter *bound;
static void clear(void *v,uint32_t n){uint8_t *p=v;while(n--)*p++=0;}
static int valid(const nra_adapter *a){return a&&a->self==a&&a->read&&a->error;}
static void *fail(nra_adapter *a,uint32_t e){if(valid(a))a->error(a->opaque,e);return 0;}
static int overlaps(const void *p,uintptr_t n,const void *q,uintptr_t m)
{
 uintptr_t x=(uintptr_t)p,y=(uintptr_t)q;
 if(!p||!q||!n||!m)return 0;
 if(x>UINTPTR_MAX-n||y>UINTPTR_MAX-m)return 1;
 return x>=y?x-y<m:y-x<n;
}
static const uint8_t *readable(nra_adapter *a,const void *p,uint32_t n)
{
 const uint8_t *v;
 if(!n)return p;
 if(!p||(uintptr_t)p>UINTPTR_MAX-n)return 0;
 v=a->read(a->opaque,p,n);return v==(const uint8_t *)p?v:0;
}
static int equal_bytes(const uint8_t *a,const uint8_t *b,uint32_t n)
{while(n--)if(*a++!=*b++)return 0;return 1;}
static nra_module *module(nra_adapter *a,const void *handle)
{
 unsigned i;if(!valid(a))return 0;if(!handle)handle=a->root;
 for(i=0;i<NRA_MODULES;i++)if(a->module[i].active&&a->module[i].mapped==handle)return &a->module[i];
 return 0;
}
int nra_init(nra_adapter *a,nra_read read,nra_error error,void *opaque)
{
 if(!a||!read||!error)return 0;clear(a,sizeof(*a));a->read=read;a->error=error;a->opaque=opaque;a->self=a;return 1;
}
int nra_register(nra_adapter *a,const nr_resources *r,const void *base,uint32_t bytes,int root)
{
 unsigned i,slot=NRA_MODULES;uint32_t j,total=0;const uint8_t *mapped=base,*q;
 if(!valid(a))return 0;
 if(!r||r->self!=r||r->count>NR_LEAVES||!r->image.file||!base||
    ((uintptr_t)base&65535u)||bytes!=r->image.size||(uintptr_t)base>UINTPTR_MAX-bytes)
  {fail(a,NRA_ERROR_INVALID_PARAMETER);return 0;}
 if(overlaps(a,sizeof(*a),r,sizeof(*r))||overlaps(a,sizeof(*a),r->image.file,r->image.bytes)||
    overlaps(a,sizeof(*a),base,bytes)||overlaps(r,sizeof(*r),base,bytes)||
    overlaps(r->image.file,r->image.bytes,base,bytes))
  {fail(a,NRA_ERROR_INVALID_PARAMETER);return 0;}
 for(i=0;i<NRA_MODULES;i++){
  nra_module *m=&a->module[i];
  if(!m->active){if(slot==NRA_MODULES)slot=i;continue;}
  if(m->resources==r||overlaps(m->mapped,m->bytes,base,bytes)||
     overlaps(m->resources,sizeof(*m->resources),base,bytes)||
     overlaps(m->resources->image.file,m->resources->image.bytes,base,bytes)||
     overlaps(m->mapped,m->bytes,r,sizeof(*r))||
     overlaps(m->mapped,m->bytes,r->image.file,r->image.bytes))
   {fail(a,NRA_ERROR_INVALID_PARAMETER);return 0;}
 }
 if(slot==NRA_MODULES||(root&&a->root)){fail(a,NRA_ERROR_CALL_NOT_IMPLEMENTED);return 0;}
 q=readable(a,mapped,r->image.headers);
 if(!q||!equal_bytes(q,r->image.file,r->image.headers))
  {fail(a,NRA_ERROR_BAD_EXE_FORMAT);return 0;}
 if(r->present){
  const uint8_t *raw=np_raw(&r->image,r->directory_rva,r->directory_bytes);
  if(r->directory_bytes>NRA_VERIFY_BYTES){fail(a,NRA_ERROR_CALL_NOT_IMPLEMENTED);return 0;}
  if(r->directory_rva>bytes||r->directory_bytes>bytes-r->directory_rva)
   {fail(a,NRA_ERROR_BAD_EXE_FORMAT);return 0;}
  q=readable(a,mapped+r->directory_rva,r->directory_bytes);
  if(!raw||!q||!equal_bytes(raw,q,r->directory_bytes)){fail(a,NRA_ERROR_BAD_EXE_FORMAT);return 0;}
  total=r->directory_bytes;
 }
 for(j=0;j<r->count;j++){
  const nr_leaf *leaf=&r->leaf[j];nr_data d;const char *error=0;
  if(leaf->bytes>NRA_VERIFY_BYTES-total){fail(a,NRA_ERROR_CALL_NOT_IMPLEMENTED);return 0;}
  total+=leaf->bytes;
  if(!nr_load(r,leaf,&d,&error)||leaf->data_rva>bytes||leaf->bytes>bytes-leaf->data_rva||
     !(q=readable(a,mapped+leaf->data_rva,leaf->bytes))||!equal_bytes(q,d.data,leaf->bytes))
   {fail(a,NRA_ERROR_BAD_EXE_FORMAT);return 0;}
 }
 clear(&a->module[slot],sizeof(a->module[slot]));a->module[slot].resources=r;
 a->module[slot].mapped=mapped;a->module[slot].bytes=bytes;a->module[slot].active=1;
 if(root)a->root=base;return 1;
}
int nra_unregister(nra_adapter *a,const void *handle)
{
 nra_module *m;if(!handle||!(m=module(a,handle))){fail(a,NRA_ERROR_INVALID_HANDLE);return 0;}
 if(a->root==handle)a->root=0;clear(m,sizeof(*m));return 1;
}
int nra_bind(nra_adapter *a){if(!valid(a)||(bound&&bound!=a))return 0;bound=a;return 1;}
void nra_unbind(nra_adapter *a){if(bound==a)bound=0;}
static unsigned info_index(nra_module *m,const void *handle)
{unsigned i;for(i=0;i<m->resources->count;i++)if(handle==&m->resources->leaf[i])return i;return NR_LEAVES;}
static int marked(const uint32_t *bits,unsigned i){return !!(bits[i/32]&(1u<<(i%32)));}
static void mark(uint32_t *bits,unsigned i){bits[i/32]|=1u<<(i%32);}
void *nra_find_counted(nra_adapter *a,const void *handle,const nr_key *type,const nr_key *name,uint16_t language)
{
 nra_module *m=module(a,handle);nr_handle info;const char *error=0;unsigned i;
 if(!m)return fail(a,NRA_ERROR_INVALID_HANDLE);
 if(!type||!name||!readable(a,type,sizeof(*type))||!readable(a,name,sizeof(*name)))return fail(a,NRA_ERROR_INVALID_PARAMETER);
 if(type->kind>NR_KEY_NAME||name->kind>NR_KEY_NAME||
    (type->kind==NR_KEY_ID&&(type->id>0x7fffffffu||type->units||type->utf16))||
    (name->kind==NR_KEY_ID&&(name->id>0x7fffffffu||name->units||name->utf16))||
    (type->kind==NR_KEY_NAME&&type->id)||(name->kind==NR_KEY_NAME&&name->id))return fail(a,NRA_ERROR_INVALID_PARAMETER);
 if((type->kind==NR_KEY_NAME&&(type->units>65535u||(type->units&&!readable(a,type->utf16,type->units*2u))))||
    (name->kind==NR_KEY_NAME&&(name->units>65535u||(name->units&&!readable(a,name->utf16,name->units*2u)))))return fail(a,NRA_ERROR_INVALID_PARAMETER);
 if(!nr_lookup(m->resources,type,name,language,&info,&error))return fail(a,NRA_ERROR_RESOURCE_LANG_NOT_FOUND);
 i=info_index(m,info);mark(m->found,i);return (void *)info;
}
void *nra_load(nra_adapter *a,const void *handle,const void *info)
{
 nra_module *m=module(a,handle);unsigned i;const nr_leaf *leaf;const uint8_t *q;
 if(!m||(i=info_index(m,info))==NR_LEAVES||!marked(m->found,i))return fail(a,NRA_ERROR_INVALID_HANDLE);
 leaf=&m->resources->leaf[i];q=readable(a,m->mapped+leaf->data_rva,leaf->bytes);
 if(!q)return fail(a,NRA_ERROR_BAD_EXE_FORMAT);mark(m->loaded,i);return (void *)q;
}
uint32_t nra_sizeof(nra_adapter *a,const void *handle,const void *info)
{
 nra_module *m=module(a,handle);unsigned i;
 if(!m||(i=info_index(m,info))==NR_LEAVES||!marked(m->found,i)){fail(a,NRA_ERROR_INVALID_HANDLE);return 0;}
 return m->resources->leaf[i].bytes;
}
static int loaded(nra_adapter *a,const void *data)
{
 unsigned i,j;if(!valid(a)||!data)return 0;
 for(i=0;i<NRA_MODULES;i++){nra_module *m=&a->module[i];if(!m->active)continue;
  for(j=0;j<m->resources->count;j++)if(marked(m->loaded,j)&&data==m->mapped+m->resources->leaf[j].data_rva)return 1;
 }return 0;
}
void *nra_lock(nra_adapter *a,const void *data){if(!loaded(a,data))return fail(a,NRA_ERROR_INVALID_HANDLE);return (void *)data;}
int nra_free(nra_adapter *a,const void *data){if(!loaded(a,data))fail(a,NRA_ERROR_INVALID_HANDLE);return 0;}
typedef struct query {nr_key key;uint8_t text[NRA_QUERY_UNITS*2u];} query;
static int query_read(nra_adapter *a,const void *value,int wide,query *q)
{
 uintptr_t v=(uintptr_t)value;uint32_t i,n=0,number=0;int decimal=0;
 clear(&q->key,sizeof(q->key));
 if(v<=65535u){q->key.id=(uint32_t)v;return 1;}
 for(i=0;i<=NRA_QUERY_UNITS;i++){
  const uint8_t *p;uint16_t c;uint32_t stride=wide?2u:1u;
  if(v>UINTPTR_MAX-i*stride||!(p=readable(a,(const void *)(v+i*stride),stride)))return 0;
  c=wide?np_u16(p):*p;
  if(!c){if(decimal){if(!n)return 0;q->key.id=number;}else{q->key.kind=NR_KEY_NAME;q->key.units=n;q->key.utf16=q->text;}return 1;}
  if(i==NRA_QUERY_UNITS)return 0;
  if(!i&&c=='#'){decimal=1;continue;}
  if(decimal){if(c<'0'||c>'9'||number>(65535u-(c-'0'))/10u)return 0;number=number*10u+c-'0';n++;}
  else {if(c>127)return -1;q->text[n*2u]=(uint8_t)c;q->text[n*2u+1]=0;n++;}
 }
 return 0;
}
static uint16_t fold(uint16_t c){return c>='a'&&c<='z'?(uint16_t)(c-32):c;}
static int ascii(const nr_key *key)
{uint32_t i;if(key->kind==NR_KEY_ID)return 1;for(i=0;i<key->units;i++)if(np_u16(key->utf16+i*2u)>127)return 0;return 1;}
static int exact(const nr_key *a,const nr_key *b)
{return a->kind==b->kind&&(a->kind==NR_KEY_ID?a->id==b->id:
 a->units==b->units&&equal_bytes(a->utf16,b->utf16,a->units*2u));}
static int matches(const nr_key *key,const nr_key *q)
{
 uint32_t i;if(key->kind!=q->kind)return 0;
 if(key->kind==NR_KEY_ID)return key->id==q->id;
 if(key->units!=q->units)return 0;
 for(i=0;i<key->units;i++)if(fold(np_u16(key->utf16+i*2u))!=fold(np_u16(q->utf16+i*2u)))return 0;
 return 1;
}
static void *find_win32(nra_adapter *a,const void *handle,const void *type,const void *name,uint16_t language,int wide,int defaults)
{
 nra_module *m=module(a,handle);query qt,qn;int t,n,have_type=0,have_name=0,unknown_type=0,unknown_name=0,ambiguous=0;
 unsigned i,index=NR_LEAVES,count=0;const nr_key *seen_type=0,*seen_name=0;
 if(!m)return fail(a,NRA_ERROR_INVALID_HANDLE);
 t=query_read(a,type,wide,&qt);n=query_read(a,name,wide,&qn);
 if(t<0||n<0)return fail(a,NRA_ERROR_CALL_NOT_IMPLEMENTED);
 if(!t||!n)return fail(a,NRA_ERROR_INVALID_PARAMETER);
 if(!m->resources->present)return fail(a,NRA_ERROR_RESOURCE_DATA_NOT_FOUND);
 for(i=0;i<m->resources->count;i++){
  const nr_leaf *leaf=&m->resources->leaf[i];
  if(leaf->type.kind==qt.key.kind&&!ascii(&leaf->type)){unknown_type=1;continue;}
  if(!matches(&leaf->type,&qt.key))continue;have_type=1;
  if(seen_type&&!exact(seen_type,&leaf->type))ambiguous=1;seen_type=&leaf->type;
  if(leaf->name.kind==qn.key.kind&&!ascii(&leaf->name)){unknown_name=1;continue;}
  if(!matches(&leaf->name,&qn.key))continue;have_name=1;
  if(seen_name&&!exact(seen_name,&leaf->name))ambiguous=1;seen_name=&leaf->name;
  if(defaults||leaf->language==language){index=i;count++;}
 }
 if(!have_type)return fail(a,unknown_type?NRA_ERROR_CALL_NOT_IMPLEMENTED:NRA_ERROR_RESOURCE_TYPE_NOT_FOUND);
 if(!have_name)return fail(a,unknown_name?NRA_ERROR_CALL_NOT_IMPLEMENTED:NRA_ERROR_RESOURCE_NAME_NOT_FOUND);
 /* A missing requested language may have valid native fallback alternatives;
  * never report the leaf absent while that policy remains unimplemented. */
 if(count!=1||ambiguous||unknown_type||unknown_name)return fail(a,NRA_ERROR_CALL_NOT_IMPLEMENTED);
 mark(m->found,index);return (void *)&m->resources->leaf[index];
}
void *NRA_CALL nra_FindResourceExA(void *m,const char *t,const char *n,uint16_t l)
{return find_win32(bound,m,t,n,l,0,l==0||l==0x400||l==0x800||l==0xc00);}
void *NRA_CALL nra_FindResourceExW(void *m,const uint16_t *t,const uint16_t *n,uint16_t l)
{return find_win32(bound,m,t,n,l,1,l==0||l==0x400||l==0x800||l==0xc00);}
void *NRA_CALL nra_FindResourceA(void *m,const char *n,const char *t){return find_win32(bound,m,t,n,0,0,1);}
void *NRA_CALL nra_FindResourceW(void *m,const uint16_t *n,const uint16_t *t){return find_win32(bound,m,t,n,0,1,1);}
void *NRA_CALL nra_LoadResource(void *m,void *r){return nra_load(bound,m,r);}
void *NRA_CALL nra_LockResource(void *r){return nra_lock(bound,r);}
uint32_t NRA_CALL nra_SizeofResource(void *m,void *r){return nra_sizeof(bound,m,r);}
int NRA_CALL nra_FreeResource(void *r){return nra_free(bound,r);}
