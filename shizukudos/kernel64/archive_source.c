/* SPDX-License-Identifier: GPL-2.0-only */
#include "archive_source.h"
#include "../accounts/sha256.h"
#define ARCHIVE_SOURCE_SLOTS 8u
#define ARCHIVE_SOURCE_MAX_BYTES (256ull<<20)
struct archive_source {
 void *owner;uint64_t *pages;unsigned page_count,refs;
 archive_source_info_t info;
};
static struct archive_source slots[ARCHIVE_SOURCE_SLOTS];
static const uint8_t *origin_bytes;
static uint64_t origin_size,epoch;
static uint8_t *origin_table;
static shz_storage_provenance_t origin;
static kmutex_t lock;
static volatile unsigned lock_state;
static void acquire(void)
{
 unsigned expected=0;
 if(__atomic_compare_exchange_n(&lock_state,&expected,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
  mutex_init(&lock);__atomic_store_n(&lock_state,2,__ATOMIC_RELEASE);
 }
 while(__atomic_load_n(&lock_state,__ATOMIC_ACQUIRE)!=2)__asm__ volatile("pause");
 mutex_lock(&lock);
}
static struct archive_source *find(archive_source_t *p)
{
 unsigned i;for(i=0;i<ARCHIVE_SOURCE_SLOTS;i++)if(p==&slots[i]&&slots[i].refs)return p;
 return 0;
}
static int equal(struct archive_source *s,const uint8_t id[16],uint64_t generation,uint64_t bytes)
{return s&&id&&s->info.generation==generation&&s->info.bytes==bytes&&!memcmp(s->info.id,id,16);}
static void destroy(struct archive_source *s)
{
 unsigned i;for(i=0;i<s->page_count;i++)if(s->pages[i])pmm_free(s->pages[i]);
 kfree(s->pages);memset(s,0,sizeof *s);
}
static uint32_t read32(const uint8_t *p){return shz_dp_u32(p);}
static uint64_t read64(const uint8_t *p){return (uint64_t)read32(p)|(uint64_t)read32(p+4)<<32;}
static int archive_valid(const uint8_t *p,uint64_t bytes)
{
 uint32_t count,i;uint64_t table;
 if(!p||bytes<16||memcmp(p,"SHZARC01",8)||read32(p+12))return 0;
 count=read32(p+8);if(count>4096)return 0;table=16+(uint64_t)count*136;if(table>bytes)return 0;
 for(i=0;i<count;i++){
  const uint8_t *entry=p+16+(uint64_t)i*136;uint64_t off=read64(entry+120),len=read64(entry+128);unsigned j;
  for(j=0;j<120&&entry[j];j++){} /* bounded entry path */
  if(j==120||!j||off<table||off>bytes||len>bytes-off)return 0;
 }
 return 1;
}
int archive_source_bind_origin(const shz_bootinfo_t *bi,const uint8_t *data,uint64_t bytes)
{
 const shz_storage_provenance_t *p;unsigned i;int rc=-1;
 if(!bi||bi->magic!=SHZ_BOOTINFO_MAGIC||bi->abi_major!=SHZ_ABI_MAJOR||bi->domain_id!=SHZ_DOM_KERNEL64||
 bi->flags!=SHZ_BIF_UEFI_DIRECT||!SHZ_BOOTINFO_HAS(bi,storage)||!data||!bytes||
 bi->initrd_gpa>=bi->ram_size||bytes>bi->ram_size-bi->initrd_gpa||bytes!=bi->initrd_size||
 (uintptr_t)data!=(uintptr_t)p2v(bi->initrd_gpa))return -1;
 p=&bi->storage;
 if(p->magic!=SHZ_STORAGE_MAGIC||p->version!=SHZ_STORAGE_VERSION||p->size!=sizeof *p||p->reserved||
 p->flags!=SHZ_STORAGE_ARCHIVE_READ||p->archive_gpa!=bi->initrd_gpa||p->archive_size!=bytes||
 !shz_storage_match(&p->boot,&p->archive)||!archive_valid(data,bytes))return -1;
 acquire();
 for(i=0;i<ARCHIVE_SOURCE_SLOTS;i++)if(slots[i].refs)goto done;
 /* Bind once for this boot. No live origin replacement or hidden role reset. */
 if(origin.magic)goto done;
 {size_t table_bytes=(size_t)(16+(uint64_t)read32(data+8)*136);
 origin_table=kmalloc(table_bytes);if(!origin_table)goto done;
 memcpy(origin_table,data,table_bytes);
 if(memcmp(origin_table,data,table_bytes)){kfree(origin_table);origin_table=0;goto done;}
 }
 origin=*p;origin_bytes=data;origin_size=bytes;rc=0;
done:mutex_unlock(&lock);return rc;
}
int archive_source_origin(shz_storage_provenance_t *out)
{
 int rc=-1;if(!out)return -1;acquire();if(origin.magic==SHZ_STORAGE_MAGIC){*out=origin;rc=0;}
 mutex_unlock(&lock);return rc;
}
int archive_source_open(void *owner,const char *path,archive_source_t **out,archive_source_info_t *out_info)
{
 struct archive_source *s=0;fsnode_t *node;uint64_t off=0,length=0;uint32_t count,i;unsigned selected=0,j,any;
 uint8_t before[32],after[32];sha256_ctx hash;int rc=-1;
 if(!owner||!path||!out||!out_info)return -1;
 acquire();if(!origin_bytes||epoch==UINT64_MAX)goto done;
 node=fs_lookup(path);
 if(!node||node->is_dir||node->backing!=FSB_RAM||!node->readonly||!node->data||!node->size||node->size>ARCHIVE_SOURCE_MAX_BYTES)goto done;
 count=read32(origin_table+8);
 for(i=0;i<count;i++){
  const uint8_t *e=origin_table+16+(uint64_t)i*136;
  uint64_t eo=read64(e+120),el=read64(e+128);
  if(fs_lookup((const char *)e)==node&&node->data==origin_bytes+eo&&node->size==el){off=eo;length=el;selected++;}
 }
 if(selected!=1||off>origin_size||length>origin_size-off)goto done;
 for(i=0;i<ARCHIVE_SOURCE_SLOTS;i++)if(!slots[i].refs){s=&slots[i];break;}
 if(!s)goto done;
 memset(s,0,sizeof *s);s->page_count=(unsigned)((length+PAGE_SIZE-1)/PAGE_SIZE);
 s->pages=kmalloc((size_t)s->page_count*sizeof *s->pages);if(!s->pages)goto done;
 memset(s->pages,0,(size_t)s->page_count*sizeof *s->pages);
 sha256_init(&hash);sha256_update(&hash,origin_bytes+off,(size_t)length);sha256_final(&hash,before);
 sha256_init(&hash);
 for(i=0;i<s->page_count;i++){
  uint64_t at=(uint64_t)i*PAGE_SIZE;size_t n=(size_t)(length-at>PAGE_SIZE?PAGE_SIZE:length-at);uint8_t *dst;
  s->pages[i]=pmm_alloc();if(!s->pages[i])goto failed;
  dst=(uint8_t *)p2v(s->pages[i]);memcpy(dst,origin_bytes+off+at,n);sha256_update(&hash,dst,n);
 }
 sha256_final(&hash,s->info.sha256);sha256_init(&hash);sha256_update(&hash,origin_bytes+off,(size_t)length);sha256_final(&hash,after);
 if(memcmp(before,s->info.sha256,32)||memcmp(after,s->info.sha256,32))goto failed;
 /* No source metadata/path custody is retained as an authority substitute:
  * source bytes now live only in private kernel-owned snapshot pages. */
 for(j=0;j<8;j++){
  krandom_get(s->info.id,16);any=0;for(i=0;i<16;i++)any|=s->info.id[i];
  if(any)break;
 }
 if(j==8)goto failed;
 s->info.generation=++epoch;s->info.bytes=length;s->info.physical_origin=origin.archive;
 s->owner=owner;s->refs=1;*out=s;*out_info=s->info;rc=0;goto done;
failed:destroy(s);
done:mutex_unlock(&lock);return rc;
}
int archive_source_info(void *owner,archive_source_t *p,const archive_source_info_t *review,archive_source_info_t *out)
{
 struct archive_source *s;int rc=-1;if(!owner||!review||!out)return -1;acquire();s=find(p);
 if(s&&s->owner==owner&&equal(s,review->id,review->generation,review->bytes)){*out=s->info;rc=0;}mutex_unlock(&lock);return rc;
}
int archive_source_read(void *owner,archive_source_t *p,const archive_source_info_t *review,uint64_t off,void *buf,uint64_t bytes)
{
 struct archive_source *s;uint8_t *out=buf;int rc=-1;
 if(!owner||!review||(!buf&&bytes))return -1;
 acquire();s=find(p);
 if(!s||s->owner!=owner||!equal(s,review->id,review->generation,review->bytes)||off>s->info.bytes||bytes>s->info.bytes-off)goto done;
 while(bytes){unsigned page=(unsigned)(off/PAGE_SIZE);size_t within=(size_t)(off%PAGE_SIZE),n=(size_t)(bytes>PAGE_SIZE-within?PAGE_SIZE-within:bytes);
  memcpy(out,(const uint8_t *)p2v(s->pages[page])+within,n);out+=n;off+=n;bytes-=n;
 }rc=0;
done:mutex_unlock(&lock);return rc;
}
int archive_source_close(void *owner,archive_source_t *p,const archive_source_info_t *review)
{
 struct archive_source *s;int rc=-1;if(!owner||!review)return -1;acquire();s=find(p);
 if(s&&s->owner==owner&&equal(s,review->id,review->generation,review->bytes)){s->owner=0;if(!--s->refs)destroy(s);rc=0;}mutex_unlock(&lock);return rc;
}
int archive_source_match(archive_source_t *p,const uint8_t id[16],uint64_t generation,uint64_t bytes)
{int ok;acquire();ok=equal(find(p),id,generation,bytes);mutex_unlock(&lock);return ok?0:-1;}
int archive_source_retain(void *owner,archive_source_t *p,const uint8_t id[16],uint64_t generation,uint64_t bytes)
{
 struct archive_source *s;int rc=-1;acquire();s=find(p);
 if(owner&&equal(s,id,generation,bytes)&&s->owner==owner&&s->refs<UINT32_MAX){s->refs++;rc=0;}mutex_unlock(&lock);return rc;
}
void archive_source_release(archive_source_t *p,const uint8_t id[16],uint64_t generation)
{
 struct archive_source *s;acquire();s=find(p);
 if(s&&equal(s,id,generation,s->info.bytes)&&s->refs>(s->owner?1u:0u))if(!--s->refs)destroy(s);
 mutex_unlock(&lock);
}
