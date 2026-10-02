/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only admission of the existing owned ESP namespace. Runtime writes are
 * translations into already allocated DISK.IMG sectors only. No FAT allocation,
 * file growth, metadata writes or physical-device authorization happens here.
 */
#include "persistent_disk.h"
#include <string.h>
static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1]<<8); }
static uint32_t u32(const uint8_t *p) { return (uint32_t)u16(p) | (uint32_t)u16(p+2)<<16; }
static int eoc(uint32_t n) { return n >= 0x0ffffff8u; }
static int valid_cluster(const w98_persist_disk_t *m,uint32_t n) { return n>=2 && n-2<m->clusters; }
static int raw_read(w98_persist_disk_t *m,uint64_t lba,uint8_t *data)
{
    if(lba>=m->block.sectors || m->block.read(m->block.opaque,lba,1,data)) { m->failed=1;return -1; }
    return 0;
}
static void observe(w98_persist_disk_t *m,const uint8_t *data)
{
    unsigned i;for(i=0;i<512;i++){m->metadata_observation_fnv64^=data[i];m->metadata_observation_fnv64*=1099511628211ull;}
}
static int fat_next(w98_persist_disk_t *m,uint32_t n,uint32_t *next)
{
    const uint32_t sector=n/128;
    if(sector>=m->fat_sectors)return -1;
    if(!m->fat_cache_valid || m->fat_cache_sector!=sector){
        if(raw_read(m,m->reserved+sector,m->fat_cache) || raw_read(m,m->reserved+m->fat_sectors+sector,m->mirror) || memcmp(m->fat_cache,m->mirror,512))return -1;
        m->fat_cache_sector=sector;m->fat_cache_valid=1;
    }
    *next=u32(m->fat_cache+(n%128)*4)&0x0fffffffu;return 0;
}
static int claimed(const w98_persist_disk_t *m,uint32_t n) { return (m->seen[(n-2)/8]>>(n-2)%8)&1; }
static int claim(w98_persist_disk_t *m,uint32_t n)
{
    if(!valid_cluster(m,n) || claimed(m,n))return -1;
    m->seen[(n-2)/8]|=(uint8_t)(1u<<((n-2)%8));return 0;
}
static uint64_t cluster_lba(const w98_persist_disk_t *m,uint32_t n) { return m->data_lba+(uint64_t)(n-2)*m->spc; }
static int extent(w98_persist_disk_t *m,uint32_t first,uint32_t count,uint64_t lba)
{
    w98_disk_extent_t *last;
    if(!count || lba>=m->block.sectors || count>m->block.sectors-lba || first>=W98_PERSIST_DISK_SECTORS || count>W98_PERSIST_DISK_SECTORS-first)return -1;
    if(m->extents){last=&m->extent[m->extents-1];if(last->first+last->count==first && last->device_lba+last->count==lba){last->count+=count;return 0;}}
    if(m->extents==W98_PERSIST_MAX_EXTENTS)return -1;
    last=&m->extent[m->extents++];last->first=first;last->count=count;last->device_lba=lba;return 0;
}
static int file_chain(w98_persist_disk_t *m,uint32_t first,uint32_t bytes,int disk)
{
    const uint32_t total=bytes?(uint32_t)(((uint64_t)bytes+m->spc*512-1)/(m->spc*512)):0;
    uint32_t n=first,next,i,logical=0;
    if(!total)return first?-1:0;
    for(i=0;i<total;i++){
        uint32_t sectors=m->spc;
        if(claim(m,n) || fat_next(m,n,&next))return -1;
        if(disk){if(sectors>W98_PERSIST_DISK_SECTORS-logical)sectors=W98_PERSIST_DISK_SECTORS-logical;if(extent(m,logical,sectors,cluster_lba(m,n)))return -1;logical+=sectors;}
        if(i+1==total){if(!eoc(next))return -1;}else if(!valid_cluster(m,next))return -1;
        n=next;
    }
    return disk && logical!=W98_PERSIST_DISK_SECTORS?-1:0;
}
static int zero(const uint8_t *p,unsigned bytes) { unsigned i;for(i=0;i<bytes;i++)if(p[i])return 0;return 1; }
static uint8_t fold(uint8_t c) { return c>='a' && c<='z'?(uint8_t)(c-'a'+'A'):c; }
static int equal_name(const uint8_t *a,const char *b)
{
    unsigned i;for(i=0;i<11;i++)if(fold(a[i])!=(uint8_t)b[i])return 0;return 1;
}
static int unique_name(w98_persist_disk_t *m,const w98_disk_dir_t *d,const uint8_t *raw)
{
    uint8_t name[11];unsigned i,dir=(unsigned)(d-m->directory);
    if(dir>=W98_PERSIST_MAX_DIRS || m->names_seen==4096)return -1;
    for(i=0;i<11;i++)name[i]=fold(raw[i]);
    for(i=0;i<m->names_seen;i++)if(m->name[i].directory==dir && !memcmp(m->name[i].name,name,11))return -1;
    memcpy(m->name[m->names_seen].name,name,11);m->name[m->names_seen++].directory=(uint8_t)dir;return 0;
}
static int directory(w98_persist_disk_t *m,const w98_disk_dir_t *d,unsigned *shzdos,unsigned *disk)
{
    uint32_t n=d->first,next,s;int ended=0;
    do {
        if(claim(m,n))return -1;
        for(s=0;s<m->spc;s++){
            unsigned pos;
            if(raw_read(m,cluster_lba(m,n)+s,m->sector))return -1;
            observe(m,m->sector);
            for(pos=0;pos<512;pos+=32){
                const uint8_t *p=m->sector+pos;uint32_t first,bytes;unsigned i;uint8_t attr;
                if(ended || !p[0]){ended=1;if(!zero(p,32))return -1;continue;}
                if(p[0]==0xe5)continue;
                if(++m->entries_seen>4096)return -1;
                attr=p[11];if(attr==0x0f || (attr&0xc0))return -1; /* owned builder uses exact8.3 names */
                first=(uint32_t)u16(p+20)<<16|u16(p+26);bytes=u32(p+28);
                if(unique_name(m,d,p))return -1;
                /* Type checks precede every attribute branch: another object
                 * with the target spelling cannot hide behind volume/dir/file. */
                if(d->first==m->root && equal_name(p,"SHZDOS     ") && (!(attr&16) || (attr&8)))return -1;
                if(d->shzdos && equal_name(p,"DISK    IMG") && (attr&24))return -1;
                if(!memcmp(p,".          ",11)){if(attr!=16 || first!=d->first || bytes)return -1;continue;}
                if(!memcmp(p,"..         ",11)){if(attr!=16 || bytes || (first!=d->parent && !(d->parent==m->root && !first)))return -1;continue;}
                for(i=0;i<11;i++)if(p[i]<0x20 || p[i]>0x7e || p[i]=='/' || p[i]=='\\' || p[i]==':' || p[i]=='*' || p[i]=='?')return -1;
                if(attr&8){if(attr!=8 || d->first!=m->root || first || bytes)return -1;continue;}
                if(attr&16){
                    w98_disk_dir_t *child;
                    if(bytes || !valid_cluster(m,first) || m->dirs==W98_PERSIST_MAX_DIRS || d->depth==8)return -1;
                    child=&m->directory[m->dirs++];child->first=first;child->parent=d->first;child->depth=d->depth+1;
                    child->shzdos=d->first==m->root && equal_name(p,"SHZDOS     ");
                    if(child->shzdos && ++*shzdos!=1)return -1;
                }else{
                    const int member=d->shzdos && equal_name(p,"DISK    IMG");
                    if(member && (bytes!=(2u<<30) || ++*disk!=1))return -1;
                    if(file_chain(m,first,bytes,member))return -1;
                }
            }
        }
        if(fat_next(m,n,&next))return -1;
        n=next;
    }while(!eoc(n));
    return ended?0:-1;
}
int w98_persist_disk_init(w98_persist_disk_t *m,uint32_t optin,const w98_owned_block_t *b)
{
    uint32_t sectors,fat0,fat1,i,next;unsigned shzdos=0,disk=0;
    if(m)m->admitted=0;
    if(!m || !b || optin!=W98_DISK_BACKEND_OPTIN || b->sectors!=W98_PERSIST_ESP_SECTORS || !b->read || !b->write || !b->flush)return -1;
    memset(m,0,sizeof *m);m->block=*b;m->metadata_observation_fnv64=14695981039346656037ull;
    if(raw_read(m,0,m->sector))goto bad;
    if(u16(m->sector+11)!=512 || m->sector[16]!=2 || m->sector[21]!=0xf8 || u16(m->sector+17) || u16(m->sector+19) || u16(m->sector+22) || u32(m->sector+28) || u16(m->sector+40) || u16(m->sector+42) || u16(m->sector+48)!=1 || u16(m->sector+50)!=6 || u32(m->sector+67)!=W98_PERSIST_VOLUME_ID || memcmp(m->sector+82,"FAT32   ",8) || u16(m->sector+510)!=0xaa55)goto bad;
    m->spc=m->sector[13];m->reserved=u16(m->sector+14);m->fat_sectors=u32(m->sector+36);m->root=u32(m->sector+44);sectors=u32(m->sector+32);
    if(!m->spc || m->spc>128 || (m->spc&(m->spc-1)) || m->reserved<32 || sectors!=W98_PERSIST_ESP_SECTORS || !m->fat_sectors || m->fat_sectors>(sectors-m->reserved)/2)goto bad;
    m->data_lba=m->reserved+2*m->fat_sectors;m->clusters=(sectors-m->data_lba)/m->spc;
    if(m->clusters<65525 || m->clusters>W98_PERSIST_MAX_CLUSTERS || (uint64_t)m->fat_sectors*128<m->clusters+2 || !valid_cluster(m,m->root))goto bad;
    if(raw_read(m,6,m->mirror) || memcmp(m->sector,m->mirror,512))goto bad;
    observe(m,m->sector);
    for(i=1;i<=7;i+=6){
        if(raw_read(m,i,m->sector) || u32(m->sector)!=0x41615252 || u32(m->sector+484)!=0x61417272 || u32(m->sector+508)!=0xaa550000)goto bad;
        next=u32(m->sector+488);if(next!=0xffffffff && next>m->clusters)goto bad;
        next=u32(m->sector+492);if(next!=0xffffffff && !valid_cluster(m,next))goto bad;
        observe(m,m->sector);
    }
    for(i=0;i<m->fat_sectors;i++){
        if(raw_read(m,m->reserved+i,m->fat_cache) || raw_read(m,m->reserved+m->fat_sectors+i,m->mirror) || memcmp(m->fat_cache,m->mirror,512))goto bad;
        observe(m,m->fat_cache);
    }
    if(fat_next(m,0,&fat0) || fat_next(m,1,&fat1) || fat0!=0x0ffffff8 || fat1!=0x0fffffff)goto bad;
    m->dirs=1;m->directory[0].first=m->root;
    for(i=0;i<m->dirs;i++)if(directory(m,&m->directory[i],&shzdos,&disk))goto bad;
    if(shzdos!=1 || disk!=1 || !m->extents)goto bad;
    for(i=2;i<m->clusters+2;i++)if(fat_next(m,i,&next) || (next && !claimed(m,i)))goto bad;
    m->admitted=1;return 0;
bad:m->failed=1;m->admitted=0;return -1;
}
static int location(w98_persist_disk_t *m,uint32_t sector,uint64_t *lba)
{
    uint32_t lo=0,hi=m->extents;
    if(!m->admitted || m->failed || sector>=W98_PERSIST_DISK_SECTORS)return -1;
    while(lo<hi){uint32_t at=lo+(hi-lo)/2;const w98_disk_extent_t *e=&m->extent[at];if(sector<e->first)hi=at;else if(sector-e->first>=e->count)lo=at+1;else{*lba=e->device_lba+sector-e->first;return *lba<m->block.sectors?0:-1;}}
    return -1;
}
static int member_read(void *opaque,uint32_t sector,uint8_t *out)
{
    w98_persist_disk_t *m=opaque;uint64_t lba;int rc;
    if(!out || location(m,sector,&lba) || __atomic_exchange_n(&m->busy,1,__ATOMIC_ACQUIRE))return -1;
    rc=m->block.read(m->block.opaque,lba,1,out);if(rc)m->failed=1;__atomic_store_n(&m->busy,0,__ATOMIC_RELEASE);return rc?-1:0;
}
static int member_write(void *opaque,uint32_t sector,const uint8_t *data)
{
    w98_persist_disk_t *m=opaque;uint64_t lba;int rc;
    if(!data || location(m,sector,&lba) || __atomic_exchange_n(&m->busy,1,__ATOMIC_ACQUIRE))return -1;
    rc=m->block.write(m->block.opaque,lba,1,data);if(rc)m->failed=1;__atomic_store_n(&m->busy,0,__ATOMIC_RELEASE);return rc?-1:0;
}
static int member_flush(void *opaque)
{
    w98_persist_disk_t *m=opaque;int rc;
    if(!m->admitted || m->failed || __atomic_exchange_n(&m->busy,1,__ATOMIC_ACQUIRE))return -1;
    rc=m->block.flush(m->block.opaque);if(rc)m->failed=1;__atomic_store_n(&m->busy,0,__ATOMIC_RELEASE);return rc?-1:0;
}
int w98_persist_disk_backend(w98_persist_disk_t *m,w98_disk_backend_t *out)
{
    if(!m || !out || !m->admitted || m->failed)return -1;
    out->bytes=2ull<<30;out->opaque=m;out->read_sector=member_read;out->write_sector=member_write;out->flush=member_flush;return 0;
}
