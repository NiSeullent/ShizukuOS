/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored sparse synthetic FAT32 sector model. No disk image,
 * host block device, operating-system file, guest or upstream implementation.
 * Interface facts: Microsoft FAT32 specification 1.03 (2000), pages 12-18,
 * https://www.cs.fsu.edu/~cop4610t/assignments/project3/spec/fatspec.pdf
 * Fixtures were drafted from fat.h and that format contract before fat.c.
 */
#include "fat.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SENTINEL 0xa5u
#define MAP_CAP 1152u
#define SECTOR_CAP 96u
#define FIRST_LBA (f.first_lba)
#define FAT_SECTORS 520u
#define CLUSTERS 65536u
#define RESERVED 32u
#define CAPACITY NTWF_MAX_FILE_BYTES
static uint64_t checks, scenarios, injected, fuzz_cases;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr,"FAT model line %u: %s; scenario=%" PRIu64 "\n", \
            (unsigned)__LINE__,#x,scenarios); exit(1); } } while (0)

struct fat_entry { uint32_t cluster, value[2]; };
struct data_sector { uint64_t lba; uint8_t bytes[512]; };
struct fixture {
    uint8_t mbr[512], bpb[512];
    struct fat_entry fat[MAP_CAP];
    struct data_sector sectors[SECTOR_CAP];
    uint32_t fat_entries, sector_entries, selected, spc, fat_count;
    uint32_t root, cluster_count, file_size, file_count, file_clusters[1024];
    uint32_t reads, clocks, read_fail, clock_fail, backwards_at;
    uint32_t timeout_on_read, frozen, step_us, last_remaining;
    uint64_t now, deadline, disk_sectors, first_lba;
    uint8_t *expected;
};
static struct fixture f;
static struct ntwf_workspace *work;
static uint8_t *destination, *before_destination;
static struct ntwf_io io;
static struct ntwf_request request;
static struct ntwf_file_info info, before_info;

static void put16(uint8_t *p,uint16_t v) { p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p,uint32_t v) {
    p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t data_start(void) { return FIRST_LBA+RESERVED+(uint64_t)f.fat_count*FAT_SECTORS; }
static uint64_t cluster_sector(uint32_t cluster) { return data_start()+(uint64_t)(cluster-2u)*f.spc; }
static struct data_sector *sector(uint64_t lba) {
    uint32_t i;
    for(i=0;i<f.sector_entries;++i)if(f.sectors[i].lba==lba)return &f.sectors[i];
    CHECK(f.sector_entries<SECTOR_CAP);
    f.sectors[f.sector_entries].lba=lba;
    memset(f.sectors[f.sector_entries].bytes,0,512);
    return &f.sectors[f.sector_entries++];
}
static void fat(uint32_t cluster,uint32_t first,uint32_t second) {
    uint32_t i;
    for(i=0;i<f.fat_entries;++i)if(f.fat[i].cluster==cluster)break;
    CHECK(i<MAP_CAP);
    if(i==f.fat_entries)++f.fat_entries;
    f.fat[i].cluster=cluster;f.fat[i].value[0]=first;f.fat[i].value[1]=second;
}
static uint8_t *record(uint32_t cluster,uint32_t ordinal) {
    CHECK(ordinal<16u*f.spc);
    return sector(cluster_sector(cluster)+ordinal/16u)->bytes+(ordinal%16u)*32u;
}
static void file_record(uint32_t root,uint32_t ordinal,const char name[11],
                        uint8_t attributes,uint32_t first,uint32_t bytes) {
    uint8_t *entry=record(root,ordinal);
    memset(entry,0,32);memcpy(entry,name,11);entry[11]=attributes;
    put16(entry+20,(uint16_t)(first>>16));put16(entry+26,(uint16_t)first);put32(entry+28,bytes);
}
static void deleted_directory(uint32_t root) {
    uint32_t i;
    for(i=0;i<16u*f.spc;++i)record(root,i)[0]=0xe5;
}
static void chain(uint32_t size,uint32_t count,const uint32_t *clusters) {
    uint32_t i;
    f.file_size=size;f.file_count=count;
    CHECK(count<=1024);
    for(i=0;i<count;++i){f.file_clusters[i]=clusters[i];fat(clusters[i],
        i+1u<count?clusters[i+1u]:0x0fffffffu,i+1u<count?clusters[i+1u]:0x0fffffffu);}
    file_record(f.root,0,"KERNEL  BIN",0x20,count?clusters[0]:0,size);
    /* Independent expected data table; the I/O model computes a separate
     * quotient/remainder expression from file byte position. */
    for(i=0;i<size && i<CAPACITY;++i)f.expected[i]=(uint8_t)(((i*17u)+(i/251u))^0xa7u);
}
static int read_sector(void *user,uint64_t lba,uint8_t output[512],uint32_t remaining) {
    struct fixture *m=user;
    uint32_t i,j;
    CHECK(m==&f && output!=NULL && lba<m->disk_sectors && lba<io.sector_count);
    CHECK(remaining>0 && remaining<=request.time_budget_us);
    CHECK(m->reads<request.read_budget);
    if(m->last_remaining)CHECK(remaining<=m->last_remaining);
    m->last_remaining=remaining;++m->reads;
    if(m->read_fail==m->reads){memset(output,0x7e,512);return -1;}
    memset(output,0,512);
    if(lba==0)memcpy(output,m->mbr,512);
    else if(lba==FIRST_LBA)memcpy(output,m->bpb,512);
    else {
        int supplied=0;
        for(i=0;i<m->sector_entries;++i)if(m->sectors[i].lba==lba){memcpy(output,m->sectors[i].bytes,512);supplied=1;break;}
        for(i=0;i<m->fat_count && !supplied;++i){
            uint64_t start=FIRST_LBA+RESERVED+(uint64_t)i*FAT_SECTORS;
            if(lba>=start && lba<start+FAT_SECTORS){
                uint32_t first=(uint32_t)(lba-start)*128u;
                for(j=0;j<m->fat_entries;++j)if(m->fat[j].cluster>=first && m->fat[j].cluster-first<128u)
                    put32(output+(m->fat[j].cluster-first)*4u,m->fat[j].value[i]);
                supplied=1;
            }
        }
        for(i=0;i<m->file_count && !supplied;++i){
            uint64_t start=cluster_sector(m->file_clusters[i]);
            if(lba>=start && lba<start+m->spc){
                uint64_t first=((uint64_t)i*m->spc+lba-start)*512u;
                for(j=0;j<512;++j){uint64_t pos=first+j;
                    output[j]=(uint8_t)(((17u*(pos%256u)+(pos/251u)%256u)%256u)^0xa7u);}
                supplied=1;
            }
        }
        /* Unspecified sectors are zero, like a sparse synthetic volume. */
    }
    if(m->timeout_on_read==m->reads)m->now+=request.time_budget_us;
    return 0;
}
static int now_us(void *user,uint64_t *out) {
    struct fixture *m=user;CHECK(m==&f && out!=NULL);++m->clocks;
    if(m->clock_fail==m->clocks)return -1;
    if(m->backwards_at==m->clocks){*out=0;return 0;}
    *out=m->now;
    if(!m->frozen)m->now+=m->step_us;
    return 0;
}
static void reset(void) {
    uint8_t *expected=f.expected;
    uint32_t clusters[3]={5,137,8};
    memset(&f,0,sizeof(f));f.expected=expected;f.spc=1;f.fat_count=2;f.root=2;f.first_lba=2048;
    f.cluster_count=CLUSTERS;
    f.step_us=10;f.now=1000000;f.disk_sectors=FIRST_LBA+RESERVED+2u*FAT_SECTORS+CLUSTERS;
    f.mbr[510]=0x55;f.mbr[511]=0xaa;f.mbr[446+4]=0x0c;
    put32(f.mbr+446+8,(uint32_t)FIRST_LBA);put32(f.mbr+446+12,(uint32_t)(f.disk_sectors-FIRST_LBA));
    f.bpb[510]=0x55;f.bpb[511]=0xaa;put16(f.bpb+11,512);f.bpb[13]=1;
    put16(f.bpb+14,RESERVED);f.bpb[16]=2;f.bpb[21]=0xf8;
    put32(f.bpb+28,(uint32_t)FIRST_LBA);put32(f.bpb+32,(uint32_t)(f.disk_sectors-FIRST_LBA));
    put32(f.bpb+36,FAT_SECTORS);put32(f.bpb+44,2);
    fat(0,0x0ffffff8u,0x0ffffff8u);fat(1,0x0fffffffu,0x0fffffffu);fat(2,0x0fffffffu,0x0fffffffu);
    chain(1201,3,clusters);
    memset(&io,0,sizeof(io));io.struct_size=sizeof(io);io.abi_version=1;io.sector_bytes=512;
    io.sector_count=f.disk_sectors;io.user=&f;io.read_sector=read_sector;io.now_us=now_us;
    memset(&request,0,sizeof(request));request.struct_size=sizeof(request);request.abi_version=1;
    request.read_budget=NTWF_MAX_READS;request.time_budget_us=NTWF_MAX_TIME_US;memcpy(request.name,"KERNEL  BIN",11);
    memset(destination,SENTINEL,CAPACITY);memset(&info,SENTINEL,sizeof(info));
    memset(work,0x6d,sizeof(*work));
}
static int invoke(size_t capacity) {
    int status;
    memcpy(before_destination,destination,CAPACITY);memcpy(&before_info,&info,sizeof(info));++scenarios;
    status=ntwf_read_root83(&io,&request,work,destination,capacity,&info);
    CHECK(f.reads<=request.read_budget || request.read_budget>NTWF_MAX_READS);
    if(status!=NTWF_OK){CHECK(!memcmp(destination,before_destination,CAPACITY));CHECK(!memcmp(&info,&before_info,sizeof(info)));}
    else {
        CHECK(info.struct_size==80 && info.abi_version==1 && info.file_bytes==f.file_size);
        CHECK(info.partition_index==request.partition_index && info.partition_lba==FIRST_LBA);
        CHECK(info.partition_sectors==get32(f.mbr+446+request.partition_index*16+12));
        CHECK(info.volume_sectors==get32(f.bpb+32) && info.sectors_per_cluster==f.spc);
        CHECK(info.cluster_count==f.cluster_count && info.root_cluster==f.root);
        CHECK(info.first_cluster==(f.file_count?f.file_clusters[0]:0));
        CHECK(info.fat_sectors==FAT_SECTORS && info.fat_count==f.fat_count);
        CHECK(info.file_clusters==f.file_count && info.sector_reads==f.reads && info.reserved==0);
        CHECK(info.root_clusters>=1 && info.root_clusters<=64 && info.file_bytes<=capacity);
        CHECK(!memcmp(destination,f.expected,f.file_size));
        CHECK(!memcmp(destination+f.file_size,before_destination+f.file_size,CAPACITY-f.file_size));
    }
    return status;
}

static void invalid_call(const struct ntwf_io *input,const struct ntwf_request *req,
                         struct ntwf_workspace *scratch,void *output,size_t capacity,
                         struct ntwf_file_info *metadata) {
    uint8_t *saved=NULL, saved_info[sizeof(struct ntwf_file_info)];
    if(output && capacity){saved=malloc(capacity);CHECK(saved);memcpy(saved,output,capacity);}
    if(metadata)memcpy(saved_info,metadata,sizeof(saved_info));
    ++scenarios;
    CHECK(ntwf_read_root83(input,req,scratch,output,capacity,metadata)==NTWF_INVALID);
    CHECK(!f.reads && !f.clocks);
    if(saved)CHECK(!memcmp(saved,output,capacity));
    if(metadata)CHECK(!memcmp(saved_info,metadata,sizeof(saved_info)));
    free(saved);
}

static void happy_and_chains(void) {
    uint32_t i,list[1024]={0};
    reset();CHECK(invoke(CAPACITY)==NTWF_OK);CHECK(info.mirrored==1 && info.active_fat==0 && info.root_clusters==1);
    for(i=0;i<4;++i){reset();if(i){memcpy(f.mbr+446+i*16,f.mbr+446,16);memset(f.mbr+446,0,16);}
        request.partition_index=i;CHECK(invoke(1201)==NTWF_OK);}
    reset();chain(0,0,list);CHECK(invoke(1)==NTWF_OK);
    for(i=0;i<1024;++i)list[i]=5u+i*2u;
    reset();chain(CAPACITY,1024,list);CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();chain(512,1,list);CHECK(invoke(512)==NTWF_OK);
    reset();chain(513,2,list);CHECK(invoke(513)==NTWF_OK);
    reset();fat(5,0xfffffff8u,0x0ffffff8u);chain(512,1,list);fat(5,0xfffffff8u,0x0ffffff8u);
    CHECK(invoke(512)==NTWF_OK);
    reset();CHECK(invoke(1200)!=NTWF_OK);
    reset();put32(record(2,0)+28,CAPACITY+1u);CHECK(invoke(CAPACITY)==NTWF_LIMIT);
    reset();put32(record(2,0)+28,0);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    for(i=0;i<8;++i){static const uint32_t bad[]={0,1,0x0ffffff0u,0x0ffffff6u,0x0ffffff7u,65538,5,2};
        reset();fat(5,bad[i],bad[i]);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);}
    reset();fat(5,0x0fffffffu,0x0fffffffu);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(8,9,9);fat(9,0x0fffffffu,0x0fffffffu);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(137,5,5);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(5,137,138);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();put16(f.bpb+40,0x81);fat(5,0,137);fat(137,0,8);fat(8,0,0x0fffffffu);
    CHECK(invoke(CAPACITY)==NTWF_OK);CHECK(info.active_fat==1 && info.mirrored==0);
}

static void directory_cases(void) {
    uint32_t i, clusters[3]={501,701,901};
    reset();deleted_directory(2);fat(2,3,3);fat(3,0x0fffffffu,0x0fffffffu);
    file_record(3,0,"KERNEL  BIN",0x27,5,1201);CHECK(invoke(CAPACITY)==NTWF_OK);CHECK(info.root_clusters==2);
    reset();file_record(2,1,"KERNEL  BIN",0x20,5,1201);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();file_record(2,1,"KERNEL  BIN",0x10,5,0);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();record(2,0)[11]=0x10;CHECK(invoke(CAPACITY)==NTWF_UNSUPPORTED);
    for(i=0;i<3;++i){reset();
        if(i==0)record(2,0)[0]=0xe5;
        if(i==1)record(2,0)[11]=0x0f;
        if(i==2)record(2,0)[11]=0x08;
        file_record(2,1,"KERNEL  BIN",0x06,5,1201);CHECK(invoke(CAPACITY)==NTWF_OK);}
    reset();memset(record(2,0),0,32);file_record(2,1,"KERNEL  BIN",0x20,5,1201);
    CHECK(invoke(CAPACITY)==NTWF_NOT_FOUND);
    reset();file_record(2,2,"KERNEL  BIN",0x20,5,1201);CHECK(invoke(CAPACITY)==NTWF_OK);
    /* A logical directory end does not excuse a malformed allocated chain. */
    reset();fat(2,2,2);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(2,3,3);fat(3,2,2);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(2,0,0);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();chain(1201,3,clusters);
    for(i=2;i<65;++i)fat(i,i+1u,i+1u);
    fat(65,0x0fffffffu,0x0fffffffu);
    CHECK(invoke(CAPACITY)==NTWF_OK);CHECK(info.root_clusters==64);
    reset();chain(1201,3,clusters);
    for(i=2;i<66;++i)fat(i,i+1u,i+1u);
    fat(66,0x0fffffffu,0x0fffffffu);
    CHECK(invoke(CAPACITY)==NTWF_LIMIT);
    reset();fat(2,8,8);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();memcpy(record(2,0),"OTHER   BIN",11);CHECK(invoke(CAPACITY)==NTWF_NOT_FOUND);
    reset();f.root=500;f.sector_entries=0;put32(f.bpb+44,500);fat(500,0x0fffffffu,0x0fffffffu);
    {uint32_t moved[3]={5,137,8};chain(1201,3,moved);}
    CHECK(invoke(CAPACITY)==NTWF_OK);CHECK(info.root_cluster==500);
}

static void geometry_cases(void) {
    uint32_t i;
    static const struct { uint16_t offset;uint8_t width;uint32_t value; } malformed[]={
        {11,2,0},{11,2,1024},{13,1,0},{13,1,3},{13,1,128},{14,2,0},
        {16,1,0},{16,1,3},{17,2,1},{19,2,1},{22,2,1},{28,4,0},{32,4,0},
        {32,4,32},{32,4,UINT32_MAX},{36,4,0},{36,4,1},{36,4,UINT32_MAX},
        {40,2,0x40},{40,2,0x100},{40,2,0x82},{42,2,1},{44,4,0},{44,4,1},
        {44,4,65538},{44,4,0x0ffffff0},{44,4,0x0ffffff7},{510,2,0}
    };
    for(i=0;i<sizeof(malformed)/sizeof(malformed[0]);++i){
        reset();if(malformed[i].width==1)f.bpb[malformed[i].offset]=(uint8_t)malformed[i].value;
        else if(malformed[i].width==2)put16(f.bpb+malformed[i].offset,(uint16_t)malformed[i].value);
        else put32(f.bpb+malformed[i].offset,malformed[i].value);
        CHECK(invoke(CAPACITY)!=NTWF_OK);++fuzz_cases;
    }
    reset();put32(f.bpb+32,RESERVED+2u*FAT_SECTORS+65524u);CHECK(invoke(CAPACITY)==NTWF_UNSUPPORTED);
    reset();f.cluster_count=65525;put32(f.bpb+32,RESERVED+2u*FAT_SECTORS+65525u);
    CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();put16(f.bpb+48,1);put16(f.bpb+50,6);
    memset(sector(FIRST_LBA+1u)->bytes,0x3c,512);memset(sector(FIRST_LBA+6u)->bytes,0xc3,512);
    CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();f.mbr[510]=0;CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();f.mbr[446]=0x80;CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();f.mbr[446]=1;CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();f.mbr[450]=0x83;CHECK(invoke(CAPACITY)==NTWF_UNSUPPORTED);
    reset();f.mbr[450]=0x0b;CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();put32(f.mbr+454,0);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();put32(f.mbr+458,0);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();put32(f.mbr+454,0xffffff00u);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();put32(f.mbr+458,UINT32_MAX);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();memcpy(f.mbr+462,f.mbr+446,16);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();f.mbr[462+4]=0xee;put32(f.mbr+462+8,1);put32(f.mbr+462+12,100);CHECK(invoke(CAPACITY)==NTWF_UNSUPPORTED);
    reset();f.mbr[462+4]=0x0c;put32(f.mbr+462+8,1);put32(f.mbr+462+12,100);CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();f.mbr[462]=1;CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(0,0x0ffffff0u,0x0ffffff0u);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(1,0x03ffffffu,0x03ffffffu);CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();fat(1,0x03fffffeu,0x03fffffeu);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(1,0x03ffffffu,0x0fffffffu);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();fat(5,0x10000089u,0xf0000089u);CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();put16(f.bpb+40,7);CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();f.bpb[21]=0xf0;fat(0,0x0ffffff0u,0x0ffffff0u);CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();f.bpb[21]=0xf1;CHECK(invoke(CAPACITY)!=NTWF_OK);
    reset();put16(record(2,0)+20,0x0fff);put16(record(2,0)+26,0xfff0);CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();io.sector_count=f.disk_sectors-1u;CHECK(invoke(CAPACITY)==NTWF_CORRUPT);
    reset();{
        const uint64_t shift=UINT64_C(0xffffff00)-f.first_lba;
        f.first_lba+=shift;f.disk_sectors+=shift;io.sector_count=f.disk_sectors;
        for(i=0;i<f.sector_entries;++i)f.sectors[i].lba+=shift;
        put32(f.mbr+454,(uint32_t)f.first_lba);put32(f.bpb+28,(uint32_t)f.first_lba);
        CHECK(data_start()>UINT32_MAX);CHECK(invoke(CAPACITY)==NTWF_OK);
        CHECK(info.partition_lba==UINT64_C(0xffffff00));
    }
    for(i=1;i<=64;i*=2){uint32_t copies;
        for(copies=1;copies<=2;++copies){uint32_t list[3]={5,137,8};uint32_t total;
            reset();f.spc=i;f.fat_count=copies;f.sector_entries=0;
            total=RESERVED+copies*FAT_SECTORS+CLUSTERS*i;
            f.disk_sectors=FIRST_LBA+total;io.sector_count=f.disk_sectors;
            f.bpb[13]=(uint8_t)i;f.bpb[16]=(uint8_t)copies;
            put32(f.bpb+32,total);put32(f.mbr+458,total);
            chain(1201,(1201u+512u*i-1u)/(512u*i),list);CHECK(invoke(CAPACITY)==NTWF_OK);
        }
    }
}

static void failures_and_budgets(void) {
    uint32_t reads,clocks,i;
    reset();CHECK(invoke(CAPACITY)==NTWF_OK);reads=f.reads;clocks=f.clocks;CHECK(reads>5 && clocks>reads);
    for(i=1;i<=reads;++i){reset();f.read_fail=i;CHECK(invoke(CAPACITY)==NTWF_IO);CHECK(f.reads==i);++injected;}
    for(i=1;i<=clocks;++i){reset();f.clock_fail=i;CHECK(invoke(CAPACITY)==NTWF_CLOCK);CHECK(f.clocks==i);++injected;}
    for(i=2;i<=clocks;++i){reset();f.backwards_at=i;CHECK(invoke(CAPACITY)==NTWF_CLOCK);++injected;}
    for(i=1;i<=reads;++i){reset();f.timeout_on_read=i;CHECK(invoke(CAPACITY)==NTWF_TIMEOUT);CHECK(f.reads==i);++injected;}
    for(i=1;i<reads;++i){reset();request.read_budget=i;f.frozen=1;CHECK(invoke(CAPACITY)==NTWF_LIMIT);CHECK(f.reads==i);}
    reset();request.read_budget=reads;f.frozen=1;CHECK(invoke(CAPACITY)==NTWF_OK);
    reset();request.time_budget_us=1;CHECK(invoke(CAPACITY)==NTWF_TIMEOUT);CHECK(f.reads==0);
    reset();f.now=UINT64_MAX-5u;CHECK(invoke(CAPACITY)==NTWF_CLOCK);
    reset();request.read_budget=0;CHECK(invoke(CAPACITY)==NTWF_INVALID);CHECK(!f.reads && !f.clocks);
    reset();request.read_budget=NTWF_MAX_READS+1u;CHECK(invoke(CAPACITY)==NTWF_INVALID);CHECK(!f.reads && !f.clocks);
    reset();request.time_budget_us=0;CHECK(invoke(CAPACITY)==NTWF_INVALID);CHECK(!f.reads && !f.clocks);
    reset();request.time_budget_us=NTWF_MAX_TIME_US+1u;CHECK(invoke(CAPACITY)==NTWF_INVALID);CHECK(!f.reads && !f.clocks);
}

static void invalid_and_aliases(void) {
    uint32_t i;
    static const uint8_t bad_name[]={0,'a','.', '/', '\\',':','*','?','"','<','>','|',0x80};
    for(i=0;i<sizeof(bad_name);++i){reset();request.name[0]=bad_name[i];CHECK(invoke(CAPACITY)==NTWF_INVALID);CHECK(!f.reads && !f.clocks);}
    reset();memset(request.name,' ',11);CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();request.name[1]=' ';CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();request.partition_index=4;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();io.abi_version=2;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();io.reserved=1;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();io.sector_bytes=4096;CHECK(invoke(CAPACITY)!=NTWF_OK);CHECK(!f.reads && !f.clocks);
    reset();io.read_sector=NULL;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();io.now_us=NULL;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();request.reserved=1;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();request.padding=1;CHECK(invoke(CAPACITY)==NTWF_INVALID);
    reset();CHECK(invoke(0)==NTWF_INVALID);
    /* Inputs embedded inside uninitialized scratch remain well-formed. */
    reset();memcpy(work,&io,sizeof(io));invalid_call((const struct ntwf_io *)(void *)work,&request,work,destination,CAPACITY,&info);
    reset();memcpy(work,&request,sizeof(request));invalid_call(&io,(const struct ntwf_request *)(void *)work,work,destination,CAPACITY,&info);
    reset();invalid_call(&io,&request,work,destination,CAPACITY,(struct ntwf_file_info *)(void *)work);
    reset();invalid_call(&io,&request,work,work->staging,CAPACITY,&info);
    reset();invalid_call(&io,&request,work,destination,CAPACITY,(struct ntwf_file_info *)(void *)(destination+CAPACITY-sizeof(info)));
    reset();memcpy(destination,&io,sizeof(io));invalid_call((const struct ntwf_io *)(void *)destination,&request,work,destination,CAPACITY,&info);
    reset();memcpy(destination,&request,sizeof(request));invalid_call(&io,(const struct ntwf_request *)(void *)destination,work,destination,CAPACITY,&info);
    reset();memcpy(&info,&io,sizeof(io));invalid_call((const struct ntwf_io *)(void *)&info,&request,work,destination,CAPACITY,&info);
    reset();memcpy(&info,&request,sizeof(request));invalid_call(&io,(const struct ntwf_request *)(void *)&info,work,destination,CAPACITY,&info);
    reset();invalid_call(NULL,&request,work,destination,CAPACITY,&info);
    reset();invalid_call(&io,NULL,work,destination,CAPACITY,&info);
    reset();invalid_call(&io,&request,NULL,destination,CAPACITY,&info);
    reset();invalid_call(&io,&request,work,NULL,CAPACITY,&info);
    reset();invalid_call(&io,&request,work,destination,CAPACITY,NULL);
}

int main(void) {
    work=malloc(sizeof(*work));destination=malloc(CAPACITY);before_destination=malloc(CAPACITY);f.expected=malloc(CAPACITY);
    CHECK(work && destination && before_destination && f.expected);
    happy_and_chains();directory_cases();geometry_cases();failures_and_budgets();invalid_and_aliases();
    printf("{\"status\":\"PASS\",\"checks\":%" PRIu64 ",\"scenarios\":%" PRIu64
           ",\"injected_callbacks\":%" PRIu64 ",\"mutation_cases\":%" PRIu64 "}\n",checks,scenarios,injected,fuzz_cases);
    free(f.expected);free(before_destination);free(destination);free(work);return 0;
}
