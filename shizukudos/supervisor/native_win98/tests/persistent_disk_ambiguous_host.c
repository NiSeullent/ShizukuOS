/* SPDX-License-Identifier: GPL-2.0-only
 * Review regression controls; same bounded modeled FAT device as the positive
 * controls. No media or device I/O. Inclusion preserves that frozen fixture. */
#define main positive_fixture_main
#include "persistent_disk_host.c"
#undef main
static unsigned ambiguity;
static int ambiguous_read(void *ctx,uint64_t lba,unsigned count,void *out)
{
    uint8_t *p=out;int rc=read_block(ctx,lba,count,out);if(rc)return rc;
    if(lba>=32 && lba<1184 && (lba-32)%576==0)u32(p+8*4,0x0fffffff);
    if(lba==cluster(2)){
        if(ambiguity==0){entry(p+32,"SHZDOS     ",32,8,512);entry(p+64,"SHZDOS     ",16,3,0);entry(p+96,"EFI        ",16,4,0);}
        if(ambiguity==2){entry(p+96,"shzdos     ",16,8,0);}
    }
    if(lba==cluster(3)){
        if(ambiguity==1){entry(p+64,"DISK    IMG",16,8,0);entry(p+96,"DISK    IMG",32,10,2u<<30);entry(p+128,"KEEP    BIN",32,6,512);}
        if(ambiguity==3){entry(p+128,"keep    bin",32,8,512);}
    }
    if(lba==cluster(8) && (ambiguity==1 || ambiguity==2)){
        entry(p,".          ",16,8,0);entry(p+32,"..         ",16,ambiguity==1?3:2,0);
    }
    return 0;
}
int main(void)
{
    w98_owned_block_t b={W98_PERSIST_ESP_SECTORS,&map,ambiguous_read,write_block,flush_block};unsigned accepted=0;
    for(ambiguity=0;ambiguity<4;ambiguity++){
        fixture();if(!w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b)){++accepted;printf("case%u ambiguous namespace accepted\n",ambiguity);}
        CHECK(!writes && !flushes);
    }
    CHECK(accepted==0);
    printf("PASS %u checks; duplicate/case-folded/type-ambiguous FAT names refused; modeled metadata only\n",checks);return 0;
}
