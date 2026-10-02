/* SPDX-License-Identifier: GPL-2.0-only */
#include "persistence.h"
static int fresh_ata(const w98_ata_t *a)
{return a && a->disk && a->bytes==(2ull<<30) && a->sectors==W98_PERSIST_DISK_SECTORS && !a->backend_attached && !a->backend_failed && a->status==0x50 && !a->remaining && !a->word && !a->writing;}
static int attach_map(w98_persistence_t *s,w98_ata_t *a)
{
    w98_owned_block_t raw;
    if(w98_vblk_block(&s->device,&raw) || w98_persist_disk_init(&s->map,W98_DISK_BACKEND_OPTIN,&raw) || w98_vblk_seal_member(&s->device,&s->map) || w98_persist_disk_backend(&s->map,&s->backend) || w98_ata_attach_backend(a,W98_DISK_BACKEND_OPTIN,&s->backend)){
        s->failed=1;(void)w98_vblk_close(&s->device);return -1;
    }
    s->ata=a;s->attached=1;return 0;
}
int w98_persistence_attach(w98_persistence_t *s,w98_ata_t *a,const w98_persist_config_t *c,uint64_t bytes,const w98_vblk_io_t *io)
{
    if(!c && !bytes)return 0; /* original RAM baseline, no callbacks */
    if(!s || s->attached || s->failed || !fresh_ata(a) || w98_vblk_init(&s->device,c,bytes,io))return -1;
    return attach_map(s,a);
}
int w98_persistence_attach_native(w98_persistence_t *s,w98_ata_t *a,const w98_persist_config_t *c,uint64_t bytes,const shz_info_t *i)
{
    if(!c && !bytes)return 0;
    if(!s || s->attached || s->failed || !fresh_ata(a) || w98_vblk_native_init(&s->device,c,bytes,i))return -1;
    return attach_map(s,a);
}
int w98_persistence_finish(w98_persistence_t *s)
{
    int rc=0;
    if(!s)return -1;
    if(!s->attached)return s->failed?-1:0;
    if(s->failed || !s->ata || s->ata->backend_failed || s->backend.flush(s->backend.opaque))rc=-1;
    if(w98_vblk_close(&s->device))rc=-1;
    if(rc){s->failed=1;if(s->ata){s->ata->backend_failed=1;s->ata->status=0x51;s->ata->error=4;}}
    s->attached=0;return rc;
}
