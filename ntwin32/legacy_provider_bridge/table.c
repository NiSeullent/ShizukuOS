/* SPDX-License-Identifier: GPL-2.0-only
 * Validate the complete table before returning any provider function address.
 * All foreign reads go through a module-bounded reader. No function is called.
 */
#include "table.h"

static uint32_t word(const unsigned char *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static int string(ntwp_read_fn read, void *ctx, uint32_t at, char out[256])
{
    unsigned i;
    if (!at) return 0;
    for (i=0;i<256;i++) {
        unsigned char c;
        if (at>UINT32_MAX-i || !read(ctx,at+i,&c,1,0)) return 0;
        out[i]=(char)c;
        if (!c) return i!=0;
        if (c<33 || c>126 || c=='/' || c=='\\' || c==':') return 0;
    }
    return 0;
}
static int compare(const char *a,const char *b,int fold)
{
    unsigned i;
    for (i=0;i<256;i++) {
        unsigned x=(unsigned char)a[i],y=(unsigned char)b[i];
        if (fold) { if(x>='a'&&x<='z')x-=32; if(y>='a'&&y<='z')y-=32; }
        if (x!=y) return x<y?-1:1;
        if (!x) return 0;
    }
    return 1;
}

int ntwp_find_table(ntwp_read_fn read,void *ctx,uint32_t tables,
                    const char *expected,const char *name,uint16_t ordinal,uint32_t *address)
{
    unsigned index;
    int matched_table=0,found=0;
    uint32_t candidate=0;
    if (!read || !address || !expected || (!name&&!ordinal) || (name&&ordinal)) return NTWP_INVALID;
    *address=0;
    for (index=0;index<4;index++) {
        unsigned char row[20];
        uint32_t module,names,ncount,ords,ocount,n;
        char dll[256],previous[256];
        if (tables>UINT32_MAX-index*20 || !read(ctx,tables+index*20,row,20,0)) return NTWP_INVALID;
        module=word(row); names=word(row+4); ncount=word(row+8); ords=word(row+12); ocount=word(row+16);
        if (!module) {
            if (names||ncount||ords||ocount || !matched_table) return NTWP_INVALID;
            *address=candidate; return found?NTWP_FOUND:NTWP_MISSING;
        }
        if (!string(read,ctx,module,dll) || compare(dll,expected,1) || matched_table ||
            ncount>128 || ocount>128 || (!ncount&&names) || (ncount&&!names) ||
            (!ocount&&ords) || (ocount&&!ords)) return NTWP_INVALID;
        matched_table=1; previous[0]=0;
        for (n=0;n<ncount;n++) {
            unsigned char pair[8],probe;
            uint32_t target; char current[256];
            if (names>UINT32_MAX-n*8 || !read(ctx,names+n*8,pair,8,0) ||
                !string(read,ctx,word(pair),current) || (n&&compare(previous,current,0)>=0)) return NTWP_INVALID;
            target=word(pair+4);
            if (!target || !read(ctx,target,&probe,1,1)) return NTWP_INVALID;
            if (name&&!compare(current,name,0)) { candidate=target; found=1; }
            { unsigned j;for(j=0;j<256;j++){previous[j]=current[j];if(!current[j])break;} }
        }
        { uint32_t prior=0;
          for(n=0;n<ocount;n++) {
            unsigned char pair[8],probe;uint32_t number,target;
            if(ords>UINT32_MAX-n*8 || !read(ctx,ords+n*8,pair,8,0))return NTWP_INVALID;
            number=word(pair);target=word(pair+4);
            if (!number || number>65535 || number<=prior || !target || !read(ctx,target,&probe,1,1))return NTWP_INVALID;
            prior=number;
            if (ordinal==number) {candidate=target;found=1;}
          }
        }
    }
    return NTWP_INVALID; /* A bounded, zero-filled terminator is mandatory. */
}
