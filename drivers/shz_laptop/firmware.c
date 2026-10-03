/* SPDX-License-Identifier: GPL-2.0-only */
#include "firmware.h"
#include "internal.h"
#define SDT_HEADER 36u
#define ROOT_MAX (SDT_HEADER+SHZ_FIRMWARE_ROOT_ENTRIES*8u)
#define READ_CHUNK 128u
struct firmware_reader {
    shz_firmware_read_fn read;void *context;size_t remaining;
};
static int same(const uint8_t *a,const uint8_t *b,size_t bytes) {
    size_t i;for(i=0;i<bytes;i++)if(a[i]!=b[i])return 0;return 1;
}
static uint8_t add_bytes(uint8_t sum,const uint8_t *p,size_t bytes) {
    size_t i;for(i=0;i<bytes;i++)sum=(uint8_t)(sum+p[i]);return sum;
}
static int read_bytes(struct firmware_reader *r,uint64_t pa,void *out,size_t bytes) {
    int error;
    if(!bytes || pa>UINT64_MAX-(bytes-1u))return SHZ_MALFORMED;
    if(bytes>r->remaining)return SHZ_CAPACITY;
    r->remaining-=bytes;
    error=r->read(r->context,pa,out,bytes);
    return error>0 ? SHZ_IO:error;
}
static int table_header(struct firmware_reader *r,uint64_t pa,uint8_t *header,
                        size_t *bytes) {
    int error=read_bytes(r,pa,header,SDT_HEADER);size_t n;
    if(error)return error;
    n=shz_le32(header+4);
    if(n<SDT_HEADER || pa>UINT64_MAX-(n-1u))return SHZ_MALFORMED;
    *bytes=n;return SHZ_DRIVER_OK;
}
static int snapshot(struct firmware_reader *r,uint64_t pa,const uint8_t *header,
                    uint8_t *buffer,size_t bytes) {
    int error=read_bytes(r,pa,buffer,bytes);
    if(error)return error;
    if(!same(header,buffer,SDT_HEADER))return SHZ_STALE;
    return add_bytes(0,buffer,bytes) ? SHZ_MALFORMED:SHZ_DRIVER_OK;
}
/* Unknown tables are checksum-validated without interpreting their payload.
 * Retain and compare the actual header on the first streamed read, so a changed
 * length/signature between header and body cannot choose a different schema.
 */
static int stream_table(struct firmware_reader *r,uint64_t pa,const uint8_t *header,
                        size_t bytes) {
    uint8_t buffer[READ_CHUNK],sum=0;size_t offset=0;int error;
    if(bytes>SHZ_FIRMWARE_OTHER_TABLE_MAX)return SHZ_CAPACITY;
    while(offset<bytes) {
        size_t count=bytes-offset;if(count>sizeof(buffer))count=sizeof(buffer);
        error=read_bytes(r,pa+offset,buffer,count);if(error)return error;
        if(!offset && !same(header,buffer,SDT_HEADER))return SHZ_STALE;
        sum=add_bytes(sum,buffer,count);offset+=count;
    }
    return sum ? SHZ_MALFORMED:SHZ_DRIVER_OK;
}
static int root_address(struct firmware_reader *r,uint64_t pa,uint64_t *root,
                        uint8_t *revision,uint8_t *xsdt) {
    uint8_t first[20],header[36],chunk[READ_CHUNK],sum;
    uint32_t bytes;size_t offset;int error;
    error=read_bytes(r,pa,first,sizeof(first));if(error)return error;
    if(!same(first,(const uint8_t *)"RSD PTR ",8) || add_bytes(0,first,sizeof(first)))
        return SHZ_MALFORMED;
    *revision=first[15];*xsdt=0;*root=shz_le32(first+16);
    if(*revision==1)return SHZ_UNSUPPORTED;
    if(!*revision)return *root ? SHZ_DRIVER_OK:SHZ_NOT_FOUND;
    error=read_bytes(r,pa,header,sizeof(header));if(error)return error;
    if(!same(first,header,sizeof(first)))return SHZ_STALE;
    bytes=shz_le32(header+20);
    if(bytes<sizeof(header) || pa>UINT64_MAX-(bytes-1u))return SHZ_MALFORMED;
    if(bytes>SHZ_FIRMWARE_RSDP_MAX)return SHZ_CAPACITY;
    if(header[33] || header[34] || header[35])return SHZ_MALFORMED;
    sum=add_bytes(0,header,sizeof(header));offset=sizeof(header);
    while(offset<bytes) {
        size_t count=bytes-offset;if(count>sizeof(chunk))count=sizeof(chunk);
        error=read_bytes(r,pa+offset,chunk,count);if(error)return error;
        sum=add_bytes(sum,chunk,count);offset+=count;
    }
    if(sum)return SHZ_MALFORMED;
    if(shz_le64(header+24)) {*root=shz_le64(header+24);*xsdt=1;}
    return *root ? SHZ_DRIVER_OK:SHZ_NOT_FOUND;
}
int shz_laptop_firmware_probe(shz_firmware_read_fn read,void *context,
                             uint64_t rsdp_pa,struct shz_laptop_firmware *out) {
    struct firmware_reader r;struct shz_laptop_firmware found;
    uint8_t root[ROOT_MAX],table[SHZ_TABLE_MAX],header[SDT_HEADER];
    uint64_t addresses[SHZ_FIRMWARE_ROOT_ENTRIES];
    size_t bytes,width,count,i,j;int error;
    if(!read || !out)return SHZ_INVALID;
    if(!rsdp_pa)return SHZ_NOT_FOUND;
    r.read=read;r.context=context;r.remaining=SHZ_FIRMWARE_READ_BUDGET;
    shz_zero(&found,sizeof(found));found.rsdp_pa=rsdp_pa;
    error=root_address(&r,rsdp_pa,&found.root_pa,&found.rsdp_revision,&found.uses_xsdt);
    if(error)return error;
    if(found.root_pa==rsdp_pa)return SHZ_MALFORMED;
    error=table_header(&r,found.root_pa,header,&bytes);if(error)return error;
    if(!same(header,(const uint8_t *)(found.uses_xsdt ? "XSDT":"RSDT"),4))
        return SHZ_MALFORMED;
    width=found.uses_xsdt ? 8u:4u;
    if((bytes-SDT_HEADER)%width)return SHZ_MALFORMED;
    count=(bytes-SDT_HEADER)/width;
    if(count>SHZ_FIRMWARE_ROOT_ENTRIES)return SHZ_CAPACITY;
    error=snapshot(&r,found.root_pa,header,root,bytes);if(error)return error;
    found.entry_count=(uint32_t)count;
    /* Validate all addresses before fetching any member. Multiple tables with
     * the same unknown signature (e.g. SSDT) are valid; duplicate addresses or
     * duplicate singleton FADT/ECDT signatures are not accepted.
     */
    for(i=0;i<count;i++) {
        const uint8_t *entry=root+SDT_HEADER+i*width;
        uint64_t address=found.uses_xsdt ? shz_le64(entry):shz_le32(entry);
        if(!address || address==found.root_pa || address==rsdp_pa)return SHZ_MALFORMED;
        for(j=0;j<i;j++)if(address==addresses[j])return SHZ_MALFORMED;
        addresses[i]=address;
    }
    for(i=0;i<count;i++) {
        uint64_t address=addresses[i];
        error=table_header(&r,address,header,&bytes);if(error)return error;
        if(same(header,(const uint8_t *)"FACP",4)) {
            if(found.fadt_pa)return SHZ_MALFORMED;
            if(bytes>sizeof(table))return SHZ_CAPACITY;
            error=snapshot(&r,address,header,table,bytes);if(error)return error;
            error=shz_parse_fadt(table,bytes,&found.fixed);if(error)return error;
            found.fadt_pa=address;
        } else if(same(header,(const uint8_t *)"ECDT",4)) {
            if(found.ecdt_pa)return SHZ_MALFORMED;
            if(bytes>sizeof(table))return SHZ_CAPACITY;
            error=snapshot(&r,address,header,table,bytes);if(error)return error;
            error=shz_parse_ecdt(table,bytes,&found.ec);if(error)return error;
            found.ecdt_pa=address;found.has_ecdt=1;
        } else {
            error=stream_table(&r,address,header,bytes);if(error)return error;
        }
    }
    if(!found.fadt_pa)return SHZ_NOT_FOUND;
    shz_copy(out,&found,sizeof(found));return SHZ_DRIVER_OK;
}
