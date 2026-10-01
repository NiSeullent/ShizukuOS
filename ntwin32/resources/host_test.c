/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only immutable resource tests. The target PE is read as data, never run.
 */
#include "resources.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks, cases;
static void check(int condition, const char *what, unsigned line)
{
    checks++;
    if (!condition) { fprintf(stderr, "FAIL line %u: %s\n", line, what); exit(1); }
}
#define CHECK(x) check(!!(x), #x, __LINE__)
#define CASE(s) do { cases++; printf("CASE %s\n", s); } while (0)
static void put(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void word(uint8_t *p, uint16_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static nr_key id(uint32_t n)
{ nr_key k = { NR_KEY_ID, n, 0, 0 }; return k; }
static nr_key name(const uint8_t *p, uint32_t n)
{ nr_key k = { NR_KEY_NAME, 0, n, p }; return k; }
#define FILE_BYTES 0x1400u
static uint8_t f[FILE_BYTES], saved[FILE_BYTES];
static np_image image;
static nr_resources store, other;
static const char *error;
static void directory(uint8_t *r, uint32_t at, uint16_t names, uint16_t ids)
{ word(r+at+12, names); word(r+at+14, ids); }
static void entry(uint8_t *r, uint32_t at, uint32_t key, uint32_t target)
{ put(r+at,key); put(r+at+4,target); }
static void fixture(void)
{
    uint8_t *o, *s, *r;
    memset(f,0,sizeof(f)); f[0]='M'; f[1]='Z'; put(f+60,0x80);
    put(f+0x80,0x4550); word(f+0x84,0x14c); word(f+0x86,2);
    word(f+0x94,224); word(f+0x96,0x2102); o=f+0x98;
    word(o,0x10b); put(o+28,0x400000); put(o+32,0x1000); put(o+36,0x200);
    put(o+56,0x4000); put(o+60,0x200); word(o+68,2); put(o+92,16);
    put(o+112,0x1000); put(o+116,0x800);
    s=o+224; memcpy(s,".rsrc",5); put(s+8,0x2000); put(s+12,0x1000);
    put(s+16,0x1000); put(s+20,0x200); put(s+36,0x40000040);
    s+=40; memcpy(s,".other",6); put(s+8,0x1000); put(s+12,0x3000);
    put(s+16,0x200); put(s+20,0x1200); put(s+36,0x60000020);
    r=f+0x200; directory(r,0,1,1);
    entry(r,16,0x80000140,0x80000040); entry(r,24,10,0x80000080);
    directory(r,0x40,1,0); entry(r,0x50,0x80000150,0x800000c0);
    directory(r,0x80,0,1); entry(r,0x90,1,0x80000100);
    directory(r,0xc0,0,2); entry(r,0xd0,0,0x180); entry(r,0xd8,1033,0x190);
    directory(r,0x100,0,1); entry(r,0x110,1033,0x1a0);
    word(r+0x140,1); word(r+0x142,'T'); word(r+0x150,1); word(r+0x152,'A');
    put(r+0x180,0x1900); put(r+0x184,3); put(r+0x188,1200);
    put(r+0x190,0x3000); put(r+0x194,7); put(r+0x198,65001);
    put(r+0x1a0,0x1910); put(r+0x1a4,4);
    memcpy(f+0xb00,"abc",3); memcpy(f+0xb10,"defg",4); memcpy(f+0x1200,"outside",7);
}
static int parse(void)
{
    CHECK(np_parse(&image,f,sizeof(f),&error));
    memcpy(saved,f,sizeof(f)); memset(&store,0xa5,sizeof(store));
    return nr_parse(&image,&store,&error);
}
static int allzero(const void *v, size_t n)
{ const uint8_t *p=v; while(n--)if(*p++)return 0; return 1; }
static void refused(const char *expected)
{
    CHECK(!parse());
    if (!error || strcmp(error,expected))
        fprintf(stderr,"expected refusal %s, received %s\n",expected,error?error:"NULL");
    CHECK(error && !strcmp(error,expected));
    CHECK(allzero(&store,sizeof(store))); CHECK(!memcmp(f,saved,sizeof(f)));
    printf("REFUSED %s\n", expected);
}
static void lookup_and_ownership(void)
{
    uint8_t t[]={'T',0}, a[]={'A',0};
    nr_key kt=name(t,1), ka=name(a,1), k10=id(10), k1=id(1);
    nr_handle h, foreign; nr_data data; uint32_t size;
    CASE("counted-name-exact-language-codepage-external-payload");
    fixture(); CHECK(parse()); CHECK(store.count==3 && store.present);
    CHECK(nr_lookup(&store,&kt,&ka,0,&h,&error));
    CHECK(nr_load(&store,h,&data,&error)); CHECK(data.bytes==3 && data.codepage==1200);
    CHECK(data.language==0 && data.rva==0x1900 && !memcmp(data.data,"abc",3));
    CHECK(nr_lookup(&store,&kt,&ka,1033,&h,&error));
    CHECK(nr_load(&store,h,&data,&error)); CHECK(data.rva==0x3000 && data.codepage==65001);
    CHECK(data.bytes==7 && !memcmp(data.data,"outside",7));
    CHECK(nr_sizeof(&store,h,&size,&error) && size==7);
    CASE("no-implicit-language-fallback");
    CHECK(!nr_lookup(&store,&k10,&k1,0,&h,&error) && !h && !strcmp(error,"NR_NOT_FOUND"));
    CHECK(nr_lookup(&store,&k10,&k1,1033,&h,&error));
    CASE("borrowed-handle-repeated-load-no-free");
    CHECK(nr_load(&store,h,&data,&error)); CHECK(nr_load(&store,h,&data,&error));
    CHECK(data.bytes==4 && !memcmp(data.data,"defg",4));
    CASE("null-forged-interior-copied-foreign-owner-handles");
    CHECK(nr_parse(&image,&other,&error));
    CHECK(nr_lookup(&other,&k10,&k1,1033,&foreign,&error));
    { nr_leaf copy=*h; nr_handle invalid[]={0,(nr_handle)(uintptr_t)1,
        (nr_handle)((const uint8_t *)h+1),&copy,foreign}; unsigned i;
      for(i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        memset(&data,0xa5,sizeof(data)); size=0xa5;
        CHECK(!nr_load(&store,invalid[i],&data,&error));
        CHECK(!strcmp(error,"NR_HANDLE_NOT_OWNED") && allzero(&data,sizeof(data)));
        CHECK(!nr_sizeof(&store,invalid[i],&size,&error) && !size);
      }
    }
    CASE("moved-context-and-invalidated-owner");
    memcpy(&other,&store,sizeof(store));
    CHECK(!nr_load(&other,h,&data,&error));
    store.self=0; CHECK(!nr_load(&store,h,&data,&error));
    CHECK(!memcmp(f,saved,sizeof(f)));
    CASE("query-kind-id-range-count-invalid");
    CHECK(nr_parse(&image,&store,&error));
    { nr_key invalid[]={ {2,0,0,0},{0,0x80000000u,0,0},{1,0,65536,(const uint8_t *)(uintptr_t)1},
                        {1,0,1,0},{0,1,1,t} }; unsigned i;
      for(i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        CHECK(!nr_lookup(&store,&invalid[i],&k1,1033,&h,&error));
        CHECK(!h && !strcmp(error,"NR_QUERY_KEY_INVALID"));
      }
    }
}
static void accepted_profiles(void)
{
    nr_key kt=id(0), kn=id(0); nr_handle h; nr_data data;
    CASE("numeric-zero-and-31-bit-ids"); fixture(); put(f+0x218,0); put(f+0x290,0);
    CHECK(parse()); CHECK(nr_lookup(&store,&kt,&kn,1033,&h,&error));
    kt=id(0x7fffffffu); fixture(); put(f+0x218,kt.id); put(f+0x290,0);
    CHECK(parse()); CHECK(nr_lookup(&store,&kt,&kn,1033,&h,&error));
    CASE("counted-embedded-NUL-unpaired-surrogate-and-unaligned-query");
    fixture(); word(f+0x350,3); word(f+0x352,'A'); word(f+0x354,0); word(f+0x356,0xd800);
    CHECK(parse()); { uint8_t query[]={0,'A',0,0,0,0,0xd8}; uint8_t t[]={'T',0};
      kt=name(t,1); kn=name(query+1,3);
      CHECK(nr_lookup(&store,&kt,&kn,1033,&h,&error));
      kn.units=1; CHECK(!nr_lookup(&store,&kt,&kn,1033,&h,&error)); }
    CASE("empty-counted-name"); fixture(); word(f+0x350,0); CHECK(parse());
    { uint8_t t[]={'T',0}; kt=name(t,1); kn=name(0,0);
      CHECK(nr_lookup(&store,&kt,&kn,1033,&h,&error)); }
    CASE("shared-payload-and-overlapping-immutable-payloads");
    fixture(); put(f+0x390,0x1900); put(f+0x394,3); CHECK(parse());
    CHECK(store.leaf[0].data_rva==store.leaf[1].data_rva);
    CHECK(nr_load(&store,&store.leaf[0],&data,&error));
    CHECK(nr_load(&store,&store.leaf[1],&data,&error));
    fixture(); put(f+0x390,0x1901); put(f+0x394,2); CHECK(parse());
    CHECK(nr_load(&store,&store.leaf[1],&data,&error) && !memcmp(data.data,"bc",2));
    CASE("zero-size-resource-zero-RVA"); fixture(); put(f+0x380,0); put(f+0x384,0);
    CHECK(parse()); CHECK(nr_load(&store,&store.leaf[0],&data,&error)); CHECK(!data.bytes);
    CASE("absent-resource-directory"); fixture(); put(f+0x108,0); put(f+0x10c,0);
    CHECK(parse()); CHECK(!store.present && !store.count);
    CASE("empty-resource-directory"); fixture(); memset(f+0x200,0,32);
    CHECK(parse()); CHECK(store.present && !store.count);
    CASE("payload-arbitrary-section-permissions"); fixture(); CHECK(parse());
    CHECK(nr_load(&store,&store.leaf[1],&data,&error) && data.rva==0x3000);
    CASE("payload-file-backed-headers-and-uninterpreted-codepage"); fixture();
    put(f+0x380,0); put(f+0x384,2); put(f+0x388,0xffffffffu); CHECK(parse());
    CHECK(nr_load(&store,&store.leaf[0],&data,&error));
    CHECK(data.codepage==0xffffffffu && !memcmp(data.data,"MZ",2));
    CASE("ascending-counted-names"); fixture();
    word(f+0x20c,2); word(f+0x20e,0); put(f+0x218,0x80000170u);
    word(f+0x370,1); word(f+0x372,'U'); CHECK(parse());
}
static void malformed(void)
{
    CASE("root-cycle"); fixture(); put(f+0x214,0x80000000u); refused("NR_METADATA_ALIAS_UNSUPPORTED");
    CASE("shared-child-directory"); fixture(); put(f+0x21c,0x80000040u); refused("NR_METADATA_ALIAS_UNSUPPORTED");
    CASE("partial-directory-overlap"); fixture(); put(f+0x214,0x80000010u); refused("NR_METADATA_ALIAS_UNSUPPORTED");
    CASE("shared-name-metadata"); fixture(); put(f+0x250,0x80000140u); refused("NR_METADATA_ALIAS_UNSUPPORTED");
    CASE("shared-data-entry-metadata"); fixture(); put(f+0x2dc,0x180); refused("NR_METADATA_ALIAS_UNSUPPORTED");
    CASE("truncated-name"); fixture(); word(f+0x340,0xffff); refused("NR_METADATA_BOUNDS");
    CASE("name-offset-wrap"); fixture(); put(f+0x210,0xffffffffu); refused("NR_NAME_ALIGNMENT");
    CASE("name-offset-outside-directory"); fixture(); put(f+0x210,0xfffffffeu); refused("NR_NAME_BOUNDS");
    CASE("directory-count-limit"); fixture(); word(f+0x20e,0xffff); refused("NR_ENTRY_WORK_LIMIT");
    CASE("directory-count-truncated"); fixture(); word(f+0x20e,256); refused("NR_METADATA_BOUNDS");
    CASE("name-id-count-kind-mismatch"); fixture(); word(f+0x20c,0); word(f+0x20e,2); refused("NR_ENTRY_KEY_KIND");
    CASE("duplicate-languages"); fixture(); put(f+0x2d8,0); refused("NR_KEY_ORDER_OR_DUPLICATE");
    CASE("descending-languages"); fixture(); put(f+0x2d0,1034); refused("NR_KEY_ORDER_OR_DUPLICATE");
    CASE("descending-counted-names"); fixture();
    word(f+0x20c,2); word(f+0x20e,0); put(f+0x218,0x80000170u);
    word(f+0x370,1); word(f+0x372,'S'); refused("NR_KEY_ORDER_OR_DUPLICATE");
    CASE("duplicate-counted-names-distinct-records"); fixture();
    word(f+0x20c,2); word(f+0x20e,0); put(f+0x218,0x80000170u);
    word(f+0x370,1); word(f+0x372,'T'); refused("NR_KEY_ORDER_OR_DUPLICATE");
    CASE("descending-type-IDs"); fixture();
    word(f+0x20c,0); word(f+0x20e,2); put(f+0x210,11); refused("NR_KEY_ORDER_OR_DUPLICATE");
    CASE("extra-level-unsupported"); fixture(); put(f+0x2d4,0x80000100u); refused("NR_LEVEL_PROFILE_UNSUPPORTED");
    CASE("early-leaf-unsupported"); fixture(); put(f+0x214,0x180); refused("NR_LEVEL_PROFILE_UNSUPPORTED");
    CASE("language-outside-WORD-profile"); fixture(); put(f+0x310,0x10000); refused("NR_LANGUAGE_PROFILE_UNSUPPORTED");
    CASE("metadata-directory-unaligned"); fixture(); put(f+0x214,0x80000041u); refused("NR_DIRECTORY_ALIGNMENT");
    CASE("metadata-record-unaligned"); fixture(); put(f+0x2d4,0x181); refused("NR_DATA_ENTRY_ALIGNMENT");
    CASE("metadata-record-outside-root"); fixture(); put(f+0x2d4,0x800); refused("NR_METADATA_BOUNDS");
    CASE("metadata-record-truncated"); fixture(); put(f+0x2d4,0x7fc); refused("NR_METADATA_BOUNDS");
    CASE("data-reserved-unsupported"); fixture(); put(f+0x38c,1); refused("NR_DATA_RESERVED_UNSUPPORTED");
    CASE("characteristics-unsupported"); fixture(); put(f+0x200,1); refused("NR_CHARACTERISTICS_UNSUPPORTED");
    CASE("payload-size-overflow"); fixture(); put(f+0x384,0xffffffffu); refused("NR_PAYLOAD_RVA_OVERFLOW_OR_BOUNDS");
    CASE("payload-RVA-overflow"); fixture(); put(f+0x380,0xffffffffu); refused("NR_PAYLOAD_RVA_OVERFLOW_OR_BOUNDS");
    CASE("payload-virtual-zero-fill"); fixture(); put(f+0x380,0x2000); refused("NR_PAYLOAD_RAW_BACKING");
    CASE("payload-straddles-raw-end"); fixture(); put(f+0x380,0x1ffe); refused("NR_PAYLOAD_RAW_BACKING");
    CASE("base-PE-gate-rejects-resource-directory-in-zero-fill"); fixture(); put(f+0x108,0x2000);
    CHECK(!np_parse(&image,f,sizeof(f),&error) && !strcmp(error,"DIRECTORY_BOUNDS"));
}
static void aliases(void)
{
    nr_key kt=id(10), kn=id(1); nr_handle h; nr_data data; unsigned i;
    CASE("parse-output-alias-file-image-and-error-aliases"); fixture(); CHECK(parse());
    for(i=0;i<2;i++) {
        nr_resources *out=i?(nr_resources *)(void *)&image:(nr_resources *)(void *)f;
        np_image before=image; memcpy(saved,f,sizeof(f));
        CHECK(!nr_parse(&image,out,&error)); CHECK(!strcmp(error,"NR_OUTPUT_ALIASES_INPUT"));
        CHECK(!memcmp(f,saved,sizeof(f)) && !memcmp(&image,&before,sizeof(image)));
    }
    CHECK(!nr_parse(&image,&store,(const char **)(void *)f)); CHECK(!memcmp(f,saved,sizeof(f)));
    CHECK(!nr_parse(&image,&store,(const char **)(void *)&store)); CHECK(store.self==&store);
    CASE("lookup-load-sizeof-output-alias-owner-file-query");
    CHECK(nr_lookup(&store,&kt,&kn,1033,&h,&error));
    memcpy(saved,f,sizeof(f));
    CHECK(!nr_lookup(&store,&kt,&kn,1033,(nr_handle *)(void *)f,&error));
    CHECK(!nr_lookup(&store,&kt,&kn,1033,(nr_handle *)(void *)&kt,&error)); CHECK(kt.id==10);
    CHECK(!nr_load(&store,h,(nr_data *)(void *)f,&error));
    CHECK(!nr_load(&store,h,(nr_data *)(void *)&store.leaf[0],&error));
    CHECK(!nr_sizeof(&store,h,(uint32_t *)(void *)f,&error));
    CHECK(!memcmp(f,saved,sizeof(f)));
    CASE("error-alias-output-owner-file-query");
    CHECK(!nr_load(&store,h,&data,(const char **)(void *)f));
    CHECK(!nr_lookup(&store,&kt,&kn,1033,&h,(const char **)(void *)&kt)); CHECK(kt.id==10);
    CHECK(!nr_load(&store,h,&data,(const char **)(void *)&data));
    CHECK(!nr_lookup(&store,&kt,&kn,1033,&h,(const char **)(void *)&store));
    CHECK(!memcmp(f,saved,sizeof(f)) && store.self==&store);
    CASE("invalid-name-count-output-alias-preserved");
    { nr_key huge={NR_KEY_NAME,0,0xffffffffu,f};
      CHECK(!nr_lookup(&store,&huge,&kn,1033,(nr_handle *)(void *)f,&error));
      CHECK(!memcmp(f,saved,sizeof(f))); }
}
static void mutations(void)
{
    uint8_t original[FILE_BYTES]; unsigned i, n;
    CASE("bounded-deterministic-metadata-byte-mutations"); fixture(); memcpy(original,f,sizeof(f));
    for(i=0;i<0x1b0;i++)for(n=0;n<4;n++) {
        memcpy(f,original,sizeof(f)); f[0x200+i]^=(uint8_t)(1u<<(n*2));
        CHECK(np_parse(&image,f,sizeof(f),&error)); memcpy(saved,f,sizeof(f));
        if(nr_parse(&image,&store,&error)) {
            uint32_t k; for(k=0;k<store.count;k++) {
                nr_data data; nr_handle h; nr_leaf *leaf=&store.leaf[k];
                CHECK(nr_lookup(&store,&leaf->type,&leaf->name,leaf->language,&h,&error));
                CHECK(h==leaf && nr_load(&store,h,&data,&error));
            }
        } else CHECK(error && allzero(&store,sizeof(store)));
        CHECK(!memcmp(f,saved,sizeof(f)));
    }
}
static void work_limits(void)
{
    const uint32_t rawbytes=0x100000;
    uint8_t *b=calloc(1,rawbytes+0x200), *r;
    np_image p;
    nr_resources *s=calloc(1,sizeof(*s));
    uint32_t i, data_at, strings_at;
    CHECK(b && s); fixture(); memcpy(b,f,0x200); r=b+0x200;
    word(b+0x86,1); put(b+0x98+56,0x101000);
    put(b+0x98+116,rawbytes); put(b+0x178+8,rawbytes); put(b+0x178+16,rawbytes);
    CASE("metadata-region-work-ceiling");
    directory(r,0,0,4096);
    for(i=0;i<4096;i++) entry(r,16+i*8,i,0x80000000u|(0x8010+i*16));
    CHECK(np_parse(&p,b,rawbytes+0x200,&error));
    CHECK(!nr_parse(&p,s,&error)); CHECK(!strcmp(error,"NR_REGION_WORK_LIMIT"));
    CHECK(allzero(s,sizeof(*s)));
    CASE("leaf-work-ceiling"); memset(r,0,rawbytes);
    directory(r,0,0,1); entry(r,16,10,0x80000040u);
    directory(r,0x40,0,1); entry(r,0x50,1,0x80000080u);
    directory(r,0x80,0,1025); data_at=0x80+16+1025*8;
    for(i=0;i<1025;i++) {
        entry(r,0x90+i*8,i,data_at+i*16);
        put(r+data_at+i*16,0x1000+rawbytes-16); put(r+data_at+i*16+4,1);
    }
    CHECK(!nr_parse(&p,s,&error)); CHECK(!strcmp(error,"NR_LEAF_WORK_LIMIT"));
    CHECK(allzero(s,sizeof(*s)));
    CASE("counted-name-total-work-ceiling"); memset(r,0,rawbytes);
    directory(r,0,5,0); strings_at=0x100;
    for(i=0;i<5;i++) {
        entry(r,16+i*8,0x80000000u|strings_at,0x80000000u|(0x40+i*16));
        word(r+strings_at,60000); word(r+strings_at+2,(uint16_t)('A'+i));
        strings_at+=120002;
    }
    CHECK(!nr_parse(&p,s,&error)); CHECK(!strcmp(error,"NR_NAME_WORK_LIMIT"));
    CHECK(allzero(s,sizeof(*s)));
    free(s); free(b);
}
static void real_input(const char *path, unsigned input)
{
    int fd=open(path,O_RDONLY); struct stat st; const uint8_t *file; np_image p;
    nr_resources *s=calloc(1,sizeof(*s)); uint32_t i;
    np_parse_limits limits={ NP_LARGE_FILE_LIMIT,NP_LARGE_IMAGE_LIMIT,NP_LARGE_TOTAL_LIMIT };
    CASE("actual-frozen-Chromium-original-resource-walk-and-lookup");
    CHECK(fd>=0 && s); CHECK(!fstat(fd,&st));
    CHECK(st.st_size>0 && (uint64_t)st.st_size<=NP_LARGE_FILE_LIMIT);
    file=mmap(0,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    CHECK(file!=MAP_FAILED); CHECK(!close(fd));
    CHECK(np_parse_limited(&p,file,(uint32_t)st.st_size,&limits,&error));
    CHECK(nr_parse(&p,s,&error)); CHECK(s->count==(input?105u:54u));
    for(i=0;i<s->count;i++) {
        nr_leaf *leaf=&s->leaf[i]; nr_handle h; nr_data data; uint32_t size;
        CHECK(nr_lookup(s,&leaf->type,&leaf->name,leaf->language,&h,&error) && h==leaf);
        CHECK(nr_load(s,h,&data,&error)); CHECK(nr_sizeof(s,h,&size,&error) && size==data.bytes);
        CHECK(data.data==np_raw(&p,leaf->data_rva,leaf->bytes));
        printf("LEAF %u %u %u %u %u %u %u\n",input,i,leaf->entry_offset,
            leaf->data_rva,leaf->bytes,leaf->codepage,(unsigned)leaf->language);
    }
    /* The current native admission gate must remain unchanged/refusing. */
    CHECK(!np_runtime_profile(&p,&error));
    printf("REAL %u %u %u %s\n",input,s->count,s->regions,error);
    free(s); CHECK(!munmap((void *)file,(size_t)st.st_size));
}
int main(int argc,char **argv)
{
    CHECK(argc==3);
    lookup_and_ownership(); accepted_profiles(); malformed(); aliases(); mutations(); work_limits();
    real_input(argv[1],0); real_input(argv[2],1);
    printf("RESULT PASS cases=%u checks=%u native_executed=false application_success=false\n",cases,checks);
    return 0;
}
