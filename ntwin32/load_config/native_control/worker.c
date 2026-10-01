/* SPDX-License-Identifier: GPL-2.0-only -- genuine Windows DLL API/ABI probe */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../load_config.h"
#include "../../../platform/freestanding/memory.h"
#include "protocol.h"
#include "pin.h"
_Static_assert(sizeof(void *)==4 && sizeof(np_image)==2088 &&
               sizeof(np_load_config_info)==196 && sizeof(np_load_config_cookie_result)==28,
               "pinned PE32 C ABI layout");
typedef int (__cdecl *parse_fn)(np_image *,const void *,uint32_t,const char **);
typedef int (__cdecl *parse_limited_fn)(np_image *,const void *,uint32_t,const np_parse_limits *,const char **);
typedef int (__cdecl *lc_fn)(const np_image *,np_load_config_info *,const char **);
typedef int (__cdecl *lc_limited_fn)(const np_image *,np_load_config_info *,const np_load_config_limits *,const char **);
typedef int (__cdecl *cookie_fn)(const np_image *,void *,uint32_t,uint32_t,np_load_config_cookie_result *,const char **);
typedef int (__cdecl *cookie_limited_fn)(const np_image *,void *,uint32_t,uint32_t,np_load_config_cookie_result *,const np_load_config_limits *,const char **);
typedef int (__cdecl *gate_fn)(const np_image *,const char **);
typedef int (__cdecl *gate_limited_fn)(const np_image *,const np_load_config_limits *,const char **);
static HANDLE report=INVALID_HANDLE_VALUE;
static DWORD checks,failures,io_failed;
static np_image original_image,limited_image,synthetic_image;
static BYTE synthetic[4096],synthetic_copy[4096];
static HMODULE module;
static BYTE *original,*mapping;
static FARPROC functions[8];
static void text(const char *s)
{ DWORD n=0,w=0;while(s[n])n++;if(!WriteFile(report,s,n,&w,NULL)||w!=n)io_failed=1; }
static void number(const char *key,DWORD value)
{ char b[9];unsigned n;for(n=0;n<8;n++)b[n]="0123456789ABCDEF"[(value>>(28-4*n))&15];b[8]=0;text(key);text("=");text(b);text("\r\n"); }
static void check(const char *name,int ok)
{ checks++;text(ok?"PASS=":"FAIL=");text(name);text("\r\n");if(!ok)failures++; }
static void export_check(const char *name,int ok)
{ checks++;text(ok?"PASS=EXPORT_":"FAIL=EXPORT_");text(name);text("\r\n");if(!ok)failures++; }
static uint32_t hash(const BYTE *p,uint32_t n)
{ uint32_t h=2166136261u,i;for(i=0;i<n;i++){h^=p[i];h*=16777619u;}return h; }
static uint32_t word(const BYTE *p)
{ return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static void put(BYTE *p,uint32_t v)
{ unsigned i;for(i=0;i<4;i++)p[i]=(BYTE)(v>>(8*i)); }
static int same(const char *a,const char *b)
{ if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b; }
static int zero(const void *p,uint32_t n)
{ const BYTE *b=p;uint32_t i;for(i=0;i<n;i++)if(b[i])return 0;return 1; }
static int same_path(const char *a,const char *b)
{ while(*a&&*b){char x=*a++,y=*b++;if(x>='a'&&x<='z')x-=32;if(y>='a'&&y<='z')y-=32;if(x!=y)return 0;}return !*a&&!*b; }
/* Independently bound every descriptor field used by our private raw copier. */
static int descriptor(const np_image *p,const BYTE *file,uint32_t bytes,
                      uint32_t size,uint32_t headers,uint32_t sections)
{
    uint32_t e,o,s,n,span,raw_bytes;
    if(p->file!=file||p->bytes!=bytes||p->size!=size||p->headers!=headers||
       p->sections!=sections||!sections||sections>NP_SECTIONS||headers>bytes||headers>size||bytes<64)return 0;
    e=word(file+60);if(e>bytes||bytes-e<248)return 0;o=e+24;
    if(sections>(bytes-o-224)/40||p->base!=word(file+o+28)||p->entry!=word(file+o+16)||
       p->section_align!=word(file+o+32)||word(file+o+56)!=size||word(file+o+60)!=headers)return 0;
    for(n=0;n<16;n++)if(p->directory[n][0]!=word(file+o+96+8*n)||p->directory[n][1]!=word(file+o+100+8*n))return 0;
    for(n=0;n<sections;n++){
        const np_section *v=&p->section[n];s=o+224+40*n;span=word(file+s+8);raw_bytes=word(file+s+16);
        if(span<raw_bytes)span=raw_bytes;
        if(v->va!=word(file+s+12)||v->raw!=word(file+s+20)||v->bytes!=raw_bytes||v->span!=span||v->flags!=word(file+s+36)||
           v->va>size||v->span>size-v->va||v->raw>bytes||v->bytes>bytes-v->raw||v->bytes>size-v->va)return 0;
    }return 1;
}
static BYTE *mapped_copy(const np_image *p)
{
    BYTE *m=VirtualAlloc(NULL,p->size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);unsigned n;
    if(!m)return NULL;
    memcpy(m,p->file,p->headers);
    for(n=0;n<p->sections;n++)memcpy(m+p->section[n].va,p->file+p->section[n].raw,p->section[n].bytes);
    /* No fixture code/TLS/CRT is executed. Only cookie storage is API input. */
    return m;
}
static int only_cookie(const BYTE *m,const np_image *p,uint32_t skip)
{
    unsigned n;uint32_t i;
    for(i=0;i<p->size;i++)if(i<skip||i>=skip+4){
        BYTE expected=i<p->headers?p->file[i]:0;
        for(n=0;n<p->sections;n++){
            const np_section *s=&p->section[n];
            if(i>=s->va&&i-s->va<s->bytes){expected=p->file[s->raw+i-s->va];break;}
        }
        if(m[i]!=expected)return 0;
    }return 1;
}
static const BYTE *raw(const np_image *p,uint32_t rva,uint32_t n)
{
    unsigned i;if(rva<=p->headers&&n<=p->headers-rva)return p->file+rva;
    for(i=0;i<p->sections;i++){
        const np_section *s=&p->section[i];
        if(rva>=s->va&&rva-s->va<=s->bytes&&n<=s->bytes-(rva-s->va))return p->file+s->raw+rva-s->va;
    }return NULL;
}
static int executable(const np_image *p,uint32_t rva)
{ unsigned i;for(i=0;i<p->sections;i++){const np_section *s=&p->section[i];if(rva>=s->va&&rva-s->va<s->span)return (s->flags&0xe0000000u)==0x60000000u;}return 0; }
static int export_addresses(void)
{
    const BYTE *d=raw(&original_image,original_image.directory[0][0],40),*eat,*names,*ordinals;unsigned i,j;
    if(!d||word(d+20)!=8||word(d+24)!=8)return 0;
    eat=raw(&original_image,word(d+28),32);names=raw(&original_image,word(d+32),32);ordinals=raw(&original_image,word(d+36),16);
    if(!eat||!names||!ordinals)return 0;
    for(i=0;i<8;i++){
        int found=0;
        for(j=0;j<8;j++){
            const BYTE *name=raw(&original_image,word(names+4*j),1);uint32_t ordinal,rva,k;
            if(!name) return 0;
            for(k=0;k<128;k++){const BYTE *c=raw(&original_image,word(names+4*j)+k,1);if(!c||c!=name+k)return 0;if(!*c)break;}
            if(k==128)return 0;
            if(!same((const char *)name,lc_exports[i]))continue;
            ordinal=ordinals[2*j]|((uint32_t)ordinals[2*j+1]<<8);if(ordinal>=8)return 0;
            rva=word(eat+4*ordinal);
            if(rva!=LC_PIN_EXPORT_RVAS[i]||!executable(&original_image,rva)||
               (UINT_PTR)functions[i]!=(UINT_PTR)module+rva)return 0;
            found++;
        }if(found!=1)return 0;
    }return 1;
}
static void synthetic_file(void)
{
    BYTE *o,*s;unsigned n;
    memset(synthetic,0,sizeof(synthetic));synthetic[0]='M';synthetic[1]='Z';put(synthetic+60,0x80);
    put(synthetic+0x80,0x4550);synthetic[0x84]=0x4c;synthetic[0x85]=1;synthetic[0x86]=3;
    synthetic[0x94]=224;synthetic[0x96]=2;synthetic[0x97]=1;o=synthetic+0x98;
    o[0]=0x0b;o[1]=1;put(o+16,0x1000);put(o+28,0x400000);put(o+32,4096);put(o+36,512);
    put(o+56,0x4000);put(o+60,0x400);o[68]=2;o[48]=4;o[50]=10;put(o+92,16);
    put(o+96+10*8,0x3100);put(o+100+10*8,64);
    for(n=0;n<3;n++){
        s=synthetic+0x178+40*n;s[0]='.';s[1]=n==0?'t':n==1?'d':'r';
        put(s+8,n==1?0x800:0x400);put(s+12,0x1000*(n+1));put(s+16,0x400);put(s+20,0x400*(n+1));
        put(s+36,n==0?0x60000020u:n==1?0xc0000040u:0x40000040u);
    }
    synthetic[0x400]=0xc3;put(synthetic+0x800,NP_LC_DEFAULT_COOKIE);
    put(synthetic+0xd00,64);put(synthetic+0xd00+60,0x402000);
}
void WINAPI entry(void)
{
    HANDLE f=INVALID_HANDLE_VALUE;DWORD n,high=0,got,bytes,result=3;char path[260];const char *error=NULL;
    np_load_config_info info,limited_info;np_load_config_cookie_result cookie;np_parse_limits pl;
    np_load_config_limits limits;uint32_t file_hash=0,before;int ok;
    parse_fn parse;parse_limited_fn parse_limited;lc_fn lc;lc_limited_fn lc_limited;
    cookie_fn initialize;cookie_limited_fn initialize_limited;gate_fn gate;gate_limited_fn gate_limited;
    report=CreateFileA("C:\\VXDLAB\\LCWORK.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
    text("SCOPE=LOAD_CONFIG_NATIVE_DLL_API_ABI\r\nAPPLICATION_SUCCESS=0\r\nMITIGATIONS_IMPLEMENTED=0\r\nSYNTHETIC_CODE_EXECUTED=0\r\nENTROPY_SOURCE_VERIFIED=0\r\n");
    f=CreateFileA("C:\\VXDLAB\\NTWLDC.DLL",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    bytes=f==INVALID_HANDLE_VALUE?0:GetFileSize(f,&high);
    if(f!=INVALID_HANDLE_VALUE&&high==0&&bytes==LC_PIN_BYTES)original=HeapAlloc(GetProcessHeap(),0,bytes);
    ok=original&&ReadFile(f,original,bytes,&got,NULL)&&got==bytes;
    if(f!=INVALID_HANDLE_VALUE){if(!CloseHandle(f))ok=0;f=INVALID_HANDLE_VALUE;}
    check("DLL_FILE_READ",ok);if(!ok)goto finish;
    file_hash=hash(original,bytes);number("ORIGINAL_DLL_BYTES",bytes);number("ORIGINAL_DLL_FNV1A",file_hash);
    check("DLL_FILE_PIN",file_hash==LC_PIN_FNV);if(file_hash!=LC_PIN_FNV)goto finish;
    module=LoadLibraryA("C:\\VXDLAB\\NTWLDC.DLL");check("LOAD_LIBRARY_NATIVE",module!=NULL);if(!module)goto finish;
    n=GetModuleFileNameA(module,path,sizeof(path));ok=n&&n<sizeof(path)&&same_path(path,"C:\\VXDLAB\\NTWLDC.DLL");check("LOADED_MODULE_EXACT_PATH",ok);if(!ok)goto finish;
    for(n=0;n<8;n++){
        functions[n]=GetProcAddress(module,lc_exports[n]);
        ok=functions[n]&&(UINT_PTR)functions[n]==(UINT_PTR)module+LC_PIN_EXPORT_RVAS[n];
        export_check(lc_exports[n],ok);if(!ok)goto finish;
    }
    parse=(parse_fn)functions[0];parse_limited=(parse_limited_fn)functions[1];lc=(lc_fn)functions[2];lc_limited=(lc_limited_fn)functions[3];
    initialize=(cookie_fn)functions[4];initialize_limited=(cookie_limited_fn)functions[5];gate=(gate_fn)functions[6];gate_limited=(gate_limited_fn)functions[7];
    memset(&original_image,0xa5,sizeof(original_image));
    ok=parse(&original_image,original,bytes,&error)&&!error&&descriptor(&original_image,original,bytes,LC_PIN_IMAGE_SIZE,LC_PIN_HEADERS,LC_PIN_SECTIONS);check("ORIGINAL_DLL_PARSE_CDECL",ok);if(!ok)goto finish;
    pl=(np_parse_limits){bytes,original_image.size,bytes+original_image.size};limits=(np_load_config_limits){pl,4,4};
    memset(&limited_image,0xa5,sizeof(limited_image));
    ok=parse_limited(&limited_image,original,bytes,&pl,&error)&&!error&&descriptor(&limited_image,original,bytes,LC_PIN_IMAGE_SIZE,LC_PIN_HEADERS,LC_PIN_SECTIONS)&&!memcmp(&limited_image,&original_image,sizeof(limited_image));check("ORIGINAL_DLL_PARSE_LIMITED_CDECL",ok);if(!ok)goto finish;
    ok=export_addresses();check("ORIGINAL_EXPORT_RVAS_MATCH_NATIVE_POINTERS",ok);if(!ok)goto finish;
    memset(&info,0xa5,sizeof(info));check("ORIGINAL_DLL_LC_ABSENT",lc(&original_image,&info,&error)&&!error&&zero(&info,sizeof(info)));
    memset(&info,0xa5,sizeof(info));check("ORIGINAL_DLL_LC_LIMITED_ABSENT",lc_limited(&original_image,&info,&limits,&error)&&!error&&zero(&info,sizeof(info)));
    check("ORIGINAL_DLL_GATE_CDECL",gate(&original_image,&error)&&!error);
    check("ORIGINAL_DLL_GATE_LIMITED_CDECL",gate_limited(&original_image,&limits,&error)&&!error);
    mapping=mapped_copy(&original_image);check("ORIGINAL_DLL_MAPPED_COPY",mapping!=NULL);if(!mapping)goto finish;
    before=hash(mapping,original_image.size);
    memset(&cookie,0xa5,sizeof(cookie));check("ORIGINAL_DLL_COOKIE_ABSENT",initialize(&original_image,mapping,original_image.size,0x12345678,&cookie,&error)&&!error&&zero(&cookie,sizeof(cookie)));
    memset(&cookie,0xa5,sizeof(cookie));check("ORIGINAL_DLL_COOKIE_LIMITED_ABSENT",initialize_limited(&original_image,mapping,original_image.size,0,&cookie,&limits,&error)&&!error&&zero(&cookie,sizeof(cookie)));
    check("ABSENT_COOKIE_MAPPING_UNCHANGED",hash(mapping,original_image.size)==before);
    ok=VirtualFree(mapping,0,MEM_RELEASE);check("ORIGINAL_DLL_MAPPING_RELEASED",ok);if(!ok)goto finish;mapping=NULL;
    synthetic_file();memcpy(synthetic_copy,synthetic,sizeof(synthetic));
    memset(&synthetic_image,0xa5,sizeof(synthetic_image));
    ok=parse(&synthetic_image,synthetic,sizeof(synthetic),&error)&&!error&&descriptor(&synthetic_image,synthetic,sizeof(synthetic),0x4000,0x400,3);check("SYNTHETIC_PARSE_CDECL",ok);if(!ok)goto finish;
    pl=(np_parse_limits){sizeof(synthetic),0x4000,0x5000};limits=(np_load_config_limits){pl,4,4};
    memset(&limited_image,0xa5,sizeof(limited_image));
    ok=parse_limited(&limited_image,synthetic,sizeof(synthetic),&pl,&error)&&!error&&descriptor(&limited_image,synthetic,sizeof(synthetic),0x4000,0x400,3)&&!memcmp(&limited_image,&synthetic_image,sizeof(limited_image));check("SYNTHETIC_PARSE_LIMITED_CDECL",ok);if(!ok)goto finish;
    memset(&info,0xa5,sizeof(info));check("SYNTHETIC_COOKIE_METADATA",lc(&synthetic_image,&info,&error)&&!error&&info.present&&info.cookie_rva==0x2000&&info.cookie_initial==NP_LC_DEFAULT_COOKIE&&info.prerequisites==NP_LC_PREREQ_COOKIE);
    memset(&limited_info,0xa5,sizeof(limited_info));check("SYNTHETIC_LIMITED_METADATA",lc_limited(&synthetic_image,&limited_info,&limits,&error)&&!error&&!memcmp(&limited_info,&info,sizeof(info))&&limited_info.cookie_rva==0x2000);
    check("SYNTHETIC_COOKIE_GATE_REFUSED",!gate(&synthetic_image,&error)&&same(error,"LC_COOKIE_INITIALIZATION_REQUIRED"));
    check("SYNTHETIC_COOKIE_LIMITED_GATE_REFUSED",!gate_limited(&synthetic_image,&limits,&error)&&same(error,"LC_COOKIE_INITIALIZATION_REQUIRED"));
    mapping=mapped_copy(&synthetic_image);check("SYNTHETIC_MAPPED_COPY",mapping!=NULL);if(!mapping)goto finish;
    memset(&cookie,0xa5,sizeof(cookie));check("NATIVE_COOKIE_DEFAULT_INITIALIZED",initialize(&synthetic_image,mapping,synthetic_image.size,0x12345678,&cookie,&error)&&!error&&cookie.present&&cookie.rva==0x2000&&cookie.previous==NP_LC_DEFAULT_COOKIE&&cookie.value==0x12345678&&cookie.initialized&&!cookie.needs_crt_reinit&&!cookie.remaining_prerequisites&&word(mapping+0x2000)==0x12345678);
    check("COOKIE_ONLY_FOUR_BYTES_CHANGED",only_cookie(mapping,&synthetic_image,0x2000));
    memset(&cookie,0xa5,sizeof(cookie));check("NATIVE_COOKIE_NONDEFAULT_PRESERVED",initialize(&synthetic_image,mapping,synthetic_image.size,0,&cookie,&error)&&!error&&cookie.present&&!cookie.initialized&&!cookie.needs_crt_reinit&&!cookie.remaining_prerequisites&&cookie.previous==0x12345678&&cookie.value==0x12345678&&word(mapping+0x2000)==0x12345678);
    put(mapping+0x2000,0x1234);
    memset(&cookie,0xa5,sizeof(cookie));check("NATIVE_COOKIE_LOW_HIGHWORD_CRT_PREREQUISITE",initialize(&synthetic_image,mapping,synthetic_image.size,0x87654321,&cookie,&error)&&!error&&cookie.present&&!cookie.initialized&&cookie.needs_crt_reinit&&cookie.previous==0x1234&&cookie.value==0x1234&&word(mapping+0x2000)==0x1234&&cookie.remaining_prerequisites==NP_LC_PREREQ_COOKIE_CRT_REINIT);
    put(mapping+0x2000,0);
    memset(&cookie,0xa5,sizeof(cookie));check("NATIVE_LIMITED_COOKIE_ZERO_NORMALIZED",initialize_limited(&synthetic_image,mapping,synthetic_image.size,0,&cookie,&limits,&error)&&!error&&cookie.present&&cookie.rva==0x2000&&cookie.previous==0&&cookie.initialized&&!cookie.needs_crt_reinit&&!cookie.remaining_prerequisites&&cookie.value==0x47110000&&word(mapping+0x2000)==0x47110000);
    check("LIMITED_COOKIE_ONLY_FOUR_BYTES_CHANGED",only_cookie(mapping,&synthetic_image,0x2000));before=hash(mapping,synthetic_image.size);
    memset(&cookie,0xa5,sizeof(cookie));
    check("LIMITED_COOKIE_SHORT_MAPPING_REFUSED",!initialize_limited(&synthetic_image,mapping,synthetic_image.size-1,1,&cookie,&limits,&error)&&same(error,"LC_COOKIE_MAPPING_BOUNDS")&&zero(&cookie,sizeof(cookie)));
    check("FAILED_COOKIE_MAPPING_UNCHANGED",hash(mapping,synthetic_image.size)==before);
    ok=VirtualFree(mapping,0,MEM_RELEASE);check("SYNTHETIC_MAPPING_RELEASED",ok);if(!ok)goto finish;mapping=NULL;
    check("SYNTHETIC_FILE_UNCHANGED",!memcmp(synthetic,synthetic_copy,sizeof(synthetic)));
    pl.total_bytes--;check("LIMITED_PARSE_COMBINED_BUDGET_REFUSED",!parse_limited(&limited_image,synthetic,sizeof(synthetic),&pl,&error)&&same(error,"PARSE_TOTAL_BUDGET"));
    put(synthetic+0x98+100+10*8,72);put(synthetic+0xd00,72);put(synthetic+0xd00+64,0x403201);put(synthetic+0xd00+68,2);
    put(synthetic+0xe01,0x1000);put(synthetic+0xe05,0x1010);memcpy(synthetic_copy,synthetic,sizeof(synthetic));
    memset(&synthetic_image,0xa5,sizeof(synthetic_image));
    ok=parse(&synthetic_image,synthetic,sizeof(synthetic),&error)&&!error&&descriptor(&synthetic_image,synthetic,sizeof(synthetic),0x4000,0x400,3);check("SAFESEH_REPARSE_CDECL",ok);if(!ok)goto finish;
    memset(&info,0xa5,sizeof(info));check("SAFESEH_METADATA_PRESERVED",lc(&synthetic_image,&info,&error)&&!error&&info.seh.count==2&&(info.prerequisites&NP_LC_PREREQ_SAFESEH));
    check("SAFESEH_EXECUTION_REFUSED",!gate(&synthetic_image,&error)&&same(error,"LC_SAFESEH_RUNTIME_REQUIRED"));
    check("SAFESEH_LIMITED_EXECUTION_REFUSED",!gate_limited(&synthetic_image,&limits,&error)&&same(error,"LC_SAFESEH_RUNTIME_REQUIRED"));
    limits.table_entries=1;memset(&info,0xa5,sizeof(info));check("TABLE_BUDGET_REFUSED",!lc_limited(&synthetic_image,&info,&limits,&error)&&same(error,"LC_TABLE_LIMIT")&&zero(&info,sizeof(info)));
    limits.table_entries=2;limits.total_table_entries=1;memset(&info,0xa5,sizeof(info));check("AGGREGATE_TABLE_BUDGET_REFUSED",!lc_limited(&synthetic_image,&info,&limits,&error)&&same(error,"LC_TOTAL_TABLE_LIMIT")&&zero(&info,sizeof(info)));
    check("BUDGET_FAILURE_FILE_UNCHANGED",!memcmp(synthetic,synthetic_copy,sizeof(synthetic)));
    check("ORIGINAL_DLL_FILE_UNCHANGED",hash(original,bytes)==file_hash);
    ok=FreeLibrary(module);check("FREE_LIBRARY_NATIVE",ok);if(!ok)goto finish;module=NULL;
    ok=HeapFree(GetProcessHeap(),0,original);check("DLL_FILE_STORAGE_RELEASED",ok);if(!ok)goto finish;original=NULL;result=0;
finish:
    number("CHECKS",checks);number("FAILURES",failures);if(failures||io_failed)result=31;
    text(result?"STATUS=FAIL\r\n":"STATUS=PASS\r\n");text("OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n");
    if(!FlushFileBuffers(report)||!CloseHandle(report))result=32;
    /* A failed private process keeps allocations/module live until OS exit. */
    ExitProcess(result);
}
