/* SPDX-License-Identifier: GPL-2.0-only
 * Prospective SECUR32 profile test against the complete production C bodies.
 * Only Win32 loader/RPM/heap/lock boundaries are replaced. The PE bytes are
 * synthetic boundary inputs; no Windows loader, provider DLL or TLS executes.
 * Compile admission and bounded output ownership belong to the external runner.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

/* Preserve the SDK init callback's exact C type. The incomplete type has no
 * host table layout; its foreign 108-byte wire prefix is read through RPM. */
struct _SECURITY_FUNCTION_TABLE_A;

/* Do not replace or duplicate the table parser or native bridge algorithms. */
#include "table.c"
#include "native.c"

enum { MODULES = 6, SSPI_MODULE = 5, DATA_RVA = 0x1000,
       DATA_BYTES = 0x2000, HEADER_BYTES = 0x400, SSPI_OFFSET = 0x600 };
static const char *const mock_target[MODULES] = {
    "KERNEL32.DLL", "SHELL32.DLL", "ADVAPI32.DLL", "USER32.DLL",
    "COMCTL32.DLL", "SECUR32.DLL"
};
static const char *const mock_filename[MODULES] = {
    "M98WRAP.DLL", "M98SHELL.DLL", "M98AD2.DLL", "M98USR1.DLL",
    "M98CTL3.DLL", "M98SSPI.DLL"
};
static const char private_directory[] = "C:\\VXDLAB\\PROVIDERS";

/* Literal v1 prefix from the project's native ANSI provider. This is not the
 * larger modern SecurityFunctionTableA, nor a host-pointer-sized structure. */
typedef struct { uint32_t version, slot[26]; } sspi32_prefix;
_Static_assert(sizeof(sspi32_prefix) == 108, "SSPI32 v1 prefix through Decrypt");
_Static_assert(offsetof(sspi32_prefix, slot[24]) == 100, "Encrypt offset");
_Static_assert(offsetof(sspi32_prefix, slot[25]) == 104, "Decrypt offset");
static const unsigned supported_slot[13] = { 1,3,4,6,9,10,11,16,17,20,21,25,26 };
static const char *const supported_export[13] = {
    "EnumerateSecurityPackagesA", "AcquireCredentialsHandleA", "FreeCredentialsHandle",
    "InitializeSecurityContextA", "DeleteSecurityContext", "ApplyControlToken",
    "QueryContextAttributesA", "FreeContextBuffer", "QuerySecurityPackageInfoA",
    "ExportSecurityContext", "ImportSecurityContextA", "EncryptMessage", "DecryptMessage"
};
static unsigned endpoint_calls[14];
#define ENDPOINT(n) static void endpoint_##n(void) { endpoint_calls[n]++; }
ENDPOINT(0) ENDPOINT(1) ENDPOINT(2) ENDPOINT(3) ENDPOINT(4) ENDPOINT(5)
ENDPOINT(6) ENDPOINT(7) ENDPOINT(8) ENDPOINT(9) ENDPOINT(10) ENDPOINT(11)
ENDPOINT(12) ENDPOINT(13)
#undef ENDPOINT
static FARPROC const original_endpoint[14] = {
    endpoint_0, endpoint_1, endpoint_2, endpoint_3, endpoint_4, endpoint_5,
    endpoint_6, endpoint_7, endpoint_8, endpoint_9, endpoint_10, endpoint_11,
    endpoint_12, endpoint_13
};

typedef struct {
    uint32_t base, size, table_address;
    unsigned char headers[HEADER_BYTES], data[DATA_BYTES];
    unsigned live, loads, unloads, getters, init_calls;
    FARPROC endpoint[14], init_export;
    int missing_export; /* -1 none; 0..12 supported; 13 EndInput; 14 Init. */
} mock_image;
static mock_image mock_images[MODULES];
static uint32_t code_low, code_high, rpm_fail_at, rpm_short_at;
static unsigned getter_image, load_calls, export_calls, rpm_calls, lock_depth;
static unsigned heap_allocations, heap_frees, boundary_errors, heap_fail;
static DWORD last_error;
static unsigned total_checks, failures;

static void check(int okay, const char *tag)
{
    total_checks++;
    if (!okay) failures++;
    printf("%s: %s\n", okay ? "PASS" : "FAIL", tag);
}
static void fatal(const char *message)
{
    fprintf(stderr, "HARNESS_ERROR: %s\n", message);
    exit(2);
}
static uint32_t address_of(FARPROC fn)
{
    uintptr_t value = (uintptr_t)fn;
    if (!value || value > UINT32_MAX) fatal("actual callback is not a nonzero UINT32 address; require no-PIE host build");
    return (uint32_t)value;
}
static void store32(unsigned char *out, uint32_t value)
{
    out[0]=(unsigned char)value; out[1]=(unsigned char)(value>>8);
    out[2]=(unsigned char)(value>>16); out[3]=(unsigned char)(value>>24);
}
static const void *__cdecl fake_get_table(void)
{
    if (getter_image >= MODULES || !mock_images[getter_image].live) fatal("getter invoked without its live module");
    mock_images[getter_image].getters++;
    return (const void *)(uintptr_t)mock_images[getter_image].table_address;
}
static struct _SECURITY_FUNCTION_TABLE_A *WINAPI fake_sspi_init(void)
{
    mock_image *image=&mock_images[SSPI_MODULE];
    if (!image->live) fatal("InitSecurityInterfaceA invoked after unload");
    image->init_calls++;
    return (struct _SECURITY_FUNCTION_TABLE_A *)(uintptr_t)image->table_address;
}
static int image_index(HMODULE module)
{
    unsigned i;
    for (i=0;i<MODULES;i++) if ((uintptr_t)module==mock_images[i].base) return (int)i;
    return -1;
}

/* These functions simulate only documented Win32 boundaries. The production
 * code owns path selection, image validation, profile dispatch and caching. */
HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)1; }
BOOL ReadProcessMemory(HANDLE process, LPCVOID address, LPVOID output, SIZE_T count, SIZE_T *got)
{
    uintptr_t at=(uintptr_t)address;
    unsigned i;
    const unsigned char *source=NULL;
    int code=0;
    rpm_calls++;
    if (got) *got=0;
    if (process!=(HANDLE)(uintptr_t)1 || !output || !got || !count ||
        at>UINT32_MAX || count>UINT32_MAX-at+1u) { boundary_errors++; return FALSE; }
    if (rpm_fail_at && at<=rpm_fail_at && rpm_fail_at-at<count) return FALSE;
    for (i=0;i<MODULES;i++) {
        mock_image *image=&mock_images[i];
        if (!image->live) continue;
        if (at>=image->base && at-image->base<HEADER_BYTES && count<=HEADER_BYTES-(at-image->base)) {
            source=image->headers+(at-image->base); break;
        }
        if (at>=image->base+DATA_RVA && at-(image->base+DATA_RVA)<DATA_BYTES &&
            count<=DATA_BYTES-(at-(image->base+DATA_RVA))) {
            source=image->data+(at-(image->base+DATA_RVA)); break;
        }
        if (at>=code_low && at<code_high && count<=code_high-at) code=1;
    }
    if (!source && !code) return FALSE;
    if (rpm_short_at && at<=rpm_short_at && rpm_short_at-at<count) {
        if (count>1) { if(source) memcpy(output,source,count-1); else memset(output,0x90,count-1); }
        *got=count-1; return TRUE;
    }
    if (source) memcpy(output,source,count); else memset(output,0x90,count);
    *got=count; return TRUE;
}
HMODULE LoadLibraryA(LPCSTR path)
{
    unsigned i;
    char expected[MAX_PATH];
    load_calls++;
    if (!lock_depth) boundary_errors++;
    for (i=0;i<MODULES;i++) {
        snprintf(expected,sizeof(expected),"%s\\%s",private_directory,mock_filename[i]);
        if (!strcmp(path,expected)) {
            mock_images[i].loads++; mock_images[i].live++;
            return (HMODULE)(uintptr_t)mock_images[i].base;
        }
    }
    boundary_errors++; SetLastError(ERROR_MOD_NOT_FOUND); return NULL;
}
BOOL FreeLibrary(HMODULE module)
{
    int i=image_index(module);
    if (i<0 || !mock_images[i].live) { boundary_errors++; return FALSE; }
    mock_images[i].unloads++; mock_images[i].live--; return TRUE;
}
FARPROC GetProcAddress(HMODULE module, LPCSTR name)
{
    int index=image_index(module);
    unsigned i;
    export_calls++;
    if (index<0 || !mock_images[index].live || (uintptr_t)name<=65535u) {
        boundary_errors++; return NULL;
    }
    if (index!=SSPI_MODULE) {
        if (!strcmp(name,"get_api_table")) { getter_image=(unsigned)index; return (FARPROC)fake_get_table; }
        return NULL;
    }
    if (!strcmp(name,"InitSecurityInterfaceA"))
        return mock_images[index].missing_export==14 ? NULL : mock_images[index].init_export;
    if (!strcmp(name,"M98SspiEndInput"))
        return mock_images[index].missing_export==13 ? NULL : mock_images[index].endpoint[13];
    for (i=0;i<13;i++) if (!strcmp(name,supported_export[i]))
        return mock_images[index].missing_export==(int)i ? NULL : mock_images[index].endpoint[i];
    /* Asking this SSPI provider for the unrelated get_api_table is a bug. */
    return NULL;
}
void SetLastError(DWORD value) { last_error=value; }
DWORD GetLastError(void) { return last_error; }
HANDLE GetProcessHeap(void) { return (HANDLE)(uintptr_t)2; }
LPVOID HeapAlloc(HANDLE heap, DWORD flags, SIZE_T count)
{
    if (heap!=(HANDLE)(uintptr_t)2 || flags!=HEAP_ZERO_MEMORY || !count) { boundary_errors++; return NULL; }
    if (heap_fail) return NULL;
    heap_allocations++; return calloc(1,count);
}
BOOL HeapFree(HANDLE heap, DWORD flags, LPVOID pointer)
{
    if (heap!=(HANDLE)(uintptr_t)2 || flags || !pointer) { boundary_errors++; return FALSE; }
    heap_frees++; free(pointer); return TRUE;
}
char *lstrcpyA(char *out, const char *in) { return strcpy(out,in); }
char *lstrcatA(char *out, const char *in) { return strcat(out,in); }
void InitializeCriticalSection(CRITICAL_SECTION *lock) { lock->initialized=1; lock->held=0; }
void EnterCriticalSection(CRITICAL_SECTION *lock)
{
    if (!lock->initialized || lock->held) { boundary_errors++; return; }
    lock->held=1; lock_depth++;
}
void LeaveCriticalSection(CRITICAL_SECTION *lock)
{
    if (!lock->initialized || !lock->held || !lock_depth) { boundary_errors++; return; }
    lock->held=0; lock_depth--;
}
void DeleteCriticalSection(CRITICAL_SECTION *lock)
{
    if (!lock->initialized || lock->held) boundary_errors++;
    lock->initialized=0;
}

static void build_images(void)
{
    unsigned i,j;
    uint32_t lo=address_of((FARPROC)fake_get_table), hi=lo;
    uint32_t init=address_of((FARPROC)fake_sspi_init);
    if (init<lo)lo=init;
    if (init>hi)hi=init;
    for (j=0;j<14;j++) {
        uint32_t at=address_of(original_endpoint[j]);
        if(at<lo)lo=at;
        if(at>hi)hi=at;
    }
    code_low=lo&~0xfffu;
    if (hi>UINT32_MAX-0x1000u || code_low<0x200000u) fatal("callback geometry cannot fit bounded PE32 windows");
    code_high=(hi+0x1000u)&~0xfffu;
    if (code_high-code_low>0x100000u) fatal("callback code span exceeds synthetic fixture bound");
    memset(mock_images,0,sizeof(mock_images));
    for (i=0;i<MODULES;i++) {
        mock_image *image=&mock_images[i];
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS32 nt;
        IMAGE_SECTION_HEADER section[2];
        uint32_t data;
        image->base=(code_low&~0xffffu)-0x100000u+i*0x10000u;
        image->size=code_high-image->base;
        if (image->size>4u*1024u*1024u || code_low-image->base<0x3000u) fatal("synthetic PE sections overlap");
        memset(&dos,0,sizeof(dos)); dos.e_magic=0x5a4d; dos.e_lfanew=0x80;
        memset(&nt,0,sizeof(nt)); nt.Signature=0x00004550;
        nt.FileHeader.Machine=0x014c; nt.FileHeader.NumberOfSections=2;
        nt.FileHeader.SizeOfOptionalHeader=224;
        nt.OptionalHeader.Magic=0x010b; nt.OptionalHeader.SizeOfImage=image->size;
        nt.OptionalHeader.SizeOfHeaders=0x400; nt.OptionalHeader.ImageBase=image->base;
        memset(section,0,sizeof(section));
        section[0].VirtualAddress=0x1000; section[0].Misc.VirtualSize=0x2000;
        section[0].Characteristics=0x40000000;
        section[1].VirtualAddress=code_low-image->base;
        section[1].Misc.VirtualSize=code_high-code_low;
        section[1].Characteristics=0x60000000;
        memcpy(image->headers,&dos,sizeof(dos));
        memcpy(image->headers+0x80,&nt,sizeof(nt));
        memcpy(image->headers+0x80+248,section,sizeof(section));
        for(j=0;j<14;j++)image->endpoint[j]=original_endpoint[j];
        image->missing_export=-1; image->init_export=(FARPROC)fake_sspi_init;
        data=image->base+DATA_RVA;
        if(i==SSPI_MODULE) {
            image->table_address=data+SSPI_OFFSET;
            store32(image->data+SSPI_OFFSET,1);
            for(j=0;j<13;j++) store32(image->data+SSPI_OFFSET+4*supported_slot[j],address_of(original_endpoint[j]));
        } else {
            /* Two sorted named records, one ordinal, then an all-zero row. */
            image->table_address=data;
            store32(image->data,data+0x100); store32(image->data+4,data+0x200);
            store32(image->data+8,2); store32(image->data+12,data+0x240); store32(image->data+16,1);
            memcpy(image->data+0x100,mock_target[i],strlen(mock_target[i])+1);
            store32(image->data+0x200,data+0x300); store32(image->data+0x204,address_of(original_endpoint[0]));
            store32(image->data+0x208,data+0x320); store32(image->data+0x20c,address_of(original_endpoint[1]));
            store32(image->data+0x240,7); store32(image->data+0x244,address_of(original_endpoint[2]));
            memcpy(image->data+0x300,"LegacyOne",10); memcpy(image->data+0x320,"LegacyTwo",10);
        }
    }
}
static void reset_fixture(void)
{
    unsigned i;
    for(i=0;i<MODULES;i++)if(mock_images[i].live)fatal("test tried to reset a still-live module");
    if(lock_depth)fatal("test tried to reset inside production lock");
    build_images();
    memset(endpoint_calls,0,sizeof(endpoint_calls));
    rpm_fail_at=rpm_short_at=0; getter_image=0; load_calls=export_calls=rpm_calls=0;
    heap_allocations=heap_frees=boundary_errors=heap_fail=0; last_error=0;
}
static void *open_context(void)
{
    void *ctx=NtwOpenProviderDirectoryA(private_directory);
    if(!ctx)fatal("valid context allocation failed");
    return ctx;
}
static unsigned called_endpoints(void)
{
    unsigned i,total=0;
    for(i=0;i<14;i++)total+=endpoint_calls[i];
    return total;
}
static void check_teardown(const char *tag)
{
    unsigned i,live=0;
    for(i=0;i<MODULES;i++)live+=mock_images[i].live;
    check(!live && !lock_depth && heap_allocations==heap_frees && !boundary_errors && !called_endpoints(),tag);
}
static void check_immutable(const unsigned char *headers, const unsigned char *data, unsigned index, const char *tag)
{
    check(!memcmp(headers,mock_images[index].headers,HEADER_BYTES) &&
          !memcmp(data,mock_images[index].data,DATA_BYTES),tag);
}

static void legacy_controls(void)
{
    unsigned i;
    for(i=0;i<5;i++) {
        void *ctx;
        FARPROC found;
        unsigned char before_headers[HEADER_BYTES],before_data[DATA_BYTES];
        char tag[96];
        reset_fixture(); ctx=open_context();
        memcpy(before_headers,mock_images[i].headers,HEADER_BYTES);
        memcpy(before_data,mock_images[i].data,DATA_BYTES);
        found=NtwFindProviderExportA(ctx,mock_target[i],"LegacyOne");
        snprintf(tag,sizeof(tag),"legacy/%u/named-identity",i); check(found==original_endpoint[0],tag);
        found=NtwFindProviderExportA(ctx,mock_target[i],(const char *)(uintptr_t)7);
        snprintf(tag,sizeof(tag),"legacy/%u/ordinal-identity",i); check(found==original_endpoint[2],tag);
        found=NtwFindProviderExportA(ctx,mock_target[i],"__ABSENT__");
        snprintf(tag,sizeof(tag),"legacy/%u/missing",i); check(!found && GetLastError()==127,tag);
        snprintf(tag,sizeof(tag),"legacy/%u/cached-live-module",i);
        check(mock_images[i].loads==1 && mock_images[i].live==1 && mock_images[i].getters==1,tag);
        snprintf(tag,sizeof(tag),"legacy/%u/immutable-table",i); check_immutable(before_headers,before_data,i,tag);
        NtwCloseProviderDirectory(ctx);
        snprintf(tag,sizeof(tag),"legacy/%u/close-once",i); check(mock_images[i].unloads==1,tag);
        snprintf(tag,sizeof(tag),"legacy/%u/clean-boundaries",i); check_teardown(tag);
        reset_fixture(); ctx=open_context();
        /* Corrupt the LATER function: an earlier valid match must not escape. */
        store32(mock_images[i].data+0x20c,0x1234);
        found=NtwFindProviderExportA(ctx,mock_target[i],"LegacyOne");
        snprintf(tag,sizeof(tag),"legacy/%u/later-malformed-rejected",i); check(!found && GetLastError()==193,tag);
        snprintf(tag,sizeof(tag),"legacy/%u/malformed-unloaded",i); check(mock_images[i].loads==1 && mock_images[i].unloads==1,tag);
        NtwCloseProviderDirectory(ctx);
        snprintf(tag,sizeof(tag),"legacy/%u/no-double-unload",i); check_teardown(tag);
    }
}

static void sspi_success(void)
{
    void *ctx;
    unsigned i;
    unsigned char before_headers[HEADER_BYTES],before_data[DATA_BYTES];
    char input_dll[]="secur32.dll",input_name[]="AcquireCredentialsHandleA";
    char tag[112];
    reset_fixture(); ctx=open_context();
    memcpy(before_headers,mock_images[SSPI_MODULE].headers,HEADER_BYTES);
    memcpy(before_data,mock_images[SSPI_MODULE].data,DATA_BYTES);
    check(NtwFindProviderExportA(ctx,input_dll,input_name)==original_endpoint[1],"sspi/success/ansi-private-profile");
    check(!strcmp(input_dll,"secur32.dll") && !strcmp(input_name,"AcquireCredentialsHandleA"),"sspi/success/input-strings-immutable");
    for(i=0;i<13;i++) {
        snprintf(tag,sizeof(tag),"sspi/success/identity/%s",supported_export[i]);
        check(NtwFindProviderExportA(ctx,"SECUR32.DLL",supported_export[i])==original_endpoint[i],tag);
    }
    check(NtwFindProviderExportA(ctx,"SECUR32.DLL","InitSecurityInterfaceA")== (FARPROC)fake_sspi_init,"sspi/success/init-export-identity");
    check(NtwFindProviderExportA(ctx,"SECUR32.DLL","M98SspiEndInput")==original_endpoint[13],"sspi/success/end-input-export-identity");
    check(mock_images[SSPI_MODULE].loads==1 && mock_images[SSPI_MODULE].live==1 &&
          mock_images[SSPI_MODULE].init_calls==1 && !mock_images[SSPI_MODULE].getters,"sspi/success/cached-owned-module-and-init-once");
    check(!called_endpoints(),"sspi/success/no-credential-or-tls-invocation");
    check_immutable(before_headers,before_data,SSPI_MODULE,"sspi/success/table-and-headers-immutable");
    NtwCloseProviderDirectory(ctx);
    check(mock_images[SSPI_MODULE].unloads==1,"sspi/success/close-unloads-once");
    check_teardown("sspi/success/teardown");
}

static void early_rejections(void)
{
    static const char *const names[]={
        "AcquireCredentialsHandleW", "InitializeSecurityContextW", "EnumerateSecurityPackagesW",
        "QuerySecurityPackageInfoW", "QueryContextAttributesW", "ImportSecurityContextW",
        "InitSecurityInterfaceW", "__ABSENT__", "acquirecredentialshandlea", "get_api_table"
    };
    unsigned i;
    char tag[112];
    void *ctx;
    reset_fixture(); ctx=open_context();
    for(i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        snprintf(tag,sizeof(tag),"sspi/reject-early/%s",names[i]);
        check(!NtwFindProviderExportA(ctx,"SECUR32.DLL",names[i]) && GetLastError()==127 &&
              !load_calls && !rpm_calls && !export_calls,tag);
    }
    check(!NtwFindProviderExportA(ctx,"SECUR32.DLL",(const char *)(uintptr_t)1) && GetLastError()==127 &&
          !load_calls && !rpm_calls && !export_calls,"sspi/reject-early/ordinal-one");
    check(!NtwFindProviderExportA(ctx,"SECUR32.DLL",(const char *)(uintptr_t)65535) && GetLastError()==127 &&
          !load_calls && !rpm_calls && !export_calls,"sspi/reject-early/ordinal-max");
    check(!NtwFindProviderExportA(ctx,"SECUR32X.DLL","AcquireCredentialsHandleA") && !load_calls,"sspi/reject-early/unsupported-module");
    NtwCloseProviderDirectory(ctx); check_teardown("sspi/reject-early/teardown");
}

/* All invalid-provider trials query a valid name. They must fail as a provider
 * format/load error, unload the partial module once, and retain no cached image.
 * Restoring the boundary input must let a second lookup genuinely reload it. */
static void invalid_trial(unsigned kind, unsigned detail)
{
    void *ctx;
    mock_image *image;
    unsigned char original_headers[HEADER_BYTES],original_data[DATA_BYTES];
    unsigned char mutated_headers[HEADER_BYTES],mutated_data[DATA_BYTES];
    FARPROC originals[14],original_init;
    uint32_t original_table;
    char tag[112],label[72];
    reset_fixture(); ctx=open_context(); image=&mock_images[SSPI_MODULE];
    memcpy(original_headers,image->headers,HEADER_BYTES); memcpy(original_data,image->data,DATA_BYTES);
    memcpy(originals,image->endpoint,sizeof(originals)); original_init=image->init_export; original_table=image->table_address;
    switch(kind) {
    case 0: store32(image->data+SSPI_OFFSET,detail); snprintf(label,sizeof(label),"version-%u",detail); break;
    case 1: store32(image->data+SSPI_OFFSET+4*supported_slot[detail],address_of(original_endpoint[(detail+1)%13]));
            snprintf(label,sizeof(label),"identity-mismatch-%u",detail); break;
    case 2: image->missing_export=(int)detail; snprintf(label,sizeof(label),"missing-export-%u",detail); break;
    case 3: image->endpoint[detail]=(FARPROC)(uintptr_t)(image->base+DATA_RVA+0x100);
            store32(image->data+SSPI_OFFSET+4*supported_slot[detail],image->base+DATA_RVA+0x100);
            snprintf(label,sizeof(label),"nonexecutable-slot-%u",detail); break;
    case 4: store32(image->data+SSPI_OFFSET+4*detail,address_of(original_endpoint[0]));
            snprintf(label,sizeof(label),"unsupported-slot-%u",detail); break;
    case 5: image->init_export=(FARPROC)(uintptr_t)(image->base+DATA_RVA+0x100);
            snprintf(label,sizeof(label),"nonexecutable-init"); break;
    case 6: image->endpoint[13]=(FARPROC)(uintptr_t)(image->base+DATA_RVA+0x100);
            snprintf(label,sizeof(label),"nonexecutable-end-input"); break;
    case 7: rpm_fail_at=image->table_address; snprintf(label,sizeof(label),"unreadable-table"); break;
    case 8: rpm_short_at=image->table_address; snprintf(label,sizeof(label),"short-table-read"); break;
    case 9: image->table_address=0x1234; snprintf(label,sizeof(label),"foreign-table"); break;
    case 10: image->headers[0]=0; snprintf(label,sizeof(label),"bad-dos-magic"); break;
    case 11: rpm_short_at=image->base; snprintf(label,sizeof(label),"short-dos-read"); break;
    case 12: store32(image->data+SSPI_OFFSET+4*supported_slot[detail],0);
             snprintf(label,sizeof(label),"null-supported-slot-%u",detail); break;
    default: fatal("unknown test mutation");
    }
    memcpy(mutated_headers,image->headers,HEADER_BYTES); memcpy(mutated_data,image->data,DATA_BYTES);
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/reject",label);
    check(!NtwFindProviderExportA(ctx,"SECUR32.DLL","AcquireCredentialsHandleA") && GetLastError()==193,tag);
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/invalid-input-immutable",label);
    check_immutable(mutated_headers,mutated_data,SSPI_MODULE,tag);
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/partial-unload",label);
    check(image->loads==1 && image->unloads==1 && !image->live,tag);
    if(kind==5 || kind==10 || kind==11) {
        snprintf(tag,sizeof(tag),"sspi/invalid/%s/init-not-called",label); check(!image->init_calls,tag);
    }
    /* Only test input bytes change here. Never reach into production context. */
    memcpy(image->headers,original_headers,HEADER_BYTES); memcpy(image->data,original_data,DATA_BYTES);
    memcpy(image->endpoint,originals,sizeof(originals)); image->init_export=original_init;
    image->table_address=original_table; image->missing_export=-1; rpm_fail_at=rpm_short_at=0;
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/retry-real-identity",label);
    check(NtwFindProviderExportA(ctx,"SECUR32.DLL","AcquireCredentialsHandleA")==original_endpoint[1],tag);
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/retry-reloads",label); check(image->loads==2 && image->live==1,tag);
    NtwCloseProviderDirectory(ctx);
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/retry-close",label); check(image->unloads==2,tag);
    snprintf(tag,sizeof(tag),"sspi/invalid/%s/teardown",label); check_teardown(tag);
}
static void invalid_controls(void)
{
    unsigned i;
    static const unsigned unsupported[]={2,5,7,8,12,13,14,15,18,19,22,23,24};
    invalid_trial(0,0); invalid_trial(0,2); invalid_trial(0,UINT32_MAX);
    for(i=0;i<13;i++) { invalid_trial(1,i); invalid_trial(3,i); invalid_trial(12,i); }
    for(i=0;i<15;i++)invalid_trial(2,i);
    for(i=0;i<13;i++)invalid_trial(4,unsupported[i]);
    for(i=5;i<=11;i++)invalid_trial(i,0);
}

static void cached_tamper_control(void)
{
    void *ctx;
    mock_image *image;
    FARPROC retained;
    unsigned char before_headers[HEADER_BYTES],before_data[DATA_BYTES];
    reset_fixture(); ctx=open_context(); image=&mock_images[SSPI_MODULE];
    retained=NtwFindProviderExportA(ctx,"SECUR32.DLL","AcquireCredentialsHandleA");
    check(retained==original_endpoint[1],"sspi/cached-tamper/original-pointer-identity");
    /* Change a later supported slot while asking for the earlier retained one.
     * Keep that prior pointer uncalled. Its module lifetime still must survive. */
    store32(image->data+SSPI_OFFSET+4*26,address_of(original_endpoint[0]));
    memcpy(before_headers,image->headers,HEADER_BYTES); memcpy(before_data,image->data,DATA_BYTES);
    check(!NtwFindProviderExportA(ctx,"SECUR32.DLL","AcquireCredentialsHandleA") && GetLastError()==193,
          "sspi/cached-tamper/reject-current-full-table");
    check(image->loads==1 && image->live==1 && image->unloads==0,
          "sspi/cached-tamper/previous-pointer-keeps-module-pinned");
    check_immutable(before_headers,before_data,SSPI_MODULE,"sspi/cached-tamper/validation-does-not-repair-provider");
    store32(image->data+SSPI_OFFSET+4*26,address_of(original_endpoint[12]));
    check(NtwFindProviderExportA(ctx,"SECUR32.DLL","DecryptMessage")==original_endpoint[12],
          "sspi/cached-tamper/repaired-input-revalidated");
    check(image->loads==1 && image->live==1 && image->unloads==0,
          "sspi/cached-tamper/no-unload-or-reload-before-close");
    NtwCloseProviderDirectory(ctx);
    check(image->unloads==1,"sspi/cached-tamper/close-final-reference-once");
    check_teardown("sspi/cached-tamper/teardown-with-no-credential-calls");
}

static void context_controls(void)
{
    void *ctx;
    reset_fixture();
    check(!NtwOpenProviderDirectoryA("PROVIDERS") && GetLastError()==87,"context/reject-relative-directory");
    check(!NtwOpenProviderDirectoryA("C:\\VXDLAB\\P\"ROVIDERS") && GetLastError()==87,"context/reject-quoted-directory");
    heap_fail=1;
    check(!NtwOpenProviderDirectoryA(private_directory) && GetLastError()==8,"context/allocation-failure");
    heap_fail=0; ctx=open_context();
    check(!NtwFindProviderExportA(NULL,"SECUR32.DLL","AcquireCredentialsHandleA") && GetLastError()==87,"context/null-context");
    check(!NtwFindProviderExportA(ctx,NULL,"AcquireCredentialsHandleA") && GetLastError()==87,"context/null-module");
    check(!NtwFindProviderExportA(ctx,"SECUR32.DLL",NULL) && GetLastError()==87,"context/null-name");
    NtwCloseProviderDirectory(NULL); NtwCloseProviderDirectory(ctx);
    check(!load_calls && !export_calls && !rpm_calls,"context/close-unused-no-provider-load");
    check_teardown("context/unused-teardown");
    reset_fixture(); ctx=open_context();
    check(NtwFindProviderExportA(ctx,"KERNEL32.DLL","LegacyOne")==original_endpoint[0],"sspi/mixed/legacy-live-before-sspi-failure");
    store32(mock_images[SSPI_MODULE].data+SSPI_OFFSET,2);
    check(!NtwFindProviderExportA(ctx,"SECUR32.DLL","AcquireCredentialsHandleA"),"sspi/mixed/sspi-invalid-rejected");
    check(mock_images[0].live==1 && mock_images[0].unloads==0,"sspi/mixed/invalid-sspi-retains-legacy-module");
    store32(mock_images[SSPI_MODULE].data+SSPI_OFFSET,1);
    check(NtwFindProviderExportA(ctx,"SECUR32.DLL","DecryptMessage")==original_endpoint[12],"sspi/mixed/sspi-retry-identity");
    check(NtwFindProviderExportA(ctx,"SHELL32.DLL","LegacyOne")==original_endpoint[0],"sspi/mixed/second-legacy-profile");
    NtwCloseProviderDirectory(ctx);
    check(mock_images[0].unloads==1 && mock_images[1].unloads==1 && mock_images[5].unloads==2,"sspi/mixed/close-only-owned-live-modules");
    check_teardown("sspi/mixed/teardown-and-no-credential-calls");
}

int main(void)
{
    /* The no-PIE callable boundary is a harness precondition, never feature RED. */
    if(sizeof(void *)!=8)fatal("this fixture requires host64 plus fixed-width SSPI32 wire data");
    build_images();
    printf("ABI_PREFLIGHT: host_pointer_bytes=8 wire_word_bytes=4 wire_prefix_bytes=108 callable_addresses_fit_u32=1\n");
    context_controls(); legacy_controls(); early_rejections(); sspi_success(); invalid_controls(); cached_tamper_control();
    printf("SUMMARY: %u native SSPI bridge checks, %u failures\n",total_checks,failures);
    return failures ? 1 : 0;
}
