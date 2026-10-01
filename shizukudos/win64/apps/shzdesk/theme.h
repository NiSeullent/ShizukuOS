/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS userland shell themes. Client surfaces only: this does not replace
 * the Windows98 UXTHEME provider or certify system-wide/non-client theming.
 * Settings belong to the writable data volume, never the shipped ISO.
 */
#ifndef SHZDESK_THEME_H
#define SHZDESK_THEME_H
#include <stdint.h>
#ifndef SHZ_THEME_HOST_TEST
#include <windows.h>
#endif
#define SHZ_THEME_CLASSIC 1u
#define SHZ_THEME_SHIZUKU 2u
#define SHZ_THEME_RECORD_BYTES 18u
#define SHZ_THEME_RGB(r,g,b) ((uint32_t)(r) | ((uint32_t)(g)<<8) | ((uint32_t)(b)<<16))
struct shz_theme_colors {
    uint32_t desktop, panel, surface, text, desktop_text;
    uint32_t selected, selected_text, edge_light, edge_dark, pressed;
};
static const struct shz_theme_colors *shz_theme_palette(unsigned style)
{
    static const struct shz_theme_colors classic = {
        SHZ_THEME_RGB(0,128,128), SHZ_THEME_RGB(192,192,192), SHZ_THEME_RGB(255,255,255),
        SHZ_THEME_RGB(0,0,0), SHZ_THEME_RGB(255,255,255), SHZ_THEME_RGB(0,0,128),
        SHZ_THEME_RGB(255,255,255), SHZ_THEME_RGB(255,255,255), SHZ_THEME_RGB(64,64,64),
        SHZ_THEME_RGB(192,192,192)
    };
    static const struct shz_theme_colors shizuku = {
        SHZ_THEME_RGB(14,36,54), SHZ_THEME_RGB(232,241,248), SHZ_THEME_RGB(250,253,255),
        SHZ_THEME_RGB(20,38,54), SHZ_THEME_RGB(228,246,255), SHZ_THEME_RGB(0,106,168),
        SHZ_THEME_RGB(255,255,255), SHZ_THEME_RGB(255,255,255), SHZ_THEME_RGB(93,131,156),
        SHZ_THEME_RGB(199,224,240)
    };
    return style==SHZ_THEME_CLASSIC ? &classic : style==SHZ_THEME_SHIZUKU ? &shizuku : 0;
}
static int shz_theme_encode(unsigned style, char output[SHZ_THEME_RECORD_BYTES])
{
    static const char classic[] = "SHZTHEME1\nclassic\n";
    static const char shizuku[] = "SHZTHEME1\nshizuku\n";
    const char *record = style==SHZ_THEME_CLASSIC ? classic : style==SHZ_THEME_SHIZUKU ? shizuku : 0;
    unsigned i;
    if (!record || !output) return 0;
    for(i=0;i<SHZ_THEME_RECORD_BYTES;++i) output[i]=record[i];
    return 1;
}
static int shz_theme_decode(const char *bytes, unsigned size, unsigned *output)
{
    char record[SHZ_THEME_RECORD_BYTES]; unsigned style,i;
    if(!bytes || !output || size!=SHZ_THEME_RECORD_BYTES) return 0;
    for(style=SHZ_THEME_CLASSIC;style<=SHZ_THEME_SHIZUKU;++style){
        shz_theme_encode(style,record);
        for(i=0;i<size && bytes[i]==record[i];++i) {}
        if(i==size){*output=style;return 1;}
    }
    return 0;
}
static DWORD shz_theme_last_error(DWORD fallback)
{
    DWORD error=GetLastError();
    return error ? error : fallback;
}
static int shz_theme_read_path(const WCHAR *path, unsigned *style, DWORD *error)
{
    HANDLE file; LARGE_INTEGER size; char bytes[SHZ_THEME_RECORD_BYTES];
    DWORD count=0,got=0,failure=0; unsigned decoded=0;
    file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(file==INVALID_HANDLE_VALUE){
        failure=GetLastError();
        if(failure==ERROR_FILE_NOT_FOUND || failure==ERROR_PATH_NOT_FOUND){*error=0;return 0;}
        *error=failure ? failure : ERROR_READ_FAULT;return -1;
    }
    if(!GetFileSizeEx(file,&size)) failure=shz_theme_last_error(ERROR_READ_FAULT);
    else if(size.QuadPart!=SHZ_THEME_RECORD_BYTES) failure=ERROR_INVALID_DATA;
    while(!failure && count<SHZ_THEME_RECORD_BYTES){
        got=0;
        if(!ReadFile(file,bytes+count,SHZ_THEME_RECORD_BYTES-count,&got,0)) failure=shz_theme_last_error(ERROR_READ_FAULT);
        else if(!got || got>SHZ_THEME_RECORD_BYTES-count) failure=ERROR_READ_FAULT;
        if(!failure) count+=got;
    }
    if(!CloseHandle(file) && !failure) failure=shz_theme_last_error(ERROR_WRITE_FAULT);
    if(!failure && !shz_theme_decode(bytes,count,&decoded)) failure=ERROR_INVALID_DATA;
    if(failure){*error=failure;return -1;}
    *style=decoded;*error=0;return 1;
}
/* Return 1 for a validated setting, 0 when absent, -1 on invalid data or I/O. */
static int shz_theme_load(unsigned *style, DWORD *error)
{
    return shz_theme_read_path(L"D:\\SHZTHEME.CFG",style,error);
}
static int shz_theme_save(unsigned style, DWORD *error)
{
    static const WCHAR temporary[]=L"D:\\SHZTHNEW.CFG";
    static const WCHAR destination[]=L"D:\\SHZTHEME.CFG";
    char bytes[SHZ_THEME_RECORD_BYTES]; HANDLE file; DWORD count=0,written=0,failure=0;
    unsigned readback=0; int loaded;
    if(!shz_theme_encode(style,bytes)){*error=ERROR_INVALID_PARAMETER;return 0;}
    file=CreateFileW(temporary,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
    if(file==INVALID_HANDLE_VALUE){*error=shz_theme_last_error(ERROR_WRITE_FAULT);return 0;}
    while(!failure && count<SHZ_THEME_RECORD_BYTES){
        written=0;
        if(!WriteFile(file,bytes+count,SHZ_THEME_RECORD_BYTES-count,&written,0)) failure=shz_theme_last_error(ERROR_WRITE_FAULT);
        else if(!written || written>SHZ_THEME_RECORD_BYTES-count) failure=ERROR_WRITE_FAULT;
        if(!failure) count+=written;
    }
    if(!failure && !FlushFileBuffers(file)) failure=shz_theme_last_error(ERROR_WRITE_FAULT);
    if(!CloseHandle(file) && !failure) failure=shz_theme_last_error(ERROR_WRITE_FAULT);
    if(!failure){
        loaded=shz_theme_read_path(temporary,&readback,&failure);
        if(loaded!=1 || readback!=style) failure=failure ? failure : ERROR_INVALID_DATA;
    }
    if(!failure && !MoveFileExW(temporary,destination,MOVEFILE_REPLACE_EXISTING)) failure=shz_theme_last_error(ERROR_WRITE_FAULT);
    if(failure){DeleteFileW(temporary);*error=failure;return 0;}
    *error=0;return 1;
}
#endif
