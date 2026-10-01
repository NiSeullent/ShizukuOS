/* SPDX-License-Identifier: GPL-2.0-only
 * Native Win98 NLS/registry/version-backed locale provider. No inferred
 * location, fixed US UI language, or successful synthetic installation.
 */
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include "m98_vlc_locale.h"
#include "m98_vlc_locale_core.h"
#include "kex_abi.h"
static int registry_number(HKEY root,const char *path,const char *name,unsigned base,uint32_t *value)
{
    HKEY key;char data[12];DWORD type=0,bytes=sizeof(data);LONG result;
    if(RegOpenKeyExA(root,path,0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS)return 0;
    result=RegQueryValueExA(key,name,0,&type,(BYTE *)data,&bytes);RegCloseKey(key);
    return result==ERROR_SUCCESS&&type==REG_SZ&&m98_locale_number(data,bytes,base,value);
}
int WINAPI m98_vlc_GetGeoInfoW(GEOID id,GEOTYPE type,LPWSTR out,int capacity,LANGID language)
{
    char data[12];uint32_t error=0;int needed,i;
    if(capacity<0||(language&&type!=GEO_RFC1766&&type!=GEO_LCID)){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    needed=m98_locale_geo_ascii(id,type,data,&error);
    if(!needed){SetLastError(error);return 0;}
    if(!capacity)return needed;
    if(!out||capacity<needed){SetLastError(ERROR_INSUFFICIENT_BUFFER);return 0;}
    for(i=0;i<needed;i++)out[i]=(WCHAR)(unsigned char)data[i];return needed;
}
GEOID WINAPI m98_vlc_GetUserGeoID(GEOCLASS classification)
{
    uint32_t value;const m98_geo_record *geo;DWORD saved=GetLastError();
    if(classification!=GEOCLASS_NATION&&classification!=GEOCLASS_REGION){SetLastError(ERROR_INVALID_PARAMETER);return GEOID_NOT_AVAILABLE;}
    if(!registry_number(HKEY_CURRENT_USER,"Control Panel\\International\\Geo",
        classification==GEOCLASS_NATION?"Nation":"Region",10,&value)||value>INT32_MAX||
        !(geo=m98_locale_geo((int32_t)value))||geo->classification!=(uint32_t)classification){
        SetLastError(saved);return GEOID_NOT_AVAILABLE;
    }
    SetLastError(saved);return (GEOID)value;
}
static LANGID installed_ui_language(void)
{
    char path[MAX_PATH];DWORD n,dummy=0,bytes;BYTE *data;void *translations=0;UINT count=0;LANGID language=0;unsigned i;
    n=GetSystemDirectoryA(path,sizeof(path));if(!n||n>=MAX_PATH-10)return 0;
    {static const char tail[]="\\USER.EXE";for(i=0;i<sizeof(tail);i++)path[n+i]=tail[i];}
    bytes=GetFileVersionInfoSizeA(path,&dummy);if(!bytes||bytes>1024*1024)return 0;
    data=HeapAlloc(GetProcessHeap(),0,bytes);if(!data)return 0;
    if(GetFileVersionInfoA(path,0,bytes,data)&&VerQueryValueA(data,"\\VarFileInfo\\Translation",&translations,&count)&&
       translations&&count&&count%4==0&&(uintptr_t)translations>=(uintptr_t)data&&
       (uintptr_t)translations<=(uintptr_t)data+bytes&&count<=bytes-((uintptr_t)translations-(uintptr_t)data)){
        for(i=0;i<count/4;i++){
            LANGID candidate=((WORD *)translations)[2*i];
            if(candidate&&candidate!=0xffff){if(language&&language!=candidate){language=0;break;}language=candidate;}
        }
    }
    HeapFree(GetProcessHeap(),0,data);return language;
}
LANGID WINAPI m98_vlc_GetUserDefaultUILanguage(void)
{
    uint32_t configured;LANGID result;DWORD saved=GetLastError();
    if(registry_number(HKEY_CURRENT_USER,"Control Panel\\Desktop\\ResourceLocale",0,16,&configured)&&
       configured&&configured<65536){SetLastError(saved);return (LANGID)configured;}
    result=installed_ui_language();if(result){SetLastError(saved);return result;}
    SetLastError(ERROR_NOT_SUPPORTED);return 0;
}
static int native_locale(void *context,uint32_t locale,uint32_t flags)
{(void)context;return IsValidLocale(locale,flags)!=FALSE;}
BOOL WINAPI m98_vlc_IsValidLanguageGroup(LGRPID group,DWORD flags)
{
    char key[5];static const char digits[]="0123456789abcdef";uint32_t value;DWORD saved=GetLastError();BOOL result;unsigned i;
    if(group<1||group>17){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    if(flags!=LGRPID_INSTALLED&&flags!=LGRPID_SUPPORTED){SetLastError(ERROR_INVALID_FLAGS);return FALSE;}
    for(i=0;i<4;i++)key[i]=digits[(group>>(12-4*i))&15];key[4]=0;
    if(registry_number(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\Nls\\Language Groups",key,10,&value)&&value<=1)
        result=flags==LGRPID_SUPPORTED||value==1;
    else result=m98_locale_group(group,flags,native_locale,0);
    SetLastError(saved);return result;
}
static const m98_named_api names[]={
    {"GetGeoInfoW",(unsigned long)m98_vlc_GetGeoInfoW},
    {"GetUserDefaultUILanguage",(unsigned long)m98_vlc_GetUserDefaultUILanguage},
    {"GetUserGeoID",(unsigned long)m98_vlc_GetUserGeoID},
    {"IsValidLanguageGroup",(unsigned long)m98_vlc_IsValidLanguageGroup}
};
static const m98_api_table tables[]={{"KERNEL32.DLL",names,4,0,0},{0,0,0,0,0}};
__declspec(dllexport) const m98_api_table *get_api_table(void){return tables;}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved)
{(void)module;(void)reason;(void)reserved;return TRUE;}
