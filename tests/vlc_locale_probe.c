/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only native NLS/registry/geographical provider control. No language,
 * location, machine, or user preference is installed or changed by this test.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
typedef int (WINAPI *geo_info_fn)(GEOID,GEOTYPE,LPWSTR,int,LANGID);
typedef GEOID (WINAPI *user_geo_fn)(GEOCLASS);
typedef LANGID (WINAPI *ui_language_fn)(void);
typedef BOOL (WINAPI *language_group_fn)(LGRPID,DWORD);
static HANDLE report=INVALID_HANDLE_VALUE;
static unsigned checks,failures;static int bad_io;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static void put(const char *s){DWORD written,n=length(s);if(!WriteFile(report,s,n,&written,0)||written!=n)bad_io=1;}
static void check(const char *label,int ok){checks++;if(!ok)failures++;put(ok?"VLCLOC_PASS=":"VLCLOC_FAIL=");put(label);put("\r\n");}
static void hex(const char *label,DWORD value){char data[9];unsigned i;put(label);for(i=0;i<8;i++)data[i]="0123456789ABCDEF"[(value>>(28-4*i))&15];data[8]=0;put(data);put("\r\n");}
static int wide_ascii(const WCHAR *value,const char *expected){unsigned i=0;while(expected[i]){if(value[i]!=(WCHAR)(unsigned char)expected[i])return 0;i++;}return value[i]==0;}
static int configured_geo_absent(void){HKEY key;DWORD type,size=12;char value[12];LONG result;
    result=RegOpenKeyExA(HKEY_CURRENT_USER,"Control Panel\\International\\Geo",0,KEY_QUERY_VALUE,&key);
    if(result==ERROR_FILE_NOT_FOUND)return 1;if(result!=ERROR_SUCCESS)return 0;
    result=RegQueryValueExA(key,"Nation",0,&type,(BYTE *)value,&size);RegCloseKey(key);return result==ERROR_FILE_NOT_FOUND;
}
void WINAPI entry(void)
{
    HMODULE module;geo_info_fn info;user_geo_fn geo;ui_language_fn ui;language_group_fn group;
    WCHAR output[16];GEOID nation;LANGID language;unsigned i;DWORD saved;BOOL supported,installed;
    report=CreateFileA("C:\\VXDLAB\\VLCLOC.LOG",GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
    if(report==INVALID_HANDLE_VALUE)ExitProcess(20);
    module=LoadLibraryA("C:\\VXDLAB\\M98LOC.DLL");check("OWNED_LOCALE_DLL_LOAD",module!=0);
    if(!module)goto finish;
    info=(geo_info_fn)GetProcAddress(module,"GetGeoInfoW");geo=(user_geo_fn)GetProcAddress(module,"GetUserGeoID");
    ui=(ui_language_fn)(void *)GetProcAddress(module,"GetUserDefaultUILanguage");group=(language_group_fn)GetProcAddress(module,"IsValidLanguageGroup");
    check("FOUR_DIRECT_PROVIDER_EXPORTS",info&&geo&&ui&&group);if(!info||!geo||!ui||!group)goto release;
    SetLastError(0x12345678);check("REAL_KOREAN_GEO_ISO2_SIZE",info(134,GEO_ISO2,0,0,0)==3&&GetLastError()==0x12345678);
    check("REAL_KOREAN_GEO_ISO2",info(134,GEO_ISO2,output,16,0)==3&&wide_ascii(output,"KR"));
    check("REAL_KOREAN_GEO_ISO3",info(134,GEO_ISO3,output,16,0)==4&&wide_ascii(output,"KOR"));
    check("REAL_KOREAN_GEO_UN_NUMBER",info(134,GEO_ISO_UN_NUMBER,output,16,0)==4&&wide_ascii(output,"410"));
    check("REAL_US_GEO_ISO2",info(244,GEO_ISO2,output,16,0)==3&&wide_ascii(output,"US"));
    check("REAL_JAPAN_GEO_ISO2",info(122,GEO_ISO2,output,16,0)==3&&wide_ascii(output,"JP"));
    check("REAL_CHINA_GEO_ISO2",info(45,GEO_ISO2,output,16,0)==3&&wide_ascii(output,"CN"));
    for(i=0;i<16;i++)output[i]=0x5555;
    check("SMALL_BUFFER_REJECTED",!info(134,GEO_ISO3,output,3,0)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER);
    check("SMALL_BUFFER_UNCHANGED",output[0]==0x5555&&output[15]==0x5555);
    check("NULL_BUFFER_REJECTED",!info(134,GEO_ISO2,0,3,0)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER);
    check("NEGATIVE_CAPACITY_REJECTED",!info(134,GEO_ISO2,output,-1,0)&&GetLastError()==ERROR_INVALID_PARAMETER);
    check("UNKNOWN_GEO_REJECTED",!info(-1,GEO_ISO2,output,16,0)&&GetLastError()==ERROR_INVALID_PARAMETER);
    check("NONLOCALIZED_LANGUAGE_REJECTED",!info(134,GEO_ISO2,output,16,0x0412)&&GetLastError()==ERROR_INVALID_PARAMETER);
    check("UNSUPPORTED_COORDINATES_NOT_FABRICATED",!info(134,GEO_LATITUDE,output,16,0)&&GetLastError()==ERROR_CALL_NOT_IMPLEMENTED);
    SetLastError(0x23456789);nation=geo(GEOCLASS_NATION);saved=GetLastError();hex("ACTUAL_CONFIGURED_GEOID=",nation);
    check("USER_GEOGRAPHY_NOT_INFERRED",!configured_geo_absent()||nation==GEOID_NOT_AVAILABLE);
    check("USER_GEO_QUERY_LASTERROR_PRESERVED",saved==0x23456789);
    check("INVALID_GEOCLASS_REJECTED",geo(0)==GEOID_NOT_AVAILABLE&&GetLastError()==ERROR_INVALID_PARAMETER);
    language=ui();hex("ACTUAL_UI_LANGUAGE=",language);check("ACTUAL_UI_LANGUAGE_AVAILABLE",language!=0&&language!=0xffff);
    supported=IsValidLocale(0x0412,LCID_SUPPORTED);installed=IsValidLocale(0x0412,LCID_INSTALLED);
    SetLastError(0x34567890);check("KOREAN_SUPPORTED_NATIVE_NLS",group(LGRPID_KOREAN,LGRPID_SUPPORTED)==supported);
    check("LANGUAGE_QUERY_LASTERROR_PRESERVED",GetLastError()==0x34567890);
    check("KOREAN_INSTALLED_NATIVE_NLS",group(LGRPID_KOREAN,LGRPID_INSTALLED)==installed);
    check("UNKNOWN_LANGUAGE_GROUP_REJECTED",!group(0,LGRPID_SUPPORTED)&&GetLastError()==ERROR_INVALID_PARAMETER);
    check("INVALID_LANGUAGE_FLAGS_REJECTED",!group(LGRPID_KOREAN,3)&&GetLastError()==ERROR_INVALID_FLAGS);
release:
    check("OWNED_LOCALE_DLL_RELEASE",FreeLibrary(module));
finish:
    hex("CHECKS=",checks);hex("FAILURES=",failures);put(failures||bad_io?"STATUS=FAIL\r\n":"STATUS=PASS\r\n");
    if(!FlushFileBuffers(report))bad_io=1;CloseHandle(report);ExitProcess(failures||bad_io?31:0);
}
