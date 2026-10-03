/* SPDX-License-Identifier: GPL-2.0-only
 * Production profile.c; the shell lookup and directory calls are boundaries.
 * These controls do not claim actual Windows login or filesystem isolation. */
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include "profile.h"
static char folder[MAX_PATH],created[MAX_PATH];
static DWORD error,attributes,drive_type;
static int lookup_ok,create_ok,lookup_count,create_count,attr_count;
static unsigned checks,failed;
#define CHECK(x) do{++checks;if(!(x)){++failed;fprintf(stderr,"profile assertion %u\n",__LINE__);}}while(0)
DWORD GetLastError(void){return error;}
void SetLastError(DWORD e){error=e;}
BOOL SHGetSpecialFolderPathA(void *window,char *out,int csidl,BOOL create)
{
    ++lookup_count;CHECK(!window && csidl==CSIDL_APPDATA && create==TRUE);
    if(!lookup_ok)return 0;
    memcpy(out,folder,sizeof folder);return 1;
}
BOOL CreateDirectoryA(const char *path,void *security)
{++create_count;CHECK(!security);strcpy(created,path);return create_ok;}
DWORD GetDriveTypeA(const char *root)
{CHECK(root[0]==folder[0] && root[1]==':' && root[2]=='\\' && !root[3]);return drive_type;}
DWORD GetFileAttributesA(const char *path)
{++attr_count;CHECK(!strcmp(path,created));return attributes;}
static void reset(const char *path)
{
    memset(folder,0,sizeof folder);if(path)strcpy(folder,path);
    created[0]=0;error=0;attributes=FILE_ATTRIBUTE_DIRECTORY;drive_type=DRIVE_FIXED;
    lookup_ok=create_ok=1;lookup_count=create_count=attr_count=0;
}
static void reject(pz98_paths *out)
{
    pz98_paths before=*out;CHECK(!pz98_profile_paths(out));
    CHECK(!memcmp(out,&before,sizeof before));CHECK(GetLastError()!=0);
}
int main(void)
{
    pz98_paths a,b,out;unsigned type;size_t maximum;
    memset(&out,0x5a,sizeof out);
    reset("C:\\Windows\\Profiles\\Alice\\Application Data");
    CHECK(pz98_profile_paths(&a));CHECK(lookup_count==1 && create_count==1 && attr_count==1);
    CHECK(!strcmp(a.preferences,"C:\\Windows\\Profiles\\Alice\\Application Data\\Shizuku-Personalization\\preferences.pz"));
    CHECK(!strcmp(a.bitmap,"C:\\Windows\\Profiles\\Alice\\Application Data\\Shizuku-Personalization\\wallpaper.bmp"));
    CHECK(!strcmp(a.html,"C:\\Windows\\Profiles\\Alice\\Application Data\\Shizuku-Personalization\\wallpaper.htm"));
    reset("C:\\Windows\\Profiles\\Bob\\Application Data");
    CHECK(pz98_profile_paths(&b));CHECK(strcmp(a.preferences,b.preferences) && strcmp(a.bitmap,b.bitmap) && strcmp(a.html,b.html));
    reset("C:\\Windows\\Application Data");create_ok=0;error=ERROR_ALREADY_EXISTS;
    CHECK(pz98_profile_paths(&b));CHECK(attr_count==1);
    reset("C:\\Windows\\Application Data");create_ok=0;error=ERROR_ACCESS_DENIED;
    reject(&out);CHECK(attr_count==0 && create_count==1 && error==ERROR_ACCESS_DENIED);
    reset("C:\\Windows\\Application Data");attributes=FILE_ATTRIBUTE_NORMAL;
    reject(&out);CHECK(error==ERROR_INVALID_DATA);
    reset("C:\\Windows\\Application Data");attributes=INVALID_FILE_ATTRIBUTES;error=ERROR_ACCESS_DENIED;
    reject(&out);CHECK(error==ERROR_ACCESS_DENIED);
    reset(NULL);lookup_ok=0;reject(&out);CHECK(create_count==0 && attr_count==0);
    reset(NULL);reject(&out);CHECK(create_count==0);
    reset("relative");reject(&out);CHECK(create_count==0);
    reset("C:relative");reject(&out);CHECK(create_count==0);
    reset("\\\\server\\share");reject(&out);CHECK(create_count==0);
    for(type=DRIVE_UNKNOWN;type<=DRIVE_RAMDISK;type++) {
        reset("Z:\\Profiles\\Alice\\Application Data");drive_type=type;
        if(type==DRIVE_FIXED || type==DRIVE_REMOVABLE || type==DRIVE_RAMDISK)
            CHECK(pz98_profile_paths(&b));
        else {reject(&out);CHECK(error==ERROR_NOT_SUPPORTED && create_count==0);}
    }
    /* Longest valid filename must also fit each store suffix and terminator. */
    maximum=MAX_PATH-1-4-1-strlen("preferences.pz")-1-strlen("Shizuku-Personalization");
    reset("C:\\");memset(folder+3,'a',maximum-3);folder[maximum]=0;
    CHECK(pz98_profile_paths(&b));CHECK(strlen(b.preferences)+4==MAX_PATH-1);
    reset("C:\\");memset(folder+3,'a',maximum-2);folder[maximum+1]=0;
    reject(&out);CHECK(error==ERROR_BUFFER_OVERFLOW && create_count==0);
    reset("C:\\");memset(folder+3,'a',MAX_PATH-4);folder[MAX_PATH-1]=0;
    reject(&out);CHECK(error==ERROR_BUFFER_OVERFLOW && create_count==0);
    reset(NULL);memset(folder,'a',sizeof folder);reject(&out);
    CHECK(error==ERROR_BUFFER_OVERFLOW && create_count==0);
    reset(NULL);CHECK(!pz98_profile_paths(NULL));CHECK(error==ERROR_INVALID_PARAMETER && !lookup_count);
    printf("%s: %u production profile checks, %u failures; shell/directory boundaries modeled\n",failed?"FAIL":"PASS",checks,failed);
    return failed?1:0;
}
