/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production WER block with declared host registry adapters.
 * No host Windows registry, guest or crash reporting service is invoked. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
typedef uint16_t WCHAR;typedef const WCHAR *PCWSTR;typedef uint8_t BYTE;
typedef uint32_t DWORD;typedef int32_t LONG,HRESULT;typedef int BOOL;typedef void *HKEY;
#define WINAPI
#define DLLAPI
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define KEY_SET_VALUE 2
#define REG_DWORD 4
#define REG_OPTION_NON_VOLATILE 0
#define HKEY_CURRENT_USER ((HKEY)(uintptr_t)1)
#define HKEY_LOCAL_MACHINE ((HKEY)(uintptr_t)2)
#define E_INVALIDARG ((HRESULT)0x80070057)
#define HRESULT_FROM_WIN32(e) ((e)<=0?(HRESULT)(e):(HRESULT)(((DWORD)(e)&0xffffu)|0x80070000u))
typedef struct { unsigned root; WCHAR name[MAX_PATH]; DWORD value; unsigned alive; } value_t;
typedef struct { unsigned root,alive; } key_t;
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static value_t values[32];static key_t keys[16];static unsigned roots[2];
static unsigned injected,creates,opens,sets,deletes,closes;
static _Atomic unsigned checks;
static LONG create_error=5,open_error=3,set_error=13,delete_error=2,close_error=6;
#define CHECK(x) do { ++checks;if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);exit(2);} } while(0)
static unsigned wlength(PCWSTR s){unsigned n=0;while(s[n])++n;return n;}
static BOOL same(PCWSTR a,PCWSTR b){unsigned i;for(i=0;a[i]&&b[i];++i){WCHAR x=a[i],y=b[i];if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y)return FALSE;}return a[i]==b[i];}
static void key_path(HKEY root,PCWSTR path,DWORD rights){CHECK(root==HKEY_CURRENT_USER||root==HKEY_LOCAL_MACHINE);CHECK(same(path,L"Software\\Microsoft\\Windows Error Reporting\\ExcludedApplications"));CHECK(rights==KEY_SET_VALUE);}
static LONG acquire(unsigned root,HKEY *out){unsigned i;for(i=0;i<16;++i)if(!keys[i].alive){keys[i].root=root;keys[i].alive=1;*out=&keys[i];return 0;}return 8;}
static LONG RegCreateKeyExW(HKEY root,PCWSTR path,DWORD reserved,WCHAR *cls,DWORD options,DWORD rights,void *security,HKEY *out,DWORD *disposition){
    LONG status;key_path(root,path,rights);CHECK(!reserved&&!cls&&!options&&!security&&!disposition);
    pthread_mutex_lock(&lock);++creates;if(injected&1)status=create_error;else{unsigned i=root==HKEY_LOCAL_MACHINE;roots[i]=1;status=acquire(i,out);}pthread_mutex_unlock(&lock);return status;
}
static LONG RegOpenKeyExW(HKEY root,PCWSTR path,DWORD options,DWORD rights,HKEY *out){
    LONG status;key_path(root,path,rights);CHECK(!options);pthread_mutex_lock(&lock);++opens;
    if(injected&2)status=open_error;else{unsigned i=root==HKEY_LOCAL_MACHINE;status=roots[i]?acquire(i,out):2;}pthread_mutex_unlock(&lock);return status;
}
static LONG RegSetValueExW(HKEY h,PCWSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD bytes){
    key_t *key=h;unsigned i,slot=32;LONG status=0;CHECK(!reserved&&type==REG_DWORD&&bytes==4&&wlength(name)<MAX_PATH);pthread_mutex_lock(&lock);++sets;CHECK(key->alive);
    if(injected&4)status=set_error;else{for(i=0;i<32;++i){if(values[i].alive&&values[i].root==key->root&&same(values[i].name,name)){slot=i;break;}if(!values[i].alive&&slot==32)slot=i;}
        CHECK(slot<32);values[slot].root=key->root;values[slot].alive=1;memcpy(values[slot].name,name,(wlength(name)+1)*2);memcpy(&values[slot].value,data,4);}
    pthread_mutex_unlock(&lock);return status;
}
static LONG RegDeleteValueW(HKEY h,PCWSTR name){key_t *key=h;unsigned i;LONG status=2;pthread_mutex_lock(&lock);++deletes;CHECK(key->alive);
    if(injected&8)status=delete_error;else for(i=0;i<32;++i)if(values[i].alive&&values[i].root==key->root&&same(values[i].name,name)){values[i].alive=0;status=0;break;}
    pthread_mutex_unlock(&lock);return status;
}
static LONG RegCloseKey(HKEY h){key_t *key=h;pthread_mutex_lock(&lock);CHECK(key->alive);key->alive=0;++closes;pthread_mutex_unlock(&lock);return injected&16?close_error:0;}
#include "wer_production.inc"
static BOOL present(unsigned root,PCWSTR name){unsigned i;for(i=0;i<32;++i)if(values[i].alive&&values[i].root==root&&same(values[i].name,name)&&values[i].value==1)return TRUE;return FALSE;}
static void *thread_body(void *opaque){BOOL machine=(BOOL)(uintptr_t)opaque;PCWSTR name=machine?L"machine.bin":L"thread.bin";HRESULT hr=WerAddExcludedApplication(name,machine);return (void *)(intptr_t)hr;}
int main(void){WCHAR limit[MAX_PATH+1],unicode[]=L"test_한글.bin";unsigned i,before;pthread_t t[2];void *result;
    CHECK(!exclusion_name(NULL)&&!exclusion_name(L"")&&!exclusion_name(L"C:\\"));
    CHECK(WerAddExcludedApplication(NULL,FALSE)==E_INVALIDARG&&WerRemoveExcludedApplication(L"",TRUE)==E_INVALIDARG&&creates==0&&opens==0);
    for(i=0;i<MAX_PATH;++i)limit[i]='x';
    limit[MAX_PATH]=0;
    CHECK(WerAddExcludedApplication(limit,FALSE)==E_INVALIDARG&&creates==0);limit[MAX_PATH-1]=0;
    CHECK(WerAddExcludedApplication(limit,FALSE)==0&&present(0,limit));CHECK(WerRemoveExcludedApplication(limit,FALSE)==0&&!present(0,limit));
    CHECK(WerAddExcludedApplication(L"C:\\app\\test.bin",FALSE)==0&&present(0,L"test.bin")&&!present(1,L"test.bin"));
    CHECK(WerAddExcludedApplication(L"TEST.BIN",TRUE)==0&&present(1,L"test.bin"));
    CHECK(WerAddExcludedApplication(unicode,FALSE)==0&&present(0,unicode));
    CHECK(WerRemoveExcludedApplication(unicode,FALSE)==0&&!present(0,unicode));
    CHECK(WerRemoveExcludedApplication(L"D:\\else\\TEST.BIN",FALSE)==0&&!present(0,L"test.bin")&&present(1,L"test.bin"));
    CHECK(WerRemoveExcludedApplication(L"test.bin",FALSE)==HRESULT_FROM_WIN32(2));
    CHECK(WerRemoveExcludedApplication(L"test.bin",TRUE)==0&&!present(1,L"test.bin"));
    roots[0]=0;before=creates;CHECK(WerRemoveExcludedApplication(L"missing.bin",FALSE)==HRESULT_FROM_WIN32(2)&&creates==before&&!roots[0]);
    injected=1;before=closes;CHECK(WerAddExcludedApplication(L"fail.bin",FALSE)==HRESULT_FROM_WIN32(5)&&closes==before);
    injected=4|16;CHECK(WerAddExcludedApplication(L"fail.bin",FALSE)==HRESULT_FROM_WIN32(13)&&!present(0,L"fail.bin"));
    injected=16;CHECK(WerAddExcludedApplication(L"close.bin",FALSE)==HRESULT_FROM_WIN32(6)&&present(0,L"close.bin"));
    injected=2;before=closes;CHECK(WerRemoveExcludedApplication(L"close.bin",FALSE)==HRESULT_FROM_WIN32(3)&&closes==before);
    injected=8|16;delete_error=5;CHECK(WerRemoveExcludedApplication(L"close.bin",FALSE)==HRESULT_FROM_WIN32(5)&&present(0,L"close.bin"));
    injected=16;CHECK(WerRemoveExcludedApplication(L"close.bin",FALSE)==HRESULT_FROM_WIN32(6)&&!present(0,L"close.bin"));
    injected=0;CHECK(!pthread_create(&t[0],NULL,thread_body,(void *)0)&&!pthread_create(&t[1],NULL,thread_body,(void *)1));
    CHECK(!pthread_join(t[0],&result)&&!(intptr_t)result);CHECK(!pthread_join(t[1],&result)&&!(intptr_t)result);
    CHECK(present(0,L"thread.bin")&&present(1,L"machine.bin"));CHECK(WerRemoveExcludedApplication(L"thread.bin",FALSE)==0&&WerRemoveExcludedApplication(L"machine.bin",TRUE)==0);
    for(i=0;i<16;++i)CHECK(!keys[i].alive);
    printf("WER-EXCLUSIONS-HOST:%u checks PASS; exact bodies, registry adapters, real errors, no VM\n",checks);return 0;
}
