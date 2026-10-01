/* SPDX-License-Identifier: GPL-2.0-only: real DLL detach, references and VAD retirement. */
#include "k32test.h"
#include "nt.h"
#include "loader_fixture.h"
typedef ULONG (WINAPI *value_fn)(void);
typedef void (WINAPI *configure_fn)(loader_fixture_trace *);
typedef NTSTATUS (NTAPI *addref_fn)(ULONG, PVOID);
typedef struct { ULONG Flags; const SHZ_UNICODE_STRING *FullDllName, *BaseDllName; PVOID DllBase; ULONG SizeOfImage; } notify_data;
typedef void (NTAPI *notify_fn)(ULONG, const notify_data *, PVOID);
typedef NTSTATUS (NTAPI *register_fn)(ULONG, notify_fn, PVOID, PVOID *);
typedef NTSTATUS (NTAPI *unregister_fn)(PVOID);
typedef struct { PVOID BaseAddress; SIZE_T SizeOfImage; ULONG Sequence, TimeDateStamp, CheckSum; WCHAR ImageName[32]; ULONG Version[2]; } unload_record;
typedef PVOID (NTAPI *trace_fn)(void);
static addref_fn addref;
static unregister_fn unregister_notify;
static HMODULE selected_a, selected_b;
static ULONG notifications, mapped_notifications, revival_success, once_notifications;
static PVOID once_cookie;
static void NTAPI observe(ULONG reason, const notify_data *data, PVOID context)
{
    MEMORY_BASIC_INFORMATION mbi;
    (void)context;
    if (reason != 2 || (data->DllBase != selected_a && data->DllBase != selected_b)) return;
    ++notifications;
    if (VirtualQuery(data->DllBase,&mbi,sizeof mbi)==sizeof mbi && mbi.State==MEM_COMMIT) ++mapped_notifications;
    if (addref(0,data->DllBase)==0) ++revival_success;
}
static void NTAPI once(ULONG reason, const notify_data *data, PVOID context)
{
    (void)data; (void)context;
    if (reason==2) { ++once_notifications; unregister_notify(once_cookie); }
}
static BOOL mapped(HMODULE module, DWORD state)
{
    MEMORY_BASIC_INFORMATION mbi;
    return VirtualQuery(module,&mbi,sizeof mbi)==sizeof mbi && mbi.State==state;
}
static BOOL absent_from_three_lists(HMODULE module)
{
    SHZ_PEB_LDR_DATA *ldr=PEB_LDR(shz_peb());
    LIST_ENTRY *heads[3]={&ldr->InLoadOrderModuleList,&ldr->InMemoryOrderModuleList,&ldr->InInitializationOrderModuleList};
    unsigned i;
    for(i=0;i<3;++i){LIST_ENTRY *l;unsigned count=0;for(l=heads[i]->Flink;l!=heads[i];l=l->Flink){
        SHZ_LDR_ENTRY *e=(SHZ_LDR_ENTRY *)((BYTE *)l-i*sizeof(LIST_ENTRY));
        if(++count>SHZ_LDR_RETIRE_MAX || e->DllBase==module)return FALSE;
    }}
    return TRUE;
}
int main(void)
{
    HMODULE a,a2,b,ntdll=GetModuleHandleW(L"ntdll.dll");
    loader_fixture_trace state={0};
    configure_fn configure;
    value_fn attached,init_free,dependency;
    register_fn register_notify;
    trace_fn get_trace;
    PVOID observer_cookie=0;
    ULONG i,saw_a=0,saw_b=0;
    addref=(addref_fn)GetProcAddress(ntdll,"LdrAddRefDll");
    register_notify=(register_fn)GetProcAddress(ntdll,"LdrRegisterDllNotification");
    unregister_notify=(unregister_fn)GetProcAddress(ntdll,"LdrUnregisterDllNotification");
    get_trace=(trace_fn)GetProcAddress(ntdll,"RtlGetUnloadEventTrace");
    CHECK(addref&&register_notify&&unregister_notify&&get_trace,"actual loader lifecycle exports resolve");
    if(!addref||!register_notify||!unregister_notify||!get_trace)return 1;
    CHECK(register_notify(0,observe,0,&observer_cookie)==0&&register_notify(0,once,0,&once_cookie)==0,"register real observer and self-unregistering callback");
    a=LoadLibraryW(L"loader_fixture_a.dll"); b=GetModuleHandleW(L"loader_fixture_b.dll");
    CHECK(a&&b,"actual importer and eager dependency map");
    if(!a||!b)return 1;
    selected_a=a;selected_b=b;
    configure=(configure_fn)GetProcAddress(a,"LoaderAConfigure");attached=(value_fn)GetProcAddress(a,"LoaderAAttached");
    init_free=(value_fn)GetProcAddress(a,"LoaderAInitFree");dependency=(value_fn)GetProcAddress(a,"LoaderADependency");
    CHECK(configure&&attached&&init_free&&dependency,"actual fixture exports resolve");
    if(!configure||!attached||!init_free||!dependency)return 1;
    CHECK(attached()==1&&init_free()==0&&dependency()==78,"attach runs once, active-callback release rejects, dependency is callable");
    configure(&state);
    a2=LoadLibraryW(L"loader_fixture_a.dll");
    CHECK(a2==a&&attached()==1,"second explicit reference reuses mapping without duplicate attach");
    CHECK(FreeLibrary(a)&&mapped(a,MEM_COMMIT)&&state.count==0&&notifications==0,"one release retains remaining explicit reference");
    CHECK(FreeLibrary(a2),"final explicit release commits real retirement");
    CHECK(state.count==2&&state.order[0]==1&&state.order[1]==2,"real detach callbacks run importer before dependency");
    CHECK(state.reserved_nonnull==0&&state.dependency_value==77&&state.recursive_free_succeeded==0,"dynamic detach gets NULL reserved, mapped dependency and rejects duplicate recursive release");
    CHECK(notifications==2&&mapped_notifications==2&&revival_success==0&&once_notifications==1,"unload notifications precede unmapping, block revival and safely self-unregister");
    CHECK(!GetModuleHandleW(L"loader_fixture_a.dll")&&!GetModuleHandleW(L"loader_fixture_b.dll"),"actual published module lookup no longer finds retired images");
    CHECK(absent_from_three_lists(a)&&absent_from_three_lists(b),"both actual entries removed from all three PEB lists");
    CHECK(mapped(a,MEM_FREE)&&mapped(b,MEM_FREE),"actual image reservations are released, not only hidden from lookup");
    for(i=0;i<64;++i){unload_record *r=(unload_record *)get_trace()+i;if(r->BaseAddress==a&&r->Sequence)++saw_a;if(r->BaseAddress==b&&r->Sequence)++saw_b;}
    CHECK(saw_a&&saw_b,"actual completed retirements populate unload trace");
    CHECK(!FreeLibrary(a)&&addref(0,a)!=0,"stale reference cannot unload or revive retired image");
    CHECK(unregister_notify(observer_cookie)==0&&unregister_notify(once_cookie)!=0,"remaining observer unregisters and removed cookie stays invalid");

    memset(&state,0,sizeof state);
    a=LoadLibraryW(L"loader_fixture_a.dll"); b=LoadLibraryW(L"loader_fixture_b.dll");
    CHECK(a&&b,"fresh mappings can be loaded after retirement"); if(!a||!b)return 1;
    attached=(value_fn)GetProcAddress(a,"LoaderAAttached");configure=(configure_fn)GetProcAddress(a,"LoaderAConfigure");
    CHECK(attached&&attached()==1&&configure,"fresh image state gets a new attach");if(!configure||!attached)return 1;configure(&state);
    CHECK(FreeLibrary(a)&&state.count==1&&state.order[0]==1&&mapped(a,MEM_FREE)&&mapped(b,MEM_COMMIT),"independently referenced dependency survives importer retirement");
    dependency=(value_fn)GetProcAddress(b,"LoaderBValue");CHECK(dependency&&dependency()==77,"surviving dependency remains genuinely callable");
    CHECK(FreeLibrary(b)&&state.count==2&&state.order[1]==2&&mapped(b,MEM_FREE),"dependency's own final release detaches and releases its reservation");

    b=LoadLibraryW(L"loader_fixture_b.dll");CHECK(b!=0,"load module for real pin contract");if(!b)return 1;
    CHECK(addref(2,b)!=0&&addref(1,b)==0,"invalid flags reject and real pin succeeds");
    CHECK(FreeLibrary(b)&&mapped(b,MEM_COMMIT)&&GetModuleHandleW(L"loader_fixture_b.dll")==b,"pin preserves the actual process-lifetime mapping");
    return k32t_finish("T_LDR_UNLOAD");
}
