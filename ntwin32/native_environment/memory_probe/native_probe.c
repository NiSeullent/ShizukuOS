/* SPDX-License-Identifier: GPL-2.0-only -- own original-Win98 measurement. */
#include "native_common.h"
#include "../../process_exit/original_kernel.h"
#include <stddef.h>
_Static_assert(sizeof(void *)==4&&sizeof(MEMORYSTATUS)==32,"PE32 memory ABI");
_Static_assert(offsetof(MEMORYSTATUS,dwLength)==0&&offsetof(MEMORYSTATUS,dwMemoryLoad)==4&&offsetof(MEMORYSTATUS,dwTotalPhys)==8&&offsetof(MEMORYSTATUS,dwAvailPhys)==12&&offsetof(MEMORYSTATUS,dwTotalPageFile)==16&&offsetof(MEMORYSTATUS,dwAvailPageFile)==20&&offsetof(MEMORYSTATUS,dwTotalVirtual)==24&&offsetof(MEMORYSTATUS,dwAvailVirtual)==28,"native DWORD field offsets");
typedef VOID (WINAPI *memory_fn)(LPMEMORYSTATUS);
typedef VOID (WINAPI *time_fn)(LPSYSTEMTIME);
typedef DWORD (WINAPI *tick_fn)(void);
typedef struct capture {DWORD guard_before;MEMORYSTATUS memory;DWORD guard_after;SYSTEMTIME before,after;DWORD tick_before,tick_after,error;} capture;
static capture samples[3];static mp_report report;
/* Exported own wrapper makes the actual indirect stdcall ABI inspectable. */
void WINAPI mp_memory_call(memory_fn query,LPMEMORYSTATUS memory){query(memory);}
static void utc(const SYSTEMTIME *t)
{mp_value(&report,"UTC_YEAR",t->wYear);mp_value(&report,"UTC_MONTH",t->wMonth);mp_value(&report,"UTC_DAY",t->wDay);
 mp_value(&report,"UTC_HOUR",t->wHour);mp_value(&report,"UTC_MINUTE",t->wMinute);mp_value(&report,"UTC_SECOND",t->wSecond);mp_value(&report,"UTC_MILLISECOND",t->wMilliseconds);}
void WINAPI entry(void)
{
 memory_fn query;time_fn time;tick_fn tick;mp_api_identity memory_id,time_id,tick_id;
 DWORD code=3,i,j,flags,last,sentinel=0x51a2b3c4u;int guards=1;
 if(!mp_report_open(&report,"C:\\VXDLAB\\MEMSTAT.LOG"))ExitProcess(21);
 mp_value(&report,"OWN_MEMORY_PROBE_ENTRY",1);mp_value(&report,"APPLICATION_SUCCESS",0);
 if(!px_original_win98()){mp_value(&report,"ACTUAL_ORIGINAL_WIN98_GUARD",0);goto done;}mp_value(&report,"ACTUAL_ORIGINAL_WIN98_GUARD",1);
 SetLastError(sentinel);query=(memory_fn)(void *)mp_original("GlobalMemoryStatus",&memory_id);last=GetLastError();
 mp_value(&report,"MEMORY_RESOLVER_LAST_ERROR",last);if(!query||last!=sentinel)goto done;mp_value(&report,"API_ID_GLOBALMEMORYSTATUS",1);mp_identity(&report,&memory_id);
 SetLastError(sentinel);time=(time_fn)(void *)mp_original("GetSystemTime",&time_id);last=GetLastError();
 mp_value(&report,"TIME_RESOLVER_LAST_ERROR",last);if(!time||last!=sentinel)goto done;mp_value(&report,"API_ID_GETSYSTEMTIME",1);mp_identity(&report,&time_id);
 SetLastError(sentinel);tick=(tick_fn)(void *)mp_original("GetTickCount",&tick_id);last=GetLastError();
 mp_value(&report,"TICK_RESOLVER_LAST_ERROR",last);if(!tick||last!=sentinel||report.failed)goto done;mp_value(&report,"API_ID_GETTICKCOUNT",1);mp_identity(&report,&tick_id);
 /* No logging, delays or allocations between these three measurements. The
  * status API is VOID: its LastError is an observation, never a success code. */
 for(i=0;i<3;i++){capture *s=&samples[i];s->guard_before=0x736d656du;s->guard_after=0x98765432u;
  for(j=0;j<sizeof(s->memory);j++)((BYTE *)&s->memory)[j]=0xff;s->memory.dwLength=sizeof(s->memory);
  time(&s->before);s->tick_before=tick();SetLastError(sentinel);mp_memory_call(query,&s->memory);s->error=GetLastError();s->tick_after=tick();time(&s->after);
 }
 code=0;
 for(i=0;i<3;i++){capture *s=&samples[i];mp_status m;
  for(j=0;j<sizeof(m);j++)((BYTE *)&m)[j]=((const BYTE *)&s->memory)[j];flags=mp_flags(&m);
  mp_value(&report,"SNAPSHOT_INDEX",i);mp_value(&report,"TIMESTAMP_BEFORE",1);utc(&s->before);mp_value(&report,"TIMESTAMP_AFTER",1);utc(&s->after);
  mp_value(&report,"TICK_BEFORE",s->tick_before);mp_value(&report,"TICK_AFTER",s->tick_after);mp_value(&report,"TICK_DELTA_MOD32",mp_tick_delta(s->tick_before,s->tick_after));
  mp_value(&report,"RAW_LENGTH",m.length);mp_value(&report,"RAW_MEMORY_LOAD_PERCENT",m.load);mp_value(&report,"RAW_TOTAL_PHYS_BYTES",m.total_phys);mp_value(&report,"RAW_AVAIL_PHYS_BYTES",m.avail_phys);
  mp_value(&report,"RAW_TOTAL_PAGEFILE_BYTES",m.total_page);mp_value(&report,"RAW_AVAIL_PAGEFILE_BYTES",m.avail_page);mp_value(&report,"RAW_TOTAL_VIRTUAL_BYTES",m.total_virtual);mp_value(&report,"RAW_AVAIL_VIRTUAL_BYTES",m.avail_virtual);
  mp_value(&report,"VOID_API_LAST_ERROR_OBSERVATION",s->error);mp_value(&report,"SNAPSHOT_FLAGS",flags);
  if(s->guard_before!=0x736d656du||s->guard_after!=0x98765432u)guards=0;
  if(flags&31u)code=3;
 }
 if(!guards)code=3;mp_value(&report,"STATUS_BUFFER_CANARIES",guards);mp_value(&report,"IMMEDIATE_SNAPSHOTS_CAPTURED",3);
done:
 if(report.failed)code=31;mp_value(&report,"PROBE_SELECTED_RESULT",code);mp_value(&report,"PROBE_OWN_OS_EXIT_REQUIRES_OUTER",1);
 if(!mp_report_close(&report))code=31;ExitProcess(code);
}
