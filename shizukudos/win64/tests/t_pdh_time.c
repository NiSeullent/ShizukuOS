/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
#include <pdh.h>
#include <pdhmsg.h>
#include <winperf.h>
static ULONGLONG bits(FILETIME value) {return ((ULONGLONG)value.dwHighDateTime<<32)|value.dwLowDateTime;}
static void busy(DWORD milliseconds)
{
    LARGE_INTEGER now,start,frequency;QueryPerformanceFrequency(&frequency);QueryPerformanceCounter(&start);
    do { QueryPerformanceCounter(&now); } while((now.QuadPart-start.QuadPart)*1000<frequency.QuadPart*milliseconds);
}
int main(void)
{
    FILETIME idle[2],kernel[2],user[2];PDH_HQUERY query,other;PDH_HCOUNTER cpu,up,missing;
    PDH_FMT_COUNTERVALUE value;PDH_RAW_COUNTER raw[2];PDH_STATUS result;DWORD type;double expected,difference,sleep_rate;
    CHECK(GetSystemTimes(&idle[0],&kernel[0],&user[0]),"actual atomic scheduler CPU-time snapshot succeeds");
    CHECK(bits(kernel[0])>=bits(idle[0]),"kernel CPU time includes actual idle time");
    CHECK(GetSystemTimes(NULL,NULL,NULL),"documented optional CPU-time outputs accepted");
    CHECK(PdhOpenQueryW(NULL,0,&query)==0&&query,"real local PDH query opens");
    CHECK(PdhCollectQueryData(query)==(PDH_STATUS)PDH_NO_DATA,"empty query has no invented data");
    CHECK(PdhAddEnglishCounterW(query,L"\\Processor(_Total)\\% Processor Time",0,&cpu)==0,"real total-CPU counter attaches");
    CHECK(PdhAddEnglishCounterW(query,L"\\System\\System Up Time",0,&up)==0,"actual uptime counter attaches independently");
    result=PdhAddEnglishCounterW(query,L"\\Processor Information(_Total)\\% Processor Utility",0,&missing);
    CHECK(result==(PDH_STATUS)PDH_CSTATUS_NO_COUNTER&&!missing,"unsupported frequency-weighted provider returns no fabricated utility");
    CHECK(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==(PDH_STATUS)PDH_INVALID_DATA,"CPU rate cannot exist before real samples");
    CHECK(PdhCollectQueryData(query)==0,"first real scheduler sample collected");
    CHECK(PdhGetRawCounterValue(cpu,&type,&raw[0])==0&&type==PERF_100NSEC_TIMER_INV,"raw CPU sample exposes real idle/total time");
    CHECK(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==(PDH_STATUS)PDH_INVALID_DATA,"one CPU sample is insufficient for a rate");
    Sleep(250);CHECK(PdhCollectQueryData(query)==0,"second real sample after sleep collected");
    CHECK(PdhGetRawCounterValue(cpu,NULL,&raw[1])==0,"second raw sample collected");
    CHECK(raw[1].SecondValue>raw[0].SecondValue&&raw[1].FirstValue>raw[0].FirstValue,"sleep advances actual total and idle CPU time");
    result=PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,&type,&value);
    CHECK(result==0&&value.CStatus==(PDH_STATUS)PDH_CSTATUS_VALID_DATA&&value.doubleValue>=0&&value.doubleValue<=100,"CPU rate derives from current measured sample interval");
    if(result)return 1;
    sleep_rate=value.doubleValue;
    expected=100.0*(1.0-(double)(raw[1].FirstValue-raw[0].FirstValue)/(double)(raw[1].SecondValue-raw[0].SecondValue));
    difference=value.doubleValue-expected;if(difference<0)difference=-difference;
    CHECK(difference<0.000001,"formatted CPU rate agrees with independent raw-delta calculation");
    CHECK(PdhGetFormattedCounterValue(up,PDH_FMT_DOUBLE,NULL,&value)==0&&value.doubleValue>0,"uptime is actual positive boot clock seconds");
    CHECK(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE|PDH_FMT_LONG,NULL,&value)==(PDH_STATUS)PDH_INVALID_ARGUMENT,"ambiguous numeric format fails");
    busy(250);CHECK(PdhCollectQueryData(query)==0,"sample actual busy user execution");
    CHECK(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==0&&value.doubleValue>sleep_rate+20,"real CPU rate responds to busy execution instead of a fixed value");
    CHECK(GetSystemTimes(&idle[1],&kernel[1],&user[1])&&bits(user[1])>bits(user[0])&&bits(kernel[1])>=bits(kernel[0]),"user/kernel execution counters advance from real execution");
    CHECK(PdhRemoveCounter(cpu)==0,"remove actual owned counter");
    CHECK(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==(PDH_STATUS)PDH_INVALID_HANDLE,"removed counter token cannot access freed memory");
    CHECK(PdhCloseQuery(query)==0,"close query and its remaining owned counter");
    CHECK(PdhCollectQueryData(query)==(PDH_STATUS)PDH_INVALID_HANDLE&&PdhRemoveCounter(up)==(PDH_STATUS)PDH_INVALID_HANDLE,"closed query and child tokens stay invalid");
    CHECK(PdhOpenQueryW(NULL,0,&other)==0&&other!=query,"new query cannot reuse stale generation token");
    CHECK(PdhCloseQuery(other)==0,"close replacement query");
    return k32t_finish("T_PDH_TIME");
}
