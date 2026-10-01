/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <pthread.h>
#include "pdh_host_contract.h"
#define SHZ_PDH_HOST_TEST 1
#include "../dlls/pdh/pdh_time.c"
static unsigned checks;
#define VERIFY(x) do {++checks;if(!(x)){fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x);exit(1);}}while(0)
static void *worker(void *unused)
{
    unsigned i;(void)unused;
    for(i=0;i<2000;++i){PDH_HQUERY q;PDH_HCOUNTER c;PDH_FMT_COUNTERVALUE v;
        if(PdhOpenQueryW(NULL,0,&q)||PdhAddEnglishCounterW(q,L"\\System\\System Up Time",0,&c)||
           PdhCollectQueryData(q)||PdhGetFormattedCounterValue(c,PDH_FMT_DOUBLE,NULL,&v)||v.doubleValue!=5.0||
           PdhRemoveCounter(c)||PdhCloseQuery(q))abort();}
    return NULL;
}
int main(void)
{
    PDH_HQUERY q,other;PDH_HCOUNTER cpu,up,invalid;PDH_FMT_COUNTERVALUE value;PDH_RAW_COUNTER raw;DWORD type;unsigned i;pthread_t threads[8];
    VERIFY(PdhOpenQueryW(NULL,0,NULL)==PDH_INVALID_ARGUMENT);
    VERIFY(PdhOpenQueryW(L"counter.log",0,&q)==PDH_NOT_IMPLEMENTED&&!q);
    VERIFY(PdhOpenQueryW(NULL,0,&q)==0&&q);
    VERIFY(PdhCollectQueryData(q)==PDH_NO_DATA);
    VERIFY(PdhAddEnglishCounterW(q,L"\\Processor(_Total)\\% Processor Time",0,&cpu)==0);
    VERIFY(PdhAddEnglishCounterW(q,L"\\System\\System Up Time",0,&up)==0);
    VERIFY(PdhAddEnglishCounterW(q,L"\\Processor Information(_Total)\\% Processor Utility",0,&invalid)==PDH_CSTATUS_NO_COUNTER&&!invalid);
    VERIFY(PdhAddEnglishCounterW(q,L"\\\\remote\\System\\System Up Time",0,&invalid)==PDH_CSTATUS_NO_MACHINE);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==PDH_INVALID_DATA&&value.CStatus==PDH_CSTATUS_INVALID_DATA);
    snapshot_idle=100;snapshot_kernel=200;snapshot_user=100;snapshot_uptime=1000;
    VERIFY(PdhCollectQueryData(q)==0);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==PDH_INVALID_DATA);
    VERIFY(PdhGetFormattedCounterValue(up,PDH_FMT_DOUBLE,NULL,&value)==0&&value.doubleValue==1.0&&value.CStatus==PDH_CSTATUS_NEW_DATA);
    VERIFY(PdhGetFormattedCounterValue(up,PDH_FMT_DOUBLE,NULL,&value)==0&&value.CStatus==PDH_CSTATUS_VALID_DATA);
    snapshot_idle=160;snapshot_kernel=280;snapshot_user=120;snapshot_uptime=2000;
    VERIFY(PdhCollectQueryData(q)==0);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,&type,&value)==0&&value.doubleValue==40.0&&type==PERF_100NSEC_TIMER_INV);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_LONG,NULL,&value)==0&&value.longValue==40&&value.CStatus==PDH_CSTATUS_VALID_DATA);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_LARGE|PDH_FMT_1000,NULL,&value)==0&&value.largeValue==40000);
    VERIFY(PdhGetRawCounterValue(cpu,&type,&raw)==0&&raw.FirstValue==160&&raw.SecondValue==400&&raw.MultiCount==1);
    VERIFY(PdhGetRawCounterValue(up,NULL,&raw)==PDH_NOT_IMPLEMENTED);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE|PDH_FMT_LONG,NULL,&value)==PDH_INVALID_ARGUMENT);
    snapshot_failure=1;VERIFY(PdhCollectQueryData(q)==PDH_INVALID_DATA);snapshot_failure=0;
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==0&&value.doubleValue==40);
    VERIFY(PdhCollectQueryData(q)==0);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==PDH_INVALID_DATA);
    snapshot_idle=1000;snapshot_kernel=300;snapshot_user=200;VERIFY(PdhCollectQueryData(q)==0);
    VERIFY(PdhGetFormattedCounterValue(cpu,PDH_FMT_DOUBLE,NULL,&value)==PDH_INVALID_DATA);
    VERIFY(PdhRemoveCounter(cpu)==0&&PdhRemoveCounter(cpu)==PDH_INVALID_HANDLE);
    VERIFY(PdhCloseQuery(q)==0&&PdhCollectQueryData(q)==PDH_INVALID_HANDLE);
    VERIFY(PdhGetFormattedCounterValue(up,PDH_FMT_DOUBLE,NULL,&value)==PDH_INVALID_HANDLE);
    VERIFY(PdhOpenQueryW(NULL,0,&other)==0&&other!=q);VERIFY(PdhCloseQuery(other)==0);
    snapshot_idle=100;snapshot_kernel=200;snapshot_user=100;snapshot_uptime=5000;
    for(i=0;i<8;++i)VERIFY(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for(i=0;i<8;++i)VERIFY(pthread_join(threads[i],NULL)==0);
    VERIFY(queries==NULL);
    printf("PDH-HOST: %u assertions; 16000 concurrent complete query/counter lifecycles passed\n",checks);return 0;
}
