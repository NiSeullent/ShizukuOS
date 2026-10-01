/* SPDX-License-Identifier: GPL-2.0-only
 * Concurrent publication must never admit aliased private host tables.
 * Actual C metadata/ordering only; no VMX or AP execution is claimed.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/vmx_cpu_state.h"
#define ROUNDS 20000u
static vmx_cpu_topology_t t;
static pthread_barrier_t start,done;
static int admitted[2];
static void *publish(void *p)
{
 unsigned cpu=(unsigned)(uintptr_t)p;
 for(unsigned i=0;i<ROUNDS;++i) {
  pthread_barrier_wait(&start);
  admitted[cpu]=vmx_cpu_publish_tables(&t,cpu,0x1000,0x2000,0x3000)==0;
  pthread_barrier_wait(&done);
 }
 return NULL;
}
int main(void)
{
 const uint32_t ids[2]={11,97};pthread_t threads[2];unsigned bad=0;
 pthread_barrier_init(&start,NULL,3);pthread_barrier_init(&done,NULL,3);
 for(unsigned i=0;i<2;++i) if(pthread_create(&threads[i],NULL,publish,(void*)(uintptr_t)i))return 2;
 for(unsigned i=0;i<ROUNDS;++i) {
  memset(&t,0,sizeof t);
  if(vmx_cpu_topology_init(&t,ids,2,11)||vmx_cpu_begin(&t,0)||vmx_cpu_begin(&t,1))return 3;
  pthread_barrier_wait(&start);pthread_barrier_wait(&done);
  bad+=admitted[0]&&admitted[1];
 }
 for(unsigned i=0;i<2;++i)pthread_join(threads[i],NULL);
 printf("Host table publication: %u rounds, aliased double admissions=%u\n",ROUNDS,bad);
 return bad?1:0;
}
