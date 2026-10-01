/* SPDX-License-Identifier: GPL-2.0-only
 * C99 contract checks against a truncating legacy CRT double. */
#include "m98_trident_script_port.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <float.h>
#include <math.h>
extern int m98_qjs_classify(double),m98_qjs_isnan(double),m98_qjs_signbit(double);
extern int m98_qjs_isnanf(float);
static unsigned checks,allocated,freed;static int deny;
#define C(x) do{++checks;if(!(x)){fprintf(stderr,"format FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
void *m98_script_scratch_alloc(size_t n){if(deny)return NULL;void *p=malloc(n);if(p)++allocated;return p;}
void m98_script_scratch_free(void *p){if(p){++freed;free(p);}}
int main(void){char b[32],large[600];memset(large,'x',sizeof(large)-1);large[599]=0;
    C(m98_qjs_snprintf(NULL,0,"%s:%d","hello",12)==8);
    C(m98_qjs_snprintf(b,1,"%s","hello")==5&&!b[0]);
    C(m98_qjs_snprintf(b,6,"%s","hello")==5&&!strcmp(b,"hello"));
    C(m98_qjs_snprintf(b,5,"%s","hello")==5&&!strcmp(b,"hell"));
    C(m98_qjs_snprintf(b,sizeof(b),"%lld",INT64_MIN)==20&&!strcmp(b,"-9223372036854775808"));
    C(m98_qjs_snprintf(b,sizeof(b),"%llu",UINT64_MAX)==20&&!strcmp(b,"18446744073709551615"));
    C(m98_qjs_snprintf(b,sizeof(b),"%zu/%td",(size_t)123,(ptrdiff_t)-7)==6&&!strcmp(b,"123/-7"));
    C(m98_qjs_snprintf(b,sizeof(b),"%.*s/%04x/%%",3,"abcdef",17)==10&&!strcmp(b,"abc/0011/%"));
    C(m98_qjs_snprintf(b,sizeof(b),"%+08d",-15)==8&&!strcmp(b,"-0000015"));
    C(m98_qjs_snprintf(b,sizeof(b),"%.2f",1.25)==4&&!strcmp(b,"1.25"));
    C(m98_qjs_snprintf(b,sizeof(b),"%s",large)==599&&strlen(b)==31);
    C(m98_qjs_snprintf(NULL,0,"%s",large)==599);
    deny=1;C(m98_qjs_snprintf(b,sizeof(b),"%s",large)==-1&&!b[0]);deny=0;
    C(m98_qjs_snprintf(b,sizeof(b),"%n",(int *)NULL)==-1&&!b[0]);
    C(m98_qjs_snprintf(b,sizeof(b),"%ls",(void *)NULL)==-1);
    C(m98_qjs_snprintf(NULL,1,"x")==-1);C(allocated==freed);
    C(m98_qjs_classify(0)==2&&m98_qjs_classify(-0.)==2);
    C(!m98_qjs_signbit(0)&&m98_qjs_signbit(-0.));
    C(m98_qjs_classify(INFINITY)==1&&m98_qjs_classify(-INFINITY)==1);
    C(m98_qjs_signbit(-INFINITY)&&!m98_qjs_signbit(INFINITY));
    C(m98_qjs_classify(DBL_MIN)==4&&m98_qjs_classify(DBL_MAX)==4);
    C(m98_qjs_classify(0x1p-1074)==3&&m98_qjs_classify(-0x1p-1074)==3);
    C(m98_qjs_isnan(NAN)&&!m98_qjs_isnan(INFINITY)&&!m98_qjs_isnan(-0.));
    C(m98_qjs_isnanf(NAN)&&!m98_qjs_isnanf(INFINITY)&&!m98_qjs_isnanf(FLT_MIN));
    union {uint64_t bits;double value;} signaling={UINT64_C(0xfff0000000000001)};
    union {uint32_t bits;float value;} float_signaling={UINT32_C(0xff800001)};
    C(m98_qjs_isnan(signaling.value)&&m98_qjs_signbit(signaling.value));
    C(m98_qjs_isnanf(float_signaling.value));
    double (*volatile actual_round)(double)=round;volatile double round_input;
    round_input=0.5;C(actual_round(round_input)==1);round_input=-0.5;C(actual_round(round_input)==-1);
    round_input=-0.1;C(actual_round(round_input)==0&&m98_qjs_signbit(actual_round(round_input)));
    round_input=INFINITY;C(actual_round(round_input)==INFINITY);round_input=NAN;C(m98_qjs_isnan(actual_round(round_input)));
    printf("PASS: bounded C99 formatting and IEEE/math helpers %u assertions; legacy CRT double, native pending\n",checks);return 0;
}
