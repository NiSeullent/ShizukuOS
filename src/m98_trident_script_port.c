/* SPDX-License-Identifier: GPL-2.0-only
 * C99 length/truncation adapter over the original CRT's bounded _vsnprintf.
 * Workspace is charged to the active interpreter's configured memory limit.
 * No unbounded _vsprintf, guessed required length or global locale mutation. */
#include "m98_trident_script_port.h"
#include <string.h>
#include <stdint.h>
#include <float.h>
#include <math.h>
_Static_assert(sizeof(double)==8&&DBL_MANT_DIG==53&&sizeof(float)==4&&FLT_MANT_DIG==24,"IEEE numeric classifier profile");
/* No prebuilt MinGW classifier helpers: inspect actual IEEE encodings without
 * comparison/overflow or changing NaN, signed-zero and subnormal semantics.
 * Internal classes: NaN0, infinity1, zero2, subnormal3, normal4. */
int m98_qjs_classify(double x){uint64_t bits;memcpy(&bits,&x,8);bits&=UINT64_C(0x7fffffffffffffff);
    if(bits>=UINT64_C(0x7ff0000000000000))return bits==UINT64_C(0x7ff0000000000000)?1:0;
    if(bits<UINT64_C(0x0010000000000000))return bits?3:2;
    return 4;
}
int m98_qjs_isnan(double x){return m98_qjs_classify(x)==0;}
int m98_qjs_isnanf(float x){uint32_t bits;memcpy(&bits,&x,4);return (bits&UINT32_C(0x7fffffff))>UINT32_C(0x7f800000);}
int m98_qjs_signbit(double x){uint64_t bits;memcpy(&bits,&x,8);return (int)(bits>>63);}
#ifdef _WIN32
int __isnan(double x){return m98_qjs_isnan(x);}
int __isnanf(float x){return m98_qjs_isnanf(x);}
int __signbit(double x){return m98_qjs_signbit(x);}
int __fpclassify(double x){switch(m98_qjs_classify(x)){
    case 0:return FP_NAN;case 1:return FP_INFINITE;case 2:return FP_ZERO;case 3:return FP_SUBNORMAL;default:return FP_NORMAL;}}
#endif
#define FORMAT_BOUND 1024u
#define WORK_BOUND (1u<<20)
static int append(char *out,size_t *n,char c){if(*n>=FORMAT_BOUND-1)return 0;out[(*n)++]=c;return 1;}
static int translate(const char *format,char out[FORMAT_BOUND]){
    size_t i=0,n=0;if(!format)return 0;
    while(format[i]){
        if(i>=FORMAT_BOUND-1||!append(out,&n,format[i]))return 0;
        if(format[i++]!='%')continue;
        if(format[i]=='%'){if(!append(out,&n,format[i++]))return 0;continue;}
        while(format[i]&&strchr("-+ #0",format[i]))if(!append(out,&n,format[i++]))return 0;
        if(format[i]=='*'){if(!append(out,&n,format[i++]))return 0;}
        else while(format[i]>='0'&&format[i]<='9')if(!append(out,&n,format[i++]))return 0;
        if(format[i]=='.'){
            if(!append(out,&n,format[i++]))return 0;
            if(format[i]=='*'){if(!append(out,&n,format[i++]))return 0;}
            else while(format[i]>='0'&&format[i]<='9')if(!append(out,&n,format[i++]))return 0;
        }
        char length=0;
        if(format[i]=='I'&&format[i+1]=='6'&&format[i+2]=='4'){i+=3;length='q';}
        else if(format[i]=='l'&&format[i+1]=='l'){i+=2;length='q';}
        else if(format[i]=='j'){++i;length='q';}
        else if(format[i]=='z'||format[i]=='t'){++i;length='l';}
        else if(format[i]=='l'){++i;length='l';}
        else if(format[i]=='h'){++i;length='h';if(format[i]=='h')return 0;}
        /* Wide strings/chars, %n, long-double and hex-float conversions are
         * outside the audited QuickJS production callers. Reject explicitly. */
        char conversion=format[i++];
        if(!conversion||!strchr("diuoxXcsfFeEgG",conversion))return 0;
        if(length&&(conversion=='s'||conversion=='c'||strchr("fFeEgG",conversion)))return 0;
        if(length=='q'){if(!append(out,&n,'I')||!append(out,&n,'6')||!append(out,&n,'4'))return 0;}
        else if(length&&!append(out,&n,length))return 0;
        if(!append(out,&n,conversion))return 0;
    }
    out[n]=0;return 1;
}
int m98_qjs_vsnprintf(char *dst,size_t count,const char *format,va_list arguments){
    char adjusted[FORMAT_BOUND],small[128],*work=small;size_t capacity=sizeof(small);int result=-1;
    if((!dst&&count)||!translate(format,adjusted)){if(dst&&count)dst[0]=0;return -1;}
    if(dst&&count)dst[0]=0;
    for(;;){
        va_list copy;va_copy(copy,arguments);
        result=m98_script_legacy_vsnprintf(work,capacity,adjusted,copy);va_end(copy);
        if(result>=0&&(size_t)result<capacity){
            if(count){size_t copied=(size_t)result<count-1?(size_t)result:count-1;memcpy(dst,work,copied);dst[copied]=0;}
            break;
        }
        if(work!=small)m98_script_scratch_free(work);
        work=small;
        if(capacity>=WORK_BOUND){result=-1;break;}
        capacity*=2;work=m98_script_scratch_alloc(capacity);
        if(!work){result=-1;break;}
    }
    if(work!=small)m98_script_scratch_free(work);
    return result;
}
int m98_qjs_snprintf(char *dst,size_t count,const char *format,...){
    va_list arguments;int result;va_start(arguments,format);
    result=m98_qjs_vsnprintf(dst,count,format,arguments);va_end(arguments);return result;
}
