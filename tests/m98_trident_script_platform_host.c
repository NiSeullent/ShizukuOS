/* SPDX-License-Identifier: GPL-2.0-only
 * Host original-CRT/legacy-format doubles. Actual Win98 APIs remain pending. */
#include <math.h>
#include <stdio.h>
#include <string.h>
#include "m98_trident_script_port.h"
int m98_script_legacy_vsnprintf(char *p,size_t n,const char *f,va_list a){
    char adjusted[1024];size_t i=0,k=0;
    while(f[i]){if(f[i]=='I'&&f[i+1]=='6'&&f[i+2]=='4'){adjusted[k++]='l';adjusted[k++]='l';i+=3;}else adjusted[k++]=f[i++];}
    adjusted[k]=0;int r=vsnprintf(p,n,adjusted,a);return r<0||(size_t)r>=n?-1:r;
}
#define ONE(name) double m98_math_##name(double x){return name(x);}
ONE(sin) ONE(cos) ONE(tan) ONE(acos) ONE(asin) ONE(atan) ONE(exp) ONE(log)
ONE(log10) ONE(sqrt) ONE(floor) ONE(ceil) ONE(fabs) ONE(sinh) ONE(cosh) ONE(tanh)
#undef ONE
double m98_math_atan2(double x,double y){return atan2(x,y);}
double m98_math_fmod(double x,double y){return fmod(x,y);}
double m98_math_frexp(double x,int *n){return frexp(x,n);}
double m98_math_ldexp(double x,int n){return ldexp(x,n);}
long double m98_math_sqrtl(long double x){return sqrtl(x);}
