/* SPDX-License-Identifier: GPL-2.0-only
 * Negative controls for the actual GCC instrumentation / available Clang
 * sanitizer-runtime link; a clean test run alone cannot prove it is active. */
#include <limits.h>
#include <stdlib.h>
int main(int argc,char **argv){
    if(argc!=2)return 2;
    if(argv[1][0]=='a'){volatile unsigned char *p=malloc(4);if(!p)return 2;p[4]=7;free((void *)p);return 0;}
    if(argv[1][0]=='u'){volatile int n=INT_MAX;return n+1;}
    return 2;
}
