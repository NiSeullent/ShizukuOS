/* SPDX-License-Identifier: GPL-2.0-only
 * Same-source host rendering of a captured, bounded native state. This is only
 * a transport/completed-publication reference; independently selected gameplay
 * controls and real guest pixels are required for native acceptance.
 */
#include "dead_screen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static ds_state state;
static uint32_t pixels[4096u*4096u];
static int serial_writer(void *unused,const char *bytes,size_t n)
{(void)unused;return fwrite(bytes,1,n,stdout)==n?0:-1;}
int main(int argc,char **argv)
{
    unsigned w,h;
    if(argc!=5 || sscanf(argv[2],"%u",&w)!=1 || sscanf(argv[3],"%u",&h)!=1 ||
       w<640 || h<480 || w>4096 || h>4096 || (strcmp(argv[4],"graphics") && strcmp(argv[4],"text") && strcmp(argv[4],"serial")))return 2;
    FILE *f=fopen(argv[1],"rb");if(!f)return 3;
    const size_t n=fread(&state,1,sizeof state,f);const int extra=fgetc(f);const int bad=ferror(f);const int closed=fclose(f);
    if(n!=sizeof state || extra!=EOF || bad || closed || !state.latched)return 4;
    if(!strcmp(argv[4],"serial"))return ds_fallback(&state,serial_writer,0) || fflush(stdout)?8:0;
    ds_surface surface={pixels,w,h,w,(size_t)w*h,1};
    const int rc=!strcmp(argv[4],"text")?ds_fallback_framebuffer(&state,&surface):ds_render(&state,&surface);
    if(rc || fprintf(stdout,"P6\n%u %u\n255\n",w,h)<0)return 5;
    for(size_t i=0;i<(size_t)w*h;++i) {
        const uint32_t p=pixels[i];const unsigned char rgb[3]={(unsigned char)p,(unsigned char)(p>>8),(unsigned char)(p>>16)};
        if(fwrite(rgb,1,3,stdout)!=3)return 6;
    }
    return fflush(stdout)?7:0;
}
