/* SPDX-License-Identifier: GPL-2.0-only */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel32/k32_office_binary.h"
static unsigned checks;
#define VERIFY(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL: line %d: %s\n",__LINE__,#c);abort(); } } while(0)
struct memory { unsigned char bytes[1024]; size_t length; unsigned error; };
static unsigned memory_read(void *arg, uint64_t off, void *out, size_t n)
{
    struct memory *m = arg;
    VERIFY(off <= m->length && n <= m->length - off);
    if (m->error) return m->error;
    memcpy(out, m->bytes + (size_t)off, n); return 0;
}
static void put16(unsigned char *p, unsigned v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); }
static void put32(unsigned char *p, uint32_t v) { unsigned i; for(i=0;i<4;++i)p[i]=(unsigned char)(v>>(i*8)); }
static void make_pe(struct memory *m, int wide)
{
    unsigned char *file, *optional, *section;
    unsigned opt = wide ? 240 : 224;
    memset(m, 0, sizeof *m); m->length=1024;
    m->bytes[0]='M';m->bytes[1]='Z';put16(m->bytes+8,4);put32(m->bytes+60,128);
    memcpy(m->bytes+128,"PE\0\0",4);file=m->bytes+132;optional=m->bytes+152;section=optional+opt;
    put16(file,wide?0x8664:0x14c);put16(file+2,1);put16(file+16,opt);put16(file+18,2);
    put16(optional,wide?0x20b:0x10b);put32(optional+56,8192);put32(optional+60,512);
    put32(section+8,16);put32(section+12,4096);put32(section+16,512);put32(section+20,512);
}
static unsigned file_read(void *arg, uint64_t off, void *out, size_t n)
{
    FILE *f=arg;
    if(fseeko(f,(off_t)off,SEEK_SET))return 5;
    return fread(out,1,n,f)==n?0:193;
}
int main(int argc,char **argv)
{
    struct memory m; struct shz_binary_reader reader={memory_read,&m,1024};struct shz_binary_result result;
    unsigned error,i;uint32_t seed=1234567;
    make_pe(&m,0);VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==0&&result.mz);
    make_pe(&m,1);VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==6);
    put16(m.bytes+132,0xaa64);VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==6);
    put16(m.bytes+132,0x14c);VERIFY(shz_binary_classify(&reader,&result)==193);
    make_pe(&m,0);put16(m.bytes+132,0x1c4);VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==0);
    put16(m.bytes+150,0x2002);VERIFY(shz_binary_classify(&reader,&result)==193);
    make_pe(&m,1);put32(m.bytes+412,0xfffffff0);VERIFY(shz_binary_classify(&reader,&result)==193);
    make_pe(&m,1);reader.length=400;m.length=400;VERIFY(shz_binary_classify(&reader,&result)==193);
    make_pe(&m,1);reader.length=1024;m.error=5;VERIFY(shz_binary_classify(&reader,&result)==5);
    memset(&m,0,sizeof m);m.length=1024;m.bytes[0]='M';m.bytes[1]='Z';put16(m.bytes+8,4);
    VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==1);
    put32(m.bytes+60,0xfffffffc);VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==1);
    put32(m.bytes+60,128);m.bytes[128]='N';m.bytes[129]='E';m.bytes[182]=2;
    VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==2);
    m.bytes[182]=1;VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==5);
    m.bytes[182]=5;VERIFY(shz_binary_classify(&reader,&result)==0&&result.type==1);
    m.bytes[182]=0;VERIFY(shz_binary_classify(&reader,&result)==50);
    m.bytes[128]='L';m.bytes[129]='X';VERIFY(shz_binary_classify(&reader,&result)==50);
    m.bytes[0]=0;VERIFY(shz_binary_classify(&reader,&result)==193&&!result.mz);
    for(i=0;i<20000;++i){unsigned j;m.length=i%1025;reader.length=m.length;for(j=0;j<m.length;++j){seed=seed*1664525u+1013904223u;m.bytes[j]=(unsigned char)(seed>>24);}error=shz_binary_classify(&reader,&result);VERIFY(error==0||error==193||error==50);}
    for(i=1;i<(unsigned)argc;++i){FILE *f=fopen(argv[i],"rb");off_t length;VERIFY(f!=NULL);VERIFY(fseeko(f,0,SEEK_END)==0);length=ftello(f);VERIFY(length>=0);reader.read=file_read;reader.context=f;reader.length=(uint64_t)length;error=shz_binary_classify(&reader,&result);VERIFY(error==0&&result.type==6);VERIFY(fclose(f)==0);printf("Actual AMD64 publisher input classified: %s\n",argv[i]);}
    printf("OFFICE-BINARY-HOST: %u checks passed; PE32/PE32+, DOS/NE, bounds, read failure, malformed input corpus\n",checks);return 0;
}
