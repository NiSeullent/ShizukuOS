/* SPDX-License-Identifier: GPL-2.0-only
 * Host controls for explicit large PE parsing budgets. No guest code runs.
 */
#include "pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
static unsigned checks;
static int count_relocation(void *opaque,uint32_t rva)
{
 uint32_t *count=opaque;(void)rva;++*count;return 1;
}
static void require(int ok,const char *label)
{
 ++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",label);exit(1);}
}
static void *mapped_file(const char *path,uint32_t *length)
{
 struct stat s;int fd=open(path,O_RDONLY);void *p;
 require(fd>=0,"open original input");require(!fstat(fd,&s),"stat original input");
 require(s.st_size>=64&&s.st_size<=NP_LARGE_FILE_LIMIT,"bounded original input");
 *length=(uint32_t)s.st_size;p=mmap(NULL,*length,PROT_READ,MAP_PRIVATE,fd,0);
 require(p!=MAP_FAILED,"map original input read-only");require(!close(fd),"close input handle");return p;
}
static void put32(unsigned char *p,uint32_t v)
{
 p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);
 p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);
}
int main(int argc,char **argv)
{
 np_image image;const char *error=NULL;np_parse_limits budget;
 uint32_t fn,cn,pe,opt,count=0;const unsigned char *fixture,*chrome;
 unsigned char *changed;uint32_t target_image,relocation_count=0,observed=0;
 int imports_ok,relocations_ok,tls_ok,large_relocations_ok;
 np_tls_info tls;char imports_error[96]={0},relocations_error[96]={0},tls_error[96]={0};
 require(argc==3,"fixture and immutable Chromium DLL arguments");
 fixture=mapped_file(argv[1],&fn);chrome=mapped_file(argv[2],&cn);
 require(np_parse(&image,fixture,fn,&error),"default original linked fixture");
 require(cn==283207168u,"official large Chromium DLL exact byte count");
 require(!np_parse(&image,chrome,cn,&error)&&!strcmp(error,"FILE_SIZE"),
         "default 32 MiB file limit preserved");
 budget=(np_parse_limits){NP_LARGE_FILE_LIMIT,NP_LARGE_IMAGE_LIMIT,NP_LARGE_TOTAL_LIMIT};
 require(np_parse_limited(&image,chrome,cn,&budget,&error),"actual large DLL structural parse");
 target_image=image.size;
 require(cn+target_image>=cn,"actual aggregate fits uint32");
 budget=(np_parse_limits){cn,target_image,cn+target_image};
 require(np_parse_limited(&image,chrome,cn,&budget,&error),"exact per-input budget accepted");
 budget.total_bytes--;
 require(!np_parse_limited(&image,chrome,cn,&budget,&error)&&!strcmp(error,"PARSE_TOTAL_BUDGET"),
         "one byte below aggregate rejected");
 budget.total_bytes++;budget.file_bytes--;
 require(!np_parse_limited(&image,chrome,cn,&budget,&error)&&!strcmp(error,"FILE_SIZE"),
         "one byte below file budget rejected");
 budget.file_bytes++;budget.image_bytes-=4096;
 require(!np_parse_limited(&image,chrome,cn,&budget,&error)&&!strcmp(error,"IMAGE_BOUNDS"),
         "one page below image budget rejected");
 budget.image_bytes=target_image;
 require(!np_parse_limited(&image,chrome,cn,NULL,&error)&&!strcmp(error,"PARSE_BUDGET_BOUNDS"),
         "null opt-in policy rejected");
 for(unsigned field=0;field<3;field++){
  np_parse_limits bad=budget;uint32_t *slot=field==0?&bad.file_bytes:field==1?&bad.image_bytes:&bad.total_bytes;
  *slot=0;require(!np_parse_limited(&image,chrome,cn,&bad,&error)&&!strcmp(error,"PARSE_BUDGET_BOUNDS"),
                 "zero policy field rejected");
  *slot=field==0?NP_LARGE_FILE_LIMIT+1:field==1?NP_LARGE_IMAGE_LIMIT+1:NP_LARGE_TOTAL_LIMIT+1;
  require(!np_parse_limited(&image,chrome,cn,&bad,&error)&&!strcmp(error,"PARSE_BUDGET_BOUNDS"),
          "hard ceiling plus one rejected");
  *slot=0xffffffffu;
  require(!np_parse_limited(&image,chrome,cn,&bad,&error),"wrapped/unbounded policy rejected");
 }
 require(!np_parse_limited(NULL,chrome,cn,&budget,&error),"null image output rejected");
 require(!np_parse_limited(&image,NULL,cn,&budget,&error),"null mapped file rejected");
 require(!np_parse_limited(&image,chrome,63,&budget,&error),"truncated header rejected");
 changed=malloc(fn);require(changed!=NULL,"small mutation control allocation");
 memcpy(changed,fixture,fn);pe=np_u32(changed+60);opt=pe+24;
 require(opt+64<=fn,"fixture optional header available");
 put32(changed+opt+56,128u*1024u*1024u);
 require(!np_parse(&image,changed,fn,&error)&&!strcmp(error,"IMAGE_BOUNDS"),
         "default 64 MiB image limit preserved");
 require(np_parse_limited(&image,changed,fn,&budget,&error),"explicit larger virtual image allowed");
 put32(changed+60,0xfffffff0u);
 require(!np_parse_limited(&image,changed,fn,&budget,&error),"overflowing PE header still rejected");
 memcpy(changed,fixture,fn);put32(changed+opt+56,0xfffff000u);
 require(!np_parse_limited(&image,changed,fn,&budget,&error),"overflowing image still rejected");
 memcpy(changed,fixture,fn);
 require(np_parse_limited(&image,changed,fn,&budget,&error),"original relocation mutation control");
 {
  const unsigned char *block=np_raw(&image,image.directory[5][0],8);
  require(block!=NULL,"linked fixture relocation block available");
  put32(changed+(block-changed)+4,0xfffffffcu);
  require(!np_relocations_limited(&image,NULL,NULL,NP_LARGE_RELOC_LIMIT,&error)&&
          !strcmp(error,"RELOC_BLOCK"),"large budget does not permit overflowing relocation blocks");
 }
 free(changed);
 require(np_parse_limited(&image,chrome,cn,&budget,&error),"reparse original after rejected controls");
 imports_ok=np_imports(&image,1,NULL,NULL,&count,&error);
 if(error)snprintf(imports_error,sizeof(imports_error),"%s",error);
 relocations_ok=np_relocations(&image,NULL,NULL,&error);
 if(error)snprintf(relocations_error,sizeof(relocations_error),"%s",error);
 require(!relocations_ok&&!strcmp(relocations_error,"RELOC_LIMIT"),"default relocation limit preserved");
 large_relocations_ok=np_relocations_limited(&image,count_relocation,&relocation_count,
                                             NP_LARGE_RELOC_LIMIT,&error);
 require(large_relocations_ok&&relocation_count==4664381u,
         "every original Chromium HIGHLOW relocation validated within explicit ceiling");
 require(np_relocations_limited(&image,NULL,NULL,relocation_count,&error),
         "exact original relocation work budget accepted");
 require(!np_relocations_limited(&image,count_relocation,&observed,relocation_count-1,&error)&&
          !strcmp(error,"RELOC_LIMIT")&&observed==relocation_count-1,
         "one entry below work budget refuses before callback");
 observed=0;
 require(!np_relocations_limited(&image,count_relocation,&observed,0,&error)&&
          !strcmp(error,"RELOC_WORK_BUDGET")&&!observed,"zero work budget refuses all callbacks");
 require(!np_relocations_limited(&image,count_relocation,&observed,NP_LARGE_RELOC_LIMIT+1,&error)&&
          !observed,"work ceiling plus one refuses all callbacks");
 require(!np_relocations_limited(&image,count_relocation,&observed,0xffffffffu,&error)&&
          !observed,"unbounded work request refuses all callbacks");
 require(!np_relocations_limited(NULL,count_relocation,&observed,1,&error)&&
          !observed,"null relocation image refuses all callbacks");
 tls_ok=np_tls(&image,&tls,&error);
 if(error)snprintf(tls_error,sizeof(tls_error),"%s",error);
 require(!np_execution_profile(&image,&error),"classic execution remains refused");
 require(!np_runtime_profile(&image,&error),"runtime execution remains refused");
 require(!munmap((void *)fixture,fn),"unmap fixture");
 require(!munmap((void *)chrome,cn),"unmap large original file");
 printf("{\"status\":\"PASS\",\"checks\":%u,\"file_bytes\":%u,\"image_bytes\":%u,"
        "\"aggregate_bytes\":%u,\"imports_valid\":%s,\"imports\":%u,\"imports_error\":\"%s\","
        "\"default_relocations_valid\":%s,\"default_relocations_error\":\"%s\","
        "\"limited_relocations_valid\":%s,\"relocations\":%u,\"tls_valid\":%s,\"tls_error\":\"%s\","
        "\"entry_points_called\":0,\"native_executed\":false}\n",checks,cn,target_image,cn+target_image,
        imports_ok?"true":"false",count,imports_error,relocations_ok?"true":"false",relocations_error,
        large_relocations_ok?"true":"false",relocation_count,
        tls_ok?"true":"false",tls_error);
 return 0;
}
