/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWPE_H
#define NTWPE_H
#include <stdint.h>
#define NP_SECTIONS 96
#define NP_IMPORTS 8192
#define NP_FILE_LIMIT (32u*1024u*1024u)
#define NP_IMAGE_LIMIT (64u*1024u*1024u)
#define NP_LARGE_FILE_LIMIT (512u*1024u*1024u)
#define NP_LARGE_IMAGE_LIMIT (512u*1024u*1024u)
#define NP_LARGE_TOTAL_LIMIT (1024u*1024u*1024u)
#define NP_RELOC_LIMIT 262144u
#define NP_LARGE_RELOC_LIMIT 8388608u
#define NP_TLS_CALLBACKS 64u
typedef struct np_tls_info {
 uint32_t present,template_rva,template_bytes,zero_bytes,index_rva,callbacks_rva;
 uint32_t alignment,count,callback[NP_TLS_CALLBACKS];
} np_tls_info;
typedef struct np_section {uint32_t va,span,raw,bytes,flags;} np_section;
typedef struct np_image {
 const uint8_t *file; uint32_t bytes,base,size,headers,entry,section_align;
 uint16_t sections,characteristics,subsystem,subsystem_major,subsystem_minor;
 uint32_t directory[16][2]; np_section section[NP_SECTIONS];
} np_image;
/* Explicit opt-in parsing budget. This admits no execution or allocation. */
typedef struct np_parse_limits {
 uint32_t file_bytes,image_bytes,total_bytes;
} np_parse_limits;
typedef int (*np_import_fn)(void *,const char *,const char *,uint16_t,uint32_t,int);
typedef int (*np_reloc_fn)(void *,uint32_t);
int np_parse(np_image *,const void *,uint32_t,const char **);
int np_parse_limited(np_image *,const void *,uint32_t,const np_parse_limits *,const char **);
const uint8_t *np_raw(const np_image *,uint32_t,uint32_t);
int np_memory(const np_image *,uint32_t,uint32_t,int);
int np_imports(const np_image *,int,np_import_fn,void *,uint32_t *,const char **);
int np_relocations(const np_image *,np_reloc_fn,void *,const char **);
int np_relocations_limited(const np_image *,np_reloc_fn,void *,uint32_t,const char **);
int np_export(const np_image *,const char *,uint16_t,uint32_t *,const char **,const char **);
int np_execution_profile(const np_image *,const char **);
int np_runtime_profile(const np_image *,const char **);
int np_tls(const np_image *,np_tls_info *,const char **);
uint32_t np_u32(const uint8_t *);
uint16_t np_u16(const uint8_t *);
#endif
