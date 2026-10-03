/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_release.h"
#if defined(SHZ_NATIVE_INSTALLER_RELEASE) && !defined(SHZ_STANDALONE)
#error "Native release records belong only to the installer standalone kernel"
#endif
#ifdef SHZ_NATIVE_INSTALLER_RELEASE
/* This symbol is generated under held actual-producer custody by kbuild only.
 * Never provide runtime registration or a caller-approved override. */
extern const setup_native_release_record_v1 shz_installer_release_v1;
static int nonzero(const uint8_t *p)
{ uint8_t v=0;for(unsigned i=0;i<32;i++)v|=p[i];return v!=0; }
static int equal(const uint8_t *a,const uint8_t *b)
{ uint8_t v=0;for(unsigned i=0;i<32;i++)v|=a[i]^b[i];return v==0; }
int setup_native_release_available(void)
{
 const setup_native_release_record_v1 *r=&shz_installer_release_v1;
 return r->magic==0x31524e53u&&r->version==1&&r->bytes==128&&!r->reserved&&
  r->manifest_bytes&&r->manifest_bytes<=((uint64_t)4<<20)&&
  r->sim_bytes&&r->sim_bytes<=SHZ_NATIVE_KERNEL_SOURCE_MAX&&
  nonzero(r->manifest_sha256)&&nonzero(r->sim_sha256)&&nonzero(r->evidence_sha256);
}
unsigned setup_native_release_state(void) { return setup_native_release_available()?1u:2u; }
int setup_native_release_info(unsigned role,uint64_t *bytes,uint8_t sha256[32])
{
 const setup_native_release_record_v1 *r=&shz_installer_release_v1;
 if(role>1||!bytes||!sha256||!setup_native_release_available())return -1;
 *bytes=role?r->sim_bytes:r->manifest_bytes;
 for(unsigned i=0;i<32;i++)sha256[i]=(role?r->sim_sha256:r->manifest_sha256)[i];
 return 0;
}
int setup_native_release_source(const archive_source_info_t *s,unsigned role)
{
 const setup_native_release_record_v1 *r=&shz_installer_release_v1;
 if(!s||role>1||!setup_native_release_available())return -1;
 return s->bytes==(role?r->sim_bytes:r->manifest_bytes)&&
  equal(s->sha256,role?r->sim_sha256:r->manifest_sha256)?0:-1;
}
int setup_native_release_pair(const archive_source_info_t p[2])
{ return p&&setup_native_release_source(&p[0],0)==0&&setup_native_release_source(&p[1],1)==0?0:-1; }
#else
/* Public development builds have no private release or producer authority. */
int setup_native_release_available(void) { return 0; }
unsigned setup_native_release_state(void) { return 0; }
int setup_native_release_info(unsigned role,uint64_t *bytes,uint8_t sha256[32])
{ (void)role;(void)bytes;(void)sha256;return -1; }
int setup_native_release_source(const archive_source_info_t *s,unsigned role)
{ (void)s;(void)role;return -1; }
int setup_native_release_pair(const archive_source_info_t p[2])
{ (void)p;return -1; }
#endif
