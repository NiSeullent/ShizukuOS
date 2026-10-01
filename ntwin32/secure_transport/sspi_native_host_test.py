#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual adapter ABI fault model; no host trust-store or VM modifications.

Win32 calls and the already independently real-TLS-tested stream core are mocked.
This proves descriptor/lifetime/status translation only, never real TLS/Windows
execution. Generated model sources, compiler/run logs and source hashes are kept
in a NEW private output. --sanitize uses local clang ASan/UBSan, no installation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCES = ("sspi_native.c", "sspi_native.h", "sspi_native.def", "sspi_native_host_test.py",
           "sspi_stream.h", "sspi_stream.c", "native_runtime.h", "transport.h")

SHIM = r'''#ifndef M98SSPI_TEST_WIN32_H
#define M98SSPI_TEST_WIN32_H
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#define WINAPI
typedef uint32_t ULONG, DWORD;
typedef uintptr_t ULONG_PTR;
typedef int32_t SECURITY_STATUS;
typedef int BOOL;
typedef void *HINSTANCE, *LPVOID, *HCERTSTORE;
typedef char SEC_CHAR;
typedef void (*SEC_GET_KEY_FN)(void);
typedef struct { ULONG_PTR dwLower, dwUpper; } SecHandle, CredHandle, CtxtHandle;
typedef SecHandle *PSecHandle;
typedef CredHandle *PCredHandle;
typedef CtxtHandle *PCtxtHandle;
typedef struct { uint32_t LowPart; int32_t HighPart; } TimeStamp, *PTimeStamp;
typedef struct { ULONG cbBuffer, BufferType; void *pvBuffer; } SecBuffer, *PSecBuffer;
typedef struct { ULONG ulVersion, cBuffers; PSecBuffer pBuffers; } SecBufferDesc, *PSecBufferDesc;
typedef struct { ULONG fCapabilities; uint16_t wVersion,wRPCID; ULONG cbMaxToken;
                 SEC_CHAR *Name,*Comment; } SecPkgInfoA,*PSecPkgInfoA;
typedef struct { ULONG cbHeader,cbTrailer,cbMaximumMessage,cBuffers,cbBlockSize; } SecPkgContext_StreamSizes;
typedef struct { DWORD dwCertEncodingType; const unsigned char *pbCertEncoded;
                 DWORD cbCertEncoded; } CERT_CONTEXT, *PCERT_CONTEXT;
typedef const CERT_CONTEXT *PCCERT_CONTEXT;
typedef struct { DWORD dwVersion,cCreds; PCCERT_CONTEXT *paCred; HCERTSTORE hRootStore;
 DWORD cMappers; void **aphMappers; DWORD cSupportedAlgs; DWORD *palgSupportedAlgs;
 DWORD grbitEnabledProtocols,dwMinimumCipherStrength,dwMaximumCipherStrength,
 dwSessionLifespan,dwFlags,dwCredFormat; } SCHANNEL_CRED;
typedef pthread_mutex_t CRITICAL_SECTION;
void InitializeCriticalSection(CRITICAL_SECTION *);
void DeleteCriticalSection(CRITICAL_SECTION *);
void EnterCriticalSection(CRITICAL_SECTION *);
void LeaveCriticalSection(CRITICAL_SECTION *);
HCERTSTORE CertOpenStore(const char *,DWORD,ULONG_PTR,DWORD,const void *);
PCCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE,PCCERT_CONTEXT);
BOOL CertFreeCertificateContext(PCCERT_CONTEXT);
BOOL CertCloseStore(HCERTSTORE,DWORD);
DWORD GetLastError(void);
#define TRUE 1
#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define CRYPT_E_NOT_FOUND UINT32_C(0x80092004)
#define X509_ASN_ENCODING 1
#define CERT_STORE_PROV_SYSTEM_A ((const char *)(uintptr_t)9)
#define CERT_SYSTEM_STORE_CURRENT_USER 0x10000
#define CERT_STORE_OPEN_EXISTING_FLAG 0x4000
#define CERT_STORE_READONLY_FLAG 0x8000
#define SEC_E_OK 0
#define SEC_E_INSUFFICIENT_MEMORY ((int32_t)0x80090300)
#define SEC_E_INVALID_HANDLE ((int32_t)0x80090301)
#define SEC_E_UNSUPPORTED_FUNCTION ((int32_t)0x80090302)
#define SEC_E_INTERNAL_ERROR ((int32_t)0x80090304)
#define SEC_E_SECPKG_NOT_FOUND ((int32_t)0x80090305)
#define SEC_E_INVALID_TOKEN ((int32_t)0x80090308)
#define SEC_E_UNKNOWN_CREDENTIALS ((int32_t)0x8009030d)
#define SEC_E_NO_CREDENTIALS ((int32_t)0x8009030e)
#define SEC_E_MESSAGE_ALTERED ((int32_t)0x8009030f)
#define SEC_E_OUT_OF_SEQUENCE ((int32_t)0x80090310)
#define SEC_I_CONTINUE_NEEDED ((int32_t)0x00090312)
#define SEC_E_CONTEXT_EXPIRED ((int32_t)0x80090317)
#define SEC_I_CONTEXT_EXPIRED ((int32_t)0x00090317)
#define SEC_E_INCOMPLETE_MESSAGE ((int32_t)0x80090318)
#define SEC_E_BUFFER_TOO_SMALL ((int32_t)0x80090321)
#define SEC_E_WRONG_PRINCIPAL ((int32_t)0x80090322)
#define SEC_I_RENEGOTIATE ((int32_t)0x00090321)
#define SEC_E_UNTRUSTED_ROOT ((int32_t)0x80090325)
#define SEC_E_ILLEGAL_MESSAGE ((int32_t)0x80090326)
#define SEC_E_CERT_UNKNOWN ((int32_t)0x80090327)
#define SEC_E_CERT_EXPIRED ((int32_t)0x80090328)
#define SECPKG_CRED_INBOUND 1
#define SECPKG_CRED_OUTBOUND 2
#define SECPKG_CRED_BOTH 3
#define SECBUFFER_VERSION 0
#define SECBUFFER_EMPTY 0
#define SECBUFFER_DATA 1
#define SECBUFFER_TOKEN 2
#define SECBUFFER_MISSING 4
#define SECBUFFER_EXTRA 5
#define SECBUFFER_STREAM_TRAILER 6
#define SECBUFFER_STREAM_HEADER 7
#define SECBUFFER_ALERT 17
#define SECBUFFER_ATTRMASK UINT32_C(0xf0000000)
#define SECBUFFER_READONLY UINT32_C(0x80000000)
#define SECPKG_ATTR_STREAM_SIZES 4
#define ISC_REQ_DELEGATE 1
#define ISC_REQ_MUTUAL_AUTH 2
#define ISC_REQ_REPLAY_DETECT 4
#define ISC_REQ_SEQUENCE_DETECT 8
#define ISC_REQ_CONFIDENTIALITY 16
#define ISC_REQ_ALLOCATE_MEMORY 256
#define ISC_REQ_DATAGRAM 1024
#define ISC_REQ_CONNECTION 2048
#define ISC_REQ_EXTENDED_ERROR 16384
#define ISC_REQ_STREAM 32768
#define ISC_REQ_INTEGRITY 65536
#define ISC_REQ_MANUAL_CRED_VALIDATION 524288
#define ISC_RET_REPLAY_DETECT ISC_REQ_REPLAY_DETECT
#define ISC_RET_SEQUENCE_DETECT ISC_REQ_SEQUENCE_DETECT
#define ISC_RET_CONFIDENTIALITY ISC_REQ_CONFIDENTIALITY
#define ISC_RET_ALLOCATED_MEMORY ISC_REQ_ALLOCATE_MEMORY
#define ISC_RET_CONNECTION ISC_REQ_CONNECTION
#define ISC_RET_STREAM ISC_REQ_STREAM
#define ISC_RET_INTEGRITY ISC_REQ_INTEGRITY
#define SECPKG_FLAG_INTEGRITY 1
#define SECPKG_FLAG_PRIVACY 2
#define SECPKG_FLAG_CONNECTION 16
#define SECPKG_FLAG_CLIENT_ONLY 64
#define SECPKG_FLAG_STREAM 1024
#define SECPKG_ID_NONE 65535
#define SCHANNEL_CRED_VERSION 4
#define SCH_CRED_NO_DEFAULT_CREDS 16
#define SCH_CRED_AUTO_CRED_VALIDATION 32
#define SCH_CRED_MANUAL_CRED_VALIDATION 8
#define SCH_CRED_REVOCATION_CHECK_CHAIN 512
#define SP_PROT_TLS1_3_CLIENT 8192
#define SCHANNEL_SHUTDOWN 1
typedef struct {
 ULONG dwVersion;
 SECURITY_STATUS (*EnumerateSecurityPackagesA)(ULONG*,PSecPkgInfoA*);
 void *QueryCredentialsAttributesA;
 SECURITY_STATUS (*AcquireCredentialsHandleA)(SEC_CHAR*,SEC_CHAR*,ULONG,void*,void*,SEC_GET_KEY_FN,void*,PCredHandle,PTimeStamp);
 SECURITY_STATUS (*FreeCredentialHandle)(PCredHandle);
 void *Reserved2;
 SECURITY_STATUS (*InitializeSecurityContextA)(PCredHandle,PCtxtHandle,SEC_CHAR*,ULONG,ULONG,ULONG,PSecBufferDesc,ULONG,PCtxtHandle,PSecBufferDesc,ULONG*,PTimeStamp);
 void *AcceptSecurityContext,*CompleteAuthToken;
 SECURITY_STATUS (*DeleteSecurityContext)(PCtxtHandle);
 SECURITY_STATUS (*ApplyControlToken)(PCtxtHandle,PSecBufferDesc);
 SECURITY_STATUS (*QueryContextAttributesA)(PCtxtHandle,ULONG,void*);
 void *ImpersonateSecurityContext,*RevertSecurityContext,*MakeSignature,*VerifySignature;
 SECURITY_STATUS (*FreeContextBuffer)(void*);
 SECURITY_STATUS (*QuerySecurityPackageInfoA)(SEC_CHAR*,PSecPkgInfoA*);
 void *Reserved3,*Reserved4;
 SECURITY_STATUS (*ExportSecurityContext)(PCtxtHandle,ULONG,PSecBuffer,void**);
 SECURITY_STATUS (*ImportSecurityContextA)(SEC_CHAR*,PSecBuffer,void*,PCtxtHandle);
 void *AddCredentialsA,*Reserved8,*QuerySecurityContextToken;
 SECURITY_STATUS (*EncryptMessage)(PCtxtHandle,ULONG,PSecBufferDesc,ULONG);
 SECURITY_STATUS (*DecryptMessage)(PCtxtHandle,PSecBufferDesc,ULONG,ULONG*);
 void *SetContextAttributesA,*SetCredentialsAttributesA,*ChangeAccountPasswordA;
} SecurityFunctionTableA,*PSecurityFunctionTableA;
#endif
'''

DRIVER = r'''#define M98SSPI_HOST_TEST 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sspi_native.c"
static unsigned checks, failures, groups;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr,"FAIL:%d %s\n",__LINE__,#x); } } while (0)
#define GROUP(s) do { ++groups; printf("group %u: %s\n",groups,s); } while (0)
static int lock_depth, runtime_inits, runtime_finis, runtime_init_fail, runtime_fini_fail;
static int create_fail, core_creates, core_deletes, encrypt_mutations;
static int root_count, root_fail_after=-1, root_close_fail, root_open_fail;
static int root_store_exists=1,root_store_creations;
static unsigned root_frees, root_closes, root_position;
static DWORD last_error;
static unsigned char root_der[68];
static CERT_CONTEXT root_certs[MAX_ROOTS+1];
static unsigned char last_ca[M98SSPI_MAX_CA];
static size_t last_ca_size;
struct ntwssp_pool { int alive; };
typedef struct { int used,established,peer_closed,failed,pending_status;
 uint32_t generation,flags; int backend_error; size_t pending_size;
 unsigned char pending[128]; } fake_context;
static fake_context fakes[NTWSSP_MAX_CONTEXTS];
static uint32_t fake_generation;
static int handshake_status=NTWSSP_CONTINUE, decrypt_status=NTWSSP_OK;
static size_t handshake_consumed, handshake_missing, handshake_size=3;
static size_t decrypt_consumed=25,decrypt_missing, decrypt_size=3;
static int control_response;
void InitializeCriticalSection(CRITICAL_SECTION *p) { CHECK(pthread_mutex_init(p,NULL)==0); }
void DeleteCriticalSection(CRITICAL_SECTION *p) { CHECK(pthread_mutex_destroy(p)==0); }
void EnterCriticalSection(CRITICAL_SECTION *p) { pthread_mutex_lock(p); CHECK(!lock_depth); ++lock_depth; }
void LeaveCriticalSection(CRITICAL_SECTION *p) { CHECK(lock_depth==1); --lock_depth; pthread_mutex_unlock(p); }
HCERTSTORE CertOpenStore(const char *provider,DWORD encoding,ULONG_PTR x,DWORD flags,const void *name) {
 const char*s=name;
 CHECK(lock_depth==1); CHECK(x==0 && !encoding && !strcmp(s,"ROOT")); root_position=0;
 CHECK(provider==CERT_STORE_PROV_SYSTEM_A && flags==(CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG));
 if(!root_store_exists){
  if(flags&CERT_STORE_OPEN_EXISTING_FLAG){last_error=2;return NULL;}
  ++root_store_creations;root_store_exists=1;
 }
 return root_open_fail ? NULL : (void*)(uintptr_t)0x1122;
}
PCCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE s,PCCERT_CONTEXT prev) {
 CHECK(lock_depth==1 && s==(void*)(uintptr_t)0x1122);
 CHECK((root_position==0 && prev==NULL) || (root_position>0 && prev==&root_certs[root_position-1]));
 if (root_fail_after>=0 && root_position==(unsigned)root_fail_after) { last_error=0xdead; return NULL; }
 if (root_position==(unsigned)root_count) { last_error=CRYPT_E_NOT_FOUND; return NULL; }
 return &root_certs[root_position++];
}
BOOL CertFreeCertificateContext(PCCERT_CONTEXT p) { CHECK(lock_depth==1 && p); ++root_frees; return TRUE; }
BOOL CertCloseStore(HCERTSTORE s,DWORD flags) { CHECK(lock_depth==1 && s && !flags); ++root_closes; return !root_close_fail; }
DWORD GetLastError(void) { CHECK(lock_depth==1); return last_error; }
int ntwst_native_runtime_init(void) { CHECK(lock_depth==1); ++runtime_inits; return runtime_init_fail ? NTWST_RANDOM_ERROR : NTWST_OK; }
int ntwst_native_runtime_fini(void) { CHECK(lock_depth==1); ++runtime_finis; return runtime_fini_fail ? NTWST_ENGINE_ERROR : NTWST_OK; }
static fake_context *fake(ntwssp_pool *p,ntwssp_handle h) {
 CHECK(lock_depth==1); CHECK(p && p->alive);
 if (!h.slot || h.slot>NTWSSP_MAX_CONTEXTS || h.kind!=NTWSSP_CONTEXT_KIND) return NULL;
 return fakes[h.slot-1].used && fakes[h.slot-1].generation==h.generation ? &fakes[h.slot-1] : NULL;
}
int ntwssp_pool_create(ntwssp_pool **p) { CHECK(lock_depth==1); *p=calloc(1,sizeof **p); if(*p)(*p)->alive=1; return *p?NTWSSP_OK:NTWSSP_NO_MEMORY; }
void ntwssp_pool_destroy(ntwssp_pool *p) { CHECK(lock_depth==1); memset(fakes,0,sizeof fakes); free(p); }
int ntwssp_create(ntwssp_pool *p,const ntwssp_options *o,ntwssp_handle *h) {
 unsigned i; CHECK(lock_depth==1 && p && o->hostname && o->ca && o->ca_size);
 if (create_fail) return NTWSSP_NO_MEMORY;
 for(i=0;i<NTWSSP_MAX_CONTEXTS && fakes[i].used;++i);
 if(i==NTWSSP_MAX_CONTEXTS)return NTWSSP_LIMIT;
 CHECK(o->ca_size<=sizeof last_ca); memcpy(last_ca,o->ca,o->ca_size); last_ca_size=o->ca_size;
 fakes[i].used=1;fakes[i].generation=++fake_generation;
 *h=(ntwssp_handle){NTWSSP_CONTEXT_KIND,i+1,fakes[i].generation}; ++core_creates; return NTWSSP_OK;
}
int ntwssp_delete(ntwssp_pool *p,ntwssp_handle h) { fake_context*c=fake(p,h); if(!c)return NTWSSP_INVALID; memset(c,0,sizeof*c); ++core_deletes; return NTWSSP_OK; }
int ntwssp_query(ntwssp_pool*p,ntwssp_handle h,ntwssp_info*out) {
 fake_context*c=fake(p,h);if(!c)return NTWSSP_INVALID;
 memset(out,0,sizeof*out);out->established=c->established;out->failed=c->failed;
 out->peer_closed=c->peer_closed;out->verify_flags=c->flags;out->backend_error=c->backend_error;return NTWSSP_OK;
}
int ntwssp_stream_sizes(ntwssp_pool*p,ntwssp_handle h,ntwssp_sizes*out) {
 fake_context*c=fake(p,h);if(!c)return NTWSSP_INVALID;if(!c->established)return NTWSSP_STATE;
 *out=(ntwssp_sizes){5,32,16383,4,1};return NTWSSP_OK;
}
static int emit(fake_context*c,ntwssp_buffer*out,int status,size_t n) {
 size_t i;out->size=0;out->required=n;
 if(out->capacity<n){c->pending_size=n;c->pending_status=status;for(i=0;i<n;++i)c->pending[i]=(unsigned char)(0xa0+i);return NTWSSP_BUFFER_TOO_SMALL;}
 for(i=0;i<n;++i) { out->data[i]=(unsigned char)(0xa0+i); }
 out->size=n;return status;
}
int ntwssp_handshake(ntwssp_pool*p,ntwssp_handle h,ntwssp_input*in,ntwssp_buffer*out) {
 fake_context*c=fake(p,h);int s;if(!c)return NTWSSP_INVALID;
 in->consumed=in->missing=0;
 if(c->pending_size){if(in->size)return NTWSSP_BUSY; s=emit(c,out,c->pending_status,c->pending_size);if(s!=NTWSSP_BUFFER_TOO_SMALL)c->pending_size=0;return s;}
 CHECK(handshake_consumed<=in->size);in->consumed=handshake_consumed;in->missing=handshake_missing;
 if(handshake_status==NTWSSP_OK)c->established=1;
 return emit(c,out,handshake_status,handshake_size);
}
int ntwssp_encrypt(ntwssp_pool*p,ntwssp_handle h,ntwssp_buffer*a,ntwssp_buffer*b,ntwssp_buffer*t) {
 fake_context*c=fake(p,h);size_t i;if(!c)return NTWSSP_INVALID;
 if(!c->established || c->peer_closed)return NTWSSP_STATE;
 a->size=t->size=0;a->required=5;t->required=32;
 if(a->capacity<5 || t->capacity<32)return NTWSSP_BUFFER_TOO_SMALL;
 if(overlap(a->data,a->capacity,b->data,b->capacity)||overlap(a->data,a->capacity,t->data,t->capacity)||overlap(b->data,b->capacity,t->data,t->capacity))return NTWSSP_INVALID;
 ++encrypt_mutations;memset(a->data,0x17,5);for(i=0;i<b->size;++i)b->data[i]^=0x5a;memset(t->data,0xbb,17);a->size=5;t->size=17;return NTWSSP_OK;
}
int ntwssp_decrypt(ntwssp_pool*p,ntwssp_handle h,ntwssp_input*in,ntwssp_buffer*out) {
 fake_context*c=fake(p,h);if(!c)return NTWSSP_INVALID;
 in->consumed=in->missing=out->size=out->required=0;
 CHECK(!overlap(in->data,in->size,out->data,out->capacity));
 if(c->peer_closed)return NTWSSP_CLOSED;
 in->consumed=decrypt_consumed;in->missing=decrypt_missing;out->required=decrypt_size;
 CHECK(out->capacity>=decrypt_size);
 if(decrypt_status==NTWSSP_OK){CHECK(decrypt_size==3);memcpy(out->data,"abc",3);out->size=3;}
 if(decrypt_status==NTWSSP_CLOSED)c->peer_closed=1;
 return decrypt_status;
}
int ntwssp_take_token(ntwssp_pool*p,ntwssp_handle h,ntwssp_buffer*out) {
 if(!fake(p,h))return NTWSSP_INVALID;
 if(!control_response)return NTWSSP_STATE;
 control_response=0;return emit(&fakes[h.slot-1],out,NTWSSP_CONTINUE,2);
}
int ntwssp_shutdown(ntwssp_pool*p,ntwssp_handle h,ntwssp_buffer*out) {
 fake_context*c=fake(p,h);if(!c)return NTWSSP_INVALID;
 if(c->pending_size){int s=emit(c,out,c->pending_status,c->pending_size);if(s!=NTWSSP_BUFFER_TOO_SMALL)c->pending_size=0;return s;}
 return emit(c,out,NTWSSP_OK,7);
}
int ntwssp_end_input(ntwssp_pool*p,ntwssp_handle h) { fake_context*c=fake(p,h);return !c?NTWSSP_INVALID:c->peer_closed?NTWSSP_CLOSED:NTWSSP_TRUNCATED; }
static M98SSPI_PRIVATE_CRED private_ca(unsigned char *p,ULONG n) { return (M98SSPI_PRIVATE_CRED){M98SSPI_PRIVATE_CRED_VERSION,sizeof(M98SSPI_PRIVATE_CRED),p,n,0,0}; }
static SECURITY_STATUS acquire(PCredHandle h,void*auth) { return AcquireCredentialsHandleA(NULL,M98SSPI_PACKAGE_A,SECPKG_CRED_OUTBOUND,NULL,auth,NULL,NULL,h,NULL); }
static SECURITY_STATUS isc(PCredHandle cr,PCtxtHandle old,char*host,ULONG flags,PSecBufferDesc in,PCtxtHandle h,PSecBufferDesc out) {
 ULONG attrs=0xffffffff;SECURITY_STATUS s=InitializeSecurityContextA(cr,old,host,flags,0,0,in,0,h,out,&attrs,NULL);
 if(s!=SEC_E_OK) { CHECK(!(attrs&RET_SECURITY)); }
 return s;
}
static void hs(int status,size_t consumed,size_t missing,size_t token) { handshake_status=status;handshake_consumed=consumed;handshake_missing=missing;handshake_size=token; }
static CtxtHandle establish(PCredHandle cr,char*name) {
 unsigned char bytes[128];SecBuffer b={sizeof bytes,SECBUFFER_TOKEN,bytes};SecBufferDesc out={0,1,&b};CtxtHandle h={0};
 hs(NTWSSP_OK,0,0,3);CHECK(isc(cr,NULL,name,ISC_REQ_STREAM,NULL,&h,&out)==SEC_E_OK);return h;
}
static SecBufferDesc decrypt_desc(SecBuffer b[4],unsigned char *data,size_t n) {
 memset(b,0,4*sizeof*b);b[0]=(SecBuffer){(ULONG)n,SECBUFFER_DATA,data};return(SecBufferDesc){0,4,b};
}
static void *worker(void *arg) {
 unsigned i;(void)arg;
 for(i=0;i<200;++i){
  unsigned char ca_bytes[]={0x30,1},bytes[128];CredHandle credential_handle;CtxtHandle context_handle;
  M98SSPI_PRIVATE_CRED policy=private_ca(ca_bytes,sizeof ca_bytes);ULONG attrs=0;
  SecBuffer token={sizeof bytes,SECBUFFER_TOKEN,bytes};SecBufferDesc desc={0,1,&token};
  PSecPkgInfoA p=NULL;SecPkgContext_StreamSizes stream_sizes;
  if(QuerySecurityPackageInfoA(M98SSPI_PACKAGE_A,&p)!=SEC_E_OK||!p||FreeContextBuffer(p)!=SEC_E_OK)return(void*)1;
  if(acquire(&credential_handle,&policy)!=SEC_E_OK)return(void*)1;
  if(InitializeSecurityContextA(&credential_handle,NULL,"thread.test",ISC_REQ_STREAM,0,0,NULL,0,
      &context_handle,&desc,&attrs,NULL)!=SEC_E_OK)return(void*)1;
  if(QueryContextAttributesA(&context_handle,4,&stream_sizes)!=SEC_E_OK||stream_sizes.cbHeader!=5)return(void*)1;
  if(FreeCredentialsHandle(&credential_handle)!=SEC_E_OK||DeleteSecurityContext(&context_handle)!=SEC_E_OK)return(void*)1;
 }
 return NULL;
}
int main(void) {
 unsigned char ca[]={1,2,3,4}, output[128], cipher[80], saved[80], head[5], payload[3]={'a','b','c'}, tail[32];
 M98SSPI_PRIVATE_CRED auth=private_ca(ca,sizeof ca);CredHandle cr,stale,cr2;CtxtHandle h,oldh,other;
 SecBuffer b={sizeof output,SECBUFFER_TOKEN,output}, ib[2],db[4],eb[4];
 SecBufferDesc od={0,1,&b},id={0,2,ib},dd,ed={0,4,eb};SecPkgContext_StreamSizes sizes;
 PSecPkgInfoA info=NULL;PSecurityFunctionTableA table;ULONG count,qop,shutdown=SCHANNEL_SHUTDOWN;
 SecBuffer shut={sizeof shutdown,SECBUFFER_TOKEN,&shutdown};SecBufferDesc sd={0,1,&shut};unsigned i;
 GROUP("entry, real ABI table, discovery, owned allocation rejection");
 CHECK(InitSecurityInterfaceA()==NULL);CHECK(M98SspiDllMain(NULL,DLL_PROCESS_ATTACH,NULL));
 table=InitSecurityInterfaceA();CHECK(table && table->dwVersion==1 && table->EncryptMessage==EncryptMessage && table->DecryptMessage==DecryptMessage);
 CHECK(!table->AcceptSecurityContext && !table->MakeSignature && table->ExportSecurityContext==ExportSecurityContext);
 CHECK(table->ExportSecurityContext(NULL,0,NULL,NULL)==SEC_E_UNSUPPORTED_FUNCTION);
 CHECK(table->ImportSecurityContextA(NULL,NULL,NULL,NULL)==SEC_E_UNSUPPORTED_FUNCTION);
 CHECK(EnumerateSecurityPackagesA(&count,&info)==SEC_E_OK && count==1 && info);
 CHECK(!strcmp(info->Name,M98SSPI_PACKAGE_A) && !(info->fCapabilities & 0x8));
 CHECK(FreeContextBuffer(info)==SEC_E_OK);CHECK(FreeContextBuffer(info)==SEC_E_INVALID_HANDLE);
 CHECK(FreeContextBuffer(ca)==SEC_E_INVALID_HANDLE);CHECK(FreeContextBuffer(NULL)==SEC_E_INVALID_HANDLE);
 CHECK(QuerySecurityPackageInfoA("NTLM",&info)==SEC_E_SECPKG_NOT_FOUND && !info);
 GROUP("credentials, policy rejects, CA copy and generation handles");
 CHECK(acquire(&cr,&auth)==SEC_E_OK);stale=cr;ca[0]=0xff;
 h=establish(&cr,"example.test");CHECK(last_ca_size==4 && last_ca[0]==1);
 CHECK(FreeCredentialsHandle(&cr)==SEC_E_OK);CHECK(FreeCredentialsHandle(&stale)==SEC_E_INVALID_HANDLE);
 CHECK(QueryContextAttributesA(&h,SECPKG_ATTR_STREAM_SIZES,&sizes)==SEC_E_OK);
 CHECK(sizes.cbHeader==5 && sizes.cbTrailer==32 && sizes.cbMaximumMessage==16383 && sizes.cBuffers==4);
 CHECK(DeleteSecurityContext(&h)==SEC_E_OK);CHECK(runtime_finis==1);
 CHECK(acquire(&cr,&auth)==SEC_E_OK && cr.dwUpper!=stale.dwUpper);
 CHECK(FreeCredentialsHandle(&stale)==SEC_E_INVALID_HANDLE);
 { CredHandle wrong={0};CHECK(AcquireCredentialsHandleA(NULL,"NTLM",2,NULL,&auth,NULL,NULL,&wrong,NULL)==SEC_E_SECPKG_NOT_FOUND);
 CHECK(AcquireCredentialsHandleA(NULL,M98SSPI_PACKAGE_A,1,NULL,&auth,NULL,NULL,&wrong,NULL)==SEC_E_UNSUPPORTED_FUNCTION);
 CHECK(AcquireCredentialsHandleA("user",M98SSPI_PACKAGE_A,2,NULL,&auth,NULL,NULL,&wrong,NULL)==SEC_E_UNSUPPORTED_FUNCTION);
 auth.dwFlags=1;CHECK(acquire(&wrong,&auth)==SEC_E_INVALID_TOKEN);auth.dwFlags=0;
 auth.cbSize=0;CHECK(acquire(&wrong,&auth)==SEC_E_INVALID_TOKEN);auth.cbSize=sizeof auth; }
 GROUP("ROOT uses original DER, strict enumeration failure, hRootStore never clientCA");
 for(i=0;i<sizeof root_der;++i)root_der[i]=(unsigned char)i;
 for(i=0;i<MAX_ROOTS+1;++i)root_certs[i]=(CERT_CONTEXT){1,root_der,sizeof root_der};
 root_count=2;CHECK(acquire(&cr2,NULL)==SEC_E_OK);other=establish(&cr2,"root.test");
 CHECK(strstr((char*)last_ca,"AAECAwQF") && strstr((char*)last_ca,"-----END CERTIFICATE-----"));
 { size_t j, lines=0;for(j=0;j<last_ca_size;++j)if(last_ca[j]=='\n')++lines;CHECK(lines==8); }
 CHECK(DeleteSecurityContext(&other)==SEC_E_OK);CHECK(FreeCredentialsHandle(&cr2)==SEC_E_OK);
 root_count=0;CHECK(acquire(&cr2,NULL)==SEC_E_NO_CREDENTIALS);
 root_count=2;root_fail_after=1;CHECK(acquire(&cr2,NULL)==SEC_E_INTERNAL_ERROR);root_fail_after=-1;
 root_certs[0].dwCertEncodingType=0;CHECK(acquire(&cr2,NULL)==SEC_E_INVALID_TOKEN && root_frees);root_certs[0].dwCertEncodingType=1;
 root_close_fail=1;CHECK(acquire(&cr2,NULL)==SEC_E_INTERNAL_ERROR);root_close_fail=0;
 root_open_fail=1;CHECK(acquire(&cr2,NULL)==SEC_E_NO_CREDENTIALS);root_open_fail=0;
 root_store_exists=0;CHECK(acquire(&cr2,NULL)==SEC_E_NO_CREDENTIALS && !root_store_exists && !root_store_creations);root_store_exists=1;
 root_count=MAX_ROOTS+1;CHECK(acquire(&cr2,NULL)==SEC_E_INVALID_TOKEN);root_count=2;
 { SCHANNEL_CRED sc={0};sc.dwVersion=SCHANNEL_CRED_VERSION;sc.hRootStore=(void*)1;
 CHECK(acquire(&cr2,&sc)==SEC_E_UNSUPPORTED_FUNCTION);sc.hRootStore=NULL;sc.dwFlags=SCH_CRED_MANUAL_CRED_VALIDATION;
 CHECK(acquire(&cr2,&sc)==SEC_E_UNSUPPORTED_FUNCTION);sc.dwFlags=SCH_CRED_REVOCATION_CHECK_CHAIN;
 CHECK(acquire(&cr2,&sc)==SEC_E_UNSUPPORTED_FUNCTION);sc.dwFlags=SCH_CRED_AUTO_CRED_VALIDATION|SCH_CRED_NO_DEFAULT_CREDS;sc.grbitEnabledProtocols=SP_PROT_TLS1_3_CLIENT;
 CHECK(acquire(&cr2,&sc)==SEC_E_OK);CHECK(FreeCredentialsHandle(&cr2)==SEC_E_OK); }
 GROUP("bad options, DNS, readonly, foreign/wrong-kind handles before effects");
 b=(SecBuffer){sizeof output,SECBUFFER_TOKEN,output};hs(NTWSSP_CONTINUE,0,0,3);
 CHECK(isc(&cr,NULL,"127.0.0.1",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INVALID_TOKEN);
 CHECK(isc(&cr,NULL,"bad_name.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INVALID_TOKEN);
 CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM|ISC_REQ_DATAGRAM,NULL,&h,&od)==SEC_E_UNSUPPORTED_FUNCTION);
 CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM|ISC_REQ_MANUAL_CRED_VALIDATION,NULL,&h,&od)==SEC_E_UNSUPPORTED_FUNCTION);
 CHECK(isc(&cr,NULL,"example.test",0,NULL,&h,&od)==SEC_E_UNSUPPORTED_FUNCTION);
 b.BufferType|=SECBUFFER_READONLY;CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_UNSUPPORTED_FUNCTION);b.BufferType=SECBUFFER_TOKEN;
 CHECK(DeleteSecurityContext((PCtxtHandle)&cr)==SEC_E_INVALID_HANDLE);
 oldh=(CtxtHandle){CONTEXT_KIND|1,0};CHECK(DeleteSecurityContext(&oldh)==SEC_E_INVALID_HANDLE);
 oldh=(CtxtHandle){(ULONG_PTR)0xdeadbeef,1};CHECK(DeleteSecurityContext(&oldh)==SEC_E_INVALID_HANDLE);
 GROUP("descriptor corruption and unsupported credential options preserve state");
 od.ulVersion=1;CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INVALID_TOKEN);od.ulVersion=0;
 od.cBuffers=0;CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INVALID_TOKEN);od.cBuffers=1;
 b.cbBuffer=1;b.pvBuffer=NULL;CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INVALID_TOKEN);b=(SecBuffer){sizeof output,SECBUFFER_TOKEN,output};
 { SCHANNEL_CRED sc={0};sc.dwVersion=4;sc.cCreds=1;CHECK(acquire(&cr2,&sc)==SEC_E_UNSUPPORTED_FUNCTION);
 sc.cCreds=0;sc.grbitEnabledProtocols=0x800;CHECK(acquire(&cr2,&sc)==SEC_E_UNSUPPORTED_FUNCTION);
 sc.grbitEnabledProtocols=0;sc.dwVersion=3;CHECK(acquire(&cr2,&sc)==SEC_E_UNSUPPORTED_FUNCTION); }
 create_fail=1;hs(NTWSSP_CONTINUE,0,0,3);b=(SecBuffer){0,SECBUFFER_TOKEN,NULL};
 CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM|ISC_REQ_ALLOCATE_MEMORY,NULL,&h,&od)==SEC_E_INSUFFICIENT_MEMORY && !b.pvBuffer);
 create_fail=0;b=(SecBuffer){sizeof output,SECBUFFER_TOKEN,output};
 GROUP("retained first/final handshake tokens, retry, shutdown admission");
 b=(SecBuffer){1,SECBUFFER_TOKEN,output};hs(NTWSSP_CONTINUE,0,0,3);
 CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_BUFFER_TOO_SMALL && b.cbBuffer==3);
 oldh=h;b.cbBuffer=sizeof output;CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,NULL,&h,&od)==SEC_I_CONTINUE_NEEDED && b.cbBuffer==3);
 ib[0]=(SecBuffer){10,SECBUFFER_TOKEN,cipher};ib[1]=(SecBuffer){0};hs(NTWSSP_OK,10,0,9);b.cbBuffer=1;
 CHECK(isc(&cr,&h,"EXAMPLE.TEST",ISC_REQ_STREAM,&id,&h,&od)==SEC_E_BUFFER_TOO_SMALL && b.cbBuffer==9);
 CHECK(ApplyControlToken(&h,&sd)==SEC_E_OUT_OF_SEQUENCE);
 CHECK(QueryContextAttributesA(&h,SECPKG_ATTR_STREAM_SIZES,&sizes)==SEC_E_OUT_OF_SEQUENCE);
 b.cbBuffer=sizeof output;ib[1]=(SecBuffer){0};
 CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,&id,&h,&od)==SEC_E_OUT_OF_SEQUENCE);
 CHECK(ApplyControlToken(&h,&sd)==SEC_E_OUT_OF_SEQUENCE);
 b.cbBuffer=sizeof output;CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_OK && b.cbBuffer==9);
 CHECK(QueryContextAttributesA(&h,SECPKG_ATTR_STREAM_SIZES,&sizes)==SEC_E_OK);
 CHECK(DeleteSecurityContext(&h)==SEC_E_OK);CHECK(DeleteSecurityContext(&oldh)==SEC_E_INVALID_HANDLE);
 GROUP("MISSING versus consumed-prefix EXTRA and immutable retained tails");
 b.cbBuffer=sizeof output;hs(NTWSSP_CONTINUE,0,0,3);CHECK(isc(&cr,NULL,"example.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_I_CONTINUE_NEEDED);
 memset(cipher,0x31,sizeof cipher);memcpy(saved,cipher,sizeof cipher);ib[0]=(SecBuffer){13,SECBUFFER_TOKEN,cipher};ib[1]=(SecBuffer){0};
 hs(NTWSSP_INCOMPLETE,10,7,0);b.cbBuffer=sizeof output;
 CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,&id,&h,&od)==SEC_I_CONTINUE_NEEDED);
 CHECK(ib[1].BufferType==SECBUFFER_EXTRA && ib[1].cbBuffer==3 && ib[1].pvBuffer==cipher+10 && !memcmp(cipher,saved,sizeof cipher));
 ib[0]=(SecBuffer){3,SECBUFFER_TOKEN,cipher+10};ib[1]=(SecBuffer){0};hs(NTWSSP_INCOMPLETE,0,7,0);b.cbBuffer=sizeof output;
 CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,&id,&h,&od)==SEC_E_INCOMPLETE_MESSAGE);
 CHECK(ib[1].BufferType==SECBUFFER_MISSING && ib[1].cbBuffer==7 && !ib[1].pvBuffer);
 ib[0]=(SecBuffer){20,SECBUFFER_TOKEN,cipher};ib[1]=(SecBuffer){0};hs(NTWSSP_OK,10,0,0);b.cbBuffer=sizeof output;
 CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,&id,&h,&od)==SEC_E_OK && ib[1].BufferType==SECBUFFER_EXTRA && ib[1].cbBuffer==10);
 GROUP("encryption actual descriptor ranges, small-buffer no sequence advance, unsupported QOP");
 eb[0]=(SecBuffer){4,SECBUFFER_STREAM_HEADER,head};eb[1]=(SecBuffer){3,SECBUFFER_DATA,payload};eb[2]=(SecBuffer){32,SECBUFFER_STREAM_TRAILER,tail};eb[3]=(SecBuffer){0};
 CHECK(EncryptMessage(&h,0,&ed,0)==SEC_E_BUFFER_TOO_SMALL && eb[0].cbBuffer==5 && !encrypt_mutations && !memcmp(payload,"abc",3));
 CHECK(EncryptMessage(&h,1,&ed,0)==SEC_E_UNSUPPORTED_FUNCTION && !encrypt_mutations);
 eb[1].BufferType|=SECBUFFER_READONLY;CHECK(EncryptMessage(&h,0,&ed,0)==SEC_E_UNSUPPORTED_FUNCTION);eb[1].BufferType=SECBUFFER_DATA;
 eb[2].pvBuffer=payload;CHECK(EncryptMessage(&h,0,&ed,0)==SEC_E_INVALID_TOKEN && !encrypt_mutations && !memcmp(payload,"abc",3));eb[2].pvBuffer=tail;
 eb[3].BufferType=SECBUFFER_DATA;CHECK(EncryptMessage(&h,0,&ed,0)==SEC_E_INVALID_TOKEN && !encrypt_mutations);eb[3].BufferType=SECBUFFER_EMPTY;
 CHECK(EncryptMessage(&h,0,&ed,0)==SEC_E_OK && encrypt_mutations==1 && eb[2].cbBuffer==17 && payload[0]==('a'^0x5a));
 GROUP("decryption staged plaintext, unmodified EXTRA, incomplete and close idempotence");
 memset(cipher,0x43,sizeof cipher);memcpy(saved,cipher,sizeof cipher);dd=decrypt_desc(db,cipher,50);decrypt_status=NTWSSP_OK;decrypt_consumed=25;decrypt_missing=0;decrypt_size=3;
 qop=5;CHECK(DecryptMessage(&h,&dd,0,&qop)==SEC_E_OK && qop==0);
 CHECK(db[1].BufferType==SECBUFFER_DATA && db[1].pvBuffer==cipher+5 && db[1].cbBuffer==3 && !memcmp(cipher+5,"abc",3));
 CHECK(db[3].BufferType==SECBUFFER_EXTRA && db[3].pvBuffer==cipher+25 && db[3].cbBuffer==25 && !memcmp(cipher+25,saved+25,25));
 dd=decrypt_desc(db,cipher,3);decrypt_status=NTWSSP_INCOMPLETE;decrypt_consumed=0;decrypt_missing=2;decrypt_size=0;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_E_INCOMPLETE_MESSAGE && db[1].BufferType==SECBUFFER_MISSING && db[1].cbBuffer==2);
 dd=decrypt_desc(db,cipher,25);decrypt_status=NTWSSP_CLOSED;decrypt_consumed=25;decrypt_missing=0;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_I_CONTEXT_EXPIRED);dd=decrypt_desc(db,NULL,0);
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_I_CONTEXT_EXPIRED);CHECK(M98SspiEndInput(&h)==SEC_I_CONTEXT_EXPIRED);
 CHECK(DeleteSecurityContext(&h)==SEC_E_OK);
 GROUP("posthandshake response token is drained before traffic and shutdown");
 h=establish(&cr,"example.test");dd=decrypt_desc(db,cipher,25);decrypt_status=NTWSSP_CONTINUE;decrypt_consumed=25;decrypt_size=0;control_response=1;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_I_RENEGOTIATE);CHECK(ApplyControlToken(&h,&sd)==SEC_E_OUT_OF_SEQUENCE);
 b=(SecBuffer){1,SECBUFFER_TOKEN,output};CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_BUFFER_TOO_SMALL && b.cbBuffer==2);
 b.cbBuffer=sizeof output;CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_OK && b.cbBuffer==2);
 CHECK(ApplyControlToken(&h,&sd)==SEC_E_OK);b.cbBuffer=1;
 CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_BUFFER_TOO_SMALL && b.cbBuffer==7);
 b.cbBuffer=sizeof output;CHECK(isc(NULL,&h,NULL,ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_OK && b.cbBuffer==7);
 CHECK(M98SspiEndInput(&h)==SEC_E_ILLEGAL_MESSAGE);CHECK(DeleteSecurityContext(&h)==SEC_E_OK);
 GROUP("253-byte DNS continuation, credential lifetime and allocated tokens");
 { char name[254];size_t k;for(k=0;k<253;++k)name[k]=((k+1)%64==0)?'.':'a';name[253]=0;
 b=(SecBuffer){0,SECBUFFER_TOKEN,NULL};hs(NTWSSP_CONTINUE,0,0,3);
 CHECK(isc(&cr,NULL,name,ISC_REQ_STREAM|ISC_REQ_ALLOCATE_MEMORY,NULL,&h,&od)==SEC_I_CONTINUE_NEEDED && b.cbBuffer==3 && b.pvBuffer);
 CHECK(FreeContextBuffer(b.pvBuffer)==SEC_E_OK);b=(SecBuffer){sizeof output,SECBUFFER_TOKEN,output};hs(NTWSSP_OK,0,0,0);
 CHECK(isc(NULL,&h,name,ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_OK);
 CHECK(FreeCredentialsHandle(&cr)==SEC_E_OK);CHECK(QueryContextAttributesA(&h,4,&sizes)==SEC_E_OK);CHECK(DeleteSecurityContext(&h)==SEC_E_OK); }
 GROUP("bounded slots, immutable generations, allocator exhaustion and runtime failure");
 CHECK(acquire(&cr,&auth)==SEC_E_OK);
 { CtxtHandle hs_array[NTWSSP_MAX_CONTEXTS];CredHandle creds[M98SSPI_MAX_CREDENTIALS-1];
 for(i=0;i<NTWSSP_MAX_CONTEXTS;++i) { hs_array[i]=establish(&cr,"slots.test"); }
 b=(SecBuffer){sizeof output,SECBUFFER_TOKEN,output};
 CHECK(isc(&cr,NULL,"slots.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INSUFFICIENT_MEMORY);
 for(i=0;i<NTWSSP_MAX_CONTEXTS;++i)CHECK(DeleteSecurityContext(&hs_array[i])==SEC_E_OK);
 for(i=0;i<M98SSPI_MAX_CREDENTIALS-1;++i)CHECK(acquire(&creds[i],&auth)==SEC_E_OK);
 CHECK(acquire(&cr2,&auth)==SEC_E_INSUFFICIENT_MEMORY);
 for(i=0;i<M98SSPI_MAX_CREDENTIALS-1;++i)CHECK(FreeCredentialsHandle(&creds[i])==SEC_E_OK);
 }
 { PSecPkgInfoA many[ALLOCATIONS];for(i=0;i<ALLOCATIONS;++i)CHECK(QuerySecurityPackageInfoA(M98SSPI_PACKAGE_A,&many[i])==SEC_E_OK);
 CHECK(QuerySecurityPackageInfoA(M98SSPI_PACKAGE_A,&info)==SEC_E_INSUFFICIENT_MEMORY);
 for(i=0;i<ALLOCATIONS;++i)CHECK(FreeContextBuffer(many[i])==SEC_E_OK); }
 { uint32_t before=next_generation;next_generation=UINT32_MAX;CHECK(acquire(&cr2,&auth)==SEC_E_INSUFFICIENT_MEMORY);
 b=(SecBuffer){sizeof output,SECBUFFER_TOKEN,output};CHECK(isc(&cr,NULL,"slots.test",ISC_REQ_STREAM,NULL,&h,&od)==SEC_E_INSUFFICIENT_MEMORY);next_generation=before; }
 CHECK(FreeCredentialsHandle(&cr)==SEC_E_OK);runtime_init_fail=1;CHECK(acquire(&cr,&auth)==SEC_E_INTERNAL_ERROR);runtime_init_fail=0;
 GROUP("multi-thread calls serialize every allocation and native/core operation");
 hs(NTWSSP_OK,0,0,0);
 { pthread_t threads[8];void *results[8]={0};int created[8],joined[8];
 /* Main does not update the assertion counter while worker assertions run. */
 for(i=0;i<8;++i)created[i]=pthread_create(&threads[i],NULL,worker,NULL);
 for(i=0;i<8;++i)joined[i]=created[i]?1:pthread_join(threads[i],&results[i]);
 for(i=0;i<8;++i){CHECK(!created[i] && !joined[i]);CHECK(!results[i]);} }
 GROUP("certificate and authentication errors, no unsupported attributes success");
 CHECK(acquire(&cr,&auth)==SEC_E_OK);h=establish(&cr,"errors.test");
 CHECK(QueryContextAttributesA(&h,0,&sizes)==SEC_E_UNSUPPORTED_FUNCTION);
 { fake_context*f=&fakes[contexts[(h.dwLower&0xffff)-1].core.slot-1];
 dd=decrypt_desc(db,cipher,25);decrypt_status=NTWSSP_VERIFY;decrypt_consumed=0;decrypt_size=0;f->flags=MBEDTLS_X509_BADCERT_CN_MISMATCH;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_E_WRONG_PRINCIPAL);f->flags=MBEDTLS_X509_BADCERT_EXPIRED;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_E_CERT_EXPIRED);f->flags=MBEDTLS_X509_BADCERT_NOT_TRUSTED;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_E_UNTRUSTED_ROOT);f->backend_error=MBEDTLS_ERR_SSL_INVALID_MAC;decrypt_status=NTWSSP_ENGINE;
 CHECK(DecryptMessage(&h,&dd,0,NULL)==SEC_E_MESSAGE_ALTERED); }
 CHECK(DeleteSecurityContext(&h)==SEC_E_OK);runtime_fini_fail=1;CHECK(FreeCredentialsHandle(&cr)==SEC_E_OK);runtime_fini_fail=0;
 CHECK(acquire(&cr,&auth)==SEC_E_INTERNAL_ERROR);CHECK(M98SspiDllMain(NULL,DLL_PROCESS_DETACH,NULL));
 CHECK(core_creates==core_deletes && root_closes>0 && !lock_depth);
 printf("{\"groups\":%u,\"checks\":%u,\"failures\":%u,\"real_tls_proven\":false,\"native_guest_proven\":false}\n",groups,checks,failures);
 return failures?1:0;
}
'''

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_build(output, hashes):
    import pefile
    frozen = ROOT / "build/secure-transport/native-v5-crt"
    upstream = ROOT / "build/secure-transport/native-v3/upstream/mbedtls-3.6.7/include"
    cmake = frozen / "cmake"
    retained = [cmake / "CMakeFiles/M98TLS.dir" / (n + ".c.obj")
                for n in ("native_runtime", "native_crt", "native_time")]
    retained += [cmake / "libntwst.a"]
    retained += [cmake / "upstream/library" / ("lib" + n + ".a")
                 for n in ("mbedtls", "mbedx509", "mbedcrypto")]
    retained += [cmake / "upstream/3rdparty/everest/libeverest.a",
                 cmake / "upstream/3rdparty/p256-m/libp256m.a"]
    baseline = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    build_receipt = frozen / "build-result.json"
    project = frozen / "project"
    configuration = project / "user_config.h"
    inputs = retained + [baseline, build_receipt, configuration]
    prior = json.loads(build_receipt.read_text())
    if prior["target"] != "win98-x86" or prior["upstream"]["version"] != "3.6.7":
        raise ValueError("require the reviewed native 3.6.7 build")
    for n in ("transport.c", "native_runtime.c", "native_crt.c", "native_time.c", "user_config.h"):
        path = project / n
        if digest(path) != prior["source_sha256"][n]:
            raise ValueError("frozen project source binding changed: " + n)
        inputs.append(path)
    input_hashes = {str(path): digest(path) for path in inputs}
    shutil.copyfile(configuration, output / "user_config.h")
    binary = output / "M98SSPI.dll"
    command = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-march=i486", "-Wall", "-Wextra",
               "-Werror", "-Wpedantic", "-ffunction-sections", "-fdata-sections",
               "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
               '-DMBEDTLS_USER_CONFIG_FILE="user_config.h"', "-I" + str(output),
               "-I" + str(upstream), "-shared", "-nostartfiles", "-static", "-static-libgcc",
               "-Wl,--gc-sections,--no-insert-timestamp,--subsystem,windows:4.10,"
               "--major-os-version,4,--minor-os-version,10,--entry,_M98SspiDllMain@12",
               str(output / "sspi_native.c"), str(output / "sspi_stream.c")]
    command += list(map(str, retained))
    command += [str(output / "sspi_native.def"), "-ladvapi32", "-lcrypt32", "-o", str(binary)]
    proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
    (output / "compiler.stdout").write_text(proc.stdout)
    (output / "compiler.stderr").write_text(proc.stderr)
    audit = None
    passed = False
    if proc.returncode == 0:
        pe = pefile.PE(str(binary))
        exports = sorted(s.name.decode("ascii") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols)
        expected = sorted(("AcquireCredentialsHandleA", "FreeCredentialsHandle", "InitializeSecurityContextA",
                           "DeleteSecurityContext", "QuerySecurityPackageInfoA", "EnumerateSecurityPackagesA",
                           "FreeContextBuffer", "QueryContextAttributesA", "EncryptMessage", "DecryptMessage",
                           "ApplyControlToken", "InitSecurityInterfaceA", "M98SspiEndInput",
                           "ExportSecurityContext", "ImportSecurityContextA"))
        inventory = json.loads(baseline.read_text())["dlls"]
        imports, missing = {}, []
        for row in pe.DIRECTORY_ENTRY_IMPORT:
            dll = row.dll.decode("ascii").upper()
            symbols = [s.name.decode("ascii") if s.name else "#" + str(s.ordinal) for s in row.imports]
            imports[dll] = symbols
            missing += [[dll, s] for s in symbols if s not in inventory.get(dll, [])]
        forbidden = {str(i): pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size for i in (9, 10, 13, 14)}
        relocations = sum(s.type == 3 for row in pe.DIRECTORY_ENTRY_BASERELOC for s in row.entries)
        audit = {"machine": pe.FILE_HEADER.Machine, "optional_magic": pe.OPTIONAL_HEADER.Magic,
                 "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000), "timestamp": pe.FILE_HEADER.TimeDateStamp,
                 "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                 "os_version": [pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, pe.OPTIONAL_HEADER.MinorOperatingSystemVersion],
                 "subsystem_version": [pe.OPTIONAL_HEADER.MajorSubsystemVersion, pe.OPTIONAL_HEADER.MinorSubsystemVersion],
                 "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                 "exports": exports, "exports_exact": exports == expected,
                 "imports": imports, "import_count": sum(map(len, imports.values())),
                 "imports_absent_from_original_win98_inventory": missing,
                 "forbidden_directory_sizes": forbidden, "highlow_relocations": relocations,
                 "bytes": binary.stat().st_size, "sha256": digest(binary)}
        passed = (audit["machine"] == 0x14c and audit["optional_magic"] == 0x10b and audit["dll"]
                  and audit["timestamp"] == 0 and audit["subsystem"] == 2 and audit["os_version"] == [4, 10]
                  and audit["subsystem_version"] == [4, 10] and audit["entry_rva"] != 0 and audit["exports_exact"]
                  and not missing and not any(forbidden.values()) and relocations > 0)
    if hashes != {name: digest(HERE / name) for name in SOURCES} or input_hashes != {
            str(path): digest(path) for path in inputs}:
        passed = False
    receipt = {"schema": "win98modern.sspi-native-pe-build.v1", "passed": passed,
               "source_sha256": hashes, "retained_input_sha256": input_hashes,
               "compiler_argv": command, "compiler_exit": proc.returncode, "audit": audit,
               "real_tls_proven_by_this_test": False, "native_guest_proven": False,
               "native_ROOT_execution_proven": False, "os_provider_registered": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": passed, "native_pe_audit": audit, "receipt": str(output / "receipt.json")}))
    if proc.returncode:
        print(proc.stderr, end="")
    return 0 if passed else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--sanitize", action="store_true")
    p.add_argument("--native", action="store_true", help="strict x86 Win98 DLL build and OEM PE inventory gate")
    args = p.parse_args()
    if args.native and args.sanitize:
        p.error("native PE build and host sanitization are separate evidence domains")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        p.error("preserve previous runs; output must be a new directory")
    output.mkdir(parents=True, mode=0o700)
    hashes = {name: digest(HERE / name) for name in SOURCES}
    for name in SOURCES:
        shutil.copyfile(HERE / name, output / name)
    if args.native:
        return native_build(output, hashes)
    (output / "sspi_native_test_win32.h").write_text(SHIM)
    (output / "driver.c").write_text(DRIVER)
    compiler = "clang" if args.sanitize else "gcc"
    headers = ROOT / "build/secure-transport/native-v3/upstream/mbedtls-3.6.7/include"
    config = ROOT / "build/secure-transport/host-v4-gui/project"
    command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wpedantic", "-pthread", '-DMBEDTLS_USER_CONFIG_FILE="user_config.h"',
               "-I" + str(output), "-I" + str(config), "-I" + str(headers),
               str(output / "driver.c"), "-o", str(output / "abi-model")]
    if args.sanitize:
        command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    commands = [command, [str(output / "abi-model")]]
    runs = []
    for index, cmd in enumerate(commands):
        proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=120)
        (output / f"step-{index}.stdout").write_text(proc.stdout)
        (output / f"step-{index}.stderr").write_text(proc.stderr)
        runs.append({"argv": cmd, "exit": proc.returncode})
        if proc.returncode:
            print(proc.stdout, end="")
            print(proc.stderr, end="")
            break
    passed = len(runs) == 2 and all(row["exit"] == 0 for row in runs)
    model = None
    if len(runs) == 2:
        lines = (output / "step-1.stdout").read_text().splitlines()
        if lines and lines[-1].startswith("{"):
            model = json.loads(lines[-1])
    if hashes != {name: digest(HERE / name) for name in SOURCES}:
        passed = False
    generated = {f.name: digest(f) for f in output.iterdir() if f.is_file()}
    receipt = {"schema": "win98modern.sspi-native-abi-model.v1", "passed": passed,
               "sanitize": args.sanitize, "source_sha256": hashes, "generated_sha256": generated,
               "runs": runs, "model": model, "real_tls_proven": False,
               "native_guest_proven": False, "os_provider_registered": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": passed, "model": model, "receipt": str(output / "receipt.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
