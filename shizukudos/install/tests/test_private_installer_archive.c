/* SPDX-License-Identifier: GPL-2.0-only */
/* Host firmware/IRQ/PMM fixture only. Real parser, namespace and snapshots. */
#define main original_host_fixture_unused
#include "../../kernel64/host/test_archive_source.c"
#undef main
int main(int argc,char **argv)
{
 FILE *input;long length;uint8_t *bytes,*copy;unsigned role;
 shz_bootinfo_t bi={0};
 const char *paths[2]={"C:\\SHZ\\SETUP\\NATIVE\\MANIFEST.JSON","C:\\SHZ\\SETUP\\NATIVE\\ESP.SIM"};
 if(argc!=2)return 2;
 input=fopen(argv[1],"rb");if(!input)return 2;
 if(fseek(input,0,SEEK_END)||(length=ftell(input))<=0||fseek(input,0,SEEK_SET))return 2;
 bytes=malloc((size_t)length);if(!bytes||fread(bytes,1,(size_t)length,input)!=(size_t)length)return 2;
 fclose(input);fs_init();CHECK(fs_load_archive(bytes,(uint64_t)length)==6);
 bi.magic=SHZ_BOOTINFO_MAGIC;bi.abi_major=SHZ_ABI_MAJOR;bi.size=sizeof bi;bi.domain_id=SHZ_DOM_KERNEL64;
 bi.flags=SHZ_BIF_UEFI_DIRECT;bi.initrd_gpa=(uint64_t)(uintptr_t)bytes;bi.initrd_size=(uint64_t)length;
 bi.ram_size=bi.initrd_gpa+(uint64_t)length;
 bi.storage.magic=SHZ_STORAGE_MAGIC;bi.storage.version=SHZ_STORAGE_VERSION;
 bi.storage.size=sizeof bi.storage;bi.storage.flags=SHZ_STORAGE_ARCHIVE_READ;
 bi.storage.boot.version=SHZ_STORAGE_VERSION;bi.storage.boot.size=sizeof bi.storage.boot;
 bi.storage.boot.transport=SHZ_STORAGE_SATA;bi.storage.boot.device=31;bi.storage.boot.function=2;
 bi.storage.boot.unit=0;bi.storage.boot.multiplier=0xffff;
 bi.storage.boot.sectors=1000;bi.storage.boot.block_size=2048;
 bi.storage.boot.media_flags=SHZ_STORAGE_READONLY|SHZ_STORAGE_REMOVABLE;
 bi.storage.archive=bi.storage.boot;bi.storage.archive_gpa=bi.initrd_gpa;bi.storage.archive_size=bi.initrd_size;
 CHECK(archive_source_bind_origin(&bi,bytes,(uint64_t)length)==0);
 for(role=0;role<2;role++){
  archive_source_t *handle=0;archive_source_info_t info;fsnode_t *node=fs_lookup(paths[role]);unsigned j;
  CHECK(node&&node->readonly&&node->backing==FSB_RAM);
  if(!node)return 2;
  CHECK(archive_source_open(owner,paths[role],&handle,&info)==0);
  copy=malloc((size_t)info.bytes);if(!copy)return 2;
  CHECK(archive_source_read(owner,handle,&info,0,copy,info.bytes)==0);
  CHECK(info.bytes==node->size&&!memcmp(copy,node->data,(size_t)info.bytes));
  printf("role=%u bytes=%llu sha256=",role,(unsigned long long)info.bytes);
  for(j=0;j<32;j++){printf("%02x",info.sha256[j]);}
  printf("\n");
  CHECK(archive_source_close(owner,handle,&info)==0);free(copy);
 }
 CHECK(pages_allocated==pages_freed);
 printf("PACKAGED_NATIVE_NODES checks=%u failures=%u actual_parser_namespace_snapshot=1 host_firmware_PMM_modeled=1 producer_approved=0 VM_executed=0\n",checks,failures);
 /* Namespace retains initrd and table pointers until host process exit. */
 return failures?1:0;
}
