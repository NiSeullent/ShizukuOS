/* SPDX-License-Identifier: GPL-2.0-only
 * Real upstream HLSL -> DXBC -> SPIR-V and pinned DXBC -> assembly checks.
 * Generated SPIR-V is inspected structurally, not run on a Vulkan device.
 */
#include "vkd3d_shader.h"
#include "vkd3d_shader_private.h"
#include "fixture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static int compile(struct vkd3d_shader_code input, enum vkd3d_shader_source_type source,
        enum vkd3d_shader_target_type target, const void *next,
        struct vkd3d_shader_code *output, char **messages)
{
    struct vkd3d_shader_compile_info ci={0};
    ci.type=VKD3D_SHADER_STRUCTURE_TYPE_COMPILE_INFO;ci.next=next;
    ci.source=input;ci.source_type=source;ci.target_type=target;
    ci.log_level=VKD3D_SHADER_LOG_INFO;ci.source_name="owned-real-shader-test";
    return vkd3d_shader_compile(&ci,output,messages);
}
static void save(const char *directory,const char *name,struct vkd3d_shader_code code)
{
    char path[2048];FILE *f;
    CHECK(code.size>0 && code.size<1024*1024);
    CHECK(snprintf(path,sizeof(path),"%s/%s",directory,name)>0);
    CHECK((f=fopen(path,"wb"))!=NULL);
    CHECK(fwrite(code.code,1,code.size,f)==code.size);
    CHECK(!fclose(f));
}
static unsigned inspect_spirv(struct vkd3d_shader_code code)
{
    const uint32_t *w=code.code;
    size_t i=5,n=code.size/4;
    unsigned entries=0,functions=0,returns=0,stores=0,adds=0,floats=0;
    CHECK(code.size>=20 && !(code.size%4));
    CHECK(w[0]==0x07230203 && w[1]>=0x00010000 && w[1]<=0x00010600);
    CHECK(w[3]>0 && w[3]<100000 && w[4]==0);
    while(i<n) {
        unsigned count=w[i]>>16,op=w[i]&65535;
        CHECK(count && count<=n-i);
        if(op==15) { CHECK(count>=4 && w[i+1]==0); ++entries; } /* Vertex */
        if(op==54) ++functions;
        if(op==253) ++returns;
        if(op==62) ++stores;
        if(op==129) ++adds; /* genuine floating-point vector addition */
        if(op==22) { CHECK(count==3 && w[i+2]==32); ++floats; }
        i+=count;
    }
    CHECK(i==n && entries==1 && functions>=1 && returns>=1 && stores>=1 && adds>=1 && floats>=1);
    return (unsigned)n;
}
int main(int argc,char **argv)
{
    static const char hlsl[]="float4 main(float4 p : POSITION) : SV_Position { return p + float4(1,2,3,0); }";
    static const char bad[]="float4 main( : SV_Position { return nonsense; }";
    struct vkd3d_shader_hlsl_source_info hi={0};
    struct vkd3d_shader_code source={hlsl,sizeof(hlsl)-1},dxbc={0},spv={0},spv2={0},assembly={0},invalid={bad,sizeof(bad)-1};
    struct vkd3d_shader_code fixture={fixture_vs_4_1,sizeof(fixture_vs_4_1)},bad_dxbc={0};
    _Alignas(uint32_t) unsigned char mutable[sizeof(fixture_vs_4_1)];
    struct vkd3d_shader_dxbc_desc d={0};
    char *messages=NULL,*text;
    unsigned words;
    size_t i;
    CHECK(argc==2);
    hi.type=VKD3D_SHADER_STRUCTURE_TYPE_HLSL_SOURCE_INFO;hi.profile="vs_4_0";hi.entry_point="main";
    CHECK(compile(source,VKD3D_SHADER_SOURCE_HLSL,VKD3D_SHADER_TARGET_DXBC_TPF,&hi,&dxbc,&messages)==VKD3D_OK);
    vkd3d_shader_free_messages(messages);messages=NULL;
    CHECK(vkd3d_shader_parse_dxbc(&dxbc,0,&d,NULL)==VKD3D_OK);
    CHECK(d.tag==0x43425844 && d.version==1 && d.section_count>=3);
    vkd3d_shader_free_dxbc(&d);
    CHECK(compile(dxbc,VKD3D_SHADER_SOURCE_DXBC_TPF,VKD3D_SHADER_TARGET_SPIRV_BINARY,NULL,&spv,&messages)==VKD3D_OK);
    vkd3d_shader_free_messages(messages);messages=NULL;
    words=inspect_spirv(spv);
    CHECK(compile(dxbc,VKD3D_SHADER_SOURCE_DXBC_TPF,VKD3D_SHADER_TARGET_SPIRV_BINARY,NULL,&spv2,&messages)==VKD3D_OK);
    CHECK(spv2.size==spv.size && !memcmp(spv2.code,spv.code,spv.size));
    vkd3d_shader_free_shader_code(&spv2);vkd3d_shader_free_messages(messages);messages=NULL;
    CHECK(compile(fixture,VKD3D_SHADER_SOURCE_DXBC_TPF,VKD3D_SHADER_TARGET_D3D_ASM,NULL,&assembly,&messages)==VKD3D_OK);
    vkd3d_shader_free_messages(messages);messages=NULL;
    CHECK((text=malloc(assembly.size+1))!=NULL);memcpy(text,assembly.code,assembly.size);text[assembly.size]=0;
    CHECK(strstr(text,"vs_4_1") && strstr(text,"dp4") && strstr(text,"dcl_input"));free(text);
    save(argv[1],"original-hlsl.dxbc",dxbc);save(argv[1],"actual-vertex.spv",spv);save(argv[1],"pinned-vs-4-1.asm",assembly);
    CHECK(compile(invalid,VKD3D_SHADER_SOURCE_HLSL,VKD3D_SHADER_TARGET_DXBC_TPF,&hi,&bad_dxbc,&messages)<0);
    CHECK(messages && *messages);vkd3d_shader_free_messages(messages);messages=NULL;
    if(bad_dxbc.code)vkd3d_shader_free_shader_code(&bad_dxbc);
    bad_dxbc=(struct vkd3d_shader_code){0};
    /* Valid-checksum invalid instruction stream must reach and fail decoder. */
    memcpy(mutable,fixture_vs_4_1,sizeof(mutable));((uint32_t *)mutable)[54]=0xffffffffu;
    vkd3d_compute_md5(mutable+20,sizeof(mutable)-20,(uint32_t *)mutable+1,VKD3D_MD5_DXBC);
    invalid.code=mutable;invalid.size=sizeof(mutable);
    CHECK(compile(invalid,VKD3D_SHADER_SOURCE_DXBC_TPF,VKD3D_SHADER_TARGET_D3D_ASM,NULL,&bad_dxbc,&messages)<0);
    vkd3d_shader_free_messages(messages);messages=NULL;
    if(bad_dxbc.code)vkd3d_shader_free_shader_code(&bad_dxbc);
    for(i=0;i<16;++i) {
        struct vkd3d_shader_code repeat={0};
        CHECK(compile(dxbc,VKD3D_SHADER_SOURCE_DXBC_TPF,VKD3D_SHADER_TARGET_SPIRV_BINARY,NULL,&repeat,NULL)==0);
        CHECK(repeat.size==spv.size && !memcmp(repeat.code,spv.code,spv.size));vkd3d_shader_free_shader_code(&repeat);
    }
    printf("GENUINE_SHADER checks=%u hlsl_dxbc_bytes=%zu spirv_words=%u pinned_assembly_bytes=%zu negative_decoder=1 cleanup=1 PASS\n",checks,dxbc.size,words,assembly.size);
    vkd3d_shader_free_shader_code(&assembly);vkd3d_shader_free_shader_code(&spv);vkd3d_shader_free_shader_code(&dxbc);
    return 0;
}
