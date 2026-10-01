/* SPDX-License-Identifier: GPL-2.0-only
 * Reuse the frozen independent bytecode oracle, then exercise actual lifetime
 * on repeated HLSL compilation, token discard and post-clone semantic failure.
 */
#define main original_shader_checks_main
#include "compiler_host.c"
#undef main

int main(int argc, char **argv)
{
    static const char good[] = "float4 main(float4 p : POSITION) : SV_Position { return p + float4(1,2,3,0); }";
    static const char *const bad[] = {
        "float4 main( : SV_Position { return nonsense; }",
        "float4 main(float4 p : POSITION) : SV_Position { return unknown_identifier; }",
        "float4 main(float4 p : POSITION) : SV_Position { return p + ; }",
        "float4 main(float4 p : POSITION) { return p; }",
    };
    struct vkd3d_shader_hlsl_source_info hi = {0};
    struct vkd3d_shader_code input, output = {0};
    char *messages = NULL;
    unsigned int i;

    CHECK(original_shader_checks_main(argc, argv) == 0);
    hi.type = VKD3D_SHADER_STRUCTURE_TYPE_HLSL_SOURCE_INFO;
    hi.profile = "vs_4_0";
    hi.entry_point = "main";
    for (i = 0; i < 16; ++i)
    {
        input = (struct vkd3d_shader_code){good, sizeof(good) - 1};
        CHECK(compile(input, VKD3D_SHADER_SOURCE_HLSL, VKD3D_SHADER_TARGET_DXBC_TPF,
                &hi, &output, &messages) == VKD3D_OK);
        CHECK(output.code && output.size == 468);
        vkd3d_shader_free_shader_code(&output);
        vkd3d_shader_free_messages(messages);
        output = (struct vkd3d_shader_code){0};
        messages = NULL;
    }
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
    {
        input = (struct vkd3d_shader_code){bad[i], strlen(bad[i])};
        CHECK(compile(input, VKD3D_SHADER_SOURCE_HLSL, VKD3D_SHADER_TARGET_DXBC_TPF,
                &hi, &output, &messages) < 0);
        CHECK(messages && *messages);
        if (output.code)
            vkd3d_shader_free_shader_code(&output);
        vkd3d_shader_free_messages(messages);
        output = (struct vkd3d_shader_code){0};
        messages = NULL;
    }
    printf("GENUINE_LIFETIME checks=%u repeated_hlsl=16 negative_hlsl=4 PASS\n", checks);
    return 0;
}
