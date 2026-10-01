#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exact, reviewable HLSL ownership repair; never modify the pinned originals."""
import difflib
import hashlib
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(wine, destination):
    shader = Path(wine) / 'libs/vkd3d/libs/vkd3d-shader'
    destination.mkdir()
    records, patches = {}, []
    for name in ('hlsl_codegen.c', 'hlsl.y'):
        original = shader / name
        before = original.read_text()
        if name == 'hlsl.y':
            anchor = '%token <name> TYPE_IDENTIFIER\n'
            assert before.count(anchor) == 1
            after = before.replace(anchor, anchor + '\n%destructor { vkd3d_free($$); } <name>\n')
        else:
            start = before.index('int hlsl_emit_vsir(')
            prefix, function = before[:start], before[start:]
            # This is the final function in the exact original source file.
            assert function.rstrip().endswith('return ctx->result;\n}')
            anchor = '    hlsl_block_init(&global_uniform_block);\n'
            assert function.count(anchor) == 1
            function = function.replace(anchor, anchor + '    hlsl_block_init(&body);\n    hlsl_block_init(&patch_body);\n')
            anchor = '    hlsl_block_cleanup(&global_uniform_block);\n\n'
            assert function.count(anchor) == 1
            function = function.replace(anchor, '')
            # Attribute parsing precedes allocation and retains its early return.
            first = function.index('    process_entry_function(ctx, &semantic_vars, &body,')
            head, tail = function[:first], function[first:]
            assert tail.count('return ctx->result;') == 5
            tail = tail.replace('return ctx->result;', 'goto cleanup;', 4)
            anchor = '    return ctx->result;\n}'
            assert tail.count(anchor) == 1
            tail = tail.replace(anchor, 'cleanup:\n    hlsl_block_cleanup(&patch_body);\n'
                '    hlsl_block_cleanup(&body);\n    hlsl_block_cleanup(&global_uniform_block);\n'
                '\n    return ctx->result;\n}')
            after = prefix + head + tail
        prepared = destination / name
        prepared.write_text(after)
        prepared.chmod(0o400)
        records[name] = {'original': str(original), 'original_sha256': sha(original),
                        'prepared': str(prepared), 'prepared_sha256': sha(prepared)}
        patches.extend(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                      fromfile='a/libs/vkd3d/libs/vkd3d-shader/' + name,
                      tofile='b/libs/vkd3d/libs/vkd3d-shader/' + name))
    patch = destination / 'vkd3d-hlsl-lifetime.patch'
    patch.write_text(''.join(patches))
    patch.chmod(0o400)
    return records, {'path': str(patch), 'sha256': sha(patch)}
