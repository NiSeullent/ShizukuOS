#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Patch a separately frozen native.c copy; never changes the held loader."""
import hashlib
BASE_SHA = "7b3fd939273b0eda2a3c705d64f4cf4df91ac59f26938c294162e95956aa60d2"


def patch(text):
    if hashlib.sha256(text.encode()).hexdigest() != BASE_SHA:
        raise ValueError("exact held native.c base required")
    def replace(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise ValueError("exact native loader seam differs")
        text = text.replace(old, new)
    replace('#include "tls_runtime.h"', '#include "tls_runtime.h"\n#include "ntwin32/resources/native_bridge/bridge.h"')
    replace('int runtime,lock_ready,closing;', 'int runtime,lock_ready,closing;int resource_mode;nrb_registry resources;')
    replace('static FARPROC runtime_hook(const char *);', 'static FARPROC runtime_hook(const char *);\nstatic int resource_prepare(loader *);\nstatic void resource_finish(loader *);\nstatic FARPROC resource_hook(const char *);')
    replace('if(!np_parse(&m->pe,m->file,size,&error)', 'if(active_loader&&active_loader->resource_mode&&!nrb_verify_file(m->name,m->file,size)){line("RESOURCE_PROFILE_BLOCKER=","EXACT_OWN_GRAPH_HASH_REQUIRED");return 0;}\n if(!np_parse(&m->pe,m->file,size,&error)')
    replace('if(!root_path&&native_module(name)){', 'if(!root_path&&native_module(name)){\n  if(l->resource_mode&&!equal_ci(name,"KERNEL32.DLL")){line("RESOURCE_PROFILE_BLOCKER=","ONLY_OWN_GRAPH_AND_KERNEL32");m->state=-2;l->blocked++;return NULL;}')
    replace('LeaveCriticalSection(&l->lock);DeleteCriticalSection(&l->lock);l->lock_ready=0;', 'resource_finish(l);\n  LeaveCriticalSection(&l->lock);DeleteCriticalSection(&l->lock);l->lock_ready=0;')
    replace('static FARPROC runtime_hook(const char *name)\n{', '#include "ntwin32/resources/native_bridge/native_hooks.inc"\nstatic FARPROC runtime_hook(const char *name)\n{\n FARPROC resource=resource_hook(name);if(resource)return resource;')
    replace('l->runtime=execute==2;', 'l->runtime=execute==2||execute==3;l->resource_mode=execute==3;')
    replace('if(l->runtime)EnterCriticalSection(&l->lock);\n {int attached=', 'if(l->resource_mode){int ready;EnterCriticalSection(&l->lock);ready=resource_prepare(l);LeaveCriticalSection(&l->lock);if(!ready){line("EXECUTION_BLOCKER=","RESOURCE_PREPARATION");goto done;}}\n if(l->runtime)EnterCriticalSection(&l->lock);\n {int attached=')
    replace('result=0;line("ENTRY=","RETURNED");}', 'result=0;line("ENTRY=","RETURNED");\n  if(l->resource_mode){typedef DWORD (WINAPI *query_fn)(void);FARPROC query=resolve(l,root,"NtwResourceResult",0,0),checks=resolve(l,root,"NtwResourceChecks",0,0);if(!query||!checks)result=31;else{result=((query_fn)(void *)query)();value("RESOURCE_APP_CHECKS=",((query_fn)(void *)checks)());}}}')
    return text
