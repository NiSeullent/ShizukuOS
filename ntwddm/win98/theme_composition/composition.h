/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_COMPOSITION_H
#define M98_COMPOSITION_H
#ifdef COMPOSITION_HOST_TEST
#include "winmock.h"
#else
#include <windows.h>
#endif
#define COMPOSE_WIDTH 456
#define COMPOSE_HEIGHT 264
#define COMPOSE_REGIONS 7
typedef HRESULT (WINAPI *compose_background)(HANDLE,HDC,int,int,const RECT *,const RECT *);
typedef HRESULT (WINAPI *compose_text)(HANDLE,HDC,int,int,LPCWSTR,int,DWORD,DWORD,const RECT *);
typedef struct {
    DWORD background_samples, background_mismatches, memory_reads_invalid;
    DWORD reference_ink[COMPOSE_REGIONS], actual_ink[COMPOSE_REGIONS];
    DWORD text_pixel_mismatches[COMPOSE_REGIONS];
    DWORD screen_samples, screen_mismatches, screen_reads_invalid, screen_bpp;
    DWORD cleanup_errors, api_stage;
    int memory_valid, transfer_succeeded;
} compose_report;
int compose_scene(HDC target, DWORD style, HANDLE window_theme, HANDLE button_theme,
                  compose_background background, compose_text text, compose_report *report);
#endif
