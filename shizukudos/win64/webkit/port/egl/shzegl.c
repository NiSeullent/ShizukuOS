/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: EGL without a GPU. The Shizuku runtime has no OpenGL/Direct3D driver (GPU.md), so
 * every display query fails with EGL_NOT_INITIALIZED/EGL_BAD_DISPLAY and WebCore and Skia stay on their unaccelerated
 * paths. Only the entry points WebCore/Skia reference are defined (found by the link). */
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <stddef.h>

static EGLint last_error = EGL_SUCCESS;

EGLint EGLAPIENTRY eglGetError(void)
{
    EGLint e = last_error;
    last_error = EGL_SUCCESS;
    return e;
}

EGLDisplay EGLAPIENTRY eglGetDisplay(EGLNativeDisplayType display)
{
    (void)display;
    last_error = EGL_BAD_DISPLAY;
    return EGL_NO_DISPLAY;
}

EGLDisplay EGLAPIENTRY eglGetPlatformDisplay(EGLenum platform, void *display, const EGLAttrib *attribs)
{
    (void)platform; (void)display; (void)attribs;
    last_error = EGL_BAD_DISPLAY;
    return EGL_NO_DISPLAY;
}

EGLDisplay EGLAPIENTRY eglGetPlatformDisplayEXT(EGLenum platform, void *display, const EGLint *attribs)
{
    (void)platform; (void)display; (void)attribs;
    last_error = EGL_BAD_DISPLAY;
    return EGL_NO_DISPLAY;
}

EGLBoolean EGLAPIENTRY eglInitialize(EGLDisplay dpy, EGLint *major, EGLint *minor)
{
    (void)dpy; (void)major; (void)minor;
    last_error = EGL_BAD_DISPLAY;
    return EGL_FALSE;
}

EGLBoolean EGLAPIENTRY eglTerminate(EGLDisplay dpy)
{
    (void)dpy;
    return EGL_TRUE;
}

__eglMustCastToProperFunctionPointerType EGLAPIENTRY eglGetProcAddress(const char *name)
{
    (void)name;
    return NULL;
}

const char *EGLAPIENTRY eglQueryString(EGLDisplay dpy, EGLint name)
{
    (void)dpy; (void)name;
    last_error = EGL_BAD_DISPLAY;
    return NULL;
}
