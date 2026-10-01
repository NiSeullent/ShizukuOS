// Copyright (C) 2012-2025 Free Software Foundation, Inc.
//
// This file is part of GCC.
//
// GCC is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3, or (at your option)
// any later version.

// GCC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// Under Section 7 of GPL version 3, you are granted additional
// permissions described in the GCC Runtime Library Exception, version
// 3.1, as published by the Free Software Foundation.

// You should have received a copy of the GNU General Public License and
// a copy of the GCC Runtime Library Exception along with this program;
// see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
// <http://www.gnu.org/licenses/>.

#include <cxxabi.h>
#include <cstdlib>
#include <new>
#include "bits/gthr.h"

#ifdef __USING_MCFGTHREAD__

#include <mcfgthread/cxa.h>

namespace __cxxabiv1 {

extern "C" int
__cxa_thread_atexit (void (_GLIBCXX_CDTOR_CALLABI *dtor)(void *),
		     void *obj, void *dso_handle) _GLIBCXX_NOTHROW
{
  return __MCF_cxa_thread_atexit (dtor, obj, dso_handle);
}

}  // namespace __cxxabiv1

#else // __USING_MCFGTHREAD__

#ifdef _GLIBCXX_THREAD_ATEXIT_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
namespace {
  // The process image already lives until exit. For a DLL acquire a real
  // reference to the module containing the destructor, then retain upstream's
  // balanced FreeLibrary after calling it. Hosts must not unload a DLL while
  // another thread is executing/registering its TLS destructor.
  bool pin_destructor_module_win9x (const void *address, HMODULE *pinned)
  {
    *pinned = nullptr;
    MEMORY_BASIC_INFORMATION info = {};
    if (VirtualQuery (address, &info, sizeof (info)) != sizeof (info)
        || !info.AllocationBase)
      return false;
    HMODULE owner = static_cast<HMODULE>(info.AllocationBase);
    if (owner == GetModuleHandleA (nullptr))
      return true;
    char path[MAX_PATH] = {};
    DWORD length = GetModuleFileNameA (owner, path, MAX_PATH);
    if (!length || length >= MAX_PATH || path[length] != '\0')
      return false;
    HMODULE reference = LoadLibraryA (path);
    if (!reference)
      return false;
    if (reference != owner)
      {
        FreeLibrary (reference);
        return false;
      }
    *pinned = reference;
    return true;
  }
}
#endif
#endif

// Simplify it a little for this file.
#ifndef _GLIBCXX_CDTOR_CALLABI
#  define _GLIBCXX_CDTOR_CALLABI
#endif

#if _GLIBCXX_HAVE___CXA_THREAD_ATEXIT

// Libc provides __cxa_thread_atexit definition.

#elif _GLIBCXX_HAVE___CXA_THREAD_ATEXIT_IMPL

extern "C" int __cxa_thread_atexit_impl (void (_GLIBCXX_CDTOR_CALLABI *func) (void *),
					 void *arg, void *d);
extern "C" int
__cxxabiv1::__cxa_thread_atexit (void (_GLIBCXX_CDTOR_CALLABI *dtor)(void *),
				 void *obj, void *dso_handle)
  _GLIBCXX_NOTHROW
{
  return __cxa_thread_atexit_impl (dtor, obj, dso_handle);
}

#else /* _GLIBCXX_HAVE___CXA_THREAD_ATEXIT_IMPL */

namespace {
  // One element in a singly-linked stack of cleanups.
  struct elt
  {
    void (_GLIBCXX_CDTOR_CALLABI *destructor)(void *);
    void *object;
    elt *next;
#ifdef _GLIBCXX_THREAD_ATEXIT_WIN32
    HMODULE dll;
#endif
  };

  // Keep a per-thread list of cleanups in gthread_key storage.
  __gthread_key_t key;
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
  // The emutls cleanup may exist before the first C++ destructor registration.
  // Publish readiness without consulting an unrelated zero-initialized key.
  volatile LONG key_ready;
#endif
  // But also support non-threaded mode.
  elt *single_thread;

  // Run the specified stack of cleanups.
  void run (void *p)
  {
    elt *e = static_cast<elt*>(p);
    while (e)
      {
	elt *old_e = e;
	e->destructor (e->object);
#ifdef _GLIBCXX_THREAD_ATEXIT_WIN32
	/* Decrement DLL count */
	if (e->dll)
	  FreeLibrary (e->dll);
#endif
	e = e->next;
	delete (old_e);
      }
  }

  // Run the stack of cleanups for the current thread.
  void run ()
  {
    for (;;)
      {
        void *e;
        if (__gthread_active_p ())
          {
            e = __gthread_getspecific (key);
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
            if (__gthread_setspecific (key, nullptr) != 0)
              std::abort ();
#else
            __gthread_setspecific (key, NULL);
#endif
          }
        else
          {
            e = single_thread;
            single_thread = NULL;
          }
        run (e);
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
        // std::exit must drain lists registered by destructors too, before
        // the static key owner deletes its key and emutls later frees cells.
        if (__gthread_active_p () ? !__gthread_getspecific (key) : !single_thread)
          break;
#else
        break;
#endif
      }
  }

  // Initialize the key for the cleanup stack.  We use a static local for
  // key init/delete rather than atexit so that delete is run on dlclose.
  void key_init() {
    struct key_s {
      key_s() {
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
        if (__gthread_key_create (&key, run) != 0)
          std::abort ();
        InterlockedExchange (&key_ready, 1);
#else
        __gthread_key_create (&key, run);
#endif
      }
      ~key_s() {
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
        InterlockedExchange (&key_ready, 0);
        if (__gthread_key_delete (key) != 0)
          std::abort ();
#else
        __gthread_key_delete (key);
#endif
      }
    };
    static key_s ks;
    // Also make sure the destructors are run by std::exit.
    // FIXME TLS cleanups should run before static cleanups and atexit
    // cleanups.
    std::atexit (run);
  }
}

#if __GXX_WEAK__ && _GLIBCXX_MAY_HAVE___CXA_THREAD_ATEXIT_IMPL
extern "C"
int __attribute__ ((__weak__))
__cxa_thread_atexit_impl (void (_GLIBCXX_CDTOR_CALLABI *func) (void *),
			  void *arg, void *d);
#endif

// ??? We can't make it an ifunc, can we?
extern "C" int
__cxxabiv1::__cxa_thread_atexit (void (_GLIBCXX_CDTOR_CALLABI *dtor)(void *),
				 void *obj, [[maybe_unused]] void *dso_handle)
  _GLIBCXX_NOTHROW
{
#if __GXX_WEAK__ && _GLIBCXX_MAY_HAVE___CXA_THREAD_ATEXIT_IMPL
  if (__cxa_thread_atexit_impl)
    // Rely on a (presumably libc-provided) __cxa_thread_atexit_impl,
    // if it happens to be defined, even if configure couldn't find it
    // during the build.  _GLIBCXX_MAY_HAVE___CXA_THREAD_ATEXIT_IMPL
    // may be defined e.g. in os_defines.h on platforms where some
    // versions of libc have a __cxa_thread_atexit_impl definition,
    // but whose earlier versions didn't.  This enables programs build
    // by toolchains compatible with earlier libc versions to still
    // benefit from a libc-provided __cxa_thread_atexit_impl.
    return __cxa_thread_atexit_impl (dtor, obj, dso_handle);
#endif

  // Do this initialization once.
  if (__gthread_active_p ())
    {
      // When threads are active use __gthread_once.
      static __gthread_once_t once = __GTHREAD_ONCE_INIT;
      __gthread_once (&once, key_init);
    }
  else
    {
      // And when threads aren't active use a static local guard.
      static bool queued;
      if (!queued)
	{
	  queued = true;
	  std::atexit (run);
	}
    }

  elt *first;
  if (__gthread_active_p ())
    first = static_cast<elt*>(__gthread_getspecific (key));
  else
    first = single_thread;

  elt *new_elt = new (std::nothrow) elt;
  if (!new_elt)
    return -1;
  new_elt->destructor = dtor;
  new_elt->object = obj;
  new_elt->next = first;
#ifdef _GLIBCXX_THREAD_ATEXIT_WIN32
  /* Store the DLL address for a later call to FreeLibrary in new_elt and
     increment DLL load count.  This blocks the unloading of the DLL
     before the thread-local dtors have been called.  This does NOT help
     if FreeLibrary/dlclose is called in excess. */
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
  if (!pin_destructor_module_win9x (reinterpret_cast<const void *>(dtor),
                                  &new_elt->dll))
    {
      delete new_elt;
      // GCC's generated TLS initializer ignores this ABI return value. A
      // new platform pin failure must stop instead of losing the destructor.
      std::abort ();
    }
#else
  GetModuleHandleExW (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		      (LPCWSTR) dtor, &new_elt->dll);
#endif
#endif

  if (__gthread_active_p ())
    {
#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
      if (__gthread_setspecific (key, new_elt) != 0)
        {
          if (new_elt->dll)
            FreeLibrary (new_elt->dll);
          delete new_elt;
          std::abort ();
        }
#else
      __gthread_setspecific (key, new_elt);
#endif
    }
  else
    single_thread = new_elt;

  return 0;
}

#if defined(IEWEBKIT_WIN9X) && IEWEBKIT_WIN9X
// Called by the genuine libgcc emutls destructor while its original TLS cells
// are still installed. Clear each saved list before invoking it, then drain
// lists registered by destructors too. The later pthread key callback sees an
// empty list and cannot invoke a destructor for an already freed emutls cell.
extern "C" void
__cxa_thread_atexit_emutls_drain ()
{
  if (__gthread_active_p ())
    {
      if (!InterlockedCompareExchange (&key_ready, 0, 0))
        return;
      for (;;)
        {
          void *pending = __gthread_getspecific (key);
          if (!pending)
            break;
          if (__gthread_setspecific (key, nullptr) != 0)
            std::abort ();
          run (pending);
        }
    }
  else
    {
      while (single_thread)
        run ();
    }
}
#endif

#endif /* _GLIBCXX_HAVE___CXA_THREAD_ATEXIT_IMPL */

#endif // __USING_MCFGTHREAD__
