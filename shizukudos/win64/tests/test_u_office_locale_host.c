/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the production locale initialization/lock protocol with a real
 * recursive pthread mutex adapter. Native critical-section behavior is
 * independently exercised by t_u_office_locale in the guest.
 */
#define _GNU_SOURCE
#define SHZ_HOST_TEST
#define SHZ_UCRT_LOCALE_HOST_TEST
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef pthread_mutex_t os_critsec;
static unsigned initialization_count;
static void InitializeCriticalSection(os_critsec *lock)
{
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) ||
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) ||
        pthread_mutex_init(lock, &attr) || pthread_mutexattr_destroy(&attr))
        abort();
    ++initialization_count;
    /* Force simultaneous first callers to observe the initializing state. */
    usleep(10000);
}
static void EnterCriticalSection(os_critsec *lock)
{
    if (pthread_mutex_lock(lock)) abort();
}
static void LeaveCriticalSection(os_critsec *lock)
{
    if (pthread_mutex_unlock(lock)) abort();
}
static void Sleep(unsigned ms) { if (ms) usleep(ms * 1000); else sched_yield(); }
#include "../dlls/ucrtbase/ucrt_office_locale.c"

static unsigned checks;
#define VERIFY(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL: line %d: %s\n", __LINE__, #c); abort(); } } while (0)

static pthread_barrier_t start;
static unsigned counter;
static void *racer(void *unused)
{
    unsigned i;
    (void)unused;
    pthread_barrier_wait(&start);
    for (i = 0; i < 5000; ++i) {
        _lock_locales();
        _lock_locales();
        ++counter;
        _unlock_locales();
        _unlock_locales();
    }
    return NULL;
}

static int contender_started, contender_acquired;
static void *contender(void *unused)
{
    (void)unused;
    __atomic_store_n(&contender_started, 1, __ATOMIC_RELEASE);
    _lock_locales();
    __atomic_store_n(&contender_acquired, 1, __ATOMIC_RELEASE);
    _unlock_locales();
    return NULL;
}

int main(void)
{
    pthread_t threads[12], other;
    unsigned i;
    VERIFY(pthread_barrier_init(&start, NULL, 13) == 0);
    for (i = 0; i < 12; ++i) VERIFY(pthread_create(&threads[i], NULL, racer, NULL) == 0);
    pthread_barrier_wait(&start);
    for (i = 0; i < 12; ++i) VERIFY(pthread_join(threads[i], NULL) == 0);
    VERIFY(initialization_count == 1);
    VERIFY(__atomic_load_n(&g_locale_lock_state, __ATOMIC_ACQUIRE) == 2);
    VERIFY(counter == 60000);
    VERIFY(pthread_barrier_destroy(&start) == 0);

    _lock_locales();
    _lock_locales();
    VERIFY(pthread_create(&other, NULL, contender, NULL) == 0);
    while (!__atomic_load_n(&contender_started, __ATOMIC_ACQUIRE)) sched_yield();
    usleep(20000);
    VERIFY(!__atomic_load_n(&contender_acquired, __ATOMIC_ACQUIRE));
    _unlock_locales();
    usleep(20000);
    VERIFY(!__atomic_load_n(&contender_acquired, __ATOMIC_ACQUIRE));
    _unlock_locales();
    VERIFY(pthread_join(other, NULL) == 0);
    VERIFY(__atomic_load_n(&contender_acquired, __ATOMIC_ACQUIRE));
    VERIFY(pthread_mutex_destroy(&g_locale_lock) == 0);
    printf("OFFICE-LOCALE-HOST: %u checks passed; 60000 protected updates, recursive ownership, concurrent initialization\n", checks);
    return 0;
}
