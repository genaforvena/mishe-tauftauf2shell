/* Lab-only instrument: replace nfcapd's wall clock for one experiment.
 * Intercepts only gettimeofday(), the sole source of fs->received in the
 * pinned collector (nfcapd.c:343, :442).  clock_gettime(CLOCK_MONOTONIC)
 * and time() are untouched.  Without LAB_CLOCK_MS this delegates directly.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/time.h>

int gettimeofday(struct timeval *tv, void *tz)
{
    static int (*real_gettimeofday)(struct timeval *, void *);
    const char *s;
    long long ms;

    if (!real_gettimeofday)
        real_gettimeofday = dlsym(RTLD_NEXT, "gettimeofday");
    s = getenv("LAB_CLOCK_MS");
    if (!s || !*s)
        return real_gettimeofday(tv, tz);
    ms = strtoll(s, NULL, 10);
    if (ms < 0)
        return real_gettimeofday(tv, tz);
    if (tv) {
        tv->tv_sec = (time_t)(ms / 1000);
        tv->tv_usec = (suseconds_t)((ms % 1000) * 1000);
    }
    return 0;
}
