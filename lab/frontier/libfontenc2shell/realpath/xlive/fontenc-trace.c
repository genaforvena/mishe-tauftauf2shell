/* Observation-only LD_PRELOAD shim: log libfontenc public calls made by the X
 * server, then forward to the real (pinned, vulnerable) library. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

void *FontEncFind(const char *name, const char *file)
{
    static void *(*real)(const char *, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "FontEncFind");
    fprintf(stderr, "LFTRACE FontEncFind name=%s file=%s\n",
            name ? name : "(null)", file ? file : "(null)");
    return real(name, file);
}

void *FontEncMapFind(const char *name, int type, int pid, int eid,
                     const char *file)
{
    static void *(*real)(const char *, int, int, int, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "FontEncMapFind");
    fprintf(stderr, "LFTRACE FontEncMapFind name=%s file=%s\n",
            name ? name : "(null)", file ? file : "(null)");
    return real(name, type, pid, eid, file);
}

void *FontEncReallyLoad(const char *name, const char *file)
{
    static void *(*real)(const char *, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "FontEncReallyLoad");
    fprintf(stderr, "LFTRACE FontEncReallyLoad name=%s file=%s\n",
            name ? name : "(null)", file ? file : "(null)");
    return real(name, file);
}

char *FontEncFromXLFD(const char *name, int length)
{
    static char *(*real)(const char *, int);
    if (!real) real = dlsym(RTLD_NEXT, "FontEncFromXLFD");
    char *r = real(name, length);
    fprintf(stderr, "LFTRACE FontEncFromXLFD -> %s\n", r ? r : "(null)");
    return r;
}
