/* rung-4 consumer probe: place a live object immediately after `prefixed`
 * before the overflowing strcat runs, then check whether the one-byte NUL
 * reaches it. Interposes only strcat; the real library and its allocator are
 * otherwise unmodified. The call with a 100-byte source is tar_get_name's
 * strcat(prefixed, name) at parse-tar.c:253. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *canary;
static const size_t canary_len = 64;
static int done;

char *strcat(char *dest, const char *src)
{
    static char *(*real_strcat)(char *, const char *);
    if (!real_strcat)
        real_strcat = dlsym(RTLD_NEXT, "strcat");

    /* prefixed is 156 prefix chars + '/' + NUL when the 100-byte name is
     * appended: strlen(dest) == 157 at the overflowing call. */
    if (!done && strlen(src) == 100 && strlen(dest) == 157) {
        char *result;
        int corrupted = 0;
        done = 1;
        canary = malloc(canary_len);          /* live object after `prefixed` */
        memset(canary, 0x5a, canary_len);
        fprintf(stderr,
                "PROBE dest=%p canary=%p delta=%td canary[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                (void *)dest, (void *)canary, canary - dest,
                (unsigned char)canary[0], (unsigned char)canary[1],
                (unsigned char)canary[2], (unsigned char)canary[3],
                (unsigned char)canary[4], (unsigned char)canary[5],
                (unsigned char)canary[6], (unsigned char)canary[7]);
        result = real_strcat(dest, src);       /* writes the fixed NUL */
        for (size_t i = 0; i < canary_len; i++) {
            if ((unsigned char)canary[i] != 0x5a) {
                corrupted = 1;
                fprintf(stderr, "PROBE canary byte %zu changed to %02x\n",
                        i, (unsigned char)canary[i]);
            }
        }
        fprintf(stderr, "PROBE canary_corrupted=%d\n", corrupted);
        return result;
    }
    return real_strcat(dest, src);
}
