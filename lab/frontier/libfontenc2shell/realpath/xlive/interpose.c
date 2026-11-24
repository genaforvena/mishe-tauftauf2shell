/*
 * W187 test-only LD_PRELOAD interposer.  Not part of any pinned upstream
 * source.  Logs the 131072-byte encoding buffer, every live FontMapRec from
 * FontEncFind, and every FontEncRecode call; supplies the benign marker whose
 * address is baked into a crafted .enc by run-xfptr.sh.
 */
#define _GNU_SOURCE
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <X11/fonts/fontenc.h>

static unsigned lf_marker(unsigned code, void *data)
{
    (void)code; (void)data;
    write(2, "LF_XVFB_MARKER\n", 15);
    return 0xabcd1234u;
}

__attribute__((constructor)) static void lf_init(void)
{
    fprintf(stderr, "LF_MARKER_ADDR=%p\n", (void *)lf_marker);
}

void *reallocarray(void *p, size_t n, size_t s)
{
    static void *(*real_reallocarray)(void *, size_t, size_t);
    void *r;
    if (!real_reallocarray)
        real_reallocarray = dlsym(RTLD_NEXT, "reallocarray");
    r = real_reallocarray(p, n, s);
    if (n * s == 131072)
        fprintf(stderr, "LF_BUF=%p\n", r);
    return r;
}

FontEncPtr FontEncFind(const char *charset, const char *fontfile)
{
    static FontEncPtr (*real_find)(const char *, const char *);
    FontEncPtr e;
    FontMapPtr m;
    int n = 0;
    (void)fontfile;
    if (!real_find)
        real_find = dlsym(RTLD_NEXT, "FontEncFind");
    e = real_find(charset, fontfile);
    fprintf(stderr, "LF_FIND charset=%s enc=%p\n", charset, (void *)e);
    if (e)
        for (m = e->mappings; m; m = m->next)
            fprintf(stderr, "LF_FIND_MAP n=%d m=%p recode=%p\n", ++n,
                    (void *)m, (void *)m->recode);
    return e;
}

unsigned FontEncRecode(unsigned code, FontMapPtr mapping)
{
    static unsigned (*real_recode)(unsigned, void *);
    static int bt_done;
    if (!real_recode)
        real_recode = dlsym(RTLD_NEXT, "FontEncRecode");
    fprintf(stderr, "LF_RECODE_MAP=%p\n", mapping);
    if (!bt_done && getenv("LF_BT")) {
        void *frames[16];
        int n = backtrace(frames, 16);
        fprintf(stderr, "LF_RECODE_BT_BEGIN\n");
        backtrace_symbols_fd(frames, n, 2);
        fprintf(stderr, "LF_RECODE_BT_END\n");
        bt_done = 1;
    }
    return real_recode(code, mapping);
}
