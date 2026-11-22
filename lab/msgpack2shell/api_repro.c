/* Real public-API two-migrate reproducer from msgpack/msgpack-c#1197.
 * No struct field is written by this file; init/append_ref/clear/migrate are
 * the only API calls used.  cap/used are read from the public struct fields.
 * argv[1] = number of append_ref calls into A between migrate1 and migrate2
 *           (4 = upstream two-migrate variant, 2 = equal-capacity safe control)
 */
#include <msgpack/vrefbuffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char PAYLOAD[16] = "XXXXXXXXXXXXXXX";

static void dump(const char *tag, msgpack_vrefbuffer *b) {
    printf("%s: cap=%zu used=%zu\n", tag,
           (size_t)(b->end - b->array), (size_t)(b->tail - b->array));
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int second = (argc > 1) ? atoi(argv[1]) : 4;
    msgpack_vrefbuffer A, B;
    int i, rc;

    if (!msgpack_vrefbuffer_init(&A, 0, 0)) return 2;
    if (!msgpack_vrefbuffer_init(&B, 0, 0)) return 2;

    for (i = 0; i < 5; i++) msgpack_vrefbuffer_append_ref(&A, PAYLOAD, 8);
    dump("A before migrate1", &A);
    dump("B before migrate1", &B);
    rc = msgpack_vrefbuffer_migrate(&A, &B);
    printf("migrate1 rc=%d\n", rc);
    dump("A after migrate1", &A);
    dump("B after migrate1", &B);

    for (i = 0; i < second; i++) msgpack_vrefbuffer_append_ref(&A, PAYLOAD, 8);
    printf("migrate2 check: to->tail+nused=%p vbuf->end=%p cmp=%d\n",
           (void*)(B.tail + second), (void*)A.end,
           (B.tail + second) < A.end);
    dump("A before migrate2", &A);
    dump("B before migrate2", &B);
    rc = msgpack_vrefbuffer_migrate(&A, &B);
    printf("migrate2 rc=%d\n", rc);
    dump("A after migrate2", &A);
    dump("B after migrate2", &B);

    msgpack_vrefbuffer_destroy(&A);
    msgpack_vrefbuffer_destroy(&B);
    return 0;
}
