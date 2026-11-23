/* Deep-tile Core decode shape: exr_read_tile_chunk_info -> exr_decoding_run,
 * no decode_flags. Counterpart of flat_harness.c for the advisory's tiled claim. */
#include <openexr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    const int                 W = 64, H = 1, NSAMP = 1024;

    setvbuf (stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf (stderr, "usage: %s file.exr [prepass]\n", argv[0]);
        return 2;
    }

    rv = exr_start_read (&ctxt, argv[1], &cxt_init);
    printf ("START rv=%d\n", (int) rv);
    if (rv != EXR_ERR_SUCCESS) return 3;

    rv = exr_read_tile_chunk_info (ctxt, 0, 0, 0, 0, 0, &cinfo);
    printf ("TILECHUNK rv=%d packed=%llu unpacked=%llu width=%d height=%d\n",
            (int) rv, (unsigned long long) cinfo.packed_size,
            (unsigned long long) cinfo.unpacked_size, cinfo.width,
            cinfo.height);
    if (rv != EXR_ERR_SUCCESS) return 4;

    rv = exr_decoding_initialize (ctxt, 0, &cinfo, &decode);
    printf ("INIT rv=%d channels=%d\n", (int) rv, (int) decode.channel_count);
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
    if (argc > 2 && strcmp (argv[2], "prepass") == 0)
        decode.decode_flags = EXR_DECODE_SAMPLE_DATA_ONLY;

    rv = exr_decoding_choose_default_routines (ctxt, 0, &decode);
    printf ("ROUTINES rv=%d\n", (int) rv);
    if (rv != EXR_ERR_SUCCESS) return 7;

    printf ("RUN flags=%u\n", (unsigned) decode.decode_flags);
    rv = exr_decoding_run (ctxt, 0, &decode);
    printf ("DECODE rv=%d %s\n", (int) rv, exr_get_error_code_as_string (rv));
    fflush (stdout);

    exr_decoding_destroy (ctxt, &decode);
    exr_finish (&ctxt);
    free (deep_ptrs);
    free (deep_data);
    return rv == EXR_ERR_SUCCESS ? 0 : 1;
}
