/* W174: decode a large valid row 0, then forged row 1, in one process.
 * Unlike W172's groom_harness.c the destination is a contiguous flat deep
 * buffer: generic_unpack_deep() copies all samples of a valid row there. */
#include <openexr.h>
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char** argv)
{
    exr_context_t ctxt = NULL;
    exr_context_initializer_t ci = EXR_DEFAULT_CONTEXT_INITIALIZER;
    const int W = 16, NSAMP = 1024;
    float* deep_data = NULL;
    int y;

    setvbuf (stdout, NULL, _IONBF, 0);
    if (argc < 2) return 2;
    if (exr_start_read (&ctxt, argv[1], &ci) != EXR_ERR_SUCCESS) return 3;
    deep_data = (float*) calloc ((size_t) W * NSAMP, sizeof (float));
    if (!deep_data) return 6;

    for (y = 0; y < 2; ++y) {
        exr_chunk_info_t cinfo = { 0 };
        exr_decode_pipeline_t dec = EXR_DECODE_PIPELINE_INITIALIZER;
        exr_result_t rv = exr_read_scanline_chunk_info (ctxt, 0, y, &cinfo);
        printf ("CHUNK y=%d rv=%d packed=%llu unpacked=%llu\n", y, (int) rv,
                (unsigned long long) cinfo.packed_size,
                (unsigned long long) cinfo.unpacked_size);
        if (rv != EXR_ERR_SUCCESS) return 4;
        rv = exr_decoding_initialize (ctxt, 0, &cinfo, &dec);
        if (rv != EXR_ERR_SUCCESS) return 5;
        for (int c = 0; c < dec.channel_count; ++c) {
            dec.channels[c].decode_to_ptr = (uint8_t*) deep_data;
            dec.channels[c].user_pixel_stride = NSAMP * sizeof (float);
            dec.channels[c].user_line_stride = W * NSAMP * sizeof (float);
        }
        rv = exr_decoding_choose_default_routines (ctxt, 0, &dec);
        if (rv != EXR_ERR_SUCCESS) return 7;
        rv = exr_decoding_run (ctxt, 0, &dec);
        printf ("DECODE y=%d rv=%d %s\n", (int) y, (int) rv,
                exr_get_error_code_as_string (rv));
        exr_decoding_destroy (ctxt, &dec);
    }
    exr_finish (&ctxt);
    free (deep_data);
    return 0;
}
