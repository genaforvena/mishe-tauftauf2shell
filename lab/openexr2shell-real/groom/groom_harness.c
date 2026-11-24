/* W172: decode valid chunk 0, then forged chunk 1, in one process. */
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
    float** deep_ptrs = NULL;
    int y;

    setvbuf (stdout, NULL, _IONBF, 0);
    if (argc < 2) return 2;
    if (exr_start_read (&ctxt, argv[1], &ci) != EXR_ERR_SUCCESS) return 3;
    deep_data = (float*) calloc ((size_t) W * NSAMP, sizeof (float));
    deep_ptrs = (float**) calloc ((size_t) W, sizeof (float*));
    if (!deep_data || !deep_ptrs) return 6;
    for (int i = 0; i < W; ++i) deep_ptrs[i] = deep_data + (size_t) i * NSAMP;

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
            dec.channels[c].decode_to_ptr = (uint8_t*) deep_ptrs;
            dec.channels[c].user_pixel_stride = sizeof (float*);
            dec.channels[c].user_line_stride = W * sizeof (float*);
        }
        rv = exr_decoding_choose_default_routines (ctxt, 0, &dec);
        if (rv != EXR_ERR_SUCCESS) return 7;
        rv = exr_decoding_run (ctxt, 0, &dec);
        printf ("DECODE y=%d rv=%d %s\n", y, (int) rv,
                exr_get_error_code_as_string (rv));
        exr_decoding_destroy (ctxt, &dec);
    }
    exr_finish (&ctxt);
    free (deep_ptrs);
    free (deep_data);
    return 0;
}
