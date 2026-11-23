/* Flat Core decode under a guarded allocator: measure real heap overwrite.
 * Each allocation gets a distinct fill byte, a 16 KiB guard of the inverse,
 * and frees are deferred so post-decode inspection sees overwritten guards. */
#include <openexr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUARD 16384
#define MAXALLOCS 8192

typedef struct {
    size_t   bytes;
    uint8_t* raw;
    uint8_t* user;
    int      index;
} allocation_t;

static allocation_t allocations[MAXALLOCS];
static int          nallocs = 0;

static void*
guarded_alloc (size_t bytes)
{
    uint8_t pattern;
    uint8_t* raw;
    allocation_t* a;
    if (nallocs >= MAXALLOCS) return NULL;
    raw = (uint8_t*) malloc (sizeof (size_t) + bytes + GUARD);
    if (!raw) return NULL;
    a = &allocations[nallocs];
    pattern = (uint8_t) ((nallocs * 37 + 11) & 0xff);
    *(size_t*) raw = bytes;
    a->raw = raw;
    a->user = raw + sizeof (size_t);
    a->bytes = bytes;
    a->index = nallocs;
    memset (a->user, pattern, bytes);
    memset (a->user + bytes, (uint8_t) ~pattern, GUARD);
    ++nallocs;
    return a->user;
}

static void
guarded_free (void* ptr)
{
    /* Deferred: never release, so overwritten guard bytes survive. */
    (void) ptr;
}

static int
allocation_index (const void* p)
{
    for (int i = 0; i < nallocs; ++i)
        if (allocations[i].user == p) return i;
    return -1;
}

static void
report_guards (const char* tag)
{
    size_t total = 0;
    printf ("GUARDS %s nallocs=%d\n", tag, nallocs);
    for (int i = 0; i < nallocs; ++i) {
        allocation_t* a = &allocations[i];
        uint8_t expected = (uint8_t) ~((i * 37 + 11) & 0xff);
        size_t changed = 0, first = (size_t) -1;
        for (size_t j = 0; j < GUARD; ++j) {
            if (a->user[a->bytes + j] != expected) {
                if (first == (size_t) -1) first = j;
                ++changed;
            }
        }
        if (changed) {
            printf ("GUARD-CHANGE alloc=%d size=%zu changed=%zu first=+%zu "
                    "expected=0x%02x actual@first=0x%02x\n",
                    i, a->bytes, changed, first, expected,
                    a->user[a->bytes + first]);
            total += changed;
        }
    }
    printf ("GUARD-TOTAL %s changed=%zu\n", tag, total);
}

int
main (int argc, char** argv)
{
    exr_context_t          ctxt = NULL;
    exr_context_initializer_t cxt_init = EXR_DEFAULT_CONTEXT_INITIALIZER;
    exr_chunk_info_t       cinfo = { 0 };
    exr_decode_pipeline_t  decode = EXR_DECODE_PIPELINE_INITIALIZER;
    exr_result_t           rv;
    float**                deep_ptrs = NULL;
    float*                 deep_data = NULL;
    const int              W = 64, NSAMP = 1024;
    int                    unpacked_idx, scratch_idx;

    setvbuf (stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf (stderr, "usage: %s file.exr\n", argv[0]);
        return 2;
    }
    exr_set_default_memory_routines (guarded_alloc, guarded_free);

    rv = exr_start_read (&ctxt, argv[1], &cxt_init);
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

    rv = exr_decoding_run (ctxt, 0, &decode);
    printf ("DECODE rv=%d %s\n", (int) rv, exr_get_error_code_as_string (rv));

    unpacked_idx = allocation_index (decode.unpacked_buffer);
    scratch_idx = allocation_index (decode.scratch_buffer_1);
    printf ("BUFFERS unpacked=%p alloc=%d size=%zu scratch1=%p alloc=%d "
            "size=%zu\n",
            decode.unpacked_buffer, unpacked_idx, decode.unpacked_alloc_size,
            decode.scratch_buffer_1, scratch_idx, decode.scratch_alloc_size_1);

    report_guards ("post-decode");
    fflush (stdout);
    exr_decoding_destroy (ctxt, &decode);
    exr_finish (&ctxt);
    free (deep_ptrs);
    free (deep_data);
    return 0;
}
