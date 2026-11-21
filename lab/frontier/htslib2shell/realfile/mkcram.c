/* Convert a tiny SAM text file to a CRAM v4.0 file using pinned htslib 1.23.1. */
#include <stdio.h>
#include <stdlib.h>
#include "htslib/hts.h"
#include "htslib/sam.h"

int main(int argc, char **argv) {
    const char *sam_path = argc > 1 ? argv[1] : "tiny.sam";
    const char *cram_path = argc > 2 ? argv[2] : "base.cram";

    htsFile *in = hts_open(sam_path, "r");
    if (!in) { fprintf(stderr, "cannot open %s\n", sam_path); return 1; }

    htsFile *out = hts_open(cram_path, "wc");
    if (!out) { fprintf(stderr, "cannot open %s\n", cram_path); return 1; }
    if (hts_set_opt(out, CRAM_OPT_VERSION, "4.0") != 0) {
        fprintf(stderr, "cannot set CRAM v4.0\n");
        return 1;
    }
    /* No external reference sequence is needed for this demonstration. */
    if (hts_set_opt(out, CRAM_OPT_NO_REF, 1) != 0) {
        fprintf(stderr, "cannot set CRAM_OPT_NO_REF\n");
        return 1;
    }

    sam_hdr_t *hdr = sam_hdr_read(in);
    if (!hdr) { fprintf(stderr, "cannot read SAM header\n"); return 1; }
    if (sam_hdr_write(out, hdr) < 0) { fprintf(stderr, "cannot write header\n"); return 1; }

    bam1_t *b = bam_init1();
    int r, n = 0;
    while ((r = sam_read1(in, hdr, b)) >= 0) {
        if (sam_write1(out, hdr, b) < 0) { fprintf(stderr, "cannot write record\n"); return 1; }
        n++;
    }
    if (r < -1) { fprintf(stderr, "SAM read error %d\n", r); return 1; }
    printf("wrote %d records to %s\n", n, cram_path);

    bam_destroy1(b);
    sam_hdr_destroy(hdr);
    if (hts_close(out) < 0) { fprintf(stderr, "close out failed\n"); return 1; }
    if (hts_close(in) < 0) { fprintf(stderr, "close in failed\n"); return 1; }
    return 0;
}
