/*
 * Consumer-reality probe: mimic the exact allocation order in pinned
 * cram_io.c:4601-4637 (cram_read_slice) and measure whether the 4096-byte
 * block_by_id chunk is immediately followed by the 4096-byte cigar chunk.
 * If so, the OOB slot at index 513 (offset 4104) lands in live cigar data.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    int n = 4; /* s->hdr->num_blocks */
    void **block = calloc(n, sizeof(*block));       /* cram_io.c:4601 */
    /* cram_read_block() x n omitted: only sizes matter for adjacency here. */
    for (int i = 0; i < n; i++) block[i] = malloc(64);

    void **block_by_id = calloc(512, sizeof(block[0])); /* :4620 */
    uint32_t *cigar = malloc(1024 * sizeof(*cigar));    /* :4633 */

    printf("block_by_id = %p\n", (void *)block_by_id);
    printf("cigar       = %p\n", (void *)cigar);
    printf("cigar - block_by_id = %td bytes\n", (char *)cigar - (char *)block_by_id);
    printf("block_by_id[512] at offset 4096 = next chunk prev_size\n");
    printf("block_by_id[513] at offset 4104 = next chunk SIZE field\n");
    /* Next chunk user = userA + 4096 (user) + 16 (chunk header). */
    if ((char *)cigar - (char *)block_by_id == 4112)
        printf("VERDICT adjacent: OOB index 513 overwrites the glibc chunk SIZE"
               " field of the next allocation (s->cigar in cram_read_slice)\n");
    else
        printf("VERDICT not adjacent: OOB index 513 lands elsewhere in heap\n");
    return 0;
}
