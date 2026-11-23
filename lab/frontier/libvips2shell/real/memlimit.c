/* Bounded eager-zero-fill probe for the W7 loader stall, lab only.
 *
 * Allocates N MiB with posix_memalign and zeroes it, timing the memset.
 * This is the allocation primitive used by pinned vips_tracked_aligned_alloc()
 * (iofuncs/memory.c:369-414), which posix_memalign()s and then memset()s the
 * whole block. Compile with -O0: an -O2 build removes the unused memset.
 *
 * No libvips, no image, no network, no command execution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int
main(int argc, char **argv)
{
	size_t mb = argc > 1 ? (size_t) atoi(argv[1]) : 64;
	size_t size = mb * 1024 * 1024;
	void *buf = NULL;
	struct timespec a, b;
	double dt;

	if (posix_memalign(&buf, 16, size)) {
		printf("ALLOC_FAIL mb=%zu\n", mb);
		return 1;
	}
	clock_gettime(CLOCK_MONOTONIC, &a);
	memset(buf, 0, size);
	clock_gettime(CLOCK_MONOTONIC, &b);
	dt = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
	printf("memset %zu MB in %.3f s (%.1f MB/s)\n", mb, dt, mb / dt);
	free(buf);
	return 0;
}
