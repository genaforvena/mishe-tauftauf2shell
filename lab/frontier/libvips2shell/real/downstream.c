/* Real downstream consumer probe for CVE-2026-69242, lab only.
 *
 * Loads the crafted many-band TIFF through the real VipsForeignLoadTiff,
 * then asks a real VipsRegion for two lines and addresses line 1 through
 * the pinned VIPS_REGION_ADDR macro. No synthetic image and no direct
 * vips_region_paint_pel() call: this exercises the region-address path a
 * real downstream consumer uses on pixels produced by the loader.
 *
 * No network, no external target, no command execution, no marker claim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <vips/vips.h>

int
main(int argc, char **argv)
{
	VipsImage *im;
	VipsRegion *reg;
	VipsRect r;
	int rc;
	unsigned char v;

	if (VIPS_INIT(argv[0]))
		return 1;
	if (argc < 2) {
		fprintf(stderr, "usage: %s FILE\n", argv[0]);
		return 2;
	}

	im = vips_image_new_from_file(argv[1],
		"access", VIPS_ACCESS_SEQUENTIAL, NULL);
	if (!im) {
		printf("DOWNLOAD=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
		vips_shutdown();
		return 0;
	}
	printf("DOWNLOAD=OK Xsize=%d Ysize=%d Bands=%d BandFmt=%d "
		"sizeof_line=%" G_GUINT64_FORMAT
		" sizeof_image=%" G_GUINT64_FORMAT "\n",
		im->Xsize, im->Ysize, im->Bands, im->BandFmt,
		VIPS_IMAGE_SIZEOF_LINE(im), VIPS_IMAGE_SIZEOF_IMAGE(im));
	fflush(stdout);

	reg = vips_region_new(im);
	r.left = 0;
	r.top = 0;
	r.width = 4;
	r.height = 2;
	rc = vips_region_prepare(reg, &r);
	printf("REGION_PREPARE=%d data=%p bpl=%d lskip=%llu "
		"valid={%d,%d,%d,%d} msg=%s\n",
		rc, (void *) reg->data, reg->bpl,
		(unsigned long long) VIPS_REGION_LSKIP(reg),
		reg->valid.left, reg->valid.top,
		reg->valid.width, reg->valid.height, vips_error_buffer());
	vips_error_clear();
	fflush(stdout);

	if (rc == 0 && reg->data && reg->valid.height >= 2) {
		v = *VIPS_REGION_ADDR(reg, 0, 1);
		printf("LINE1_BYTE=%02x\n", v);
		fflush(stdout);
	}

	g_object_unref(reg);
	g_object_unref(im);
	vips_shutdown();
	return 0;
}
