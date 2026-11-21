/* ASan harness driver: decodes a PNG file through the PINNED Png_Decode.
   No PNG parsing/reimplementation here -- all parsing is the real pinned code. */
#include "Bitmap.h"
#include "Stream.h"
#include "Platform.h"
#include "Errors.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
	FILE* f;
	long len;
	unsigned char* buf;
	struct Stream s;
	struct Bitmap bmp;
	cc_result r;

	if (argc != 2) { fprintf(stderr, "usage: %s <png>\n", argv[0]); return 2; }
	f = fopen(argv[1], "rb");
	if (!f) { perror("fopen"); return 2; }
	fseek(f, 0, SEEK_END); len = ftell(f); fseek(f, 0, SEEK_SET);
	buf = (unsigned char*)malloc((size_t)len);
	if (fread(buf, 1, (size_t)len, f) != (size_t)len) { perror("fread"); return 2; }
	fclose(f);

	Stream_ReadonlyMemory(&s, buf, (cc_uint32)len);
	r = Png_Decode(&bmp, &s);
	printf("RESULT=0x%08X w=%d h=%d scan0=%p\n", r, bmp.width, bmp.height, (void*)bmp.scan0);
	fflush(stdout);
	free(buf);
	return 0;
}
