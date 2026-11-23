/* Lab-only driver: real libgphoto2 2.5.34 API + real jl2005c camlib,
 * virtual USB port from libgphoto2_port/vusb with a lab JL2005 reply model.
 * No network, no real USB device. Model/port are selected explicitly. */
#include <stdio.h>
#include <stdlib.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>

int main(int argc, char **argv)
{
	Camera *cam = NULL;
	CameraAbilitiesList *al = NULL;
	CameraAbilities ab;
	GPPortInfoList *il = NULL;
	GPPortInfo pi;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	int m, idx, rc;

	if (gp_camera_new(&cam) < GP_OK) return 2;
	if (gp_abilities_list_new(&al) < GP_OK) return 2;
	if (gp_abilities_list_load(al, NULL) < GP_OK) return 2;
	m = gp_abilities_list_lookup_model(al, " JL2005B/C/D camera");
	printf("model_index=%d\n", m);
	if (m < 0) return 2;
	if (gp_abilities_list_get_abilities(al, m, &ab) < GP_OK) return 2;
	if (gp_camera_set_abilities(cam, ab) < GP_OK) return 2;

	if (gp_port_info_list_new(&il) < GP_OK) return 2;
	if (gp_port_info_list_load(il) < GP_OK) return 2;
	idx = gp_port_info_list_lookup_path(il, path);
	printf("port_index=%d path=%s\n", idx, path);
	if (idx < 0) return 2;
	if (gp_port_info_list_get_info(il, idx, &pi) < GP_OK) return 2;
	if (gp_camera_set_port_info(cam, pi) < GP_OK) return 2;

	rc = gp_camera_init(cam, NULL);
	printf("gp_camera_init rc=%d\n", rc);
	return 0;
}
