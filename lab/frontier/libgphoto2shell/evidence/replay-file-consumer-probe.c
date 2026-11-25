/* W194 lab-only probe: real gphoto2 consumer after the W193 partial-priv
 * overwrite. Build against the W193 clang installdir with
 *   clang -O0 -g -fno-omit-frame-pointer -I$P/include -I$T/pins \
 *     $(pkg-config --cflags glib-2.0) replay-file-consumer-probe.c -o probe \
 *     -L$P/lib -lgphoto2 -lgphoto2_port $(pkg-config --libs glib-2.0)
 * The attack run uses setarch -R so the fixed 4-bit priv guess matches.
 * No canary, live address, gdb write or synthetic consumer is involved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>

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
	const char *out = argc > 2 ? argv[2] : "/tmp/w194-consumer.bin";
	const char *name = NULL, *data = NULL;
	unsigned long size = 0;
	int m, idx, rc, i;

	setvbuf(stdout, NULL, _IONBF, 0);
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
	printf("AFTER_INIT rc=%d\n", rc);
	if (rc < GP_OK) return 3;
	if (getenv("M2SHELL_W194_SKIP_CONSUMER"))
		return 0;

	if (gp_list_new(&list) < GP_OK) return 2;
	rc = gp_camera_folder_list_files(cam, "/", list, NULL);
	printf("LIST rc=%d count=%d\n", rc, gp_list_count(list));
	if (rc == GP_OK && gp_list_count(list) > 0) {
		gp_list_get_name(list, 0, &name);
		printf("FIRST_NAME=%s\n", name);
	}

	if (gp_file_new(&file) < GP_OK) return 2;
	rc = gp_camera_file_get(cam, "/", "jl_001.ppm", GP_FILE_TYPE_RAW,
				file, NULL);
	printf("FILE_GET rc=%d\n", rc);
	if (rc == GP_OK) {
		rc = gp_file_get_data_and_size(file, &data, &size);
		printf("DATA rc=%d size=%lu bytes=", rc, size);
		for (i = 0; i < 16 && i < (int)size; i++)
			printf("%02x", (unsigned char)data[i]);
		printf("\n");
		rc = gp_file_save(file, out);
		printf("FILE_SAVE rc=%d path=%s\n", rc, out);
	}
	gp_file_free(file);
	gp_list_free(list);
	gp_camera_exit(cam, NULL);
	return 0;
}
