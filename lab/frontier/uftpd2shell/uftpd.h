/* Minimal stand-in for uftpd's own header, only for compiling the verbatim
 * compose_path() extracted from the pinned upstream src/common.c.  The vulnerable
 * and fixed function bodies are NOT reimplemented: run.sh extracts them at
 * replay time and pads line numbers to match the pinned source file.
 */
#ifndef UFTPD_H_
#define UFTPD_H_

#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Debug/log macros in the real header only produce output; compose_path()'s
 * memory behaviour does not depend on them. */
#define DBG(...)  do { } while (0)
#define INFO(...) do { } while (0)
#define WARN(...) do { } while (0)
#define ERR(...)  do { } while (0)

typedef struct {
	int sd;
	char cwd[PATH_MAX];
} ctrl_t;

extern char *home;             /* real uftpd: configured FTP root */
extern int chrooted;           /* real uftpd: 0 means no chroot */

size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);
char *compose_path(ctrl_t *ctrl, char *path);

#endif
