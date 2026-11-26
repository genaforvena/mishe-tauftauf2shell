/*
 * php2shell wake 72 — negative control for a non-FSIZE write interruption.
 *
 * Question: can handled, non-fatal signals interrupt a large pwrite() into a
 * regular file, returning a SHORT count while the process survives? If yes,
 * the 126714 splice (new prefix + old tail) could be produced without an
 * RLIMIT_FSIZE clamp. This probe is deliberately independent of PHP: if the
 * kernel/glibc write does not return short here, the FPM session-write path
 * cannot get a short write this way either.
 *
 * Child: 4 MiB "old tail" ('O'), then pwrite 256 MiB of 'N' at offset 0 with
 * a no-SA_RESTART handler installed for SIGUSR1/SIGCONT/SIGWINCH.
 * Parent: floods the child with that signal while the write runs.
 * Output per signal: pwrite return, requested count, handler hits, exit code.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t hits = 0;

static void handler(int sig) { (void)sig; hits++; }

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "SIGUSR1";
    int signo = !strcmp(name, "SIGUSR1") ? SIGUSR1
              : !strcmp(name, "SIGCONT") ? SIGCONT
              : !strcmp(name, "SIGWINCH") ? SIGWINCH : 0;
    if (!signo) {
        dprintf(2, "usage: %s SIGUSR1|SIGCONT|SIGWINCH\n", argv[0]);
        return 2;
    }

    char path[] = "/tmp/php2shell-write-cut-probe-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 2;
    unlink(path); /* private inode; no lab or host path is touched */

    const size_t old_len = 4u << 20;
    char *old = malloc(old_len);
    if (!old) return 2;
    memset(old, 'O', old_len);
    if (write(fd, old, old_len) != (ssize_t)old_len) return 3;
    free(old);

    const size_t len = 256u << 20;
    char *buf = malloc(len);
    if (!buf) return 2;
    memset(buf, 'N', len);

    struct sigaction sa = {0};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART */
    if (sigaction(signo, &sa, NULL)) return 2;

    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        errno = 0;
        ssize_t got = pwrite(fd, buf, len, 0);
        dprintf(1, "signal=%s pwrite=%zd of %zu errno=%d handler_hits=%d\n",
                name, got, len, errno, (int)hits);
        _exit(got == (ssize_t)len ? 0 : 1);
    }

    for (volatile long i = 0; i < 2000000; i++) {
        kill(child, signo);
        if ((i & 255) == 0) sched_yield();
    }
    int status = 0;
    waitpid(child, &status, 0);
    dprintf(1, "signal=%s child_exit=%d\n", name, WEXITSTATUS(status));
    free(buf);
    close(fd);
    return 0;
}
