/* aftershell-kill.c — syscall-boundary interruption shim for the
 * php2shell CVE-2026-126714 producer harness.
 *
 * The vendor advisory's remote interruption is a worker death during the
 * buffered pwrite() in ps_files_write() (e.g. a hard OOM kill in another
 * thread). This shim reproduces that interruption deterministically at the
 * syscall boundary: when PHP's session write reaches pwrite(fd, buf, n, 0)
 * with n > AFTERSHELL_KILL_AT, it writes exactly KILL_AT bytes and then
 * SIGKILLs the process — leaving prefix-of-new + tail-of-old on the inode,
 * exactly the documented post-kill state. The PHP-side path (real session
 * decode/encode, real ps_files_write, real fd/inode, real kernel partial
 * write + lock release on death) is fully genuine; only the kill is
 * simulated.
 *
 * Build: cc -shared -fPIC -O2 -o lab/preload/aftershell-kill.so lab/php2shell/aftershell-kill.c
 * Gated on the AFTERSHELL_KILL_AT env var; fires at most once per process.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stddef.h>

static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static int fired = 0;

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
{
    if (!real_pwrite) {
        real_pwrite = (ssize_t (*)(int, const void *, size_t, off_t))
            dlsym(RTLD_NEXT, "pwrite");
    }
    const char *k = getenv("AFTERSHELL_KILL_AT");
    if (!fired && k && off == 0) {
        size_t cut = (size_t) atol(k);
        if (cut > 0 && n > cut) {
            fired = 1;
            /* partial copy first — these bytes become durable page cache,
             * the remainder of the old inode is retained (no truncate
             * happened because the replacement is not shorter). */
            (void) real_pwrite(fd, buf, cut, 0);
            kill(getpid(), SIGKILL);
            for (;;) pause(); /* not reached */
        }
    }
    return real_pwrite(fd, buf, n, off);
}
