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
 * Gated on the AFTERSHELL_KILL_AT env var; fires at most once per process.
 * An optional AFTERSHELL_KILL_ARM=<path> makes the kill conditional on that
 * file existing at call time — for long-lived multi-request workers (FPM)
 * where the interrupt must fire in one chosen request only, not the first
 * write the process ever performs. Unset → armed unconditionally, which is
 * the original per-process behavior of the CGI harnesses.
 *
 * Calibration mode (measurement only, no kill): with AFTERSHELL_LOG_ONLY=1
 * and AFTERSHELL_LOG_FILE=<path>, every pwrite(fd, buf, n, 0) is dumped to
 * that file as "=== pwrite n=<len> ===" + raw bytes, so a harness can read
 * back the exact buffer PHP's session write produced and pick the cut
 * offset K before doing the real kill run.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>

static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static int fired = 0;

static void dump_buffer(const void *buf, size_t n)
{
    const char *path = getenv("AFTERSHELL_LOG_FILE");
    FILE *f;
    if (!path) return;
    f = fopen(path, "ab");
    if (!f) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(f, "[%lu.%09lu] === pwrite n=%zu ===\n", ts.tv_sec, ts.tv_nsec, n);
    fwrite(buf, 1, n, f);
    fputc('\n', f);
    fclose(f);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
{
    if (!real_pwrite) {
        real_pwrite = (ssize_t (*)(int, const void *, size_t, off_t))
            dlsym(RTLD_NEXT, "pwrite");
    }
    if (getenv("AFTERSHELL_LOG_ONLY") && off == 0) {
        dump_buffer(buf, n);
    }
    const char *k = getenv("AFTERSHELL_KILL_AT");
    const char *arm = getenv("AFTERSHELL_KILL_ARM");
    if (!fired && k && off == 0
        && (!arm || access(arm, F_OK) == 0)) {
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
