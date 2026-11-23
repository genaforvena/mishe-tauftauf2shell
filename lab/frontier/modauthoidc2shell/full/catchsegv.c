/* Lab-only SIGSEGV backtrace shim for the plain httpd crash probe.
 * Apache installs its own fatal-signal handlers; interpose sigaction so
 * SIGSEGV lands here instead, print a backtrace and exit. Nothing else changes.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);

static void segv_handler(int sig) {
    void *bt[64];
    int n = backtrace(bt, 64);
    const char head[] = "SEGVHANDLER signal=";
    char num[8];
    write(2, head, sizeof(head) - 1);
    num[0] = (char)('0' + sig);
    write(2, num, 1);
    write(2, "\n", 1);
    backtrace_symbols_fd(bt, n, 2);
    _exit(128 + sig);
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
    static sigaction_fn real_sigaction;
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (sig == SIGSEGV && act) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        return real_sigaction(sig, &sa, old);
    }
    return real_sigaction(sig, act, old);
}
