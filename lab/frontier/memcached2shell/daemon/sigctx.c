/* Loopback lab only. Capture faulting registers without ptrace.
 *
 * Loaded via LD_PRELOAD at process start. It does nothing until SIGSEGV or
 * SIGBUS, then reads the kernel-provided ucontext at the fault, writes the
 * registers with write(2) and exits. No breakpoint, signal injection or
 * debugger stop touches the 1000 ms poll() timeout that the crawler bug
 * depends on. The constructor deliberately performs NO heap allocation:
 * a /proc/self/maps READER ADDED HERE CHANGED THE DAEMON'S FAULT BEHAVIOUR
 * (two 120 s runs then completed without faulting), so this shim stays minimal.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

static void emit(const char *s) {
    size_t n = strlen(s);
    ssize_t ignored = write(STDERR_FILENO, s, n);
    (void)ignored;
}

static void hexline(const char *name, uint64_t value) {
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "%s=0x%016llx\n", name,
                     (unsigned long long)value);
    if (n > 0) {
        ssize_t ignored = write(STDERR_FILENO, buf, (size_t)n);
        (void)ignored;
    }
}

static void on_fault(int sig, siginfo_t *info, void *uc) {
    static volatile int in_handler;
    if (__sync_fetch_and_add(&in_handler, 1) != 0) {
        struct sigaction d;
        memset(&d, 0, sizeof(d));
        d.sa_handler = SIG_DFL;
        sigaction(sig, &d, NULL);
        _exit(128 + sig);
    }
    ucontext_t *ctx = (ucontext_t *)uc;
    mcontext_t *mc = &ctx->uc_mcontext;
    char head[128];
    int n = snprintf(head, sizeof(head), "SIGCTX signal=%d pid=%d si_addr=",
                     sig, (int)getpid());
    if (n > 0) {
        ssize_t ignored = write(STDERR_FILENO, head, (size_t)n);
        (void)ignored;
    }
    hexline("si_addr", (uint64_t)(uintptr_t)info->si_addr);
    hexline("RIP", mc->gregs[REG_RIP]);
    hexline("RAX", mc->gregs[REG_RAX]);
    hexline("RBX", mc->gregs[REG_RBX]);
    hexline("RCX", mc->gregs[REG_RCX]);
    hexline("RDX", mc->gregs[REG_RDX]);
    hexline("RSI", mc->gregs[REG_RSI]);
    hexline("RDI", mc->gregs[REG_RDI]);
    hexline("RBP", mc->gregs[REG_RBP]);
    hexline("RSP", mc->gregs[REG_RSP]);
    hexline("R8", mc->gregs[REG_R8]);
    hexline("R9", mc->gregs[REG_R9]);
    hexline("R10", mc->gregs[REG_R10]);
    hexline("R11", mc->gregs[REG_R11]);
    hexline("R12", mc->gregs[REG_R12]);
    hexline("R13", mc->gregs[REG_R13]);
    hexline("R14", mc->gregs[REG_R14]);
    hexline("R15", mc->gregs[REG_R15]);
    emit("SIGCTX END\n");
    _exit(128 + sig);
}

__attribute__((constructor)) static void install(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}
