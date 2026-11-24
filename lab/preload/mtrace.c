/* mtrace.c — synthetic LD_PRELOAD malloc/free tracer for ruby2shell Stage A.
 * Approved mechanism (operator standing approvals: "LD_PRELOAD mechanics
 * (synthetic-labeled)"). Logs every malloc/calloc/realloc/free with the
 * glibc chunk size read at free time, so a corrupted size LSB (0x53) is
 * captured before glibc's own checks abort the process.
 *
 * Hooks call __libc_malloc/__libc_free directly (no dlsym recursion).
 * Output: raw write(2) lines to fd from env MTRACE_FD (default 2).
 *   M <seq> <size> <ptr>
 *   C <seq> <count> <size> <ptr>
 *   R <seq> <oldptr> <newsize> <newptr>
 *   F <seq> <ptr> <sizefield-hex>   (sizefield = *(size_t*)(ptr-8))
 * Build: gcc -shared -fPIC -O2 -o mtrace.so mtrace.c
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/uio.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static int out_fd = 2;
static unsigned long seq = 0;
static int case_only = 0;
static int case_stop = 0;
static size_t case_first_request = 0;
static const char *case_arm_file = 0;
static __thread size_t case_second_request = 0;
static __thread char *case_end = 0;
static __thread void *case_victim = 0;
static __thread void *case_physical = 0;
static __thread int case_waiting_second = 0;
static __thread int case_overflow_seen = 0;

__attribute__((constructor))
static void mtrace_init(void)
{
    const char *fd_s = getenv("MTRACE_FD");
    if (fd_s)
        out_fd = atoi(fd_s);
    case_only = getenv("MTRACE_CASE_ONLY") != NULL;
    case_stop = getenv("MTRACE_CASE_STOP") != NULL;
    case_first_request = (size_t)strtoull(getenv("MTRACE_CASE_REQUEST") ?
                                          getenv("MTRACE_CASE_REQUEST") : "0",
                                          NULL, 0);
    case_arm_file = getenv("MTRACE_CASE_ARM_FILE");
}

static void emit(const char *tag, unsigned long a, unsigned long b,
                 unsigned long c)
{
    if (case_only)
        return;
    char buf[128];
    int len = snprintf(buf, sizeof buf, "%s %lu %lx %lx %lx\n",
                       tag, seq, a, b, c);
    if (len > 0)
        write(out_fd, buf, (size_t)len);
}

/* Analysis-only geometry probe for rb_str_casemap's two adjacent allocations.
 * MTRACE_CASE_REQUEST is the first mapping-buffer request (N+44). Arming by a
 * lab-created file avoids matching identical boot allocations. No probe output
 * is used by the stock/oracle-free driver or payload. */
static unsigned long case_read(void *p)
{
    unsigned long value = 0;
    struct iovec local = { .iov_base = &value, .iov_len = sizeof value };
    struct iovec remote = { .iov_base = p, .iov_len = sizeof value };
    if (syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0) !=
        (ssize_t)sizeof value)
        return 0;
    return value;
}

static void case_snapshot(const char *tag, size_t sizefield)
{
    size_t grown = (sizefield & ~(size_t)0xff) | 0x53;
    char *victim_header = case_end - 8;
    char *next = victim_header + (grown & ~(size_t)7);
    char *physical = victim_header + (sizefield & ~(size_t)7);
    if (tag[0] == 'B')
        case_physical = physical;
    char buf[512];
    int len = snprintf(buf, sizeof buf,
                       "%s tid=%ld first_request=%#lx end=%p victim=%p size=%#lx "
                       "fd=%p bk=%p next=%p next_prev=%#lx next_size=%#lx "
                       "physical=%p physical_prev=%#lx physical_size=%#lx "
                       "physical_fd=%p physical_bk=%p\n",
                       tag, syscall(SYS_gettid), case_first_request, case_end,
                       case_victim, sizefield,
                       (void *)case_read(case_end + 8),
                       (void *)case_read(case_end + 16), next,
                       case_read(next), case_read(next + 8), physical,
                       case_read(physical), case_read(physical + 8),
                       (void *)case_read(physical + 16),
                       (void *)case_read(physical + 24));
    if (len > 0)
        write(out_fd, buf, (size_t)len);
}

static void case_allocation(size_t size, void *p)
{
    if (!case_overflow_seen)
        return;
    char buf[192];
    int len;
    if (p == case_victim) {
        len = snprintf(buf, sizeof buf,
                       "C tid=%ld request=%#lx ptr=%p size=%#lx\n",
                       syscall(SYS_gettid), size, p, *(size_t *)case_end);
    } else if (p == case_physical) {
        len = snprintf(buf, sizeof buf,
                       "P tid=%ld request=%#lx ptr=%p size=%#lx\n",
                       syscall(SYS_gettid), size, p, case_read(case_physical + 8));
    } else {
        return;
    }
    if (len > 0)
        write(out_fd, buf, (size_t)len);
}

void *malloc(size_t size)
{
    if (case_waiting_second && size != case_second_request) {
        case_end = 0;
        case_victim = 0;
        case_physical = 0;
        case_waiting_second = 0;
        case_overflow_seen = 0;
    }
    if (case_first_request && size == case_first_request &&
        case_arm_file && access(case_arm_file, F_OK) == 0) {
        size_t n = size - 44;
        size_t capa = n + 20;
        size_t consumed = capa / 2 + 1;
        case_second_request = 2 * (n - consumed) + 44;
        case_physical = 0;
        case_waiting_second = 1;
        case_overflow_seen = 0;
    } else if (case_waiting_second && size == case_second_request) {
        case_snapshot("A", *(size_t *)case_end);
        case_waiting_second = 0;
        case_overflow_seen = 1;
        if (case_stop)
            kill(getpid(), SIGSTOP);
    }
    void *p = __libc_malloc(size);
    case_allocation(size, p);
    if (case_waiting_second && size == case_first_request) {
        case_end = (char *)p + size;
        case_victim = case_end + 8;
        case_snapshot("B", *(size_t *)case_end);
    }
    emit("M", size, (unsigned long)(uintptr_t)p, 0);
    return p;
}

void *calloc(size_t n, size_t size)
{
    void *p = __libc_calloc(n, size);
    case_allocation(n * size, p);
    emit("C", n * size, (unsigned long)(uintptr_t)p, 0);
    return p;
}

void *realloc(void *old, size_t size)
{
    void *p = __libc_realloc(old, size);
    case_allocation(size, p);
    emit("R", (unsigned long)(uintptr_t)old, size,
         (unsigned long)(uintptr_t)p);
    return p;
}

void free(void *p)
{
    if (p) {
        size_t sizefield = *(size_t *)((char *)p - 8);
        if (p == case_victim)
            case_snapshot("V", sizefield);
        emit("F", (unsigned long)(uintptr_t)p, sizefield, 0);
    }
    __libc_free(p);
}
