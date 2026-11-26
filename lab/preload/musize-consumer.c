/* Lab-only observer for the Ruby GC consumer of a malloc chunk size word.
 *
 * Build: gcc -shared -fPIC -O1 -Wall -Wextra -ldl -o musize-consumer.so musize-consumer.c
 * RUBY2SHELL_MUS_ARM=<file> enables logging once <file> exists (after boot).
 *
 * Lines (all writes are observations; no target memory is modified):
 *   A armed                                      arm file observed
 *   M <user-ptr> <req>                           65..80-byte mallocs
 *   V <user-ptr> <raw-header> <usable> <caller>  first 20 usable-size calls
 *   C <user-ptr> <raw-header> <usable> <caller>  first 12 ruby-binary calls
 *   U <user-ptr> <raw-header> <usable> <caller>  usable-size calls whose
 *                                               raw size low byte is 0x53
 *   D usable=<n> ruby=<n>                        totals at process exit
 *
 * The overflow writes 0x53 at `user_ptr + request_size`, i.e. into the next
 * chunk's size word when that address lies in [next_user-8, next_user).
 * U/C/V lines with the ruby binary as caller are Ruby's own accounting reader
 * (gc/default/default.c:8177/8284), which runs before glibc free/realloc
 * reads the same word.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);

static size_t (*real_usable)(void *);
static const char *arm_path;
static int armed;
static __thread int busy;
static unsigned long usable_calls;
static unsigned long ruby_calls;
static unsigned long sampled;
static unsigned long verbose;
#define DEST_RING 4096
static void *dests[DEST_RING];
static unsigned long dest_count;

static int header_overlap_kind(void *p)
{
    unsigned long n = dest_count < DEST_RING ? dest_count : DEST_RING;
    int kind = 0;
    for (unsigned long i = 0; i < n; i++) {
        char *d = (char *)dests[i];
        if ((char *)p - 16 <= d && d < (char *)p - 8) kind = 1;
        if (d == (char *)p - 8) return 2;
    }
    return kind;
}

__attribute__((constructor)) static void init(void)
{
    real_usable = (size_t (*)(void *))dlsym(RTLD_NEXT, "malloc_usable_size");
    arm_path = getenv("RUBY2SHELL_MUS_ARM");
}

__attribute__((destructor)) static void done(void)
{
    char b[96];
    int k = snprintf(b, sizeof b, "D usable=%lu ruby=%lu\n", usable_calls, ruby_calls);
    if (k > 0) (void)!write(2, b, (size_t)k);
}

static void emit(const char *fmt, ...)
{
    char b[192];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    if (k > 0) (void)!write(2, b, (size_t)k);
}

static void check_arm(void)
{
    if (!armed && arm_path && access(arm_path, F_OK) == 0) {
        armed = 1;
        emit("A armed\n");
    }
}

static const char *caller_name(void *caller, char *buf, size_t cap)
{
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname) {
        unsigned long off = (unsigned long)caller - (unsigned long)info.dli_fbase;
        snprintf(buf, cap, "%s+%#lx", info.dli_fname, off);
    } else {
        snprintf(buf, cap, "?+%p", caller);
    }
    return buf;
}

static int is_ruby_caller(void *caller)
{
    char name[160];
    const char *n = caller_name(caller, name, sizeof name);
    return strstr(n, "/bin/ruby") != NULL;
}

void *malloc(size_t n)
{
    void *p = __libc_malloc(n);
    check_arm();
    if (n >= 65 && n <= 80) dests[dest_count++ % DEST_RING] = (char *)p + n;
    if (armed && !busy && n >= 65 && n <= 80) {
        busy = 1;
        char name[160];
        emit("M %p %zu %s\n", p, n,
             caller_name(__builtin_return_address(0), name, sizeof name));
        busy = 0;
    }
    return p;
}

size_t malloc_usable_size(void *p)
{
    if (!p || !real_usable) return real_usable ? real_usable(p) : 0;
    size_t hdr = ((size_t *)p)[-1];
    void *caller = __builtin_return_address(0);
    __atomic_add_fetch(&usable_calls, 1, __ATOMIC_RELAXED);
    check_arm();
    int ruby = is_ruby_caller(caller);
    if (ruby) __atomic_add_fetch(&ruby_calls, 1, __ATOMIC_RELAXED);
    if (armed && !busy) {
        busy = 1;
        char name[160];
        const char *who = caller_name(caller, name, sizeof name);
        if (verbose < 20) {
            verbose++;
            emit("V %p %#zx %zu %s\n", p, hdr, real_usable(p), who);
        }
        if (ruby && sampled < 12) {
            sampled++;
            emit("C %p %#zx %zu %s\n", p, hdr, real_usable(p), who);
        }
        if ((hdr & 0xff) == 0x53) {
            emit("U %p %#zx %zu %s\n", p, hdr, real_usable(p), who);
        }
        int kind = header_overlap_kind(p);
        if (kind) {
            emit("W %p %#zx %zu %d %s\n", p, hdr, real_usable(p), kind, who);
        }
        busy = 0;
    }
    return real_usable(p);
}
