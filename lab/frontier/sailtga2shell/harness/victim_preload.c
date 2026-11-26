/* sailtga2shell w1 — lab-only malloc interposer.
 * When SAIL_VICTIM_ARM=1, the first malloc(256) (the TGA pixel buffer) is
 * followed immediately by a live victim object with a pointer-bearing field.
 * The field initially holds benign_control(); an overflow can retarget it to
 * benign_marker(). victim_call() is invoked by the driver only when armed.
 * All marker I/O uses syscalls: the heap is corrupted by the overflow and a
 * libc allocation inside the marker would abort on glibc metadata checks.
 * This is a SYNTHETIC in-process consumer: rung-4 mechanics, never r5. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);

struct victim {
    void *fp;          /* pointer-bearing field at victim+0 */
    uint32_t magic;
    uint32_t canary;
    unsigned char pad[32];
};

static struct victim *g_victim;
static void *g_pixel;
static int g_done;

static void emit(int fd, const char *msg, size_t len)
{
    ssize_t ignored = write(fd, msg, len);
    (void)ignored;
}

void benign_marker(void)
{
    static const char msg[] = "BENIGN_MARKER_EXECUTED\n";
    emit(STDERR_FILENO, msg, sizeof(msg) - 1);
    int fd = open("evidence-w3/marker.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        emit(fd, msg, sizeof(msg) - 1);
        close(fd);
    }
}

void benign_control(void)
{
    static const char msg[] = "CONTROL_FP_UNCHANGED\n";
    emit(STDERR_FILENO, msg, sizeof(msg) - 1);
}

void victim_call(void)
{
    if (g_victim != NULL && g_victim->fp != NULL) {
        ((void (*)(void))g_victim->fp)();
    }
}

void *malloc(size_t size)
{
    void *p = __libc_malloc(size);

    if (!g_done && size == 256) {
        const char *arm = getenv("SAIL_VICTIM_ARM");
        if (arm != NULL && arm[0] == '1') {
            g_done = 1;
            g_pixel = p;
            g_victim = (struct victim *)__libc_malloc(sizeof(struct victim));
            if (g_victim != NULL) {
                g_victim->fp = (void *)benign_control;
                g_victim->magic = 0x5350494CU; /* "LIPS" */
                g_victim->canary = 0xDEADBEEFU;
                memset(g_victim->pad, 0x5A, sizeof(g_victim->pad));
            }
        }
    }
    return p;
}

__attribute__((destructor)) static void victim_report(void)
{
    if (g_victim == NULL || g_pixel == NULL) {
        emit(STDERR_FILENO, "VICTIM none\n", 12);
        return;
    }
    const unsigned char *v = (const unsigned char *)g_victim;
    fprintf(stderr, "VICTIM pixel=%p victim=%p delta=%ld fp=%p magic=%08x canary=%08x "
                    "marker=%p control=%p first16=",
            g_pixel, (void *)g_victim,
            (long)((char *)g_victim - (char *)g_pixel),
            g_victim->fp, g_victim->magic, g_victim->canary,
            (void *)benign_marker, (void *)benign_control);
    for (int i = 0; i < 16; i++) {
        fprintf(stderr, "%02x", v[i]);
    }
    fprintf(stderr, "\n");
}
