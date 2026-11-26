/* ettercapgg2shell: in-process driver for the verbatim gg_get_version bodies.
 * No packet capture, socket, listener or external target is used.
 * The only attacker-controlled value is the u_int32 `version` argument,
 * supplied on the command line exactly as the Gadu-Gadu dissector supplies
 * gg_login50/60/70->version or gg_status50->version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>


/* Harness-only typedef matching verbatim upstream include/ec_stdint.h:39:
 * typedef uint32_t u_int32; The extracted function body is unchanged. */
typedef uint32_t u_int32;
#ifdef FIXED_BUILD
#include "gg_ver_fixed.inc"
#else
#include "gg_ver_vuln.inc"
#endif

#ifndef ASAN_BUILD
/* The deliberate 14-byte overflow corrupts the following chunk's size field.
 * printf() and free() would both touch allocator metadata and abort before
 * the chosen bytes are observed, so plain builds emit with write(2) and do
 * not free. This is a harness observation aid, not part of the sink. */
static void put(const char *s, size_t n) { (void)!write(1, s, n); }
static size_t fmt_hex2(char *dst, unsigned v)
{
    static const char hx[] = "0123456789abcdef";
    dst[0] = hx[(v >> 4) & 15];
    dst[1] = hx[v & 15];
    return 2;
}
static size_t fmt_dec(char *dst, size_t v)
{
    size_t r[16], j = 0, n = 0;
    if (v == 0) r[j++] = 0;
    while (v) { r[j++] = v % 10; v /= 10; }
    while (j) dst[n++] = (char)('0' + r[--j]);
    return n;
}
#endif

int main(int argc, char **argv)
{
    uint32_t version;
    char *tbuf3;
    size_t i, n;

    if (argc != 2)
        return 2;
    version = (uint32_t)strtoul(argv[1], NULL, 0);

    /* verbatim dissector allocation: SAFE_CALLOC(tbuf3, 30, sizeof(char))
     * at vulnerable src/dissectors/ec_gg.c:356 */
    tbuf3 = (char *)calloc(30, sizeof(char));
    if (tbuf3 == NULL)
        return 3;

#ifdef FIXED_BUILD
    gg_get_version(version, tbuf3, 30);
#else
    gg_get_version(version, tbuf3);
#endif

#ifndef ASAN_BUILD
    /* Snapshot before emitting: no libc allocation after the write. */
    n = 0;
    while (n < 80 && tbuf3[n] != '\0') n++;
    put("len=", 4);
    {
        char tmp[16];
        size_t k = fmt_dec(tmp, n);
        put(tmp, k);
    }
    put("\nbuf=", 5);
    put(tbuf3, n);
    put("\n", 1);
    for (i = 11; i < 44; i++) {
        char line[32];
        size_t k = 0;
        line[k++] = 'b';
        if (i >= 10) line[k++] = (char)('0' + (i / 10));
        line[k++] = (char)('0' + (i % 10));
        line[k++] = '=';
        k += fmt_hex2(line + k, (unsigned char)tbuf3[i]);
        line[k++] = '\n';
        put(line, k);
    }
#else
    /* ASan aborts inside the sink on the attack input, so this is reached
     * only on clean inputs and cannot manufacture a second report. */
    n = strlen(tbuf3);
    printf("len=%zu\n", n);
    free(tbuf3);
#endif
    return 0;
}
