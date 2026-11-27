#include <libical/ical.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static icalcomponent *add(icalparser *parser, const char *text)
{
    char *line = icalmemory_strdup(text);
    if (!line) exit(2);
    icalcomponent *component = icalparser_add_line(parser, line);
    /* Match the caller-side release used by icalparser_parse(). */
    icalmemory_free_buffer(line);
    return component;
}

static icalcomponent *feed(icalparser *parser, const char *const *lines, size_t count)
{
    icalcomponent *result = NULL;
    for (size_t i = 0; i < count; ++i) {
        icalcomponent *component = add(parser, lines[i]);
        if (component) {
            if (result) icalcomponent_free(result);
            result = component;
        }
    }
    return result;
}

static void report(const char *tag, icalcomponent *component)
{
    if (!component) {
        printf("%s: NULL\n", tag);
        return;
    }
    char *text = icalcomponent_as_ical_string(component);
    printf("%s: non-NULL, %zu bytes of serialized text\n", tag, text ? strlen(text) : 0);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2 || argc > 3) {
        fprintf(stderr,
                "usage: %s clean-free-destroy|clean-inspect-twice|clean-free-twice|two-sessions|complete"
                " [truncated|unclosed-child]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *shape = argc == 3 ? argv[2] : "truncated";
    int unclosed = strcmp(shape, "unclosed-child") == 0;
    if (!unclosed && strcmp(shape, "truncated") != 0) return 2;

    /* Both inputs stop while a component is still open ("in the middle of
       parsing something"): no END lines at all, or an outer END while a child
       is still open. */
    static const char *const truncated[] = {
        "BEGIN:VCALENDAR", "VERSION:2.0",
        "BEGIN:VEVENT", "UID:truncated@example.invalid"
    };
    static const char *const unclosed_child[] = {
        "BEGIN:VCALENDAR", "BEGIN:VEVENT", "END:VCALENDAR"
    };
    static const char *const complete[] = {
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//UAF ownership example//EN",
        "BEGIN:VEVENT", "UID:complete@example.invalid",
        "DTSTAMP:20261009T000000Z", "DTSTART:20261009T010000Z", "SUMMARY:Complete",
        "END:VEVENT", "END:VCALENDAR"
    };
    const char *const *history = unclosed ? unclosed_child : truncated;
    size_t history_count = unclosed ? sizeof(unclosed_child) / sizeof(unclosed_child[0])
                                    : sizeof(truncated) / sizeof(truncated[0]);
    size_t complete_count = sizeof(complete) / sizeof(complete[0]);

    icalparser *parser = icalparser_new();
    if (!parser) return 2;

    if (strcmp(mode, "complete") == 0) {
        /* Control: add_line() itself returns the completed component and
           icalparser_clean() has nothing left to hand out. */
        icalcomponent *component = feed(parser, complete, complete_count);
        report("add_line returned", component);
        if (component) icalcomponent_free(component);
        icalcomponent *leftover = icalparser_clean(parser);
        report("clean returned", leftover);
        if (leftover) icalcomponent_free(leftover);
        icalparser_free(parser);
        printf("mode=complete\n");
        return 0;
    }

    (void)feed(parser, history, history_count);
    icalcomponent *first = icalparser_clean(parser);
    report("first clean returned", first);
    /* Documented: the returned component is property of the caller. */
    if (first) icalcomponent_free(first);

    if (strcmp(mode, "clean-inspect-twice") == 0 || strcmp(mode, "clean-free-twice") == 0) {
        icalcomponent *second = icalparser_clean(parser);
        printf("second clean returned the same pointer: %s\n",
               second == first ? "yes" : "no");
        if (strcmp(mode, "clean-inspect-twice") == 0) {
            report("second clean returned", second);
            if (second) icalcomponent_free(second);
        } else if (second) {
            icalcomponent_free(second);
        }
    } else if (strcmp(mode, "two-sessions") == 0) {
        /* Documented reuse: clean returns what was parsed so far, the caller
           frees it, and the parser is used to parse something new. */
        (void)feed(parser, history, history_count);
        icalcomponent *second = icalparser_clean(parser);
        report("second session clean returned", second);
        if (second) icalcomponent_free(second);
    } else if (strcmp(mode, "clean-free-destroy") != 0) {
        icalparser_free(parser);
        return 2;
    }

    icalparser_free(parser);
    printf("mode=%s shape=%s\n", mode, shape);
    return 0;
}
