/* Local reproduction driver: calls the verbatim AXIOM Guththila reader
 * wrapper's next() operation on a crafted in-memory XML document. No socket,
 * no external system. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <guththila.h>
#include <axutil_env.h>
#include <axutil_allocator.h>
#include <axutil_error_default.h>
#include <axutil_log_default.h>
#include <axiom_xml_reader.h>

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    const char *xml = argc > 1 ? argv[1] : "<!ENTITY x \"y\"><a/>";
    int i;
    axiom_xml_reader_t *reader = NULL;
    axutil_allocator_t *allocator = NULL;
    axutil_error_t *error = NULL;
    axutil_log_t *log = NULL;
    axutil_env_t *env = NULL;

    allocator = axutil_allocator_init(NULL);
    if (!allocator) return 2;
    error = axutil_error_create(allocator);
    log = axutil_log_create(allocator, NULL, NULL);
    env = axutil_env_create_with_error_log(allocator, error, log);
    if (!env) return 2;
    if (env->log) env->log->level = AXIS2_LOG_LEVEL_CRITICAL;

    {
        guththila_t raw;
        guththila_reader_t *raw_reader = guththila_reader_create_for_memory(
            (void *)xml, (int)strlen(xml), env);
        if (guththila_init(&raw, raw_reader, env) == GUTHTHILA_SUCCESS)
            printf("raw[0]=%d\n", guththila_next(&raw, env));
    }
    reader = axiom_xml_reader_create_for_memory(env, (void *)xml,
        (int)strlen(xml), NULL, AXIS2_XML_PARSER_TYPE_BUFFER);
    printf("reader=%p bytes=%zu\n", (void *)reader, strlen(xml));
    if (!reader) return 2;
    for (i = 0; i < 16; ++i)
    {
        int ev = reader->ops->next(reader, env);
        printf("event[%d]=%d\n", i, ev);
        if (ev == -1) break;
    }
    return 0;
}
