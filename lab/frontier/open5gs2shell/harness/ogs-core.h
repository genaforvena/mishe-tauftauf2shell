/* Stand-in for the parts of ogs-core.h used by the pinned parser file.
 * The pinned multipart_parser-v2.8.0.c is compiled verbatim, untouched. */
#ifndef OGS_CORE_H_STANDIN
#define OGS_CORE_H_STANDIN
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OGS_GNUC_FALLTHROUGH do { } while (0)
#define OGS_ERROR (-1)

static void ogs_error(const char *message) { printf("ERROR=%s\n", message); }
static void ogs_free(void *p) { free(p); }

#endif
