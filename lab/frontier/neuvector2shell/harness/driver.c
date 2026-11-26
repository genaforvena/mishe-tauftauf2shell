/* Stand-in driver for the verbatim pinned dpi_sig_bld() function.
 * The function body is included byte-for-byte from pins/; only types,
 * macros and external collaborators are replaced by local stand-ins.
 * No NeuVector binary, Go controller, API or network wire is exercised.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USER_SIG_LEN 2048
#define MSG_START 1
#define MSG_END 2
#define DBG_DETECT 0
#define DEBUG_ERROR(a, ...) ((void)0)
#define DEBUG_DLP(...) ((void)0)
#define GET_NEW_DLP_DETECTOR_VER() ((uint16_t)1)

typedef struct { unsigned int db_count, db_bytes, scratch_size; } dpi_hs_summary_t;
struct ether_addr { unsigned char a[6]; };
typedef struct {
    uint16_t dlp_ver;
    dpi_hs_summary_t dlp_pcre_hs_summary;
    int dlp_ref_cnt;
} dpi_detector_t;
typedef struct { char *rule_pattern; } dpi_rule_pat_t;
typedef struct {
    char *rulename;
    unsigned int sigid;
    int num_dlp_rule_pats;
    dpi_rule_pat_t *dlp_rule_pat_list;
} dpi_rule_t;
typedef struct {
    int num_macs, num_del_macs, num_dlp_rules, apply_dir;
    struct ether_addr *mac_list, *del_mac_list;
    dpi_rule_t *dlp_rule_list;
} dpi_dlpbld_t;

static dpi_detector_t g_detector;
static unsigned char g_capture[4096];
static int g_captured_len = 0;

static dpi_detector_t *dpi_dlp_detector_init(int apply_dir)
{
    (void)apply_dir;
    memset(&g_detector, 0, sizeof(g_detector));
    g_detector.dlp_ref_cnt = 1;
    return &g_detector;
}

static void dpi_dlp_detector_destroy(dpi_detector_t *d) { (void)d; }
static void dpi_dlp_detect_release(struct ether_addr *a) { (void)a; }
static void dpi_dlp_detect_update(struct ether_addr *a, dpi_detector_t *d)
{
    (void)a;
    (void)d;
}
static int dp_dlp_build_detector(dpi_detector_t *d)
{
    (void)d;
    return 0;
}

static void dpi_dlp_proc(char *buf, void *detector)
{
    (void)detector;
#ifdef PLAIN_MODE
    /* Plain builds only: read past the logical 2048-byte buffer to show
     * where the attacker-chosen bytes landed. ASan builds copy only the
     * in-bounds prefix so the readback cannot mask the first WRITE. */
    memcpy(g_capture, buf, sizeof(g_capture));
    g_captured_len = (int)strlen(buf);
#else
    memcpy(g_capture, buf, MAX_USER_SIG_LEN);
    g_captured_len = (int)strlen(buf);
#endif
}

#ifdef VARIANT_FIXED
#include "pins/dpi-fixed.inc"
#else
#include "pins/dpi-vulnerable.inc"
#endif

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "safe";
    int attack = strcmp(mode, "attack") == 0;
    size_t patlen = attack ? 2100 : 8;
    char *pattern = (char *)malloc(patlen + 1);
    char *name = (char *)malloc(16);
    dpi_rule_pat_t pats[1];
    dpi_rule_t rules[1];
    dpi_dlpbld_t bld;
    int rc;

    if (!pattern || !name) return 2;
    memset(pattern, 'M', patlen);
    pattern[patlen] = '\0';
    strcpy(name, "rule0");

    pats[0].rule_pattern = pattern;
    rules[0].rulename = name;
    rules[0].sigid = 42;
    rules[0].num_dlp_rule_pats = 1;
    rules[0].dlp_rule_pat_list = pats;

    memset(&bld, 0, sizeof(bld));
    bld.num_dlp_rules = 1;
    bld.apply_dir = 0;
    bld.dlp_rule_list = rules;

    rc = dpi_sig_bld(&bld, MSG_START | MSG_END);

    printf("MODE=%s PATLEN=%zu RC=%d SIG_LEN=%d\n",
           mode, patlen, rc, g_captured_len);
#ifdef PLAIN_MODE
    printf("CANARY_AFTER=");
    for (int i = 0; i < 16; i++)
        printf("%02x", g_capture[MAX_USER_SIG_LEN + i]);
    printf("\n");
#endif
    free(pattern);
    free(name);
    return 0;
}
