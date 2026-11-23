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

#line 2424 "convert.c.fixed"
#define F_ExtractOldTo(qp, buf, ch, maxsize) \
do { \
	size_t	c = 0; \
	while ((qp)->statement[qp->opos] != '\0' && (qp)->statement[qp->opos] != ch) \
	{ \
		if (c + 1 >= maxsize) \
			break; \
		buf[c++] = (qp)->statement[qp->opos++];	\
	} \
	if ((qp)->statement[qp->opos] == '\0')	\
		{retval = SQL_ERROR; goto cleanup;} \
	buf[c] = '\0'; \
} while (0)
#line 5607 "convert.c.fixed"
static int
processParameters(QueryParse *qp, QueryBuild *qb,
		size_t *output_count, SQLLEN param_pos[][2], size_t param_pos_count)
{
	int retval, innerParenthesis, param_count;
	BOOL stop;

	/* begin with outer '(' */
	innerParenthesis = 0;
	param_count = 0;
	if (NULL != output_count)
		*output_count = 0;
	stop = FALSE;
	for (; F_OldPos(qp) < qp->stmt_len; F_OldNext(qp))
	{
		retval = inner_process_tokens(qp, qb);
		if (retval == SQL_ERROR)
			return retval;
		if (MBCS_NON_ASCII(qp->encstr))
			continue;
		if (!QP_in_idle_status(qp))
			continue;

		switch (F_OldChar(qp))
		{
			case ',':
				if (1 == innerParenthesis)
				{
					if ((size_t) (param_count + 1) >= param_pos_count)
					{
						qb->errornumber = STMT_EXEC_ERROR;
						qb->errormsg = "too many parameters in the escape function call";
						return SQL_ERROR;
					}
					param_pos[param_count][1] = F_NewPos(qb) - 2;
					param_count++;
					param_pos[param_count][0] = F_NewPos(qb);
					param_pos[param_count][1] = -1;
				}
				break;
			case '(':
				if (0 == innerParenthesis)
				{
					param_pos[param_count][0] = F_NewPos(qb);
					param_pos[param_count][1] = -1;
				}
				innerParenthesis++;
				break;

			case ')':
				innerParenthesis--;
				if (0 == innerParenthesis)
				{
					if ((size_t) (param_count + 1) >= param_pos_count)
					{
						qb->errornumber = STMT_EXEC_ERROR;
						qb->errormsg = "too many parameters in the escape function call";
						return SQL_ERROR;
					}
					param_pos[param_count][1] = F_NewPos(qb) - 2;
					param_count++;
					param_pos[param_count][0] =
					param_pos[param_count][1] = -1;
				}
				if (output_count)
					*output_count = F_NewPos(qb);
				break;

			case ODBC_ESCAPE_END:
				stop = (0 == innerParenthesis);
				break;

		}
		if (stop) /* returns with the last } position */
			break;
	}
	if (param_pos[param_count][0] >= 0)
	{
		MYLOG(0, "closing ) not found %d\n", innerParenthesis);
		qb->errornumber = STMT_EXEC_ERROR;
		qb->errormsg = "processParameters closing ) not found";
		return SQL_ERROR;
	}
	else if (1 == param_count) /* the 1 parameter is really valid ? */
	{
		BOOL	param_exist = FALSE;
		SQLLEN	i;

		for (i = param_pos[0][0]; i <= param_pos[0][1]; i++)
		{
			if (IS_NOT_SPACE(qb->query_statement[i]))
			{
				param_exist = TRUE;
				break;
			}
		}
		if (!param_exist)
		{
			param_pos[0][0] = param_pos[0][1] = -1;
		}
	}

	return SQL_SUCCESS;
}
#define PP_CALL(q,a,o,p) processParameters((q),(a),(o),(p),16)

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
#line 2424 "convert.c.fixed"
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
