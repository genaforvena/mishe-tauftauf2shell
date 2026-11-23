/* Public ODBC API reachability harness for CVE-2026-120061.
 * Uses unixODBC's driver manager, the pinned psqlODBC driver .so and a
 * loopback fake PostgreSQL handshake (fakepg.py). No stubs and no copied
 * parser source. SQLDriverConnect + SQLExecDirect carry the crafted SQL.
 */
#include <stdio.h>
#include <string.h>
#include <sql.h>
#include <sqlext.h>

static void diag(SQLSMALLINT type, SQLHANDLE h)
{
	SQLCHAR state[8], msg[512];
	SQLINTEGER nat;
	SQLSMALLINT len, i = 1;
	while (SQLGetDiagRec(type, h, i++, state, &nat, msg, sizeof(msg), &len) == SQL_SUCCESS)
		printf("DIAG state=%s nat=%d msg=%s\n", state, (int) nat, msg);
}

int main(int argc, char **argv)
{
	SQLHENV env;
	SQLHDBC dbc;
	SQLHSTMT stmt;
	SQLRETURN rc;
	SQLCHAR out[1024];
	SQLSMALLINT olen;
	const char *sql = (argc > 1) ? argv[1] : "{fn CONCAT(1,2)}";
	const int use_exec = (argc > 2 && strcmp(argv[2], "exec") == 0);

	setbuf(stdout, NULL);
	if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env) != SQL_SUCCESS)
		return 2;
	SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER) SQL_OV_ODBC3, 0);
	if (SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc) != SQL_SUCCESS)
		return 2;
	rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *) "DSN=pg2shell;", SQL_NTS,
	                      out, sizeof(out), &olen, SQL_DRIVER_NOPROMPT);
	printf("CONNECT rc=%d\n", (int) rc);
	if (rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO) {
		diag(SQL_HANDLE_DBC, dbc);
		return 2;
	}
	if (SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt) != SQL_SUCCESS)
		return 2;
	if (use_exec)
		rc = SQLExecDirect(stmt, (SQLCHAR *) sql, SQL_NTS);
	else
		rc = SQLPrepare(stmt, (SQLCHAR *) sql, SQL_NTS);
	printf("%s rc=%d\n", use_exec ? "EXECDIRECT" : "PREPARE", (int) rc);
	if (rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO)
		diag(SQL_HANDLE_STMT, stmt);
	return (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO) ? 0 : 1;
}
