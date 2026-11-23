/* Real-object driver for CVE-2026-120061: calls upstream
 * prepareParametersNoDesc() from pinned psqlODBC objects. No stubs, no
 * copied source slices. Only a zeroed StatementClass/ConnectionClass is
 * constructed, because no PostgreSQL server is available in the lab.
 */
#include "config.h"
#include "psqlodbc.h"
#include "connection.h"
#include "statement.h"
#include "bind.h"
#include "convert.h"
#include "descriptor.h"
#include <stdlib.h>
#include <string.h>

extern RETCODE prepareParametersNoDesc(StatementClass *stmt, BOOL fake_params, BOOL param_cast);

int main(int argc, char **argv)
{
	ConnectionClass *conn;
	StatementClass *stmt;
	RETCODE rc;
	const char *sql = (argc > 1) ? argv[1] : "{fn CONCAT(1,2)}";

	conn = calloc(1, sizeof(ConnectionClass));
	stmt = calloc(1, sizeof(StatementClass));
	if (!conn || !stmt)
		return 2;
	stmt->ipd = calloc(1, sizeof(DescriptorClass));
	stmt->apd = calloc(1, sizeof(DescriptorClass));
	stmt->ard = calloc(1, sizeof(DescriptorClass));
	stmt->ird = calloc(1, sizeof(DescriptorClass));
	stmt->hdbc = conn;
	stmt->statement = strdup(sql);
	stmt->statement_type = STMT_TYPE_SELECT;
	conn->pg_version_major = 14;
	conn->pg_version_minor = 0;
	conn->ccsc = 0;
	setbuf(stdout, NULL);
	rc = prepareParametersNoDesc(stmt, FALSE, FALSE);
	printf("RC=%d ERRNUM=%d ERRMSG=%s OUT=%s\n", (int) rc,
	       (int) SC_get_errornumber(stmt),
	       SC_get_errormsg(stmt) ? SC_get_errormsg(stmt) : "(null)",
	       stmt->statement ? stmt->statement : "(null)");
	return rc == SQL_SUCCESS ? 0 : 1;
}
