/*
 * Standalone probe of the stack-object store pattern in pinned pgactive
 * 2.1.9 src/pgactive_conflict_handlers.c:716,751-791. Real PostgreSQL 16.15
 * server headers supply FunctionCallInfoBaseData, NullableDatum and
 * InitFunctionCallInfoData; only the three pointer-producing calls
 * (heap_copy_tuple_as_datum x2, cstring_to_text) are replaced by chosen
 * constants so the program needs no backend. The store sequence and the
 * order of the args[] writes are the same as the pinned source.
 *
 * gcc -fsanitize=address -g -O0 \
 *   -I/tmp/pgactive-build/pg16root/usr/include/postgresql/16/server \
 *   fcinfo-probe.c -o fcinfo-probe
 */
#include "postgres.h"
#include "fmgr.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#undef printf				/* postgres.h redirects printf to pg_printf */

int
main(void)
{
	FmgrInfo	finfo;
	FunctionCallInfoBaseData fcinfo;

	memset(&finfo, 0, sizeof(finfo));
	printf("sizeof(FunctionCallInfoBaseData)=%zu offsetof(args)=%zu sizeof(NullableDatum)=%zu\n",
		   sizeof(FunctionCallInfoBaseData),
		   offsetof(FunctionCallInfoBaseData, args),
		   sizeof(NullableDatum));
	fflush(stdout);

	/* pinned :716 -- 2.1.9 uses the bare object, not LOCAL_FCINFO(fcinfo, 5) */
	InitFunctionCallInfoData(fcinfo, &finfo, 5, InvalidOid, NULL, NULL);

	/* pinned :759-791 -- five NullableDatum slots written past that object */
	fcinfo.args[0].value = (Datum) UINT64CONST(0x4141414141414141);
	fcinfo.args[0].isnull = false;
	fcinfo.args[1].value = (Datum) UINT64CONST(0x4242424242424242);
	fcinfo.args[1].isnull = false;
	fcinfo.args[2].value = (Datum) UINT64CONST(0x4343434343434343);
	fcinfo.args[2].isnull = false;
	fcinfo.args[3].value = (Datum) 4;
	fcinfo.args[3].isnull = false;
	fcinfo.args[4].value = (Datum) 5;
	fcinfo.args[4].isnull = false;

	printf("nargs=%d a4=%llu\n", fcinfo.nargs,
		   (unsigned long long) fcinfo.args[4].value);
	fflush(stdout);
	return 0;
}
