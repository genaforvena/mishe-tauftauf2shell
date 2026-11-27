/*
 * Direct-call harness for the libiscsi REPORT LUNS data-in unmarshaller.
 * A malicious iSCSI target's REPORT LUNS reply with 4..7 bytes of data-in
 * makes num_luns = datain.size/8 - 1 = -1. The allocation size wraps to two
 * bytes and list->num writes four bytes past it. The fixed build returns
 * NULL before the allocation (num_luns < 0 guard).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scsi-lowlevel.h"

int main(int argc, char **argv)
{
	unsigned char cdb[SCSI_CDB_MAX_SIZE];
	size_t size = 4;
	unsigned char *data;
	struct scsi_task *task;
	struct scsi_reportluns_list *list;
	int i;

	if (argc > 1)
		size = strtoul(argv[1], NULL, 10);
	if (size == 0 || size > 64)
		return 2;

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = SCSI_OPCODE_REPORTLUNS;

	/* scsi_free_scsi_task() frees datain.data, so this must be heap. */
	data = malloc(size);
	if (data == NULL)
		return 2;
	memset(data, 0x41, size);

	task = scsi_create_task(6, cdb, SCSI_XFER_READ, (int)size);
	if (task == NULL) {
		free(data);
		return 2;
	}
	task->datain.data = data;
	task->datain.size = size;

	list = scsi_datain_unmarshall(task);
	printf("unmarshall=%p datain_size=%zu", (void *)list, size);
	if (list != NULL)
		printf(" num=%u (%d)", list->num, (int)list->num);
	printf("\n");
	for (i = 0; i < 1; i++)
		fflush(stdout);

	scsi_free_scsi_task(task);
	return 0;
}
