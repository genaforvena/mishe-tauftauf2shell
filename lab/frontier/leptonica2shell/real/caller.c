/* Reachability probe through the in-tree library caller of
 * l_byteaInitFromFile(): saConcatenatePdfToData() in src/pdfio1.c.
 * The oversized PDF-list member triggers the same upstream memcpy.
 */
#include <stdio.h>
#include "allheaders.h"

int main(int argc, char **argv)
{
    SARRAY   *sa;
    l_uint8  *data = NULL;
    size_t    nbytes = 0;
    l_int32   ret;

    if (argc != 2) return 2;
    sa = sarrayCreate(1);
    sarrayAddString(sa, argv[1], L_COPY);
    ret = saConcatenatePdfToData(sa, &data, &nbytes);
    if (data) LEPT_FREE(data);
    sarrayDestroy(&sa);
    return 0;
}
