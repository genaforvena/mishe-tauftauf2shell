/* Minimal real-library caller for CVE-2026-137063.
 * Calls the upstream l_byteaInitFromFile() API; no upstream byte is edited.
 */
#include <stdio.h>
#include "allheaders.h"

int main(int argc, char **argv)
{
    L_BYTEA   *ba;
    l_uint8   *data;
    size_t     nbytes;

    if (argc != 2) return 2;
    ba = l_byteaInitFromFile(argv[1]);
    printf("BA=%s\n", ba ? "nonnull" : "NULL");
    if (!ba) return 0;
    data = l_byteaGetData(ba, &nbytes);
    printf("SIZE=%zu FIRST=%02x\n", nbytes, data ? data[0] : 0);
    l_byteaDestroy(&ba);
    return 0;
}
