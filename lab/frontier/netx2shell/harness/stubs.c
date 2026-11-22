/* Host-build link stubs only. No crypto or certificate logic lives here. */
#include <string.h>
#include "tx_api.h"

void *(*volatile _nx_crypto_memset_ptr)(void *dest, int value, size_t size) = memset;
void *(*volatile _nx_crypto_memcpy_ptr)(void *dest, const void *src, size_t size) = memcpy;

UINT _tx_thread_sleep(ULONG timer_ticks)
{
    (void)timer_ticks;
    return 0;
}
