/* Harness-only lwIP core stubs.
 * Only the primitives the public MQTT reproducer reaches are implemented.
 * All allocations go to libc malloc so ASan reports the rx_buffer overrun as
 * a genuine heap-buffer-overflow on the mqtt_client_t allocation. */
#include "lwip/pbuf.h"
#include "lwip/mem.h"
#include <stdlib.h>
#include <string.h>

void *mem_malloc(mem_size_t size) { return malloc(size); }
void *mem_calloc(mem_size_t count, mem_size_t size) { return calloc(count, size); }
void mem_free(void *mem) { free(mem); }

struct pbuf *pbuf_alloc(pbuf_layer l, u16_t length, pbuf_type type)
{
  (void)l; (void)type;
  struct pbuf *p;
  p = (struct pbuf *)malloc(sizeof(struct pbuf) + length);
  if (p == NULL) return NULL;
  memset(p, 0, sizeof(*p));
  p->payload = (u8_t *)(p + 1);
  p->len = length;
  p->tot_len = length;
  p->next = NULL;
  return p;
}

u8_t pbuf_free(struct pbuf *p) { free(p); return 1; }

u8_t pbuf_get_at(const struct pbuf *p, u16_t offset)
{
  return ((const u8_t *)p->payload)[offset];
}

void *pbuf_get_contiguous(const struct pbuf *p, void *buffer, size_t bufsize,
                          u16_t len, u16_t offset)
{
  size_t avail;
  if (offset <= p->len && (size_t)len <= (size_t)(p->len - offset))
    return (u8_t *)p->payload + offset;
  if (len > bufsize) return NULL;
  avail = (offset < p->len) ? (size_t)(p->len - offset) : 0;
  memset(buffer, 0, bufsize);
  if (avail) memcpy(buffer, (const u8_t *)p->payload + offset, avail);
  return buffer;
}
