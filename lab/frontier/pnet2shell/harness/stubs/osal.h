#ifndef HARNESS_OSAL_H
#define HARNESS_OSAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint32_t osal_tick_t;
#define BIT(n) (1u << (n))
#define NELEMENTS(a) (sizeof(a) / sizeof((a)[0]))
#define CC_PACKED_BEGIN
#define CC_PACKED __attribute__((packed))
#define CC_PACKED_END
#define CC_STATIC_ASSERT(x) _Static_assert((x), #x)
typedef struct os_mutex os_mutex_t;
typedef struct os_event os_event_t;

#endif
