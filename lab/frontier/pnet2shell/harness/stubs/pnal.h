/* Harness shim for platform types used by the pinned pnet_api.h/pf_types.h.
 * The release tarball omits the separate pnal/osal dependency; these opaque
 * typedefs preserve the field names and rough sizes needed to compile the
 * real pinned parser and struct layout. */
#ifndef HARNESS_PNAL_H
#define HARNESS_PNAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "pnet_options.h"

#define PNAL_HOSTNAME_MAX_SIZE 64
typedef uint32_t pnal_ipaddr_t;
typedef uint16_t pnal_ipport_t;
typedef struct pnal_eth_handle pnal_eth_handle_t;
typedef struct pnal_buf pnal_buf_t;
typedef struct pnal_eth_callback pnal_eth_callback_t;

typedef enum pnal_eth_mau
{
   PNAL_ETH_MAU_UNKNOWN = 0,
   PNAL_ETH_MAU_COPPER_100BaseTX_FULL_DUPLEX = 1,
} pnal_eth_mau_t;

typedef struct pnal_eth_status
{
   bool is_autonegotiation_supported;
   bool is_autonegotiation_enabled;
   pnal_eth_mau_t operational_mau_type;
   bool running;
} pnal_eth_status_t;

typedef struct pnal_cfg
{
   uint32_t unused;
} pnal_cfg_t;

typedef struct pnal_ethertype pnal_ethertype_t;
#endif
