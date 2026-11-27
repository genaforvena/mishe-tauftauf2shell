#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

/* Minimal standalone config for the public MQTT rx_buffer overrun reproducer.
 * LWIP_ALTCP=1 keeps the real altcp_* symbols the PoC stubs.
 * MEM_LIBC_MALLOC=1 routes mem_malloc() to libc malloc. Note the overrun is
 * intra-object, so ASan stays silent; the oracle is UBSan array-bounds.
 */
#define NO_SYS                    1
#define LWIP_ALTCP                1
#define LWIP_TCP                  1
#define LWIP_UDP                  0
#define LWIP_NETCONN              0
#define LWIP_SOCKET               0
#define LWIP_RAW                  0
#define LWIP_DNS                  0
#define LWIP_DHCP                 0
#define LWIP_AUTOIP               0
#define LWIP_IGMP                 0
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK  0
#define MEM_LIBC_MALLOC           1
#define MEMP_LIBC_MALLOC          1
#define MQTT                      1

#endif /* LWIP_LWIPOPTS_H */
