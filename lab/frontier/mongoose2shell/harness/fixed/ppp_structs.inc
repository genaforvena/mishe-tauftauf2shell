#line 10 "l2_ppp.c.751f14742dea"
#if defined(__DCC__)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
// all in network order

struct ppp {  // RFC-1661
  uint16_t proto;
};

struct lcp {  // RFC-1661
  uint8_t code, id;
  uint16_t len;
};

struct ipcp {  // RFC-1332
  uint8_t code, id;
  uint16_t len;
};

struct ipv6cp {  // RFC-5072
  uint8_t code, id;
  uint16_t len;
};

struct hdlc_ {  // RFC-1662, "PPP in HDLC-like Framing"
  uint8_t addr, ctrl;
};

struct pppoe {  // RFC-2516, "A Method for Transmitting PPP Over Ethernet
                // (PPPoE)"
  uint8_t vertype, code;
  uint16_t id, len;
};

#if defined(__DCC__)
#pragma pack(0)
#else
#pragma pack(pop)
#endif

#define MG_PPP_ADDR 0xff
#define MG_PPP_CTRL 0x03

#define MG_PPP_PROTO_IP 0x0021
#define MG_PPP_PROTO_IPV6 0x0057
#define MG_PPP_PROTO_LCP 0xc021
#define MG_PPP_PROTO_IPCP 0x8021
#define MG_PPP_PROTO_IPV6CP 0x8057
#define MG_PPP_PROTO_PAP 0xc023
#define MG_PPP_PROTO_CHAP 0xc223

#define MG_PPP_LCP_CFG_REQ 1
#define MG_PPP_LCP_CFG_ACK 2
#define MG_PPP_LCP_CFG_NACK 3
#define MG_PPP_LCP_CFG_REJECT 4
#define MG_PPP_LCP_CFG_TERM_REQ 5
#define MG_PPP_LCP_CFG_TERM_ACK 6
#define MG_PPP_LCP_REJECT 8
#define MG_PPP_LCP_ECHO_REQ 9
#define MG_PPP_LCP_ECHO_REPLY 10

#define MG_PPP_IPCP_CFG_REQ 1
#define MG_PPP_IPCP_CFG_ACK 2
#define MG_PPP_IPCP_CFG_NACK 3
#define MG_PPP_IPCP_CFG_REJECT 4
#define MG_PPP_IPCP_OPT_IPADDR 3

#define MG_PPP_IPV6CP_CFG_REQ 1
#define MG_PPP_IPV6CP_CFG_ACK 2
#define MG_PPP_IPV6CP_CFG_NACK 3
#define MG_PPP_IPV6CP_CFG_REJECT 4
#define MG_PPP_IPV6CP_OPT_IFCID 1

#define MG_PPPoE_PADI 0x09
#define MG_PPPoE_PADO 0x07
#define MG_PPPoE_PADR 0x19
#define MG_PPPoE_PADS 0x65
#define MG_PPPoE_PADT 0xa7
