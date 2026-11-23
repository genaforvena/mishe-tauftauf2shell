#line 350 "l2_ppp.c.8bb65c64926d"
static void ppp_handle_ipv6cp(struct mg_tcpip_if *ifp, uint8_t *ipv6cpp,
                              size_t ipv6cpsz) {
  uint16_t len;
  uint8_t id;
  struct ipv6cp *ipv6cp = (struct ipv6cp *) ipv6cpp;
  uint8_t req[14];
  memset(req, 0, sizeof(req));
  req[0] = MG_PPP_IPV6CP_CFG_REQ, req[3] = 14, req[4] = MG_PPP_IPV6CP_OPT_IFCID,
  req[5] = 10;
  if (ipv6cpsz < sizeof(*ipv6cp)) return;
  id = ipv6cp->id;
  len = mg_ntohs(ipv6cp->len);
  switch (ipv6cp->code) {
    case MG_PPP_IPV6CP_CFG_REQ:
      MG_VERBOSE(("got IPV6CP config request..."));
      if (len >= 10 &&
          find_opt(
              MG_PPP_IPV6CP_OPT_IFCID, 10, (const uint8_t *) (ipv6cp + 1),
              len - sizeof(*ipv6cp),
              (uint8_t *) &((struct mg_l2addr *) (ifp->gwmac))->addr.ieee64)) {
        if (((struct mg_l2addr *) (ifp->gwmac))->addr.ieee64 != 0) {
          MG_DEBUG(("IPV6CP cfg, GW IFCID: %M", mg_print_ieee64,
                    &((struct mg_l2addr *) (ifp->gwmac))->addr.ieee64));
          ipv6cp->code = MG_PPP_IPV6CP_CFG_ACK;
          ppp_tx_frame(ifp, MG_PPP_PROTO_IPV6CP, ipv6cpp, len);
          req[1] = id;
          ifp->ip6ll[0] = 0, ifp->ip6ll[1] = 0;  // clear any former ll address
          memset(req + 6, 0, 8);                 // Inform ifc id 0
          ppp_tx_frame(ifp, MG_PPP_PROTO_IPV6CP, req, sizeof(req));
        } else {
          MG_ERROR(("Peer is not able to provide its interface id"));
          ipv6cp->code = MG_PPP_IPV6CP_CFG_REJECT;
          ppp_tx_frame(ifp, MG_PPP_PROTO_IPV6CP, ipv6cpp, len);
        }
      } else {
        MG_ERROR(("Peer did not provide its interface id"));
        // We should NACK with an added option, but we can't provide one for
        // them
        ipv6cp->code = MG_PPP_IPV6CP_CFG_REJECT;
        ppp_tx_frame(ifp, MG_PPP_PROTO_IPV6CP, ipv6cpp, len);
      }
      break;
    case MG_PPP_IPV6CP_CFG_ACK:
      // Our peer accepted our ifc id
      MG_VERBOSE(("got IPV6CP config ack"));
      break;
    case MG_PPP_IPV6CP_CFG_NACK:
      MG_VERBOSE(("got IPV6CP config nack"));
      // NACK contains our "suggested" IFC id, use it
      if (len >= 10 &&
          find_opt(
              MG_PPP_IPV6CP_OPT_IFCID, 10, (const uint8_t *) (ipv6cp + 1),
              len - sizeof(*ipv6cp),
              (uint8_t *) &((struct mg_l2addr *) (ifp->mac))->addr.ieee64)) {
        MG_DEBUG(("IPV6CP cfg, IFCID: %M", mg_print_ieee64,
                  &((struct mg_l2addr *) (ifp->mac))->addr.ieee64));
        ipv6cp->code = MG_PPP_IPV6CP_CFG_REQ;
        ppp_tx_frame(ifp, MG_PPP_PROTO_IPV6CP, ipv6cpp, len);
      } else {
        MG_ERROR(("Peer is not able to offer an interface id"));
      }
      break;
    case MG_PPP_IPV6CP_CFG_REJECT:
      MG_ERROR(("Peer rejected our interface id"));
      break;
  }
}
