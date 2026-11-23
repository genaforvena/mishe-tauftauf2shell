#line 231 "l2_ppp.c.8bb65c64926d"
static size_t ppp_tx_frame(struct mg_tcpip_if *ifp, uint16_t proto,
                           uint8_t *data, size_t datasz) {
  uint8_t *pay = ppp_tx_frame_header(ifp, proto);
  memcpy(pay, data, datasz);
  return ppp_tx_frame_trailer(ifp, datasz, pay + datasz);
}
