#line 278 "l2_ppp.c.751f14742dea"
static bool find_opt(const uint8_t opt, const uint8_t optlen,
                     const uint8_t *opts, size_t optslen, uint8_t *dest) {
  uint8_t *p = (uint8_t *) opts;
  while (optslen >= 2) {  // parse options for requested one
    if (p[1] > optslen || p[1] < 2) return false;  // truncated / malformed
    if (p[0] == opt && p[1] == optlen) {
      memcpy(dest, p + 2, optlen - 2);
      return true;
    }
    optslen -= p[1];
    p += p[1];
  }
  return false;
}
