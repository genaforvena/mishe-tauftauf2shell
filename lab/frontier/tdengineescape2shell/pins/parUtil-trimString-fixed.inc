#line 425 "parUtil.c"
int32_t trimString(const char* src, int32_t len, char* dst, int32_t dlen) {
  if (len <= 0 || dlen <= 0) return 0;

  char    delim = src[0];
  int32_t j = 0;
  for (uint32_t k = 1; k < len - 1; ++k) {
    if (j >= dlen) {
      dst[j - 1] = '\0';
      return j;
    }
    if (src[k] == delim && src[k + 1] == delim) {  // deal with "", ''
      dst[j] = src[k + 1];
      j++;
      k++;
      continue;
    }

    if (src[k] == '\\') {  // deal with escape character
      if (src[k + 1] == 'n') {
        dst[j] = '\n';
      } else if (src[k + 1] == 'r') {
        dst[j] = '\r';
      } else if (src[k + 1] == 't') {
        dst[j] = '\t';
      } else if (src[k + 1] == '\\') {
        dst[j] = '\\';
      } else if (src[k + 1] == '\'') {
        dst[j] = '\'';
      } else if (src[k + 1] == '"') {
        dst[j] = '"';
      } else if (src[k + 1] == 'f') {
        dst[j] = '\f';
      } else if (src[k + 1] == 'b') {
        dst[j] = '\b';
#line 459 "parUtil.c"
      } else if (src[k + 1] == '%' || src[k + 1] == '_' || src[k + 1] == 'x') {
        // Security fix: Check bounds before writing 2 bytes for escape sequences
        if (j + 1 >= dlen) {
          dst[j] = '\0';
          return j;
        }
        dst[j++] = src[k];
        dst[j] = src[k + 1];
      } else {
        dst[j] = src[k + 1];
      }
      j++;
      k++;
      continue;
    }

    dst[j] = src[k];
    j++;
  }
  if (j >= dlen) j = dlen - 1;
  dst[j] = '\0';
  return j;
}
