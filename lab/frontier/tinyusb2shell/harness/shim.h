/* Minimal local scaffolding for the verbatim TinyUSB HID report-descriptor
 * parser. All constants below are copied by value from the pinned headers:
 * src/class/hid/hid.h (enum values) and src/class/hid/hid_host.h
 * (tuh_hid_report_info_t). No upstream source is modified. */
#ifndef TINYUSB_HID_SHIM_H
#define TINYUSB_HID_SHIM_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TU_ATTR_PACKED __attribute__((packed))
#define TU_MIN(_x, _y) (((_x) < (_y)) ? (_x) : (_y))
#define tu_memclr(buffer, size) (void) memset((buffer), 0, (size))
#define TU_LOG(n, ...) ((void) 0)
#define TU_LOG_DRV(...) ((void) 0)

typedef struct {
  uint8_t  report_id;
  uint8_t  usage;
  uint16_t usage_page;
} tuh_hid_report_info_t;

/* hid.h: Report Item Types */
enum { RI_TYPE_MAIN = 0, RI_TYPE_GLOBAL = 1, RI_TYPE_LOCAL = 2 };
/* hid.h: Report Item Main group */
enum {
  RI_MAIN_INPUT = 8, RI_MAIN_OUTPUT = 9, RI_MAIN_COLLECTION = 10,
  RI_MAIN_FEATURE = 11, RI_MAIN_COLLECTION_END = 12
};
/* hid.h: Report Item Global group */
enum {
  RI_GLOBAL_USAGE_PAGE = 0, RI_GLOBAL_LOGICAL_MIN = 1,
  RI_GLOBAL_LOGICAL_MAX = 2, RI_GLOBAL_PHYSICAL_MIN = 3,
  RI_GLOBAL_PHYSICAL_MAX = 4, RI_GLOBAL_UNIT_EXPONENT = 5,
  RI_GLOBAL_UNIT = 6, RI_GLOBAL_REPORT_SIZE = 7,
  RI_GLOBAL_REPORT_ID = 8, RI_GLOBAL_REPORT_COUNT = 9,
  RI_GLOBAL_PUSH = 10, RI_GLOBAL_POP = 11
};
/* hid.h: Report Item Local group */
enum {
  RI_LOCAL_USAGE = 0, RI_LOCAL_USAGE_MIN = 1, RI_LOCAL_USAGE_MAX = 2,
  RI_LOCAL_DESIGNATOR_INDEX = 3, RI_LOCAL_DESIGNATOR_MIN = 4,
  RI_LOCAL_DESIGNATOR_MAX = 5, RI_LOCAL_STRING_INDEX = 7,
  RI_LOCAL_STRING_MIN = 8, RI_LOCAL_STRING_MAX = 9,
  RI_LOCAL_DELIMITER = 10
};

#endif
