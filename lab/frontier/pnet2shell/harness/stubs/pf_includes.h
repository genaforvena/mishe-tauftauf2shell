/* Harness shim: only the real pinned type headers needed by
 * src/device/pf_block_reader.c. Generated pnet_options.h supplies the
 * compile-time configuration; osal/log are no-op stubs. */
#ifndef HARNESS_PF_INCLUDES_H
#define HARNESS_PF_INCLUDES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "osal.h"
#include "osal_log.h"
#include "pnal.h"
#include "pnet_api.h"
#include "pf_types.h"
#endif
