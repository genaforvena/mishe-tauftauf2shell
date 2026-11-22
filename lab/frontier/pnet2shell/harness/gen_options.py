#!/usr/bin/env python3
"""Generate pnet_options.h from the pinned template for the local harness.

The release tarball has no CMake files, so the harness fixes every option
explicitly. PNET_MAX_MC_CR is 1 (the vendor's stated default); other sizes are
ordinary small configuration values and only affect struct layout, not the
presence of the unchecked index.
"""
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])

values = {
    "PNET_OPTION_FAST_STARTUP": 0,
    "PNET_OPTION_PARAMETER_SERVER": 0,
    "PNET_OPTION_IR": 0,
    "PNET_OPTION_SR": 0,
    "PNET_OPTION_REDUNDANCY": 0,
    "PNET_OPTION_AR_VENDOR_BLOCKS": 0,
    "PNET_OPTION_RS": 0,
    "PNET_OPTION_MC_CR": 1,
    "PNET_OPTION_SRL": 0,
    "PNET_OPTION_SNMP": 0,
    "PNET_OPTION_DRIVER_ENABLE": 0,
    "PNET_USE_ATOMICS": 0,
    "PNET_MAX_AR": 2,
    "PNET_MAX_API": 1,
    "PNET_MAX_CR": 2,
    "PNET_MAX_SLOTS": 10,
    "PNET_MAX_SUBSLOTS": 32,
    "PNET_MAX_DFP_IOCR": 0,
    "PNET_MAX_PHYSICAL_PORTS": 1,
    "PNET_MAX_LOG_BOOK_ENTRIES": 10,
    "PNET_MAX_ALARMS": 10,
    "PNET_MAX_ALARM_PAYLOAD_DATA_SIZE": 32,
    "PNET_MAX_DIAG_ITEMS": 10,
    "PNET_MAX_DIAG_MANUF_DATA_SIZE": 32,
    "PNET_MAX_MC_CR": 1,
    "PNET_MAX_AR_VENDOR_BLOCKS": 1,
    "PNET_MAX_AR_VENDOR_BLOCK_DATA_LENGTH": 32,
    "PNET_MAX_MAN_SPECIFIC_FAST_STARTUP_DATA_LENGTH": 32,
    "PNET_MAX_SESSION_BUFFER_SIZE": 4096,
    "PNET_MAX_DIRECTORYPATH_SIZE": 64,
    "PNET_MAX_FILENAME_SIZE": 64,
    "PNET_MAX_PORT_DESCRIPTION_SIZE": 64,
    "LOG_LEVEL": "INFO",
    "PF_ETH_LOG": "OFF",
    "PF_LLDP_LOG": "OFF",
    "PF_SNMP_LOG": "OFF",
    "PF_CPM_LOG": "OFF",
    "PF_PPM_LOG": "OFF",
    "PF_DCP_LOG": "OFF",
    "PF_RPC_LOG": "OFF",
    "PF_ALARM_LOG": "OFF",
    "PF_AL_BUF_LOG": "OFF",
    "PF_PNAL_LOG": "OFF",
    "PNET_LOG": "OFF",
}
import re

text = src.read_text()
for name, value in values.items():
    text = text.replace("@%s@" % name, str(value))
if "@" in text.replace('"@"', ""):
    leftovers = sorted(set(part for part in text.split("@")[1::2]))
    raise SystemExit("unsubstituted template tokens: %s" % leftovers)
text = re.sub(
    r"^#cmakedefine01 ([A-Z_0-9]+)$",
    lambda m: "#define %s %s" % (m.group(1), values[m.group(1)]),
    text,
    flags=re.MULTILINE,
)
dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(text)
