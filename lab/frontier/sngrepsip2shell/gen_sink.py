#!/usr/bin/env python3
"""Generate harness TUs from verbatim pinned src/sip.c slices.

The slice is raw lines 316-341 of the pinned blob (sip_validate_packet through
its first regexec). Nothing inside the #line-mapped slice is authored here;
all scaffolding is in the header/footer and is labeled frontier scaffolding.
"""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parent
PINS = ROOT / "pins"
OUT = ROOT / "h"
START, END = 316, 341  # inclusive, 1-based, raw pinned blob

HEADER = r'''// frontier scaffolding (not upstream source): minimal types, globals, driver
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u_char;
typedef struct packet { uint32_t payload_len; u_char *payload; } packet_t;
static u_char *packet_payload(packet_t *p) { return p->payload; }
static uint32_t packet_payloadlen(packet_t *p) { return p->payload_len; }
#define VALIDATE_NOT_SIP 0
#define MAX_SIP_PAYLOAD 10240  /* verbatim raw sip.h:47, pinned */
#define MAX_CONTENT_LENGTH_SIZE 10 /* verbatim raw sip.h:50, pinned */
static struct { regex_t reg_valid; } calls;
'''

FOOTER = r'''
#line 500 "frontier-driver.cpp"
    return VALIDATE_NOT_SIP;
}

// frontier scaffolding: build a nonzero SIP payload of the requested size.
int main(int argc, char **argv) {
    size_t len = argc > 1 ? strtoul(argv[1], NULL, 10) : 10240;
    int flags = REG_EXTENDED | REG_ICASE;  /* raw sip.c:174/:201 flags */
    if (regcomp(&calls.reg_valid, "^([A-Z]+ [A-Z]+:|SIP/2\\.0 [0-9]{3})", flags) != 0)
        return 2;
    u_char *src = (u_char *)malloc(len ? len : 1);
    if (!src) return 3;
    for (size_t i = 0; i < len; i++) src[i] = (u_char)'A'; /* no NUL byte */
    packet_t packet;
    packet.payload_len = (uint32_t)len;
    packet.payload = src;
    int rc = sip_validate_packet(&packet);
    printf("SIP_VALIDATE_RC=%d payload_len=%zu\n", rc, len);
    free(src);
    regfree(&calls.reg_valid);
    return 0;
}
'''

EXPECT = {
    320: "    u_char payload[MAX_SIP_PAYLOAD{fix}];",
    327: "    if (plen == 0 || plen > MAX_SIP_PAYLOAD)",
    331: "    memset(payload, 0, {memset});",
    332: "    memcpy(payload, packet_payload(packet), plen);",
    338: "    if (regexec(&calls.reg_valid, (const char *) payload, 2, pmatch, 0) != 0) {",
}


def generate(name: str, fixed: bool) -> None:
    raw = (PINS / name).read_bytes().decode("utf-8")
    lines = raw.splitlines(keepends=True)
    assert len(lines) >= END, "short pinned blob"
    for lineno, template in EXPECT.items():
        if fixed and lineno in (320, 331):
            want = template.replace("{fix}", " + 1").replace("{memset}", "sizeof(payload)")
        else:
            want = template.replace("{fix}", "").replace("{memset}", "MAX_SIP_PAYLOAD")
        assert lines[lineno - 1].rstrip("\n") == want, (name, lineno, lines[lineno - 1])
    slice_text = "".join(lines[START - 1:END])
    out = HEADER + f'#line {START} "src/sip.c"\n' + slice_text + FOOTER
    dest = OUT / ("sink_fixed.cpp" if fixed else "sink_vuln.cpp")
    dest.write_text(out)
    digest = hashlib.sha256(slice_text.encode()).hexdigest()[:16]
    print(f"SLICE_OK {dest.name} raw:{START}-{END} sha256-16={digest}")


if __name__ == "__main__":
    generate("sip.c.vuln", False)
    generate("sip.c.fixed", True)
    for pin in ("sip.c.vuln", "sip.c.fixed", "sip.h.vuln", "packet.h.vuln"):
        h = hashlib.sha256((PINS / pin).read_bytes()).hexdigest()
        print(f"PIN {pin} {h}")
    sys.exit(0)
