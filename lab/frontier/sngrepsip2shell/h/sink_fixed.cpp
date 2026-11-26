// frontier scaffolding (not upstream source): minimal types, globals, driver
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
#line 316 "src/sip.c"
int
sip_validate_packet(packet_t *packet)
{
    uint32_t plen = packet_payloadlen(packet);
    u_char payload[MAX_SIP_PAYLOAD + 1];
    regmatch_t pmatch[4];
    char cl_header[MAX_CONTENT_LENGTH_SIZE];
    int content_len;
    int bodylen;

    // Max SIP payload allowed
    if (plen == 0 || plen > MAX_SIP_PAYLOAD)
        return VALIDATE_NOT_SIP;

    // Get payload from packet(s)
    memset(payload, 0, sizeof(payload));
    memcpy(payload, packet_payload(packet), plen);

    // Initialize variables
    memset(cl_header, 0, sizeof(cl_header));

    // Check if the first line follows SIP request or response format
    if (regexec(&calls.reg_valid, (const char *) payload, 2, pmatch, 0) != 0) {
        // Not a SIP message AT ALL
        return VALIDATE_NOT_SIP;
    }

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
