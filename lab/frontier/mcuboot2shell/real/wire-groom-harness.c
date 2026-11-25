/*
 * W3: W2's loopback wire server with the W1 groom/readback path enabled.
 * Server locals are static under WIRE_GROOM (see wire-harness.c), and the
 * chosen 16-byte plaintext comes from the wire after the 32-byte header.
 * This is still a lab transport shim: no SMP parser, no real image/TLV.
 */
#define WIRE_GROOM 1
#include "wire-harness.c"
