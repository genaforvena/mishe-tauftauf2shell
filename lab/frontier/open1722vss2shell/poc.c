/*
 * Open1722 VSS path-length harness.  The PDU is built and consumed through
 * the pinned public API; Vss.c and InlineExports.c are compiled unmodified
 * from either the vulnerable tag or the fixed commit.  Nothing here is a
 * hand-copied approximation of the library function.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "avtp/acf/AcfCommon.h"
#include "avtp/acf/custom/Vss.h"

static uint8_t *frame(size_t bytes)
{
    uint8_t *p = (uint8_t *)calloc(bytes, 1);
    if (p == NULL) {
        fprintf(stderr, "calloc failed\n");
        exit(2);
    }
    return p;
}

static Avtp_Vss_t *header(uint8_t *p, uint16_t declared_bytes, Vss_AddrMode_t mode,
                          Vss_Datatype_t datatype)
{
    Avtp_Vss_t *vss = (Avtp_Vss_t *)p;
    Avtp_Vss_Init(vss);
    Avtp_Vss_SetAddrMode(vss, mode);
    Avtp_Vss_SetDatatype(vss, datatype);
    Avtp_AcfCommon_SetAcfMsgLength((Avtp_AcfCommon_t *)p,
                                   (uint64_t)(declared_bytes / AVTP_QUADLET_SIZE));
    return vss;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s CASE\n", argv[0]);
        return 2;
    }
    const char *test = argv[1];

    if (strcmp(test, "read_oob") == 0) {
        /* Header-only INTEROP frame: the 2-byte path prefix is not inside
         * the declared message or the allocation. */
        uint8_t *p = frame(AVTP_VSS_FIXED_HEADER_LEN);
        Avtp_Vss_t *vss = header(p, AVTP_VSS_FIXED_HEADER_LEN, VSS_INTEROP_MODE, VSS_UINT8);
        printf("read_oob valid=%d\n", Avtp_Vss_IsValid(vss, AVTP_VSS_FIXED_HEADER_LEN));
        printf("read_oob len=%u\n", Avtp_Vss_CalcVssPathLength(vss));
        free(p);
        return 0;
    }

    if (strcmp(test, "adjacent") == 0) {
        /* Chosen prefix bytes live in the object adjacent to the declared
         * header-only frame.  Vulnerable code reads them despite the
         * declared length; fixed code returns 0. */
        uint8_t *p = frame(AVTP_VSS_FIXED_HEADER_LEN + 2);
        Avtp_Vss_t *vss = header(p, AVTP_VSS_FIXED_HEADER_LEN, VSS_INTEROP_MODE, VSS_UINT8);
        p[AVTP_VSS_FIXED_HEADER_LEN] = 0x41;
        p[AVTP_VSS_FIXED_HEADER_LEN + 1] = 0x42;
        printf("adjacent len=%u\n", Avtp_Vss_CalcVssPathLength(vss));
        free(p);
        return 0;
    }

    if (strcmp(test, "wrap") == 0) {
        /* 0xFFFF + 2 wraps uint16 to 1, so the writer targets the path
         * area instead of the position after a 65537-byte path. */
        uint8_t *p = frame(AVTP_VSS_FIXED_HEADER_LEN + 12);
        Avtp_Vss_t *vss = header(p, AVTP_VSS_FIXED_HEADER_LEN + 8, VSS_INTEROP_MODE, VSS_UINT8);
        p[AVTP_VSS_FIXED_HEADER_LEN] = 0xff;
        p[AVTP_VSS_FIXED_HEADER_LEN + 1] = 0xff;
        VssData_t data;
        memset(&data, 0, sizeof(data));
        data.data_uint8 = 0x5a;
        printf("wrap len=%u\n", Avtp_Vss_CalcVssPathLength(vss));
        Avtp_Vss_SetVssData(vss, &data);
        printf("wrap b12=%02x b13=%02x b20=%02x\n",
               p[AVTP_VSS_FIXED_HEADER_LEN], p[AVTP_VSS_FIXED_HEADER_LEN + 1], p[20]);
        free(p);
        return 0;
    }

    if (strcmp(test, "safe") == 0) {
        /* Well-framed INTEROP frame: prefix 0x0004 means a 6-byte path and
         * the data byte belongs at offset 18. */
        uint8_t *p = frame(AVTP_VSS_FIXED_HEADER_LEN + 12);
        Avtp_Vss_t *vss = header(p, AVTP_VSS_FIXED_HEADER_LEN + 8, VSS_INTEROP_MODE, VSS_UINT8);
        p[AVTP_VSS_FIXED_HEADER_LEN] = 0x00;
        p[AVTP_VSS_FIXED_HEADER_LEN + 1] = 0x04;
        VssData_t data;
        memset(&data, 0, sizeof(data));
        data.data_uint8 = 0x5a;
        printf("safe len=%u\n", Avtp_Vss_CalcVssPathLength(vss));
        Avtp_Vss_SetVssData(vss, &data);
        printf("safe b18=%02x\n", p[18]);
        free(p);
        return 0;
    }

    fprintf(stderr, "unknown case %s\n", test);
    return 2;
}
