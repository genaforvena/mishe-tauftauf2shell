/*
 * Lab-only deterministic core harness for MsQuic CVE-2026-62815.
 *
 * Drives the exact two core operations from one receive cycle:
 *   QuicPathRemove()            <- NEW_CONNECTION_ID retire, non-active path
 *   QuicConnRecvPostProcessing() <- promotes the now-stale QUIC_PATH*
 *
 * No TLS, no network, no synthetic packet encryption. This is a core-state
 * experiment, NOT wire traffic and NOT a rung-4/rung-5 claim.
 */
#include "precomp.h"
#include <stdio.h>
#include <stdlib.h>

/* Not declared in public headers; definition lives in core/connection.c. */
void QuicConnRecvPostProcessing(QUIC_CONNECTION* Connection, QUIC_PATH** Path, QUIC_RX_PACKET* Packet);

static
QUIC_STATUS
NoopConnCallback(
    HQUIC Connection,
    void* Context,
    QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Connection);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Event);
    return QUIC_STATUS_SUCCESS;
}

static
void
NoopCcReset(
    QUIC_CONGESTION_CONTROL* Cc,
    BOOLEAN FullReset
    )
{
    UNREFERENCED_PARAMETER(Cc);
    UNREFERENCED_PARAMETER(FullReset);
}

int
main(
    int argc,
    char** argv
    )
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    QUIC_CONNECTION* Conn = (QUIC_CONNECTION*)calloc(1, sizeof(QUIC_CONNECTION));
    if (Conn == NULL) {
        return 2;
    }

    QUIC_CID_LIST_ENTRY Cid0, Cid1;
    memset(&Cid0, 0, sizeof(Cid0));
    memset(&Cid1, 0, sizeof(Cid1));

    Conn->PathsCount = 2;
    Conn->ClientCallbackHandler = NoopConnCallback;
    Conn->CongestionControl.QuicCongestionControlReset = NoopCcReset;

    Conn->Paths[0].InUse = TRUE;
    Conn->Paths[0].IsActive = TRUE;
    Conn->Paths[0].ID = 10;
    Conn->Paths[0].DestCid = &Cid0;
    Conn->Paths[0].GotValidPacket = TRUE;

    Conn->Paths[1].InUse = TRUE;
    Conn->Paths[1].IsActive = FALSE;
    Conn->Paths[1].ID = 99;
    Conn->Paths[1].DestCid = &Cid1;
    Conn->Paths[1].GotValidPacket = TRUE;

    QUIC_PATH* StalePath = &Conn->Paths[1];

    printf("BEFORE remove: count=%u p0(ID=%u inuse=%d active=%d) p1(ID=%u inuse=%d active=%d)\n",
        Conn->PathsCount,
        Conn->Paths[0].ID, Conn->Paths[0].InUse, Conn->Paths[0].IsActive,
        Conn->Paths[1].ID, Conn->Paths[1].InUse, Conn->Paths[1].IsActive);

    /* NEW_CONNECTION_ID retire path with no spare CID -> QuicConnReplaceRetiredCids. */
    QuicPathRemove(Conn, 1);
    printf("AFTER remove:  count=%u p0(ID=%u inuse=%d active=%d) p1(ID=%u inuse=%d active=%d) stale=%p\n",
        Conn->PathsCount,
        Conn->Paths[0].ID, Conn->Paths[0].InUse, Conn->Paths[0].IsActive,
        Conn->Paths[1].ID, Conn->Paths[1].InUse, Conn->Paths[1].IsActive,
        (void*)StalePath);

    QUIC_RX_PACKET Packet;
    memset(&Packet, 0, sizeof(Packet));
    Packet.DestCidLen = 0;              /* skip source-CID lookup branch */
    Packet.HasNonProbingFrame = TRUE;
    Packet.NewLargestPacketNumber = TRUE;

    QUIC_PATH* Path = StalePath;
    QuicConnRecvPostProcessing(Conn, &Path, &Packet);
    printf("AFTER post:    count=%u p0(ID=%u inuse=%d active=%d) p1(ID=%u inuse=%d active=%d) pathret=%s\n",
        Conn->PathsCount,
        Conn->Paths[0].ID, Conn->Paths[0].InUse, Conn->Paths[0].IsActive,
        Conn->Paths[1].ID, Conn->Paths[1].InUse, Conn->Paths[1].IsActive,
        Path == &Conn->Paths[0] ? "&Paths[0]" : "stale");

    int Swapped = (Conn->Paths[0].ID == 99 && Conn->Paths[1].ID == 10);
    printf("VERDICT: stale-slot swap %s (active path overwritten by removed path)\n",
        Swapped ? "OBSERVED" : "NOT OBSERVED");

    free(Conn);
    return Swapped ? 1 : 0;
}
