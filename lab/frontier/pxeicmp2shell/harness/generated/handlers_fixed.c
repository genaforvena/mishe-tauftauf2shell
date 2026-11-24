/* Verbatim extraction from pins/PxeBcSupport.c.fixed; see extract-index.txt. */
#include "standin.h"
VOID
EFIAPI
PxeBcIcmpErrorDpcHandle (
  IN VOID  *Context
  )
{
  EFI_STATUS              Status;
  EFI_IP4_RECEIVE_DATA    *RxData;
  EFI_IP4_PROTOCOL        *Ip4;
  PXEBC_PRIVATE_DATA      *Private;
  EFI_PXE_BASE_CODE_MODE  *Mode;
  UINT8                   Type;
  UINTN                   Index;
  UINT32                  CopiedLen;
  UINT8                   *IcmpError;
  UINT32                  FragmentLen;

  Private = (PXEBC_PRIVATE_DATA *)Context;
  Mode    = &Private->Mode;
  Status  = Private->IcmpToken.Status;
  RxData  = Private->IcmpToken.Packet.RxData;
  Ip4     = Private->Ip4;

  ASSERT (!Mode->UsingIpv6);

  if (Status == EFI_ABORTED) {
    //
    // It's triggered by user cancellation.
    //
    return;
  }

  if (RxData == NULL) {
    goto ON_EXIT;
  }

  if (Status != EFI_ICMP_ERROR) {
    //
    // The return status should be recognized as EFI_ICMP_ERROR.
    //
    goto ON_RECYCLE;
  }

  if ((EFI_IP4 (RxData->Header->SourceAddress) != 0) &&
      (NTOHL (Mode->SubnetMask.Addr[0]) != 0) &&
      IP4_NET_EQUAL (NTOHL (Mode->StationIp.Addr[0]), EFI_NTOHL (RxData->Header->SourceAddress), NTOHL (Mode->SubnetMask.Addr[0])) &&
      !NetIp4IsUnicast (EFI_NTOHL (RxData->Header->SourceAddress), NTOHL (Mode->SubnetMask.Addr[0])))
  {
    //
    // The source address of the received packet should be a valid unicast address.
    //
    goto ON_RECYCLE;
  }

  if (!EFI_IP4_EQUAL (&RxData->Header->DestinationAddress, &Mode->StationIp.v4)) {
    //
    // The destination address of the received packet should be equal to the host address.
    //
    goto ON_RECYCLE;
  }

  //
  // The protocol has been configured to only receive ICMP packet.
  //
  ASSERT (RxData->Header->Protocol == EFI_IP_PROTO_ICMP);

  Type = *((UINT8 *)RxData->FragmentTable[0].FragmentBuffer);

  if ((Type != ICMP_DEST_UNREACHABLE) &&
      (Type != ICMP_SOURCE_QUENCH) &&
      (Type != ICMP_REDIRECT) &&
      (Type != ICMP_TIME_EXCEEDED) &&
      (Type != ICMP_PARAMETER_PROBLEM))
  {
    //
    // The type of the receveid ICMP message should be ICMP_ERROR_MESSAGE.
    //
    goto ON_RECYCLE;
  }

  //
  // Copy ICMP error fragments into Mode->IcmpError in order. The maximum
  // buffer size is sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR); truncate any excess.
  //
  ZeroMem (&Mode->IcmpError, sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR));
  for (Index = 0, IcmpError = (UINT8 *)&Mode->IcmpError, CopiedLen = 0;
       (Index < RxData->FragmentCount) &&
       (CopiedLen < sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR));
       Index++, IcmpError += FragmentLen, CopiedLen += FragmentLen)
  {
    FragmentLen = MIN (
                    RxData->FragmentTable[Index].FragmentLength,
                    (UINT32)(sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR) - CopiedLen)
                    );
    CopyMem (IcmpError, RxData->FragmentTable[Index].FragmentBuffer, FragmentLen);
  }

ON_RECYCLE:
  gBS->SignalEvent (RxData->RecycleSignal);

ON_EXIT:
  Private->IcmpToken.Status = EFI_NOT_READY;
  Ip4->Receive (Ip4, &Private->IcmpToken);
}

VOID
EFIAPI
PxeBcIcmp6ErrorDpcHandle (
  IN VOID  *Context
  )
{
  PXEBC_PRIVATE_DATA      *Private;
  EFI_IP6_RECEIVE_DATA    *RxData;
  EFI_IP6_PROTOCOL        *Ip6;
  EFI_PXE_BASE_CODE_MODE  *Mode;
  EFI_STATUS              Status;
  UINTN                   Index;
  UINT8                   Type;
  UINT32                  CopiedLen;
  UINT8                   *Icmp6Error;
  UINT32                  FragmentLen;

  Private = (PXEBC_PRIVATE_DATA *)Context;
  Mode    = &Private->Mode;
  Status  = Private->Icmp6Token.Status;
  RxData  = Private->Icmp6Token.Packet.RxData;
  Ip6     = Private->Ip6;

  ASSERT (Mode->UsingIpv6);

  if (Status == EFI_ABORTED) {
    //
    // It's triggered by user cancellation.
    //
    return;
  }

  if (RxData == NULL) {
    goto ON_EXIT;
  }

  if (Status != EFI_ICMP_ERROR) {
    //
    // The return status should be recognized as EFI_ICMP_ERROR.
    //
    goto ON_RECYCLE;
  }

  if (!NetIp6IsValidUnicast (&RxData->Header->SourceAddress)) {
    //
    // The source address of the received packet should be a valid unicast address.
    //
    goto ON_RECYCLE;
  }

  if (!NetIp6IsUnspecifiedAddr (&Mode->StationIp.v6) &&
      !EFI_IP6_EQUAL (&RxData->Header->DestinationAddress, &Mode->StationIp.v6))
  {
    //
    // The destination address of the received packet should be equal to the host address.
    //
    goto ON_RECYCLE;
  }

  //
  // The protocol has been configured to only receive ICMP packet.
  //
  ASSERT (RxData->Header->NextHeader == IP6_ICMP);

  Type = *((UINT8 *)RxData->FragmentTable[0].FragmentBuffer);

  if ((Type != ICMP_V6_DEST_UNREACHABLE) &&
      (Type != ICMP_V6_PACKET_TOO_BIG) &&
      (Type != ICMP_V6_TIME_EXCEEDED) &&
      (Type != ICMP_V6_PARAMETER_PROBLEM))
  {
    //
    // The type of the receveid packet should be an ICMP6 error message.
    //
    goto ON_RECYCLE;
  }

  //
  // Copy ICMP error fragments into Mode->IcmpError in order. The maximum
  // buffer size is sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR); truncate any excess.
  //
  ZeroMem (&Mode->IcmpError, sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR));
  for (Index = 0, Icmp6Error = (UINT8 *)&Mode->IcmpError, CopiedLen = 0;
       (Index < RxData->FragmentCount) &&
       (CopiedLen < sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR));
       Index++, Icmp6Error += FragmentLen, CopiedLen += FragmentLen)
  {
    FragmentLen = MIN (
                    RxData->FragmentTable[Index].FragmentLength,
                    (UINT32)(sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR) - CopiedLen)
                    );
    CopyMem (Icmp6Error, RxData->FragmentTable[Index].FragmentBuffer, FragmentLen);
  }

ON_RECYCLE:
  gBS->SignalEvent (RxData->RecycleSignal);

ON_EXIT:
  Private->Icmp6Token.Status = EFI_NOT_READY;
  Ip6->Receive (Ip6, &Private->Icmp6Token);
}
