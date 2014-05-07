/**
 * \addtogroup coresec
 * @{
 */

/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Easy Broadcast Encryption and Authentication Protocol (EBEAP).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/ebeap.h"
#include "net/llsec/coresec/coresec.h"
#include "net/llsec/llsec802154.h"
#include "net/llsec/ccm-star.h"
#include "lib/prng.h"
#include "net/mac/framer.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "dev/watchdog.h"
#include <string.h>

#ifdef EBEAP_CONF_BROADCAST_MIC_LENGTH
#define BROADCAST_MIC_LENGTH      EBEAP_CONF_BROADCAST_MIC_LENGTH
#else /* EBEAP_CONF_BROADCAST_MIC_LENGTH */
#define BROADCAST_MIC_LENGTH      LLSEC802154_MIC_LENGTH
#endif /* EBEAP_CONF_BROADCAST_MIC_LENGTH */

#ifdef EBEAP_CONF_MAX_BUFFERED_CCM_MICS
#define MAX_BUFFERED_CCM_MICS     EBEAP_CONF_MAX_BUFFERED_CCM_MICS
#else /* EBEAP_CONF_MAX_BUFFERED_CCM_MICS */
#define MAX_BUFFERED_CCM_MICS     3
#endif /* EBEAP_CONF_MAX_BUFFERED_CCM_MICS */

#if EBEAP_WITH_ENCRYPTION
#define SECURITY_LEVEL (LLSEC802154_SECURITY_LEVEL | (1 << 2))
#else /* EBEAP_WITH_ENCRYPTION */
#define SECURITY_LEVEL (LLSEC802154_SECURITY_LEVEL & ~(1 << 2))
#endif /* EBEAP_WITH_ENCRYPTION */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

struct mic {
  struct mic *next;
  union {
    uint8_t u8[BROADCAST_MIC_LENGTH];
  };
};

MEMB(mics_memb, struct mic, MAX_BUFFERED_CCM_MICS);
LIST(mic_list);
#if EBEAP_WITH_ENCRYPTION
uint8_t ebeap_broadcast_key[NEIGHBOR_BROADCAST_KEY_LEN];
#endif /* EBEAP_WITH_ENCRYPTION */

/*---------------------------------------------------------------------------*/
/**
 * Payload format: 
 * | 0x0d | 0x00 | CCM*-MIC for neighbor 0 | ... | CCM*-MIC for last neighbor |
 */
static void
prepare_announce()
{
  struct neighbor *next;
  uint8_t announced_mics[NEIGHBOR_MAX * BROADCAST_MIC_LENGTH];
  uint8_t *payload;
  uint8_t announced_mics_len;
  uint8_t max_index;
  
  /* clear sequence number */
  ((uint8_t *) packetbuf_hdrptr())[2] = 0;
  
  max_index = 0;
  next = neighbor_head();
  while(next) {
    if(!next->status) {
      CORESEC_SET_PAIRWISE_KEY(next->pairwise_key);
      CCM_STAR.mic(linkaddr_node_addr.u8,
          announced_mics + (next->local_index * BROADCAST_MIC_LENGTH),
          BROADCAST_MIC_LENGTH);
      if(next->local_index > max_index) {
        max_index = next->local_index;
      }
    }
    next = neighbor_next(next);
  }
  
  /* reset packetbuf for sending a command frame */
  payload = coresec_prepare_command_frame(EBEAP_ANNOUNCE_IDENTIFIER, &linkaddr_null);
  
  /* write payload */
  /* TODO We currently assume that all MICs fit within a single ANNOUNCE command */
  payload[0] = 0;
  announced_mics_len = (max_index + 1) * BROADCAST_MIC_LENGTH;
  memcpy(payload + 1, announced_mics, announced_mics_len);
  packetbuf_set_datalen(1 + 1 + announced_mics_len);
}
/*---------------------------------------------------------------------------*/
void
ebeap_send_broadcast(mac_callback_t sent, void *ptr)
{
  struct queuebuf *qb;
  
  coresec_add_security_header(SECURITY_LEVEL);
  
  qb = queuebuf_new_from_packetbuf();
  if(!neighbor_head()
      || !qb
      || (NETSTACK_FRAMER.create() < 0)) {
    PRINTF("ebeap: Did not send broadcast\n");
    if(qb) {
      queuebuf_free(qb);
    }
    sent(ptr, MAC_TX_ERR, 0);
    return;
  }
  
  prepare_announce();
  coresec_send_command_frame();
  watchdog_periodic();
  
  queuebuf_to_packetbuf(qb);
  queuebuf_free(qb);
#if EBEAP_WITH_ENCRYPTION
  CORESEC_SET_BROADCAST_KEY(ebeap_broadcast_key);
  CCM_STAR.ctr(linkaddr_node_addr.u8);
#endif /* EBEAP_WITH_ENCRYPTION */
  NETSTACK_MAC.send(sent, ptr);
}
/*---------------------------------------------------------------------------*/
static int
is_mic_stored(uint8_t *mic)
{
  struct mic *next;
  
  next = list_head(mic_list);
  while(next) {
    if(memcmp(mic, next->u8, BROADCAST_MIC_LENGTH) == 0) {
      return 1;
    }
    next = list_item_next(next);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
void
ebeap_on_announce(struct neighbor *sender, uint8_t *payload)
{
  struct mic *received_mic;
  uint8_t *max_payload;
  
  if(!sender || sender->status) {
    return;
  }
  
  PRINTF("ebeap: Received ANNOUNCE\n");  
  
  /* calculate CCM*-MIC location */
  payload += 1 + (sender->foreign_index * BROADCAST_MIC_LENGTH);
  
  /* check if CCM*-MIC location is within ANNOUNCE */
  max_payload = ((uint8_t *) packetbuf_dataptr()) + packetbuf_datalen() - 1;
  if(payload + BROADCAST_MIC_LENGTH - 1 > max_payload) {
    PRINTF("ebeap: Out of bounds\n");
    return;
  }
  
  /* 
   * check if contained CCM*-MIC is already stored, e.g.,
   * due to duplicated ANNOUNCE
   */
  if(is_mic_stored(payload)) {
    PRINTF("ebeap: Already stored\n");
    return;
  }
  
  /* allocate memory */
  received_mic = memb_alloc(&mics_memb);
  if(!received_mic) {
    memb_free(&mics_memb, list_chop(mic_list));
    received_mic = memb_alloc(&mics_memb);
  }
  
  /* store CCM*-MIC */
  memcpy(received_mic->u8, payload, BROADCAST_MIC_LENGTH);
  list_push(mic_list, received_mic);
}
/*---------------------------------------------------------------------------*/
int
ebeap_decrypt_verify_broadcast(struct neighbor *sender)
{
  uint8_t mic[BROADCAST_MIC_LENGTH];
  uint8_t *hdrptr;
  
  if(packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL) != SECURITY_LEVEL) {
    return 0;
  }
  
  hdrptr = (uint8_t *) packetbuf_hdrptr();
  /* clear frame pending bit */
  hdrptr[0] &= ~(1 << 4);
  /* clear sequence number */
  hdrptr[2] = 0;
  
#if EBEAP_WITH_ENCRYPTION
  CORESEC_SET_BROADCAST_KEY(sender->broadcast_key);
  CCM_STAR.ctr(sender->ids.extended_addr.u8);
#endif /* EBEAP_WITH_ENCRYPTION */
  CORESEC_SET_PAIRWISE_KEY(sender->pairwise_key);
  CCM_STAR.mic(sender->ids.extended_addr.u8,
      mic,
      BROADCAST_MIC_LENGTH);
  
  return is_mic_stored(mic);
}
/*---------------------------------------------------------------------------*/
void
ebeap_init(void)
{
#if EBEAP_WITH_ENCRYPTION
  prng_rand(ebeap_broadcast_key, NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* EBEAP_WITH_ENCRYPTION */
  memb_init(&mics_memb);
  list_init(mic_list);
}
/*---------------------------------------------------------------------------*/

/** @} */
