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
 *         Common functionality of compromise-resilient LLSEC drivers.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/coresec.h"
#include "net/llsec/coresec/ebeap.h"
#include "net/llsec/ccm-star.h"
#include "net/llsec/anti-replay.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include <string.h>

#define QUOTE(name)            #name
#define STR(macro)             QUOTE(macro)
#define CORESEC_SCHEME_NAME    STR(CORESEC_SCHEME)
#define SECURITY_HEADER_LENGTH 5

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*---------------------------------------------------------------------------*/
void
coresec_add_security_header(uint8_t sec_lvl)
{
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, sec_lvl);
  anti_replay_set_counter();
}
/*---------------------------------------------------------------------------*/
uint8_t *
coresec_prepare_command_frame(uint8_t command_frame_identifier, const linkaddr_t *dest)
{
  uint8_t *payload;
  
  /* reset packetbuf */
  packetbuf_clear();
  payload = packetbuf_dataptr();
  
  /* create frame */
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, dest);
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_CMDFRAME);
  memcpy(payload, &command_frame_identifier, 1);
  
  return payload + 1;
}
/*---------------------------------------------------------------------------*/
void
coresec_send_command_frame(void)
{
  NETSTACK_MAC.send(NULL, NULL);
}
/*---------------------------------------------------------------------------*/
int
coresec_decrypt_verify_unicast(uint8_t *key)
{
  uint8_t generated_mic[CORESEC_UNICAST_MIC_LENGTH];
  uint8_t *received_mic;
  const uint8_t *sender_addr;
#if LLSEC802154_USES_ENCRYPTION
  uint8_t sec_lvl;
  
  sec_lvl = packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL);
  if((sec_lvl & 3) != (LLSEC802154_SECURITY_LEVEL & 3)) {
#else /* LLSEC802154_USES_ENCRYPTION */
  if(packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL) != LLSEC802154_SECURITY_LEVEL) {
#endif /* LLSEC802154_USES_ENCRYPTION */
    return 0;
  }
  
  sender_addr = packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8;
  
  packetbuf_set_datalen(packetbuf_datalen() - CORESEC_UNICAST_MIC_LENGTH);
  CORESEC_SET_PAIRWISE_KEY(key);
#if LLSEC802154_USES_ENCRYPTION
  if(sec_lvl & (1 << 2)) {
    CCM_STAR.ctr(sender_addr);
  }
#endif /* LLSEC802154_USES_ENCRYPTION */
  CCM_STAR.mic(sender_addr, generated_mic, CORESEC_UNICAST_MIC_LENGTH);
  
  received_mic = ((uint8_t *) packetbuf_dataptr()) + packetbuf_datalen();
  return (memcmp(generated_mic, received_mic, CORESEC_UNICAST_MIC_LENGTH) == 0);
}
/*---------------------------------------------------------------------------*/
static void
dispatch_command_frame(struct neighbor *sender)
{
  uint8_t *payload;
  uint8_t command_frame_identifier;
  
  payload = (uint8_t *) packetbuf_dataptr();
  command_frame_identifier = payload[0];
  payload += 1;
  
  if(command_frame_identifier == EBEAP_ANNOUNCE_IDENTIFIER) {
    ebeap_on_announce(sender, payload);
  } else {
    CORESEC_SCHEME.on_command_frame(command_frame_identifier, sender, payload);
  }
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
  
  if(packetbuf_holds_broadcast()) {
    /* broadcast */
    ebeap_send_broadcast(sent, ptr);
  } else {
    /* unicast */
    coresec_add_security_header(LLSEC802154_SECURITY_LEVEL);
    NETSTACK_MAC.send(sent, ptr);
  }
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  uint8_t sec_lvl;
  struct neighbor *neighbor;
  uint8_t *dataptr;
  uint8_t datalen;
  
  sec_lvl = packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL);
  if(sec_lvl && !packetbuf_holds_broadcast()) {
    neighbor = neighbor_get(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
    if(!neighbor) {
      return 0;
    }
    
    dataptr = packetbuf_dataptr();
    datalen = packetbuf_datalen();
    
    CORESEC_SET_PAIRWISE_KEY(neighbor->pairwise_key);
    CCM_STAR.mic(linkaddr_node_addr.u8, dataptr + datalen, CORESEC_UNICAST_MIC_LENGTH);
#if LLSEC802154_USES_ENCRYPTION
    if(sec_lvl & (1 << 2)) {
      CCM_STAR.ctr(linkaddr_node_addr.u8);
    }
#endif /* LLSEC802154_USES_ENCRYPTION */
    packetbuf_set_datalen(datalen + CORESEC_UNICAST_MIC_LENGTH);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  const linkaddr_t *sender_addr;
  struct neighbor *sender;
  
  sender_addr = packetbuf_addr(PACKETBUF_ADDR_SENDER);
  if(linkaddr_cmp(sender_addr, &linkaddr_node_addr)) {
    PRINTF("coresec: frame from ourselves\n");
    return;
  }
  
  sender = neighbor_get(sender_addr);
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) == FRAME802154_CMDFRAME) {
    dispatch_command_frame(sender);
  } else {
    if(!CORESEC_SCHEME.is_bootstrapped() || !sender || sender->status) {
      PRINTF("coresec: Ignored incoming frame\n");
      return;
    }
    
    if(packetbuf_holds_broadcast()) {
      /* broadcast */
      if(!ebeap_decrypt_verify_broadcast(sender)) {
        PRINTF("coresec: Invalid broadcast\n");
        return;
      }
    } else {
      /* unicast */
      if(!coresec_decrypt_verify_unicast(sender->pairwise_key)) {
        PRINTF("coresec: Invalid unicast\n");
        return;
      }
    }
    
    if(anti_replay_was_replayed(&sender->anti_replay_info)) {
      PRINTF("coresec: Replayed\n");
      return;
    }
    
    NETSTACK_NETWORK.input();
  }
}
/*---------------------------------------------------------------------------*/
static void
bootstrap(llsec_on_bootstrapped_t on_bootstrapped)
{
  neighbor_init();
  ebeap_init();
  CORESEC_SCHEME.bootstrap(on_bootstrapped);
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_overhead(void)
{
  if(packetbuf_holds_broadcast()) {
    return SECURITY_HEADER_LENGTH;
  } else {
    return SECURITY_HEADER_LENGTH + LLSEC802154_MIC_LENGTH;
  }
}
/*---------------------------------------------------------------------------*/
const struct llsec_driver coresec_driver = {
  "coresec#" CORESEC_SCHEME_NAME,
  bootstrap,
  send,
  on_frame_created,
  input,
  get_overhead
};
/*---------------------------------------------------------------------------*/

/** @} */
