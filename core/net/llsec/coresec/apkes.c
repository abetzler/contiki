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
 *         Adaptable Pairwise Key Establishment Scheme (APKES).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/apkes.h"
#include "net/llsec/coresec/coresec.h"
#include "net/llsec/coresec/ebeap.h"
#include "net/llsec/anti-replay.h"
#include "net/packetbuf.h"
#include "lib/prng.h"
#include "lib/memb.h"
#include "lib/random.h"
#include "sys/etimer.h"
#include "sys/ctimer.h"
#include "sys/node-id.h"
#include <string.h>

#ifdef APKES_CONF_ROUNDS
#define ROUNDS                    APKES_CONF_ROUNDS
#else /* APKES_CONF_ROUNDS */
#define ROUNDS                    6
#endif /* APKES_CONF_ROUNDS */

#ifdef APKES_CONF_ROUND_DURATION
#define ROUND_DURATION            APKES_CONF_ROUND_DURATION
#else /* APKES_CONF_ROUND_DURATION */
#define ROUND_DURATION            (7 * CLOCK_SECOND)
#endif /* APKES_CONF_ROUND_DURATION */

#ifdef APKES_CONF_MAX_TENTATIVE_NEIGHBORS
#define MAX_TENTATIVE_NEIGHBORS   APKES_CONF_MAX_TENTATIVE_NEIGHBORS
#else /* APKES_CONF_MAX_TENTATIVE_NEIGHBORS */
#define MAX_TENTATIVE_NEIGHBORS   2
#endif /* APKES_CONF_MAX_TENTATIVE_NEIGHBORS */

#ifdef APKES_CONF_MAX_WAITING_PERIOD
#define MAX_WAITING_PERIOD        APKES_CONF_MAX_WAITING_PERIOD
#else /* APKES_CONF_MAX_WAITING_PERIOD */
#define MAX_WAITING_PERIOD        (ROUND_DURATION - (2 * CLOCK_SECOND))
#endif /* APKES_CONF_MAX_WAITING_PERIOD */

#ifdef APKES_CONF_ACK_DELAY
#define ACK_DELAY                 APKES_CONF_ACK_DELAY
#else /* APKES_CONF_ACK_DELAY */
#define ACK_DELAY                 (5 * CLOCK_SECOND)
#endif /* APKES_CONF_ACK_DELAY */

/* Command frame identifiers */
#define HELLO_IDENTIFIER          0x0A
#define HELLOACK_IDENTIFIER       0x0B
#define ACK_IDENTIFIER            0x0C

#define CHALLENGE_LEN             (NEIGHBOR_PAIRWISE_KEY_LEN/2)

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

struct wait_timer {
  struct ctimer ctimer;
  struct neighbor *neighbor;
};

static void wait_callback(void *ptr);
static void send_helloack(struct neighbor *receiver);
static void send_ack(struct neighbor *receiver);

MEMB(wait_timers_memb, struct wait_timer, MAX_TENTATIVE_NEIGHBORS);
/* A random challenge, which will be attached to HELLO commands */
static uint8_t our_challenge[CHALLENGE_LEN];
PROCESS(apkes_process, "apkes_process");
/* The network layer will be started after bootstrapping */
static llsec_on_bootstrapped_t on_bootstrapped;

/*---------------------------------------------------------------------------*/
static void
generate_pairwise_key(struct neighbor *neighbor, uint8_t *shared_secret)
{
  CORESEC_SET_PAIRWISE_KEY(shared_secret);
  aes_128_padded_encrypt(neighbor->metadata, NEIGHBOR_PAIRWISE_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
static uint8_t *
get_pairwise_key_with(struct neighbor *neighbor)
{
  uint8_t *key;
  
  if(neighbor->status == NEIGHBOR_TENTATIVE_AWAITING_ACK) {
    /* sending a message to a tentative neighbor --> must be HELLOACK */
    key = APKES_SCHEME.get_secret_with_hello_sender(&neighbor->ids);
    if(key) {
      generate_pairwise_key(neighbor, key);
    }
  } else {
    key = neighbor->pairwise_key;
  }
  
  return key;
}
/*---------------------------------------------------------------------------*/
static void
broadcast_hello(void)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(HELLO_IDENTIFIER, &linkaddr_null);
  
  /* write payload */
  prng_rand(our_challenge, CHALLENGE_LEN);
  memcpy(payload, our_challenge, CHALLENGE_LEN);
  payload += CHALLENGE_LEN;
  memcpy(payload, &node_id, NEIGHBOR_SHORT_ADDR_LEN);
  
  packetbuf_set_datalen(1         /* command frame identifier */
      + CHALLENGE_LEN             /* challenge */
      + NEIGHBOR_SHORT_ADDR_LEN); /* short address */
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_hello(struct neighbor *sender, uint8_t *payload)
{
  struct wait_timer *free_wait_timer;
  clock_time_t waiting_period;
  
  PRINTF("apkes: Received HELLO\n");
  
  free_wait_timer = memb_alloc(&wait_timers_memb);
  if(!free_wait_timer) {
    PRINTF("apkes: HELLO flood?\n");
    return;
  }
  
  if(sender || !((sender = neighbor_new()))) {
    memb_free(&wait_timers_memb, free_wait_timer);
    return;
  }
  
  /* Create tentative neighbor */
  sender->status = NEIGHBOR_TENTATIVE;
  neighbor_update_ids(&sender->ids, payload + CHALLENGE_LEN);
  
  /* Write challenges to sender->metadata */
  memcpy(sender->metadata, payload, CHALLENGE_LEN);
  prng_rand(sender->metadata + CHALLENGE_LEN, CHALLENGE_LEN);
  
  /* Set up waiting period */
  waiting_period = (MAX_WAITING_PERIOD * (uint32_t) random_rand()) / RANDOM_RAND_MAX;
  sender->expiration_time = clock_seconds() + ((MAX_WAITING_PERIOD + ACK_DELAY) / CLOCK_SECOND);
  free_wait_timer->neighbor = sender;
  ctimer_set(&free_wait_timer->ctimer,
      waiting_period,
      wait_callback,
      free_wait_timer);
  
  PRINTF("apkes: Will send HELLOACK in %lus\n", waiting_period / CLOCK_SECOND);
}
/*---------------------------------------------------------------------------*/
static void
wait_callback(void *ptr)
{
  struct wait_timer *expired_wait_timer;
  
  PRINTF("apkes: wait_callback\n");
  
  expired_wait_timer = (struct wait_timer *) ptr;
  
  if(expired_wait_timer->neighbor->status == NEIGHBOR_TENTATIVE) {
    expired_wait_timer->neighbor->status = NEIGHBOR_TENTATIVE_AWAITING_ACK;
    send_helloack(expired_wait_timer->neighbor);
  }
  
  memb_free(&wait_timers_memb, expired_wait_timer);
}
/*---------------------------------------------------------------------------*/
static void
send_helloack(struct neighbor *receiver)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(HELLOACK_IDENTIFIER, &receiver->ids.extended_addr);
#if EBEAP_WITH_ENCRYPTION
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL | (1 << 2));
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_5_BYTE_KEY_ID_MODE);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, HELLOACK_IDENTIFIER);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1, node_id);
#else /* EBEAP_WITH_ENCRYPTION */
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  /* write payload */
  memcpy(payload, receiver->metadata, 2 * CHALLENGE_LEN);
  payload += 2 * CHALLENGE_LEN;
  memcpy(payload, &receiver->local_index, 1);
  payload += 1;
#if EBEAP_WITH_ENCRYPTION
  memcpy(payload, ebeap_broadcast_key, NEIGHBOR_BROADCAST_KEY_LEN);
#else /* EBEAP_WITH_ENCRYPTION */
  memcpy(payload, &node_id, NEIGHBOR_SHORT_ADDR_LEN);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  packetbuf_set_datalen(1            /* command frame identifier */
      + 2 * CHALLENGE_LEN            /* Neighbor's challenge || Our challenge */
      + 1                            /* local index of receiver */
#if EBEAP_WITH_ENCRYPTION
      + NEIGHBOR_BROADCAST_KEY_LEN); /* broadcast key */
#else /* EBEAP_WITH_ENCRYPTION */
      + NEIGHBOR_SHORT_ADDR_LEN);    /* short address */
#endif /* EBEAP_WITH_ENCRYPTION */
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_helloack(struct neighbor *sender, uint8_t *payload)
{
  struct neighbor_ids ids;
  uint8_t *key;
#if EBEAP_WITH_ENCRYPTION
  uint16_t short_addr;
#endif /* EBEAP_WITH_ENCRYPTION */
  
  PRINTF("apkes: Received HELLOACK\n");
  
#if EBEAP_WITH_ENCRYPTION
  short_addr = packetbuf_attr(PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1);
  neighbor_update_ids(&ids, &short_addr);
#else /* EBEAP_WITH_ENCRYPTION */
  neighbor_update_ids(&ids,
      payload + 2 * CHALLENGE_LEN + 1 + NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  key = APKES_SCHEME.get_secret_with_helloack_sender(&ids);
  if(!key
      || !coresec_decrypt_verify_unicast(key)
      || (memcmp(our_challenge, payload, CHALLENGE_LEN) != 0)) {
    PRINTF("apkes: Invalid HELLOACK\n");
    return;
  }
  
  if(sender) {
    switch(sender->status) {
    case(NEIGHBOR_PERMANENT):
      if(anti_replay_was_replayed(&sender->anti_replay_info)) {
        return;
      }
      break;
    case(NEIGHBOR_TENTATIVE):
      break;
    default:
      return;
    }
  } else {
    /* sender unknown --> create new neighbor */
    sender = neighbor_new();
    if (!sender) {
      return;
    }
  }
  
  memcpy(sender->metadata, payload, 2 * CHALLENGE_LEN);
  generate_pairwise_key(sender, key);
  sender->ids = ids;
  neighbor_update(sender, payload + 2 * CHALLENGE_LEN);
  
  send_ack(sender);
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct neighbor *receiver)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(ACK_IDENTIFIER, &receiver->ids.extended_addr);
#if EBEAP_WITH_ENCRYPTION
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL | (1 << 2));
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, ACK_IDENTIFIER);
#else /* EBEAP_WITH_ENCRYPTION */
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  /* write payload */
  memcpy(payload, &receiver->local_index, 1);
#if EBEAP_WITH_ENCRYPTION
  memcpy(payload + 1, ebeap_broadcast_key, NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  packetbuf_set_datalen(1            /* command frame identifier */
      + 1                            /* local index of receiver */
      + NEIGHBOR_BROADCAST_KEY_LEN); /* broadcast key */
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_ack(struct neighbor *sender, uint8_t *payload)
{
  PRINTF("apkes: Received ACK\n");
  
  if(!sender
      || (sender->status != NEIGHBOR_TENTATIVE_AWAITING_ACK)
      || !coresec_decrypt_verify_unicast(sender->pairwise_key)) {
    PRINTF("apkes: Invalid ACK\n");
    return;
  }
  
  neighbor_update(sender, payload);
}
/*---------------------------------------------------------------------------*/
static void
on_command_frame(uint8_t command_frame_identifier,
    struct neighbor *sender,
    uint8_t *payload)
{
  switch(command_frame_identifier) {
  case HELLO_IDENTIFIER:
    on_hello(sender, payload);
    break;
  case HELLOACK_IDENTIFIER:
    on_helloack(sender, payload);
    break;
  case ACK_IDENTIFIER:
    on_ack(sender, payload);
    break;
  default:
    PRINTF("apkes: Received unknown command with identifier %x \n", command_frame_identifier);
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(apkes_process, ev, data)
{
  static struct etimer round_timer;
  static uint8_t i;
  
  PROCESS_BEGIN();
  
  etimer_set(&round_timer, ROUND_DURATION);
  for(i = 1; i <= ROUNDS; i++) {
    broadcast_hello();
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&round_timer));
    if(i != ROUNDS) {
      etimer_reset(&round_timer);
    }
  }
  
  on_bootstrapped();
  on_bootstrapped = NULL;
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
bootstrap(llsec_on_bootstrapped_t on_bootstrapped_param)
{
  on_bootstrapped = on_bootstrapped_param;
  memb_init(&wait_timers_memb);
  APKES_SCHEME.init();
  process_start(&apkes_process, NULL);
}
/*---------------------------------------------------------------------------*/
static int
is_bootstrapped()
{
  return on_bootstrapped == NULL;
}
/*---------------------------------------------------------------------------*/
const struct coresec_scheme apkes_coresec_scheme = {
  is_bootstrapped,
  bootstrap,
  on_command_frame,
  get_pairwise_key_with
};
/*---------------------------------------------------------------------------*/

/** @} */
