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
#include "net/llsec/coresec/apkes-trickle.h"
#include "net/llsec/coresec/apkes-flash.h"
#include "net/llsec/coresec/coresec.h"
#include "net/llsec/coresec/ebeap.h"
#include "net/llsec/anti-replay.h"
#include "net/packetbuf.h"
#include "lib/prng.h"
#include "lib/memb.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/node-id.h"
#include <string.h>

#ifdef APKES_CONF_MAX_REFRESHS
#define MAX_REFRESHS              APKES_CONF_MAX_REFRESHS
#else /* APKES_CONF_MAX_REFRESHS */
#define MAX_REFRESHS              3
#endif /* APKES_CONF_MAX_REFRESHS */

#ifdef APKES_CONF_REFRESH_DELAY
#define REFRESH_DELAY             APKES_CONF_REFRESH_DELAY
#else /* APKES_CONF_REFRESH_DELAY */
#define REFRESH_DELAY             3 /* seconds */ 
#endif /* APKES_CONF_REFRESH_DELAY */

/* Command frame identifiers */
#define HELLO_IDENTIFIER          0x0A
#define HELLOACK_IDENTIFIER       0x0B
#define ACK_IDENTIFIER            0x0C
#define UPDATE_IDENTIFIER         0x0E
#define UPDATEACK_IDENTIFIER      0x0F
#define REFRESH_IDENTIFIER        0x10

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
static void send_updateack(struct neighbor *receiver);

MEMB(wait_timers_memb, struct wait_timer, APKES_MAX_TENTATIVE_NEIGHBORS);
/* A random challenge, which will be attached to HELLO commands */
static uint8_t our_challenge[CHALLENGE_LEN];
static struct ctimer refresh_timer;

/*---------------------------------------------------------------------------*/
static uint8_t *
prepare_update_command(uint8_t command_frame_identifier,
    struct neighbor *receiver,
    uint8_t *extra_data,
    uint8_t extra_data_len)
{
  uint8_t *payload;
  uint8_t payload_len;
  
  payload = coresec_prepare_command_frame(command_frame_identifier,
      &receiver->ids.extended_addr);
#if EBEAP_WITH_ENCRYPTION
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL | (1 << 2));
#else /* EBEAP_WITH_ENCRYPTION */
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  /* write payload */
  memcpy(payload, extra_data, extra_data_len);
  payload += extra_data_len;
  memcpy(payload, &node_id, NEIGHBOR_SHORT_ADDR_LEN);
  payload += NEIGHBOR_SHORT_ADDR_LEN;
  payload[0] = receiver->local_index;
  payload++;
#if EBEAP_WITH_ENCRYPTION
  memcpy(payload, ebeap_broadcast_key, NEIGHBOR_BROADCAST_KEY_LEN);
  payload += NEIGHBOR_BROADCAST_KEY_LEN;
#endif /* EBEAP_WITH_ENCRYPTION */
  
  payload_len = 1                   /* command frame identifier */
      + extra_data_len
      + NEIGHBOR_SHORT_ADDR_LEN     /* short address */
      + 1                           /* local index */
      + NEIGHBOR_BROADCAST_KEY_LEN; /* broadcast key */
  
  packetbuf_set_datalen(payload_len);
#if EBEAP_WITH_ENCRYPTION
  packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_PAYLOAD_BYTES,
      payload_len - NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  return payload;
}
/*---------------------------------------------------------------------------*/
static void
generate_pairwise_key(uint8_t *result, uint8_t *shared_secret)
{
  CORESEC_SET_PAIRWISE_KEY(shared_secret);
  aes_128_padded_encrypt(result, NEIGHBOR_PAIRWISE_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
static void
refresh_pairwise_key(struct neighbor* neighbor)
{
  CORESEC_SET_PAIRWISE_KEY(neighbor->pairwise_key);
  memset(neighbor->pairwise_key, 0, NEIGHBOR_PAIRWISE_KEY_LEN);
  aes_128_padded_encrypt(neighbor->pairwise_key, NEIGHBOR_PAIRWISE_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
void
apkes_broadcast_hello(void)
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
  waiting_period = (APKES_MAX_WAITING_PERIOD * (uint32_t) random_rand()) / RANDOM_RAND_MAX;
  sender->expiration_time = clock_seconds() + ((APKES_MAX_WAITING_PERIOD + APKES_ACK_DELAY) / CLOCK_SECOND);
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
  uint8_t *secret;
  
  /* write payload */
  prepare_update_command(HELLOACK_IDENTIFIER,
      receiver,
      receiver->metadata + CHALLENGE_LEN,
      CHALLENGE_LEN);
  
  /* generate pairwise key */
  secret = APKES_SCHEME.get_secret_with_hello_sender(&receiver->ids);
  if(!secret) {
    PRINTF("apkes: could not get secret with HELLO sender\n");
    return;
  }
  generate_pairwise_key(receiver->pairwise_key, secret);
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_helloack(struct neighbor *sender, uint8_t *payload)
{
  struct neighbor_ids ids;
  uint8_t *secret;
  uint8_t key[NEIGHBOR_PAIRWISE_KEY_LEN];
  
  PRINTF("apkes: Received HELLOACK\n");
  
  neighbor_update_ids(&ids, payload + CHALLENGE_LEN);
  secret = APKES_SCHEME.get_secret_with_helloack_sender(&ids);
  if(!secret) {
    PRINTF("apkes: could not get secret with HELLOACK sender\n");
    return;
  }
  
  /* copy challenges and generate key */
  memcpy(key,
      our_challenge,
      CHALLENGE_LEN);
  memcpy(key + CHALLENGE_LEN,
      payload,
      CHALLENGE_LEN);
  generate_pairwise_key(key, secret);
  
  if(!coresec_decrypt_verify_unicast(key)) {
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
  
  memcpy(sender->pairwise_key, key, NEIGHBOR_PAIRWISE_KEY_LEN);
  neighbor_update(sender, payload + CHALLENGE_LEN);
  send_ack(sender);
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct neighbor *receiver)
{
  prepare_update_command(ACK_IDENTIFIER, receiver, NULL, 0);
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
void
apkes_send_update(struct neighbor *receiver)
{
  prepare_update_command(UPDATE_IDENTIFIER, receiver, NULL, 0);
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_update(struct neighbor *sender, uint8_t *payload)
{
  PRINTF("apkes: Received UPDATE\n");
  
  if(!sender
      || !coresec_decrypt_verify_unicast(sender->pairwise_key)
      || anti_replay_was_replayed(&sender->anti_replay_info)) {
    return;
  }
  
  send_updateack(sender);
  neighbor_update(sender, payload);
}
/*---------------------------------------------------------------------------*/
static void
send_updateack(struct neighbor *receiver)
{
  prepare_update_command(UPDATEACK_IDENTIFIER, receiver, NULL, 0);
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_updateack(struct neighbor *sender, uint8_t *payload)
{
  PRINTF("apkes: Received UPDATEACK\n");
  
  if(!sender
      || !coresec_decrypt_verify_unicast(sender->pairwise_key)
      || anti_replay_was_replayed(&sender->anti_replay_info)) {
    return;
  }
  
  neighbor_update(sender, payload);
}
/*---------------------------------------------------------------------------*/
static void
restore_neighbors(void)
{
  struct neighbor *next;
  struct neighbor *current;
  
  apkes_flash_restore_neighbors();
  next = neighbor_head();
  while(next) {
    current = next;
    next = neighbor_next(current);
    if(current->status) {
      PRINTF("apkes: Deleting tentative neighbor %d\n", current->ids.short_addr);
      neighbor_delete(current);
    } else {
      PRINTF("apkes: Refreshing permanent neighbor %d\n", current->ids.short_addr);
      anti_replay_reset_info(&current->anti_replay_info);
      refresh_pairwise_key(current);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
broadcast_refresh(void *ptr)
{
  static int refresh_count = MAX_REFRESHS;
  llsec_on_bootstrapped_t on_bootstrapped;
  
  if(refresh_count--) {
    PRINTF("apkes: Broadcasting REFRESH\n");
      
    coresec_prepare_command_frame(REFRESH_IDENTIFIER, &linkaddr_null);
    packetbuf_set_datalen(1);
    ebeap_send_broadcast(NULL, NULL);
    
    ctimer_set(&refresh_timer,
        REFRESH_DELAY * CLOCK_SECOND,
        broadcast_refresh,
        ptr);
  } else {
    apkes_flash_backup_neighbors();
    on_bootstrapped = (llsec_on_bootstrapped_t) ptr;
    on_bootstrapped();
  }
}
/*---------------------------------------------------------------------------*/
static void
on_refresh(struct neighbor *sender)
{
  uint8_t pairwise_key_backup[NEIGHBOR_PAIRWISE_KEY_LEN];
  
  memcpy(pairwise_key_backup, sender->pairwise_key, NEIGHBOR_PAIRWISE_KEY_LEN); 
  refresh_pairwise_key(sender);
  if(!ebeap_decrypt_verify_broadcast(sender)) {
    PRINTF("apkes: Received invalid REFRESH\n");
    memcpy(sender->pairwise_key, pairwise_key_backup, NEIGHBOR_PAIRWISE_KEY_LEN);
  } else {
    PRINTF("apkes: Received valid REFRESH\n");
    anti_replay_reset_info(&sender->anti_replay_info);
    apkes_flash_backup_neighbors();
  }
}
/*---------------------------------------------------------------------------*/
static void
on_command_frame(uint8_t command_frame_identifier,
    struct neighbor *sender,
    uint8_t *payload)
{
#if EBEAP_WITH_ENCRYPTION
  switch(command_frame_identifier) {
  case HELLOACK_IDENTIFIER:
  case ACK_IDENTIFIER:
    packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_PAYLOAD_BYTES,
        packetbuf_datalen() - NEIGHBOR_BROADCAST_KEY_LEN - CORESEC_UNICAST_MIC_LENGTH);
    break;
  }
#endif /* EBEAP_WITH_ENCRYPTION */
  
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
  case UPDATE_IDENTIFIER:
    on_update(sender, payload);
    break;
  case UPDATEACK_IDENTIFIER:
    on_updateack(sender, payload);
    break;
  case REFRESH_IDENTIFIER:
    on_refresh(sender);
    break;
  default:
    PRINTF("apkes: Received unknown command with identifier %x \n", command_frame_identifier);
  }
}
/*---------------------------------------------------------------------------*/
static void
bootstrap(llsec_on_bootstrapped_t on_bootstrapped)
{
  memb_init(&wait_timers_memb);
  APKES_SCHEME.init();
  
  restore_neighbors();
  if(neighbor_head()) {
    broadcast_refresh(on_bootstrapped);
    apkes_trickle_bootstrap(NULL);
  } else {
    apkes_trickle_bootstrap(on_bootstrapped);
  }
}
/*---------------------------------------------------------------------------*/
const struct coresec_scheme apkes_coresec_scheme = {
  apkes_trickle_is_bootstrapped,
  bootstrap,
  on_command_frame
};
/*---------------------------------------------------------------------------*/

/** @} */
