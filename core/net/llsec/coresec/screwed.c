/**
 * \addtogroup coresec
 * @{
 */

/*
 * Copyright (c) 2014, Fraunhofer Heinrich-Hertz-Institut.
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
 */

/**
 * \file
 *         Secure Channel Reciprocity-based Wormhole Detection (SCREWED).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/screwed.h"
#include "net/llsec/coresec/apkes.h"
#include "net/llsec/coresec/apkes-trickle.h"
#include "net/llsec/anti-replay.h"
#include "net/llsec/ccm-star.h"
#include "net/mac/frame802154.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "lib/aes-128.h"
#include "lib/prng.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "sys/ctimer.h"
#include "sys/clock.h"
#include <string.h>

#define MAX_PINGS                SCREWED_MAX_PINGS

#ifdef SCREWED_CONF_MIN_PINGS
#define MIN_PINGS                SCREWED_CONF_MIN_PINGS
#else /* SCREWED_CONF_MIN_PINGS */
#define MIN_PINGS                10
#endif /* SCREWED_CONF_MIN_PINGS */

#ifdef SCREWED_CONF_TIMEOUT
#define TIMEOUT                  SCREWED_CONF_TIMEOUT
#else /* SCREWED_CONF_TIMEOUT */
#define TIMEOUT                  (CLOCK_SECOND/20)
#endif /* SCREWED_CONF_TIMEOUT */

#ifdef SCREWED_CONF_PING_DELAY
#define PING_DELAY               SCREWED_CONF_PING_DELAY
#else /* SCREWED_CONF_PING_DELAY */
#define PING_DELAY               (TIMEOUT/4)
#endif /* SCREWED_CONF_PING_DELAY */

/* RECIPROCITY_THRESHOLD = r^2 * 100 */
#ifdef SCREWED_CONF_RECIPROCITY_THRESHOLD
#define RECIPROCITY_THRESHOLD    SCREWED_CONF_RECIPROCITY_THRESHOLD
#else /* SCREWED_CONF_MIN_PINGS */
/* default to rho = 0.93 */
#define RECIPROCITY_THRESHOLD    86
#endif /* SCREWED_CONF_MIN_PINGS */

#ifdef SCREWED_CONF_MIN_DBM
#define MIN_DBM                  SCREWED_CONF_MIN_DBM
#else /* SCREWED_CONF_MIN_DBM */
#define MIN_DBM                  -7
#endif /* SCREWED_CONF_MIN_DBM */

#define INVALID_RSSI             127

#define PING_IDENTIFIER          0xA0
#define PONG_IDENTIFIER          0xA1
#define JUDGE_IDENTIFIER         0xA2
#define VERDICT_IDENTIFIER       0xA3

#define PING_SEC_LVL             (LLSEC802154_SECURITY_LEVEL & 3)
/* differentiates PING nonces from PONG nonces */
#define PONG_SEC_LVL             (0x80 | PING_SEC_LVL)

#define VERDICT_KEEP             0
#define VERDICT_DROP             1

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*
 * The diagonals hold the distributions of P_A - P_B = delta
 */
static const uint16_t pairs[8][8] = {
    
/*    P_B:   0   ,  -1   ,  -2   ,  -3   ,  -4   ,  -5   ,  -6   ,  -7  */
/* P_A */
/*  0 */ {   177 ,   428 ,  1031 ,  2487 ,  5996 , 14451 , 32767 , 65535 },
/* -1 */ {   428 ,  1309 ,  3156 ,  7606 , 18333 , 32767 , 51083 , 65535 },
/* -2 */ {  1031 ,  3156 ,  8308 , 20024 , 32767 , 47201 , 59538 , 65535 },
/* -3 */ {  2487 ,  7606 , 20024 , 32767 , 45511 , 57928 , 63047 , 65535 },
/* -4 */ {  5996 , 18333 , 32767 , 45511 , 57226 , 62379 , 64503 , 65535 },
/* -5 */ { 14451 , 32767 , 47201 , 57928 , 62379 , 64225 , 65107 , 65535 },
/* -6 */ { 32767 , 51083 , 59538 , 63047 , 64503 , 65107 , 65357 , 65535 },
/* -7 */ { 65535 , 65535 , 65535 , 65535 , 65535 , 65535 , 65535 , 65535 }
};

struct context {
  struct neighbor *neighbor;
  int8_t phase;
  uint8_t current_channel;
  uint32_t counter;
  int is_pinger;
  struct ctimer timeout;
  int8_t rssis[MAX_PINGS];
  int8_t dbms[MAX_PINGS];
  int8_t pinger_dbms[MAX_PINGS]; /* only used by PONGer */
  linkaddr_t *nonce_addr;
  uint8_t next_ping_mic[CORESEC_UNICAST_MIC_LENGTH];
  uint8_t next_pong_mic[CORESEC_UNICAST_MIC_LENGTH];
};

static void next_phase(void *ptr);
static void ping_pong_mic(uint8_t sec_lvl, uint8_t *result);
static void send_ping_pong(uint8_t command_frame_identifier, uint8_t *mic);
static void start_judgement(void);
static void judgement_timeout(void *ptr);
static void send_judge(void);
static int retain_best(int8_t *pinger_rssis,
    int16_t *expected_diffs,
    int16_t *actual_diffs);
static int8_t correlation(int16_t *data1, int16_t *data2);
static void send_verdict(uint8_t verdict);
static void enforce(uint8_t verdict);

static struct context context;
static int is_busy;

/*---------------------------------------------------------------------------*/
static void
draw_ponger_dbms(void)
{
  uint8_t filled;
  uint8_t random_sums[AES_128_BLOCK_SIZE];
  uint8_t i;
  uint16_t random_pairs[AES_128_BLOCK_SIZE / 2];
  uint8_t j;
  int8_t sum;
  uint8_t a;
  uint8_t b;
  
  prng_rand(random_pairs, AES_128_BLOCK_SIZE);
  j = 0;
  filled = 0;
  while(1) {
    prng_rand(random_sums, AES_128_BLOCK_SIZE);
    for(i = 0; i < AES_128_BLOCK_SIZE; i++) {
      /* since 17 is prime, the remainder is uniformly distributed */
      sum = (random_sums[i] % 17) - 7;
      if(sum > 7) {
        continue;
      }
      
      if(sum >= 0) {
        a = 0;
        b = sum;
      } else {
        a = sum * -1;
        b = 0;
      }
      
      while(random_pairs[j] > pairs[a][b]) {
        a++;
        b++;
      }
      
      context.pinger_dbms[filled] = a * -1;
      context.dbms[filled] = b * -1;
      
      if(++j == (AES_128_BLOCK_SIZE / 2)) {
        prng_rand(random_pairs, AES_128_BLOCK_SIZE);
      }
      if(++filled == MAX_PINGS) {
        return;
      }
    }
  };
}
/*---------------------------------------------------------------------------*/
int
set_context(struct neighbor *neighbor, int is_pinger, int8_t *pinger_dbms)
{
  if(is_busy) {
    PRINTF("screwed: busy\n");
    return 0;
  }
  is_busy = 1;
  
  neighbor->status = NEIGHBOR_SAMPLING;
  context.neighbor = neighbor;
  context.phase = -1;
  context.current_channel = CC2420_CONF_CHANNEL;
  context.counter = anti_replay_get_counter();
  context.is_pinger = is_pinger;
  if(is_pinger) {
    memcpy(context.dbms, pinger_dbms, MAX_PINGS);
    /* reserve counter + 1, ... counter + MAX_PINGS */
    anti_replay_counter += MAX_PINGS;
    context.nonce_addr = &linkaddr_node_addr;
    next_phase(NULL);
  } else {
    draw_ponger_dbms();
    memcpy(pinger_dbms, context.pinger_dbms, MAX_PINGS);
    context.nonce_addr = &context.neighbor->ids.extended_addr;
  }
  
  /* TODO leave CC2420 always on (not NETSTACK_RDC.off(1)) */
  
  return 1;
}
/*---------------------------------------------------------------------------*/
int
screwed_prepare_pong(struct neighbor *receiver, int8_t *pinger_dbms)
{
  return set_context(receiver, 0, pinger_dbms);
}
/*---------------------------------------------------------------------------*/
void
screwed_pong(void *ptr, int status, int transmissions)
{
  if(status != MAC_TX_OK) {
    enforce(VERDICT_DROP);
    return;
  }
  next_phase(NULL);
}
/*---------------------------------------------------------------------------*/
int
screwed_ping(struct neighbor *sender, int8_t *pinger_dbms)
{
  return set_context(sender, 1, pinger_dbms);
}
/*---------------------------------------------------------------------------*/
static void
hop_channel(void)
{
  context.current_channel = ((context.current_channel - 11 + 7) % 16) + 11;
}
/*---------------------------------------------------------------------------*/
static void
set_radio(uint8_t channel, int8_t dbm)
{
  NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, channel);
  NETSTACK_RADIO.set_value(RADIO_PARAM_TXPOWER, dbm);
}
/*---------------------------------------------------------------------------*/
static void
on_timeout(void *ptr)
{
  context.rssis[context.phase] = INVALID_RSSI;
  next_phase(&context.timeout);
}
/*---------------------------------------------------------------------------*/
static void
next_phase(void *ptr)
{
  if(++context.phase == MAX_PINGS) {
    start_judgement();
    return;
  }
  
  if(ptr) {
    /* timeout occured */
    ctimer_reset(&context.timeout);
  } else {
    ctimer_stop(&context.timeout);
    ctimer_set(&context.timeout, TIMEOUT, on_timeout, NULL);
  }
  
  /* prepare radio */
  hop_channel();
  set_radio(context.current_channel, context.dbms[context.phase]);
  
  /* precompute mics */
  packetbuf_clear();
  ping_pong_mic(PING_SEC_LVL, context.next_ping_mic);
  packetbuf_clear();
  ping_pong_mic(PONG_SEC_LVL, context.next_pong_mic);
  
  if(context.is_pinger) {
    /* Gives the PONGer time for switching the channel */
    clock_wait(PING_DELAY);
    send_ping_pong(PING_IDENTIFIER, context.next_ping_mic);
  }
}
/*---------------------------------------------------------------------------*/
static void
ping_pong_mic(uint8_t sec_lvl, uint8_t *result)
{
  frame802154_frame_counter_t frame_counter;
  
  frame_counter.u32 = LLSEC802154_HTONL(context.counter + context.phase + 1);
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1, frame_counter.u16[0]);
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3, frame_counter.u16[1]);
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, sec_lvl);
  
  CORESEC_SET_PAIRWISE_KEY(context.neighbor->pairwise_key);
  CCM_STAR.mic(context.nonce_addr->u8,
      result,
      CORESEC_UNICAST_MIC_LENGTH);
}
/*---------------------------------------------------------------------------*/
static void
send_ping_pong(uint8_t command_frame_identifier, uint8_t *mic)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(command_frame_identifier,
      &context.neighbor->ids.extended_addr);
  memcpy(payload, mic, CORESEC_UNICAST_MIC_LENGTH);
  packetbuf_set_datalen(1 + CORESEC_UNICAST_MIC_LENGTH);
  
  NETSTACK_FRAMER.create_and_secure();
  NETSTACK_RADIO.send(packetbuf_hdrptr(), packetbuf_totlen());
}
/*---------------------------------------------------------------------------*/
static void
on_ping_pong(uint8_t *payload)
{
  if(memcmp(payload,
      ((context.is_pinger)
          ? context.next_pong_mic
          : context.next_ping_mic),
      CORESEC_UNICAST_MIC_LENGTH) != 0) {
    return;
  }
  
  context.rssis[context.phase] = (int8_t) packetbuf_attr(PACKETBUF_ATTR_RSSI);
  
  if(!context.is_pinger) {
    send_ping_pong(PONG_IDENTIFIER, context.next_pong_mic);
  }
  
  next_phase(NULL);
}
/*---------------------------------------------------------------------------*/
static void
start_judgement(void)
{
  PRINTF("screwed: starting judgement\n");
  
  ctimer_stop(&context.timeout);
  context.neighbor->status = NEIGHBOR_JUDGING;
  set_radio(CC2420_CONF_CHANNEL, 0);
  /* TODO switch CC2420 always-on off */
  
  if(context.is_pinger) {
    send_judge();
  }
  ctimer_set(&context.timeout, CLOCK_SECOND * 10, judgement_timeout, NULL);
}
/*---------------------------------------------------------------------------*/
static void
judgement_timeout(void *ptr)
{
  enforce(VERDICT_DROP);
}
/*---------------------------------------------------------------------------*/
static void
send_judge(void)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(JUDGE_IDENTIFIER,
      &context.neighbor->ids.extended_addr);
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
  
  memcpy(payload, context.rssis, MAX_PINGS);
  packetbuf_set_datalen(1 + MAX_PINGS);
  
  coresec_send_command_frame();
  PRINTF("screwed: sent judge\n");
}
/*---------------------------------------------------------------------------*/
static void
on_judge(int8_t *pinger_rssis)
{
  uint8_t verdict;
  int16_t expected_diffs[MIN_PINGS];
  int16_t actual_diffs[MIN_PINGS];
  
  verdict = VERDICT_DROP;
  if(!retain_best(pinger_rssis, expected_diffs, actual_diffs)) {
    PRINTF("screwed: Too lossy\n");
  } else {
    int8_t corr;
    
    corr = correlation(expected_diffs, actual_diffs);
    PRINTF("screwed: r^2 * 100 * sign(r) = %i; rho = %i\n", corr, RECIPROCITY_THRESHOLD);
    if(corr >= RECIPROCITY_THRESHOLD) {
      verdict = VERDICT_KEEP;
    }
  }
  
  send_verdict(verdict);
  enforce(verdict);
}
/*---------------------------------------------------------------------------*/
/* returns 0 <-> failed to retain MIN_PINGS RSSIs */
static int
retain_best(int8_t *pinger_rssis,
    int16_t *expected_diffs,
    int16_t *actual_diffs)
{
  uint8_t i;
  uint8_t j;
  uint8_t invalid_rssis;
#if DEBUG
  context.current_channel = CC2420_CONF_CHANNEL;
  for(i = 0; i < MAX_PINGS; i++) {
    hop_channel();
    if(pinger_rssis[i] != INVALID_RSSI) {
      PRINTF("Alice;PONG;0;%i;%i;%i;%i\nBob;PING;0;%i;%i;%i;%i\n",
          context.current_channel,
          i,
          pinger_rssis[i],
          context.dbms[i],
          context.current_channel,
          i,
          context.rssis[i],
          context.pinger_dbms[i]);
    }
  }
#endif /* DEBUG */
  
  invalid_rssis = 0;
  for(i = 0; i < MAX_PINGS; i++) {
    if(pinger_rssis[i] == INVALID_RSSI) {
      invalid_rssis++;
    }
  }
  
  PRINTF("screwed: N_received = %i\n", MAX_PINGS - invalid_rssis);
  
  if(invalid_rssis > MAX_PINGS - MIN_PINGS) {
    return 0;
  }
  
  /* each round drops the RSSI pair with the highest discrepancy */
  while(invalid_rssis < MAX_PINGS - MIN_PINGS) {
    int16_t discrepancy;
    int16_t max_discrepancy;
    uint8_t max_discrepancy_index;
    
    max_discrepancy = -1;
    for(i = 0; i < MAX_PINGS; i++) {
      if(pinger_rssis[i] == INVALID_RSSI) {
        continue;
      }
      
      discrepancy = (context.pinger_dbms[i] - context.dbms[i])
          - (context.rssis[i] - pinger_rssis[i]);
      discrepancy *= discrepancy;
      if(discrepancy >= max_discrepancy) {
        max_discrepancy = discrepancy;
        max_discrepancy_index = i;
      }
    }
    
    /* discard */
    pinger_rssis[max_discrepancy_index] = INVALID_RSSI;
    invalid_rssis++;
  }
  
  j = 0;
  for(i = 0; i < MAX_PINGS; i++) {
    if(pinger_rssis[i] != INVALID_RSSI) {
      expected_diffs[j] = context.pinger_dbms[i] - context.dbms[i];
      actual_diffs[j] = context.rssis[i] - pinger_rssis[i];
      j++;
    }
  }
  
  return 1;
}
/*---------------------------------------------------------------------------*/
static int16_t
get_mean_and_scale(int16_t *x)
{
  uint8_t i;
  int16_t sum;
  
  sum = 0;
  for(i = 0; i < MIN_PINGS; i++) {
    /* scale up to get better precision */
    x[i] *= 5;
    sum += x[i];
  }
  
  return sum / MIN_PINGS;
}
/*---------------------------------------------------------------------------*/
static int32_t
covariance(int16_t *x, int16_t mean_x, int16_t *y, int16_t mean_y)
{
  uint8_t i;
  int32_t sum;
    
  sum = 0;
  for(i = 0; i < MIN_PINGS; i++) {
    sum += (x[i] - mean_x) * (y[i] - mean_y);
  }
  
  return sum / (MIN_PINGS - 1);
}
/*---------------------------------------------------------------------------*/
/* Returns (correlation^2 * 100) * sign(correlation) */
static int8_t
correlation(int16_t *data1, int16_t *data2)
{
  int16_t mean1;
  int16_t mean2;
  int32_t var1;
  int32_t var2;
  int32_t cov;
  
  mean1 = get_mean_and_scale(data1);
  mean2 = get_mean_and_scale(data2);
  cov = covariance(data1, mean1, data2, mean2);
  var1 = covariance(data1, mean1, data1, mean1);
  var2 = covariance(data2, mean2, data2, mean2);
  
  PRINTF("screwed: cor^2 * 100 = %"PRId32" / %"PRId32"\n", (cov * cov), var1 * var2);
  
  var1 *= var2;
  if(!var1) {
    return -100;
  }
  return ((cov * cov) * 100 / var1) * (cov >= 0 ? 1 : -1);
}
/*---------------------------------------------------------------------------*/
static void
send_verdict(uint8_t verdict)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(VERDICT_IDENTIFIER,
      &context.neighbor->ids.extended_addr);
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
  
  payload[0] = verdict;
  packetbuf_set_datalen(1 + 1);
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
enforce(uint8_t verdict)
{
  ctimer_stop(&context.timeout);
  
  if(verdict != VERDICT_KEEP) {
    PRINTF("screwed: drop\n");
    neighbor_delete(context.neighbor);
  } else {
    PRINTF("screwed: keep\n");
    context.neighbor->status = NEIGHBOR_PERMANENT;
    neighbor_prolong(context.neighbor);
    apkes_trickle_on_new_neighbor();
  }
  is_busy = 0;
}
/*---------------------------------------------------------------------------*/
void
screwed_on_command_frame(uint8_t command_frame_identifier,
    struct neighbor *sender,
    uint8_t *payload)
{
  if(!is_busy) {
    PRINTF("screwed: not busy\n");
    return;
  }
  if(context.neighbor != sender) {
    PRINTF("screwed: wrong sender\n");
    return;
  }
  
  switch(context.neighbor->status) {
  case(NEIGHBOR_SAMPLING):
    switch(command_frame_identifier) {
    case PING_IDENTIFIER:
    case PONG_IDENTIFIER:
      on_ping_pong(payload);
      break;
    default:
      PRINTF("screwed: unknown sampling command\n");
      break;
    }
    break;
  case(NEIGHBOR_JUDGING):
    if((!coresec_decrypt_verify_unicast(sender->pairwise_key))
        || (anti_replay_was_replayed(&sender->anti_replay_info))) {
      PRINTF("screwed: verification failed\n");
      return;
    }
    
    switch(command_frame_identifier) {
    case JUDGE_IDENTIFIER:
      on_judge((int8_t *) payload);
      break;
    case VERDICT_IDENTIFIER:
      enforce(payload[0]);
      break;
    default:
      PRINTF("screwed: unknown judgement command\n");
      break;
    }
    break;
  default:
    PRINTF("screwed: should not happen\n");
    break;
  }
}
/*---------------------------------------------------------------------------*/
int
screwed_is_busy(void)
{
  return is_busy;
}
/*---------------------------------------------------------------------------*/

/** @} */
