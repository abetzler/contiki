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
 *         Neighbor management for compromise-resilient LLSEC drivers.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/neighbor.h"
#include "net/llsec/coresec/apkes.h"
#include "net/llsec/coresec/apkes-trickle.h"
#include "net/llsec/coresec/apkes-flash.h"
#include "net/llsec/coresec/coresec.h"
#include "net/llsec/ccm-star.h"
#include "net/packetbuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "sys/etimer.h"

#ifdef NEIGHBOR_CONF_LIFETIME
#define LIFETIME                 NEIGHBOR_CONF_LIFETIME
#else /* NEIGHBOR_CONF_LIFETIME */
#define LIFETIME                 (60 * 60) /* seconds */
#endif /* NEIGHBOR_CONF_LIFETIME */

#ifdef NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL
#define UPDATE_CHECK_INTERVAL    NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL
#else /* NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL */
#define UPDATE_CHECK_INTERVAL    (60 * 3) /* seconds */
#endif /* NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL */

#ifdef NEIGHBOR_CONF_MAX_UPDATES
#define MAX_UPDATES              NEIGHBOR_CONF_MAX_UPDATES
#else /* NEIGHBOR_CONF_MAX_UPDATES */
#define MAX_UPDATES              3
#endif /* NEIGHBOR_CONF_MAX_UPDATES */

#ifdef NEIGHBOR_CONF_UPDATEACK_WAITING_PERIOD
#define UPDATEACK_WAITING_PERIOD NEIGHBOR_CONF_UPDATEACK_WAITING_PERIOD
#else /* NEIGHBOR_CONF_UPDATEACK_WAITING_PERIOD */
#define UPDATEACK_WAITING_PERIOD 5 /* seconds */
#endif /* NEIGHBOR_CONF_UPDATEACK_WAITING_PERIOD */

#define LAZY_THRESHOLD           (NEIGHBOR_MAX - APKES_MAX_TENTATIVE_NEIGHBORS)

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

MEMB(neighbors_memb, struct neighbor, NEIGHBOR_MAX);
LIST(neighbor_list);
PROCESS(update_process, "update_process");

/*---------------------------------------------------------------------------*/
int
neighbor_count(void)
{
  return list_length(neighbor_list);
}
/*---------------------------------------------------------------------------*/
void
neighbor_prolong(struct neighbor *neighbor)
{
  neighbor->expiration_time = clock_seconds() + LIFETIME;
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_head(void)
{
  return list_head(neighbor_list);
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_next(struct neighbor *previous)
{
  return list_item_next(previous);
}
/*---------------------------------------------------------------------------*/
static void
add(struct neighbor *new_neighbor)
{
  struct neighbor *current;
  struct neighbor *next;
  
  current = neighbor_head();
  
  if(!current) {
    new_neighbor->local_index = 0;
    list_add(neighbor_list, new_neighbor);
  } else {
    while(((next = list_item_next(current)))) {
      if((next->local_index - current->local_index) > 1) {
        break;
      }
      current = next;
    }
    new_neighbor->local_index = current->local_index + 1;
    list_insert(neighbor_list, current, new_neighbor);
  }
}
/*---------------------------------------------------------------------------*/
static void
delete_expired_neighbors(void)
{
  struct neighbor *next;
  struct neighbor *current;
  
  next = neighbor_head();
  while(next) {
    current = next;
    next = list_item_next(current);
    if(current->expiration_time <= clock_seconds()) {
      neighbor_delete(current);
    }
  }
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_new(void)
{
  struct neighbor *new_neighbor;
  
  delete_expired_neighbors();
  new_neighbor = memb_alloc(&neighbors_memb);
  if(!new_neighbor) {
    PRINTF("neighbor: ERROR\n");
    return NULL;
  }
  add(new_neighbor);
  return new_neighbor;
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_get(const linkaddr_t *extended_addr)
{
  struct neighbor *next;
  
  next = neighbor_head();
  while(next) {
    if(linkaddr_cmp(&next->ids.extended_addr, extended_addr)) {
      return next;
    }
    next = list_item_next(next);
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
neighbor_update_ids(struct neighbor_ids *ids, void *short_addr)
{
  memcpy(ids->extended_addr.u8,
      packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8,
      sizeof(linkaddr_t));
  memcpy(&ids->short_addr,
      short_addr,
      NEIGHBOR_SHORT_ADDR_LEN);
}
/*---------------------------------------------------------------------------*/
void
neighbor_update(struct neighbor *neighbor, uint8_t *data)
{
  neighbor_update_ids(&neighbor->ids, data);
  data += NEIGHBOR_SHORT_ADDR_LEN;
  anti_replay_init_info(&neighbor->anti_replay_info);
  neighbor->status = NEIGHBOR_PERMANENT;
  neighbor->foreign_index = data[0];
  data++;
#if NEIGHBOR_BROADCAST_KEY_LEN
  memcpy(&neighbor->broadcast_key, data, NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* NEIGHBOR_BROADCAST_KEY_LEN */
  
  neighbor_prolong(neighbor);
  apkes_flash_backup_neighbors();
  apkes_trickle_on_new_neighbor();
  
#if DEBUG
  {
    uint8_t i;
    
    PRINTF("neighbor: Neighbor %04X:\n", neighbor->ids.short_addr);
    PRINTF("neighbor: Foreign index: %i Local index: %i\n", neighbor->foreign_index, neighbor->local_index);
#if NEIGHBOR_BROADCAST_KEY_LEN
    PRINTF("neighbor: Broadcast key: ");
    for(i = 0; i < NEIGHBOR_BROADCAST_KEY_LEN; i++) {
      PRINTF("%x", neighbor->broadcast_key[i]);
    }
    PRINTF("\n");
#endif /* NEIGHBOR_BROADCAST_KEY_LEN */
    
    PRINTF("neighbor: Pairwise key: ");
    for(i = 0; i < NEIGHBOR_PAIRWISE_KEY_LEN; i++) {
      PRINTF("%x", neighbor->pairwise_key[i]);
    }
    PRINTF("\n");
  }
#endif /* DEBUG */
}
/*---------------------------------------------------------------------------*/
void
neighbor_delete(struct neighbor *neighbor)
{
  list_remove(neighbor_list, neighbor);
  memb_free(&neighbors_memb, neighbor);
}
/*---------------------------------------------------------------------------*/
static int
shall_update(struct neighbor *neighbor)
{
  clock_time_t now;
  
  now = clock_seconds();
  
  if(neighbor_count() <= LAZY_THRESHOLD) {
    /* We have enough slots available so do not bother with UPDATEs */
    neighbor_prolong(neighbor);
    return 0;
  }
  
  if(now > neighbor->expiration_time) {
    /* 
     * We tried to update him without success.
     * This slot will be freed when delete_expired_neighbors is called.
     */
    return 0;
  }
  
  if(neighbor->expiration_time - now
      > UPDATE_CHECK_INTERVAL + NEIGHBOR_MAX * UPDATEACK_WAITING_PERIOD * MAX_UPDATES) {
    /* wait for next interval */
    return 0;
  }
  
  /* send UPDATE */
  return 1;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(update_process, ev, data)
{
  static struct etimer update_check_timer;
  static struct etimer retry_timer;
  static struct neighbor *next;
  static uint8_t max_retries;
  
  PROCESS_BEGIN();
  
  PRINTF("neighbor: Started update_process\n");
  etimer_set(&update_check_timer, UPDATE_CHECK_INTERVAL * CLOCK_SECOND);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&update_check_timer));
    
    next = neighbor_head();
    while(next) {
      max_retries = MAX_UPDATES;
      while(shall_update(next) && max_retries--) {
        PRINTF("neighbor: Sending UPDATE\n");
        apkes_send_update(next);
        etimer_set(&retry_timer, UPDATEACK_WAITING_PERIOD * CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&retry_timer));
      }
      next = list_item_next(next);
    }
    
    delete_expired_neighbors();
    etimer_reset(&update_check_timer);
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void
neighbor_init(void)
{
  memb_init(&neighbors_memb);
  list_init(neighbor_list);
  process_start(&update_process, NULL);
}
/*---------------------------------------------------------------------------*/

/** @} */
