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
#include "net/llsec/anti-replay.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/packetbuf.h"
#include <string.h>

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

MEMB(neighbors_memb, struct neighbor, NEIGHBOR_MAX);
LIST(neighbor_list);

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
delete_expired_tentatives(void)
{
  struct neighbor *next;
  struct neighbor *current;
  
  next = neighbor_head();
  while(next) {
    current = next;
    next = list_item_next(current);
    if(current->status && (current->expiration_time <= clock_seconds())) {
      neighbor_delete(current);
    }
  }
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_new(void)
{
  struct neighbor *new_neighbor;
  
  delete_expired_tentatives();
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
  memcpy(&ids->short_addr, short_addr, NEIGHBOR_SHORT_ADDR_LEN);
}
/*---------------------------------------------------------------------------*/
void
neighbor_update(struct neighbor *neighbor, uint8_t *data)
{
  anti_replay_init_info(&neighbor->anti_replay_info);
  neighbor->status = NEIGHBOR_PERMANENT;
  neighbor->foreign_index = data[0];
  data++;
#if NEIGHBOR_BROADCAST_KEY_LEN
  memcpy(&neighbor->broadcast_key, data, NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* NEIGHBOR_BROADCAST_KEY_LEN */
  
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
void
neighbor_init(void)
{
  memb_init(&neighbors_memb);
  list_init(neighbor_list);
}
/*---------------------------------------------------------------------------*/

/** @} */
