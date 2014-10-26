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
 *         Localized Encryption and Authentication Protocol (LEAP).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/leap.h"
#include "net/llsec/coresec/apkes-flash.h"
#include "net/llsec/coresec/apkes-trickle.h"
#include "sys/ctimer.h"
#include "lib/aes-128.h"
#include <string.h>

#ifdef LEAP_CONF_KEY_ERASURE_DELAY
#define KEY_ERASURE_DELAY  LEAP_CONF_KEY_ERASURE_DELAY
#else /* LEAP_CONF_KEY_ERASURE_DELAY */
#define KEY_ERASURE_DELAY  (2 * 60 * CLOCK_SECOND)
#endif /* LEAP_CONF_KEY_ERASURE_DELAY */

#define INDIVIDUAL_KEY_LEN LEAP_MASTER_KEY_LEN

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/* Cryptographic material */
static uint8_t master_key[LEAP_MASTER_KEY_LEN];
static uint8_t individual_key[INDIVIDUAL_KEY_LEN];
/* Used for decrypting and verifying HELLOACKs */
static uint8_t temporary_individual_key[INDIVIDUAL_KEY_LEN];
/* Schedules the erasure of the master key */
struct ctimer erasure_timer;

/*---------------------------------------------------------------------------*/
static void
generate_individual_key(uint8_t *individual_key, const linkaddr_t *address)
{
  AES_128.set_key(master_key);
  memset(individual_key, 0, INDIVIDUAL_KEY_LEN);
  memcpy(individual_key, address->u8, sizeof(linkaddr_t));
  aes_128_padded_encrypt(individual_key, INDIVIDUAL_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
static uint8_t *
get_secret_with_hello_sender(struct neighbor_ids *ids)
{
  return individual_key;
}
/*---------------------------------------------------------------------------*/
static uint8_t *
get_secret_with_helloack_sender(struct neighbor_ids *ids)
{
  if(ctimer_expired(&erasure_timer)) {
    return NULL;
  }
  
  generate_individual_key(temporary_individual_key, &ids->extended_addr);
  
  return temporary_individual_key;
}
/*---------------------------------------------------------------------------*/
static void
erase(void *ptr)
{
  memset(master_key, 0, LEAP_MASTER_KEY_LEN);
  memset(temporary_individual_key, 0, INDIVIDUAL_KEY_LEN);
  apkes_flash_erase_keying_material();
  
  PRINTF("leap: erased master key\n");
  
  apkes_trickle_stop();
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  apkes_flash_restore_keying_material(master_key, LEAP_MASTER_KEY_LEN, 0);
  generate_individual_key(individual_key, &linkaddr_node_addr);
  ctimer_set(&erasure_timer, KEY_ERASURE_DELAY, erase, NULL);
}
/*---------------------------------------------------------------------------*/
const struct apkes_scheme leap_apkes_scheme = {
  init,
  get_secret_with_hello_sender,
  get_secret_with_helloack_sender
};
/*---------------------------------------------------------------------------*/

/** @} */
