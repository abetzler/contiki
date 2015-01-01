/**
 * \addtogroup llsec
 * @{
 */

/**
 * \defgroup coresec
 * 
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

#ifndef CORESEC_H_
#define CORESEC_H_

#include "net/llsec/llsec802154.h"
#include "net/llsec/llsec.h"
#include "net/llsec/coresec/neighbor.h"
#include "lib/aes-128.h"

#if CORESEC_PAIRWISE_KEY_LEN % 2
#error "Use only even CORESEC_PAIRWISE_KEY_LEN values\n"
#endif /* CORESEC_PAIRWISE_KEY_LEN */

#ifdef CORESEC_CONF_UNICAST_MIC_LENGTH
#define CORESEC_UNICAST_MIC_LENGTH      CORESEC_CONF_UNICAST_MIC_LENGTH
#else /* CORESEC_CONF_UNICAST_MIC_LENGTH */
#define CORESEC_UNICAST_MIC_LENGTH      LLSEC802154_MIC_LENGTH
#endif /* CORESEC_CONF_UNICAST_MIC_LENGTH */

#if CORESEC_PAIRWISE_KEY_LEN == 16
#define CORESEC_SET_PAIRWISE_KEY(key)   AES_128.set_key(key)
#else /* CORESEC_PAIRWISE_KEY_LEN */
#define CORESEC_SET_PAIRWISE_KEY(key)   aes_128_set_padded_key(key, NEIGHBOR_PAIRWISE_KEY_LEN)
#endif /* CORESEC_PAIRWISE_KEY_LEN */

#if CORESEC_BROADCAST_KEY_LEN == 16
#define CORESEC_SET_BROADCAST_KEY(key)  AES_128.set_key(key)
#else /* CORESEC_BROADCAST_KEY_LEN */
#define CORESEC_SET_BROADCAST_KEY(key)  aes_128_set_padded_key(key, NEIGHBOR_BROADCAST_KEY_LEN)
#endif /* CORESEC_BROADCAST_KEY_LEN */

#ifdef CORESEC_CONF_SCHEME
#define CORESEC_SCHEME                  CORESEC_CONF_SCHEME
#else /* CORESEC_CONF_SCHEME */
#define CORESEC_SCHEME                  apkes_coresec_scheme
#endif /* CORESEC_CONF_SCHEME */

/**
 * Structure of a pairwise key establishment scheme
 */
struct coresec_scheme {
  
  /** Whether or not bootstrapping was finished */
  int (*is_bootstrapped)(void);
  
  /** Called once at startup (prior to starting upper layers) */
  void (* bootstrap)(llsec_on_bootstrapped_t on_bootstrapped);
  
  /** Notifies the key establishment scheme of received command frames */
  void (* on_command_frame)(uint8_t command_frame_identifier,
      struct neighbor *sender,
      uint8_t *payload);
};

extern const struct coresec_scheme CORESEC_SCHEME;
extern const struct llsec_driver coresec_driver;

void coresec_add_security_header(uint8_t sec_lvl);
uint8_t *coresec_prepare_command_frame(uint8_t command_frame_identifier, const linkaddr_t *dest);
void coresec_send_command_frame(void);
int coresec_decrypt_verify_unicast(uint8_t *key);

#endif /* CORESEC_H_ */

/** @} */
/** @} */
