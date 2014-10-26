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

#ifndef APKES_H_
#define APKES_H_

#include "net/llsec/coresec/coresec.h"

#ifdef APKES_CONF_MAX_WAITING_PERIOD
#define APKES_MAX_WAITING_PERIOD        APKES_CONF_MAX_WAITING_PERIOD
#else /* APKES_CONF_MAX_WAITING_PERIOD */
#define APKES_MAX_WAITING_PERIOD        (20 * CLOCK_SECOND)
#endif /* APKES_CONF_MAX_WAITING_PERIOD */

#ifdef APKES_CONF_ACK_DELAY
#define APKES_ACK_DELAY                 APKES_CONF_ACK_DELAY
#else /* APKES_CONF_ACK_DELAY */
#define APKES_ACK_DELAY                 (5 * CLOCK_SECOND)
#endif /* APKES_CONF_ACK_DELAY */

#ifdef APKES_CONF_MAX_TENTATIVE_NEIGHBORS
#define APKES_MAX_TENTATIVE_NEIGHBORS   APKES_CONF_MAX_TENTATIVE_NEIGHBORS
#else /* APKES_CONF_MAX_TENTATIVE_NEIGHBORS */
#define APKES_MAX_TENTATIVE_NEIGHBORS   3
#endif /* APKES_CONF_MAX_TENTATIVE_NEIGHBORS */

/* Defines the plugged-in scheme */
#ifdef APKES_CONF_SCHEME
#define APKES_SCHEME                    APKES_CONF_SCHEME
#else /* APKES_CONF_SCHEME */
#define APKES_SCHEME                    leap_apkes_scheme
#endif /* APKES_CONF_SCHEME */

/**
 * Structure of a pluggable scheme
 */
struct apkes_scheme {
  
  /** Called at startup */
  void (* init)(void);
  
  /**
   * \return      Shared secret of length >= CORESEC_PAIRWISE_KEY_LEN
   * \retval NULL HELLO shall be discarded
   */
  uint8_t* (* get_secret_with_hello_sender)(struct neighbor_ids *ids);
  
  /**
   * \return      Shared secret of length >= CORESEC_PAIRWISE_KEY_LEN
   * \retval NULL HELLOACK shall be discarded
   */
  uint8_t* (* get_secret_with_helloack_sender)(struct neighbor_ids *ids);
};

extern const struct apkes_scheme APKES_SCHEME;
extern const struct coresec_scheme apkes_coresec_scheme;

void apkes_broadcast_hello(void);
void apkes_init(void);
void apkes_send_update(struct neighbor *receiver);

#endif /* APKES_H_ */

/** @} */
