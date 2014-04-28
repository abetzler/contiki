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

#ifndef SCREWED_H_
#define SCREWED_H_

#include "net/llsec/coresec/neighbor.h"

#ifdef SCREWED_CONF_MAX_PINGS
#define SCREWED_MAX_PINGS          SCREWED_CONF_MAX_PINGS
#else /* SCREWED_CONF_MAX_PINGS */
#define SCREWED_MAX_PINGS          16
#endif /* SCREWED_CONF_MAX_PINGS */
#define SCREWED_PIGGYBACK_LEN      SCREWED_MAX_PINGS

/**
 * \brief    Prepares PONGing
 * \retval 0 <-> error
 */
int screwed_prepare_pong(struct neighbor *receiver, int8_t *pinger_dbms);

/**
 * \brief    Starts PONGing
 */
void screwed_pong(void *ptr, int status, int transmissions);

/**
 * \brief    Starts PINGing
 * \retval 0 <-> error
 */
int screwed_ping(struct neighbor *sender, int8_t *pinger_dbms);

/**
 * \brief    Processes command frames
 */
void screwed_on_command_frame(uint8_t command_frame_identifier, struct neighbor *sender, uint8_t *payload);

/**
 * \brief    Whether SCREWED is currently busy
 */
int screwed_is_busy(void);

#endif /* SCREWED_H_ */

/** @} */
