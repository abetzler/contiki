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
 *         Easy Broadcast Encryption and Authentication Protocol (EBEAP).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef EBEAP_H_
#define EBEAP_H_

#include "net/llsec/coresec/neighbor.h"
#include "net/mac/mac.h"

#define EBEAP_WITH_ENCRYPTION     NEIGHBOR_BROADCAST_KEY_LEN
#define EBEAP_ANNOUNCE_IDENTIFIER 0x0D

#if EBEAP_WITH_ENCRYPTION
extern uint8_t ebeap_broadcast_key[NEIGHBOR_BROADCAST_KEY_LEN];
#endif /* EBEAP_WITH_ENCRYPTION */

void ebeap_send_broadcast(mac_callback_t sent, void *ptr);
void ebeap_on_announce(struct neighbor *sender, uint8_t *payload);
int ebeap_decrypt_verify_broadcast(struct neighbor *sender);
void ebeap_init(void);

#endif /* EBEAP_H_ */

/** @} */
