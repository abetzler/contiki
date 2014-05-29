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
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Replays everything verbatim.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "wormsec.h"
#include "net/mac/frame802154.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "sys/ctimer.h"

#define TIMEOUT                    (CLOCK_SECOND/20)
#define MAX_PINGS                  90
#define ADAPTIVE                   0
#define OFFSET                     -7

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

static int8_t phase;
static struct ctimer timeout;
static uint8_t current_channel;
static int is_busy;
#if ADAPTIVE
static int8_t ping_rssi;
#endif

/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
hop_channel(void)
{
  current_channel = ((current_channel - 11 + 7) % 16) + 11;
}
/*---------------------------------------------------------------------------*/
static void
next_phase(void *ptr)
{
  if(++phase == MAX_PINGS) {
      ctimer_stop(&timeout);
    is_busy = 0;
    NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, CC2420_CONF_CHANNEL);
    return;
  }
  
  if(ptr) {
    /* timeout occured */
    ctimer_reset(&timeout);
  } else {
    ctimer_stop(&timeout);
    ctimer_set(&timeout, TIMEOUT, next_phase, &timeout);
  }
  
  hop_channel();
  NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, current_channel);
}
/*---------------------------------------------------------------------------*/
static void
replay(void)
{
  NETSTACK_RADIO.send(packetbuf_hdrptr(), packetbuf_totlen());
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  uint8_t *dataptr;
#if ADAPTIVE
  int8_t pong_rssi;
  int8_t pong_power;
#endif /* ADAPTIVE */
  
  dataptr = packetbuf_dataptr();
  if(!is_busy) {
    replay();
    /*
    if((packetbuf_attr(PACKETBUF_ATTR_KEY_ID_MODE) == FRAME802154_1_BYTE_KEY_ID_MODE)
        && (packetbuf_attr(PACKETBUF_ATTR_KEY_INDEX) == 0x0C)) {*/
    if((packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) == FRAME802154_CMDFRAME)
        && (dataptr[0] == 0x0C)) {
      /* this is an ACK */
      PRINTF("ACK\n");
      phase = -1;
      current_channel = CC2420_CONF_CHANNEL;
      is_busy = 1;
      next_phase(NULL);
    } else {
      /* something else */
      PRINTF("replayed\n");
    }
  } else {
    if(!packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL)
        && (packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) == FRAME802154_CMDFRAME)) {
      switch(dataptr[0]) {
      case(0x0E): /* PING */
#if ADAPTIVE
        ping_rssi = packetbuf_attr(PACKETBUF_ATTR_RSSI);
        NETSTACK_RADIO.set_value(RADIO_PARAM_TXPOWER, OFFSET);
#endif /* ADAPTIVE */
        replay();
        break;
      case(0x0F): /* PONG */
#if ADAPTIVE
        pong_rssi = packetbuf_attr(PACKETBUF_ATTR_RSSI);
        pong_power = pong_rssi - ping_rssi + OFFSET;
      
        if((pong_power >= -12) && (pong_power <= 0)) {
          NETSTACK_RADIO.set_value(RADIO_PARAM_TXPOWER, pong_power);
#endif /* ADAPTIVE */
          replay();
          next_phase(NULL);
#if ADAPTIVE
        }
        PRINTF("%i\n", pong_power);
#endif /* ADAPTIVE */
        break;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_overhead(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
bootstrap(llsec_on_bootstrapped_t on_bootstrapped)
{
  on_bootstrapped();
}
/*---------------------------------------------------------------------------*/
const struct llsec_driver wormsec_driver = {
  "wormsec",
  bootstrap,
  send,
  on_frame_created,
  input,
  get_overhead
};
/*---------------------------------------------------------------------------*/

/** @} */
