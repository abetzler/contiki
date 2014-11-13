/*
 * Copyright (c) 2008, Swedish Institute of Computer Science.
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
 *         MAC interface for packaging radio packets into 802.15.4 frames
 *
 * \author
 *         Adam Dunkels <adam@sics.se>
 *         Eric Gnoske <egnoske@gmail.com>
 *         Blake Leverett <bleverett@gmail.com>
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include <string.h>
#include "net/mac/sicslowmac/sicslowmac.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"

#define DEBUG 0

#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7])
#else
#define PRINTF(...)
#define PRINTADDR(addr)
#endif

/*---------------------------------------------------------------------------*/
static void
send_packet(mac_callback_t sent, void *ptr)
{
  int ret;
  
#if !NETSTACK_CONF_BRIDGE_MODE
  packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &linkaddr_null);
#endif
  
  if(NETSTACK_FRAMER.create_and_secure() < 0) {
    PRINTF("6MAC: Frame creation failed\n");
    return;
  }
  
  ret = NETSTACK_RADIO.send(packetbuf_hdrptr(), packetbuf_totlen());
  mac_call_sent_callback(sent, ptr, ret, 1);
}
/*---------------------------------------------------------------------------*/
void
send_list(mac_callback_t sent, void *ptr, struct rdc_buf_list *buf_list)
{
  if(buf_list != NULL) {
    queuebuf_to_packetbuf(buf_list->buf);
    send_packet(sent, ptr);
  }
}
/*---------------------------------------------------------------------------*/
static void
input_packet(void)
{
  if(NETSTACK_FRAMER.parse() < 0) {
    PRINTF("6MAC: Frame parsing failed\n");
    return;
  }
  
  if(!packetbuf_holds_broadcast()
#if !NETSTACK_CONF_BRIDGE_MODE
      && !linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
          &linkaddr_node_addr)
#endif
      ) {
    PRINTF("6MAC: not for us\n");
  }
  
  PRINTF("6MAC-IN: %2X", packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE));
  PRINTADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  PRINTADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  PRINTF("%u\n", packetbuf_datalen());
  NETSTACK_MAC.input();
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  return NETSTACK_RADIO.on();
}
/*---------------------------------------------------------------------------*/
static int
off(int keep_radio_on)
{
  if(keep_radio_on) {
    return NETSTACK_RADIO.on();
  } else {
    return NETSTACK_RADIO.off();
  }
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  NETSTACK_RADIO.on();
}
/*---------------------------------------------------------------------------*/
static unsigned short
channel_check_interval(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
const struct rdc_driver sicslowmac_driver = {
  "sicslowmac",
  init,
  send_packet,
  send_list,
  input_packet,
  on,
  off,
  channel_check_interval
};
/*---------------------------------------------------------------------------*/
