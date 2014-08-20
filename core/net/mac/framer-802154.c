/* 
 * Copyright (c) 2009, Swedish Institute of Computer Science.
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
 *         MAC framer for IEEE 802.15.4
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "net/mac/framer-802154.h"
#include "net/mac/frame802154.h"
#include "net/llsec/llsec802154.h"
#include "net/packetbuf.h"
#include "lib/random.h"
#include <string.h>

#define DEBUG 0

#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7])
#else
#define PRINTF(...)
#define PRINTADDR(addr)
#endif

/**  \brief The sequence number (0x00 - 0xff) added to the transmitted
 *   data or MAC command frame. The default is a random value within
 *   the range.
 */
static uint8_t mac_dsn;

static uint8_t initialized = 0;

/**  \brief The 16-bit identifier of the PAN on which the device is
 *   sending to.  If this value is 0xffff, the device is not
 *   associated.
 */
static const uint16_t mac_dst_pan_id = IEEE802154_PANID;

/**  \brief The 16-bit identifier of the PAN on which the device is
 *   operating.  If this value is 0xffff, the device is not
 *   associated.
 */
static const uint16_t mac_src_pan_id = IEEE802154_PANID;

/*---------------------------------------------------------------------------*/
#if LLSEC802154_USES_EXPLICIT_KEYS
static uint8_t
get_key_id_len(uint8_t key_id_mode)
{
  switch(key_id_mode) {
  case FRAME802154_1_BYTE_KEY_ID_MODE:
    return 1;
  case FRAME802154_5_BYTE_KEY_ID_MODE:
    return 5;
  case FRAME802154_9_BYTE_KEY_ID_MODE:
    return 9;
  default:
    return 0;
  }
}
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
/*---------------------------------------------------------------------------*/
static int
hdr_length(void)
{
  return 2 /* Frame Control */
      + 1 /* Sequence Number */
      + 2 /* Destination PAN Identifier */
      + (packetbuf_holds_broadcast() ? 2 : LINKADDR_SIZE) /* Destination Address */
      + 0 /* Source PAN Identifier (always compressed) */
      + LINKADDR_SIZE /* Source Address */
#if LLSEC802154_SECURITY_LEVEL
      /* Auxiliary Security Header */
      + (packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL) ? 5 : 0)
#if LLSEC802154_USES_EXPLICIT_KEYS
      + get_key_id_len(packetbuf_attr(PACKETBUF_ATTR_KEY_ID_MODE))
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
#endif /* LLSEC802154_SECURITY_LEVEL */
      ;
}
/*---------------------------------------------------------------------------*/
static void
create_addr(uint8_t *p, const linkaddr_t *addr)
{
  uint8_t i;
  
  for(i = 0; i < LINKADDR_SIZE; i++) {
    p[i] = addr->u8[LINKADDR_SIZE - 1 - i];
  }
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  uint8_t *hdrptr;
  uint8_t *p;
  int is_broadcast;
#if LLSEC802154_SECURITY_LEVEL
  frame802154_frame_counter_t frame_counter;
  uint8_t security_level = packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL);
#if LLSEC802154_USES_EXPLICIT_KEYS
  uint8_t i;
  frame802154_key_source_t key_source;
  uint8_t key_id_mode = packetbuf_attr(PACKETBUF_ATTR_KEY_ID_MODE);
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
#endif /* LLSEC802154_SECURITY_LEVEL */
  
  if(!packetbuf_hdralloc(hdr_length())) {
    PRINTF("15.4-OUT: too large header: %u\n", hdr_length());
    return FRAMER_FAILED;
  }
  
  hdrptr = p = packetbuf_hdrptr();
  is_broadcast = packetbuf_holds_broadcast();
  
  /* Frame Type | Sec. Enabled | Frame Pending | Ack Request | PAN ID Compr. */
  p[0] = (packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) & 7) 
#if LLSEC802154_SECURITY_LEVEL
      | (security_level ? 1 << 3 : 0)
#endif /* LLSEC802154_SECURITY_LEVEL */
      | (packetbuf_attr(PACKETBUF_ATTR_PENDING) ? 1 << 4 : 0)
      | (packetbuf_attr(PACKETBUF_ATTR_MAC_ACK) && !is_broadcast ? 1 << 5 : 0)
      | (1 << 6);
  
  /* Dest. Addressing Mode | Frame Version | Source Addressing Mode */
  p[1] = (is_broadcast || (LINKADDR_SIZE == 2)
              ? FRAME802154_SHORTADDRMODE << 2
              : FRAME802154_LONGADDRMODE << 2)
    | (FRAME802154_IEEE802154_2006 << 4)
    | (LINKADDR_SIZE == 2
      ? FRAME802154_SHORTADDRMODE << 6
      : FRAME802154_LONGADDRMODE << 6);
  
  /* Sequence Number */
  if(!packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO)) {
    if(!initialized) {
      initialized = 1;
      mac_dsn = random_rand() & 0xff;
    }
    /* Ensure that the sequence number 0 is not used as it would bypass the above check. */
    if(mac_dsn == 0) {
      mac_dsn++;
    }
    packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, mac_dsn++);
  }
  p[2] = (uint8_t) packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
  p += 3;
  
  /* Destination PAN ID */
  p[0] = mac_dst_pan_id & 0xff;
  p[1] = (mac_dst_pan_id >> 8) & 0xff;
  p += 2;
  
  /* Destination address */
  if(is_broadcast) {
    p[0] = 0xFF;
    p[1] = 0xFF;
    p += 2;
  } else {
    create_addr(p, packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
    p += LINKADDR_SIZE;
  }
  
  /* Source PAN ID (always compressed) */
  
  /* Source address */
  create_addr(p, &linkaddr_node_addr);
  p += LINKADDR_SIZE;
  
#if LLSEC802154_SECURITY_LEVEL
  /* Auxiliary Security Header */
  if(security_level) {
    p[0] = security_level
#if LLSEC802154_USES_EXPLICIT_KEYS
        | (key_id_mode << 3)
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
    ;
    p += 1;
    frame_counter.u16[0] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1);
    frame_counter.u16[1] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3);
    memcpy(p, frame_counter.u8, 4);
    p += 4;
    
#if LLSEC802154_USES_EXPLICIT_KEYS
    if(key_id_mode) {
      memset(key_source.u8, 0, sizeof(key_source));
      key_source.u16[0] = packetbuf_attr(PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1);
      i = (key_id_mode - 1) * 4;
      memcpy(p, key_source.u8, i);
      p += i;
      p[0] = (uint8_t) packetbuf_attr(PACKETBUF_ATTR_KEY_INDEX);
      p += 1;
    }
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
  }
#endif /* LLSEC802154_SECURITY_LEVEL */
  
  PRINTF("15.4-OUT: %2X", packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE));
  PRINTADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  PRINTF("%d %u (%u)\n", p - hdrptr, packetbuf_datalen(), packetbuf_totlen());
  
  return p - hdrptr;
}
/*---------------------------------------------------------------------------*/
static uint8_t
parse_addr(uint8_t *p, uint8_t mode, uint8_t type)
{
  linkaddr_t addr;
  uint8_t i;
  
  switch(mode) {
  case FRAME802154_SHORTADDRMODE:
    if((p[0] == 0xFF) && (p[1] == 0xFF)) {
      if(type == PACKETBUF_ADDR_SENDER) {
        /* the source address is 0xFFFF */
        return 0;
      }
      packetbuf_set_addr(type, &linkaddr_null);
    } else {
      if(LINKADDR_SIZE == 8) {
        return 0;
      }
      addr.u8[1] = p[0];
      addr.u8[0] = p[1];
      packetbuf_set_addr(type, &addr);
    }
    return 2;
  case FRAME802154_LONGADDRMODE:
    if(LINKADDR_SIZE == 2) {
      return 0;
    }
    for(i = 0; i < 8; i++) {
      addr.u8[LINKADDR_SIZE - i - 1] = p[i];
    }
    packetbuf_set_addr(type, &addr);
    return 8;
  default:
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  uint8_t *hdrptr;
  uint8_t *p;
  int panid_compressed;
  uint8_t dest_addr_mode;
  uint8_t src_addr_mode;
  uint16_t dest_pid;
  uint8_t addr_len;
#if LLSEC802154_SECURITY_LEVEL
  int security_enabled;
  frame802154_frame_counter_t frame_counter;
#if LLSEC802154_USES_EXPLICIT_KEYS
  uint8_t key_id_mode;
  frame802154_key_source_t key_source;
  uint8_t i;
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
#endif /* LLSEC802154_SECURITY_LEVEL */
  
  if(packetbuf_datalen() < 3) {
    return FRAMER_FAILED;
  }
  
  hdrptr = p = packetbuf_hdrptr();
  
  /* Frame Type | Sec. Enabled | Frame Pending | Ack Request | PAN ID Compr. */
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, p[0] & 7);
#if LLSEC802154_SECURITY_LEVEL
  security_enabled = (p[0] >> 3) & 1;
#endif /* LLSEC802154_SECURITY_LEVEL */
  packetbuf_set_attr(PACKETBUF_ATTR_PENDING, (p[0] >> 4) & 1);
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, (p[0] >> 5) & 1);
  panid_compressed = (p[0] >> 6) & 1;
  
  /* Dest. Addressing Mode | Frame Version | Source Addressing Mode */
  dest_addr_mode = (p[1] >> 2) & 3;
  /* ignore Frame Version */
  src_addr_mode = (p[1] >> 6) & 3;
  
  /* Sequence Number */
  packetbuf_set_attr(PACKETBUF_ATTR_PACKET_ID, p[2]);
  p += 3;
  
  if(dest_addr_mode) {
    /* Destination PAN ID */
    dest_pid = p[0] + (p[1] << 8);
    if(dest_pid != mac_src_pan_id && dest_pid != FRAME802154_BROADCASTPANDID) {
      PRINTF("15.4: for another pan %X\n", dest_pid);
      return FRAMER_FAILED;
    }
    p += 2;
    
    /* Destination address */
    addr_len = parse_addr(p, dest_addr_mode, PACKETBUF_ADDR_RECEIVER);
    if(!addr_len) {
      return FRAMER_FAILED;
    }
    p += addr_len;
  }
  
  if(src_addr_mode) {
    /* Source PAN ID */
    if(!panid_compressed) {
      p += 2;
    }
    
    /* Source address */
    addr_len = parse_addr(p, src_addr_mode, PACKETBUF_ADDR_SENDER);
    if(!addr_len) {
      return FRAMER_FAILED;
    }
    p += addr_len;
  }
  
#if LLSEC802154_SECURITY_LEVEL
  if(security_enabled) {
    packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, p[0] & 7);
#if LLSEC802154_USES_EXPLICIT_KEYS
    key_id_mode = (p[0] >> 3) & 3;
    packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, key_id_mode);
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
    p += 1;
    memcpy(frame_counter.u8, p, 4);
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1, frame_counter.u16[0]);
    packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3, frame_counter.u16[1]);
    p += 4;
#if LLSEC802154_USES_EXPLICIT_KEYS
    if(key_id_mode) {
      i = (key_id_mode - 1) * 4;
      memcpy(key_source.u8, p, i);
      packetbuf_set_attr(PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1, key_source.u16[0]);
      p += i;
      packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, p[0]);
      p += 1;
    }
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
  }
#endif /* LLSEC802154_SECURITY_LEVEL */

  if(!packetbuf_hdrreduce(p - hdrptr)) {
    return FRAMER_FAILED;
  }
  
  PRINTF("15.4-IN: %2X", packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE));
  PRINTADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  PRINTADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  PRINTF("%d %u (%u)\n", p - hdrptr, packetbuf_datalen(), packetbuf_totlen());
  
  return p - hdrptr;
}
/*---------------------------------------------------------------------------*/
const struct framer framer_802154 = {
  hdr_length,
  create,
  framer_canonical_create_and_secure,
  parse
};
/*---------------------------------------------------------------------------*/
