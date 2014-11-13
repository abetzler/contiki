/*
 *  Copyright (c) 2008, Swedish Institute of Computer Science
 *  All rights reserved.
 *
 *  Additional fixes for AVR contributed by:
 *        Colin O'Flynn coflynn@newae.com
 *        Eric Gnoske egnoske@gmail.com
 *        Blake Leverett bleverett@gmail.com
 *        Mike Vidales mavida404@gmail.com
 *        Kevin Brown kbrown3@uccs.edu
 *        Nate Bohlmann nate@elfwerks.com
 *
 *  Additional fixes for MSP430 contributed by:
 *        Joakim Eriksson
 *        Niclas Finne
 *        Nicolas Tsiftes
 *
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of the copyright holders nor the names of
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
*/

/**
 *    \addtogroup net 802.15.4 frame creation and parsing
 *    @{
 */

/**
 *    \defgroup frame802154 802.15.4 frame creation and parsing
 *    @{
 */
/**
 *  \file
 *  \brief 802.15.4 frame creation and parsing functions
 *
 *  This file converts to and from a structure to a packed 802.15.4
 *  frame.
 *
*/


/* Includes */
#ifndef FRAME_802154_H
#define FRAME_802154_H

#include "contiki-conf.h"

#ifdef IEEE802154_CONF_PANID
#define IEEE802154_PANID           IEEE802154_CONF_PANID
#else /* IEEE802154_CONF_PANID */
#define IEEE802154_PANID           0xABCD
#endif /* IEEE802154_CONF_PANID */

/* Macros & Defines */

/** \brief These are some definitions of values used in the FCF.  See the 802.15.4 spec for details.
 *  \name FCF element values definitions
 *  @{
 */
#define FRAME802154_BEACONFRAME     (0x00)
#define FRAME802154_DATAFRAME       (0x01)
#define FRAME802154_ACKFRAME        (0x02)
#define FRAME802154_CMDFRAME        (0x03)

#define FRAME802154_BEACONREQ       (0x07)

#define FRAME802154_IEEERESERVED    (0x00)
#define FRAME802154_NOADDR          (0x00)      /**< Only valid for ACK or Beacon frames. */
#define FRAME802154_SHORTADDRMODE   (0x02)
#define FRAME802154_LONGADDRMODE    (0x03)

#define FRAME802154_NOBEACONS       (0x0F)

#define FRAME802154_BROADCASTADDR   (0xFFFF)
#define FRAME802154_BROADCASTPANDID (0xFFFF)

#define FRAME802154_IEEE802154_2003 (0x00)
#define FRAME802154_IEEE802154_2006 (0x01)

#define FRAME802154_SECURITY_LEVEL_NONE        (0)
#define FRAME802154_SECURITY_LEVEL_MIC_32      (1)
#define FRAME802154_SECURITY_LEVEL_MIC_64      (2)
#define FRAME802154_SECURITY_LEVEL_MIC_128     (3)
#define FRAME802154_SECURITY_LEVEL_ENC         (4)
#define FRAME802154_SECURITY_LEVEL_ENC_MIC_32  (5)
#define FRAME802154_SECURITY_LEVEL_ENC_MIC_64  (6)
#define FRAME802154_SECURITY_LEVEL_ENC_MIC_128 (7)

#define FRAME802154_IMPLICIT_KEY               (0)
#define FRAME802154_1_BYTE_KEY_ID_MODE         (1)
#define FRAME802154_5_BYTE_KEY_ID_MODE         (2)
#define FRAME802154_9_BYTE_KEY_ID_MODE         (3)

typedef union {
  uint32_t u32;
  uint16_t u16[2];
  uint8_t u8[4];
} frame802154_frame_counter_t;

typedef union {
  uint16_t u16[4];
  uint8_t u8[8];
} frame802154_key_source_t;

/** @} */
#endif /* FRAME_802154_H */
/** @} */
/** @} */
