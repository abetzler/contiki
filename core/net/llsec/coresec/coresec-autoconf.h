/**
 * \addtogroup coresec
 * @{
 */

/*
 * Copyright (c) 2014, Hasso-Plattner-Institut.
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
 *         Autoconfigures coresec-related settings
 *         according to LLSEC802154_CONF_SECURITY_LEVEL.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#undef NETSTACK_CONF_LLSEC
#define NETSTACK_CONF_LLSEC                 coresec_driver

#undef PACKETBUF_CONF_HDR_SIZE
#define PACKETBUF_CONF_HDR_SIZE             28

#if ((LLSEC802154_CONF_SECURITY_LEVEL & 3) == 1)
#define CORESEC_CONF_UNICAST_MIC_LENGTH     4
#define EBEAP_CONF_BROADCAST_MIC_LENGTH     5
#define NEIGHBOR_CONF_BROADCAST_KEY_LEN     8
#define NEIGHBOR_CONF_PAIRWISE_KEY_LEN      10
#elif ((LLSEC802154_CONF_SECURITY_LEVEL & 3) == 2)
#define CORESEC_CONF_UNICAST_MIC_LENGTH     6
#define EBEAP_CONF_BROADCAST_MIC_LENGTH     7
#define NEIGHBOR_CONF_BROADCAST_KEY_LEN     8
#define NEIGHBOR_CONF_PAIRWISE_KEY_LEN      12
#elif ((LLSEC802154_CONF_SECURITY_LEVEL & 3) == 3)
#define CORESEC_CONF_UNICAST_MIC_LENGTH     8
#define EBEAP_CONF_BROADCAST_MIC_LENGTH     9
#define NEIGHBOR_CONF_BROADCAST_KEY_LEN     12
#define NEIGHBOR_CONF_PAIRWISE_KEY_LEN      16
#else
#error "unsupported security level"
#endif

#if !(LLSEC802154_CONF_SECURITY_LEVEL & 4)
#undef NEIGHBOR_CONF_BROADCAST_KEY_LEN
#define NEIGHBOR_CONF_BROADCAST_KEY_LEN 0
#endif

#define NEIGHBOR_CONF_MAX ((127 - 19)/EBEAP_CONF_BROADCAST_MIC_LENGTH)
