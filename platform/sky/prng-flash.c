/*
 * Copyright (c) 2014, Konrad-Felix Krentz.
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
 *         Helpers for accessing external flash memory.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "sys/prng-flash.h"
#include "contiki.h"
#include "dev/xmem.h"
#include "lib/prng.h"

/*---------------------------------------------------------------------------*/
static void
preload(uint8_t *seed, uint32_t resets)
{
  xmem_erase(XMEM_ERASE_UNIT_SIZE, PRNG_FLASH_SEED_OFFSET);
  xmem_pwrite(seed, PRNG_SEED_LEN, PRNG_FLASH_SEED_OFFSET);
  xmem_pwrite(&resets, sizeof(uint32_t), PRNG_FLASH_SEED_OFFSET + PRNG_SEED_LEN);
}
/*---------------------------------------------------------------------------*/
void
prng_flash_preload_seed(uint8_t *seed)
{
  preload(seed, 0);
}
/*---------------------------------------------------------------------------*/
void
prng_flash_restore_seed(void)
{
  xmem_pread(prng_seed, PRNG_SEED_LEN, PRNG_FLASH_SEED_OFFSET);
  xmem_pread(&prng_node_resets, sizeof(prng_node_resets), PRNG_FLASH_SEED_OFFSET + PRNG_SEED_LEN);
  preload(prng_seed, prng_node_resets + 1);
}
/*---------------------------------------------------------------------------*/
