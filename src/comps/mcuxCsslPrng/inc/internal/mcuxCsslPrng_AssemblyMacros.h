/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2026 NXP                                                 */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxCsslPrng_AssemblyMacros.h
 * @brief Assembly macros for accessing PRNG
 */


#ifndef MCUXCSSLPRNG_ASSEMBLYMACROS_H_
#define MCUXCSSLPRNG_ASSEMBLYMACROS_H_

#include <mcuxCsslPrng_AssemblyHeader.h>


/**
 * Assembly macro to initialize PRNG base address (higher 20 bits on RISC-V)
 *
 * regPrngAddr: register to be initialized to the base address to access PRNG
 */
#if defined(__IASMARM__) || defined(__ICCARM__)
MCUXCSSLPRNG_INIT_ADDR macro regPrngAddr
#if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  /* No init needed for stub*/
#else
  ldr   regPrngAddr, =MCUXCSSLPRNG_PRNG_ADDR
#endif
  endm
#elif defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
.macro MCUXCSSLPRNG_INIT_ADDR  regPrngAddr
#if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  /* No init needed for stub*/
#else
  ldr   \regPrngAddr, =MCUXCSSLPRNG_PRNG_ADDR
#endif
.endmacro
#elif MCUXCL_FEATURE_CSSL_SC_RISCV_ASM
.macro MCUXCSSLPRNG_INIT_ADDR  regPrngAddr
#if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  /* No init needed for stub*/
#else
  lui   \regPrngAddr, %hi(MCUXCSSLPRNG_PRNG_ADDR)
#endif
.endmacro
#elif defined(__GNUC__)
.macro MCUXCSSLPRNG_INIT_ADDR  regPrngAddr
#if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  /* No init needed for stub*/
#else
  ldr   \regPrngAddr, =MCUXCSSLPRNG_PRNG_ADDR
#endif
.endm
#else
  #error "Unsupported compiler for MCUXCSSLPRNG_INIT_ADDR macro"
#endif

#ifdef MCUXCL_FEATURE_CSSL_SC_RISCV_ASM
/**
 * Assembly macro to conditionally initialize PRNG base address
 *
 * This macro assumes the register (regPrngAddr) already contains the base address
 * of another hardware SFR (addressOtherHw). If the 2 SFR base addresses (PRNG and
 * the other hardware) are different, this macro will overwrite the register
 * with PRNG SFR base address. If both SFR base addresses are the same, this
 * macro will not do anything. Using this macro can avoid initializing register
 * with the same address.
 *
 * ps, RISC-V splits an address to (unsigned) higher 20 bits and (signed) lower 12 bits.
 * An address is split to the higher part, %hi(address) = (address + 0x800) >> 12, and lower part.
 * If higher 21 bits of 2 addresses are the same, they will map to the same higher part.
 *
 * regPrngAddr:    register to be updated to the base address to access PRNG
 * addressOtherHw: a constant, which is an address of another hardware SFR
 */
.macro MCUXCSSLPRNG_INIT_ADDR_COND  regPrngAddr, addressOtherHw
#if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
#else
.if (((\addressOtherHw) >> 11) != (MCUXCSSLPRNG_PRNG_ADDR >> 11))
  MCUXCSSLPRNG_INIT_ADDR  \regPrngAddr
.endif
#endif
.endmacro
#endif /* MCUXCL_FEATURE_CSSL_SC_RISCV_ASM */

/**
 * Fetch one word of PRNG from hardware SFR
 *
 * regPrngAddr: register containing the base address to access PRNG
 * regRandom:   register to be loaded one word of PRNG
 */
#if defined(__IASMARM__) || defined(__ICCARM__)
MCUXCSSLPRNG_GET_PRNG macro regPrngAddr, regRandom
  #if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  ldr regRandom, =0xDEADBEEF
  #else
  ldr regRandom, [regPrngAddr]
  #endif /* MCUXCL_FEATURE_CSSL_SC_RISCV_ASM */
  endm
#elif defined(MCUXCL_FEATURE_CSSL_SC_RISCV_ASM)
.macro MCUXCSSLPRNG_GET_PRNG  regPrngAddr, regRandom
  #if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  lw  \regRandom, =0xDEADBEEF
  #else
  lw  \regRandom, %lo(MCUXCSSLPRNG_PRNG_ADDR) (\regPrngAddr)
  #endif
.endmacro
#elif defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
.macro MCUXCSSLPRNG_GET_PRNG  regPrngAddr, regRandom
  #if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  ldr \regRandom, =0xDEADBEEF
  #else
  ldr \regRandom, [\regPrngAddr]
  #endif
.endmacro
#elif defined(__GNUC__)
.macro MCUXCSSLPRNG_GET_PRNG  regPrngAddr, regRandom
  #if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
  ldr \regRandom, =0xDEADBEEF
  #else
  ldr \regRandom, [\regPrngAddr]
  #endif
.endm
#endif

#endif /* MCUXCSSLPRNG_ASSEMBLYMACROS_H_ */
