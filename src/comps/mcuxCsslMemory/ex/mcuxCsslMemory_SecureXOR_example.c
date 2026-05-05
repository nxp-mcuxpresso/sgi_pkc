/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025 NXP                                                 */
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
 * @example  mcuxCsslMemory_SecureXOR_example.c
 * @brief Example for the secure XOR function
 */


#include <stdbool.h>
#include <stdint.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslMemory_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>


#define BYTELEN_SOURCE  64u
#define BYTELEN_TARGET  64u
#define XOR_CONSTANT    0xE6u


static inline void resetArray(uint8_t* arr, uint32_t size)
{
    for(uint32_t i=0u; i<size; i++)
    {
        arr[i] = 0u;
    }
}

/* Array of 0x00 ~ 0x3F */
static uint32_t source[BYTELEN_SOURCE / (sizeof(uint32_t))] =
{
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
};
/* Array of 0x00 ~ 0x3F */
static uint32_t source2[BYTELEN_SOURCE / (sizeof(uint32_t))] =
{
    0x03020100u, 0x07060504u, 0x0B0A0908u, 0x0F0E0D0Cu,
    0x13121110u, 0x17161514u, 0x1B1A1918u, 0x1F1E1D1Cu,
    0x23222120u, 0x27262524u, 0x2B2A2928u, 0x2F2E2D2Cu,
    0x33323130u, 0x37363534u, 0x3B3A3938u, 0x3F3E3D3Cu
};

bool mcuxCsslMemory_SecureXOR_example(void)
{
    uint8_t target[BYTELEN_TARGET] = {0};
    
    uint8_t * pSource = (uint8_t *)source;
    const uint8_t * pSource2 = (uint8_t *) source2;
    uint8_t * pTarget = (uint8_t *) target;

    /* Example of mcuxCsslMemory_SecureXOR with KEEP_ORDER. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultSecureXOR, tokenSecureXOR,
        mcuxCsslMemory_SecureXOR(MCUX_CSSL_PI_PROTECT(pSource, pSource2, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_KEEP_ORDER),
                                 pSource, pSource2, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_KEEP_ORDER) );
    if (   (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureXOR) != tokenSecureXOR)
        || (MCUXCSSLMEMORY_STATUS_OK != resultSecureXOR))
    {
        return MCUXCSSLMEMORY_EX_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    resetArray(target,BYTELEN_TARGET);

    /* Example of mcuxCsslMemory_SecureXOR with REVERSE_ORDER. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultSecureXORRev, tokenSecureXORRev,
        mcuxCsslMemory_SecureXOR(MCUX_CSSL_PI_PROTECT(pSource, pSource2, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_REVERSE_ORDER),
                                 pSource, pSource2, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_REVERSE_ORDER) );
    if (   (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureXOR) != tokenSecureXORRev)
        || (MCUXCSSLMEMORY_STATUS_OK != resultSecureXORRev))
    {
        return MCUXCSSLMEMORY_EX_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    resetArray(target,BYTELEN_TARGET);

    /* Example of mcuxCsslMemory_SecureXORWithConst. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultSecureXORWithConst, tokenSecureXORWithConst,
        mcuxCsslMemory_SecureXORWithConst(MCUX_CSSL_PI_PROTECT(pSource, XOR_CONSTANT, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE),
                                 pSource, XOR_CONSTANT, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE) );
    if (   (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureXORWithConst) != tokenSecureXORWithConst)
        || (MCUXCSSLMEMORY_STATUS_OK != resultSecureXORWithConst))
    {
        return MCUXCSSLMEMORY_EX_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCSSLMEMORY_EX_OK;
}
