/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxCsslMemory_Internal_XOR.c
 */
#include <stddef.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxCsslMemory_Internal_XOR.h>

#define WORDSIZE  (sizeof(uint32_t))

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Int_XOR)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_XOR(
                                                        uint8_t *pTarget,
                                                        const uint8_t *pSource,
                                                        const uint8_t *pSource2,
                                                        uint32_t length
                                                      )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Int_XOR);
    uint32_t remainingLen = length;

    MCUX_CSSL_DI_RECORD(xorParams, 2u * length);
    MCUX_CSSL_FP_LOOP_DECL(mcuxCsslMemory_Int_XOR_loop);

    /* xor by word if aligned */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("casting pointer to integer to check alignment.")
    if ((remainingLen >= WORDSIZE) && (0u == ((uint32_t)pTarget & (WORDSIZE - 1u)))
                && (0u == ((uint32_t)pSource & (WORDSIZE - 1u)))
                && (0u == ((uint32_t)pSource2 & (WORDSIZE - 1u))))
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    {
        do
        {
            MCUX_CSSL_DI_DONOTOPTIMIZE(pSource);
            MCUX_CSSL_DI_DONOTOPTIMIZE(pSource2);
            MCUX_CSSL_DI_DONOTOPTIMIZE(pTarget);
            MCUX_CSSL_FP_LOOP_ITERATION(mcuxCsslMemory_Int_XOR_loop);
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pSource, pSource2 and pTarget are word aligned.")
            const uint32_t temp1 = *(const uint32_t *)pSource;
            const uint32_t temp2 = *(const uint32_t *)pSource2;
            *(uint32_t *)pTarget = temp1 ^ temp2;
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

            MCUX_CSSL_FP_LOOP_ITERATION(mcuxCsslMemory_Int_XOR_loop);
            pSource += WORDSIZE;
            pSource2 += WORDSIZE;
            pTarget += WORDSIZE;
            MCUX_CSSL_FP_LOOP_ITERATION(mcuxCsslMemory_Int_XOR_loop);
            remainingLen -= WORDSIZE;
            MCUX_CSSL_FP_LOOP_ITERATION(mcuxCsslMemory_Int_XOR_loop);
        } while (remainingLen >= WORDSIZE);
    }

    /* xor the remaining bytes */
    while (remainingLen > 0u)
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(pSource);
        MCUX_CSSL_DI_DONOTOPTIMIZE(pSource2);
        MCUX_CSSL_DI_DONOTOPTIMIZE(pTarget);
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Caller should set length and bufLength properly to make sure not to overflow.")
        const uint8_t temp1 = *pSource++;
        const uint8_t temp2 = *pSource2++;
        *pTarget++ = temp1 ^ temp2;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        remainingLen--;
        MCUX_CSSL_FP_LOOP_ITERATION(mcuxCsslMemory_Int_XOR_loop);
    }

    MCUX_CSSL_DI_EXPUNGE(xorParams, pTarget);
    MCUX_CSSL_DI_EXPUNGE(xorParams, pSource);
    MCUX_CSSL_DI_EXPUNGE(xorParams, pSource2);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxCsslMemory_Int_XOR,
                              MCUX_CSSL_FP_LOOP_ITERATIONS(mcuxCsslMemory_Int_XOR_loop, length));
}

