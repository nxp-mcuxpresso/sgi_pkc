/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021, 2023-2025 NXP                                       */
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
 * @file  mcuxClPkc_UPTRT.c
 * @brief PKC UPTRT (Universal pointer FUP table) generation function
 */


#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClPkc_Internal_Types.h>
#include <internal/mcuxClPkc_Internal_Functions.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPrng_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPkc_GenerateUPTRT)
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_GenerateUPTRT(
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
    uint16_t *pUPTRT,
    const uint8_t *pBaseBuffer,
    uint16_t bufferLength,
    uint8_t noOfBuffer)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPkc_GenerateUPTRT);

    uint32_t offset = MCUXCLPKC_PTR2OFFSET(pBaseBuffer);

    /* Caller shall provide valid pBaseBuffer, bufferLength and noOfBuffer, */
    /* such that all PKC operands are in valid range (PKC RAM).             */
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(offset, MCUXCLPKC_RAM_OFFSET_MIN, MCUXCLPKC_RAM_OFFSET_MAX - MCUXCLPKC_WORDSIZE)
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID((uint32_t) bufferLength, 0u, MCUXCLPKC_RAM_SIZE)
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID((uint32_t) noOfBuffer, 0u, 255u)
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(offset + ((uint32_t) bufferLength * (uint32_t) noOfBuffer), MCUXCLPKC_RAM_OFFSET_MIN + MCUXCLPKC_WORDSIZE, MCUXCLPKC_RAM_OFFSET_MAX)

    MCUX_CSSL_FP_LOOP_DECL(uptrtUpdateLoop);
    for (uint32_t idx = 0; idx < (uint32_t) noOfBuffer; idx++)
    {
        pUPTRT[idx] = (uint16_t) offset;
        offset += bufferLength;
        MCUX_CSSL_FP_LOOP_ITERATION(uptrtUpdateLoop);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPkc_GenerateUPTRT,
        MCUX_CSSL_FP_LOOP_ITERATIONS(uptrtUpdateLoop, noOfBuffer));
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPkc_RandomizeUPTRT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_RandomizeUPTRT(
    uint16_t *pUPTRT,
    uint8_t noOfBuffer)
{
    MCUX_CSSL_FP_LOOP_DECL(randomizationLoop);
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPkc_RandomizeUPTRT, MCUX_CSSL_FP_LOOP_ITERATIONS(randomizationLoop, ((uint32_t)noOfBuffer - 1U)));

    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID((uint32_t) noOfBuffer, 0u, 255u)
    
    /* Randomize entries in UPTRT by Knuth shuffle. */
    for (uint32_t idx = (uint32_t) noOfBuffer; idx > 1u; idx--)
    {
        /* Generate a random number in the range [0, idx-1], where idx <= noOfBuffer <= 255. */
        MCUX_CSSL_FP_FUNCTION_CALL(random32, mcuxClPrng_generate_word());
        MCUX_CSSL_FP_LOOP_ITERATION(randomizationLoop, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
        uint32_t random8 = random32 >> 8;
        random8 *= idx;
        random8 >>= 24;

        /* Swap. */
        uint16_t temp0 = pUPTRT[idx - 1u];
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("random8 in range [0, idx-1]")
        uint16_t temp1 = pUPTRT[random8];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        pUPTRT[random8] = temp0;
        pUPTRT[idx - 1u] = temp1;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPkc_RandomizeUPTRT);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPkc_ReRandomizeUPTRT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_ReRandomizeUPTRT(
    uint16_t *pUPTRT,
    uint16_t bufferLength,
    uint8_t noOfBuffer)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPkc_ReRandomizeUPTRT);

    MCUX_CSSL_FP_LOOP_DECL(uptrtUpdateLoop);
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID((uint32_t) noOfBuffer, 0u, 255u)

    /* Randomize entries in UPTRT by Knuth shuffle. */
    for (uint32_t idx = (uint32_t) noOfBuffer; idx > 1u; idx--)
    {
        /* Generate a random number in the range [0, idx-1], where idx <= noOfBuffer <= 255. */
        MCUX_CSSL_FP_FUNCTION_CALL(random32, mcuxClPrng_generate_word());
        uint32_t random8 = random32 >> 8u;
        random8 *= idx;
        random8 >>= 24u;

        /* Swap. */
        uint16_t offset0 = pUPTRT[idx - 1u];
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("random8 in range [0, idx-1]")
        uint16_t offset1 = pUPTRT[random8];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        pUPTRT[random8] = offset0;
        pUPTRT[idx - 1u] = offset1;

        /* Caller shall provide UPTR table with all offsets being exactly a multiple of MCUXCLPKC_WORDSIZE. */
        uint32_t *ptr0 = MCUXCLPKC_OFFSET2PTRWORD(offset0);
        uint32_t *ptr1 = MCUXCLPKC_OFFSET2PTRWORD(offset1);

        /* Swap contents of the two buffers, of which the size is a multiple of CPU word. */
        MCUX_CSSL_FP_LOOP_DECL(innerLoop);
        for (uint32_t i = 0u; i < ((uint32_t) bufferLength / 4U); i++)
        {
            uint32_t temp0 = ptr0[i];
            uint32_t temp1 = ptr1[i];
            ptr1[i] = temp0;
            ptr0[i] = temp1;
            MCUX_CSSL_FP_LOOP_ITERATION(innerLoop);
        }
        MCUX_CSSL_FP_LOOP_ITERATION(uptrtUpdateLoop,
            MCUX_CSSL_FP_LOOP_ITERATIONS(innerLoop, ((uint32_t) bufferLength / 4U)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPkc_ReRandomizeUPTRT,
        MCUX_CSSL_FP_LOOP_ITERATIONS(uptrtUpdateLoop, ((uint32_t)noOfBuffer - 1U)));
}
