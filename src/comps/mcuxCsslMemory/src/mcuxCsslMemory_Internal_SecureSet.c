/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file  mcuxCsslMemory_Internal_SecureSet.c
 */
#include <stddef.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxCsslPrng_Macros.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>
#include <internal/mcuxCsslMemory_Internal_SecureSet.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Int_SecSet)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecSet
(
    uint8_t * pDst,
    uint8_t val,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Int_SecSet);
    uint32_t remainLength = length;
    uint32_t wordVal = ((uint32_t)val << 24u) | ((uint32_t)val << 16u) | ((uint32_t)val << 8u) | (uint32_t)val;
    const uint32_t cpuWordSize = sizeof(uint32_t);

    volatile uint8_t *p8Dst = pDst;

    // Randomize the output buffer before setting the value
    uint32_t randomWordValue = MCUXCSSLPRNG_GENERATE_WORD();
    uint8_t randomByteValue = (uint8_t) (randomWordValue & 0xFFu);

    MCUX_CSSL_FP_LOOP_DECL(FirstByteLoop);
    MCUX_CSSL_FP_LOOP_DECL(SecondByteLoop);
    MCUX_CSSL_FP_LOOP_DECL(WordLoop);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("intentional pointer to integer cast to check alignment")
    while ((0u != ((uint32_t) p8Dst & (cpuWordSize - 1u))) && (0u != remainLength))
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        MCUX_CSSL_FP_LOOP_ITERATION(FirstByteLoop);
        *p8Dst = randomByteValue;
        *p8Dst = val;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Validity ensured by the caller.")
        p8Dst++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        remainLength--;
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("p8Dst is CPU word-aligned after the previous loop.")
    volatile uint32_t *p32Dst = (volatile uint32_t *) p8Dst;  /* p8Dst is CPU word-aligned after the previous loop. */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    while (cpuWordSize <= remainLength)
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(p32Dst);
        MCUX_CSSL_FP_LOOP_ITERATION(WordLoop);
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Validity ensured by the caller.")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("p32Dst has properly aligned and cast was valid")
        *p32Dst = randomWordValue;
        *p32Dst = wordVal;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
        p32Dst++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        remainLength -= cpuWordSize;
    }

    p8Dst = (volatile uint8_t *) p32Dst;
    while (0u != remainLength)
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        MCUX_CSSL_FP_LOOP_ITERATION(SecondByteLoop);
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Validity ensured by the caller.")
        *p8Dst = randomByteValue;
        *p8Dst = val;
        p8Dst++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        remainLength--;
    }

    MCUX_CSSL_FP_COUNTER_STMT(uint32_t noOfBytesToAlignment = ((0u - ((uint32_t) pDst)) & (cpuWordSize - 1u)));
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t firstByteIteration = (length > noOfBytesToAlignment)
                             ? noOfBytesToAlignment
                             : length);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t wordIteration = (length > firstByteIteration)
                             ? ((length - firstByteIteration) / cpuWordSize)
                             : 0u);

    MCUX_CSSL_DI_EXPUNGE(secureSetParams, (uint32_t) p8Dst);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxCsslMemory_Int_SecSet,
        MCUX_CSSL_FP_LOOP_ITERATIONS(FirstByteLoop, firstByteIteration),
        MCUX_CSSL_FP_LOOP_ITERATIONS(WordLoop, wordIteration),
        MCUX_CSSL_FP_LOOP_ITERATIONS(SecondByteLoop, length - (wordIteration * cpuWordSize) - firstByteIteration));
}
