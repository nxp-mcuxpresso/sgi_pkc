/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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

/** @file  mcuxClPrng_SCM.c
 *  @brief Implementation of the non-cryptographic PRNG functions using SCM. */

#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPrng_Internal.h>
#include <mcuxClBuffer.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <mcuxCsslDataIntegrity.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPrng_generate_word)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClPrng_generate_word(void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPrng_generate_word);

    MCUXCLPRNG_INIT()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_INTEGER_TO_POINTER("PRNG SFR address")
    MCUXCLPRNG_GET_WORD(randomWord);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_INTEGER_TO_POINTER()

    MCUXCLPRNG_RESTORE()

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPrng_generate_word, randomWord);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPrng_generate_Internal)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPrng_generate_Internal(
    uint8_t*              pOut,
    uint32_t              outLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPrng_generate_Internal);

    MCUX_CSSL_DI_RECORD(sumOfPassedInputParams, (uint32_t)pOut);
    MCUX_CSSL_DI_RECORD(sumOfPassedInputParams, outLength);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("casting pointer to integer to check alignment.");
    const uint32_t dstAddress = (uint32_t) pOut;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER();

    uint32_t unalignedBytes = sizeof(uint32_t) - (dstAddress % sizeof(uint32_t));
    uint32_t leadingBytes = (unalignedBytes < outLength) ? unalignedBytes : outLength;
    uint32_t outLengthFullWords = (outLength - leadingBytes) / sizeof(uint32_t);
    uint32_t remainingBytes = (outLength - leadingBytes) % sizeof(uint32_t);

    MCUXCLPRNG_INIT()

    while (0u != leadingBytes) /* destination address is not aligned. */
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(pOut);
        MCUXCLPRNG_GET_WORD(randomWord);
        uint8_t randomByte = (uint8_t)(randomWord & 0xFFu);
        /* Write random byte to pOut */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Caller shall provide valid buffer pOut of outLength.");
        *(pOut++)= randomByte;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        leadingBytes--;
    }

    for(uint32_t i = 0u; i < outLengthFullWords; i++)
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(pOut);
        MCUXCLPRNG_GET_WORD(drawnRandom);
        /* Write random word to pOut */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Caller shall provide valid buffer pOut of outLength.");
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pOut is 32-bit aligned")
        *((uint32_t*)pOut) = drawnRandom;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        pOut = pOut + sizeof(uint32_t);
    }

    while(0u != remainingBytes)
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(pOut);
        MCUXCLPRNG_GET_WORD(randomWord);
        uint8_t randomByte = (uint8_t)(randomWord & 0xFFu);
        /* Write random byte to pOut */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Caller shall provide valid buffer pOut of outLength.");
        *(pOut++)= randomByte;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        remainingBytes--;
    }

    MCUXCLPRNG_RESTORE()

    MCUX_CSSL_DI_EXPUNGE(incrementedOutputPointer, (uint32_t)pOut);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPrng_generate_Internal);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPrng_generate)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPrng_generate(
    mcuxClSession_Handle_t pSession,
    mcuxCl_Buffer_t        pOut,
    uint32_t              outLength
)
{
    //TODO CLNS-10974 improve this function
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPrng_generate);

    uint32_t outLengthFullWords = (outLength / sizeof(uint32_t));
    MCUX_CSSL_DI_RECORD(sumOfBufferWrite1Params, outLengthFullWords * (uint32_t)pOut);
    MCUX_CSSL_DI_RECORD(sumOfBufferWrite1Params, outLengthFullWords * sizeof(uint32_t));

    MCUXCLPRNG_INIT()

    for(uint32_t i = 0u; i < outLengthFullWords; i++)
    {
        MCUXCLPRNG_GET_WORD(drawnRandom);

        /* Write to pOut */
        MCUX_CSSL_DI_RECORD(sumOfBufferWrite1Params, i * sizeof(uint32_t));
        MCUX_CSSL_DI_RECORD(sumOfBufferWrite1Params, (uint32_t) &drawnRandom);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pOut, i * sizeof(uint32_t), (const uint8_t*)(&drawnRandom), sizeof(uint32_t)));
    }

    uint32_t remainingBytes = (outLength % sizeof(uint32_t));
    if(0u != remainingBytes)
    {
        MCUXCLPRNG_GET_WORD(drawnRandomRemainingBytes);
        MCUX_CSSL_DI_RECORD(sumOfBufferWrite2Params, (uint32_t)pOut);
        MCUX_CSSL_DI_RECORD(sumOfBufferWrite2Params, outLengthFullWords * sizeof(uint32_t));
        MCUX_CSSL_DI_RECORD(sumOfBufferWrite2Params, (uint32_t) &drawnRandomRemainingBytes);
        MCUX_CSSL_DI_RECORD(sumOfBufferWrite2Params, remainingBytes);

        /* Write to pOut */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pOut, outLengthFullWords * sizeof(uint32_t), (const uint8_t*)(&drawnRandomRemainingBytes), remainingBytes));
    }

    MCUXCLPRNG_RESTORE()

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPrng_generate,
        (outLengthFullWords * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write)),
        MCUX_CSSL_FP_CONDITIONAL((0U != remainingBytes),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write)));
}
