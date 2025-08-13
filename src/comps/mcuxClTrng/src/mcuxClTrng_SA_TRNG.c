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

/** @file  mcuxClTrng_SA_TRNG.c
 *  @brief Implementation of the Trng component which provides APIs for
 *  handling of Trng random number. This file implements the functions
 *  declared in mcuxClTrng_Internal_Functions.h. */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClMemory.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClTrng_SfrAccess.h>
#include <internal/mcuxClTrng_Internal.h>
#include <internal/mcuxClTrng_Internal_SA_TRNG.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>

/**
 * @brief Wait until TRNG entropy generation is ready.
 *
 * @param[in] pNoOfTrngErrors TRNG error counter
 *
 * @note Data Integrity: Expunge(TRNG status bit) = Expunge(MCUXCLTRNG_SFR_BITREAD(MCTL, TSTOP_OK))
*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_WaitForReady)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_WaitForReady(mcuxClSession_Handle_t pSession, uint32_t *pNoOfTrngErrors)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_WaitForReady);

    do
    {
        /* Check whether TRNG has stopped generating */
        if (1u == (MCUXCLTRNG_SFR_BITREAD(MCTL, TSTOP_OK)))
        {
            /* Check wehether valid entropy has been generated */
            if ((1u != MCUXCLTRNG_SFR_BITREAD(MCTL, ENT_VAL)) || (0u != (MCUXCLTRNG_SFR_BITREAD(MCTL, ERR))))
            {
                /* TRNG hardware error detected: */
                /* Check how many errors occurred so far */
                if (MCUXCLTRNG_ERROR_LIMIT > (*pNoOfTrngErrors))
                {
                    /* Increase TRNG error counter */
                    (*pNoOfTrngErrors) += 1u;

                    /* Enable programming mode to clear the ERR flag*/
                    MCUXCLTRNG_SFR_BITSET(MCTL, PRGM);

                    /* Enable run mode to restart the entropy generation */
                    MCUXCLTRNG_SFR_BITCLEAR(MCTL, PRGM);
                }
                else
                {
                    /* Number of TRNG errors exceeded the limit, trigger Fault Attack. */
                    MCUXCLSESSION_FAULT(pSession, MCUXCLTRNG_STATUS_FAULT_ATTACK);
                }
            }
            else
            {
                /* Generated entropy is valid. Exit loop */
                break;
            }
        }
    } while(true);

    /* Record the status bit of TRNG to DI (at this point we expect it to be "TRNG ready" in all cases, never "TRNG busy") */
    MCUX_CSSL_DI_RECORD(trngStatus, MCUXCLTRNG_SFR_BITREAD(MCTL, TSTOP_OK));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_WaitForReady);
}

/**
 *  @brief Initialization function for the SA_TRNG
 *  @deprecated This function is deprecated, kept only for backward compatibility.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_Init(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_Init);
 
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_Init);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_checkConfig)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_checkConfig(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_checkConfig);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_checkConfig);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_getEntropyInput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_getEntropyInput(
    mcuxClSession_Handle_t pSession,
    uint32_t *pEntropyInput,
    uint32_t entropyInputLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_getEntropyInput);

    if ((NULL == pEntropyInput) || ((entropyInputLength % sizeof(uint32_t)) != 0u))
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLTRNG_STATUS_ERROR);
    }

    /* Put TRNG in running mode (clear PRGM bit) in case it has not been done before. */
    MCUXCLTRNG_SFR_BITCLEAR(MCTL, PRGM);

    /* Count the observed number of TRNG errors */
    uint32_t noOfTrngErrors = 0u;

    /* Copy full words of entropy.
     * NOTE: mcuxClMemory_copy_words_int is used since only word-wise SFR access is allowed.
     */
    uint32_t entropyInputWordLength = (entropyInputLength >> 2u);
    uint32_t *pDest = pEntropyInput;

    /* The subsequent loop to draw TRNG words is started with an offset to ensure that the last TRNG word drawn within the loop
    *  is the last word in the TRNG entropy register. This will trigger another TRNG entropy generation and reduces the time to wait
    *  for the TRNG to be ready when this function is called the next time.
    */
    uint32_t offset = MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS - (entropyInputWordLength % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS);

    /* Wait until TRNG entropy generation is ready. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClTrng_WaitForReady(pSession, &noOfTrngErrors));
    /* Expunge the status bit of TRNG from DI (recorded in mcuxClTrng_WaitForReady)  */
    MCUX_CSSL_DI_EXPUNGE(trngStatus, 1u);

    MCUX_CSSL_FP_LOOP_DECL(forLoop);
    for(uint32_t i = offset; i < (entropyInputWordLength + offset); i++)
    {
        /* When i is a multiple of the TRNG output buffer size (MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS) wait until new entropy words have been generated. */
        if((i % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS) == 0u)
        {
            /* Wait until TRNG entropy generation is ready. */
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClTrng_WaitForReady(pSession, &noOfTrngErrors));
            /* Expunge the status bit of TRNG from DI (recorded in mcuxClTrng_WaitForReady)  */
            MCUX_CSSL_DI_EXPUNGE(trngStatus, 1u);
        }
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_OUT_OF_BOUNDS_ACCESS("Overrunning array due to accessing index in ENT is caused by incorrect array size specified in external header that is outside our control")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_ARRAY_OUT_OF_BOUNDS("Overrunning array due to accessing index in ENT is caused by incorrect array size specified in external header that is outside our control")
        const volatile uint32_t *pTrngSrc = &(MCUXCLTRNG_SFR_READ(ENT)[i % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS]);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ARRAY_OUT_OF_BOUNDS()
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OUT_OF_BOUNDS_ACCESS()
        /* Balance DI for mcuxClMemory_copy_words_int */
        MCUX_CSSL_DI_RECORD(memCopyDIpDest, pDest);
        MCUX_CSSL_DI_RECORD(memCopyDIpSrc, pTrngSrc);
        MCUX_CSSL_DI_RECORD(memCopyDIpLength, sizeof(uint32_t));
        /* Copy word of entropy into destination buffer. */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pDest can't be larger than max(uint32_t)")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_VOLATILE("Access to a HW peripheral")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_OUT_OF_BOUNDS_ACCESS("Overrunning array due to de-referencing pTrngSrc is caused by external header that is outside our control")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_ARRAY_OUT_OF_BOUNDS("Overrunning array due to de-referencing pTrngSrc is caused by external header that is outside our control")
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int((uint8_t*)pDest, (uint8_t const *)pTrngSrc, sizeof(uint32_t)));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ARRAY_OUT_OF_BOUNDS()
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OUT_OF_BOUNDS_ACCESS()
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_VOLATILE()
        /* Increment pDest to point to the next word. */
        pDest++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        MCUX_CSSL_FP_LOOP_ITERATION(forLoop,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int),
            MCUX_CSSL_FP_CONDITIONAL((i % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS) == 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_WaitForReady)));
    }

    MCUX_CSSL_DI_EXPUNGE(trngOutputSize, entropyInputLength);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_getEntropyInput,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_WaitForReady),
        /* Inside for-loop */
        MCUX_CSSL_FP_LOOP_ITERATIONS(forLoop, entropyInputWordLength) );
}
