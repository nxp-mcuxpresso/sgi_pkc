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
#include <internal/mcuxClTrng_SfrAccess.h>
#include <internal/mcuxClTrng_Internal.h>
#include <internal/mcuxClTrng_Internal_SA_TRNG.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

/**
 * @brief Wait until TRNG entropy generation is ready.
 *
 * @param[in] pNoOfTrngErrors TRNG error counter
 *
 * @return Status of the operation
 * @retval #MCUXCLTRNG_STATUS_OK Entropy is ready and valid
 * @retval #MCUXCLTRNG_STATUS_FAULT_ATTACK TRNG error counter exceeded the error limit
*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_WaitForReady)
static inline void mcuxClTrng_WaitForReady(mcuxClSession_Handle_t pSession, uint32_t *pNoOfTrngErrors)
{
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
}

/**
 *  @brief Initialization function for the SA_TRNG
 *
 *  This function performs all required steps to be done before SA_TRNG data can be requested via the function
 *  mcuxClTrng_getEntropyInput.
 *
 *  NOTES:
 *   - Enabling and configuration of the SA_TRNG shall be done before calling the Crypto Library.
 *     The Crypto Library requires the TRNG to be configured in dual oscillator mode. Therefore,
 *     this function simply verifies that the TRNG is configured in dual oscillator mode.
 *   - For performance it is recommended to put the TRNG in running mode immediately after configuration.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_Init(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_Init);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClTrng_checkConfig(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_Init,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_checkConfig));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_checkConfig)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_checkConfig(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_checkConfig);

    /* Verify that the TRNG is configured in dual oscillator mode. */
    if(MCUXCLTRNG_SFR_BITREAD(OSC2_CTL, TRNG_ENT_CTL) != MCUXCLTRNG_SA_TRNG_HW_DUAL_OSCILLATOR_MODE)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLTRNG_STATUS_ERROR);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_checkConfig);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_getEntropyInput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClTrng_getEntropyInput(
    mcuxClSession_Handle_t pSession,
    uint32_t *pEntropyInput,
    uint32_t entropyInputLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_getEntropyInput,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_checkConfig));

    if ((NULL == pEntropyInput) || ((entropyInputLength % sizeof(uint32_t)) != 0u))
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLTRNG_STATUS_ERROR);
    }

    /* Call check configuration function to ensure the TRNG is properly configured for upcoming TRNG accesses */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClTrng_checkConfig(pSession));

    /* Put TRNG in running mode (clear PRGM bit) in case it has not been done before. */
    MCUXCLTRNG_SFR_BITCLEAR(MCTL, PRGM);

    /* Count the observed number of TRNG errors */
    uint32_t noOfTrngErrors = 0u;

    /* Copy full words of entropy.
     * NOTE: Memory_copy is not used since it copies byte-wise from SFR while only word-wise SFR access is allowed.
     */
    uint32_t entropyInputWordLength = (entropyInputLength >> 2u);
    uint32_t *pDest = pEntropyInput;

    /* The subsequent loop to draw TRNG words is started with an offset to ensure that the last TRNG word drawn within the loop
    *  is the last word in the TRNG entropy register. This will trigger another TRNG entropy generation and reduces the time to wait
    *  for the TRNG to be ready when this function is called the next time.
    */
    uint32_t offset = MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS - (entropyInputWordLength % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS);

    /* Wait until TRNG entropy generation is ready. */
    mcuxClTrng_WaitForReady(pSession, &noOfTrngErrors);

    for(uint32_t i = offset; i < (entropyInputWordLength + offset); i++)
    {
        /* When i is a multiple of the TRNG output buffer size (MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS) wait until new entropy words have been generated. */
        if((i % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS) == 0u)
        {
            /* Wait until TRNG entropy generation is ready. */
            mcuxClTrng_WaitForReady(pSession, &noOfTrngErrors);
        }
        /* Copy word of entropy into destination buffer. */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pDest can't be larger than max(uint32_t)")
        *pDest = MCUXCLTRNG_SFR_READ(ENT)[i % MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS];
        /* Increment pDest to point to the next word. */
        pDest++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    MCUX_CSSL_DI_EXPUNGE(trngOutputSize, entropyInputLength);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClTrng_getEntropyInput);
}

