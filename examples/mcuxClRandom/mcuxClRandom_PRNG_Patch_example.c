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
 * @example mcuxClRandom_PRNG_Patch_example.c
 * @brief   Example for the mcuxClRandom component
 */

#include <mcuxClToolchain.h>
#include <mcuxClRandom.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClCore_Examples.h> // Defines and assertions for examples

static const ALIGNED uint8_t randomData[] = {0x8au,0x76u,0x90u,0xd2u,0xd9u,0x55u,0x3cu,0x93u,
                                             0x03u,0x52u,0x3au,0x3cu,0xbeu,0xe1u,0x39u,0xa4u,
                                             0xefu,0xf1u,0xc4u,0xbbu,0xa3u,0xc7u,0x09u,0xf3u,
                                             0xb7u,0x14u,0x07u,0xb2u,0xd8u,0x98u,0xa0u,0xaeu};

static mcuxClRandom_Status_t prngPatchFunction(
    void *pCustomState,
    mcuxCl_Buffer_t pOut,
    uint32_t outLength
)
{
    uint32_t *pIndexRandomData = (uint32_t *)pCustomState;

    for (uint32_t i = 0u; i < outLength; i++)
    {
        /* Ideally mcuxClBuffer_export should be used on larger chunks of data. Using it on individual bytes is just used to keep the example simple. */
        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(be_status, be_token, mcuxClBuffer_export(pOut, i, (uint8_t const *)&randomData[*pIndexRandomData], 1u));
        if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_export) != be_token) || (MCUXCLBUFFER_STATUS_OK != be_status))
        {
          return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_END();
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("modular arithmetic")
        *pIndexRandomData = (*pIndexRandomData + 1u) % sizeof(randomData);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    return MCUXCLRANDOM_STATUS_OK;  
}

/** Performs an example usage of the mcuxClRandom component
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClRandom_PRNG_Patch_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRANDOM_NCINIT_WACPU_SIZE, 0u);

    /* Initialize PRNG. This initializes PRNG in normal / unpatched mode */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("session->apiCall is not NULL")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(nci_status, nci_token, mcuxClRandom_ncInit(
                                        session
                                   ));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != nci_token) || (MCUXCLRANDOM_STATUS_OK != nci_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Start with PRNG in normal mode                                         */
    /**************************************************************************/

    uint8_t pPrngData[16u];
    MCUXCLBUFFER_INIT(pPrngBuffer, session, pPrngData, sizeof(pPrngData));

    /* Generate non cryptographic random values. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ncg_status1, ncg_token1, mcuxClRandom_ncGenerate(
                                        session,
                                        pPrngBuffer,
                                        sizeof(pPrngData)
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate) != ncg_token1) || (MCUXCLRANDOM_STATUS_OK != ncg_status1))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Check whether unpatched PRNG indeed outputs unexpected data */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT")
    bool outputAsExpected = mcuxClCore_assertEqual((const uint8_t *) pPrngData, (const uint8_t*) randomData, sizeof(pPrngData));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* Return error if buffers are equal */
    if(outputAsExpected)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Put PRNG in patch mode                                                 */
    /**************************************************************************/

    /* Initialize index to be used as custom context. As local variable to avoid DATA section in examples. */
    volatile uint32_t indexRandomData = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(patch_status, patch_token, mcuxClRandom_ncPatch(
                                        session,
                                        (mcuxClRandom_CustomNcGenerateAlgorithm_t) prngPatchFunction,
                                        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_VOLATILE()
                                        (void *) &indexRandomData
                                        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_VOLATILE()
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncPatch) != patch_token) || (MCUXCLRANDOM_STATUS_OK != patch_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate patched random values. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ncg_status2, ncg_token2, mcuxClRandom_ncGenerate(
                                        session,
                                        pPrngBuffer,
                                        sizeof(pPrngData)
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate) != ncg_token2) || (MCUXCLRANDOM_STATUS_OK != ncg_status2))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Check whether patched PRNG indeed outputs expected data */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT")
    outputAsExpected = mcuxClCore_assertEqual((const uint8_t *) pPrngData, (const uint8_t*) randomData, sizeof(pPrngData));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* Return error if buffers are unequal */
    if(!outputAsExpected)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Check that the index used by the patch function is updated as expected. */
    if (indexRandomData != (sizeof(pPrngData) % sizeof(randomData)))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    
    /**************************************************************************/
    /* Return to PRNG in normal mode                                          */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(unpatch_status, unpatch_token, mcuxClRandom_ncInit(
                                        session
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != unpatch_token) || (MCUXCLRANDOM_STATUS_OK != unpatch_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate non cryptographic random values. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ncg_status3, ncg_token3, mcuxClRandom_ncGenerate(
                                        session,
                                        pPrngBuffer,
                                        sizeof(pPrngData)
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate) != ncg_token3) || (MCUXCLRANDOM_STATUS_OK != ncg_status3))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Check whether unpatched PRNG indeed outputs unexpected data */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT")
    outputAsExpected = mcuxClCore_assertEqual((const uint8_t *) pPrngData, (const uint8_t*) randomData, sizeof(pPrngData));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* Return error if buffers are equal */
    if(outputAsExpected)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
