/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

/** @file  mcuxClRandom_PRNG.c
 *  @brief Implementation of the non-cryptographic PRNG functions. */

#include <mcuxClToolchain.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClRandom.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClRandom_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncPatch)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_ncPatch(
    mcuxClSession_Handle_t pSession,
    mcuxClRandom_CustomNcGenerateAlgorithm_t prngPatchFunction,
    void *pCustomPrngState
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_ncPatch, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);

    MCUX_CSSL_DI_RECORD(sumOfRandomNcPatchParams, (uint32_t)pSession + (uint32_t) pCustomPrngState);

    /* Set the PRNG patch function to patch the PRNG */
    pSession->randomCfg.prngPatchFunction = prngPatchFunction;
    pSession->randomCfg.pCustomPrngState = pCustomPrngState;

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomNcPatchParams, (uint32_t)pSession + (uint32_t) pCustomPrngState);

    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_ncPatch, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncInit)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_ncInit(
    mcuxClSession_Handle_t pSession
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_ncInit, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);

    MCUX_CSSL_DI_RECORD(sumOfRandomNcInitParams, (uint32_t)pSession);

    /* Reset the PRNG patch function to un-patch the PRNG */
    pSession->randomCfg.prngPatchFunction = NULL;
    pSession->randomCfg.pCustomPrngState = NULL;

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomNcInitParams, (uint32_t)pSession);

    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_ncInit, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncGenerate_Internal)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandom_ncGenerate_Internal(
    mcuxClSession_Handle_t pSession,
    uint8_t*              pOut,
    uint32_t              outLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_ncGenerate_Internal);

    if(NULL != pSession->randomCfg.prngPatchFunction)
    {
        MCUXCLBUFFER_INIT(pBufOut, NULL, pOut, outLength);
        mcuxClRandom_Status_t result_customAlg =  (mcuxClRandom_Status_t)pSession->randomCfg.prngPatchFunction(
                    pSession->randomCfg.pCustomPrngState,
                    pBufOut,
                    outLength);

        MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, result_customAlg);
        MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandom_ncGenerate_Internal);
    }

    /* Assume normal mode going forward. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pOut, outLength));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandom_ncGenerate_Internal, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncGenerateWord_Internal)
uint32_t mcuxClRandom_ncGenerateWord_Internal(mcuxClSession_Handle_t pSession)
{
    if(NULL != pSession->randomCfg.prngPatchFunction)
    {
        uint32_t rngWord = 0x0u;
        MCUXCLBUFFER_INIT(pBufRandom, NULL, (uint8_t *) &rngWord, 4u);
        (void) pSession->randomCfg.prngPatchFunction(
                pSession->randomCfg.pCustomPrngState,
                pBufRandom,
                sizeof(uint32_t));
        return rngWord;
    }

    return (uint32_t)mcuxClPrng_generate_word();
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncGenerate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_ncGenerate(
    mcuxClSession_Handle_t pSession,
    mcuxCl_Buffer_t        pOut,
    uint32_t              outLength
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_ncGenerate, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);

    MCUX_CSSL_DI_RECORD(sumOfRandomNcGenerateParams, (uint32_t)pSession + (uint32_t)pOut + outLength);

    if(NULL != pSession->randomCfg.prngPatchFunction)
    {
        mcuxClRandom_Status_t result_customAlg = (mcuxClRandom_Status_t)pSession->randomCfg.prngPatchFunction(
                    pSession->randomCfg.pCustomPrngState,
                    pOut,
                    outLength);

        MCUX_CSSL_DI_EXPUNGE(sumOfRandomNcGenerateParams, (uint32_t)pSession + (uint32_t)pOut + outLength);

        MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, result_customAlg);
        MCUXCLSESSION_EXIT(pSession, mcuxClRandom_ncGenerate, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    /* Assume normal mode going forward. */

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate(pSession, pOut, outLength));

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomNcGenerateParams, (uint32_t)pSession + (uint32_t)pOut + outLength);

    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_ncGenerate, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate));
}
