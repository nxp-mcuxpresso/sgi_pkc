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

/** @file  mcuxClRandom_DRBG.c
 *  @brief Implementation of the Random component which provides APIs for
 *  handling of DRBG random number generators. This file implements the functions
 *  declared in mcuxClRandom.h. */

#include <mcuxClToolchain.h>

#include <mcuxClBuffer.h>
#include <mcuxClRandom.h>
#include <mcuxClSession.h>
#include <mcuxCsslDataIntegrity.h>

#include <internal/mcuxClCrc_Internal_Functions.h>
#include <internal/mcuxClMemory_ClearSecure_Internal.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>


/**
 * @brief This function verifies a Random mode
 *
 * @param  mode[in]       Random mode to be verified
 * @param  pSession[in]   Session handle
 *
 * @return void
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - #MCUXCLRANDOM_STATUS_FAULT_ATTACK  if the Random mode is uninitialized
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_verifyMode)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandom_verifyMode(mcuxClSession_Handle_t pSession, mcuxClRandom_Mode_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_verifyMode);

    // TODO CLNS-7923: Need to be discussed whether INVALID_PARAM or FAULT_ATTACK should be returned
    if(mode == NULL)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandom_verifyMode);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_generate_internal)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandom_generate_internal(
    mcuxClSession_Handle_t pSession,
    mcuxCl_Buffer_t        pOut,
    uint32_t              outLength,
    const uint32_t        *pXorMask
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_generate_internal);

    mcuxClRandom_Context_t pRngCtx = pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t sessionMode = pSession->randomCfg.mode;

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(pSession, pRngCtx, sessionMode->contextSize));

    /* Call generate function from randommodes */
    MCUX_CSSL_FP_EXPECT(sessionMode->pOperationMode->protectionTokenGenerateFunction);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(sessionMode->pOperationMode->generateFunction(pSession, sessionMode, pRngCtx, pOut, outLength, pXorMask));

    /* Update the context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pRngCtx, sessionMode->contextSize));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandom_generate_internal);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_init(
    mcuxClSession_Handle_t pSession,
    mcuxClRandom_Context_t pContext,
    mcuxClRandom_Mode_t    mode
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_init, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    MCUX_CSSL_DI_RECORD(randomInitParamPsession, (uint32_t)pSession);
    MCUX_CSSL_DI_RECORD(randomInitParamPctx, (uint32_t)pContext);
    MCUX_CSSL_DI_RECORD(randomInitParamMode, (uint32_t)mode);

    /* Verify passed mode parameter */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_verifyMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_verifyMode(pSession, mode));

    /* Store context in session. */
    pSession->randomCfg.ctx = pContext;

    /* Store mode in session. */
    pSession->randomCfg.mode = mode;

    /* Call internal init function */
    MCUX_CSSL_FP_EXPECT(mode->pOperationMode->protectionTokenInitFunction);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->pOperationMode->initFunction(pSession, mode, pContext));

    /* Initialize the context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, mode->contextSize));

    MCUX_CSSL_DI_EXPUNGE(randomInitParamPsession, (uint32_t)pSession);
    MCUX_CSSL_DI_EXPUNGE(randomInitParamPctx, (uint32_t)pContext);
    MCUX_CSSL_DI_EXPUNGE(randomInitParamMode, (uint32_t)mode);
    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_init, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_reseed)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_reseed(
    mcuxClSession_Handle_t pSession
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_reseed, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    MCUX_CSSL_DI_RECORD(sumOfRandomReseedParams,  (uint32_t)pSession);

    /* Verify context integrity */
    mcuxClRandom_Context_t pRngCtx = pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t sessionMode = pSession->randomCfg.mode;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(pSession, pRngCtx, sessionMode->contextSize));

    /* Call internal reseed function */
    MCUX_CSSL_FP_EXPECT(sessionMode->pOperationMode->protectionTokenReseedFunction);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(sessionMode->pOperationMode->reseedFunction(pSession, sessionMode, pRngCtx));

    /* Update the context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pRngCtx, sessionMode->contextSize));

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomReseedParams, (uint32_t)pSession);
    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_reseed, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_generate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_generate(
    mcuxClSession_Handle_t pSession,
    mcuxCl_Buffer_t        pOut,
    uint32_t              outLength
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_generate, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, (uint32_t)pSession + (uint32_t)pOut + outLength);

    /* Call internal generate function */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate_internal));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_generate_internal(pSession, pOut, outLength, NULL));

    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_generate, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_uninit)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_uninit(
  mcuxClSession_Handle_t pSession
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_uninit, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    MCUX_CSSL_DI_RECORD(sumOfRandomUninitParams, (uint32_t)pSession);

    /* Verify context integrity */
    mcuxClRandom_Mode_t sessionMode = pSession->randomCfg.mode;
    mcuxClRandom_Context_t pRngCtx = pSession->randomCfg.ctx;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(pSession, pRngCtx, sessionMode->contextSize));

    /* Clear the context. ContextSize will never be 0. An error here is considered a fault attack, so no DI or FP balancing is needed. */
    MCUX_CSSL_DI_RECORD(clearSecureDI, (uint32_t)pSession->randomCfg.ctx + sessionMode->contextSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_secure_int((uint8_t *) pSession->randomCfg.ctx, sessionMode->contextSize));

    /* Clear pointers stored in the session. */
    pSession->randomCfg.ctx = NULL;
    pSession->randomCfg.mode = NULL;

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomUninitParams, (uint32_t)pSession);
    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_uninit, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_selftest)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_selftest(
    mcuxClSession_Handle_t pSession,
    mcuxClRandom_Mode_t    mode
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_selftest, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    MCUX_CSSL_DI_RECORD(sumOfRandomSelftestParams, (uint32_t)pSession + (uint32_t)mode);

    /* Verify passed mode parameter */
    (void) mcuxClRandom_verifyMode(pSession, mode);

    /* Call internal selftest function. */
    MCUX_CSSL_FP_EXPECT(mode->pOperationMode->protectionTokenSelftestFunction);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->pOperationMode->selftestFunction(pSession, mode));

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomSelftestParams, (uint32_t)pSession + (uint32_t)mode);
    MCUXCLSESSION_EXIT(pSession, mcuxClRandom_selftest, diRefValue, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_checkSecurityStrength)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_checkSecurityStrength(
    mcuxClSession_Handle_t pSession,
    uint32_t              securityStrength
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClRandom_checkSecurityStrength, diRefValue, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    MCUX_CSSL_DI_RECORD(sumOfRandomCheckSecurityStrengthParams, (uint32_t)pSession + (uint32_t)securityStrength);

    mcuxClRandom_Mode_t sessionMode = pSession->randomCfg.mode;

    MCUX_CSSL_DI_EXPUNGE(sumOfRandomCheckSecurityStrengthParams, (uint32_t)pSession + (uint32_t)securityStrength);

    if(securityStrength > sessionMode->securityStrength)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLRANDOM_STATUS_LOW_SECURITY_STRENGTH);
    }

    MCUXCLSESSION_EXIT(pSession,
                      mcuxClRandom_checkSecurityStrength,
                      diRefValue,
                      MCUXCLRANDOM_STATUS_OK,
                      MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}
