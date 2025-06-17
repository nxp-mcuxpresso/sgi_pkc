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

#include <mcuxClToolchain.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClMemory.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClRandomModes_Functions_TestMode.h>

#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_TestMode.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClRandomModes_Private_ExitGates.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClRandom_OperationModeDescriptor_t mcuxClRandomModes_OperationModeDescriptor_TestMode_PrDisabled =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    .initFunction                    = mcuxClRandomModes_TestMode_initFunction,
    .reseedFunction                  = mcuxClRandomModes_TestMode_reseedFunction,
    .generateFunction                = mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
    .selftestFunction                = mcuxClRandomModes_TestMode_selftestFunction,
    .protectionTokenInitFunction     = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_TestMode_initFunction,
    .protectionTokenReseedFunction   = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_TestMode_reseedFunction,
    .protectionTokenGenerateFunction = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
    .protectionTokenSelftestFunction = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_TestMode_selftestFunction,
    .operationMode                   = MCUXCLRANDOMMODES_TESTMODE,
};



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_createTestFromNormalMode)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_createTestFromNormalMode(mcuxClRandom_ModeDescriptor_t *pTestMode, mcuxClRandom_Mode_t normalMode, const uint32_t * const pCustomSeed)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_createTestFromNormalMode);

    MCUX_CSSL_ANALYSIS_START_CAST_TO_MORE_SPECIFIC_TYPE() /*For a normal mode, auxParam contains a pointer to mcuxClRandom_OperationModeDescriptor_t */
    pTestMode->pOperationMode   = (mcuxClRandom_OperationModeDescriptor_t *) normalMode->auxParam;
    MCUX_CSSL_ANALYSIS_STOP_CAST_TO_MORE_SPECIFIC_TYPE()
    pTestMode->pDrbgMode        = normalMode->pDrbgMode;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded because TestMode needs to update the custom seed hold in auxParam.")
    pTestMode->auxParam         = (uint32_t *) pCustomSeed;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
    pTestMode->contextSize      = normalMode->contextSize;
    pTestMode->securityStrength = normalMode->securityStrength;

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(
      mcuxClRandomModes_createTestFromNormalMode,
      MCUXCLRANDOM_STATUS_OK,
      MCUXCLRANDOM_STATUS_FAULT_ATTACK
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_updateEntropyInput)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_updateEntropyInput(mcuxClRandom_ModeDescriptor_t *pTestMode, const uint32_t * const pCustomSeed)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_updateEntropyInput);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded because TestMode needs to update the custom seed hold in auxParam.")
    pTestMode->auxParam         = (uint32_t *) pCustomSeed;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandomModes_updateEntropyInput, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}


/**
 * \brief This function instantiates a DRBG in TEST_MODE following the lines of the function Instantiate_function specified in NIST SP800-90A
 *
 * This function instantiates a DRBG in TEST_MODE following the lines of the function Instantiate_function specified in NIST SP800-90A.
 * The function reads entropy input and nonce for the DRBG seed from a buffer provided by the user of the CL.
 *
 * \param  session[in]          Handle for the current CL session
 * \param  mode[in]             Handle for the current Random Mode
 * \param  context[in]          Handle for the current Random Context
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_TestMode_initFunction, mcuxClRandom_initFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_TestMode_initFunction(
                    mcuxClSession_Handle_t pSession,
                    mcuxClRandom_Mode_t mode,
                    mcuxClRandom_Context_t context
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_TestMode_initFunction);

    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_Generic(context);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    /* Initialize the reseedSeedOffset field of the context */
    pRngCtxGeneric->reseedSeedOffset = 0u;

    /* Request and init HW */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_requestHW));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_requestHW(pSession));


    /* Derive the initial DRBG state from the user-defined entropy input and nonce. Return value is not checked, but instead forwarded to API. */
    MCUX_CSSL_FP_EXPECT(pDrbgMode->pDrbgAlgorithms->protectionTokenInstantiateAlgorithm);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pDrbgMode->pDrbgAlgorithms->instantiateAlgorithm(
                pSession,
                mode,
                context,
                (uint8_t *) mode->auxParam));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_cleanupOnExit(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_TestMode_initFunction);
}


/**
 * \brief This function reseeds a DRBG in TEST_MODE following the lines of the function Reseed_function specified in NIST SP800-90A
 *
 * This function reseeds a DRBG in TEST_MODE following the lines of the function Reseed_function specified in NIST SP800-90A.
 * The function reads entropy input for the DRBG seed from a buffer provided by the user of the CL.
 *
 * \param  session[in]          Handle for the current CL session
 * \param  mode[in]             Handle for the current Random Mode
 * \param  context[in]          Handle for the current Random Context
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_TestMode_reseedFunction, mcuxClRandom_reseedFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_TestMode_reseedFunction(
                    mcuxClSession_Handle_t pSession,
                    mcuxClRandom_Mode_t mode,
                    mcuxClRandom_Context_t context
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_TestMode_reseedFunction);

    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_Generic(context);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    /* Request and init HW */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_requestHW));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_requestHW(pSession));


    /* Derive the initial DRBG state from the user-defined entropy input. Return value is not checked, but instead forwarded to API. */
    MCUX_CSSL_FP_EXPECT(pDrbgMode->pDrbgAlgorithms->protectionTokenReseedAlgorithm);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pDrbgMode->pDrbgAlgorithms->reseedAlgorithm(
                pSession,
                mode,
                context,
                (((uint8_t *) mode->auxParam) + pRngCtxGeneric->reseedSeedOffset)));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_cleanupOnExit(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_TestMode_reseedFunction);

}

/**
 * \brief Empty function called during mcuxClRandom_selftest when TEST_MODE is activated
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_TestMode_selftestFunction, mcuxClRandom_selftestFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_TestMode_selftestFunction(mcuxClSession_Handle_t pSession UNUSED_PARAM, mcuxClRandom_Mode_t mode UNUSED_PARAM)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_TestMode_selftestFunction);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_TestMode_selftestFunction);
}
