/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023, 2025 NXP                                            */
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
#include <mcuxCsslAnalysis.h>

#include <mcuxClRandomModes_Functions_TestMode.h>

#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#include <internal/mcuxClRandomModes_Private_PrDisabled.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClRandomModes_Private_ExitGates.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_URL_IN_COMMENTS()
/**
 * \brief This function performs a selftest of a DRBG if prediction resistance is disabled
 *
 * This function performs a selftest of a DRBG if prediction resistance is disabled. More precisely, it implements a CAVP like known answer test as specified in
 *
 *   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf
 *
 * i.e. known answer tests for the following flow are executed
 *
 *    (initialize entropy input)
 *    init
 *    (update entropy input)
 *    reseed
 *    generate
 *    generate
 *    uninit
 *
 * @param [in]     pSession   Handle for the current CL session.
 * @param [in]     testCtx    Pointer to a Random data context buffer large enough
 *                            to hold the context for the selected @p pTestMode
 * @param [in]     pTestMode   Mode of operation for random data generator.
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - MCUXCLRANDOM_STATUS_FAULT_ATTACK when one of internal operations failed
 */
MCUX_CSSL_ANALYSIS_STOP_PATTERN_URL_IN_COMMENTS()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_PrDisabled_selftestAlgorithm, mcuxClRandomModes_selftestAlgorithm_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_PrDisabled_selftestAlgorithm(mcuxClSession_Handle_t pSession, mcuxClRandom_Context_t pTestCtx, mcuxClRandom_ModeDescriptor_t *pTestMode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_PrDisabled_selftestAlgorithm);

    /* Set entropy input pointer in pTestMode */
    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(pTestMode->pDrbgMode);

    const uint32_t *const * testVectors = pDrbgMode->pDrbgTestVectors;
    MCUX_CSSL_FP_FUNCTION_CALL(ret_updateIn, mcuxClRandomModes_updateEntropyInput(pTestMode,
                testVectors[MCUXCLRANDOMMODES_TESTVECTORS_INDEX_ENTROPY_PRDISABLED]));
    if(MCUXCLRANDOM_STATUS_OK != ret_updateIn)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /***********************************************
    * Initialize DRBG with known entropy using     *
    * mcuxClRandom_init function                    *
    ************************************************/

    /* Call Random_init */
    MCUX_CSSL_FP_FUNCTION_CALL(resultInit, mcuxClRandom_init(pSession, (mcuxClRandom_Context_t)pTestCtx, pTestMode));
    if(MCUXCLRANDOM_STATUS_OK != resultInit)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /***********************************************
    * Reseed with known entropy using              *
    * mcuxClRandom_reseed function                  *
    ************************************************/

    /* Input new entropy to be used for reseeding by updating pTestMode */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_updateIn2, mcuxClRandomModes_updateEntropyInput(pTestMode,
                testVectors[MCUXCLRANDOMMODES_TESTVECTORS_INDEX_ENTROPY_RESEED_PRDISABLED]));
    if(MCUXCLRANDOM_STATUS_OK != ret_updateIn2)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(ret_reseed, mcuxClRandom_reseed(pSession));
    /* Call Random_reseed */
    if(MCUXCLRANDOM_STATUS_OK != ret_reseed)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /***********************************************
     * Generate first value using                  *
     * mcuxClRandom_generate function               *
     ***********************************************/

    uint32_t randomBytes[MCUXCLRANDOMMODES_SELFTEST_RANDOMDATALENGTH/sizeof(uint32_t)];
    MCUXCLBUFFER_INIT(pBufRandomBytes, NULL, (uint8_t*)randomBytes, MCUXCLRANDOMMODES_SELFTEST_RANDOMDATALENGTH);
    MCUX_CSSL_ANALYSIS_START_PATTERN_ADDRESS_IN_SFR_IS_NOT_REUSED_OUTSIDE()
    MCUX_CSSL_FP_FUNCTION_CALL(ret_generate,
            mcuxClRandom_generate(pSession, pBufRandomBytes, MCUXCLRANDOMMODES_SELFTEST_RANDOMDATALENGTH));
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_ADDRESS_IN_SFR_IS_NOT_REUSED_OUTSIDE()
    if(MCUXCLRANDOM_STATUS_OK != ret_generate)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /***********************************************
     * Generate second value using                 *
     * mcuxClRandom_generate function               *
     ***********************************************/
    MCUX_CSSL_ANALYSIS_START_PATTERN_ADDRESS_IN_SFR_IS_NOT_REUSED_OUTSIDE()
    MCUX_CSSL_FP_FUNCTION_CALL(ret_generate2,
            mcuxClRandom_generate(pSession, pBufRandomBytes, MCUXCLRANDOMMODES_SELFTEST_RANDOMDATALENGTH));
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_ADDRESS_IN_SFR_IS_NOT_REUSED_OUTSIDE()
    if(MCUXCLRANDOM_STATUS_OK != ret_generate2)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Verify generated random bytes */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_OBJECT_READ_BEFORE_SET("was set in mcuxClRandom_generate")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_selftest_VerifyArrays(pSession, MCUXCLRANDOMMODES_SELFTEST_RANDOMDATALENGTH/(sizeof(uint32_t)),
                                                                  testVectors[MCUXCLRANDOMMODES_TESTVECTORS_INDEX_RANDOMDATA_PRDISABLED],
                                                                  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("randomBytes is initialized in MCUXCLBUFFER_INIT")
                                                                  randomBytes));
                                                                  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OBJECT_READ_BEFORE_SET()
    /***********************************************
     * Clean up using mcuxClRandom_uninit function  *
     ***********************************************/

    uint32_t contextSizeInWords = pTestMode->contextSize / sizeof(uint32_t);
    MCUX_CSSL_FP_FUNCTION_CALL(ret_uninit, mcuxClRandom_uninit(pSession));
    if(MCUXCLRANDOM_STATUS_OK != ret_uninit)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Verify whether context is clear */
    MCUX_CSSL_FP_LOOP_DECL(forLoopVerifyCtx);
    for (uint32_t i = 0u; i < contextSizeInWords; i++)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY("pTestCtx contains an integer array of size contextSizeInWords")
        if(((uint32_t *) pTestCtx)[i] != 0u)
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY()
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }
        MCUX_CSSL_FP_LOOP_ITERATION(forLoopVerifyCtx);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_PrDisabled_selftestAlgorithm,
        /* Set entropy input pointer in pTestMode */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_updateEntropyInput),
        /* Initialize DRBG with known entropy */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init),
        /* Reseed with known entropy using */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_updateEntropyInput),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_reseed),
        /* Generate first value */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate),
        /* Generate second value */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_selftest_VerifyArrays),
        /* Clean up */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_uninit),
        /* Verify that context is clear in for-loop */
        MCUX_CSSL_FP_LOOP_ITERATIONS(forLoopVerifyCtx, contextSizeInWords));
}
