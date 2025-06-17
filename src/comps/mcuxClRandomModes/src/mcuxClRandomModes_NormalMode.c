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
#include <mcuxClSession_Types.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClRandomModes_MemoryConsumption.h>
#include <mcuxClRandomModes_Functions_TestMode.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClTrng_Internal.h>
#include <internal/mcuxClRandomModes_Private_ExitGates.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClRandom_OperationModeDescriptor_t mcuxClRandomModes_OperationModeDescriptor_NormalMode_PrDisabled = {
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    .initFunction                    = mcuxClRandomModes_NormalMode_initFunction,
    .reseedFunction                  = mcuxClRandomModes_NormalMode_reseedFunction,
    .generateFunction                = mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
    .selftestFunction                = mcuxClRandomModes_NormalMode_selftestFunction,
    .protectionTokenInitFunction     = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_initFunction,
    .protectionTokenReseedFunction   = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_reseedFunction,
    .protectionTokenGenerateFunction = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
    .protectionTokenSelftestFunction = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_selftestFunction,
    .operationMode                   = MCUXCLRANDOMMODES_NORMALMODE,
};


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_castToRandomModeDescriptor)
static mcuxClRandom_ModeDescriptor_t* mcuxClRandomModes_castToRandomModeDescriptor(uint32_t* context)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClRandom_ModeDescriptor_t *) context;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_castToRandomContext)
static mcuxClRandom_Context_t mcuxClRandomModes_castToRandomContext(uint32_t* context)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClRandom_Context_t) context;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

/**
 * \brief This function instantiates a DRBG in NORMAL_MODE following the lines of the function Instantiate_function specified in NIST SP800-90A
 *
 * This function instantiates a DRBG in NORMAL_MODE following the lines of the function Instantiate_function specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]          Handle for the current CL session
 * \param  mode[in]              Handle for the current Random Mode
 * \param  context[in]           Handle for the current Random Context
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_initFunction, mcuxClRandom_initFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_NormalMode_initFunction(
                    mcuxClSession_Handle_t pSession,
                    mcuxClRandom_Mode_t mode,
                    mcuxClRandom_Context_t context
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_initFunction);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    /* Record entropyInputLength for mcuxClTrng_getEntropyInput() */
    MCUX_CSSL_DI_RECORD(trngOutputSize, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->initSeedSize));

    /* Request and init HW */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_requestHW));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_requestHW(pSession));

    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_Generic(context);

    /* Initialize buffer in CPU workarea for the entropy input and nonce to derive the DRBG seed */
    uint32_t *pEntropyInputAndNonce = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pDrbgMode->pDrbgVariant->initSeedSize));
    /* TODO CLNS-17418 error handling */

    /* Call TRNG initialization function to ensure it's properly configured for upcoming TRNG accesses */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_Init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClTrng_Init(pSession));

    /* Generate entropy input using the TRNG */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_getEntropyInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClTrng_getEntropyInput(pSession, pEntropyInputAndNonce, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->initSeedSize))
      );

    /* Initialize the reseedSeedOffset field of the context */
    pRngCtxGeneric->reseedSeedOffset = 0u;

    /* Derive the initial DRBG state from the generated entropy input and nonce. Return value is not checked, but instead forwarded to API. */
    MCUX_CSSL_FP_EXPECT(pDrbgMode->pDrbgAlgorithms->protectionTokenInstantiateAlgorithm);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pDrbgMode->pDrbgAlgorithms->instantiateAlgorithm(
                pSession,
                mode,
                context,
                (uint8_t *) pEntropyInputAndNonce));

    /* Free workarea (pEntropyInputAndNonce) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pDrbgMode->pDrbgVariant->initSeedSize));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_cleanupOnExit(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_NormalMode_initFunction);
}


/**
 * \brief This function reseeds a DRBG in NORMAL_MODE following the lines of the function Reseed_function specified in NIST SP800-90A
 *
 * This function reseed a DRBG in NORMAL_MODE following the lines of the function Reseed_function specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]          Handle for the current CL session
 * \param  mode[in]              Handle for the current Random Mode
 * \param  context[in]           Handle for the current Random Context
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the DRBG reseeding finished successfully
 *   - MCUXCLRANDOM_STATUS_ERROR           if a memory allocation error or non-critical TRNG error occured
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the DRBG reseeding failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_reseedFunction, mcuxClRandom_reseedFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_NormalMode_reseedFunction(
                    mcuxClSession_Handle_t pSession,
                    mcuxClRandom_Mode_t mode,
                    mcuxClRandom_Context_t context
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_reseedFunction);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    /* Record entropyInputLength for mcuxClTrng_getEntropyInput() */
    MCUX_CSSL_DI_RECORD(trngOutputSize, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->reseedSeedSize));

    /* Request and init HW */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_requestHW));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_requestHW(pSession));

    /* Initialize buffer in CPU workarea for the entropy input to derive the DRBG seed */
    uint32_t *pEntropyInput = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pDrbgMode->pDrbgVariant->reseedSeedSize));
    /* TODO: CLNS-17418 error handling */

    /* Generate entropy input using the TRNG */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_getEntropyInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClTrng_getEntropyInput(pSession, pEntropyInput, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->reseedSeedSize))
        );

    /* Derive the initial DRBG state from the generated entropy input. Return value is not checked, but instead forwarded to API. */
    MCUX_CSSL_FP_EXPECT(pDrbgMode->pDrbgAlgorithms->protectionTokenReseedAlgorithm);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pDrbgMode->pDrbgAlgorithms->reseedAlgorithm(
                pSession,
                mode,
                context,
                (uint8_t *) pEntropyInput));

    /* Free workarea (pEntropyInputAndNonce) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pDrbgMode->pDrbgVariant->reseedSeedSize));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_cleanupOnExit(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_NormalMode_reseedFunction);
}


/**
 * \brief This function generates random numbers from a DRBG in NORMAL_MODE following the lines of the function Generate_function specified in NIST SP800-90A
 * and reseeds according to the DRG.3 security level.
 *
 * This function generates random numbers from a DRBG in NORMAL_MODE following the lines of the function Generate_function specified in NIST SP800-90A.
 * If reseedCounter overflowed, the DRBG will be reseeded before the randomness generation.
 * If so, the function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]         Handle for the current CL session
 * \param  mode[in]             Handle for the current Random Mode
 * \param  context[in]          Handle for the current Random Context
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength[in]        Number of requested random bytes
 * \param  pXorMask[in]         Pointer to Boolean masking used for masking DRBG output (in CtrDrbg mode only)
 *
 * \return void
 *
 * Data Integrity: Expunge(pSession + pOut + outLength + pXorMask)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled, mcuxClRandom_generateFunction_t)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_NormalMode_generateFunction_PrDisabled(
                    mcuxClSession_Handle_t pSession,
                    mcuxClRandom_Mode_t mode,
                    mcuxClRandom_Context_t context,
                    mcuxCl_Buffer_t pOut,
                    uint32_t outLength,
                    const uint32_t *pXorMask
)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled);

    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_Generic(context);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    // MCUX_CSSL_FP_COUNTER_STMT(uint64_t initialReseedCounterFP = pRngCtxGeneric->reseedCounter);

    /* Bring the DI out of balance, to be balanced by caller. This is done before any potential exit. */
    MCUX_CSSL_DI_EXPUNGE(sumOfRandomGenerateParams, pSession);
    MCUX_CSSL_DI_EXPUNGE(sumOfRandomGenerateParams, pOut);
    MCUX_CSSL_DI_EXPUNGE(sumOfRandomGenerateParams, outLength);
    MCUX_CSSL_DI_EXPUNGE(sumOfRandomGenerateParams, pXorMask);

    /* NIST SP800-90A requests outLength to be limited by 2^19 bits, i.e. 2^16 Bytes. */
    if(MCUXCLRANDOMMODES_DRBG_OUTPUT_MAX < outLength)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLRANDOM_STATUS_INVALID_PARAM);
    }

    /* Reseed the DRBG state if the reseed counter overflowed */
    if (pRngCtxGeneric->reseedCounter >= pDrbgMode->pDrbgVariant->reseedInterval)
    {
        MCUX_CSSL_FP_EXPECT(mode->pOperationMode->protectionTokenReseedFunction);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->pOperationMode->reseedFunction(pSession, mode, context));

        /* Record reseed call */
        MCUX_CSSL_DI_RECORD(reseedCondition, 1u);
    }

    /* Request and init HW */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_requestHW));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_requestHW(pSession));


    /* Generate random bytes. Return value is not checked, but instead forwarded to API. */
    MCUX_CSSL_FP_EXPECT(pDrbgMode->pDrbgAlgorithms->protectionTokenGenerateAlgorithm);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pDrbgMode->pDrbgAlgorithms->generateAlgorithm(
                pSession,
                mode,
                context,
                pOut,
                outLength,
                pXorMask));


    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_cleanupOnExit(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled);
}



/**
 * \brief This function performs a selftest of a DRBG in NORMAL_MODE
 *
 * The specific test pattern depends on the drbgMode.
 *
 * @param  pSession[in]    Handle for the current CL session
 * @param  mode[in]        Mode of operation for random data generator.
 *
 * \return void
 *   - MCUXCLRANDOM_STATUS_OK              if the selftest executed finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the selftest failed
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_selftestFunction, mcuxClRandom_selftestFunction_t)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_NormalMode_selftestFunction(mcuxClSession_Handle_t pSession, mcuxClRandom_Mode_t mode)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_selftestFunction);
    /* Back up Random configuration of current session */
    mcuxClRandom_Mode_t modeBackup = pSession->randomCfg.mode;
    mcuxClRandom_Context_t ctxBackup = pSession->randomCfg.ctx;

    /* Allocate space for new testMode */
    mcuxClRandom_ModeDescriptor_t *pTestModeDesc = mcuxClRandomModes_castToRandomModeDescriptor(mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLRANDOMMODES_TESTMODE_DESCRIPTOR_SIZE)));
    /* TODO: CLNS-17418 error handling */

    /* Derive testMode from passed mode */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createTestFromNormalMode));
    MCUX_CSSL_FP_FUNCTION_CALL(result_create, mcuxClRandomModes_createTestFromNormalMode(pTestModeDesc, mode, NULL));
    if(result_create != MCUXCLRANDOM_STATUS_OK)
    {
        MCUXCLSESSION_FAULT(pSession, result_create);
    }

    /* Allocate space for pTestCtx according to the contextSize */
    mcuxClRandom_Context_t pTestCtx = mcuxClRandomModes_castToRandomContext(mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pTestModeDesc->contextSize)));
    /* TODO: CLNS-17418 error handling */

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    /* Call function executing the DRBG mode specific selftest algorithm */
    MCUX_CSSL_FP_EXPECT(pDrbgMode->pDrbgAlgorithms->protectionTokenSelftestAlgorithm);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pDrbgMode->pDrbgAlgorithms->selftestAlgorithm(pSession, pTestCtx, pTestModeDesc));

    /* Restore Random configuration of session */
    pSession->randomCfg.mode = modeBackup;
    pSession->randomCfg.ctx = ctxBackup;

    /* Free workarea (pTestModeDesc and pTestCtx) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLRANDOMMODES_TESTMODE_DESCRIPTOR_SIZE) + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pTestModeDesc->contextSize));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_NormalMode_selftestFunction);
}


/**
 * @brief This function performs a comparison of two arrays
 *
 * @param  wordLength[in]   Length of arrays to compare in word size
 * @param  expected[in]     Input buffer with expected value
 * @param  actual[in]       Input buffer with actual value, to be compared with expected value
 *
 * @return void
 *
 * @note Function uses an early-exit mechanism with following return codes:
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the arrays are not equal
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_selftest_VerifyArrays)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_selftest_VerifyArrays(mcuxClSession_Handle_t pSession, uint32_t wordLength, const uint32_t * const expected, uint32_t *actual)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_selftest_VerifyArrays);

    for (uint32_t i = 0u; i < wordLength; i++)
    {
        if (expected[i] != actual[i])
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_selftest_VerifyArrays);
}
