/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @example mcuxClRandomModes_TestMode_CtrDrbg_AES256_DRG4_example.c
 * @brief   Example for the mcuxClRandomModes component
 */

#include <mcuxClToolchain.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClCore_Macros.h>

/* CAVP test vectors */
static const uint32_t entropyAndNonceInputInit[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLRANDOMMODES_TESTMODE_CTR_DRBG_AES256_INIT_ENTROPY_SIZE)] =
{
    0xC895B09Fu, 0xDC8A7855u, 0x30D29197u, 0xFFB78DEBu, 0xE05FBED6u, 0xFA18E8BCu, 0x08181916u, 0x22BC51E4u,
    0xC88B1DF5u, 0x15343BC6u, 0xD132B62Fu, 0xBC64248Bu, 0xDBFCEBBEu, 0x3CBA96E9u, 0x54FEC285u, 0x51008B28u
};

static const uint32_t entropyInputReseed[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLRANDOMMODES_TESTMODE_CTR_DRBG_AES256_RESEED_ENTROPY_SIZE)] =
{
    0x875CBF2Bu, 0xB691D99Eu, 0x3CB29A98u, 0x46F88260u, 0xCE3BAFD4u, 0x9A39EE02u, 0x06B14989u, 0xF16F46B6u,
    0x25DC5BB4u, 0x1B8434F4u, 0x2B30D48Bu, 0xADB5F889u
};

static const uint32_t refOutput[64u / sizeof(uint32_t)] =
{
    0x75321468u, 0x42B48F90u, 0x166757D0u, 0x8C9BE44Eu, 0x667A3AF8u, 0x3CC0CF82u, 0x1AA1EEFEu, 0xFF968FB5u,
    0x9F8DA237u, 0x218C18B9u, 0x87A0EB74u, 0xF08F03B1u, 0xB91F5360u, 0x2903E42Bu, 0xC332CCEFu, 0x9BEF0FA2u
};

/** Performs an example usage of the mcuxClRandom and mcuxClRandomModes components with test mode.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClRandomModes_TestMode_CtrDrbg_AES256_DRG4_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRANDOMMODES_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Allocate space for a test mode descriptor for an AES-256 CTR_DRBG DRG4. */
    uint32_t testModeDescBytes[(MCUXCLRANDOMMODES_TESTMODE_DESCRIPTOR_SIZE + sizeof(uint32_t) - 1U)/sizeof(uint32_t)];
    mcuxClRandom_ModeDescriptor_t *pTestModeDesc = (mcuxClRandom_ModeDescriptor_t *) testModeDescBytes;

    /**************************************************************************/
    /* Test mode creation for an AES-256 CTR_DRBG DRG4 and preparation of     */
    /* known entropy and nonce input for later DRBG instantiation             */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cp_status, cp_token, mcuxClRandomModes_createTestFromNormalMode(
                                        pTestModeDesc,
                                        mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG4,
                                        entropyAndNonceInputInit
                                   ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createTestFromNormalMode) != cp_token) || (MCUXCLRANDOM_STATUS_OK != cp_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Test mode initialization with known entropy and nonce input            */
    /**************************************************************************/
    uint32_t context[MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE_IN_WORDS] = {0};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ri_status, init_token, mcuxClRandom_init(
                                        session,
                                        (mcuxClRandom_Context_t)context,
                                        pTestModeDesc
                                   ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != init_token) || (MCUXCLRANDOM_STATUS_OK != ri_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Reseed the DRBG with a known entropy, and generate two random bytes    */
    /* strings                                                                */
    /**************************************************************************/
    /* Buffers to store the generated random values in. */
    ALIGNED uint8_t drbg_data1[64u] = {0u};
    MCUXCLBUFFER_INIT(drbgBuf1, NULL, &drbg_data1[0], 64u);
    ALIGNED uint8_t drbg_data2[64u] = {0u};
    MCUXCLBUFFER_INIT(drbgBuf2, NULL, &drbg_data2[0], 64u);

    /* Update entropy input to be taken for the upcoming reseeding */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ue_status, ue_token, mcuxClRandomModes_updateEntropyInput(pTestModeDesc, entropyInputReseed));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_updateEntropyInput) != ue_token) || (MCUXCLRANDOM_STATUS_OK != ue_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Reseed the DRBG with known entropy input */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rr_status, reseed_token, mcuxClRandom_reseed(session));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_reseed) != reseed_token) || (MCUXCLRANDOM_STATUS_OK != rr_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of 512 bits */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rg1_status, generate1_token, mcuxClRandom_generate(
                                        session,
                                        drbgBuf1,
                                        sizeof(drbg_data1)));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != generate1_token) || (MCUXCLRANDOM_STATUS_OK != rg1_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of 512 bits */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rg2_status, generate2_token, mcuxClRandom_generate(
                                        session,
                                        drbgBuf2,
                                        sizeof(drbg_data2)));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != generate2_token) || (MCUXCLRANDOM_STATUS_OK != rg2_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Compare the last generated random output to the expected output        */
    /**************************************************************************/

    bool outputIsExpected = mcuxClCore_assertEqual((const uint8_t*)drbg_data2, (const uint8_t*)refOutput, sizeof(drbg_data2));

    /* Return error if buffers are unequal */
    if(!outputIsExpected)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Random uninit. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ru_status, uninit_token, mcuxClRandom_uninit(session));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_uninit) != uninit_token) || (MCUXCLRANDOM_STATUS_OK != ru_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
