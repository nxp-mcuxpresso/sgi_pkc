/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 * @example mcuxClKdfModes_SP800_56C_twostep_hmac_example.c
 * @brief Example for the mcuxClKey component, showing a KDF according to the
 *        NIST SP800-56C Standard in TwoStep mode Using Hmac-Sha256
 */

#include <mcuxClKey.h>
#include <mcuxClKdfModes.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClHmac.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClSession.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClAes.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/* HMAC-SHA256 with default salt (all zeros sha256 block size) */
static const uint8_t sharedSecret[3] = {
    0x61u, 0x62u, 0x63u
};

static const uint8_t label[2] = {
    0x61u, 0x62u
};

static const uint8_t context[2] = {
    0x63u, 0x64u
};

static const uint8_t expectedDerivedKey[] = {
    0x19u, 0x51u, 0xbcu, 0x7cu, 0x86u, 0x9au, 0x46u, 0xd4u, 0x53u, 0x8au, 0x92u, 0x55u, 0x77u, 0x24u, 0x31u, 0x74u,
    0x5du, 0x65u, 0x6fu, 0x20u, 0x03u, 0x22u, 0x7fu, 0x07u, 0x6fu, 0x5eu, 0xe5u, 0x43u, 0xb9u, 0x2eu, 0xa3u, 0xfdu,
    0xa2u, 0xcdu, 0xe6u, 0x38u, 0x23u, 0x24u, 0x8bu, 0xd0u, 0xe6u, 0x37u, 0x58u, 0x66u, 0x18u, 0x61u, 0xd9u, 0x82u,
    0x51u, 0xa4u, 0x96u, 0x8eu, 0xfbu, 0xe1u, 0xf3u, 0x31u, 0x48u, 0x7du, 0x04u, 0xdeu, 0x91u, 0x85u, 0x69u, 0xe0u,
    0xbcu, 0xcfu, 0xc2u, 0x0eu, 0x45u, 0xd9u, 0xfdu, 0xc7u, 0x86u, 0xc0u, 0xe0u, 0x9bu, 0x94u, 0x45u, 0x39u, 0xdfu,
    0xc5u, 0x51u, 0x13u, 0x20u, 0xe1u, 0xbbu, 0x5eu, 0x0du, 0x99u, 0xccu, 0x5du, 0xe5u, 0xa9u, 0x30u, 0x44u, 0x85u,
    0xa8u, 0xfcu, 0xfcu, 0xeau, 0xdcu, 0xb5u, 0xe4u, 0x94u, 0xe1u, 0x0bu, 0x5bu, 0xaau, 0x78u, 0xd3u, 0x10u, 0x2cu,
    0x9eu, 0x9eu, 0xd5u, 0x96u, 0xf7u, 0xc8u, 0xe5u, 0x23u, 0xd1u, 0x4bu, 0x77u, 0xb3u, 0x78u, 0x85u, 0xd8u, 0xd7u,
    0xa1u, 0xbcu, 0xd4u, 0x9eu, 0x94u, 0x8bu, 0xe6u, 0x00u, 0xf7u, 0x8fu, 0x4fu, 0xbeu, 0xe3u, 0x82u, 0x4au, 0xc5u,
    0x18u, 0xa6u, 0xe9u, 0x68u, 0xddu, 0x00u, 0x30u, 0x80u, 0x61u, 0x30u, 0x4eu, 0xb7u, 0x8cu, 0x33u, 0x5fu, 0xd4u,
    0xdbu, 0xbeu, 0xadu, 0xdbu, 0x19u, 0x48u, 0x5eu, 0xc3u, 0x28u, 0x33u, 0x11u, 0xd1u, 0x15u, 0x8fu, 0x76u, 0x56u,
    0x65u, 0x03u, 0x5eu, 0x2du, 0x93u, 0x5au, 0xcbu, 0x32u, 0x4cu, 0xa9u, 0x7bu, 0xebu, 0x67u, 0x46u, 0x07u, 0x95u,
    0x19u, 0x75u, 0x4au, 0x8cu, 0x89u, 0xfau, 0x7cu, 0x26u, 0x1bu, 0xfcu, 0x10u, 0x80u, 0x74u, 0x7fu, 0xd0u, 0x10u,
    0x3cu, 0x3du, 0xdbu, 0xefu, 0xe9u, 0x63u, 0x56u, 0x42u, 0xd2u, 0xebu, 0x24u, 0x46u, 0x02u, 0xc8u, 0xf0u, 0x3du,
    0x8au, 0xbcu, 0x50u, 0x3eu, 0xdau, 0x77u, 0x2fu, 0xeau, 0x63u, 0xf1u, 0xd7u, 0x99u, 0xaeu, 0x98u, 0xa3u, 0xa0u,
    0xefu, 0x78u, 0x5eu, 0x49u, 0x1fu, 0xf0u, 0x52u, 0x4du, 0xc2u, 0x25u, 0x56u, 0xf8u, 0xb6u, 0xceu, 0x70
};



/** Performs an example key derivation using the mcuxClKey component.
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClKdfModes_SP800_56C_twostep_hmac_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_DERIVATION_NIST_SP800_56C_CPU_WA_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/
    /* Create and initialize key descriptor structure. */
    uint32_t sharedSecretDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t sharedSecretHandle = (mcuxClKey_Handle_t) &sharedSecretDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit1, tokenKeyInit1, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ sharedSecretHandle,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Hmac_variableLength,
      /* uint8_t * pKeyData                    */ (uint8_t *) sharedSecret,
      /* uint32_t keyDataLength                */ sizeof(sharedSecret)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit1) || (MCUXCLKEY_STATUS_OK != resultKeyInit1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set up input parameter structures. */
    uint8_t* pSalt = NULL;
    MCUXCLBUFFER_INIT_RO(labelBuf, session, label, sizeof(label));
    MCUXCLBUFFER_INIT_RO(contextBuf, session, context, sizeof(context));
    MCUXCLBUFFER_INIT_RO(pSaltBuf, session, pSalt, 0u);
    struct mcuxClKey_DerivationInput inputLabel = {.input=labelBuf, .size=sizeof(label)};
    struct mcuxClKey_DerivationInput inputContext = {.input=contextBuf, .size=sizeof(context)};
    struct mcuxClKey_DerivationInput inputSalt = {.input=pSaltBuf, .size=0u};

    mcuxClKey_DerivationInput_t inputs[] = {inputLabel, inputContext, inputSalt};

    /* Set up output structure. */
    uint8_t derivedKeyBuf[sizeof(expectedDerivedKey)];

    /* Create and initialize derivedKey descriptor structure. */
    uint32_t derivedKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t derivedKey = (mcuxClKey_Handle_t) &derivedKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit2, tokenKeyInit2, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ derivedKey,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Hmac_variableLength,
      /* uint8_t * pKeyData                    */ derivedKeyBuf,
      /* uint32_t keyDataLength                */ sizeof(derivedKeyBuf)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit2) || (MCUXCLKEY_STATUS_OK != resultKeyInit2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Create Hmac mode and Derivation mode                                   */
    /**************************************************************************/

    uint32_t hmacModeDescBuffer[MCUXCLHMAC_HMAC_MODE_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClMac_CustomMode_t hmacSha256 = (mcuxClMac_CustomMode_t) hmacModeDescBuffer;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(hashCreateMode_result, hashCreateMode_token, mcuxClHmac_createHmacMode(
    /* mcuxClMac_CustomMode_t mode:       */ hmacSha256,
    /* mcuxClHash_Algo_t hashAlgorithm:   */ mcuxClHash_Algorithm_Sha256)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_createHmacMode) != hashCreateMode_token) || (MCUXCLMAC_STATUS_OK != hashCreateMode_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t derivationModeDescBuffer[MCUXCLKEY_DERIVATION_MODE_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_DerivationMode_t * pDerivationMode = (mcuxClKey_DerivationMode_t *) derivationModeDescBuffer;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultModeConstruct, tokenModeConstruct, mcuxClKey_Derivation_ModeConstructor_NIST_SP800_56C(
    /* mcuxClKey_DerivationMode_t *                      */ pDerivationMode,
    /* const mcuxClKey_DerivationAlgorithmDescriptor_t * */ mcuxClKey_DerivationAlgorithm_NIST_SP800_56C_TwoStep,
    /* mcuxClMac_Mode_t                                  */ hmacSha256, // use this when using mac function as PRF
    /* mcuxClHash_Algo_t                                 */ NULL, // use this when using hash function as PRF
    /* uint32_t                                         */ 0u // no options for this mode
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_Derivation_ModeConstructor_NIST_SP800_56C) != tokenModeConstruct) || (MCUXCLKEY_STATUS_OK != resultModeConstruct))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Key Derivation                                                         */
    /**************************************************************************/

    /* Call key derivation function. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultDeriv, tokenDeriv, mcuxClKey_derivation(
      /* mcuxClSession_Handle_t pSession         */ session,
      /* mcuxClKey_Derivation_t derivationMode   */ pDerivationMode,
      /* mcuxClKey_Handle_t derivationKey        */ sharedSecretHandle,
      /* mcuxClKey_DerivationInput_t inputs[]    */ inputs,
      /* uint32_t numberOfInputs                */ 3u,
      /* mcuxClKey_Handle_t derivedKey           */ derivedKey
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_derivation) != tokenDeriv) || (MCUXCLKEY_STATUS_OK != resultDeriv))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* The derivedKey could now be used for a cryptographic operation.        */
    /**************************************************************************/


    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/

    /* Compare the derived key to the reference value. */
    if(!mcuxClCore_assertEqual(derivedKeyBuf, expectedDerivedKey, sizeof(expectedDerivedKey)))
    {
        return MCUXCLEXAMPLE_STATUS_FAILURE;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/


    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
