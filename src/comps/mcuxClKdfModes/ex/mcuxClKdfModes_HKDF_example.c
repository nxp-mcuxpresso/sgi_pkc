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
 * @example mcuxClKdfModes_HKDF_example.c
 * @brief Example for the mcuxClKey component, showing a KDF according to the
 *        RFC5869 Standard using Hmac-Sha256
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

/* Test vectors from https://datatracker.ietf.org/doc/html/rfc5869 */

#define OUTPUT_KEY_LENGTH   42

static const uint8_t sharedSecret[22] = {
    0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu,
    0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu,
    0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu, 0x0bu
};

static const uint8_t fixedInfo[10] = {
    0xf0u, 0xf1u, 0xf2u, 0xf3u, 0xf4u, 0xf5u, 0xf6u, 0xf7u,
    0xf8u, 0xf9u
};

static const uint8_t salt[13] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu
};

static const uint8_t expectedDerivedKey[OUTPUT_KEY_LENGTH] = {
    0x3cu, 0xb2u, 0x5fu, 0x25u, 0xfau, 0xacu, 0xd5u, 0x7au,
    0x90u, 0x43u, 0x4fu, 0x64u, 0xd0u, 0x36u, 0x2fu, 0x2au,
    0x2du, 0x2du, 0x0au, 0x90u, 0xcfu, 0x1au, 0x5au, 0x4cu,
    0x5du, 0xb0u, 0x2du, 0x56u, 0xecu, 0xc4u, 0xc5u, 0xbfu,
    0x34u, 0x00u, 0x72u, 0x08u, 0xd5u, 0xb8u, 0x87u, 0x18u,
    0x58u, 0x65u
};


/** Performs an example key derivation using the mcuxClKey component.
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClKdfModes_HKDF_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_DERIVATION_HKDF_CPU_WA_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0u);

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
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Hmac_variableLength,    /* size of sharedSecret does not fit any fixed size key type */
      /* uint8_t * pKeyData                    */ (uint8_t *) sharedSecret,
      /* uint32_t keyDataLength                */ sizeof(sharedSecret)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit1) || (MCUXCLKEY_STATUS_OK != resultKeyInit1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set up input parameter structures. */
    MCUXCLBUFFER_INIT_RO(fixedInfoBuf, session, fixedInfo, sizeof(fixedInfo));
    MCUXCLBUFFER_INIT_RO(saltBuf, session, salt, sizeof(salt));
    struct mcuxClKey_DerivationInput inputFixedInfo = {.input=fixedInfoBuf, .size=sizeof(fixedInfo)};
    struct mcuxClKey_DerivationInput inputSalt = {.input=saltBuf, .size=sizeof(salt)};

    mcuxClKey_DerivationInput_t inputs[] = {inputFixedInfo, inputSalt};

    /* Set up output structure. */
    uint8_t derivedKeyBuf[OUTPUT_KEY_LENGTH];

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

    uint8_t hmacModeDescBuffer[MCUXCLHMAC_HMAC_MODE_DESCRIPTOR_SIZE];
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

    uint8_t derivationModeDescBuffer[MCUXCLKEY_DERIVATION_MODE_DESCRIPTOR_SIZE];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_DerivationMode_t * pDerivationMode = (mcuxClKey_DerivationMode_t *) derivationModeDescBuffer;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultModeConstruct, tokenModeConstruct, mcuxClKey_Derivation_ModeConstructor_HKDF(
    /* mcuxClKey_DerivationMode_t *                      */ pDerivationMode,
    /* const mcuxClKey_DerivationAlgorithmDescriptor_t * */ mcuxClKey_DerivationAlgorithm_HKDF,
    /* mcuxClMac_Mode_t                                  */ hmacSha256, // use this when using mac function as PRF
    /* uint32_t                                         */ 0u // no options for this mode
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_Derivation_ModeConstructor_HKDF) != tokenModeConstruct) || (MCUXCLKEY_STATUS_OK != resultModeConstruct))
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
      /* uint32_t numberOfInputs                */ 2u,
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
    if(!mcuxClCore_assertEqual(derivedKeyBuf, expectedDerivedKey, OUTPUT_KEY_LENGTH))
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
