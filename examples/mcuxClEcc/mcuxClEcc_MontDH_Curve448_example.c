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

/**
 * @example mcuxClEcc_MontDH_Curve448_example.c
 * @brief   Example for the mcuxClEcc component curve448 related functions
 */

#include <mcuxClToolchain.h>
#include <mcuxClRandomModes.h>
#include <mcuxClEcc.h>
#include <mcuxClKey.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClCore_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE448_WACPU_SIZE, \
                                     MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WACPU_SIZE)))

#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE448_WAPKC_SIZE, \
                                     MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WAPKC_SIZE)


MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_MontDH_Curve448_example)
{
    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /* NOTE: Key generation for Curve448 from a DRBG with 128 bit security strength is not recommended. */
    /* Initialize the RNG and Initialize the PRNG */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);

    /* Prepare input for Alice key generation */
    uint32_t alicePrivKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t alicePrivKeyHandler = (mcuxClKey_Handle_t) &alicePrivKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    ALIGNED uint8_t alicePrivKeyBuffer[MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY]={0};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(aliceprivkeyinit_result, aliceprivkeyinit_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ alicePrivKeyHandler,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve448_PrivateKey,
    /* const uint8_t * pKeyData              */ alicePrivKeyBuffer,
    /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != aliceprivkeyinit_token) || (MCUXCLKEY_STATUS_OK != aliceprivkeyinit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t alicePubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t alicePubKeyHandler = (mcuxClKey_Handle_t) &alicePubKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    ALIGNED uint8_t alicePubKeyBuffer[MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY]={0};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(alicepubkeyinit_result, alicepubkeyinit_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ alicePubKeyHandler,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve448_PublicKey,
    /* const uint8_t * pKeyData              */ alicePubKeyBuffer,
    /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != alicepubkeyinit_token) || (MCUXCLKEY_STATUS_OK != alicepubkeyinit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Prepare input for Bob key generation */
    uint32_t bobPrivKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t bobPrivKeyHandler = (mcuxClKey_Handle_t) &bobPrivKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    ALIGNED uint8_t bobPrivKeyBuffer[MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY]={0};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bobprivkeyinit_result, bobprivkeyinit_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ bobPrivKeyHandler,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve448_PrivateKey,
    /* const uint8_t * pKeyData              */ bobPrivKeyBuffer,
    /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != bobprivkeyinit_token) || (MCUXCLKEY_STATUS_OK != bobprivkeyinit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t bobPubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t bobPubKeyHandler = (mcuxClKey_Handle_t) &bobPubKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    ALIGNED uint8_t bobPubKeyBuffer[MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY]={0};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bobpubkeyinit_result, bobpubkeyinit_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ bobPubKeyHandler,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve448_PublicKey,
    /* const uint8_t * pKeyData              */ bobPubKeyBuffer,
    /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != bobpubkeyinit_token) || (MCUXCLKEY_STATUS_OK != bobpubkeyinit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Call Dh KeyGeneration for Alice keys generation and check FP and return code */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(alice_keygeneration_result, alice_keygeneration_token,
        mcuxClKey_generate_keypair(session,
                                  mcuxClKey_Generation_MontDH,
                                  alicePrivKeyHandler,
                                  alicePubKeyHandler));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != alice_keygeneration_token) || (MCUXCLKEY_STATUS_OK != alice_keygeneration_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Call Dh KeyGeneration for Bob keys generation and check FP and return code */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bob_keygeneration_result, bob_keygeneration_token,
        mcuxClKey_generate_keypair(session,
                                  mcuxClKey_Generation_MontDH,
                                  bobPrivKeyHandler,
                                  bobPubKeyHandler));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != bob_keygeneration_token) || (MCUXCLKEY_STATUS_OK != bob_keygeneration_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Prepare input for Alice shared secret calculation */
    ALIGNED uint8_t aliceSharedSecret[MCUXCLECC_MONTDH_CURVE448_SIZE_SHAREDSECRET];
    uint32_t aliceSharedSecretSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(alice_keyagreement_result, alice_keyagreement_token,
        mcuxClKey_agreement(session,
                           &mcuxClKey_AgreementDescriptor_MontDH,
                           alicePrivKeyHandler,
                           bobPubKeyHandler,
                           MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
                           NULL,
                           MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                           0u,
                           MCUX_CSSL_ANALYSIS_START_SUPPRESS_USE_UNINITIALIZED_VALUE("Buffer used as output")
                           aliceSharedSecret,
                           MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_USE_UNINITIALIZED_VALUE()
                           &aliceSharedSecretSize));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_agreement) != alice_keyagreement_token) || (MCUXCLKEY_STATUS_OK != alice_keyagreement_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Prepare input for Bob shared secret calculation */
    ALIGNED uint8_t bobSharedSecret[MCUXCLECC_MONTDH_CURVE448_SIZE_SHAREDSECRET];
    uint32_t bobSharedSecretSize;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bob_keyagreement_result, bob_keyagreement_token,
        mcuxClKey_agreement(session,
                           &mcuxClKey_AgreementDescriptor_MontDH,
                           bobPrivKeyHandler,
                           alicePubKeyHandler,
                           MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
                           NULL,
                           MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                           0u,
                           MCUX_CSSL_ANALYSIS_START_SUPPRESS_USE_UNINITIALIZED_VALUE("Buffer used as output")
                           bobSharedSecret,
                           MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_USE_UNINITIALIZED_VALUE()
                           &bobSharedSecretSize));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_agreement) != bob_keyagreement_token) || (MCUXCLKEY_STATUS_OK != bob_keyagreement_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Alice's shared secret shall be equal to Bob's shared secret */
    for(size_t i = 0u; i < MCUXCLECC_MONTDH_CURVE448_SIZE_SHAREDSECRET; i++)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClKey_agreement")
        if(bobSharedSecret[i] != aliceSharedSecret[i])
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
        {
            return MCUXCLEXAMPLE_STATUS_ERROR;
        }
    }

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
