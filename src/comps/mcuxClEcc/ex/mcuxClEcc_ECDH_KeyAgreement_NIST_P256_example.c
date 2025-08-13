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
 * @example mcuxClEcc_ECDH_KeyAgreement_NIST_P256_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClHash.h>
#include <mcuxClEcc.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                                     MCUXCLKEY_AGREEMENT_ECDH_WACPU_SIZE)

#define MAX_PKCWA_SIZE (MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_256)

static const uint8_t pAlicePrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) = {
  0x5Du, 0x37u, 0x8Du, 0xFDu, 0x5Cu, 0xDDu, 0x7Au, 0x37u,
  0xE7u, 0x0Fu, 0x1Au, 0xF7u, 0xFEu, 0x99u, 0xA5u, 0x16u,
  0xD4u, 0xE0u, 0xC4u, 0x34u, 0xD8u, 0x49u, 0x85u, 0xFBu,
  0x12u, 0x50u, 0x32u, 0x06u, 0x73u, 0x9Au, 0x96u, 0xF4u,
};

static const uint8_t pAlicePubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0x0Cu, 0xB2u, 0x52u, 0x2Fu, 0x18u, 0xF9u, 0xB5u, 0xA3u,
  0xADu, 0x3Au, 0xE0u, 0x99u, 0x75u, 0x5Au, 0x49u, 0xCDu,
  0xCEu, 0x4Bu, 0x05u, 0x14u, 0xB5u, 0xC6u, 0x15u, 0x07u,
  0xF0u, 0xC6u, 0x39u, 0xE7u, 0x1Au, 0xB4u, 0x4Cu, 0xDEu,
  0x68u, 0xF8u, 0xDFu, 0x58u, 0xA9u, 0xC0u, 0xF8u, 0x62u,
  0x35u, 0x9Cu, 0xB2u, 0x36u, 0xF9u, 0x29u, 0xABu, 0x9Fu,
  0x89u, 0xB1u, 0xA7u, 0xA2u, 0x34u, 0xC1u, 0xE4u, 0x57u,
  0x23u, 0xC7u, 0xE9u, 0x41u, 0x25u, 0x80u, 0x46u, 0xBBu,
};

static const uint8_t pBobPrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) = {
  0x90u, 0xA1u, 0x2Cu, 0xEDu, 0x78u, 0x9Au, 0x4Fu, 0x82u,
  0x95u, 0xBAu, 0x2Fu, 0x79u, 0x3Du, 0x52u, 0x15u, 0xABu,
  0xDEu, 0x98u, 0x4Cu, 0x4Bu, 0x08u, 0x87u, 0xBFu, 0x6Fu,
  0x75u, 0x1Bu, 0x1Bu, 0x19u, 0xF2u, 0xFDu, 0x76u, 0x03u
};

static const uint8_t pBobPubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0xF4u, 0x7Au, 0x9Au, 0xA6u, 0x2Du, 0x6Bu, 0x5Cu, 0x57u,
  0x1Eu, 0xC6u, 0x6Au, 0xDFu, 0x00u, 0x1Eu, 0x2Cu, 0x2Du,
  0x21u, 0x72u, 0xDEu, 0x07u, 0x2Bu, 0xA5u, 0xB9u, 0xB4u,
  0xB2u, 0xB5u, 0xC3u, 0xEBu, 0xC9u, 0x50u, 0xE0u, 0x21u,
  0x12u, 0xF9u, 0xD0u, 0xA3u, 0xA8u, 0x85u, 0x0Bu, 0x9Bu,
  0xA6u, 0xE1u, 0x4Bu, 0x3Bu, 0x7Du, 0x54u, 0xD8u, 0x7Bu,
  0xF9u, 0x82u, 0xECu, 0x38u, 0x1Bu, 0x81u, 0x5Bu, 0x7Du,
  0x9Fu, 0x29u, 0x51u, 0x9Fu, 0x52u, 0x95u, 0x24u, 0xD6u
};

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ECDH_KeyAgreement_NIST_P256_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Setup one session to be used by all functions called */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                              MAX_CPUWA_SIZE,
                                              MAX_PKCWA_SIZE);


  /* Allocate space for and initialize Alice's private key handle for an ECDH NIST P-256 private key */
  uint32_t alicePrivKeyDesc[(MCUXCLKEY_DESCRIPTOR_SIZE + (sizeof(uint32_t)) - 1u) / (sizeof(uint32_t))];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t alicePrivKey = (mcuxClKey_Handle_t) &alicePrivKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(aliceprivkeyinit_result, aliceprivkeyinit_token, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ alicePrivKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Priv,
  /* const uint8_t * pKeyData              */ pAlicePrivKeyData,
  /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != aliceprivkeyinit_token) || (MCUXCLKEY_STATUS_OK != aliceprivkeyinit_result))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Allocate space for and initialize Alice's public key handle for an ECDH NIST P-256 public key */
  uint32_t alicePubKeyDesc[(MCUXCLKEY_DESCRIPTOR_SIZE + (sizeof(uint32_t)) - 1u) / (sizeof(uint32_t))];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t alicePubKey = (mcuxClKey_Handle_t) &alicePubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(alicepubkeyinit_result, alicepubkeyinit_token, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ alicePubKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Pub,
  /* const uint8_t * pKeyData              */ pAlicePubKeyData,
  /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != alicepubkeyinit_token) || (MCUXCLKEY_STATUS_OK != alicepubkeyinit_result))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Allocate space for and initialize Bob's private key handle for an ECDH NIST P-256 private key */
  uint32_t bobPrivKeyDesc[(MCUXCLKEY_DESCRIPTOR_SIZE + (sizeof(uint32_t)) - 1u) / (sizeof(uint32_t))];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t bobPrivKey = (mcuxClKey_Handle_t) &bobPrivKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bobprivkeyinit_result, bobprivkeyinit_token, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ bobPrivKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Priv,
  /* const uint8_t * pKeyData              */ pBobPrivKeyData,
  /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != bobprivkeyinit_token) || (MCUXCLKEY_STATUS_OK != bobprivkeyinit_result))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Allocate space for and initialize Bob's public key handle for an ECDH NIST P-256 public key */
  uint32_t bobPubKeyDesc[(MCUXCLKEY_DESCRIPTOR_SIZE + (sizeof(uint32_t)) - 1u) / (sizeof(uint32_t))];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t bobPubKey = (mcuxClKey_Handle_t) &bobPubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bobpubkeyinit_result, bobpubkeyinit_token, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ bobPubKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Pub,
  /* const uint8_t * pKeyData              */ pBobPubKeyData,
  /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != bobpubkeyinit_token) || (MCUXCLKEY_STATUS_OK != bobpubkeyinit_result))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /**************************************************************************/
  /* ECDH key agreement on NIST P-256                                       */
  /**************************************************************************/

  /* Parameters used by both Alice and Bob, but currently unused */
  uint32_t numberOfInputs = 0u;

  /* Alice computes the shared key */
  uint8_t aliceSharedSecret[MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET];
  uint32_t aliceSharedSecretSize = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(alice_keyagreement_result, alice_keyagreement_token, mcuxClKey_agreement(
    /* mcuxClSession_Handle_t pSession:                          */ session,
    /* mcuxClKey_Agreement_t agreement:                          */ mcuxClKey_Agreement_ECDH,
    /* mcuxClKey_Handle_t key:                                   */ alicePrivKey,
    /* mcuxClKey_Handle_t otherKey:                              */ bobPubKey,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxClKey_Agreement_AdditionalInput_t additionalInputs[]: */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t numberOfInputs:                                 */ numberOfInputs,
    /* uint8_t * pOut:                                          */ aliceSharedSecret,
    /* uint32_t * const pOutLength:                             */ &aliceSharedSecretSize));

  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_agreement) != alice_keyagreement_token) || (MCUXCLKEY_STATUS_OK != alice_keyagreement_result) || (aliceSharedSecretSize != MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Bob computes the shared key */
  uint8_t bobSharedSecret[MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET];
  uint32_t bobSharedSecretSize = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(bob_keyagreement_result, bob_keyagreement_token, mcuxClKey_agreement(
    /* mcuxClSession_Handle_t pSession:                          */ session,
    /* mcuxClKey_Agreement_t agreement:                          */ mcuxClKey_Agreement_ECDH,
    /* mcuxClKey_Handle_t key:                                   */ bobPrivKey,
    /* mcuxClKey_Handle_t otherKey:                              */ alicePubKey,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxClKey_Agreement_AdditionalInput_t additionalInputs[]: */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t numberOfInputs:                                 */ numberOfInputs,
    /* uint8_t * pOut:                                          */ bobSharedSecret,
    /* uint32_t * const pOutLength:                             */ &bobSharedSecretSize));

  if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_agreement) != bob_keyagreement_token) || (MCUXCLKEY_STATUS_OK != bob_keyagreement_result) || (bobSharedSecretSize != MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Verify that Alice and Bob computed the same shared key */
  if(!mcuxClCore_assertEqual(bobSharedSecret, aliceSharedSecret, MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Destroy Session and cleanup Session */
  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
