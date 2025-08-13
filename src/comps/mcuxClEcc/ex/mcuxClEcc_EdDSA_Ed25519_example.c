/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @example mcuxClEcc_EdDSA_Ed25519_example.c
 * @brief   Example for the mcuxClEcc component EdDsa related functions
 */

#include <mcuxClToolchain.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc.h>
#include <mcuxClKey.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClRandomModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_RNG_Helper.h>

#include <mcuxClSignature.h>

/* Input message taken from "TEST SHA(abc)" from Section 7.1 of IRTF rfc 8032 */
static const ALIGNED uint8_t digest[] = {
  0xDDu, 0xAFu, 0x35u, 0xA1u, 0x93u, 0x61u, 0x7Au, 0xBAu,
  0xCCu, 0x41u, 0x73u, 0x49u, 0xAEu, 0x20u, 0x41u, 0x31u,
  0x12u, 0xE6u, 0xFAu, 0x4Eu, 0x89u, 0xA9u, 0x7Eu, 0xA2u,
  0x0Au, 0x9Eu, 0xEEu, 0xE6u, 0x4Bu, 0x55u, 0xD3u, 0x9Au,
  0x21u, 0x92u, 0x99u, 0x2Au, 0x27u, 0x4Fu, 0xC1u, 0xA8u,
  0x36u, 0xBAu, 0x3Cu, 0x23u, 0xA3u, 0xFEu, 0xEBu, 0xBDu,
  0x45u, 0x4Du, 0x44u, 0x23u, 0x64u, 0x3Cu, 0xE8u, 0x0Eu,
  0x2Au, 0x9Au, 0xC9u, 0x4Fu, 0xA5u, 0x4Cu, 0xA4u, 0x9Fu
};

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WACPU_SIZE, \
                                     MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WACPU_SIZE))))

#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WAPKC_SIZE, \
                                     MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WAPKC_SIZE))

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_EdDSA_Ed25519_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Setup one session to be used by all functions called */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

  /* Initialize the RNG context and initialize the PRNG */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);

  /* Prepare buffers for generated data */
  uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  ALIGNED uint8_t pPrivKeyData[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEYDATA];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result, privkeyinit_token, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ privKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Priv,
  /* uint8_t * pKeyData                    */ pPrivKeyData,
  /* uint32_t keyDataLength                */ sizeof(pPrivKeyData)));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token) || (MCUXCLKEY_STATUS_OK != privkeyinit_result))
  {
      return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  ALIGNED uint8_t pPubKeyData[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pubkeyinit_result, pubkeyinit_token, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ pubKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Pub,
  /* uint8_t * pKeyData                    */ pPubKeyData,
  /* uint32_t keyDataLength                */ sizeof(pPubKeyData)));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token) || (MCUXCLKEY_STATUS_OK != pubkeyinit_result))
  {
      return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Key pair generation for EdDSA on Ed25519                               */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(gkp_status, gkp_token, mcuxClKey_generate_keypair(
  /* mcuxClSession_Handle_t pSession:                        */ session,
  /* mcuxClKey_Generation_t generation:                      */ mcuxClKey_Generation_EdDSA_GeneratePrivKey,
  /* mcuxClKey_Handle_t privKey:                             */ privKey,
  /* mcuxClKey_Handle_t pubKey:                              */ pubKey)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != gkp_token) || (MCUXCLKEY_STATUS_OK != gkp_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Ed25519 signature generation                                           */
  /**************************************************************************/

  ALIGNED uint8_t signature[MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE] = {0};
  uint32_t signatureSize = 0u;
  MCUXCLBUFFER_INIT_RO(buffIn, NULL, digest, sizeof(digest));
  MCUXCLBUFFER_INIT(buffSignature, NULL, signature, MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_status, ss_token, mcuxClSignature_sign(
  /* mcuxClSession_Handle_t session:   */ session,
  /* mcuxClKey_Handle_t key:           */ privKey,
  /* mcuxClSignature_Mode_t mode:      */ mcuxClSignature_Mode_Ed25519,
  /* mcuxCl_InputBuffer_t pIn:         */ buffIn,
  /* uint32_t inSize:                 */ sizeof(digest),
  /* mcuxCl_Buffer_t pSignature:       */ buffSignature,
  /* uint32_t * const pSignatureSize: */ &signatureSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != ss_token) || (MCUXCLSIGNATURE_STATUS_OK != ss_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  if(MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE != signatureSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Ed25519 signature verification                                         */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClSignature_verify(
  /* mcuxClSession_Handle_t session:  */ session,
  /* mcuxClKey_Handle_t key:          */ pubKey,
  /* mcuxClSignature_Mode_t mode:     */ mcuxClSignature_Mode_Ed25519,
  /* mcuxCl_InputBuffer_t pIn:        */ buffIn,
  /* uint32_t inSize:                */ sizeof(digest),
  /* mcuxCl_InputBuffer_t pSignature: */ buffSignature,
  /* uint32_t signatureSize:         */ signatureSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != sv_token) || (MCUXCLSIGNATURE_STATUS_OK != sv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Destroy Session and cleanup Session */
  if(!mcuxClExample_Session_Clean(session))
  {
      return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
