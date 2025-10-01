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
 * @example mcuxClEcc_Weier_KeyValidation_PublicKey_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClEcc.h>
#include <mcuxClMemory.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#define MAX_CPUWA_SIZE MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WACPU_SIZE
#define MAX_PKCWA_SIZE MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WAPKC_SIZE_256

static const uint8_t pPubKeyData_InvalidPoint[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0x0Cu, 0xB2u, 0x52u, 0x2Fu, 0x18u, 0xF9u, 0xB5u, 0xA3u,
  0xADu, 0x3Au, 0xE0u, 0x99u, 0x75u, 0x5Au, 0x49u, 0xCDu,
  0xCEu, 0x4Bu, 0x05u, 0x14u, 0xB5u, 0xC6u, 0x15u, 0x07u,
  0xF0u, 0xC6u, 0x39u, 0xE7u, 0x1Au, 0xB4u, 0x4Cu, 0xDEu,
  0x68u, 0xF8u, 0xDFu, 0x58u, 0xA9u, 0xC0u, 0xF8u, 0x62u,
  0x35u, 0x9Cu, 0xB2u, 0x36u, 0xF9u, 0x29u, 0xABu, 0x9Fu,
  0x89u, 0xB1u, 0xA7u, 0xA2u, 0x34u, 0xC1u, 0xE4u, 0x57u,
  0x23u, 0xC7u, 0xE9u, 0x41u, 0x25u, 0x80u, 0x46u, 0xBAu,
};

static const uint8_t pPubKeyData_Valid[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0x0Cu, 0xB2u, 0x52u, 0x2Fu, 0x18u, 0xF9u, 0xB5u, 0xA3u,
  0xADu, 0x3Au, 0xE0u, 0x99u, 0x75u, 0x5Au, 0x49u, 0xCDu,
  0xCEu, 0x4Bu, 0x05u, 0x14u, 0xB5u, 0xC6u, 0x15u, 0x07u,
  0xF0u, 0xC6u, 0x39u, 0xE7u, 0x1Au, 0xB4u, 0x4Cu, 0xDEu,
  0x68u, 0xF8u, 0xDFu, 0x58u, 0xA9u, 0xC0u, 0xF8u, 0x62u,
  0x35u, 0x9Cu, 0xB2u, 0x36u, 0xF9u, 0x29u, 0xABu, 0x9Fu,
  0x89u, 0xB1u, 0xA7u, 0xA2u, 0x34u, 0xC1u, 0xE4u, 0x57u,
  0x23u, 0xC7u, 0xE9u, 0x41u, 0x25u, 0x80u, 0x46u, 0xBBu,
};

/* Example of public key validation for Weierstrass curve NIST P-256. */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_Weier_KeyValidation_PublicKey_example)
{
  /* Setup one session to be used by all functions called */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

  uint32_t pubKeyDesc[(MCUXCLKEY_DESCRIPTOR_SIZE + (sizeof(uint32_t)) - 1u) / (sizeof(uint32_t))];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  /* Initialize public key with a point that is not on the curve */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pubkeyinit_result1, pubkeyinit_token1, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ pubKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Pub,
  /* const uint8_t * pKeyData              */ pPubKeyData_InvalidPoint,
  /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token1) || (MCUXCLKEY_STATUS_OK != pubkeyinit_result1))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Validate key and expect MCUXCLKEY_STATUS_VALIDATION_FAILED */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyvalidate_result1, keyvalidate_token1, mcuxClKey_validate(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Validation_t validation      */ mcuxClKey_Validation_WeierECC_PublicKey,
  /* mcuxClKey_Handle_t key                 */ pubKey));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_validate) != keyvalidate_token1) || (MCUXCLKEY_STATUS_VALIDATION_FAILED != keyvalidate_result1))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /* Initialize valid public key */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pubkeyinit_result2, pubkeyinit_token2, mcuxClKey_init(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Handle_t key                 */ pubKey,
  /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Pub,
  /* const uint8_t * pKeyData              */ pPubKeyData_Valid,
  /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token2) || (MCUXCLKEY_STATUS_OK != pubkeyinit_result2))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Validate key and expect MCUXCLKEY_STATUS_VALIDATION_PASSED */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyvalidate_result2, keyvalidate_token2, mcuxClKey_validate(
  /* mcuxClSession_Handle_t session         */ session,
  /* mcuxClKey_Validation_t validation      */ mcuxClKey_Validation_WeierECC_PublicKey,
  /* mcuxClKey_Handle_t key                 */ pubKey));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_validate) != keyvalidate_token2) || (MCUXCLKEY_STATUS_VALIDATION_PASSED != keyvalidate_result2))
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
