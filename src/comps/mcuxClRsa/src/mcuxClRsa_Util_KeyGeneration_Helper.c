/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

/** @file  mcuxClRsa_Util_KeyGeneration_Helper.c
 *  @brief mcuxClRsa: implementation of helper functions for RSA key generation
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClKey.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClRandom.h>
#include <mcuxClRsa.h>

#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_Operations.h>


#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>

#define MCUXCLRSA_KEYGEN_FP_SECSTRENGTH  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_checkSecurityStrength)

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_Util_KeyGeneration_Init_Common)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_Util_KeyGeneration_Init_Common(
  mcuxClSession_Handle_t pSession,
  mcuxClKey_Handle_t pubKey,
  mcuxClKey_Generation_t generation,
  uint32_t *pByteLenE)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_Util_KeyGeneration_Init_Common);

  const uint32_t bitLenKey = mcuxClKey_getSize(pubKey);
  const uint32_t byteLenKey = bitLenKey / 8u;

  /*
   * Check entropy provided by RNG
   * If the RNG does not provide an appropriate level of entropy (security strength) for the given key size,
   * this function returns MCUXCLRANDOM_STATUS_LOW_SECURITY_STRENGTH through the session parameter (early exit).
   */
  uint32_t securityStrength = MCUXCLRSA_GET_MINIMUM_SECURITY_STRENGTH(bitLenKey);
  MCUX_CSSL_FP_FUNCTION_CALL(ret_checkSecurityStrength, mcuxClRandom_checkSecurityStrength(pSession, securityStrength));
  /* mcuxClRandom_checkSecurityStrength is an public function. Hence check session error/fault and handle accordingly */
  MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, ret_checkSecurityStrength);

  /*
   * Check if E is FIPS compliant, i.e., is odd values in the range 2^16 < e < 2^256,
   * determine the length without leading zeros.
   * If the function does not pass the verification, it does an early-exit with MCUXCLKEY_STATUS_INVALID_INPUT error.
   */
  const mcuxClRsa_KeyGeneration_ProtocolDescriptor_t * pProtocolDescriptor = (const mcuxClRsa_KeyGeneration_ProtocolDescriptor_t *) generation->pProtocolDescriptor;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to set the generic pointer.")
  mcuxClRsa_KeyEntry_t * pPublicExponent = (mcuxClRsa_KeyEntry_t *) &pProtocolDescriptor->pubExp;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pPublicExponent->keyEntryLength dereferenced inside the mcuxClRsa_VerifyE has a compatible type and the cast was valid")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_VerifyE(pSession, pPublicExponent, pByteLenE));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /*
   * Check whether the public key data container has enough space.
  */
  const uint32_t pubKeyContainerSize = mcuxClKey_getKeyContainerSize(pubKey);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pByteLenE, 3u, 32u, MCUXCLRSA_STATUS_INVALID_INPUT /* e is in the range 2^16 < e < 2^256 */)
  if(MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(byteLenKey, *pByteLenE) > pubKeyContainerSize)
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_Util_KeyGeneration_Init_Common,
                            MCUXCLRSA_KEYGEN_FP_SECSTRENGTH,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_VerifyE));
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_Util_KeyGeneration_Init_CrtKey)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_Util_KeyGeneration_Init_CrtKey(
  mcuxClSession_Handle_t pSession,
  mcuxClKey_Handle_t pubKey,
  mcuxClKey_Generation_t generation,
  uint32_t * pByteLenE,
  mcuxClKey_Handle_t privKey)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_Util_KeyGeneration_Init_CrtKey);

  /*
   * Common initialization process:
   * - Check entropy provided by RNG
   * - Check if E is FIPS compliant
   * - Check whether the public key data container has enough space
   */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_Util_KeyGeneration_Init_Common(
                            pSession,
                            pubKey,
                        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pPublicExponent has compatible type and cast was valid")
                            generation,
                        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
                            pByteLenE));

  /*
   * Check whether the private key data container has enough space.
   */
  const uint32_t bitLenKey = mcuxClKey_getSize(pubKey);
  const uint32_t byteLenKey = bitLenKey / 8u;
  const uint32_t privKeyContainerSize = mcuxClKey_getKeyContainerSize(privKey);
  const mcuxClKey_AlgorithmId_t privKeyUsage = mcuxClKey_getKeyUsage(privKey);

  if(MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT == privKeyUsage)
  {
    if(MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRT_DATA_SIZE(byteLenKey) > privKeyContainerSize)
    {
      MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
    }
  }
  else
  {
    if(MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRTDFA_DATA_SIZE(byteLenKey) > privKeyContainerSize)
    {
      MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_Util_KeyGeneration_Init_CrtKey,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_KeyGeneration_Init_Common));
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_Util_KeyGeneration_Init_PlainKey)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_Util_KeyGeneration_Init_PlainKey(
  mcuxClSession_Handle_t pSession,
  mcuxClKey_Handle_t pubKey,
  mcuxClKey_Generation_t generation,
  uint32_t * pByteLenE,
  mcuxClKey_Handle_t privKey)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_Util_KeyGeneration_Init_PlainKey);

  /*
   * Common initialization process:
   * - Check entropy provided by RNG
   * - Check if E is FIPS compliant
   * - Check whether the public key data container has enough space
   */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_Util_KeyGeneration_Init_Common(
                            pSession,
                            pubKey,
                        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pPublicExponent has compatible type and cast was valid")
                            generation,
                        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
                            pByteLenE));

  /*
   * Check whether the private key data container has enough space.
   */
  const uint32_t bitLenKey = mcuxClKey_getSize(pubKey);
  const uint32_t byteLenKey = bitLenKey / 8u;
  const uint32_t privKeyContainerSize = mcuxClKey_getKeyContainerSize(privKey);

  if(MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(byteLenKey) > privKeyContainerSize)
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_Util_KeyGeneration_Init_PlainKey,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_KeyGeneration_Init_Common));
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_VerifyKey)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_VerifyKey(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey,
    mcuxClRsa_KeyEntry_t * pPublicExponent,
    uint8_t * pPkcWorkarea)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_VerifyKey);

  mcuxClKey_AlgorithmId_t privKeyUsage = mcuxClKey_getKeyUsage(privKey);
    /* Clear PKC workarea. */
    const uint32_t bitLenKey = mcuxClKey_getSize(pubKey);
    uint32_t pkcWaSize = (MCUXCLKEY_ALGO_ID_PRIVATE_KEY == privKeyUsage) ?
                          MCUXCLRSA_KEYGENERATION_PLAIN_WAPKC_SIZE(bitLenKey) :
                          MCUXCLRSA_KEYGENERATION_CRT_WAPKC_SIZE(bitLenKey);
    MCUXCLPKC_PS1_SETLENGTH(0u, pkcWaSize);
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_VERIFYKEY_PKCWA] = MCUXCLPKC_PTR2OFFSET(pPkcWorkarea);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_CONST);
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_VERIFYKEY_PKCWA, 0u);


  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_VerifyKey);
}
