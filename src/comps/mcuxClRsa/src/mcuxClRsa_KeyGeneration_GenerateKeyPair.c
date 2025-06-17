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

/** @file  mcuxClRsa_KeyGeneration_GenerateKeyPair.c
 *  @brief mcuxClRsa: implementation of RSA key generation function
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>

#include <internal/mcuxClSession_Internal.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_KeyGeneration_GenerateKeyPair, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_KeyGeneration_GenerateKeyPair(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Generation_t generation,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_KeyGeneration_GenerateKeyPair);


  /*********************************************************/
  /* Verify that the key handles are correctly initialized */
  /*********************************************************/

  /* Verify key algorithm */
  const uint32_t publicKeyAlgorithm = mcuxClKey_getAlgorithm(pubKey);
  const uint32_t privateKeyAlgorithm = mcuxClKey_getAlgorithm(privKey);
  if((MCUXCLKEY_ALGO_ID_RSA != publicKeyAlgorithm) || (MCUXCLKEY_ALGO_ID_RSA != privateKeyAlgorithm))
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /* Verify key size in bits */
  const uint32_t publicKeySize = mcuxClKey_getSize(pubKey);
  const uint32_t privateKeySize = mcuxClKey_getSize(privKey);
  if(((MCUXCLKEY_SIZE_1024 != publicKeySize)
    && (MCUXCLKEY_SIZE_2048 != publicKeySize)
    && (MCUXCLKEY_SIZE_3072 != publicKeySize)
    && (MCUXCLKEY_SIZE_4096 != publicKeySize)
    ) || (publicKeySize != privateKeySize))
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /* Verify public key usage */
  mcuxClKey_AlgorithmId_t publicKeyUsage = mcuxClKey_getKeyUsage(pubKey);
  if(MCUXCLKEY_ALGO_ID_PUBLIC_KEY != publicKeyUsage)
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /****************************************************************/
  /* Verify private key usage and execute key generation function */
  /****************************************************************/
  mcuxClKey_AlgorithmId_t privKeyUsage = mcuxClKey_getKeyUsage(privKey);
  if((MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT == privKeyUsage) || (MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT_DFA == privKeyUsage))
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClRsa_Util_KeyGeneration_Crt(pSession,
        generation,
        privKey,
        pubKey
        ));
  }
  else if(MCUXCLKEY_ALGO_ID_PRIVATE_KEY == privKeyUsage)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClRsa_Util_KeyGeneration_Plain(pSession,
        generation,
        privKey,
        pubKey
        ));
  }
  else
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_KeyGeneration_GenerateKeyPair,
    (((MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT == privKeyUsage) || (MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT_DFA == privKeyUsage)) ?
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_KeyGeneration_Crt) :
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_KeyGeneration_Plain))
    );
}
