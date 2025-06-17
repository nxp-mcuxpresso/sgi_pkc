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

/** @file  mcuxClRsa_ModeConstructors.c
 *  @brief mcuxClRsa: implementation of RSA mode constructors for Signature and Cipher components
 */

#include <mcuxClSignature.h>
#include <internal/mcuxClSignature_Internal.h>


#include <internal/mcuxClPkc_Internal_Functions.h>

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>

#include <mcuxClRsa.h>
#include <mcuxClRsa_ModeConstructors.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <mcuxCsslAnalysis.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/**
 * \brief Initialize PKC hardware
 *
 * @param[in]   pIn      session handle for the current CL session.
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_PkcInitialize, mcuxClRsa_PkcInitializeEngine_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_PkcInitialize(mcuxClSession_Handle_t session)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_PkcInitialize);
  MCUXCLPKC_FP_INITIALIZE(session);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_PkcInitialize, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Initialize));
}

/**
 * @brief Deinitialize PKC hardware
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_PkcDeinitialize, mcuxClRsa_PkcDeInitializeEngine_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_PkcDeinitialize(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_PkcDeinitialize);
  MCUXCLPKC_FP_DEINITIALIZE();
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_PkcDeinitialize, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_SignatureModeConstructor_RSASSA_PSS)
void mcuxClRsa_SignatureModeConstructor_RSASSA_PSS(
  mcuxClSignature_ModeDescriptor_t * pSignatureMode,
  mcuxClRsa_SignatureProtocolDescriptor_t * pProtocolDescriptor,
  mcuxClHash_Algo_t hashAlgorithm,
  uint32_t saltLength,
  uint32_t options)
{
  /* Fill signature protocol parameters for RSA with PSS encoding */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the protocol parameters.")
  pProtocolDescriptor->pHashAlgo = (mcuxClHash_AlgorithmDescriptor_t *)hashAlgorithm;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
  pProtocolDescriptor->pSignMode = mcuxClRsa_pssEncode;
  pProtocolDescriptor->sign_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssEncode);
  pProtocolDescriptor->pVerifyMode = mcuxClRsa_pssVerify;
  pProtocolDescriptor->verify_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssVerify);
  pProtocolDescriptor->saltLength = saltLength;
  pProtocolDescriptor->options = options;

  {
    pProtocolDescriptor->pPkcInitFun = mcuxClRsa_PkcInitialize;
    pProtocolDescriptor->pPkcDeInitFun = mcuxClRsa_PkcDeinitialize;
    pProtocolDescriptor->pkcInit_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_PkcInitialize);
    pProtocolDescriptor->pkcDeInit_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_PkcDeinitialize);
    pProtocolDescriptor->pRsaPublicExpFun = mcuxClRsa_public;
    pProtocolDescriptor->rsaPublicExp_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_public);
  }

  /* Fill signature mode parameters for RSA */
  pSignatureMode->pSignFct = mcuxClRsa_Util_sign;
  pSignatureMode->protection_token_sign = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_sign);
  pSignatureMode->pVerifyFct = mcuxClRsa_Util_verify;
  pSignatureMode->protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_verify);
  pSignatureMode->pProtocolDescriptor = pProtocolDescriptor;
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_SignatureModeConstructor_RSASSA_PKCS1_v1_5)
void mcuxClRsa_SignatureModeConstructor_RSASSA_PKCS1_v1_5(
  mcuxClSignature_ModeDescriptor_t * pSignatureMode,
  mcuxClRsa_SignatureProtocolDescriptor_t * pProtocolDescriptor,
  mcuxClHash_Algo_t hashAlgorithm,
  uint32_t options)
{
  /* Fill signature protocol parameters for RSA with PKCS#1 v1.5 encoding */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the protocol parameters")
  pProtocolDescriptor->pHashAlgo = (mcuxClHash_AlgorithmDescriptor_t *)hashAlgorithm;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
  pProtocolDescriptor->pSignMode = mcuxClRsa_pkcs1v15Encode_sign;
  pProtocolDescriptor->sign_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pkcs1v15Encode_sign);
  pProtocolDescriptor->pVerifyMode = mcuxClRsa_pkcs1v15Verify;
  pProtocolDescriptor->verify_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pkcs1v15Verify);
  pProtocolDescriptor->saltLength = 0u; /* there is no salt for PKCS#1 */
  pProtocolDescriptor->options = options;

  {
    pProtocolDescriptor->pPkcInitFun = mcuxClRsa_PkcInitialize;
    pProtocolDescriptor->pPkcDeInitFun = mcuxClRsa_PkcDeinitialize;
    pProtocolDescriptor->pkcInit_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_PkcInitialize);
    pProtocolDescriptor->pkcDeInit_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_PkcDeinitialize);
    pProtocolDescriptor->pRsaPublicExpFun = mcuxClRsa_public;
    pProtocolDescriptor->rsaPublicExp_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_public);
  }

  /* Fill signature mode parameters for RSA */
  pSignatureMode->pSignFct = mcuxClRsa_Util_sign;
  pSignatureMode->protection_token_sign = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_sign);
  pSignatureMode->pVerifyFct = mcuxClRsa_Util_verify;
  pSignatureMode->protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_verify);
  pSignatureMode->pProtocolDescriptor = pProtocolDescriptor;
}



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_KeyGeneration_ModeConstructor)
void mcuxClRsa_KeyGeneration_ModeConstructor(
  mcuxClKey_GenerationDescriptor_t * pKeyGenMode,
  const uint8_t * pE,
  uint32_t eLength
)
{
  /* Create RSA descriptor after the key mode.
   * It is assumed that sufficient space was allocated by users, with the macro MCUXCLRSA_KEYGEN_MODE_SIZE */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Explicit cast to reinterpret memory, to initialize pProtocolDescriptor at word-aligned location after pKeyGenMode")
  mcuxClRsa_KeyGeneration_ProtocolDescriptor_t *pProtocolDescriptor = (mcuxClRsa_KeyGeneration_ProtocolDescriptor_t *) ((uint8_t*)pKeyGenMode + sizeof(mcuxClKey_GenerationDescriptor_t));

  /* Fill key protocol parameters for RSA key generation */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the key protocol parameters")
  pProtocolDescriptor->pubExp.pKeyEntryData = (uint8_t *)pE;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
  pProtocolDescriptor->pubExp.keyEntryLength = eLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /* Fill cipher mode parameters for RSA */
  pKeyGenMode->pKeyGenFct = mcuxClRsa_KeyGeneration_GenerateKeyPair;
  pKeyGenMode->protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClRsa_KeyGeneration_GenerateKeyPair;
  pKeyGenMode->pProtocolDescriptor = (void *) pProtocolDescriptor;
}

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
