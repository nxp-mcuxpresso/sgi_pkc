/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClRsa_Util_verify.c
 *  @brief implementation of mcuxClRsa_Util_verify function, which is used
 *         for RSA signature verification in the mcuxClSignature component.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClRsa.h>
#include <mcuxClSignature_Constants.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClSignature_Internal.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClResource.h>
#include <internal/mcuxClResource_Internal_Types.h>
#include <internal/mcuxClSession_Internal_Functions.h>

/** Macro to request PKC resource and initialize PKC. */
#define MCUXCLRSA_UTIL_VERIFY_FP_REQUEST_INITIALIZE(session)  \
  do {  \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_request(session, \
        MCUXCLRESOURCE_HWID_PKC, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE, NULL, 0U) \
    );  \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pRsa_Signature_ProtocolDescriptor->pPkcInitFun(session));  \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
  } while (false) \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

/** Macro to deinitialize PKC and release PKC resource */
#define MCUXCLRSA_UTIL_VERIFY_FP_DEINITIALIZE_RELEASE(session)  \
  do {  \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pRsa_Signature_ProtocolDescriptor->pPkcDeInitFun()); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_release(session->pResourceCtx, MCUXCLRESOURCE_HWID_PKC)); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
  } while (false) \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

#define MCUXCLRSA_UTIL_VERIFY_FP_CALLED_REQUEST_INITIALIZE  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_request), \
    pRsa_Signature_ProtocolDescriptor->pkcInit_FunId

#define MCUXCLRSA_UTIL_VERIFY_FP_CALLED_DEINITIALIZE_RELEASE  \
    pRsa_Signature_ProtocolDescriptor->pkcDeInit_FunId,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_release)


/* TODO CLNS-17683: Align when the Signature component is updated and if the return status for mcuxClSignature_SignFct_t changes */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_Util_verify, mcuxClSignature_VerifyFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClRsa_Util_verify(
  mcuxClSession_Handle_t           pSession,
  mcuxClKey_Handle_t               key,
  mcuxClSignature_Mode_t           mode,
  mcuxCl_InputBuffer_t             pMessageOrDigest,
  uint32_t                        messageLength UNUSED_PARAM,
  mcuxCl_InputBuffer_t             pSignature,
  uint32_t                        signatureSize
  )
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_Util_verify);

  MCUX_CSSL_DI_RECORD(verifyInput, (uint32_t) pMessageOrDigest);
  MCUX_CSSL_DI_RECORD(verifySignature, (uint32_t) pSignature);

  /*****************************************************/
  /* Initialization                                    */
  /*****************************************************/

  /* Verify that the passed signatureSize value is as expected. */
  uint32_t keyBitLength = mcuxClKey_getSize(key);
  const uint32_t keyByteLength = keyBitLength / 8u;
  if (signatureSize != keyByteLength)
  {
      MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /* Setup the parameters used by RSA internal functions, based on the protocol descriptor:
   * padding mode, salt length, options, output and RSA key. */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
  const mcuxClRsa_SignatureProtocolDescriptor_t * pRsa_Signature_ProtocolDescriptor = (const mcuxClRsa_SignatureProtocolDescriptor_t*) mode->pProtocolDescriptor;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
  const uint32_t saltLength = pRsa_Signature_ProtocolDescriptor->saltLength;
  const uint32_t options = pRsa_Signature_ProtocolDescriptor->options;

  /* Check key type */
  if((MCUXCLRSA_KEYTYPE_INTERNAL_PUBLIC) != mcuxClKey_getAlgoId(key))
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /* Locate paddedMessage buffer at beginning of PKC WA and update session info */
  const uint32_t pkcWaSizeWord = MCUXCLRSA_INTERNAL_PUBLIC_OUTPUT_SIZE(keyByteLength) / (sizeof(uint32_t));
  uint8_t *pPaddedMessage = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeWord);
  MCUX_CSSL_DI_RECORD(verifyPadMsg, pPaddedMessage);

  /* Initialize PKC. */
  MCUXCLRSA_UTIL_VERIFY_FP_REQUEST_INITIALIZE(pSession);

  /*****************************************************/
  /* Perform RSA_public                                */
  /*****************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pRsa_Signature_ProtocolDescriptor->pRsaPublicExpFun(pSession, key, pSignature, pPaddedMessage));
  MCUX_CSSL_DI_EXPUNGE(verifySignature, (uint32_t) pSignature);

  /*****************************************************/
  /* Perform padding operation                         */
  /*****************************************************/

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("pLabel, pOutput, pOutLength are unused by this function")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL(retVal_PaddingOperation, pRsa_Signature_ProtocolDescriptor->pVerifyMode(
                              /* mcuxClSession_Handle_t       pSession,           */ pSession,
                              /* mcuxCl_InputBuffer_t         pInput,             */ pMessageOrDigest,
                              /* const uint32_t              inputLength,        */ 0u,
                              /* mcuxCl_Buffer_t              pVerificationInput, */ pPaddedMessage,
                              /* mcuxClHash_Algo_t            pHashAlgo,          */ pRsa_Signature_ProtocolDescriptor->pHashAlgo,
                              /* const uint8_t *             pLabel,             */ NULL,
                              /* const uint32_t              saltlabelLength,    */ saltLength,
                              /* const uint32_t              keyBitLength,       */ keyBitLength,
                              /* const uint32_t              options,            */ options,
                              /* mcuxCl_Buffer_t              pOutput             */ NULL,
                              /* uint32_t * const            pOutLength          */ NULL));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  /*****************************************************/
  /* Exit                                              */
  /*****************************************************/

  /* De-initialize PKC */
  mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeWord);
  MCUXCLRSA_UTIL_VERIFY_FP_DEINITIALIZE_RELEASE(pSession);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_Util_verify, retVal_PaddingOperation,
          MCUXCLRSA_UTIL_VERIFY_FP_CALLED_REQUEST_INITIALIZE,
          pRsa_Signature_ProtocolDescriptor->rsaPublicExp_FunId,
          pRsa_Signature_ProtocolDescriptor->verify_FunId,
          MCUXCLRSA_UTIL_VERIFY_FP_CALLED_DEINITIALIZE_RELEASE);

}
