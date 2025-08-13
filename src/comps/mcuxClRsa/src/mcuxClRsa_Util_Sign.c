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

/** @file  mcuxClRsa_Util_Sign.c
 *  @brief mcuxClRsa: implementation of RSA Sign function
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClHash.h>
#include <mcuxClSignature_Types.h>
#include <mcuxClSignature_Constants.h>
#include <mcuxClBuffer.h>

#include <mcuxClRsa.h>

#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClSignature_Internal.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>

/* TODO CLNS-17683: Align when the Signature component is updated and if the return status for mcuxClSignature_SignFct_t changes */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_Util_sign, mcuxClSignature_SignFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClRsa_Util_sign(
  mcuxClSession_Handle_t           pSession,
  mcuxClKey_Handle_t               key,
  mcuxClSignature_Mode_t           mode,
  mcuxCl_InputBuffer_t             pMessageOrDigest,
  uint32_t                        messageLength UNUSED_PARAM,
  mcuxCl_Buffer_t                  pSignature,
  uint32_t * const                pSignatureSize
  )
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_Util_sign);

  /* SREQI_RSA_0: DI protect the Key algoId.
   * Will be balanced in the call to mcuxClRsa_privatePlain() or mcuxClRsa_privateCrt() */
  MCUX_CSSL_DI_RECORD(verifyKey, mcuxClKey_getAlgoId(key));

  /*****************************************************/
  /* Initialization                                    */
  /*****************************************************/

  /* Initialize PKC */
  MCUXCLPKC_FP_REQUEST_INITIALIZE(pSession, mcuxClRsa_Util_sign);

  /*****************************************************/
  /* Perform padding operation                         */
  /*****************************************************/

  // TODO CLNS-9134: define which parameters should be verified (valid mode, hash function, key size, etc.. ?)

  /* Setup the parameters used by RSA internal functions, based on the protocol descriptor:
   * padding mode, salt length, options, signature size and RSA key. */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
  const mcuxClRsa_SignatureProtocolDescriptor_t * pRsa_Signature_ProtocolDescriptor = (const mcuxClRsa_SignatureProtocolDescriptor_t*) mode->pProtocolDescriptor;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

  const uint32_t saltLength = pRsa_Signature_ProtocolDescriptor->saltLength;
  const uint32_t options = pRsa_Signature_ProtocolDescriptor->options;

  /* Get the modulus bit length from the input key */
  uint32_t keyBitLength = mcuxClKey_getSize(key);
  *pSignatureSize = keyBitLength / 8u;

  /* Locate paddedMessage buffer at beginning of PKC WA and update session info */
  uint32_t keyByteLength = keyBitLength / 8u;
  uint32_t pkcWaUsedByte = (MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN == mcuxClKey_getAlgoId(key)) ? MCUXCLRSA_INTERNAL_PRIVATEPLAIN_INPUT_SIZE(keyByteLength) : MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(keyByteLength);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorakarea, mcuxClSession_allocateWords_pkcWa(pSession, pkcWaUsedByte / (sizeof(uint32_t))));
  uint8_t *pPaddedMessage = pPkcWorakarea;

  /* Call the padding function */
  MCUXCLBUFFER_INIT(pPaddedMessageBuf, NULL, pPaddedMessage, pkcWaUsedByte);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("pVerificationInput, pLabel, pOutLength are unused by this function")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL(retVal_PaddingOperation, pRsa_Signature_ProtocolDescriptor->pSignMode(
                              /* mcuxClSession_Handle_t       pSession,           */ pSession,
                              /* mcuxCl_InputBuffer_t         pInput,             */ pMessageOrDigest,
                              /* const uint32_t              inputLength,        */ 0u,
                              /* mcuxCl_Buffer_t              pVerificationInput, */ NULL,
                              /* mcuxClHash_Algo_t            pHashAlgo,          */ pRsa_Signature_ProtocolDescriptor->pHashAlgo,
                              /* const uint8_t *             pLabel,             */ NULL,
                              /* const uint32_t              saltlabelLength,    */ saltLength,
                              /* const uint32_t              keyBitLength,       */ keyBitLength,
                              /* const uint32_t              options,            */ options,
                              /* mcuxCl_Buffer_t              pOutput             */ pPaddedMessageBuf,
                              /* uint32_t * const            pOutLength          */ NULL
  ));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  /* Return FAULT if the pRsa_Signature_ProtocolDescriptor->pSignMode function does not return MCUXCLRSA_STATUS_INTERNAL_ENCODE_OK. */
  if(MCUXCLRSA_STATUS_INTERNAL_ENCODE_OK != retVal_PaddingOperation)
  {
    MCUXCLSESSION_FAULT(pSession, MCUXCLRSA_STATUS_FAULT_ATTACK);
  }


  if (pkcWaUsedByte > keyByteLength)
  {
    /* Clear PKC workarea after the input */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_afterInput, pPaddedMessage + keyByteLength);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_afterInput, pkcWaUsedByte - keyByteLength);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(pPaddedMessage + keyByteLength, pkcWaUsedByte - keyByteLength));
  }

  /*****************************************************/
  /* Perform RSA private operation                     */
  /*****************************************************/
  /* Call the appropriate private key operation, based on the key type */
  mcuxClKey_AlgorithmId_t keyAlgoId = mcuxClKey_getAlgoId(key);
  if(MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN == keyAlgoId)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_privatePlain(pSession, key, pPaddedMessage, pSignature));
  }
  else if((MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRT == keyAlgoId)
      || (MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRTDFA == keyAlgoId))
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_privateCRT(pSession, key, pPaddedMessage, pSignature));
  }
  else
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /*****************************************************/
  /* Exit                                              */
  /*****************************************************/

  mcuxClSession_freeWords_pkcWa(pSession, pkcWaUsedByte / (sizeof(uint32_t)));
  MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_Util_sign,
                  MCUXCLRSA_STATUS_SIGN_OK,
                  MCUXCLPKC_FP_CALLED_REQUEST_INITIALIZE,
                  pRsa_Signature_ProtocolDescriptor->sign_FunId,
                  MCUX_CSSL_FP_CONDITIONAL(pkcWaUsedByte > keyByteLength, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int)),
                  MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN == mcuxClKey_getAlgoId(key)),
                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_privatePlain)),
                  MCUX_CSSL_FP_CONDITIONAL(((MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRT == mcuxClKey_getAlgoId(key))
                    || (MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRTDFA == mcuxClKey_getAlgoId(key))),
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_privateCRT)),
                  MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
}
