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

/** @file  mcuxClSignature.c
 *  @brief mcuxClSignature: implementation of mcuxClSignature functions
 */


#include <mcuxClSignature.h>

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClRsa_Types.h>
#include <mcuxClEcc_Types.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSignature_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSignature_sign)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClSignature_sign(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_Buffer_t pSignature,
  uint32_t * const pSignatureSize
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClSignature_sign, diRefValue, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);

  *pSignatureSize = 0U;

  MCUX_CSSL_FP_FUNCTION_CALL(sign_status, mode->pSignFct(
    /* mcuxClSession_Handle_t           session:          */  session,
    /* mcuxClKey_Handle_t               key:              */  key,
    /* mcuxClSignature_Mode_t           mode:             */  mode,
    /* mcuxCl_InputBuffer_t             pIn:              */  pIn,
    /* const uint32_t                  inSize:           */  inSize,
    /* mcuxCl_Buffer_t                  pSignature:       */  pSignature,
    /* uint32_t * const                pSignatureSize:   */  pSignatureSize));

  mcuxClSignature_Status_t sign_result_tmp = sign_status;

  MCUX_CSSL_ANALYSIS_COVERITY_START_DEVIATE(MISRA_C_2012_Rule_14_3, "intentional, this 'false' is a temporary solution")
  if(
    MCUXCLRSA_STATUS_SIGN_OK == sign_status ||
    MCUXCLECC_STATUS_OK == sign_status ||
    false) // This causes a MISRA violation Rule 14.3
  {
    sign_result_tmp = MCUXCLSIGNATURE_STATUS_OK;
  }

  if(
    false) // This causes a MISRA violation Rule 14.3
  {
    sign_result_tmp = MCUXCLSIGNATURE_STATUS_FAULT_ATTACK;
  }
  MCUX_CSSL_ANALYSIS_COVERITY_STOP_DEVIATE(MISRA_C_2012_Rule_14_3)

  MCUXCLSESSION_EXIT(session,
      mcuxClSignature_sign,
      diRefValue,
      sign_result_tmp,
      MCUXCLSIGNATURE_STATUS_FAULT_ATTACK,
      mode->protection_token_sign);
}



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSignature_verify_recordParam)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClSignature_verify_recordParam(
  mcuxClSession_Handle_t session,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSignature_verify_recordParam);

  if(mcuxClSignature_Mode_ECDSA == mode)
  {
    /* Verify that the session workspace is available and has sufficient capacity.
    * As this is helper funtion for mcuxClSignature_verify(), error on insufficient memory
    * will be thrown by the main mcuxClSignature_verify() function. Here is only check
    * to prevent workspace usage in case no workspace availability. */
    if (session->cpuWa.used < session->cpuWa.size)
    {
      /* Calculate parameter sum as and place this in a workspace
      * as a hint for signature verification modes.
      * Mode implementations may leverage this if they are designed to recognize
      * active parameter protection feature. */
      uint32_t paramSum = (uint32_t)mode + (uint32_t)pIn + inSize;
      uint32_t *currentCpuWord = mcuxClSession_getEndOfUsedBuffer_Internal(session);
      *currentCpuWord = paramSum;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSignature_verify_recordParam, MCUXCLSIGNATURE_STATUS_OK);
  }
  else
  {
    /* Only mcuxClSignature_Mode_ECDSA is supporting this feature */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSignature_verify_recordParam, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSignature_verify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClSignature_verify(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_InputBuffer_t pSignature,
  uint32_t signatureSize
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClSignature_verify, diRefValue, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);

  MCUX_CSSL_FP_FUNCTION_CALL(verify_status, mode->pVerifyFct(
    /* mcuxClSession_Handle_t           session:           */  session,
    /* mcuxClKey_Handle_t               key:               */  key,
    /* mcuxClSignature_Mode_t           mode:              */  mode,
    /* mcuxCl_InputBuffer_t             pIn:               */  pIn,
    /* uint32_t                        inSize:            */  inSize,
    /* mcuxCl_InputBuffer_t             pSignature:        */  pSignature,
    /* uint32_t                        signatureSize:     */  signatureSize));

  MCUX_CSSL_DI_EXPUNGE(verifyRetCode, verify_status);

  uint32_t returnCode = MCUXCLSIGNATURE_TRANSLATE_VERIFY_RETURN_CODE(verify_status);

  MCUXCLSESSION_EXIT(session,
      mcuxClSignature_verify,
      diRefValue,
      returnCode,
      MCUXCLSIGNATURE_STATUS_FAULT_ATTACK,
      mode->protection_token_verify);

}



