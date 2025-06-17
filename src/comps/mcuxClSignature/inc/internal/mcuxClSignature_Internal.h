/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

/** @file  mcuxClSignature_Internal.h
 *  @brief Internal header for Signature types
 */

#ifndef MCUXCLSIGNATURE_INTERNAL_H_
#define MCUXCLSIGNATURE_INTERNAL_H_

#include <mcuxClSignature_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession_Types.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mode/Skeleton function types
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSignature_SignFct_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) (*mcuxClSignature_SignFct_t) (
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_Buffer_t pSignature,
  uint32_t * const pSignatureSize
));

/**
* Data Integrity: Record(returnCode)
*/
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSignature_VerifyFct_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) (*mcuxClSignature_VerifyFct_t) (
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_InputBuffer_t pSignature,
  uint32_t signatureSize
));


/**
 * \brief Signature mode descriptor structure
 * \ingroup clSignatureModes
 *
 * This structure captures all the information that the Signature interfaces need
 * to know about a particular Signature mode.
 */
struct mcuxClSignature_ModeDescriptor
{
  mcuxClSignature_SignFct_t   pSignFct;
  uint32_t protection_token_sign;
  mcuxClSignature_VerifyFct_t pVerifyFct;
  uint32_t protection_token_verify;
  const void * pProtocolDescriptor;  // TODO TBD shall this be pAlgorithmDescriptor, to be more consistent with the naming in Cipher components?
};

/**
 * @brief Signature context structure
 *
 * This structure is used in the multi-part interfaces to store the
 * information about the current operation and the relevant internal state.
 * This is the common part of the context needed by signature modes.
 */
struct mcuxClSignature_Context
{
  const mcuxClSignature_ModeDescriptor_t * pMode;
};


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSIGNATURE_INTERNAL_H_ */
