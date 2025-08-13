/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023, 2025 NXP                                            */
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

#ifndef MCUXCLSIGNATURE_FUNCTIONS_H_
#define MCUXCLSIGNATURE_FUNCTIONS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClBuffer.h>

#include <mcuxClSession_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSignature_Types.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \defgroup mcuxClSignature_Functions mcuxClSignature_Functions
 * \brief Interfaces to perform Signature operations in one shot.
 * \ingroup mcuxClSignature
 * @{
 */

/**
 * \brief One-shot signing function
 * \api
 *
 * This function performs a signing operation in one shot. The algorithm to be
 * used will be determined based on the key and mode that are provided.
 *
 * For example, to perform an ECDSA signing operation over pre-hashed data
 * with a 256-bit private key, the following needs to be provided:
 *  - ECC256 private key
 *  - ECDSA mode, pre-hashed data
 *  - Input data, hash of the data to be signed
 *  - Output data buffer
 *
 * \param      session        Handle for the current CL session.
 * \param      key            Key to be used to sign the data.
 * \param      mode           Signature mode that should be used during the
 *                            signing operation.
 * \param[in]  pIn            Pointer to the input buffer that contains the
 *                            data that needs to be signed.
 * \param      inSize         Number of bytes of data in the \p pIn buffer.
 * \param[out] pSignature     Pointer to the output buffer where the generated
 *                            signature needs to be written.
 * \param[out] pSignatureSize Will be set to the number of bytes of data
 *                            that have been written to the \p pSignature
 *                            buffer.
 * \return status
 *
 * @attention When used with RSA modes, the function uses PRNG, which has to be initialized prior to calling the function.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSignature_sign)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClSignature_sign(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_Buffer_t pSignature,
  uint32_t * const pSignatureSize
); /* oneshot sign */

/**
 * \brief Record signature verification parameters for protection.
 *
 * Records signature mode, input data pIn and inSize parameters for additional protection.
 * This function must be called immediately before the mcuxClSignature_verify function
 * call when ECDSA mode is requested. Failure to do so will result
 * in a protection token mismatch during the signature verification.
 *
 * @note This function will use the first word of CPU WA (without allocating it)
 *       to store the calculated parameter protection value. This will then be used
 *       by the mcuxClSignature_verify function to validate parameters.
 *
 * \param      pSession      Handle for the current CL session.
 * \param      mode          Signature mode that should be used during the
 *                           verification operation.
 * \param[in]  pIn           Pointer to the input buffer that contains the
 *                           data that has been signed.
 * \param      inSize        Number of bytes of data in the \p pIn buffer.
 *
 * \return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSignature_verify_recordParam)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClSignature_verify_recordParam(
  mcuxClSession_Handle_t pSession,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize
);

/**
 * \brief One-shot verification function
 * \api
 *
 * This function performs a signature verification operation in one shot. The
 * algorithm to be used will be determined based on the key and mode that are
 * provided.
 *
 * For example, to perform an ECDSA signature verification operation with
 * pre-hashed data and a 256-bit public key, the following needs to be provided:
 *  - ECC256 public key
 *  - ECDSA mode, pre-hashed data
 *  - Input data, hash of the data to be verified
 *  - Signature
 *
 * \param      session       Handle for the current CL session.
 * \param      key           Key to be used to verify the \p pSignature.
 * \param      mode          Signature mode that should be used during the
 *                           verification operation.
 * \param[in]  pIn           Pointer to the input buffer that contains the
 *                           data that has been signed.
 * \param      inSize        Number of bytes of data in the \p pIn buffer.
 * \param[in]  pSignature    Pointer to the buffer that contains the signature
 *                           that needs to be verified.
 * \param      signatureSize Number of bytes of data in the \p pSignature
 *                           buffer.
 *
#if defined(MCUXCL_FEATURE_SIGNATURE_VERIFY_PARAMETER_PROTECTION) && defined(MCUXCL_FEATURE_ECC_ECDSA_VERIFY)
 * \note                     When performing ECDSA signature verification: mode, pIn and inSize parameters
 *                           require additional protection using mcuxClSignature_verify_recordParam().
 *                           This will initialize first word of CPU WA with integrity value required by
 *                           mcuxClSignature_verify() to validate parameters.
#endif
 *
 * \return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSignature_verify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClSignature_verify(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClSignature_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_InputBuffer_t pSignature,
  uint32_t signatureSize
); /* oneshot verification */
/** @} */



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSIGNATURE_FUNCTIONS_H_ */
