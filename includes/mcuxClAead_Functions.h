/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
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

/** @file  mcuxClAead_Functions.h
 *  @brief Top-level API of the mcuxClAead component */

#ifndef MCUXCLAEAD_FUNCTIONS_H_
#define MCUXCLAEAD_FUNCTIONS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession_Types.h>
#include <mcuxClKey.h>
#include <mcuxClAead_Types.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClAead_Functions mcuxClAead_Functions
 * @brief Interfaces to perform AEAD operations.
 * @ingroup mcuxClAead
 * @{
 */

/**
 * @brief One-shot authenticated encryption function
 * @api
 * @ingroup clAeadOneShot
 *
 * This function performs an authenticated encryption operation in one shot.
 * The algorithm to be used will be determined based on the key that is
 * provided.
 *
 * For example, to perform an AES authenticated encryption operation with a
 * 128-bit key in CCM mode on padded data, the following needs to be provided:
 *  - AES128 key
 *  - CCM mode
 *  - Nonce
 *  - Plain input data
 *  - Associated data
 *  - Output data buffer
 *  - Output length buffer, to store the amount of written bytes
 *  - Tag buffer, to store the authentication tag
 *
 * @param      session     Handle for the current CL session.
 * @param      key         Key to be used to encrypt the data.
 * @param      mode        AEAD mode that should be used during the encryption
 *                         operation.
 * @param[in]  pNonce      Pointer to the buffer that contains the nonce.
 * @param      nonceLength Number of bytes of nonce data in the \p nonce buffer.
 * @param[in]  pIn         Pointer to the input buffer that contains the plain
 *                         data that need to be authenticated and encrypted.
 * @param      inLength    Number of bytes of plain data in the \p in buffer.
 * @param[in]  pAdata      Associated data for the authenticated encryption
 *                         operation. Data format depends on the chosen \p mode.
 * @param      adataLength Number of bytes of associated data in the \p adata
 *                         buffer.
 * @param[out] pOut        Pointer to the output buffer where the authenticated
 *                         encrypted data needs to be written.
 * @param[out] pOutLength  Will be set to the number of bytes of
 *                         authenticated encrypted data that have been written
 *                         to the \p out buffer.
 * @param[out] pTag        Pointer to the output buffer where the tag needs to
 *                         be written.
 * @param      tagLength   Number of bytes of tag data that will be written to
 *                         the \p tag buffer.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_encrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_encrypt(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  mcuxCl_Buffer_t pTag,
  uint32_t tagLength
);

/**
 * @brief One-shot authenticated decryption function
 * @api
 * @ingroup clAeadOneShot
 *
 * This function performs an authenticated decryption operation in one shot.
 * The algorithm to be used will be determined based on the key that is
 * provided.
 *
 * For example, to perform an AES authenticated decryption operation with a
 * 128-bit key in CCM mode on padded data, the following needs to be provided:
 *  - AES128 key
 *  - CCM mode
 *  - Nonce
 *  - Encrypted input data, length must be a multiple of the AES block size
 *  - Associated data
 *  - Authentication tag
 *  - Output data buffer
 *  - Output length buffer
 *
 * @param      session     Handle for the current CL session.
 * @param      key         Key to be used to decrypt the data.
 * @param      mode        AEAD mode that should be used during the decryption
 *                         operation.
 * @param[in]  pNonce      Pointer to the buffer that contains the nonce.
 * @param      nonceLength Number of bytes of nonce data in the \p nonce buffer.
 * @param[in]  pIn         Pointer to the input buffer that contains the
 *                         encrypted data that need to be authenticated and
 *                         decrypted.
 * @param      inLength    Number of bytes of encrypted data in the \p in buffer.
 * @param[in]  pAdata      Associated data for the authenticated decryption
 *                         operation. Data format depends on the chosen \p mode.
 * @param      adataLength Number of bytes of associated data in the \p adata
 *                         buffer.
 * @param[in]  pTag        Pointer to the buffer that contains the tag.
 * @param      tagLength   Number of bytes of tag data in the \p tag buffer.
 * @param[out] pOut        Pointer to the output buffer where the plain data
 *                         needs to be written.
 * @param[out] pOutLength  Will be set to the number of bytes of plain
 *                         data that have been written to the \p out buffer.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_decrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength,
  mcuxCl_InputBuffer_t pTag,
  uint32_t tagLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Multi-part authenticated encryption initialization function
 * @api
 * @ingroup clAeadMultiPart
 *
 * This function performs the initialization for a multi part authenticated
 * encryption operation. The algorithm to be used will be determined based on
 * the key that is provided.
 *
 * @param      session     Handle for the current CL session.
 * @param      pContext    AEAD context which is used to maintain the state and
 *                         store other relevant information about the operation.
 * @param      key         Key to be used to encrypt the data.
 * @param      mode        AEAD mode that should be used during the encryption
 *                         operation.
 * @param[in]  pNonce      Pointer to the buffer that contains the nonce.
 * @param      nonceLength Number of bytes of nonce data in the \p nonce buffer.
 * @param      inLength    Number of bytes of plain data that will be processed.
 * @param      adataLength Number of bytes of associated data that will be
 *                         processed.
 * @param      tagLength   Number of bytes to be used for the authentication tag.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_init_encrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_init_encrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength
); /* init encrypt */

/**
 * @brief Multi-part authenticated decryption initialization function
 * @api
 * @ingroup clAeadMultiPart
 *
 * This function performs the initialization for a multi part authenticated
 * decryption operation. The algorithm to be used will be determined based on
 * the key that is provided.
 *
 * @param      session     Handle for the current CL session.
 * @param      pContext    AEAD context which is used to maintain the state and
 *                         store other relevant information about the operation.
 * @param      key         Key to be used to encrypt the data.
 * @param      mode        AEAD mode that should be used during the encryption
 *                         operation.
 * @param[in]  pNonce      Pointer to the buffer that contains the nonce.
 * @param      nonceLength Number of bytes of nonce data in the \p nonce buffer.
 * @param      inLength    Number of bytes of encrypted data that will be
 *                         processed.
 * @param      adataLength Number of bytes of associated data that will be
 *                         processed.
 * @param      tagLength   Number of bytes used for the authentication tag.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_init_decrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_init_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength
); /* init decrypt */

/**
 * @brief Multi-part authenticated encryption/decryption processing function
 * for the regular data (authenticated and encrypted)
 * @api
 *
 * This function performs the processing of (a part of) a data stream for an
 * authenticated encryption/decryption operation. The algorithm and key to be
 * used will be determined based on the context that is provided.
 *
 * @param      session    Handle for the current CL session.
 * @param      pContext   AEAD context which is used to maintain the state and
 *                        store other relevant information about the operation.
 * @param[in]  pIn        Pointer to the input buffer that contains the data
 *                        that needs to be processed.
 * @param      inLength   Number of bytes of data in the @p in buffer.
 * @param[out] pOut       Pointer to the output buffer where the processed data
 *                        needs to be written.
 * @param[out] pOutLength Will be set to the number of bytes of
 *                        processed data that have been written to the @p out
 *                        buffer.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_process)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_process(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
); /* update */

/**
 * @brief Multi-part authenticated encryption/decryption processing function
 * for the associated data (authenticated only)
 * @api
 *
 * This function performs the processing of (a part of) an associated data
 * stream for an authenticated encryption/decryption operation. The algorithm
 * and key to be used will be determined based on the context that is provided.
 *
 * @param      session     Handle for the current CL session.
 * @param      pContext    AEAD context which is used to maintain the state and
 *                         store other relevant information about the operation.
 * @param[in]  pAdata      Associated data that needs to be proccessed.
 * @param      adataLength Number of bytes of associated data in the @p adata
 *                         buffer.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_process_adata)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_process_adata(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength
); /* update associated data */

/**
 * @brief Multi-part authenticated encryption/decryption finalization function
 * @api
 *
 * This function performs the finalization of an authenticated encryption or
 * decryption operation and produces the authentication tag. The algorithm and
 * key to be used will be determined based on the context that is provided.
 *
 * Note: the taglength is already specified when the INIT function is called.
 *
 * @param      session     Handle for the current CL session.
 * @param      pContext    AEAD context which is used to maintain the state and
 *                         store other relevant information about the operation.
 * @param[out] pOut        Pointer to the output buffer where the processed data
 *                         needs to be written.
 * @param[out] pOutLength  Will be set to the number of bytes of
 *                         processed data that have been written to the @p out
 *                         buffer.
 * @param[out] pTag        Pointer to the output buffer where the tag needs to
 *                         be written.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_finish)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_finish(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  mcuxCl_Buffer_t pTag
); /* finalize encrypt/decrypt + output tag */

/**
 * @brief Multi-part authenticated decryption verification function
 * @api
 *
 * This function performs the finalization of an authenticated decryption
 * operation and verifies the authentication tag. The algorithm and key to be
 * used will be determined based on the context that is provided.
 *
 * This function can be used as an alternative for @p mcuxClAead_finish when one
 * also wants to perform the tag verification step.
 *
 * Note: the taglength is already specified when the INIT function is called.
 *
 * @param      session    Handle for the current CL session.
 * @param      pContext   AEAD context which is used to maintain the state and
 *                        store other relevant information about the operation.
 * @param[in]  pTag       Pointer to the buffer that contains the tag.
 * @param[out] pOut       Pointer to the output buffer where the authenticated
 *                        decrypted data needs to be written.
 * @param[out] pOutLength Will be set to the number of bytes of
 *                        authenticated decrypted data that have been written
 *                        to the @p out buffer.
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAead_verify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_verify(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pTag,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
); /* finalize decrypt + compare tag */

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAEAD_FUNCTION_H_ */
