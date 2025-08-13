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

#ifndef MCUXCLCIPHERMODES_SGI_AES_NONBLOCKING_ONESHOT_H_
#define MCUXCLCIPHERMODES_SGI_AES_NONBLOCKING_ONESHOT_H_

/**
 * @brief Dma-driven (non-)blocking encryption with SGI
 *
 * This function starts a Dma-driven (non-)blocking oneshot encryption operation with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_CryptFunc_t.
 *
 * @attention This function does not support multiple software computations.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pKey       Handle for the used key
 * @param[in]  mode       Cipher mode to use for encryption operation
 * @param[in]  pIv        Pointer to initialization vector
 * @param[in]  ivLength   Length of initialization vector
 * @param[in]  pIn        Pointer to the input buffer
 * @param[in]  inLength   Length of the input buffer
 * @param[out] pOut       Pointer to the output buffer
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return status
 *
 * @attention If @ref MCUXCLCIPHER_STATUS_JOB_STARTED is returned, this function started a non-blocking operation.
 * Else, the operation has finished already in a blocking manner.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_encrypt_Sgi_dmaDriven, mcuxClCipher_CryptFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_encrypt_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pKey,
  mcuxClCipher_Mode_t mode,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Dma-driven (non-)blocking decryption with SGI
 *
 * This function starts a Dma-driven (non-)blocking decryption operation with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_CryptFunc_t.
 *
 * @attention This function does not support multiple software computations.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pKey       Handle for the used key
 * @param[in]  mode       Cipher mode to use for decryption operation
 * @param[in]  pIv        Pointer to initialization vector
 * @param[in]  ivLength   Length of initialization vector
 * @param[in]  pIn        Pointer to the input buffer
 * @param[in]  inLength   Length of the input buffer
 * @param[out] pOut       Pointer to the output buffer
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return status
 *
 * @attention If @ref MCUXCLCIPHER_STATUS_JOB_STARTED is returned, this function started a non-blocking operation.
 * Else, the operation has finished already in a blocking manner.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_decrypt_Sgi_dmaDriven, mcuxClCipher_CryptFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_decrypt_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pKey,
  mcuxClCipher_Mode_t mode,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Interrupt callback to complete a non-blocking oneshot operation.
 *
 * This function wraps-up a non-blocking multipart oneshot operation. It is installed as
 * resource interrupt handler to the DMA resources and is executed as part of resource interrupt handling.
 * The Clib callers needs to call @ref mcuxClResource_handle_interrupt after the DMA interrupt
 * (on DONE, or on ERROR) got triggered to also trigger this function.
 *
 * @attention This function triggers the installed user callback in the session. After the callback is done,
 * the function returns back to the resource interrupt handler, see @ref mcuxClResource_handle_interrupt.
 *
 * @param      session    Handle for the current CL session.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_ISR_completeNonBlocking_oneshot, mcuxClSession_HwInterruptHandler_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_ISR_completeNonBlocking_oneshot(
  mcuxClSession_Handle_t session
);

/**
 * @brief Process the last block for DMA-driven (non-)blocking encryption
 *
 * This function handles the processing of the last block for encryption.
 * Therefore it takes also care of padding.
 *
 * @param[in]      session           Handle for the current CL session.
 * @param[in]      pWa               Handle for the current workarea
 * @param[in]      pAlgo             Pointer to the algorithm descriptor
 * @param[in]      pIn               Pointer to last block input data
 * @param[in]      inOffset          Offset of the @p pIn buffer
 * @param[in]      totalInputLength  Total size of input in bytes
 * @param[in]      pOut              Pointer to expected last block output
 * @param[in]      outOffset         Offset of the @p pOut buffer
 * @param[in,out]  pOutLength        Pointer to the total output length
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_handleLastBlock_enc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleLastBlock_enc(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t totalInputLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief Process the last block for DMA-driven (non-)blocking decryption
 *
 * This function handles the processing of the last block for decryption.
 * Therefore it takes care of padding removal.
 *
 * @param[in]      session           Handle for the current CL session.
 * @param[in]      pWa               Handle for the current workarea
 * @param[in]      pAlgo             Pointer to the algorithm descriptor
 * @param[in]      pIn               Pointer to last block input data
 * @param[in]      inOffset          Offset of the @p pIn buffer
 * @param[in]      totalInputLength  Total size of input in bytes
 * @param[in]      pOut              Pointer to expected last block output
 * @param[in]      outOffset         Offset of the @p pOut buffer
 * @param[in,out]  pOutLength        Pointer to the total output length
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_handleLastBlock_dec)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleLastBlock_dec(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t totalInputLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

#endif /* MCUXCLCIPHERMODES_SGI_AES_NONBLOCKING_ONESHOT_H_ */
