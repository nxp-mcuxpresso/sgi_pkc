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

#ifndef MCUXCLCIPHERMODES_SGI_AES_NONBLOCKING_MULTIPART_H_
#define MCUXCLCIPHERMODES_SGI_AES_NONBLOCKING_MULTIPART_H_

/**
 * @brief Dma-driven (non-)blocking multipart process with SGI
 *
 * This function starts a Dma-driven (non-)blocking multipart process operation with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_ProcessFunc_t.
 *
 * @attention This function does not support multiple software computations.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
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
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_process_Sgi_dmaDriven, mcuxClCipher_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_process_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Dma-driven (non-)blocking multipart finish with SGI
 *
 * This function performs the finish steps for Dma-driven (non-)blocking
 * multipart processing using the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_FinishFunc_t.
 *
 * This function calls @ref mcuxClCipherModes_finish_encrypt_Sgi or @ref mcuxClCipherModes_finish_decrypt_Sgi,
 * depending on the used multipart finish API function.
 *
 * @attention This function does not support multiple software computations.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
 * @param[out] pOut       Pointer to the output buffer to write the last block(s)
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_finish_Sgi_dmaDriven, mcuxClCipher_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Process the last block for DMA-driven (non-)blocking multipart process
 *
 * This function handles the last block for a DMA-driven (non-)blocking process operation.
 * It also updates the Ctx for the next process call.
 *
 * @param[in]      session           Handle for the current CL session.
 * @param[in,out]  pWa               Handle for the current workarea
 * @param[in,out]  pCtx              Handle for the multipart context
 * @param[in]      pAlgo             Pointer to the algorithm descriptor
 * @param[in]      lastBlockRemainingBytes  Amount of unprocessed bytes in the input buffer
 * @param[in]      pIn               Pointer to current last block of input data
 * @param[in]      inOffset          Offset of the @p pIn buffer
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_handleLastBlock_process)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleLastBlock_process(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipherModes_Context_Aes_Sgi_t *pCtx,
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockRemainingBytes
);

/**
 * @brief Interrupt callback to complete a non-blocking multipart operation.
 *
 * This function wraps-up a non-blocking multipart process operation. It is installed as
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
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_ISR_completeNonBlocking_multipart, mcuxClSession_HwInterruptHandler_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_ISR_completeNonBlocking_multipart(
  mcuxClSession_Handle_t session
);

#endif /* MCUXCLCIPHERMODES_SGI_AES_NONBLOCKING_MULTIPART_H_ */
