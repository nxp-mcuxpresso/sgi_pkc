/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

#ifndef MCUXCLCIPHERMODES_SGI_FUNCTIONS_H_
#define MCUXCLCIPHERMODES_SGI_FUNCTIONS_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>

#include <mcuxClCore_Platform.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClCipherModes_Sgi_Types.h>
#include <mcuxClDma_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function used for DFA protection.
 *
 * This function is capable of computing en/decryption multiple times (depends on security setting
 * and feature SESSION_SECURITYOPTIONS_ADDITIONAL_SWCOMP) and comparing CRC result
 * of each calculation with each other to determine if any fault was injected in between calculations
 *
 * This function fulfills SREQI_BCIPHER_11
 * Code flow is described in detail in SREQI_BCIPHER_11
 *
 * @param      session      Handle for the current CL session.
 * @param      pContext     Pointer to multipart context
 * @param[in]  pWa          Pointer to cpu workarea
 * @param[in]  pIn          Buffer which holds the input data
 * @param[in]  pOut         Buffer to hold the output data
 * @param[in]  inLength     Length of input data
 * @param[in]  pIvOut       Pointer for the updated Iv
 * @param[in]  pOutLength   Pointer to length of output data
 * @param[in]  pKeyChecksum Pointer to mcuxClKey_KeyChecksum_t
 * @param[in]  cryptEngine  Engine function to do the specified crypt operation
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_crypt)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_crypt(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t *pContext,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t *pIvOut,
  uint32_t * const pOutLength,
  mcuxClKey_KeyChecksum_t* pKeyChecksum,
  mcuxClCipherModes_EngineFunc_AesSgi_t cryptEngine,
  uint32_t protectionToken_cryptEngine
);

/*
 * Skeleton and Engine functions
 */

/**
 * @brief Oneshot encryption with SGI
 *
 * This function starts a normal oneshot encryption operation with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_CryptFunc_t.
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
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_encrypt_Sgi, mcuxClCipher_CryptFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_encrypt_Sgi(
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
 * @brief Oneshot decryption with SGI
 *
 * This function starts a normal oneshot decryption operation with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_CryptFunc_t.
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
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_decrypt_Sgi, mcuxClCipher_CryptFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_decrypt_Sgi(
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
 * @brief Initialize multipart encryption with SGI
 *
 * This function performs a multipart init operation for encryption with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_InitFunc_t.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
 * @param[in]  pKey       Handle for the used key
 * @param[in]  pIv        Pointer to initialization vector
 * @param[in]  ivLength   Length of initialization vector
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_init_encrypt_Sgi, mcuxClCipher_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_init_encrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
);

/**
 * @brief Initialize multipart decryption with SGI
 *
 * This function performs a multipart init operation for decryption with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_InitFunc_t.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
 * @param[in]  pKey       Handle for the used key
 * @param[in]  pIv        Pointer to initialization vector
 * @param[in]  ivLength   Length of initialization vector
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_init_decrypt_Sgi, mcuxClCipher_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_init_decrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
);

/**
 * @brief Initialize multipart decryption with SGI
 *
 * This function performs a multipart init operation for decryption with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_InitFunc_t.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
 * @param[in]  pKey       Handle for the used key
 * @param[in]  pIv        Pointer to initialization vector
 * @param[in]  ivLength   Length of initialization vector
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_init_internal_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_init_internal_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxClCipherModes_Context_Aes_Sgi_t * const pCtx,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
);

/**
 * @brief Multipart process with SGI
 *
 * This function starts a normal multipart process operation with the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_ProcessFunc_t.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
 * @param[in]  pIn        Pointer to the input buffer
 * @param[in]  inLength   Length of the input buffer
 * @param[out] pOut       Pointer to the output buffer
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_process_Sgi, mcuxClCipher_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_process_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Multipart finish with SGI
 *
 * This function performs the finish steps for normal Cipher multipart processing using the SGI.
 * It implements the mode function pointer type @ref mcuxClCipher_FinishFunc_t.
 *
 * This function calls @ref mcuxClCipherModes_finish_encrypt_Sgi or @ref mcuxClCipherModes_finish_decrypt_Sgi,
 * depending on the used multipart finish API function.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to the multipart context
 * @param[out] pOut       Pointer to the output buffer to write the last block(s)
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_finish_Sgi, mcuxClCipher_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Multipart finish for encryption with SGI
 *
 * This function performs the finish steps for normal multipart encryption using the SGI.
 * It implements the context function pointer type @ref mcuxClCipherModes_FinishFunc_AesSgi_t.
 *
 * @param      session    Handle for the current CL session.
 * @param      pWa        Handle for the workarea
 * @param[in]  pContext   Pointer to the multipart context
 * @param[out] pOut       Pointer to the output buffer to write the last block(s)
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_finish_encrypt_Sgi, mcuxClCipherModes_FinishFunc_AesSgi_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_encrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Multipart finish for decryption with SGI
 *
 * This function performs the finish steps for normal multipart decryption using the SGI.
 * It implements the context function pointer type @ref mcuxClCipherModes_FinishFunc_AesSgi_t.
 *
 * @param      session    Handle for the current CL session.
 * @param      pWa        Handle for the workarea
 * @param[in]  pContext   Pointer to the multipart context
 * @param[out] pOut       Pointer to the output buffer to write the last block(s)
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_finish_decrypt_Sgi, mcuxClCipherModes_FinishFunc_AesSgi_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_decrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);

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
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_finish_Sgi_dmaDriven, mcuxClCipher_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);


/*
 * Interrupt Handlers for non-blocking operations
 */

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
 * @return     void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_ISR_completeNonBlocking_oneshot, mcuxClSession_HwInterruptHandler_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_ISR_completeNonBlocking_oneshot(
  mcuxClSession_Handle_t session
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
 * @return     void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_ISR_completeNonBlocking_multipart, mcuxClSession_HwInterruptHandler_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_ISR_completeNonBlocking_multipart(
  mcuxClSession_Handle_t session
);

/**
 * @brief Function to handle DMA errors that occurred during SGI AUTO mode with handshakes.
 *
 * This function cleans up the SGI in case an error happened during/after AUTO mode
 * with DMA handshakes.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_handleDmaError_autoModeNonBlocking)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleDmaError_autoModeNonBlocking(void);

/*
 * Functions to handle the last block of input data after SGI AUTO mode completed
 * */

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
 * @return void
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
 * @return void
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
 * @return void
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCIPHERMODES_SGI_FUNCTIONS_H_ */
