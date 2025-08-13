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

#ifndef MCUXCLCIPHERMODES_SGI_AES_MULTIPART_H_
#define MCUXCLCIPHERMODES_SGI_AES_MULTIPART_H_


#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>

#include <mcuxClCore_Platform.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClCipherModes_Sgi_Types.h>

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
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_finish_decrypt_Sgi, mcuxClCipherModes_FinishFunc_AesSgi_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_decrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
);


#endif /* MCUXCLCIPHERMODES_SGI_AES_MULTIPART_H_ */
