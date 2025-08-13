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

#ifndef MCUXCLCIPHERMODES_SGI_AES_ONESHOT_H_
#define MCUXCLCIPHERMODES_SGI_AES_ONESHOT_H_

#include <mcuxClCore_Platform.h>

#include <mcuxClBuffer.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession.h>

#include <internal/mcuxClCipherModes_Sgi_Types.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>

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
  uint32_t* const pOutLength
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
  uint32_t* const pOutLength
);

#endif /* MCUXCLCIPHERMODES_SGI_AES_ONESHOT_H_ */
