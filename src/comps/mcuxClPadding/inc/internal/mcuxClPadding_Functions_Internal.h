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

/**
 * @file  mcuxClPadding_Functions_Internal.h
 * @brief Functions of the padding component.
 */

#ifndef MCUXCLPADDING_FUNCTIONS_INTERNAL_H
#define MCUXCLPADDING_FUNCTIONS_INTERNAL_H

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClPadding_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief No-padding function, which adds no padding at all
 * @api
 *
 * This function throws an error if @p lastBlockLength is anything other than zero,
 * and does nothing (adding no padding) and returns OK otherwise.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be 0.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_None, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_None(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);

/**
 * @brief No-padding removal function, which removes no padding
 * @api
 *
 * This function copies @p blockLength bytes to the output buffer.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be equal to @p blockLength.
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              needs to be written.
 * @param[in]  outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_removePadding_None, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_None(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief Default adding removal function.
 * @api
 *
 * This function copies @p lastBlockLength bytes to @p pOut.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes in
 *                              @p pIn. Must be greater than 0 and less than or equal to @p blockLength.
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              needs to be written.
 * @param[in]  outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_removePadding_Default, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_Default(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief Zero-padding function, which pads a block with zeroes in the end.
 * @api
 *
 * This function copies @p lastBlockLength bytes to @p pOut and fills the
 * remainder with zeroes.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be smaller than @p blockLength.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_ISO9797_1_Method1, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_ISO9797_1_Method1(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Zero-padding removal function, which removes no padding.
 * @api
 *
 * This function throws an error if @p lastBlockLength is anything other than
 * @p blockLength, and copies @p blockLength bytes to the output buffer,
 * including possible zero-padding bytes, and returns OK otherwise.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be equal to @p blockLength.
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              needs to be written.
 * @param[in]  outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_removePadding_ISO9797_1_Method1, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_ISO9797_1_Method1(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief ISO/IEC 9797-1 padding method 2 function.
 * @api
 *
 * This function adds a single bit with value 1 after the data and fills the
 * remaining block with zeroes.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be smaller than @p blockLength.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_ISO9797_1_Method2, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_ISO9797_1_Method2(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);

/**
 * @brief ISO/IEC 9797-1 padding method 2 function.
 * @api
 *
 * This function adds a single bit with value 1 after the data and fills the
 * remaining block with zeroes for CMAC mode using.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be smaller than or equal to @p blockLength.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_MAC_ISO9797_1_Method2(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);
/**
 * @brief ISO/IEC 9797-1 method 2 padding removal function.
 * @api
 *
 * This function checks and removes the ISO/IEC 9797-1 method 2 padding according to standard.
 * It returns NOT_OK if the padding is incorrect,
 * returns an error if the @p lastBlockLength is not equal to @p blockLength,
 * and removes the padding, copies the remaining bytes to @p pOut and returns OK otherwise.
 * The random masking byte depends on a call to @ref mcuxClRandom_ncInit.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed. This buffer can be overwritten for secure padding removal.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be equal @p blockLength.
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              needs to be written.
 * @param[in]  outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_removePadding_ISO9797_1_Method2, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_ISO9797_1_Method2(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief PKCS7 padding function.
 * @api
 *
 * This function adds PKCS7 padding according to rfc2315, it adds the remaning
 * bytes in the block with the value equal to the total number of added bytes.
 * The random masking byte depends on a call to @ref mcuxClRandom_ncInit.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be smaller than @p blockLength.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_PKCS7, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_PKCS7(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);

/**
 * @brief PKCS7 padding removal function.
 * @api
 *
 * This function checks and removes PKCS7 padding according to rfc2315.
 * It returns NOT_OK if the padding is incorrect,
 * returns an error if the @p lastBlockLength is not equal to @p blockLength,
 * and removes the padding, copies the remaining bytes to @p pOut and returns OK otherwise.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed. This buffer can be overwritten for secure padding removal.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn. Must be equal @p blockLength.
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              needs to be written.
 * @param[in]  outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_removePadding_PKCS7, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_PKCS7(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief Random-padding function, which pads a block with random bytes in the end.
 * @api
 *
 * This function copies @p lastBlockLength bytes to @p pOut and fills the
 * remainder with random bytes.
 * The random bytes depend on a call to @ref mcuxClRandom_ncInit.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes in
 *                              @p pIn. Must be greater than 0 and less than or equal to @p blockLength.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_Random, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_Random(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);

/**
 * @brief Padding removal function for block ciphers in streaming mode.
 * @api
 *
 * This function copies @p lastBlockLength bytes to @p pOut, as streaming
 * modes do not have any padding to remove.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes in
 *                              @p pIn. Must be greater than 0 and less than or equal to @p blockLength.
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              needs to be written.
 * @param[in]  outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_removePadding_Stream, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_Stream(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
);

/**
 * @brief Padding function for block ciphers in streaming mode.
 * @api
 *
 * This function performs checks on @p lastBlockLength and depending on its value
 * calls @ref mcuxClPadding_addPadding_Random.
 *
 * @param[in]  blockLength      The block length of the used block cipher.
 *
 * @param[in]  pIn              Pointer to the input buffer of the block that will
 *                              be padded.
 * @param[in]  inOffset         Offset in bytes for the input buffer.
 * @param[in]  lastBlockLength  Number of bytes in the last block, i.e. the number of bytes in
 *                              @p pIn. Must be smaller than or equal @p blockLength.
 * @param[in]  totalInputLength Total number of plaintext/ciphertext bytes.
 *
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              needs to be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPadding_addPadding_Stream, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_Stream(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLPADDING_FUNCTIONS_INTERNAL_H */

