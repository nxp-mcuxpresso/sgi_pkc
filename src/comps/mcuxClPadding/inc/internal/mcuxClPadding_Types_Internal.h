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

/** @file  mcuxClPadding_Types_Internal.h
 *  @brief Internal type definitions for the mcuxClPadding component
 */

#ifndef MCUXCLPADDING_TYPES_INTERNAL_H_
#define MCUXCLPADDING_TYPES_INTERNAL_H_

#include <stdint.h>
#include <mcuxClConfig.h> // Exported features flags header
#include <internal/mcuxClPadding_Functions_Internal.h>

#include <mcuxClBuffer.h>
#include <mcuxClPadding_Types.h>
#include <mcuxClPadding_Constants.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_Platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function type for a padding functions
 *
 * A padding function padds the last block of a message. If padding is needed, it will copy
 * the incomplete last block of the message @p pIn into the output buffer @p pOut and
 * apply padding to it.
 * The function will trigger an error in case the input block does not meet the requirements
 * for the padding mode.
 *
 * @param      blockLength      The block length of the used block cipher.
 * @param[in]  pIn              Pointer to the input buffer of the block that will be padded.
 * @param      inOffset         Offset in bytes for the input buffer.
 * @param      lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn that contain the last block.
 * @param      totalInputLength Total number of plaintext bytes.
 * @param[out] pOut             Pointer to the output buffer where the padded data
 *                              will be written.
 * @param[out] pOutLength       Length of the data written to @p pOut, including the padding.
 *                              This will either be 0 or @p blockLength.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClPadding_addPaddingMode_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClPadding_addPaddingMode_t)(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength
));

/**
 * @brief Function type for a padding removal functions
 *
 * A padding removal function checks and removes padding in the input @p pIn, if possible,
 * and only copies the remaining bytes of the block to the output buffer @p pOut.
 * The function will trigger an error in case the input block does not meet the requirements
 * for the padding mode, or NOT_OK if the padding is incorrect.
 *
 * @param      blockLength      The block length of the used block cipher.
 * @param[in]  pIn              Pointer to the input buffer of the block which needs
 *                              the padding removed.
 * @param      lastBlockLength  Number of bytes in the last block, i.e. the number of bytes
 *                              in @p pIn that contain the last block (including padding).
 * @param[out] pOut             Pointer to the output buffer where the data
 *                              will be written.
 * @param      outOffset        Offset in bytes for the output buffer.
 * @param[out] pOutLength       Length of the data written to @p pOut.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClPadding_removePaddingMode_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClPadding_removePaddingMode_t)(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
));

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLPADDING_TYPES_INTERNAL_H_ */
