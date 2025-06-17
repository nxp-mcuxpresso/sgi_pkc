/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file  mcuxClDma_Utils.h
 * @brief Utils-layer of the mcuxClDma component.
 */

#ifndef MCUXCLDMA_UTILS_H_
#define MCUXCLDMA_UTILS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClDma_Drv.h>
#include <mcuxClDma_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClDma_Utils mcuxClDma_Utils
 * @brief Defines the Utils layer of the @ref mcuxClDma component.
 * @ingroup mcuxClDma
 * @{
 */


/**
 * @defgroup mcuxClDma_Utils_Functions mcuxClDma_Utils_Functions
 * @brief Functions of the Utils layer of the @ref mcuxClDma component
 * @ingroup mcuxClDma_Utils
 * @{
 */

/**
 * @brief Calculates the DMA TCD (source or destination) offset and size
 *        based on the alignment of the given address.
 *
 * The offset can be written to the DMA TCDn.SOFF or TCDn_DOFF register.
 * The size can be written to the TCDn_ATTR.SSIZE or TCDn_ATTR.DSIZE register field.
 *
 * @param[in]   pAddr    Source or destination address for the DMA channel.
 * @param[out]  pOffset  The calculated offset
 * @param[out]  pSize    The calculated size
 * @param       size     The total transfer size
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment)
void mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(
  const uint8_t *pAddr,
  uint16_t *pOffset,
  uint16_t *pSize,
  uint32_t size);

/**
 * @brief Configures the given DMA channel for data transfer of arbitrary size.
 *
 * This function will configure the given DMA channel to copy @p length
 * bytes from @p pSrc to @p pDst.
 * The access sizes and offsets will be set based on the given address alignments,
 * i.e. if both addresses are word-aligned, word-wise access will be used (if the
 * requested data length allows it).
 *
 * @attention:
 * Address alignment of both addresses does not guarantee a word-wise transfer.
 * Byte-wise data transfer will be configured if the given length is not a multiple of the
 * word length.
 *
 * @param       channel  DMA channel that should be used
 * @param[in]   pSrc     Source address
 * @param[in]   pDst     Destination address
 * @param       length   Amount of bytes to copy from source to destination.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_configureDataTransfer)
void mcuxClDma_Utils_configureDataTransfer(
  mcuxClSession_Channel_t channel,
  const uint8_t *pSrc,
  uint8_t *pDst,
  uint32_t length);


/**
 * @}
 */ /* mcuxClDma_Utils_Functions */

/**
 * @}
 */ /* mcuxClDma_Utils */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLDMA_UTILS_H_ */
