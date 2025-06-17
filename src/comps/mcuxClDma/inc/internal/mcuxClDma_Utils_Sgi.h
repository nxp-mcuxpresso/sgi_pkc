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
 * @file  mcuxClDma_Utils_Sgi.h
 * @brief Utils-layer of the mcuxClDma component to handle data transfer to/from
 *        the SGI peripheral.
 */

#ifndef MCUXCLDMA_UTILS_SGI_H_
#define MCUXCLDMA_UTILS_SGI_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClSgi_Drv.h>
#include <mcuxClSession.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClDma_Utils_Sgi mcuxClDma_Utils_Sgi
 * @brief Defines the Utils layer of the @ref mcuxClDma component for communication
 *        with the SGI peripheral.
 * @ingroup mcuxClDma_Utils
 * @{
 */

/*
 * @limitation
 * The max value of the CITER/BITER field is 0x7FFFu due to the SFR field size of 15-bit.
 * This limits the amount of hardware requests (or, major loops) that can be performed with SGI-DMA-handshakes
 * in a single DMA channel configuration, which directly leads to a limitation on the number of AES blocks
 * that can be handled with a single SGI AUTOMODE operation using handshakes.
 */
#define MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_NUMBER_OF_BLOCKS (0x7fffu)
#define MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE (MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_NUMBER_OF_BLOCKS * MCUXCLAES_BLOCK_SIZE)

/**
 * @defgroup mcuxClDma_Utils_Sgi_Functions mcuxClDma_Utils_Sgi_Functions
 * @brief Functions of the Utils layer of the @ref mcuxClDma component
 * @ingroup mcuxClDma_Utils_Sgi
 * @{
 */

/**
 * @brief Configure the DMA input channel to load data to SGI SHA2 FIFO register.
 *
 * This function configures the DMA input channel associated to the session to copy
 * data from the @p pSrc buffer to the SGI SHA2 FIFO register.
 *
 * @param     session             Handle of the current session.
 * @param[in] pSrc                Pointer to the source data location.
 * @param     srcLength           size of the source data
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_configureSgiSha2InputChannel)
void mcuxClDma_Utils_configureSgiSha2InputChannel(
  mcuxClSession_Handle_t session,
  const uint8_t *pSrc,
  uint32_t srcLength
);

/**
 * @brief Configure the given DMA input channel to load data to an SGI data register.
 *
 * This function configures the DMA input channel associated to the session to copy
 * data from the @p pSrc buffer to the given SGI data register.
 * To transfer one block of data, continue with @ref mcuxClDma_Utils_startTransferOneBlock,
 * which can be called multiple times without needing to re-configure the channel.
 *
 * @param    session             Handle of the current session.
 * @param    sgiSfrDataRegOffset Offset of the target SGI SFR,
 *                               can be either of these values:
 *                               #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                               #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                               #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                               #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                               #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in] pSrc               Pointer to the source data location.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_configureSgiInputChannel)
void mcuxClDma_Utils_configureSgiInputChannel(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDataRegOffset,
  const uint8_t *pSrc
);

/**
 * @brief Configure the DMA output channel to store data from an SGI data register.
 *
 * This function configures the DMA output channel associated to the session to copy
 * data from the given SGI data register to the @p pDst buffer.
 * To transfer one block of data, continue with @ref mcuxClDma_Utils_startTransferOneBlock,
 * which can be called multiple times without needing to re-configure the channel.
 *
 * @param    session             Handle of the current session.
 * @param    sgiSfrDataRegOffset Offset of the source SGI SFR,
 *                               can be either of these values:
 *                               #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                               #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                               #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                               #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                               #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in] pDst               Pointer to the destination data location.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_configureSgiOutputChannel)
void mcuxClDma_Utils_configureSgiOutputChannel(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDataRegOffset,
  uint8_t *pDst
);

/**
 * @brief Start the DMA channel to transfer one block of data.
 *
 * This function configures the DMA channel to transfer one block (16-byte) of data,
 * and start the channel.
 *
 * @param channel           DMA channel to start
 *
 * @pre:
 *  - This function assumes the DMA channel is otherwise already configured, for example
 *    see @ref mcuxClDma_Utils_configureSgiInputChannel and @ref mcuxClDma_Utils_configureSgiOutputChannel.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_startTransferOneBlock)
void mcuxClDma_Utils_startTransferOneBlock(
  mcuxClSession_Channel_t channel
);

/**
 * @brief Configure the DMA input channel to automatically write multiple blocks
 *        to SGI by using DMA-SGI-handshake signals.
 *
 * This function configures the DMA input channel associated to the session to copy
 * data from the @p pSrc buffer to the given SGI DATIN register.
 *
 * To configure the data size to transfer, use @ref mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks.
 * To start the transaction, configure and start the SGI in AUTO mode with handshake signals.
 *
 * @param     session                Handle of the current session.
 * @param     sgiSfrDatInOffset      Offset of the target DATIN SGI SFR,
 *                                   can be either of these values:
 *                                   #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                   #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                   #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                   #MCUXCLSGI_DRV_DATIN3_OFFSET
 * @param[in] pSrc                   Pointer to the source data location.
 *
 * @pre
 *  - inputBlocks must be in [1, MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_NUMBER_OF_BLOCKS].
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_configureSgiInputWithHandshakes)
void mcuxClDma_Utils_configureSgiInputWithHandshakes(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDatInOffset,
  const uint8_t *pSrc
);

/**
 * @brief Set the number of AES blocks to write to SGI using input handshake signals.
 *
 * This function configures the DMA input channel associated to the session to copy
 * @p inputBlocks blocks of data to the SGI using input handshake signals with the SGI.
 * Assumes @ref mcuxClDma_Utils_configureSgiInputWithHandshakes was called for general setup.
 *
 * @param session                Handle of the current session.
 * @param inputBlocks            Total number of AES blocks to copy.
 *
 * @pre
 *  - inputBlocks must be in [1, MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_NUMBER_OF_BLOCKS].
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks)
void mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks(
  mcuxClSession_Handle_t session,
  uint32_t inputBlocks
);

/**
 * @brief Configure the DMA channels to automatically write/read multiple blocks
 *        to/from SGI by using DMA-SGI-handshake signals.
 *
 * This function configures the DMA channels associated to the session to copy data to the SGI
 * using handshake signals.The input channel to copy from the @p pSrc buffer to the given SGI
 * DATIN register and the output channel to copy data from the SGI DATOUT register to the
 * @p pDst buffer.
 *
 * If no output channel is needed (i.e. for a MAC), use @ref mcuxClDma_Utils_configureSgiInputWithHandshakes.
 *
 * To configure the data sizes to transfer, use @ref mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks.
 * To start the transaction, configure and start the SGI in AUTO mode with handshake signals.
 *
 * @param     session                Handle of the current session.
 * @param     sgiSfrDatInOffset      Offset of the target DATIN SGI SFR,
 *                                   can be either of these values:
 *                                   #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                   #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                   #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                   #MCUXCLSGI_DRV_DATIN3_OFFSET
 * @param[in] pSrc                   Pointer to the source data location.
 * @param[in] pDst                   Pointer to the destination data location
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_configureSgiTransferWithHandshakes)
void mcuxClDma_Utils_configureSgiTransferWithHandshakes(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDatInOffset,
  const uint8_t *pSrc,
  uint8_t *pDst
);

/**
 * @brief Set the number of AES blocks to write to SGI using input handshake signals.
 *
 * This function configures the DMA channels associated to the session to copy the given amount
 * of blocks (16-byte) to/from the SGI using handshake signals with. The input channel to copy
 * @p inputBlocks blocks of data to SGI and the output channel to copy @p outputBlocks blocks
 * of data from SGI.
 *
 * @param session         Handle of the current session.
 * @param inputBlocks     Total number of AES blocks to send to the SGI.
 * @param outputBlocks    Total number of AES blocks to read from the SGI.
 *
 * @pre
 *  - This function assumes @ref mcuxClDma_Utils_configureSgiTransferWithHandshakes was called for general setup.
 *  - inputBlocks must be in [1, MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_NUMBER_OF_BLOCKS].
 *  - outputBlocks must be in [1, MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_NUMBER_OF_BLOCKS].
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks)
void mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks(
  mcuxClSession_Handle_t session,
  uint32_t inputBlocks,
  uint32_t outputBlocks
);


/**
 * @}
 */ /* mcuxClDma_Utils_Sgi_Functions */

/**
 * @}
 */ /* mcuxClDma_Utils_Sgi */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLDMA_UTILS_SGI_H_ */
