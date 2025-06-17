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

#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClDma_Utils.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Sfr.h>
#include <mcuxClAes_Constants.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Sfr_RegBank.h>
#include <internal/mcuxClSession_Internal_Functions.h>


/** Write the destination address of a DMA channel TCD to point to an SGI DAT (DATIN or DATOUT) register. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_writeDstAddress_Sgi)
static void mcuxClDma_Utils_writeDstAddress_Sgi(
  mcuxClSession_Channel_t channel,
  uint32_t sgiSfrDataRegOffset)
{
  mcuxClDma_Drv_writeDstAddress(channel, (uint8_t *)mcuxClSgi_Drv_getAddr(sgiSfrDataRegOffset));
}

/** Write the destination address of a DMA channel TCD to point to an SGI DAT (DATIN or DATOUT) register. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_writeSrcAddress_Sgi)
static void mcuxClDma_Utils_writeSrcAddress_Sgi(
  mcuxClSession_Channel_t channel,
  uint32_t sgiSfrDataRegOffset)
{
  mcuxClDma_Drv_writeSrcAddress(channel, (const uint8_t *)mcuxClSgi_Drv_getAddr(sgiSfrDataRegOffset));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_configureSgiSha2InputChannel)
void mcuxClDma_Utils_configureSgiSha2InputChannel(
  mcuxClSession_Handle_t session,
  const uint8_t *pSrc,
  uint32_t srcLength)
{
  /*
   * Write the TCD of the input channel
   */
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  uint16_t srcOffset = 0u;
  uint16_t srcSize = 0u;
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pSrc, &srcOffset, &srcSize, srcLength);

  mcuxClDma_Drv_writeSrcAddress(inputChannel, pSrc);
  mcuxClDma_Drv_writeSrcOffset(inputChannel, srcOffset);
  mcuxClDma_Utils_writeDstAddress_Sgi(inputChannel, MCUXCLSGI_DRV_SHAFIFO_OFFSET);
  mcuxClDma_Drv_writeDstOffset(inputChannel, MCUXCLDMA_DRV_OFFSET_INCR_DIS); /* Do not modify address of SGI_SHAFIFO */
  mcuxClDma_Sfr_writeTransferAttributes(inputChannel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE(srcSize)
                                                | MCUXCLDMA_DRV_DST_ACCESS_SIZE_4_BYTE);
  /* Do not adjust the source address, such that this channel can be continued without re-configuring the TCD */
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Do not adjust the destination address, it always point to SHA FIFO */
  mcuxClDma_Drv_writeLastDstAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  mcuxClDma_Sfr_writeTCDControlAndStatus(inputChannel, 0u);
  mcuxClDma_Drv_writeMajorLoopCounts(inputChannel, 1);
  mcuxClDma_Drv_writeTransferSize(inputChannel, srcLength);
}

/** Configure the given DMA channel to load data to an SGI DATIN register. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_configureSgiInputChannel)
void mcuxClDma_Utils_configureSgiInputChannel(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDataRegOffset,
  const uint8_t *pSrc)
{
  /*
   * Write the TCD of the input channel
   */
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  uint16_t srcOffset = 0u;
  uint16_t srcSize = 0u;
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pSrc, &srcOffset, &srcSize, MCUXCLAES_BLOCK_SIZE);

  mcuxClDma_Drv_writeSrcAddress(inputChannel, pSrc);
  mcuxClDma_Drv_writeSrcOffset(inputChannel, srcOffset);
  mcuxClDma_Utils_writeDstAddress_Sgi(inputChannel, sgiSfrDataRegOffset);
  mcuxClDma_Drv_writeDstOffset(inputChannel, MCUXCLDMA_DRV_OFFSET_INCR_DIS); /* Do not modify address of SGI_DATINx */
  mcuxClDma_Sfr_writeTransferAttributes(inputChannel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE(srcSize)
                                                | MCUXCLDMA_DRV_DST_ACCESS_SIZE_16_BYTE);
  /* Do not adjust the source address, such that this channel can be continued without re-configuring the TCD */
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Do not adjust the destination address, it always point to SGI_DATINx */
  mcuxClDma_Drv_writeLastDstAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  mcuxClDma_Sfr_writeTCDControlAndStatus(inputChannel, 0u);
}

/** Configure the given DMA channel to store data from the SGI DATOUT register */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_configureSgiOutputChannel)
void mcuxClDma_Utils_configureSgiOutputChannel(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDataRegOffset,
  uint8_t *pDst)
{
  /*
   * Write the TCD of the output channel
   */
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);
  uint16_t dstOffset = 0u;
  uint16_t dstSize = 0u;
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pDst, &dstOffset, &dstSize, MCUXCLAES_BLOCK_SIZE);

  mcuxClDma_Utils_writeSrcAddress_Sgi(outputChannel, sgiSfrDataRegOffset);
  mcuxClDma_Drv_writeSrcOffset(outputChannel, MCUXCLDMA_DRV_OFFSET_INCR_DIS); /* Do not modify address of SGI_DATOUT */
  mcuxClDma_Drv_writeDstAddress(outputChannel, pDst);
  mcuxClDma_Drv_writeDstOffset(outputChannel, dstOffset);
  mcuxClDma_Sfr_writeTransferAttributes(outputChannel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE_16_BYTE
                                                | MCUXCLDMA_DRV_DST_ACCESS_SIZE(dstSize));
  /* Do not adjust the src address, it always point to SGI_DATOUT */
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(outputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Do not adjust the destination address, such that this channel can be continued without re-configuring the TCD */
  mcuxClDma_Drv_writeLastDstAddrAdjustment(outputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  mcuxClDma_Sfr_writeTCDControlAndStatus(outputChannel, 0u);
}

/** Continue/Start the data transfer for an already configured channel.
    If functions mcuxClDma_Utils_configureSgiInputChannel/mcuxClDma_Utils_configureSgiOutputChannel
    were used to configure the channel, the SGI DATIN/DATOUT registers in the channel are correctly
    re-adjusted in the channel TCD. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_startTransferOneBlock)
void mcuxClDma_Utils_startTransferOneBlock(
  mcuxClSession_Channel_t channel)
{
  /* Transfer one block of data */
  mcuxClDma_Drv_writeMajorLoopCounts(channel, 1u);
  mcuxClDma_Drv_writeTransferSize(channel, MCUXCLAES_BLOCK_SIZE);

  /* Start the channel */
  mcuxClDma_Drv_startChannel(channel);
}

/** Configure the given DMA input channel to write blocks to SGI by using SGI input handshake signals. */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_configureSgiInputWithHandshakes)
void mcuxClDma_Utils_configureSgiInputWithHandshakes(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDatInOffset,
  const uint8_t *pSrc)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  /*
   * Configure the transaction details (TCD) of the input channel.
   */
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  uint16_t srcOffset = 0u;
  uint16_t srcSize = 0u;
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pSrc, &srcOffset, &srcSize, MCUXCLAES_BLOCK_SIZE);

  mcuxClDma_Drv_writeTransferSize(inputChannel, MCUXCLAES_BLOCK_SIZE); /* Tranfer one block per SGI request (i.e., per major loop iteration) */
  mcuxClDma_Drv_writeSrcAddress(inputChannel, pSrc);
  mcuxClDma_Drv_writeSrcOffset(inputChannel, srcOffset);
  mcuxClDma_Utils_writeDstAddress_Sgi(inputChannel, sgiSfrDatInOffset);
  mcuxClDma_Drv_writeDstOffset(inputChannel, MCUXCLDMA_DRV_OFFSET_INCR_DIS); /* Do not modify address of SGI_DATIN */
  mcuxClDma_Sfr_writeTransferAttributes(inputChannel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE(srcSize)
                                                     | MCUXCLDMA_DRV_DST_ACCESS_SIZE_16_BYTE);
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Do not adjust the dst address, it always point to SGI_DATIN */
  mcuxClDma_Drv_writeLastDstAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Turn-off hardware requests once the channel is done - will prevent channel restart from too many SGI request signals */
  mcuxClDma_Sfr_writeTCDControlAndStatus(inputChannel, MCUXCLDMA_SFR_TCD_CSR_DREQ_EN);

  /*
   * Enable the channel's hardware requests,
   * and link the requests to the SGI handshake (SGI_IN)
   */
  mcuxClDma_Drv_linkWithSgiInputHandshakes(session);
  mcuxClDma_Drv_enableHardwareRequests(inputChannel);  /* inputChannel is started by SGI_IN hardware request */
}

/** Set the number of blocks for the handshake communication with SGI AUTO mode. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks)
void mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks(
  mcuxClSession_Handle_t session,
  uint32_t inputBlocks
)
{
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClDma_Drv_writeMajorLoopCounts(inputChannel, (uint16_t)(inputBlocks & 0xffffu)); /* One major loop iteration per SGI request (i.e., per block) */

  /* Re-enable hardware requests in the channel, will be disabled automatically whenever the channels are done */
  mcuxClDma_Drv_enableHardwareRequests(inputChannel);  /* inputChannel is started by SGI_IN hardware request */
}

/** Configure the given DMA channels to read/write blocks to/from SGI by using SGI handshake signals. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_configureSgiTransferWithHandshakes)
void mcuxClDma_Utils_configureSgiTransferWithHandshakes(
  mcuxClSession_Handle_t session,
  uint32_t sgiSfrDatInOffset,
  const uint8_t *pSrc,
  uint8_t *pDst)
{
  /*
   * Configure the transaction details (TCD) for both channels
   */

  /*
   * Write the TCD of the input channel
   */
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  uint16_t srcOffset = 0u;
  uint16_t srcSize = 0u;
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pSrc, &srcOffset, &srcSize, MCUXCLAES_BLOCK_SIZE);

  mcuxClDma_Drv_writeTransferSize(inputChannel, MCUXCLAES_BLOCK_SIZE); /* Tranfer one block per SGI request (i.e., per major loop iteration) */
  mcuxClDma_Drv_writeSrcAddress(inputChannel, pSrc);
  mcuxClDma_Drv_writeSrcOffset(inputChannel, srcOffset);
  mcuxClDma_Utils_writeDstAddress_Sgi(inputChannel, sgiSfrDatInOffset);
  mcuxClDma_Drv_writeDstOffset(inputChannel, MCUXCLDMA_DRV_OFFSET_INCR_DIS); /* Do not modify address of SGI_DATIN */
  mcuxClDma_Sfr_writeTransferAttributes(inputChannel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE(srcSize)
                                                     | MCUXCLDMA_DRV_DST_ACCESS_SIZE_16_BYTE);
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Do not adjust the dst address, it always point to SGI_DATIN */
  mcuxClDma_Drv_writeLastDstAddrAdjustment(inputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Turn-off hardware requests once the channel is done - will prevent channel restart from too many SGI request signals */
  mcuxClDma_Sfr_writeTCDControlAndStatus(inputChannel, MCUXCLDMA_SFR_TCD_CSR_DREQ_EN);

  /*
   * Write the TCD of the output channel
   */
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);
  uint16_t dstOffset = 0u;
  uint16_t dstSize = 0u;
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pDst, &dstOffset, &dstSize, MCUXCLAES_BLOCK_SIZE);

  mcuxClDma_Drv_writeTransferSize(outputChannel, MCUXCLAES_BLOCK_SIZE); /* Tranfer one block per SGI request (i.e., per major loop iteration) */
  mcuxClDma_Utils_writeSrcAddress_Sgi(outputChannel, MCUXCLSGI_DRV_DATOUT_OFFSET);
  mcuxClDma_Drv_writeSrcOffset(outputChannel, MCUXCLDMA_DRV_OFFSET_INCR_DIS); /* Do not modify address of SGI_DATOUT */
  mcuxClDma_Drv_writeDstAddress(outputChannel, pDst);
  mcuxClDma_Drv_writeDstOffset(outputChannel, dstOffset);
  mcuxClDma_Sfr_writeTransferAttributes(outputChannel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE_16_BYTE
                                                      | MCUXCLDMA_DRV_DST_ACCESS_SIZE(dstSize));
  /* Do not adjust the dst address, it always point to SGI_DATOUT */
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(outputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  mcuxClDma_Drv_writeLastDstAddrAdjustment(outputChannel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS);
  /* Turn-off hardware requests once the channel is done - will prevent channel restart from too many SGI request signals */
  mcuxClDma_Sfr_writeTCDControlAndStatus(outputChannel, MCUXCLDMA_SFR_TCD_CSR_DREQ_EN);

  /*
   * Link the SGI handshake signals with the DMA channels (SGI_IN and SGI_OUT)
   */
  mcuxClDma_Drv_linkWithSgiHandshakes(session);

}

/** Set the number of in and out blocks for the handshake communication with SGI AUTO mode. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks)
void mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks(
  mcuxClSession_Handle_t session,
  uint32_t inputBlocks,
  uint32_t outputBlocks
)
{
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  mcuxClDma_Drv_writeMajorLoopCounts(inputChannel, (uint16_t)(inputBlocks & 0xffffu)); /* One major loop iteration per SGI request (i.e., per input block) */
  mcuxClDma_Drv_writeMajorLoopCounts(outputChannel, (uint16_t)(outputBlocks & 0xffffu)); /* One major loop iteration per SGI request (i.e., per output block) */

  /* Enable hardware requests in the channels, will be disabled automatically whenever the channel is done */
  mcuxClDma_Drv_enableHardwareRequests(inputChannel);  /* inputChannel is started by SGI_IN hardware request */
  mcuxClDma_Drv_enableHardwareRequests(outputChannel); /* outputChannel is started by SGI_OUT hardware request */
}

